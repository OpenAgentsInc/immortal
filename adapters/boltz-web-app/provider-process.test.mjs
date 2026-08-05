import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { createFundingGate, releasedRouteShapes } from "./adapter.mjs";

const baseUrl = process.env.IMMORTAL_BOLTZ_PROVIDER_PROCESS_URL;
const stateDirectory = process.env.IMMORTAL_BOLTZ_PROVIDER_PROCESS_STATE_DIR;

const profile = (event) => JSON.parse(event.content).mkt_swp;
const record = (snapshot, kind) => {
    const matches = snapshot.signed_records.filter((event) => event.kind === kind);
    assert.equal(matches.length, 1);
    return matches[0];
};
const contract = (snapshot) => {
    const contracts = snapshot.signed_records.filter((event) => event.kind === 39610);
    assert.equal(contracts.length, 2);
    const first = profile(contracts[0]).contract;
    assert.deepEqual(first, profile(contracts[1]).contract);
    return first;
};
const bitcoin = (terms, legId) => {
    const verifier = terms.verifier_inputs.find((value) => value.leg_id === legId);
    const leg = terms.legs.find((value) => value.leg_id === legId);
    assert.ok(verifier);
    assert.ok(leg);
    return { verifier, leg };
};
const canonicalJson = (value) => {
    if (Array.isArray(value)) {
        return `[${value.map(canonicalJson).join(",")}]`;
    }
    if (value !== null && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => (
            `${JSON.stringify(key)}:${canonicalJson(value[key])}`
        )).join(",")}}`;
    }
    return JSON.stringify(value);
};

const persistedExit = (snapshot, terms) => {
    const commitment = terms.exit_package_commitments.find((value) =>
        value.participant_role === "requester" &&
        value.path === "refund" &&
        ["presigned", "wallet_sign"].includes(value.package_mode));
    assert.ok(commitment);
    assert.match(commitment.package_sha256, /^[0-9a-f]{64}$/);
    const persisted = snapshot.exit_packages.find((candidate) => {
        const document = candidate?.document;
        if (document?.exit?.mode !== commitment.package_mode) {
            return false;
        }
        const { swap_contract_ids: _ids, contract_sha256: _contract, ...bound } = document;
        const digest = createHash("sha256").update(canonicalJson(bound)).digest("hex");
        return digest === commitment.package_sha256;
    });
    assert.ok(persisted, "matching exit package mode and digest must be persisted");
    return Object.freeze({
        mode: commitment.package_mode,
        sha256: commitment.package_sha256,
    });
};

const request = async (method, route, body) => {
    const response = await fetch(`${baseUrl}${route}`, {
        method,
        headers: {
            Origin: "http://127.0.0.1",
            ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const value = await response.json();
    assert.ok(response.ok, `${method} ${route}: ${response.status} ${JSON.stringify(value)}`);
    return value;
};

const refused = async (method, route, body) => {
    const response = await fetch(`${baseUrl}${route}`, {
        method,
        headers: {
            Origin: "http://127.0.0.1",
            ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.ok(!response.ok, `${method} ${route} unexpectedly succeeded`);
};

const statusTransaction = (snapshot, ...states) => {
    for (const event of snapshot.signed_records) {
        if (event.kind !== 39607) {
            continue;
        }
        const status = profile(event);
        if (states.includes(status.swp_state) && typeof status.transaction_id === "string") {
            return status.transaction_id;
        }
    }
    assert.fail("signed session has no public transaction for the requested states");
};

const websocketStatus = (sessionId) =>
    new Promise((resolve, reject) => {
        const socket = new WebSocket(`${baseUrl.replace(/^http/, "ws")}/v2/ws`);
        const timer = setTimeout(() => {
            socket.close();
            reject(new Error("provider WebSocket status timed out"));
        }, 10_000);
        socket.addEventListener("open", () => {
            socket.send(JSON.stringify({
                op: "subscribe",
                channel: "swap.update",
                args: [sessionId],
            }));
        });
        socket.addEventListener("message", (message) => {
            const value = JSON.parse(message.data);
            if (value.event === "update") {
                clearTimeout(timer);
                socket.close();
                resolve(value);
            }
        });
        socket.addEventListener("error", () => {
            clearTimeout(timer);
            reject(new Error("provider WebSocket failed"));
        });
    });

test("adapted web client replays its 15 calls against the provider process", {
    skip: baseUrl === undefined || stateDirectory === undefined,
}, async () => {
    assert.equal(releasedRouteShapes.length, 15);
    const submarine = JSON.parse(await readFile(
        path.join(stateDirectory, "funded-submarine-session.json"),
        "utf8",
    ));
    const reverse = JSON.parse(await readFile(
        path.join(stateDirectory, "funded-reverse-session.json"),
        "utf8",
    ));
    const submarineId = submarine.config.session_id;
    const reverseId = reverse.config.session_id;
    const submarineRfq = profile(record(submarine, 39604));
    const submarineContract = contract(submarine);
    const submarineBitcoin = bitcoin(submarineContract, "source");
    const submarineExit = persistedExit(submarine, submarineContract);
    const reverseRfq = profile(record(reverse, 39604));
    const reverseContract = contract(reverse);
    const reverseBitcoin = bitcoin(reverseContract, "destination");

    const submarinePairs = await request("GET", "/v2/swap/submarine");
    const submarineCreated = await request("POST", "/v2/swap/submarine", {
        from: "BTC",
        to: "BTC",
        invoice: submarineRfq.invoice,
        pairHash: submarinePairs.BTC.BTC.hash,
        refundPublicKey: submarineBitcoin.leg.refund_public_key,
        mktSessionId: submarineId,
    });
    assert.equal(submarineCreated.id, submarineId);

    const fundingGate = createFundingGate({
        profile: {
            cooperativeDisabled: true,
            chainPairsDisabled: true,
            cooperativeEndpointsDisabled: true,
            providerWebSocketUrl: `${baseUrl.replace(/^http/, "ws")}/v2/ws`,
        },
        prepareFunding: async () => ({
            rawTransactionHex: submarineBitcoin.verifier.funding_transaction,
            outputIndex: submarineBitcoin.verifier.output_index,
        }),
        finalizeSubmarineAndPersistExit: async (binding) => {
            const approval = await request("POST", binding.finalizePath, {
                sessionId: binding.sessionId,
                finalizePath: binding.finalizePath,
                rawTransactionHex: binding.rawTransactionHex,
                fundingTransactionSha256: binding.fundingTransactionSha256,
                outputIndex: binding.outputIndex,
            });
            assert.equal(approval.exitPackageMode, submarineExit.mode);
            assert.equal(approval.exitPackageSha256, submarineExit.sha256);
            return { ...approval, exitPackagePersisted: true };
        },
        broadcastPreparedFunding: async (prepared) => (
            await request("POST", "/v2/chain/BTC/transaction", {
                hex: prepared.rawTransactionHex,
                mktSessionId: submarineId,
            })
        ).id,
    });
    const fundingTransactionId = await fundingGate.fundSubmarine({
        sessionId: submarineId,
        address: submarineCreated.address,
        amountSats: submarineCreated.expectedAmount,
    });
    const fundingReplay = await request("POST", "/v2/chain/BTC/transaction", {
        hex: submarineBitcoin.verifier.funding_transaction,
        mktSessionId: submarineId,
    });
    assert.equal(fundingReplay.id, fundingTransactionId);

    const reversePairs = await request("GET", "/v2/swap/reverse");
    const reverseCreated = await request("POST", "/v2/swap/reverse", {
        from: "BTC",
        to: "BTC",
        invoiceAmount: Number(reverseRfq.constraints.input_amount),
        preimageHash: reverseRfq.constraints.payment_hash,
        claimPublicKey: reverseBitcoin.leg.claim_public_key,
        pairHash: reversePairs.BTC.BTC.hash,
        mktSessionId: reverseId,
    });
    assert.equal(reverseCreated.id, reverseId);
    assert.equal(typeof reverseCreated.invoice, "string");
    await refused("POST", "/v2/chain/BTC/transaction", {
        hex: submarineBitcoin.verifier.funding_transaction,
        mktSessionId: reverseId,
    });
    const reverseClaimId = statusTransaction(reverse, "requester_claimed");
    const reverseClaim = await request(
        "GET",
        `/v2/chain/BTC/transaction/${reverseClaimId}`,
    );
    const claimReplay = await request("POST", "/v2/chain/BTC/transaction", {
        hex: reverseClaim.hex,
        mktSessionId: reverseId,
    });
    assert.equal(claimReplay.id, reverseClaimId);

    const singleStatus = await request("GET", `/v2/swap/${submarineId}`);
    assert.equal(singleStatus.id, submarineId);
    const statuses = await request(
        "GET",
        `/v2/swap/status?ids=${submarineId}&ids=${reverseId}`,
    );
    assert.equal(statuses[submarineId].id, submarineId);
    assert.equal(statuses[reverseId].id, reverseId);
    const websocket = await websocketStatus(submarineId);
    assert.equal(websocket.args[0].id, submarineId);

    const submarineTransaction = await request(
        "GET",
        `/v2/swap/submarine/${submarineId}/transaction`,
    );
    assert.equal(submarineTransaction.id, fundingTransactionId);
    const reverseTransaction = await request(
        "GET",
        `/v2/swap/reverse/${reverseId}/transaction`,
    );
    assert.equal(reverseTransaction.hex, reverseBitcoin.verifier.funding_transaction);
    const released = await request(
        "GET",
        `/v2/swap/submarine/${submarineId}/preimage`,
    );
    assert.match(released.preimage, /^[0-9a-f]{64}$/);
    const reverseInvoice = reverseCreated.invoice;
    const bip21 = await request(
        "GET",
        `/v2/swap/reverse/${reverseInvoice}/bip21`,
    );
    assert.ok(bip21.bip21.includes(`lightning=${reverseInvoice}`));
    assert.match(bip21.signature, /^[0-9a-f]{128}$/);

    const fees = await request("GET", "/v2/chain/fees");
    assert.ok(Number.isSafeInteger(fees.BTC) && fees.BTC > 0);
    const transaction = await request(
        "GET",
        `/v2/chain/BTC/transaction/${reverseTransaction.id}`,
    );
    assert.equal(transaction.hex, reverseTransaction.hex);
    const nodes = await request("GET", "/v2/nodes/stats");
    assert.ok(nodes.BTC.Immortal.capacity > 0);
});
