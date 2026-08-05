import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import {
    adaptPinnedReverseCreate,
    adaptPinnedSubmarineCreate,
    createFundingGate,
    releasedRouteShapes,
} from "./adapter.mjs";

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
const waitControl = async (name) => {
    const controlPath = path.join(stateDirectory, name);
    const deadline = Date.now() + 180_000;
    for (;;) {
        try {
            return JSON.parse(await readFile(controlPath, "utf8"));
        } catch (error) {
            if (error?.code !== "ENOENT") {
                throw error;
            }
        }
        if (Date.now() >= deadline) {
            throw new Error(`timed out waiting for ${controlPath}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
};

const writeControl = async (name, value) => {
    const controlPath = path.join(stateDirectory, name);
    const temporary = `${controlPath}.${process.pid}.tmp`;
    await writeFile(temporary, JSON.stringify(value), { mode: 0o600 });
    await rename(temporary, controlPath);
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

const requestEventually = async (method, route, body) => {
    const deadline = Date.now() + 30_000;
    let lastError;
    while (Date.now() < deadline) {
        try {
            return await request(method, route, body);
        } catch (error) {
            lastError = error;
            await new Promise((resolve) => setTimeout(resolve, 100));
        }
    }
    throw lastError;
};

const providerApprovalMatchesCallback = (approval, callback) =>
    approval.requesterContractEventId === callback.requester_contract_event_id &&
    approval.providerContractEventId === callback.provider_contract_event_id &&
    approval.exitPackageSha256 === callback.exit_package_sha256 &&
    approval.exitPackageMode === callback.exit_package_mode &&
    approval.scriptPathOnly === callback.script_path_only;

const readCompactSize = (bytes, offset) => {
    assert.ok(offset < bytes.length, "compact size is truncated");
    const prefix = bytes[offset];
    if (prefix < 0xfd) {
        return { value: prefix, bytes: 1 };
    }
    const widths = new Map([[0xfd, 2], [0xfe, 4], [0xff, 8]]);
    const width = widths.get(prefix);
    assert.ok(offset + 1 + width <= bytes.length, "compact size is truncated");
    const value = width === 2
        ? bytes.readUInt16LE(offset + 1)
        : width === 4
            ? bytes.readUInt32LE(offset + 1)
            : Number(bytes.readBigUInt64LE(offset + 1));
    assert.ok(Number.isSafeInteger(value), "compact size exceeds the safe test bound");
    if (width === 2) {
        assert.ok(value >= 0xfd, "compact size uint16 is noncanonical");
    } else if (width === 4) {
        assert.ok(value > 0xffff, "compact size uint32 is noncanonical");
    } else {
        assert.ok(value > 0xffffffff, "compact size uint64 is noncanonical");
    }
    return { value, bytes: 1 + width };
};

const changedWitnessSameTransactionId = (raw) => {
    const transaction = Buffer.from(raw, "hex");
    assert.ok(
        transaction.length >= 10 && transaction[4] === 0 && transaction[5] === 1,
        "funding transaction has no SegWit witness",
    );
    let offset = 6;
    const inputs = readCompactSize(transaction, offset);
    const stripped = [transaction.subarray(0, 4), transaction.subarray(offset, offset + inputs.bytes)];
    offset += inputs.bytes;
    for (let input = 0; input < inputs.value; input += 1) {
        const start = offset;
        assert.ok(offset + 36 <= transaction.length, "funding input is truncated");
        offset += 36;
        const script = readCompactSize(transaction, offset);
        offset += script.bytes;
        assert.ok(
            script.value <= transaction.length - offset &&
                offset + script.value + 4 <= transaction.length,
            "funding input script is truncated",
        );
        offset += script.value + 4;
        stripped.push(transaction.subarray(start, offset));
    }
    const outputStart = offset;
    const outputs = readCompactSize(transaction, offset);
    offset += outputs.bytes;
    for (let output = 0; output < outputs.value; output += 1) {
        assert.ok(offset + 8 <= transaction.length, "funding output is truncated");
        offset += 8;
        const script = readCompactSize(transaction, offset);
        offset += script.bytes;
        assert.ok(script.value <= transaction.length - offset, "funding output script is truncated");
        offset += script.value;
    }
    stripped.push(transaction.subarray(outputStart, offset));
    const mutated = Buffer.from(transaction);
    let changed = false;
    for (let input = 0; input < inputs.value; input += 1) {
        const items = readCompactSize(transaction, offset);
        offset += items.bytes;
        for (let item = 0; item < items.value; item += 1) {
            const witness = readCompactSize(transaction, offset);
            offset += witness.bytes;
            assert.ok(witness.value <= transaction.length - offset, "funding witness is truncated");
            if (witness.value > 0 && !changed) {
                mutated[offset] ^= 1;
                changed = true;
            }
            offset += witness.value;
        }
    }
    assert.ok(changed && offset + 4 === transaction.length, "funding witness is not mutable");
    stripped.push(transaction.subarray(offset));
    const first = createHash("sha256").update(Buffer.concat(stripped)).digest();
    const transactionId = Buffer.from(
        createHash("sha256").update(first).digest(),
    ).reverse().toString("hex");
    return { raw: mutated.toString("hex"), transactionId };
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
    const prepared = JSON.parse(await readFile(
        path.join(stateDirectory, "boltz-web-prepared.json"),
        "utf8",
    ));
    assert.equal(prepared.schema, "openagents.immortal.boltz-adapter-prepared.v1");
    assert.equal(prepared.client, "web");
    assert.match(prepared.session_id, /^[0-9a-f]{64}$/);
    const reverse = JSON.parse(await readFile(
        path.join(stateDirectory, "funded-reverse-session.json"),
        "utf8",
    ));
    const submarineId = prepared.session_id;
    const reverseId = reverse.config.session_id;
    const reverseRfq = profile(record(reverse, 39604));
    const reverseContract = contract(reverse);
    const reverseBitcoin = bitcoin(reverseContract, "destination");

    const submarinePairs = await request("GET", "/v2/swap/submarine");
    const submarineCreate = adaptPinnedSubmarineCreate({
        from: "BTC",
        to: "BTC",
        invoice: prepared.invoice,
        pairHash: submarinePairs.BTC.BTC.hash,
        refundPublicKey: prepared.refund_public_key,
    }, submarineId);
    const submarineCreated = await requestEventually(
        "POST",
        "/v2/swap/submarine",
        submarineCreate,
    );
    assert.equal(submarineCreated.id, submarineId);
    const changedWitness = changedWitnessSameTransactionId(
        prepared.raw_transaction_hex,
    );
    await refused(
        "GET",
        `/v2/chain/BTC/transaction/${changedWitness.transactionId}`,
    );

    const fundingGate = createFundingGate({
        profile: {
            cooperativeDisabled: true,
            chainPairsDisabled: true,
            cooperativeEndpointsDisabled: true,
            providerWebSocketUrl: `${baseUrl.replace(/^http/, "ws")}/v2/ws`,
        },
        prepareFunding: async () => ({
            rawTransactionHex: prepared.raw_transaction_hex,
            outputIndex: prepared.output_index,
        }),
        finalizeSubmarineAndPersistExit: async (binding) => {
            await writeControl("boltz-web-finalize-request.json", {
                schema: "openagents.immortal.boltz-adapter-finalize.v1",
                client: "web",
                session_id: binding.sessionId,
                finalize_path: binding.finalizePath,
                raw_transaction_hex: binding.rawTransactionHex,
                funding_transaction_sha256: binding.fundingTransactionSha256,
                output_index: binding.outputIndex,
            });
            const callback = await waitControl("boltz-web-approval.json");
            assert.equal(callback.schema, "openagents.immortal.boltz-adapter-approval.v1");
            assert.equal(callback.client, "web");
            assert.equal(callback.session_id, binding.sessionId);
            assert.equal(callback.finalize_path, binding.finalizePath);
            assert.equal(
                callback.funding_transaction_sha256,
                binding.fundingTransactionSha256,
            );
            assert.equal(callback.output_index, binding.outputIndex);
            const approval = await request("POST", binding.finalizePath, {
                sessionId: binding.sessionId,
                finalizePath: binding.finalizePath,
                rawTransactionHex: binding.rawTransactionHex,
                fundingTransactionSha256: binding.fundingTransactionSha256,
                outputIndex: binding.outputIndex,
            });
            assert.ok(providerApprovalMatchesCallback(approval, callback));
            return {
                ...approval,
                exitPackagePersisted: callback.exit_package_persisted,
                authorizationSnapshotSha256:
                    callback.authorization_snapshot_sha256,
                scriptPathOnly:
                    callback.script_path_only && approval.scriptPathOnly,
            };
        },
        broadcastPreparedFunding: async (candidate) => {
            const transactionId = (
                await request("POST", "/v2/chain/BTC/transaction", {
                    hex: candidate.rawTransactionHex,
                    mktSessionId: submarineId,
                })
            ).id;
            await writeControl("boltz-web-broadcast.json", {
                schema: "openagents.immortal.boltz-adapter-broadcast.v1",
                client: "web",
                session_id: submarineId,
                transaction_id: transactionId,
            });
            const complete = await waitControl("boltz-web-complete.json");
            assert.deepEqual(complete, {
                schema: "openagents.immortal.boltz-adapter-complete.v1",
                client: "web",
                session_id: submarineId,
                transaction_id: transactionId,
            });
            return transactionId;
        },
    });
    const fundingTransactionId = await fundingGate.fundSubmarine({
        sessionId: submarineId,
        address: submarineCreated.address,
        amountSats: submarineCreated.expectedAmount,
    });
    const fundingReplay = await request("POST", "/v2/chain/BTC/transaction", {
        hex: prepared.raw_transaction_hex,
        mktSessionId: submarineId,
    });
    assert.equal(fundingReplay.id, fundingTransactionId);
    assert.equal(fundingTransactionId, changedWitness.transactionId);
    await refused("POST", "/v2/chain/BTC/transaction", {
        hex: changedWitness.raw,
        mktSessionId: submarineId,
    });
    const observedFunding = await request(
        "GET",
        `/v2/chain/BTC/transaction/${fundingTransactionId}`,
    );
    assert.equal(observedFunding.hex, prepared.raw_transaction_hex);

    const reversePairs = await request("GET", "/v2/swap/reverse");
    const reverseCreate = adaptPinnedReverseCreate({
        from: "BTC",
        to: "BTC",
        invoiceAmount: Number(reverseRfq.constraints.input_amount),
        preimageHash: reverseRfq.constraints.payment_hash,
        claimPublicKey: reverseBitcoin.leg.claim_public_key,
        pairHash: reversePairs.BTC.BTC.hash,
    }, reverseId);
    const reverseCreated = await request(
        "POST",
        "/v2/swap/reverse",
        reverseCreate,
    );
    assert.equal(reverseCreated.id, reverseId);
    assert.equal(typeof reverseCreated.invoice, "string");
    await refused("POST", "/v2/chain/BTC/transaction", {
        hex: prepared.raw_transaction_hex,
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

test("provider finalize must match the client-engine approval", () => {
    const callback = {
        requester_contract_event_id: "1".repeat(64),
        provider_contract_event_id: "2".repeat(64),
        exit_package_sha256: "3".repeat(64),
        exit_package_mode: "wallet_sign",
        script_path_only: true,
    };
    const matching = {
        requesterContractEventId: callback.requester_contract_event_id,
        providerContractEventId: callback.provider_contract_event_id,
        exitPackageSha256: callback.exit_package_sha256,
        exitPackageMode: callback.exit_package_mode,
        scriptPathOnly: true,
    };
    assert.ok(providerApprovalMatchesCallback(matching, callback));
    assert.ok(!providerApprovalMatchesCallback({
        ...matching,
        requesterContractEventId: callback.provider_contract_event_id,
        providerContractEventId: callback.requester_contract_event_id,
    }, callback));
    assert.ok(!providerApprovalMatchesCallback({
        ...matching,
        providerContractEventId: "4".repeat(64),
    }, callback));
});
