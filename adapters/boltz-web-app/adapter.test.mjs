import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    createFundingGate,
    mappingRevision,
    releasedRouteShapes,
} from "./adapter.mjs";

const sessionId = "a".repeat(64);
const requesterContractEventId = "b".repeat(64);
const providerContractEventId = "c".repeat(64);
const exitPackageSha256 = "d".repeat(64);

const fixtureUrl = new URL(
    "../../tests/fixtures/nipmkt/boltz-client-adapters-v1.json",
    import.meta.url,
);

const validProfile = () => ({
    cooperativeDisabled: true,
    chainPairsDisabled: true,
    cooperativeEndpointsDisabled: true,
    providerWebSocketUrl: "wss://provider.example/v2/ws",
});

const validRequest = () => ({
    sessionId,
    address: "bcrt1qexample",
    amountSats: 100_000,
});

const approvalFor = (binding) => ({
    sessionId: binding.sessionId,
    finalizePath: binding.finalizePath,
    fundingTransactionSha256: binding.fundingTransactionSha256,
    outputIndex: binding.outputIndex,
    requesterContractEventId,
    providerContractEventId,
    exitPackageSha256,
    exitPackagePersisted: true,
    scriptPathOnly: true,
});

test("released routes and forbidden stock paths match the fixture", async () => {
    const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
    assert.equal(fixture.mapping_revision, mappingRevision);
    assert.deepEqual(
        releasedRouteShapes.map(({ method, path }) => `${method} ${path}`),
        fixture.clients.web.route_shapes,
    );
    const source = await readFile(new URL("./adapter.mjs", import.meta.url), "utf8");
    for (const forbidden of fixture.clients.web.forbidden_source_tokens) {
        assert.equal(source.includes(forbidden), false, forbidden);
    }
});

test("funding is approved and persisted before unchanged bytes broadcast", async () => {
    const calls = [];
    const prepared = Object.freeze({
        rawTransactionHex: "020000000001",
        outputIndex: 3,
    });
    const gate = createFundingGate({
        profile: validProfile(),
        prepareFunding: async () => {
            calls.push("prepare");
            return prepared;
        },
        finalizeSubmarineAndPersistExit: async (binding) => {
            calls.push("finalize");
            return approvalFor(binding);
        },
        broadcastPreparedFunding: async (candidate) => {
            calls.push("broadcast");
            assert.deepEqual(candidate, prepared);
            return "e".repeat(64);
        },
    });

    assert.equal(gate.providerWebSocketUrl, "wss://provider.example/v2/ws");
    assert.equal(await gate.fundSubmarine(validRequest()), "e".repeat(64));
    assert.deepEqual(calls, ["prepare", "finalize", "broadcast"]);
});

test("profiles retaining stock paths fail closed", () => {
    const dependencies = {
        prepareFunding: async () => {},
        finalizeSubmarineAndPersistExit: async () => {},
        broadcastPreparedFunding: async () => {},
    };
    const invalidProfiles = [
        { ...validProfile(), cooperativeDisabled: false },
        { ...validProfile(), chainPairsDisabled: false },
        { ...validProfile(), cooperativeEndpointsDisabled: false },
        {
            ...validProfile(),
            providerWebSocketUrl: "https://relay.example/v2/ws",
        },
    ];
    for (const profile of invalidProfiles) {
        assert.throws(
            () => createFundingGate({ profile, ...dependencies }),
            { code: "invalid_immortal_boltz_profile" },
        );
    }
});

test("broadcast is unreachable without exact bilateral script approval", async (t) => {
    const cases = [
        {
            name: "finalize path",
            mutate: (approval) => {
                approval.finalizePath =
                    "/v2/swap/submarine/changed/finalize";
            },
            code: "bilateral_contract_approval_mismatch",
        },
        {
            name: "funding digest",
            mutate: (approval) => {
                approval.fundingTransactionSha256 = "f".repeat(64);
            },
            code: "bilateral_contract_approval_mismatch",
        },
        {
            name: "funding output",
            mutate: (approval) => {
                approval.outputIndex += 1;
            },
            code: "bilateral_contract_approval_mismatch",
        },
        {
            name: "provider Contract",
            mutate: (approval) => {
                approval.providerContractEventId = "";
            },
            code: "bilateral_contract_approval_mismatch",
        },
        {
            name: "persisted exit",
            mutate: (approval) => {
                approval.exitPackagePersisted = false;
            },
            code: "script_path_exit_not_persisted",
        },
        {
            name: "cooperative exit",
            mutate: (approval) => {
                approval.scriptPathOnly = false;
            },
            code: "script_path_exit_not_persisted",
        },
    ];

    for (const testCase of cases) {
        await t.test(testCase.name, async () => {
            const calls = [];
            const gate = createFundingGate({
                profile: validProfile(),
                prepareFunding: async () => {
                    calls.push("prepare");
                    return {
                        rawTransactionHex: "020000000001",
                        outputIndex: 3,
                    };
                },
                finalizeSubmarineAndPersistExit: async (binding) => {
                    calls.push("finalize");
                    const approval = approvalFor(binding);
                    testCase.mutate(approval);
                    return approval;
                },
                broadcastPreparedFunding: async () => {
                    calls.push("broadcast");
                },
            });

            await assert.rejects(gate.fundSubmarine(validRequest()), {
                code: testCase.code,
            });
            assert.deepEqual(calls, ["prepare", "finalize"]);
        });
    }
});
