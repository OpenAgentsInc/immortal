export const mappingRevision =
    "openagents.mkt-swp.boltz-released-client.v2";

const maximumRawTransactionBytes = 1_000_000;

export const releasedRouteShapes = Object.freeze([
    Object.freeze({ method: "GET", path: "/v2/swap/submarine" }),
    Object.freeze({ method: "POST", path: "/v2/swap/submarine" }),
    Object.freeze({
        method: "POST",
        path: "/v2/swap/submarine/:id/finalize",
    }),
    Object.freeze({ method: "GET", path: "/v2/swap/reverse" }),
    Object.freeze({ method: "POST", path: "/v2/swap/reverse" }),
    Object.freeze({ method: "GET", path: "/v2/swap/:id" }),
    Object.freeze({
        method: "GET",
        path: "/v2/swap/status?ids=:id...",
    }),
    Object.freeze({ method: "GET", path: "/v2/ws" }),
    Object.freeze({
        method: "GET",
        path: "/v2/swap/submarine/:id/transaction",
    }),
    Object.freeze({
        method: "GET",
        path: "/v2/swap/reverse/:id/transaction",
    }),
    Object.freeze({
        method: "GET",
        path: "/v2/swap/submarine/:id/preimage",
    }),
    Object.freeze({
        method: "GET",
        path: "/v2/swap/reverse/:invoice/bip21",
    }),
    Object.freeze({ method: "GET", path: "/v2/chain/fees" }),
    Object.freeze({
        method: "POST",
        path: "/v2/chain/BTC/transaction",
    }),
    Object.freeze({ method: "GET", path: "/v2/nodes/stats" }),
]);

const failure = (code) => Object.assign(new Error(code), { code });

const validLowerHex32 = (value) =>
    typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

const validProviderWebSocketUrl = (value) => {
    if (typeof value !== "string") {
        return false;
    }
    let parsed;
    try {
        parsed = new URL(value);
    } catch {
        return false;
    }
    return (
        (parsed.protocol === "ws:" || parsed.protocol === "wss:") &&
        parsed.host !== "" &&
        parsed.username === "" &&
        parsed.password === "" &&
        parsed.pathname === "/v2/ws" &&
        parsed.search === "" &&
        parsed.hash === ""
    );
};

const rawTransactionBytes = (value) => {
    if (
        typeof value !== "string" ||
        value.length === 0 ||
        value.length % 2 !== 0 ||
        value.length / 2 > maximumRawTransactionBytes ||
        !/^[0-9a-f]+$/.test(value)
    ) {
        throw failure("invalid_prepared_funding");
    }
    const bytes = new Uint8Array(value.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
        bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
};

const sha256Hex = async (subtle, bytes) => {
    const digest = await subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (value) =>
        value.toString(16).padStart(2, "0"),
    ).join("");
};

const validateApproval = (binding, approval) => {
    if (
        approval === null ||
        typeof approval !== "object" ||
        approval.sessionId !== binding.sessionId ||
        approval.finalizePath !== binding.finalizePath ||
        approval.fundingTransactionSha256 !==
            binding.fundingTransactionSha256 ||
        approval.outputIndex !== binding.outputIndex ||
        !validLowerHex32(approval.requesterContractEventId) ||
        !validLowerHex32(approval.providerContractEventId) ||
        approval.requesterContractEventId === approval.providerContractEventId ||
        !validLowerHex32(approval.exitPackageSha256) ||
        !["presigned", "wallet_sign"].includes(approval.exitPackageMode)
    ) {
        throw failure("bilateral_contract_approval_mismatch");
    }
    if (
        approval.exitPackagePersisted !== true ||
        approval.scriptPathOnly !== true
    ) {
        throw failure("script_path_exit_not_persisted");
    }
};

export const createFundingGate = (options) => {
    const profile = options?.profile;
    const subtle = globalThis.crypto?.subtle;
    if (
        profile?.cooperativeDisabled !== true ||
        profile?.chainPairsDisabled !== true ||
        profile?.cooperativeEndpointsDisabled !== true ||
        !validProviderWebSocketUrl(profile?.providerWebSocketUrl) ||
        typeof options?.prepareFunding !== "function" ||
        typeof options?.finalizeSubmarineAndPersistExit !== "function" ||
        typeof options?.broadcastPreparedFunding !== "function" ||
        typeof subtle?.digest !== "function"
    ) {
        throw failure("invalid_immortal_boltz_profile");
    }

    const prepareFunding = options.prepareFunding;
    const finalizeSubmarineAndPersistExit =
        options.finalizeSubmarineAndPersistExit;
    const broadcastPreparedFunding = options.broadcastPreparedFunding;

    return Object.freeze({
        providerWebSocketUrl: profile.providerWebSocketUrl,
        async fundSubmarine(request) {
            if (
                !validLowerHex32(request?.sessionId) ||
                typeof request?.address !== "string" ||
                request.address.length === 0 ||
                request.address.length > 256 ||
                !Number.isSafeInteger(request?.amountSats) ||
                request.amountSats <= 0
            ) {
                throw failure("invalid_funding_request");
            }

            const candidate = await prepareFunding(Object.freeze({ ...request }));
            const bytes = rawTransactionBytes(candidate?.rawTransactionHex);
            if (
                !Number.isSafeInteger(candidate?.outputIndex) ||
                candidate.outputIndex < 0
            ) {
                throw failure("invalid_prepared_funding");
            }
            const prepared = Object.freeze({
                rawTransactionHex: candidate.rawTransactionHex,
                outputIndex: candidate.outputIndex,
            });
            const binding = Object.freeze({
                sessionId: request.sessionId,
                finalizePath: `/v2/swap/submarine/${request.sessionId}/finalize`,
                rawTransactionHex: prepared.rawTransactionHex,
                fundingTransactionSha256: await sha256Hex(subtle, bytes),
                outputIndex: prepared.outputIndex,
            });
            const approval = await finalizeSubmarineAndPersistExit(binding);
            validateApproval(binding, approval);
            return broadcastPreparedFunding(prepared);
        },
    });
};
