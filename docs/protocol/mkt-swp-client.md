# MKT-SWP Client Engine

The `mkt-swp-verify` feature exposes Immortal's transport-neutral requester
engine for MKT-SWP v1. It runs in native or `wasm32-unknown-unknown` library
builds, owns no network connection, and adds no server process or database.
The embedding application owns Nostr transport, wallet calls, rail
observations, persistence, and user-facing policy.

## Signed records and lifecycle

`SwapRecordFactory` constructs deterministic RFQ, Quote, Order, Status,
Cancel, Close, and bilateral Swap Contract signing requests. The caller signs
the exact requested event externally. The client then checks the signer,
timestamp, kind, tags, content, event ID, signature, and MKT profile before
accepting the returned event. It does not accept a signer that silently
rewrites any requested byte.

A session binds the RFQ, unexpired Quote, Order, and both participants'
kind-39610 Swap Contracts. The two contracts must name the same order and
quote, contain the same RFC 8785-compatible canonical digest, and agree with
the Quote terms. An Order may choose only the Quote's finite `input_amount`,
`fee_payer`, `confirmation_policy`, and `public_receipt_consent` options; the
contract freezes the exact selection and recomputed output amount.
Status projection is maintained independently per signer. Sequence gaps and
forks remain visible; signer-invalid states and lifecycle regressions fail
closed. Conflicting mutual-close records remain separate evidence rather than
being collapsed into settlement truth.

## Verify before fund

`SwapSession<AwaitingVerification>` is the only state produced by creation or
restore. It can become `SwapSession<FundingAuthorized>` only after all of
these checks pass:

- the bilateral contracts and Quote remain bound to the same terms;
- the submarine, reverse, or chain timeout ladder matches the contract and
  preserves the required safety margin;
- the payment hash and amountful BOLT-11 network, amount, signature, hash,
  expiry, and minimum-final-CLTV coupling pass the owned issue-#10
  verification primitives;
- the Bitcoin transaction, output value, Taproot tree/control block,
  confirmation requirement, and RBF policy match the contract; and
- every required claim or refund package is parseable and has an exact
  contract commitment.

Only then does the engine pass a flow-specific `FundingAuthorizationRequest`
to an embedding-wallet callback: submarine and chain requesters authorize a
Bitcoin funding-template broadcast on `source`; reverse requesters authorize
payment of the verified invoice on `lightning`. Confirmation, replacement,
and competing-spend facts are obtained later through an explicit local
Bitcoin observation adapter and are not fields a funding caller can assert.
A refusal leaves funding unauthorized. The
authorized marker is private and is never serialized. Restoring a snapshot
always revalidates its signed records, exit packages, and effect ledger and
returns `AwaitingVerification`, so a persisted boolean cannot bypass the
gate.

## Exit packages and external effects

An exit package binds the participant role, leg, network, asset, effect ID,
funding outpoint and transaction, claim or refund path, unsigned transaction,
verification requirements, public secret commitments, and broadcast mode.
The final package also carries both Swap Contract event IDs and their shared
contract digest.

`package_sha256` hashes every package member except the two contract IDs and
`contract_sha256`. This projection avoids an impossible
circular dependency in which a contract event ID would commit to a package
that commits back to the event ID. The complete package must still contain
the exact bilateral IDs and digest, and those bindings are revalidated before
funding and after restore.

The client accepts only exact hashlock-claim, CLTV-refund, and CSV-refund
Taproot leaves. It executes the leaf condition against the transaction and
witness: claims require the committed 32-byte preimage and signer; CLTV and
CSV refunds require the bound lock or delay and signer. Extra branches or
stack elements fail closed. The client assembles claim and refund transactions
but delegates signatures to a wallet or external signer callback. The request
includes the exact Taproot script-path sighash. It rejects a returned
transaction if the version, lock time, inputs, outputs, non-witness
serialization, script, control block, or exact witness shape differs from the
requested path. Pre-signed packages are restricted to timeout exits, pass the
same verification, require no key, and can be converted into a bounded public
Esplora `POST /tx` request by `KeylessEsploraExecutor`.

External wallet, payment, and broadcast operations use deterministic effect
IDs. Replaying the same result is idempotent; binding one effect ID to a
different result fails closed. Recovery is rail-specific. A reverse requester
claims the destination output when it is claimable. A chain requester claims
the destination first, waits while that output remains funded and unclaimed,
and refunds the source only when the destination was never funded or its
refund is final. Missing rail state becomes an explicit unresolved-loss
result; effect-ID sorting never determines recovery order.

## Custody boundary

Snapshots contain signed public records, exit templates or complete
pre-signed transactions, public commitments, and external effect results.
Recursive tripwires reject seeds, private or claim/refund keys, preimages,
macaroons, NWC connection strings, and signing nonces. Lightning node control,
wallet policy, secret generation, signing, broadcasting, chain indexing, and
finality remain outside Immortal.

This client capability does not change relay admission or NIP-11. The relay
continues to advertise only its gated observable `mkt-swp:1` surface and keeps
the executable-profile set empty until the coordination-handler packet lands.

Run its native/no-default/WASM gate with:

```sh
./scripts/test-swp-verification.sh
```

The deterministic client corpus is
`tests/fixtures/nipmkt/swp-client-engine-v1.json`; the full repository gate is
`./scripts/test-conformance.sh`.
