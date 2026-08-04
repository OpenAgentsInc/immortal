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
contract freezes selected values, inherits every omitted value from the Quote,
and recomputes the output amount. Empty and null selections mean full
inheritance.
Status projection is maintained independently per signer. Sequence gaps and
forks remain visible. Signer-invalid states, regressions, and every descendant
of a gap, fork, or invalid claim remain retained but cannot advance the last
valid rung. Either participant may request cancellation and emit the effective
record after the other participant accepts; exact references and participant
roles establish consent without trusting cross-party timestamps. Bitcoin
broadcast remains irreversible for cancellation. Reverse Lightning initiation
may be released only by an exact persisted local cancelled or unpaid-final
observation proving that no principal moved, followed by a contiguous
`invoice_cancelled` Status. Conflicting Close
records remain separate evidence rather than being collapsed into settlement
truth. Completed and refunded Close records bind one locally verified,
persisted settlement or refund observation per leg, including its artifact,
view, policy, authority, finality, outcome, and effect-result digest. A funding
template, outpoint, or invoice digest alone is not settlement evidence, and a
Close must reference its signer's exact contiguous last-valid terminal Status.

## Verify before fund

`SwapSession<AwaitingVerification>` is the only state produced by creation or
restore. It can become `SwapSession<FundingAuthorized>` only after all of
these checks pass:

- the bilateral contracts and Quote remain bound to the same terms;
- local observed time is within the RFQ, Quote, reservation, and optional
  profile timeout after the bounded clock skew, and the reservation proof
  class, capacity commitment, allocation, and covenant inputs match the
  contract commitment;
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
Reverse funding additionally requires a typed local Lightning readiness
adapter. The resulting action binds the exact invoice, amount, network,
expiry, minimum final CLTV, maximum routing fee, and hold-invoice deadline.
Pending or held observations are accepted only after payment initiation is
durably recorded and gate reverse exit signing.
A refusal leaves funding unauthorized. The
authorization request is persisted as typed public metadata so the same
operation and crash-ready exit packages can be reconstructed after restart;
no authorization boolean is trusted. Restoring a snapshot revalidates its
signed records, full funding templates, exit packages, authorization request,
and effect ledger before it can resume the authorized typestate.

The RFQ comparison covers the ordered asset pair, exact or ranged amount, fee
cap, confirmation and replacement constraints, script mode, completion time,
invoice digest, payment hash, firm-Quote requirement, and requester spend
keys. The deterministic amount equation, `fee_bps`, provider fee, quoted rail
fees, and `floor_output_sats` rounding must reproduce the output for fixed and
selected amounts.

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

The client accepts only exact two-leaf hashlock-claim plus CLTV/CSV-refund
Taproot trees. It derives the cooperative internal key from distinct ordered
requester/provider wallet spend keys, which are separate from Nostr identity
keys, and binds the full raw funding transaction, derived txid, output, asset,
network, verifier digest, and confirmation policy. It executes the selected
leaf condition against the transaction and
witness: claims require the committed 32-byte preimage and signer; CLTV and
CSV refunds require the bound lock or delay and signer. Extra branches or
stack elements fail closed. The client assembles claim and refund transactions
but delegates signatures to a wallet or external signer callback. The request
includes the exact Taproot script-path sighash. It rejects a returned
transaction if the version, lock time, inputs, outputs, non-witness
serialization, script, control block, or exact witness shape differs from the
requested path. Pre-signed packages are restricted to timeout exits, pass the
same verification, require no key, and can be converted into a bounded public
Esplora `POST /tx` request by `KeylessEsploraExecutor`. Plaintext Esplora is
restricted to IPv4, IPv6, or `localhost` loopback; remote endpoints require
HTTPS.

External wallet, payment, and broadcast operations use deterministic effect
IDs. Snapshot schema v2 stores each bounded typed public request beside a
result row containing its exact request digest, external identifier, and
result digest. After restart, a matching funding or wallet-signing result
suppresses the callback and returns the prior operation; binding one effect ID
to a different request or result fails closed. Terminal rail and reverse
Lightning-disposition observations require the exact durable funding request
and effect. Their typed requests remain restorable in the crash window before
a Status, Cancel, or Close cites them. Recovery observations bind the session,
Order, and canonical per-rail digest before any action is selected.
Recovery is rail-specific. A reverse requester claims the destination output
when it is claimable. A chain requester claims
the destination first, waits while that output remains funded and unclaimed,
and refunds the source only when the destination was never funded or its
refund is final. Missing rail state becomes an explicit unresolved-loss
result; effect-ID sorting never determines recovery order.

Signed records may be appended after funding through the ingestion API. Exact
event replay is idempotent; changed bytes at an immutable `(kind, pubkey, d)`
address fail closed. Every append reruns role, session, Order, lifecycle,
Status, Close, recursive custody, and persisted-effect checks without dropping
the effect ledger. Recovery refuses completion on a gap, fork, invalid Status
ancestry, explicit loss, unknown rail state, or contradictory observations.
An unpaid-final invoice plus an unfunded reverse destination terminates as
cancelled instead of waiting indefinitely. A refunded reverse destination is
cancelled only with an unpaid-final invoice, waits only while payment is
pending and the counterparty is available, and otherwise reports explicit
loss.

## Custody boundary

Snapshots contain signed public records, exit templates or complete
pre-signed transactions, public commitments, and external effect results.
Recursive tripwires reject seeds, private or claim/refund keys, preimages,
macaroons, NWC connection strings, and signing nonces. Lightning node control,
wallet policy, secret generation, signing, broadcasting, chain indexing, and
finality remain outside Immortal.

NIP-59 transport also has callback APIs for event signing, NIP-44 encryption,
and NIP-44 decryption. The embedding identity service receives typed public
requests for the sender and one-time wrapper identities; it never gives
Immortal a secret key. `MarketSigner` remains a deterministic development and
fixture adapter for the same requests.

This client capability does not change relay admission or NIP-11. The relay
continues to advertise only its gated observable `mkt-swp:1` surface and keeps
the executable-profile set empty until the coordination-handler packet lands.

Run its native/no-default/WASM gate with:

```sh
./scripts/test-swp-verification.sh
```

The deterministic 62-case client corpus is
`tests/fixtures/nipmkt/swp-client-engine-v1.json`, backed by exact serialized
sessions in `tests/fixtures/nipmkt/swp-full-sessions-v1.json`. Its closed-world
replay executes the production client APIs for all six completed/refunded
flows, every requester topology, the bounded verification-refusal set,
sequencing, effect crash windows, cancellation, balanced loss, and recovery.
The 20 custody tripwires independently execute the recursive production
validator. The nameset and every expected error, result, and action are pinned;
drift fails replay on native and in the zero-import WASM probe. The probe-only
feature does not enter ordinary client or server builds. The full repository
gate is `./scripts/test-conformance.sh`.
