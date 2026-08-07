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

`SwapRecordFactory::requester_order` validates the signed Quote against the
exact RFQ and applies the minimum of the Quote, reservation, and profile
acceptance deadlines to a trusted local observation time supplied separately
from the untrusted event `created_at`. Draft and final Contract operations
reuse that timely Order observation; a Contract arriving after the Quote
deadline remains valid because Contracts do not expire. Indicative Quotes fail
closed at this execution API. `requester_contract_draft` accepts typed public
effect and exit-package inputs, binds Quote terms, selections, causal IDs, and
the reservation proof commitment; the wallet adds its executable funding and
exit bindings, then `requester_contract` revalidates the RFQ, Quote, Order,
complete Contract, and requester topology before returning a signing request.
The funded lab uses this public path rather than a private fixture Contract.
When a requester-funded Bitcoin or Liquid source transaction does not exist at
Quote time, `RequesterContractLocalInputs::funding_resolution` supplies the
exact transaction bytes, lowercase SHA-256, and output index after the Order.
Those are the only admitted additions: the composer re-derives the source
verifier digest and rejects replacement of a commitment already in the Quote.

`RequesterSessionView` is the custody-free consumer projection. Its versioned
schema exposes asset IDs, canonical amounts, fee equation and payer, rounding,
the complete optional pinned-feed tuple, structural causal references,
independent Status gap/fork lanes, typed terminal/loss state, Close conflicts,
and a Contract-terms verdict. Local verify-before-fund remains mandatory and
the view never reports funding authorization. Timeline order follows protocol
phase and per-author sequence with event-ID tie-breaks; `created_at` remains
display data. Each record requires exactly one `SignedRecordDelivery`.
Receipts retain the exact domain-validated signed bytes, trusted observation
time, sender, and direct, local, or gift-wrap provenance. Gift-wrap receipts
also bind the complete validated outer event bytes and ID. Their constructors
accept only locally signed bytes, exact direct bytes, or the non-forgeable
result of the transport unwrap operation.
The funded lab stores the receipt archive beside the client snapshot, records
both artifact paths in every restartable checkpoint, and re-decrypts archived
gift wraps before restoring the requester view. Restore accepts a receipt only
when the reconstructed delivery equals the complete archived object, including
the inner signed bytes, outer wrap bytes and ID, sender, provenance, and
observation time.

The requester projection exposes a signed Quote's `price_feed` pin for
inspection. Order construction rejects every non-null pin with
`swp_price_feed_unsupported` until MKT-SWP specifies the deterministic formula
that maps the pinned observation to the signed amounts. A URL and response
digest alone are not an amount-verification rule.

The versioned `swp-requester-api-v2.json` artifact publishes exact schemas for
Order, Contract draft, Contract signing, signed-only session projection, and
session projection from a bounded persisted snapshot. Its cases resolve pinned
JSON pointers into operation-shaped inputs, validate each input before
dispatch, and validate the actual output or error against the operation's
closed schema. Every operation has positive and negative cases replayed by
both the native and WASM fixture probes. The relay contract descriptor names
this artifact and version so SDK generation does not infer an API from Rust
source. Delivery inputs use lowercase even-length `raw_signed_event_hex`, with
a 65,536-character limit encoding the MKT private-record limit of 32,768 exact
bytes. Snapshot inputs use `snapshot_json_hex`, capped at 4,194,304 lowercase
hex characters for the runtime's 2,097,152-byte limit. Hex makes those byte
bounds identical under draft-2020-12, Rust, and JavaScript string semantics;
the corpus includes a signed multibyte UTF-8 event and a multibyte terminal
snapshot parity check. Retained outer gift-wrap bytes remain bounded to
524,288 bytes. Schema replay implements exact-one `oneOf` and rejects
unsupported keywords. The exported boundary further limits arrays to 512
items and JSON integers to the signed 64-bit maximum; the Rust runtime's wider
internal integer range is not part of this versioned SDK surface.

The published v1 bytes remain frozen for reproducibility, but v1 is withdrawn
for SDK generation. It exposed generic external-effect result rows as an input
surface, which could turn caller-authored rows into terminal authority. V2 has
no such operation: terminal authority is available only through the restored
snapshot operation after typed request/result and funding-ledger validation.
The v2 corpus includes signed-only and restored terminal views, digest,
cardinality, and funding mutations, and non-null price-feed refusal at every
public operation.

OpenAgents issue #9309 still pins Immortal commit `15e77e0` and does not yet
consume a requester API artifact. Its re-pin and v2 adoption follow the pushed
Immortal artifact; until then, the v2 contract is an Immortal export and not a
claim that the downstream Effect package already generates this surface.

Signed Status and Close records remain counterparty claims. The signed-only
session operation can project a claimed terminal state, but it keeps
`watch_terminal` and `local_effects_verified` false and never reports
`terminal_verified`. The restored-snapshot operation reruns session, lifecycle,
typed request/result cardinality and binding, post-funding, and loss-accounting
validation before those fields can become true. External effect result rows
are serialize-only opaque values: callers provide only adapter outcome
metadata, while the session derives their Order, effect, and request bindings.
Snapshot consistency is the library proof. Durable storage and the local
origin of that snapshot remain responsibilities of the trusted embedding
wallet and are not presented as cryptographic attestation.

## Executable browser ABI

`crates/immortal-client-web` is the ordinary `wasm32-unknown-unknown` artifact
for the production requester engine. It wraps
`immortal_client::browser_api::dispatch`; it is not a TypeScript rewrite and
does not use the fixture probe. The dependency-free adapter is
`adapters/immortal-client-web/adapter.mjs`, with declarations beside it.

Requests and responses use
`openagents.immortal.mkt-swp.browser-abi.v1`. Every request carries ABI version
1, one closed operation name, and one closed input object. The artifact accepts
at most 2 MiB and emits at most 8 MiB. It crosses bytes through
reset/push/invoke/length/byte exports,
so no raw linear-memory pointer becomes an ABI contract. Its WebAssembly
module has no imports. Metadata pins the ABI, the exact requester API v2 digest,
and `IMMORTAL_SOURCE_REVISION` from the build; an embedding may require both
digests and the source revision before making any operation available.

The operations validate public Offerings and exact direct/local delivery
bytes; verify externally signed records; construct RFQ, Order, requester
Contract, Cancel, and Close signing requests; compose Contract drafts; inspect
and digest-bind exit packages; create, ingest, persist, and restore requester
sessions; prepare a typed funding request only after the production
verify-before-fund checks; and cross the funding-authorized transition only
when the host returns that exact prepared request unchanged. Preparation
deliberately refuses the internal wallet callback after capturing the request,
so it cannot persist or execute an authorization.
Entropy, Nostr signing and wrapping, relay transport, durable snapshot storage,
wallet actions, rail observations, secrets, and node credentials remain host
capabilities. Gift-wrap decryption uses the existing callback transport API;
the browser ABI receives its exact validated inner bytes as a delivery.

The machine contract is
`tests/fixtures/nipmkt/swp-browser-abi-v1.json`. Run the compiled-WASM gate and
the live no-spend process gate with:

```sh
./scripts/test-client-browser-abi.sh
IMMORTAL_PROVIDER_LIVE_RELAY_PORT=18134 ./scripts/test-dev-market-provider.sh
```

The live gate invokes the exact exported wrapper functions (compiled natively
for the process test) and drives all three swap shapes through a real loopback
relay and provider, including bilateral Contracts, mutual zero-spend
cancellation, zero-loss Close, snapshot restore, and idempotent signed-record
replay. The Node gate independently proves those same wrapper functions in the
actual zero-import WebAssembly artifact.

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

Liquid submarine, reverse, and BTC/L-BTC chain sessions use
`LiquidVerifyBeforeFundInput`. The engine binds the exact ordered assets,
funding transaction digest and bytes, output, pegged asset, amount, script,
Taproot commitment, confidentiality mode, confirmation policy, and unilateral
exit-package digest to both signed Contract records. Confidential outputs are
accepted only through `verify_before_fund_with_liquid`'s local-elementsd
unblind adapter; callers cannot inject `trusted_unblind_transaction` into this
production path. The exact local genesis hash, network, pegged asset, selected
output, funding digest, and unblind-result digest are retained as typed public
provenance. A refund may retain a complete presigned transaction. A hashlock
claim retains only a `wallet_sign` template, deterministic effect ID, and
non-secret signer/preimage-recovery reference; the unreleased preimage never
enters the package, authorization request, snapshot, or effect ledger.
The recovery decoder accepts an optional `taproot_tree` only when it equals the
complete bilateral verifier tree. All other unknown members fail closed.

Liquid-source submarine and chain flows produce `BroadcastLiquid` with the
exact transaction ID and output index bound by the Contract; reverse flows
still produce the exact Lightning invoice action after Liquid lock
verification, and BTC-to-Liquid chain flows produce the Bitcoin source
broadcast only after the Liquid destination and its claim exit verify. For a
BTC-to-Liquid chain, that preflight requires local elementsd mempool acceptance
of the exact signed, unbroadcast destination template at zero confirmations;
the ordinary reverse counterparty lock still requires the signed confirmation
policy. A Liquid-to-Bitcoin chain verifies the exact Bitcoin destination
template in the same authorization. Both destination checks precede
`source_funding_required`; the provider broadcasts the already-verified
destination only after source finality. Restore reruns the bilateral term,
package-commitment, effect, provenance, destination, fee-policy, broadcast-
window, and exact-genesis bindings before it can recover `FundingAuthorized`.
Recovery selects the typed Liquid package by leg and path; a claim invokes the
local secret-store/wallet callback and validates the returned witness before
broadcast. A presigned refund exposes an exact `LiquidBroadcastRequest`
immediately, while a wallet claim exposes one only for the verified signed
transaction. Both pin `sendrawtransaction`, the local-elementsd network and
full genesis, the signed-transaction digest, and an opaque reference to the
dedicated private broadcast artifact. The executor loads the exact bytes from
that artifact and verifies the digest before RPC. The generic effect recorder
rejects Liquid broadcasts; its typed recorder resolves the opaque reference,
checks the signed transaction and digest, and derives the transaction ID and
result digest from those bytes. A crash after `sendrawtransaction` but before
effect recording therefore reloads the retained artifact without signing or
overwriting it. Wallet signing is not an effect result; recording the
digest-bound broadcast request makes restart replay idempotent.
The exit destination is inside the committed package and is
re-derived from those transaction bytes. It is not added as an unquoted
verifier member. Snapshots retain no signed claim transaction, claim witness,
preimage, unblinded transaction bytes, blinding key, value blinder, asset
blinder, or spend key.

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

Each verifier may expose a generic provider-selected `exit_path` alongside
`claim_script`/`refund_script` and their path-specific control blocks. The
generic fields must agree with their declared tree leaf, while requester exit
packages select their own path-specific fields: chain source refund and chain
destination claim. The canonical chain source refund is CLTV, matching the
provider Quote topology and the pre-signed requester exit.

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
Liquid legs are chain-like recovery rails: their canonical binding carries the
funding digest, output, amount, script, confirmation policy, expected
unfunded-destination identities, and deterministic claim/refund effect IDs.
Their Section-12-shaped recovery package is represented by its dedicated
typed funding binding rather than a Bitcoin `ExitPackage`. Its `broadcast`
member uses the local-elementsd method/network/genesis binding in place of a
Bitcoin Esplora endpoint allowlist.
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

The deterministic 64-case client corpus is
`tests/fixtures/nipmkt/swp-client-engine-v1.json`, backed by exact serialized
sessions in `tests/fixtures/nipmkt/swp-full-sessions-v1.json`. Its closed-world
replay executes the production client APIs for all six completed/refunded
flows, every requester topology, the bounded verification-refusal set,
sequencing, effect crash windows, cancellation, balanced loss, and recovery.
The 23 custody tripwires independently execute the recursive production
validator. The nameset and every expected error, result, and action are pinned;
drift fails replay on native and in the zero-import WASM probe. The probe-only
feature does not enter ordinary client or server builds. The full repository
gate is `./scripts/test-conformance.sh`.
