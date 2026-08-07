# MKT-SWP provider sessions

`immortal-provider` implements the provider role of MKT-SWP v1 without
granting the relay or the provider session library custody authority. The
transport-neutral engine accepts signed records and returns exact signing or
effect requests. The embedding process owns keys, transport, storage,
inventory, and any future rail access.

## Session contract

`ProviderDiscoveryFactory` constructs NIP-01-replaceable Provider Profile and
Offering requests. The caller signs the exact bytes and may rotate a public
head by reusing its `d` value at a later timestamp.

`ProviderSession` binds one requester, one provider, one Offering, and one
64-character lowercase-hex session ID. It accepts exact replay of an existing
event ID and rejects changed bytes or reuse of a protocol idempotency key. A
session has one RFQ, one Quote, one Order, and at most one Swap Contract per
signer. An Order must select an unexpired firm Quote with a soft or hard
reservation. Both Swap Contracts must contain identical complete terms.

The provider uses the requester engine's production validators for Quote
terms, RFQ constraints, timeout ladders, rail topology, reservation
commitments, and bilateral contracts. Every Quote constructor rejects an
amount, fee, policy, script, timing, invoice, key, or asset mismatch before it
returns signing bytes or invokes a hard-reservation callback. The provider
crate does not carry a second copy of those rules.
The three supported shapes are submarine, reverse, and chain swaps.

## Quote and reservation gates

Indicative Quotes carry `quote=indicative` and `reservation=none`. Soft Quotes
carry a complete signed reservation declaration. A hard Quote requires a
local `ReservationRequest` and an embedding callback. The Quote signing
request is returned only after the callback supplies a matching
`ReservationConfirmation`, including committed capacity and a durable proof
reference.

Reserve and release callbacks receive stable `ProviderEffectRequest` values.
The effect ID and request digest bind the session, reservation, operation, and
release cause. Exact replay returns the stored receipt; changed replay fails.
A hard reservation is released only after an effective cancellation, its
expiry, or a validated terminal Close. The embedding application performs the
durable release before the provider signs a release-dependent Close.

Reverse funding has an additional reserve gate. After the durable hard reserve
selects exact controlled UTXOs, the provider constructs and signs the funding
transaction, inserts its raw bytes, SHA-256 digest, and output index into the
destination verifier, and recomputes the leg verifier digest before returning
the Quote signing request. Both Swap Contracts therefore precommit the exact
transaction. Before broadcast, funded mode rebuilds it from the recovered
reserved inputs and fails closed unless the bytes still match; every later
chain observation must report the same committed transaction and output.

## Lifecycle and Close

Provider and requester Status streams remain independent. Gaps, forks, and
invalid transitions are retained in the projection and cannot silently
advance the session. Cancellation becomes effective only through the exact
request and acceptance references required by the client engine.

Pre-funding `cancelled`, `rejected`, and `expired` completion requires all
committed, recovered, received, fee, guarantee, and unresolved-principal
amounts to be zero. The Close names both assets, the exact released reservation
amount, no evidence references, and no unknown fields. Funded terminal outcomes
use the requester's general loss-accounting rules and require their bound rail
evidence.

Funded mode authors a signer-local terminal Close after its final
`completed`, `refunded`, or effective-cancellation path. A requester Close or
requester terminal Status does not release the provider reservation, retire
the provider actor, or exclude the session from provider recovery.

## Persistence and process boundary

Provider snapshots contain the configuration, signed records, reservation
confirmation, effect requests and receipts, and release state. They reject
unknown fields, recursive custody-material aliases, mismatched effects, more
than 512 signed records, more than 128 effects, and encodings larger than 2
MiB. Restore reruns signed-record, contract, lifecycle, and effect validation.

`immortal-provider --no-spend` uses signed provider-addressed NIP-59 recovery
wraps as its persistent history. Recovery and live ingestion are bounded and
idempotent. The process publishes discovery, answers complete RFQs, waits for
the requester's contract, countersigns identical terms, and closes mutually
cancelled submarine, reverse, and chain sessions. It never calls a funding,
wallet, node, payment, or broadcast API.

`IMMORTAL_PROVIDER_NO_SPEND_VARIANT` is an optional closed development-policy
selector. Its default preserves the normal no-spend Offering and 600-second
Quote lifetime. `demo_alternate` publishes a separately addressed Offering,
shortens the Quote lifetime to 420 seconds and the requested completion
promise by 120 seconds, and uses a distinct provider-signed reservation
disclosure. It does not alter frozen rail commitments, quote class, reservation
class, or settlement claims. Both variants remain firm/soft coordination-only
Quotes and terminate through bilateral cancellation with zero external spend.
The selector is for distinguishable local demo providers, not inventory or
price authority.

`scripts/dev-no-spend-demo.sh` supervises one disposable loopback relay and
two such provider processes. Its atomic
`openagents.immortal.no-spend-demo-manifest.v1` document exposes only public
connection and discovery data. `scripts/test-dev-no-spend-demo.sh` proves the
two signed heads and Quotes, restarts provider A after its Order while provider
B remains unchanged, and completes both sessions through bilateral Contracts,
accepted Status, mutual cancellation, and exact zero-spend Close records.

Funded mode adds a provider-owned Postgres database, a mode-0600 operator seed
file, dynamic hard reservations, bounded bitcoind and Core Lightning clients,
transaction construction, script-path settlement, and a polling watchtower.
The same binary starts it with `immortal-provider run`; `--no-spend` retains
the zero-rail rehearsal mode.

Submarine RFQs bind the requester-created invoice before the provider signs a
Quote. Reverse Quotes bind a provider-created hold invoice. Chain capacity is
reserved by exact controlled UTXOs; Lightning capacity is reserved from the
node's public balance response. The provider database stores only signed
records, public commitments, reservations, UTXO observations, transaction
artifacts, watch jobs, results, and alerts. Seeds, private keys, unreleased
preimages, RPC credentials, and node credentials are excluded by both the API
and database constraints.

Reverse Quote construction reads the synchronized `getinfo.blockheight` from
CLN and uses it with the invoice's minimum final CLTV delta to derive the
signed minimum acceptable shortest incoming-HTLC expiry. The payer may choose
a later expiry. The bitcoind and CLN heights must be ordered and within the
configured reorg-safety margin, and CLN must name the configured network.
Before publishing `lightning_htlcs_held`, the provider checks every observed
HTLC's state, amount, and expiry. Bitcoind remains authoritative for refund
heights and transaction confirmation.

Temporary CLN/bitcoind height skew defers Quote construction under a bounded
poll; it does not reject the requester's RFQ. An invalid held-HTLC set is
cancelled through signed `invoice_cancel_pending`, `invoice_cancelled`, and
`expired` statuses. Its reservation is released after the cancellation effect
is durable. A hold invoice that settled before cancellation instead marks the
reservation and session unresolved.

Signed height members are exclusive deadlines. Submarine funding and claim,
and both reverse hold/funding gates, stop when bitcoind height is equal to or
greater than the signed bound. A pre-funding reverse expiry enters the durable
invoice-cancellation path instead of funding. After a final cooperative
requester claim, the provider settles or reconciles the hold invoice and marks
the competing refund watch complete as `claim_settled`; a provider refund or
replacement remains on the refund path.

The process-level client actor uses `SwapSession` to reconstruct both signed
contracts, parses the contract-bound requester `ExitPackage`, and completes
verify-before-fund before publishing the requester authorization Status. It
also ingests the final provider Close, so a rail result without valid terminal
protocol accounting cannot pass the funded gate.

Bitcoin funding inputs use a non-RBF sequence while retaining locktime
semantics, matching the signed replacement policy. v1 executes Taproot
script-path claim/refund only. It excludes ZMQ, LND, MuSig2 key-path
execution, outbound price feeds, non-Bitcoin rails, and inventory strategy.
The separate deterministic machine surface is documented in
[`provider-contract.md`](provider-contract.md).

This provider runtime does not change the relay binary, relay contract JSON,
relay NIP-11 document, or relay executable-profile set.

## Zero-confirmation provider policy

Zero-confirmation execution is off by default and applies only to explicitly
enabled requester-funded Bitcoin source directions: submarine and Bitcoin-
source chain swaps. Reverse funding, provider-funded destination legs, and
Liquid remain confirmation-gated. An enabled policy requires a per-swap cap
and a durable aggregate in-flight cap.

The Quote signs `zero_confirmation=allowed`, `rbf=reject`, and
`replacement=track`. Admission re-parses the exact contract-bound funding
transaction, checks every input sequence, and reads `getmempoolentry` from the
provider's own loopback bitcoind. The transaction must be non-replaceable,
have `ancestorcount=1`, and have an empty `depends` set. Before publishing
`funding_zero_conf_accepted` or `source_funding_zero_conf_accepted`, the
provider atomically reserves the amount in the `zero-conf-risk-btc` capacity
bucket under a deterministic derivative of the market session ID. This keeps
the exposure reservation distinct from the session's hard Quote reservation
while preserving restart-safe aggregate accounting.

Acceptance remains at the `funding_observed` base state and never projects
finality. The Status binds the transaction, output, amount, exact input
outpoints, policy ID, and `provider_local_bitcoind` view. The provider waits
through the acceptance timestamp and rechecks before a Lightning payment or
chain destination funding effect. Replacement, competing spend, mempool
loss, or an unconfirmed ancestor produces `funding_confirmation_required` or
`source_funding_confirmation_required` with a closed reason. Pre-effect
exposure is released during that downgrade; requester verification, refund,
and confirmation rules are unchanged.

## Conformance

`tests/fixtures/nipmkt/swp-provider-engine-v1.json` is a closed 30-case
manifest. It covers discovery, all three no-spend flows, hard-reservation
outcomes and replay, release causes, Status observations, evidence references,
custody rejection, bounds, duplicate Order/contract refusal, and indicative
Quote selection refusal. The provider integration test also reconstructs each
completed history through the requester engine and validates the negotiated
terms.

`tests/fixtures/provider/provider-runtime-v1.json` is the executable funded
runtime gate. Unit tests replay its invalid held-HTLC amount/state/expiry
cases, exact and one-past exclusive height boundaries, cancelled hold state,
and cooperative reverse refund-watch retirement through the production
transition helpers. Its exact bytes and digest are bound by
`provider-contract-v1.json`.

`tests/fixtures/provider/zero-conf-v1.json` pins the disabled default,
direction gates, cap bounds, local mempool admission, durable risk bucket,
Status vocabulary, client-safety boundary, and the three adversarial process
cases. The adversarial manifest runs replacement, non-RBF competing-spend,
and ancestor-invalidation attacks and requires confirmation-required without
a provider settlement effect.

Run the native, no-default, and zero-import WASM proof with:

```sh
./scripts/test-swp-verification.sh
cargo test --locked -p immortal-provider --lib provider_runtime_fixture
./scripts/export-provider-contract.sh --check
```

The disposable bitcoind/CLN funded process gate is
`scripts/test-provider-funded.sh`. Its three-journey result is pending; the
unit and contract gates above do not replace it.
