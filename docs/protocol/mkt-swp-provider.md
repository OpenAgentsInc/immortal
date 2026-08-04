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

## Lifecycle and no-spend Close

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

Issue #25 adds funded rails, a provider database, wallet and watchtower, and a
separate deterministic provider contract export. This packet does not change
the relay binary, relay contract JSON, relay NIP-11 document, or relay
executable-profile set.

## Conformance

`tests/fixtures/nipmkt/swp-provider-engine-v1.json` is a closed 30-case
manifest. It covers discovery, all three no-spend flows, hard-reservation
outcomes and replay, release causes, Status observations, evidence references,
custody rejection, bounds, duplicate Order/contract refusal, and indicative
Quote selection refusal. The provider integration test also reconstructs each
completed history through the requester engine and validates the negotiated
terms.

Run the native, no-default, and zero-import WASM proof with:

```sh
./scripts/test-swp-verification.sh
```
