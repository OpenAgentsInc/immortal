# MKT-SWP Coordination Handler

Immortal has one optional `mkt-swp-coordination:1` handler in the existing
binary and Postgres database. It is disabled by default. It accounts for
provider-signed reservations, exposes Status gaps and forks, releases expired
reservation rows, and publishes bounded relay observations of public Bitcoin
transaction evidence. It has no wallet, balance, rail credential, or
settlement authority.

## Activation and advertisement

The handler activates only when all three conditions hold:

1. `IMMORTAL_RELAY_URL` is configured;
2. `IMMORTAL_RELAY_SECRET_KEY` configures the handler recipient and
   observation signer; and
3. `IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256` exactly matches the
   compiled digest over the coordination fixture, migration 0011, and the v1
   configuration schema.

Read the required digest from
`immortal contract | jq -r .mkt.mkt_swp.coordination.conformance_sha256`.
There is no boolean enable flag and a stale digest fails startup. The optional
`IMMORTAL_MKT_SWP_COORDINATION_SWEEP_SECONDS` is 30 by default and must be
between 1 and 3,600.

Only this active configuration adds NIP-32 and
`mkt-swp-coordination:1` to NIP-11. The existing `mkt-swp:1` extension still
describes the relay-observable wire grammar; it does not imply that this
handler is active.

## Delivery and durable boundary

A participant sends the handler an additional independently randomized NIP-59
wrap addressed to the relay signer. Counterparty and recovery deliveries use
their own wraps. The handler unwraps and validates the exact signed private
record in memory, applies the explicit MKT-SWP v1 profile registry, rejects
custody-member tripwires, and drops decrypted bytes before calling the store.

Migration 0011 stores only signed event and wrap identifiers, participant and
session identifiers required for attribution, bounded accounting fields, and
public-artifact hashes. It has no content, raw transaction, seed, preimage,
private-key, nonce, macaroon, NWC, invoice credential, or wallet column. The
outer wrap follows normal durable admission. Handler state commits before a
successful `OK`; a retry of an already stored wrap reruns the idempotent
handler transaction.

## Reservations

An indicative `reservation=none` is recorded without consuming capacity; a
firm Quote cannot disable reservation. A `soft` or `hard` reservation must be
a firm Quote and must supply a provider-local bucket, asset ID, decimal amount,
increasing allocation sequence, commitment digest, proof reference, and
expiration. Because the base MKT-SWP commitment deliberately does not disclose
total capacity, this handler extension additionally requires the private
`handler_committed_capacity` canonical-decimal member. It is covered by the
provider signature, visible only inside the handler-addressed gift wrap, and
does not alter the base MKT-SWP wire contract. The effective
deadline is the minimum of NIP-40 Quote expiration, reservation expiration,
and the optional profile timeout.

The handler serializes writers with Postgres advisory locks and enforces:

```text
sum(unexpired active reserved_amount for provider, bucket, asset)
    <= signed handler_committed_capacity
```

Every new claim must strictly increase the provider-bucket allocation sequence
and use a new commitment digest, because the commitment binds that sequence and
the then-current active set. Reuse of a reservation ID is retained inactive as
`swp_idempotency_conflict`; a repeated, decreasing, or digest-reusing
allocation is retained inactive as `swp_reservation_fork`. A claim that would
exceed its signed handler capacity or 1,024 active rows is retained inactive as
`swp_reservation_overallocated`. Exact Quote replay returns its current result,
including `swp_reservation_expired` once its deadline passes.

Reservation IDs are provider-wide, so their advisory lock precedes the bucket
lock and prevents cross-bucket races. The 1,024-row bound is also bucket-wide;
the reserved-amount inequality remains scoped to provider, bucket, and asset.

The proof-class order is provider-signed (10), handler-accounted (20),
third-party guarantee (40), Lightning liquidity (50), UTXO control (60),
funded HTLC (80), and covenant reserve (100). Covenant reserve is the
strongest hard-reservation class: the input binds its funding reference,
program, eligible-fill, minimum-output, fee-rule, expiry, and verifier-view
digests. `covenant.funding_ref` is a canonical lower-hex Bitcoin outpoint. The
handler hashes it as the reserve-unit identity,
locks it across every bucket and relay process, and refuses a second active use
even when the caller-selected `proof_ref` differs.
The class and strength express the claimed proof policy. The v1 handler checks
the bound input and double-use rules; it does not operate a chain index or
independently claim that an arbitrary covenant is safe or unspent.

Immortal does not expose an output orderbook. Price changes remain signed
Quote changes and never require the relay to spend an output.

## Status projection

The store retains up to eight signed Status events at each sequence from 0
through 4,095. `mkt_swp_status_view(session, order, author)` returns all event
IDs grouped by sequence, every missing sequence, and every duplicated
sequence. Arrival order never selects a winner. The query is ordered and
bounded to 32,769 rows, one more than the maximum valid stream, so corrupt or
unbounded state fails closed.

## Timers

Each sweep locks and releases at most 1,000 due reservations with
`FOR UPDATE SKIP LOCKED`. Its only mutation is `active=true` to `active=false`
plus release time and reason. It never signs participant records, publishes a
participant Status, cancels, accepts, closes, claims, refunds, pays, or
settles. Two relay processes may sweep the same database; row locking makes
the release idempotent.

## Public evidence observations

The v1 public hook accepts at most eight measured Bitcoin transaction entries
per handler record and 16 KiB per raw transaction. It parses transaction
bytes with the issue-#10 primitive, checks the txid and SHA-256, and drops the
bytes before storage. Immortal then publishes a relay-signed kind-1985 NIP-32
label in namespace `openagents.mkt-swp.observation`, labeled `measured` and
`observation_not_authority`.

The public event contains the rail reference, artifact and view hashes, hook,
and observation time. It omits the private source event ID, session, order,
counterparty, and amount. The private observation ledger preserves the source
link for idempotency. An observation means the handler parsed the submitted
artifact under the named view; it is not payment, finality, covenant safety,
or settlement authority.

## Conformance

`tests/fixtures/nipmkt/swp-coordination-v1.json` pins activation, bounds,
proof-class order, reservation conflicts, timer limits, dense Status views,
public observation privacy, and custody tripwires. The live process proof runs
two independently connected relay processes against one Postgres, races
capacity claims across them, compares their Status projections, and proves
idempotent timeout release. This test is part of `scripts/test-postgres.sh`
and the complete local `scripts/test-conformance.sh` gate.
