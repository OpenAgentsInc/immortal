# Immortal Roadmap

The order of work. Each milestone lands with its fixtures and leaves the
build green. Rules live in `AGENTS.md`; NIP sources live in `nips/`;
external-project reviews live in `docs/inspiration/`.

## M0 — Foundation (done)

- [x] Repo, license (CC0), README, AGENTS.md doctrine
- [x] Compiling Cargo skeleton, edition 2024
- [x] NIP source lanes and sync script (`nips/`, three pinned upstreams)
- [x] First inspiration review (nostr-rs-relay)
- [x] Deployment docs (`docs/deployment/`)

## M1 — Domain (`src/domain/`) (done)

The NIP-01 primitives, written from `nips/official/01.md`, with fixtures.

- [x] Event type, tag model, single-letter tag indexing rule
- [x] Canonical serialization and event ID (SHA-256)
- [x] Schnorr signature verification (secp256k1)
- [x] Filter model and matching (ids, authors, kinds, tags, since, until,
      limit) — no prefix matching
- [x] Classification: regular, replaceable, ephemeral, addressable;
      replacement address; expiration (NIP-40)
- [x] Deletion semantics (NIP-09), including deletion-before-event
- [x] Timestamp bounds (reject far-future events)
- [x] Fixture corpus: known event IDs, filter cases ported from
      nostr-rs-relay tests (MIT, attributed), replacement and deletion
      races

## M2 — Store (`src/store/`) (done)

Postgres owns everything. One admission transaction.

- [x] Schema migration files (versioned .sql, applied in a transaction)
- [x] Tables: `nostr_event` (with `ingest_seq`), `nostr_indexed_tag`,
      `replaceable_head`, `deletion_tombstone`, policy tables
- [x] Admission transaction: dedup, replacement compare-and-set,
      tombstones, policy, tag rows, `ingest_seq`, `NOTIFY`
- [x] Compound indexes for the NIP-01 access patterns
- [x] FTS: generated tsvector column + GIN index (for NIP-50 later)
- [x] Admission policy pipeline: allow/block lists for kinds and
      pubkeys, closed-membership mode, content-size, tag-count, and
      timestamp bounds — all configurable
- [x] Prepared statements only; least-privilege role documented

## M3 — Gateway (`src/gateway/`) (done)

The WebSocket protocol server.

- [x] WS handshake + NIP-11 document on HTTP GET
- [x] NIP-01 message flow: EVENT, REQ, CLOSE, OK, EOSE, CLOSED, NOTICE
- [x] NIP-42 per-connection challenge state
- [x] `SubscriptionIndex` (by id, author, kind, tag) — no linear scans
- [x] Race-free EOSE: buffer live events during the historical query,
      deduplicate, flush after EOSE
- [x] Ephemeral lane (kinds 20000–29999): in-process + `NOTIFY`, never
      stored
- [x] Limits: frame size, event bytes, subscriptions per connection,
      filters per REQ; per-IP and per-pubkey rate limits
- [x] Query cancel on client disconnect; bounded per-connection send
      queues; graceful shutdown

## M4 — Conformance (done)

- [x] Per-NIP fixture suite wired into the local conformance command; every
      M1–M3 behavior covered
- [x] Multi-process proof: two processes, one Postgres — cross-delivery,
      `ingest_seq` gap catch-up, kill-one chaos, fail-closed on gap
- [x] Load proof with published numbers (events/sec, connect p99,
      REQ-to-EOSE p99)

## M5 — Deployment kit (done)

- [x] Single-box acceptance: fresh Debian + apt Postgres + binary =
      running relay in minutes, README-only
- [x] Hardened systemd unit, nginx and Caddy snippets, backup and
      restore procedure, upgrade and rollback procedure
- [x] Runbooks final (`docs/deployment/`): Debian VPS, DigitalOcean,
      Google Cloud

## M6 — NIP expansion (done)

In order, each with fixtures before the next starts. The order puts the
items a production deployment depends on first, so M9 becomes reachable
as early as possible.

- [x] NIP-40 expiration sweep (scheduled delete + query-time exclusion)
- [x] NIP-70 protected events (with NIP-42 state)
- [x] NIP-17 private-message delivery gating: store gift wraps
      (kind 1059) but serve each only to its `p`-tagged recipient;
      honor kind 10050 relay lists
- [x] NIP-29 relay-managed groups: `h`-tag scoping, membership
      enforced before store, moderation kinds 9000–9010, join 9021 and
      leave 9022, relay-signed group metadata 39000–39005
- [x] NIP-86 relay management API (HTTP, NIP-98-authenticated) for
      policy and group administration without direct SQL
- [x] NIP-45 COUNT (bounded)
- [x] NIP-50 search (the FTS column from M2)
- [x] NIP-65 relay-list handling notes
- [x] Watch: NIP-77 (negentropy sync), NIP-91 (AND filters — implement
      when stable upstream)
- [x] `nips/block/` and `nips/openagents/` lanes: per-NIP owner decision,
      official lane wins on identifier conflict
- [x] Block agent identity and turns: NIP-OA owner attestations, NIP-AA
      agent authentication, NIP-AO ephemeral observer routing, and NIP-AM
      owner-private turn metrics
- [x] Block stored data: NIP-AE encrypted engrams, NIP-AP private/shared
      personas and team catalogs, NIP-ER lazy encrypted reminders, and NIP-MP
      project validation
- [x] Block relay commands and derived state: NIP-IA identity archival,
      NIP-DV DM visibility, and NIP-WP workspace profile icon
- [x] Block relay semantics: NIP-CW safe WebSocket degradation with relay-only
      overlay kinds, NIP-RS addressable read state and race-free full-state
      barrier, and NIP-GS's explicitly client-side Git signatures
- [x] NIP-PL public-envelope/auth/ACL handler fails closed while no executor
      key, lease descriptor, or push transport is configured or advertised;
      no second service was added

## M7 — Media

- [x] Blossom endpoint (NIP-B7, NIP-98 auth, NIP-94 metadata): filesystem
      storage default, one optional cloud-storage adapter

## Immediate program — protocol totality and noncustodial markets

**Owner directive, 2026-08-04:** implement every specification pinned under
`nips/official/`, `nips/block/`, and `nips/openagents/`. This program starts
now and runs alongside M8 and M9; those milestones are not prerequisites.
Earlier per-NIP deferrals and phrases such as “client-only,” “not currently
advertised,” or “compatibility-only” describe a deployment state or the
correct surface, not a permanent exclusion from implementation.

Product vocabulary follows OpenAgents Episode 213: this work delivers the
**OpenAgents Liquidity Market**, one of five interlocking Agent Markets. The
shared protocol layer is the NIP-MKT negotiated-market fabric; the first
technical system is a multi-provider noncustodial Bitcoin liquidity network.
It is not limited to a decentralized exchange and does not pool funds.

“Every” means every applicable role, not dishonest NIP-11 advertising. A
relay protocol gets domain and server handlers; a client protocol gets the
transport-neutral native/browser client behavior; operator, provider, and
executor profiles get bounded one-binary handlers where the specification
requires them. Each lands with a pinned decision, fixture corpus, negative
cases, live contract where applicable, documentation, and manual conformance.
Only behavior executable under the active configuration is advertised.
Deprecated or unrecommended NIPs—including NIP-90—receive complete pinned
compatibility and regression coverage, while new products use focused
successor microstandards.

- [ ] Build a generated three-lane implementation ledger: every pinned file,
      role, event kind/message, dependency, privacy law, authority, current
      coverage, missing handler, fixture, and advertisement condition
- [ ] Finish the complete official lane, including relay, HTTP, client,
      encryption, discovery, wallet, payment, media, sync, and compatibility
      surfaces supported by the pinned texts
- [ ] Finish the complete Block lane, including the optional NIP-CW HTTP
      profile and a fully executable NIP-PL lease/decryption/dispatch path in
      this binary; retain fail-closed non-advertisement until each is usable
- [ ] Finish the complete OpenAgents lane, including the five hardening
      families and NIP-BT after the first liquidity slice; the earlier BT
      postponement is sequencing, not cancellation
- [ ] Draft, review, pin, and implement focused OpenAgents market NIPs:
      negotiated-market base plus atomic-swap, P2P, credentialed-PFI,
      mint/federation, LSP, and later risk/guarantee profiles; do not extend
      NIP-90 for new market semantics
- [ ] Absorb the noncustodial Boltz/tbDEX surface: provider profiles and
      discovery, Offering/RFQ/Quote/Order/Status/Close, signed quote
      reservation, multi-provider routing, privacy and credential policy,
      script/invoice verification, chain/LN evidence, timeout/refund
      recovery, monitoring, disputes/recourse, and Boltz REST/WebSocket plus
      tbDEX message compatibility where interoperability justifies it
- [ ] Prove browser and native clients, at least two independently keyed
      providers, multiple relays, partitions, crashes, duplicate/conflicting
      messages, reorg/RBF, noncooperation, refund, and secret-leak rejection
      in a manual adversarial regtest lab

The noncustodial boundary is strict but deliberately ambitious. Immortal may
compute, validate, index, coordinate, route, reserve signed provider capacity,
run timers, publish relay-owned derived state, and automate recovery. It may
hold only relay/operator keys and encrypted coordination state required by a
pinned protocol. Spend authority, user/LP balances, wallet seeds, private
claim/refund keys, unreleased preimages, NWC secrets or node macaroons, bank
credentials, and final settlement authority remain with clients, providers,
or the underlying rail. All of this still obeys one binary, one Postgres,
prepared SQL, bounded work, fail-closed operation, and no GitHub workflows or
GitHub-billed automation.

## M8 — Hardening and formal work

- [ ] Formal model of the admission/replacement/deletion state machine;
      checker run in the local conformance suite; counterexamples become
      fixtures
- [ ] Fuzzing on the wire parser and filter matcher
- [ ] Long-run soak: memory, connection churn, Postgres bloat,
      `NOTIFY` storm behavior
- [ ] Security pass against the AGENTS.md rules; publish the results

## Operation Diamond Hands

**Stood down by owner direction on 2026-08-04.** Do not publish program records,
deploy `/dh`, or continue Phase 1 without a new owner decision. The generic
OT/PG validation, NIP-11-pinned client, bounded signer, browser transport, and
GPUI/wasm build infrastructure remain available for unrelated future use.
NIP-BT credits remain postponed for this stood-down program and the first
liquidity slice; they remain part of the full OpenAgents-lane target above.

### Phase 0 — read-only project surface

- [x] Adopt and fixture the NIP-OT Organization (`32100`) and NIP-PG Project
      (`32222`), Project Status (`32223`), and Project Update (`32226`) read
      contract from the pinned OpenAgents lane
- [x] Expose one transport-neutral client core from the existing crate, with
      the server-only Tokio/Postgres closure behind the default `server`
      feature
- [x] Build bounded direct-relay filters, local event ID/signature checks,
      EOSE snapshot/live folding, deterministic replacement selection,
      reconnect/stale states, malformed-event exclusion, and forward-
      compatible unknown project activity
- [x] Prove the library natively and on `wasm32-unknown-unknown` with a manual
      local command; no GitHub workflow or billed runner
- [ ] Cancelled: deploy the completed local WebSocket adapter and `/dh`
      GPUI/wasm artifact (issue #1 closed by stand-down)

### Phase 1 — joinable project

- [ ] Cancelled: select and implement a contributor admission path
- [ ] Cancelled: add project-specific identity, publication, read-after-write,
      rollback, and public runbook work (issue #2 closed by stand-down)

## M9 — Drop-in replacement kit

Everything an operator needs to replace an existing production relay with
Immortal behind the same hostname, with no client changes. Can start once
M6 reaches the NIP-29 item; does not wait for M7 or M8.

- [ ] Signed-event bulk import: JSONL in, idempotent, preserves ids and
      signatures, replays replacement and deletion rules in `ingest_seq`
      order
- [x] nostr-effect compatibility import: explicitly enabled, bounded prepared
      reads from its existing `public.events` table; cryptographic,
      replacement, deletion, and policy checks; historical-only bypass for
      extension/group rules the source never enforced; durable per-event
      ledger; startup drain plus bounded tail sweeps during a traffic cutover
- [ ] NIP-11 parity configuration: name, description, pubkey, limits,
      and supported-NIP list fully operator-configurable
- [ ] Policy parity checklist: map an existing relay's allow/block and
      membership rules onto the M2 policy pipeline
- [ ] Shadow mode guide: run Immortal read-only beside the existing
      relay, replay traffic, diff responses
- [x] Cutover and rollback runbook addition in `docs/deployment/`:
      hostname switch, import, verify, roll back

## Standing rules

- A specification change (NIP sync) is normative only after review plus a
  fixture update.
- A milestone is done when its fixtures and the guarded local deployment
  test pass. GitHub workflows and GitHub-billed automation are prohibited.
- New dependencies: owner sign-off first, recorded in AGENTS.md.
