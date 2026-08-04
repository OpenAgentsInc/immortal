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

## M7 — Media

- [ ] Blossom endpoint (NIP-B7, NIP-98 auth, NIP-94 metadata): filesystem
      storage default, one optional cloud-storage adapter

## M8 — Hardening and formal work

- [ ] Formal model of the admission/replacement/deletion state machine;
      checker run in the local conformance suite; counterexamples become
      fixtures
- [ ] Fuzzing on the wire parser and filter matcher
- [ ] Long-run soak: memory, connection churn, Postgres bloat,
      `NOTIFY` storm behavior
- [ ] Security pass against the AGENTS.md rules; publish the results

## M9 — Drop-in replacement kit

Everything an operator needs to replace an existing production relay with
Immortal behind the same hostname, with no client changes. Can start once
M6 reaches the NIP-29 item; does not wait for M7 or M8.

- [ ] Signed-event bulk import: JSONL in, idempotent, preserves ids and
      signatures, replays replacement and deletion rules in `ingest_seq`
      order
- [ ] NIP-11 parity configuration: name, description, pubkey, limits,
      and supported-NIP list fully operator-configurable
- [ ] Policy parity checklist: map an existing relay's allow/block and
      membership rules onto the M2 policy pipeline
- [ ] Shadow mode guide: run Immortal read-only beside the existing
      relay, replay traffic, diff responses
- [ ] Cutover and rollback runbook addition in `docs/deployment/`:
      hostname switch, import, verify, roll back

## Standing rules

- A specification change (NIP sync) is normative only after review plus a
  fixture update.
- A milestone is done when its fixtures and the guarded local deployment
  test pass. GitHub workflows and GitHub-billed automation are prohibited.
- New dependencies: owner sign-off first, recorded in AGENTS.md.
