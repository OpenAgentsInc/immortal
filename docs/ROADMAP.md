# Immortal Roadmap

The order of work. Each milestone lands with its fixtures and leaves the
build green. Rules live in `AGENTS.md`; NIP sources live in `nips/`;
external-project reviews live in `docs/inspiration/`.

## M0 — Foundation (done)

- [x] Repo, license (CC0), README, AGENTS.md doctrine
- [x] Compiling Cargo skeleton, edition 2024
- [x] NIP source lanes and sync script (`nips/`, three pinned upstreams)
- [x] First inspiration review (nostr-rs-relay)
- [ ] Deployment docs (`docs/deployment/`) — in progress

## M1 — Domain (`src/domain/`)

The NIP-01 primitives, written from `nips/official/01.md`, with fixtures.

- [ ] Event type, tag model, single-letter tag indexing rule
- [ ] Canonical serialization and event ID (SHA-256)
- [ ] Schnorr signature verification (secp256k1)
- [ ] Filter model and matching (ids, authors, kinds, tags, since, until,
      limit) — no prefix matching
- [ ] Classification: regular, replaceable, ephemeral, addressable;
      replacement address; expiration (NIP-40)
- [ ] Deletion semantics (NIP-09), including deletion-before-event
- [ ] Timestamp bounds (reject far-future events)
- [ ] Fixture corpus: known event IDs, filter cases ported from
      nostr-rs-relay tests (MIT, attributed), replacement and deletion
      races

## M2 — Store (`src/store/`)

Postgres owns everything. One admission transaction.

- [ ] Schema migration files (versioned .sql, applied in a transaction)
- [ ] Tables: `nostr_event` (with `ingest_seq`), `nostr_indexed_tag`,
      `replaceable_head`, `deletion_tombstone`, policy tables
- [ ] Admission transaction: dedup, replacement compare-and-set,
      tombstones, policy, tag rows, `ingest_seq`, `NOTIFY`
- [ ] Compound indexes for the NIP-01 access patterns
- [ ] FTS: generated tsvector column + GIN index (for NIP-50 later)
- [ ] Prepared statements only; least-privilege role documented

## M3 — Gateway (`src/gateway/`)

The WebSocket protocol server.

- [ ] WS handshake + NIP-11 document on HTTP GET
- [ ] NIP-01 message flow: EVENT, REQ, CLOSE, OK, EOSE, CLOSED, NOTICE
- [ ] NIP-42 per-connection challenge state
- [ ] `SubscriptionIndex` (by id, author, kind, tag) — no linear scans
- [ ] Race-free EOSE: buffer live events during the historical query,
      deduplicate, flush after EOSE
- [ ] Ephemeral lane (kinds 20000–29999): in-process + `NOTIFY`, never
      stored
- [ ] Limits: frame size, event bytes, subscriptions per connection,
      filters per REQ; per-IP and per-pubkey rate limits
- [ ] Query cancel on client disconnect; bounded per-connection send
      queues; graceful shutdown

## M4 — Conformance

- [ ] Per-NIP fixture suite wired into CI; every M1–M3 behavior covered
- [ ] Multi-process proof: two processes, one Postgres — cross-delivery,
      `ingest_seq` gap catch-up, kill-one chaos, fail-closed on gap
- [ ] Load proof with published numbers (events/sec, connect p99,
      REQ-to-EOSE p99)

## M5 — Deployment kit

- [ ] Single-box acceptance: fresh Debian + apt Postgres + binary =
      running relay in minutes, README-only
- [ ] Hardened systemd unit, nginx and Caddy snippets, backup and
      restore procedure, upgrade and rollback procedure
- [ ] Runbooks final (`docs/deployment/`): Debian VPS, DigitalOcean,
      Google Cloud

## M6 — NIP expansion

In order, each with fixtures before the next starts:

- [ ] NIP-40 expiration sweep (scheduled delete + query-time exclusion)
- [ ] NIP-70 protected events (with NIP-42 state)
- [ ] NIP-45 COUNT (bounded)
- [ ] NIP-50 search (the FTS column from M2)
- [ ] NIP-65 relay-list handling notes
- [ ] Watch: NIP-77 (negentropy sync), NIP-91 (AND filters — implement
      when stable upstream)
- [ ] `nips/block/` and `nips/openagents/` lanes: per-NIP owner decision,
      official lane wins on identifier conflict

## M7 — Media

- [ ] Blossom endpoint (NIP-B7, NIP-98 auth, NIP-94 metadata): filesystem
      storage default, one optional cloud-storage adapter

## M8 — Hardening and formal work

- [ ] Formal model of the admission/replacement/deletion state machine;
      checker run in CI; counterexamples become fixtures
- [ ] Fuzzing on the wire parser and filter matcher
- [ ] Long-run soak: memory, connection churn, Postgres bloat,
      `NOTIFY` storm behavior
- [ ] Security pass against the AGENTS.md rules; publish the results

## Standing rules

- A specification change (NIP sync) is normative only after review plus a
  fixture update.
- A milestone is done when its fixtures pass in CI and the deployment
  test still passes.
- New dependencies: owner sign-off first, recorded in AGENTS.md.
