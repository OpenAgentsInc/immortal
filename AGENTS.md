# Immortal Agent Contract

This repository is the OpenAgents Rust Nostr relay: **one Rust binary, one
Postgres, nothing else.** Read `README.md` first. The build plan and packet
breakdown live in the OpenAgents monorepo at
`docs/spacetime/2026-08-03-rust-spacetimedb-nostr-infra-considerations.md`.

## Non-negotiable design rules

1. **Single binary + Postgres.** No message broker, no sync service, no
   cache tier, no sidecar process, no embedded second database. Fanout is
   Postgres `LISTEN/NOTIFY` plus `ingest_seq` catch-up. If a proposed
   feature needs another running service, the proposal is wrong.
2. **No Electric, no NATS, no Redis/Valkey, no SpacetimeDB — ever, here.**
   Electric is used elsewhere in the OpenAgents estate for the product read
   path; it is not a relay dependency. The relay must deploy on a single box
   owned by strangers.
3. **Dependency allowlist.** Direct dependencies are limited to:
   `tokio`, `tokio-tungstenite`, `tokio-postgres`, `secp256k1`, `sha2`,
   `serde`, `serde_json`. Additions require explicit owner sign-off recorded
   in this file. No ORM, no web framework unless the owner approves one, no
   TLS in-process (the reverse proxy owns TLS).
4. **Own the protocol primitives.** NIP-01 event/tag/filter types,
   canonical-ID serialization, and filter matching are implemented here in
   `src/domain/`, conformance-tested — not imported from a third-party Nostr
   crate.
5. **Hardened by default.** Prepared statements only — no dynamic SQL.
   Bounds on frame size, subscriptions per connection, filters per REQ, and
   query cost. Rate limits per IP and pubkey. Fail closed: a process that
   cannot prove it is current drops its sockets. Ephemeral kinds
   (20000–29999) never touch storage.
6. **Conformance is differential.** Protocol fixtures run against both this
   relay and `nostr-effect`; divergence fails the build. The
   `nostr-rs-relay` (MIT) test corpus is a fixture quarry — quarry fixtures,
   never vendor architecture.
7. **Single-box acceptance test.** Fresh Debian stable + package-manager
   Postgres + this binary = serving relay, in minutes, following only the
   README. Changes that break that path are regressions.

## License and provenance

- This repo is **CC0-1.0**. Do not add dependencies or copied code whose
  license cannot sit under a CC0 project (MIT/Apache/BSD deps are fine as
  dependencies; copied code must be attributed and license-compatible).
- No secrets, tokens, or private infrastructure details in this repo, ever.
  It is public and must stay deployable by strangers.

## Workspace rules

- Work on `main`. Commit and push completed work; do not leave local-only
  commits.
- This is a standalone sibling repo of the OpenAgents workspace. Do not mix
  its commits into other repos. The OpenAgents monorepo consumes the relay
  only through its wire protocol and shared fixture corpus.
