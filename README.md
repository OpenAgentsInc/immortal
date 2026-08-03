# Immortal

A hardened Nostr relay. One Rust binary, one Postgres. Nothing else.

Named for the Immortal's hardened shields. Public domain (CC0).

## Thesis

A small activist network should be able to run durable, sovereign, signed
group infrastructure on a single cheap box with two well-understood pieces:

```text
Nostr clients  ⇄  immortal (one static Rust binary: WebSocket + NIP-11 HTTP)
                      │
                  Postgres
                  events · tag indexes · replaceable heads · deletion
                  tombstones · policy · full-text search · LISTEN/NOTIFY
                  fanout · monotonic ingest_seq
```

Postgres is pushed as far as it goes — it is the store, the query engine, the
search index, and the fanout bus. There is no message broker, no sync
service, no cache tier, no sidecar. TLS terminates at the reverse proxy
(nginx or Caddy) the box already has.

Scale-up is the same picture, wider: N immortal processes against one
Postgres, coordinated by `LISTEN/NOTIFY` plus `ingest_seq` catch-up. A
process that cannot catch up fails closed — drops its sockets — and clients
reconnect. No coordination service ever enters the design.

## Design doctrine

1. **Standard.** Boring, battle-tested components only: Rust, tokio,
   Postgres. Protocol behavior comes from NIP text, not from novel
   architecture.
2. **Hardened.** Bounded everything (frame size, subscriptions per
   connection, filters per REQ, query budgets, rate limits). Prepared
   statements only. Least-privilege database role. Fail closed, never open.
   Shipped systemd unit carries the hardening flags.
3. **Simple.** One crate. One binary. One database. A dependency tree short
   enough to read in one sitting — see the allowlist in `AGENTS.md`.
4. **Deployable by non-specialists.** The acceptance test is a fresh Debian
   stable box to a serving relay in minutes, with a package-manager Postgres
   and one binary. If a step needs a specialist, the step is a bug.

## Status

Pre-implementation skeleton. The build plan, architecture decisions, and
packet breakdown live in the OpenAgents monorepo at
`docs/spacetime/2026-08-03-rust-spacetimedb-nostr-infra-considerations.md`.

Conformance oracle: the [`nostr-effect`](https://github.com/OpenAgentsInc/nostr-effect)
TypeScript implementation — every protocol fixture runs against both, and
divergence is a build failure.

## License

CC0-1.0. Public domain. Take it, run it, fork it, no permission needed.
