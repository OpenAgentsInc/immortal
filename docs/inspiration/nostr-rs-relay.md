# Review: nostr-rs-relay

## Source

- Repo: <https://github.com/scsibug/nostr-rs-relay>
- Pinned commit: `b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4` (2026-05-22)
- License: MIT
- Version: 0.10.0, edition 2021
- Review date: 2026-08-03

## What it is

The reference Rust Nostr relay. Tokio + tungstenite WebSocket server,
SQLite as the primary store (Postgres experimental), one process-local
broadcast channel for live events, and a rich operator configuration
surface. About 10,000 lines of Rust. Its architecture is the opposite of
ours on the load-bearing axes (streaming-SQL repository trait, broadcast
to every connection, linear per-connection filter scans, dynamic SQL), so
we build greenfield — but its protocol semantics, defensive techniques,
and operator surface are the best field notes available.

## Borrow

| Item | Upstream location | How we adapt |
| --- | --- | --- |
| Event classification semantics: `is_ephemeral`, `is_replaceable`, `is_param_replaceable`, `distinct_param`, `expiration`, `is_expired`, `is_kind_metadata` | `src/event.rs` | Same predicate set in our `domain/`, written fresh against `nips/official/01.md` and `40.md`, with fixtures |
| Canonical serialization for event ID (`to_canonical`, `tags_to_canonical`) | `src/event.rs` | Same technique: serde_json with preserved order for the canonical array. Fixture-test against known event IDs |
| Single-letter tag indexing rule (`single_char_tagname`, `build_index`) | `src/event.rs` | Same rule feeds our `nostr_indexed_tag` rows |
| Future-timestamp rejection (`reject_future_seconds`) | `src/event.rs`, `[options]` | Same check in admission; ours is a hard config value, not optional |
| Filter matching semantics (`interested_in_event`, `ids_match`, `tag_match`, `kind_match`) | `src/subscription.rs` | Same semantics in `domain/`, minus prefix matching (removed from NIP-01). Port their unit-test cases as fixtures |
| NIP-91 AND-operator filters (`TagOperand`) | `src/subscription.rs` | Historical watch item: NIP-91 was absent from the M6 pin. Under protocol totality, implement its exact behavior if/when it enters the pinned official lane, with fixtures before advertisement. |
| `is_scraper` heuristic — flag subscriptions with no meaningful constraints | `src/subscription.rs` | Adopt the idea as a query-budget class: unconstrained REQs get the strictest budget |
| Query abandonment on client disconnect (oneshot `abandon_query_rx`, checked every 100 rows) | `src/repo/sqlite.rs` | Adopt the pattern with tokio-postgres: cancel historical queries when the socket closes, check the cancel token between result pages |
| Slow-query shedding with client sampling (`slow_first_event`) | `src/repo/sqlite.rs` | Adopt the principle inside our query budgets: a filter class that is measurably slow gets degraded service before it degrades the relay |
| Bounded broadcast buffer against slow consumers | `src/server.rs` (`broadcast_buffer`) | Same principle on our per-connection send queues: bounded, drop-and-close on overflow, never unbounded memory |
| Graceful shutdown lane (ctrl-c and internal signal) | `src/server.rs` | Same shape with tokio signal handling: stop accepting, drain, close |
| NIP-42 per-connection challenge state | `src/conn.rs` | Same state machine in our gateway; port their timing rules as fixtures |
| Operator limits vocabulary: `messages_per_sec`, `subscriptions_per_min`, `max_event_bytes`, `max_ws_message_bytes`, `max_ws_frame_bytes`, kind blacklist | `config.toml` `[limits]` | Same knob set as environment variables in our configuration contract |
| Operator docs precedent: reverse proxy, systemd process, database maintenance | `docs/` | Same topics in our `docs/deployment/` runbooks |
| SQLite query-planner heuristics (index selection per filter shape) | `src/repo/sqlite.rs` `query_from_filter` | Design notes only — they inform which compound Postgres indexes we create. We never build SQL from strings |
| Unit-test corpus in `event.rs` and `subscription.rs` `#[cfg(test)]` modules | `src/` | Fixture quarry: port the cases (MIT, with attribution) into our per-NIP fixture corpus |

## Reject

| Item | Reason |
| --- | --- |
| `NostrRepo` streaming-SQL repository trait | Our store is one admission transaction plus indexed reads; the trait shape fights that |
| Process-local broadcast to every connection + linear subscription scans | We use Postgres `NOTIFY` plus an indexed `SubscriptionIndex` |
| Dynamic SQL query builder | AGENTS.md rule 4: prepared statements only |
| SQLite as primary store | Owner decision: Postgres, one store |
| Prefix matching for ids/authors | Removed from current NIP-01 |
| NIP-26 delegation (`src/delegation.rs`) | Unrecommended upstream; disabled in their own build |
| Upstream NIP-05 subsystem copied as-is (`src/nip05.rs`, 658 lines) | The behavior is now in Immortal's official-lane target, but the upstream hyper/reqwest implementation is outside the allowlist. Design it against Immortal's existing stack or obtain and record separate dependency approval; do not silently import the subsystem. |
| gRPC authorization plugin (`tonic`/`prost`, `src/nauthz.rs`) | A second running service; AGENTS.md rule 1 |
| Upstream pay-to-relay subsystem copied as-is | Its external Lightning dependency and operator policy do not fit Immortal. The pinned official payment and paid-relay NIP behaviors remain protocol-totality targets; implement their noncustodial contracts against owned boundaries rather than importing this subsystem. |
| `config` crate + TOML file hierarchy | Our configuration is environment variables only |
| `tracing`/`tracing-subscriber`/`console-subscriber` stack | Outside the allowlist; we log line-oriented JSON to stdout |
| `r2d2` connection pooling | tokio-postgres manages its own connections |
| `governor` rate limiter | Our token buckets are small enough to own |

## Follow-ups

1. Port the `event.rs` and `subscription.rs` unit-test cases into the
   per-NIP fixture corpus during the domain milestone (with MIT
   attribution comments).
2. Encode the `[limits]` vocabulary into `docs/deployment/configuration.md`
   as environment variables.
3. Implement query-cancel-on-disconnect and bounded send queues in the
   gateway milestone; both get chaos fixtures.
4. Add NIP-91 to the implementation ledger when it enters the pinned official
   lane; keep it unadvertised until its exact pinned fixtures pass.
5. Implement NIP-05 verification under the full-official-lane directive.
   Resolve outbound HTTPS within the existing dependency contract or seek and
   record explicit owner approval for a new dependency before coding it.
