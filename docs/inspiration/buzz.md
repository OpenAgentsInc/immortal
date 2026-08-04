# Block Buzz

## Source

| Field | Value |
| --- | --- |
| Repository | `https://github.com/block/buzz` |
| Pinned commit | `027a74a61c8643a1d1086d3e8307fad89d7735f7` |
| Current upstream checked | `b42b0934b60b56a2f77127a2d43330f9e8dcc8e3` |
| License | Apache-2.0 |
| Version | repository snapshot, no release tag selected |
| Review date | 2026-08-03 |

The pinned commit is the source of Immortal's `nips/block/` snapshot and is an
ancestor of the reviewed upstream main. The relevant NIP documents and public
server handlers were unchanged at the current commit. Buzz's own `AGENTS.md`
identifies `block/buzz` as the public relay source; the sibling organization
repositories it names are internal build, release, deployment, and provider
machinery rather than alternate server-handler sources.

## What it is

Buzz is a multi-crate Nostr collaboration product containing a relay, clients,
agent harness, Postgres access layer, Redis fanout, media, and other product
services. Its relay already implements the Block draft NIP behaviors adopted
in this pass, making it the closest executable reference for the pinned texts.

## Borrow

| Item | Upstream location | How Immortal adapts it |
| --- | --- | --- |
| Main agent-owner first mint and NIP-OA/NIP-AA auth | `crates/buzz-relay/src/handlers/auth.rs`, `event.rs`, `ingest.rs`; `crates/buzz-db/src/event.rs` | Preserve the first-owner-wins relation and closed-relay virtual membership in a prepared Postgres transaction and per-connection NIP-42 state. |
| NIP-AO observer and NIP-AM turn envelopes | `crates/buzz-relay/src/handlers/event.rs`, `ingest.rs`; `crates/buzz-core/src/agent_turn_metric.rs` | Preserve direction, unknown-frame silent drop, freshness, independent rates, owner relation, ephemeral routing, and owner-private reads using Immortal's bounded hub. |
| Block envelope validators and private reads | `crates/buzz-relay/src/handlers/ingest.rs`, `req.rs`; `crates/buzz-db/src/event.rs` | Re-express the pinned tag and ACL rules with owned domain validators, prepared SQL gating before order/limit, and matching live-fanout gates. |
| NIP-IA, NIP-DV, and NIP-WP commands | `crates/buzz-relay/src/handlers/identity_archive.rs`, `command_executor.rs`, `relay_admin.rs`, `side_effects.rs` | Use authenticated commands, idempotency rows, atomic state mutation, and relay-signed replaceable delta/snapshot events in one Postgres database. NIP-11 reads the workspace icon from Postgres on each request for cross-process consistency. |
| FTS exclusion for encrypted/private kinds | `crates/buzz-db/src/migration.rs` and repository migrations | Rebuild Immortal's generated FTS column so no private or conditionally shared Block content enters the search index. |
| NIP-PL fail-closed ordering | `crates/buzz-relay/src/handlers/push_lease.rs`; `crates/buzz-db/src/push.rs` | Preserve authentication, signature, public-envelope, and author-private read gates. Immortal advertises no executor descriptor/key and refuses before storage because its deployment has no configured platform push transport. |

No source section was copied verbatim. The implementation was rewritten around
Immortal's existing types and architecture, while keeping observable protocol
semantics from the pinned specifications and reference handlers.

## Reject

| Item | Reason |
| --- | --- |
| SQLx, Redis pub/sub, object-storage services, and Buzz's service topology | Immortal permits one binary, one Postgres database, and its fixed dependency allowlist. |
| Buzz database modules or migrations copied literally | Their schema, tenant model, SQLx types, and service boundaries do not match Immortal's prepared `tokio-postgres` store. |
| NIP-PL executor descriptor, lease decryption, platform credentials, and APNs/FCM/UnifiedPush dispatch in the M6 release | No executor key or transport is configured or advertised in that release. Persisting an undecryptable, unexecutable lease would violate NIP-PL's atomic acceptance contract, so the current handler correctly refuses it. The full-lane roadmap now requires this surface to be implemented in-binary and fixture-proved. |
| NIP-CW HTTP `/query` and materialized overlay service | Immortal's public contract is WebSocket NIP-01. The NIP explicitly permits safe degradation there; extension fields are discarded and the standard filter is served. |
| GitHub Actions or GitHub-billed conformance | Repository invariant prohibits both; all checks run through committed local scripts. |

## Follow-ups

1. Keep every Block fixture pinned to the reviewed commit and re-review before a
   future NIP sync changes runtime behavior.
2. Implement the now owner-approved NIP-PL in-binary executor design with
   encryption, transactional lease state, and an actual non-GitHub
   platform-transport acceptance proof. Do not advertise it before that proof
   passes.
3. Revisit NIP-CW only if Immortal intentionally adds its optional HTTP query
   surface without adding a service.
