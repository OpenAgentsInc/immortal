# Conformance

M4 makes the proof surface executable on a contributor machine. The repository
carries pinned fixtures for every implemented NIP, live contracts
against a fresh Postgres database, an actual two-process chaos proof, and a
repeatable release-mode load harness. `scripts/test-postgres.sh` runs the live
proofs locally; GitHub workflows and GitHub-billed automation are prohibited
by `AGENTS.md`.

## Coverage map

| Contract | Primary proof |
| --- | --- |
| NIP-01 canonical event IDs, escaping, signatures, tags, exact filters, time bounds, kind classes, and replacement ordering | `tests/fixtures/nip01/` + `tests/domain_fixtures.rs` |
| NIP-01 EVENT/REQ/CLOSE and EVENT/OK/EOSE/CLOSED/NOTICE shapes | `nip01/gateway_messages.json`, gateway wire unit tests, and `tests/gateway_postgres.rs` |
| NIP-09 deletion by event/address, deletion-before-arrival, author ownership, and races | `nip09/deletion.json`, domain fixtures, and the live store contract |
| NIP-11 document fields, advertised limits, same-path HTTP, health, and required CORS headers | `nip11/document.json` plus gateway unit/live contracts |
| NIP-40 admission and query-time expiration boundaries | `nip40/expiration.json` plus domain/live store contracts |
| NIP-42 challenge, relay tag, timestamp, signature, connection authentication, refusal prefixes, and non-publication of kind 22242 | `nip42/auth.json` plus gateway unit/live contracts |
| NIP-17 one-recipient gift-wrap validation and authenticated historical/live/count gating; kind-10050 relay lists | `nip17/routing.json`, expanded fixtures, and the live gateway contract |
| NIP-29 group scoping, pre-store membership and supported-kind policy, moderation/join/leave state, relay-signed history and 39000–39005 metadata | `nip29/groups.json`, expanded fixtures, and the live gateway contract |
| NIP-45 bounded exact COUNT, unique results across filters, and private-event gating | `nip45/count.json`, wire fixtures, and the live gateway contract |
| NIP-50 bounded search parsing, ignored extensions, Postgres simple FTS, and result ranking | `nip50/search.json`, expanded fixtures, and the live gateway contract |
| NIP-65 relay-list shape, normal replaceable storage, and indexed `r` tags | `nip65/relay-list.json`, expanded fixtures, and the store/gateway contracts |
| NIP-70 same-connection protected publication and embedded-repost refusal | `nip70/protected.json`, expanded fixtures, and the live gateway contract |
| NIP-86/NIP-98 method shapes, exact URL/method/payload authentication, owner authorization, replay prevention, policy methods, and group extensions | `nip86/management.json`, `nip98/http-auth.json`, unit/expanded fixtures, and the live HTTP/Postgres contract |
| NIP-B7/NIP-94 media server lists and metadata; streaming upload, exact hash/auth, replay refusal, public HEAD/GET/range, ownership deletion, and filesystem publication | `nipb7/servers.json`, `nip94/metadata.json`, media unit tests, and the live HTTP/Postgres contract |
| Block NIP-OA/AA/AO/AM agent ownership, closed-relay authentication, ephemeral observer routing/rates, and owner-private turn metrics | `tests/fixtures/nipoa/`, `nipaa/`, `nipao/`, `nipam/`, `tests/agent_fixtures.rs`, and the live gateway contract |
| Block NIP-AE/AP/ER/MP/PL stored-envelope validation and authenticated author/owner/shared ACLs, including fail-closed push-executor refusal | the matching `tests/fixtures/nip*/server.json` corpora, `tests/block_fixtures.rs`, and the live gateway contract |
| Block NIP-IA/DV/WP authenticated commands, transactional derived state, relay-signed deltas/snapshots, and cross-process NIP-11 workspace icon | the matching Block fixtures plus the live gateway contract |
| Block NIP-CW safe WebSocket degradation, NIP-RS addressable/barrier semantics, and NIP-GS no-handler classification | `nipcw/`, `niprs/`, `nipgs/`, filter/store unit tests, and the live gateway contract |
| M2 migrations, hash drift, prepared admission/query paths, least privilege, policy branches, FTS, transactional NOTIFY, replacement/deletion concurrency, and ephemeral non-storage | `tests/store_static.rs` and `tests/store_postgres.rs` |
| M3 indexed fanout by ID/author/kind/tag, broad lane, race-free EOSE, deduplication, queue overflow, query cancellation, limits, rates, frame bounds, and graceful shutdown | gateway unit tests and `tests/gateway_postgres.rs` |
| M4 two binaries/one Postgres, cross-delivery, bounded sequence-gap recovery, kill-one survival, and fail-closed unbounded gap | `tests/multiprocess_postgres.rs` |
| M4 events/sec, WebSocket connect p99, and REQ-to-EOSE p99 | `tests/load_postgres.rs` and [`load-report.md`](load-report.md) |
| M6 and Block migrations, expiration sweep, group state, management replay, main-agent ownership, and relay-derived Block state | `tests/store_static.rs`, `tests/store_postgres.rs`, and `tests/gateway_postgres.rs` |
| M7 migration, pending/ready publication, media ownership, quota, and authorization replay state | `tests/store_static.rs` and `tests/gateway_postgres.rs` |

## Running locally

The complete M1–M7 manual gate is:

```sh
./scripts/test-conformance.sh
```

It runs formatting, compilation, fixtures, Clippy, rustdoc, live Postgres,
multi-process chaos, the release load proof, and the disposable Debian 13
deployment acceptance. It needs local Postgres tools plus a running Apple
Container, Podman, or Docker runtime. It never invokes GitHub automation.

For faster iteration, run the layers separately.

The fast, database-independent layer is:

```sh
cargo test --locked --all-targets
```

The complete proof creates a temporary local Postgres cluster and disposable
databases, then removes them on exit:

```sh
./scripts/test-postgres.sh
```

The destructive live tests require both a dedicated database URL and
`IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1`; without that guard they skip. The load
test is additionally ignored unless the script selects it explicitly.
