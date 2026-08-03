# Conformance

M4 makes the proof surface executable in CI. The repository carries pinned
fixtures for every NIP implemented through M3, live contracts against a fresh
Postgres database, an actual two-process chaos proof, and a repeatable
release-mode load harness. `.github/workflows/conformance.yml` runs all of
them on every pull request and every push to `main`.

## Coverage map

| Contract | Primary proof |
| --- | --- |
| NIP-01 canonical event IDs, escaping, signatures, tags, exact filters, time bounds, kind classes, and replacement ordering | `tests/fixtures/nip01/` + `tests/domain_fixtures.rs` |
| NIP-01 EVENT/REQ/CLOSE and EVENT/OK/EOSE/CLOSED/NOTICE shapes | `nip01/gateway_messages.json`, gateway wire unit tests, and `tests/gateway_postgres.rs` |
| NIP-09 deletion by event/address, deletion-before-arrival, author ownership, and races | `nip09/deletion.json`, domain fixtures, and the live store contract |
| NIP-11 document fields, advertised limits, same-path HTTP, health, and required CORS headers | `nip11/document.json` plus gateway unit/live contracts |
| NIP-40 admission and query-time expiration boundaries | `nip40/expiration.json` plus domain/live store contracts |
| NIP-42 challenge, relay tag, timestamp, signature, connection authentication, refusal prefixes, and non-publication of kind 22242 | `nip42/auth.json` plus gateway unit/live contracts |
| M2 migrations, hash drift, prepared admission/query paths, least privilege, policy branches, FTS, transactional NOTIFY, replacement/deletion concurrency, and ephemeral non-storage | `tests/store_static.rs` and `tests/store_postgres.rs` |
| M3 indexed fanout by ID/author/kind/tag, broad lane, race-free EOSE, deduplication, queue overflow, query cancellation, limits, rates, frame bounds, and graceful shutdown | gateway unit tests and `tests/gateway_postgres.rs` |
| M4 two binaries/one Postgres, cross-delivery, bounded sequence-gap recovery, kill-one survival, and fail-closed unbounded gap | `tests/multiprocess_postgres.rs` |
| M4 events/sec, WebSocket connect p99, and REQ-to-EOSE p99 | `tests/load_postgres.rs` and [`load-report.md`](load-report.md) |

## Running locally

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
