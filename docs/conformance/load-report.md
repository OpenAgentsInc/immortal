# M4 Load Report

This report publishes the first reproducible Immortal load baseline. It is a
local single-box measurement, not a capacity promise. The committed harness
is `crates/immortal-relay/tests/load_postgres.rs`; `scripts/test-postgres.sh` creates its fresh
database and runs it in Cargo's optimized release profile.

## Result — 2026-08-03

| Metric | Median | Five-run range |
| --- | ---: | ---: |
| Committed events/second | 6,849.89 | 5,604.09–6,954.65 |
| WebSocket connect p99 | 0.41 ms | 0.37–0.45 ms |
| REQ-to-EOSE p99 | 2.12 ms | 1.35–3.41 ms |

Each of five runs used:

- 2,000 pre-signed kind-1 events across four concurrent publishers; every
  publisher waited for the post-commit `OK` for each event;
- 250 sequential loopback WebSocket handshakes for the connect distribution;
  and
- 100 subscriptions requesting the latest ten kind-1 events, measured from
  sending `REQ` through receiving `EOSE`.

The reported events/second therefore measures validation, the complete
Postgres admission transaction, durable commit, and receipt of `OK` while the
gateway's notification cursor runs concurrently. Event signing is
intentionally outside the timed region; the harness gives the cursor one
second to drain before latency sampling. REQ-to-EOSE includes ten `EVENT`
frames plus `EOSE`.

## Host and software

- Apple M5 Max, 128 GiB RAM, arm64
- macOS 26.4 (Darwin 25.4.0)
- PostgreSQL 16.14, default durable `fsync` and `synchronous_commit` settings,
  local Unix socket
- rustc 1.94.1, Cargo 1.94.1, optimized release profile
- relay WebSockets on loopback, without TLS or a reverse proxy

The test Postgres cluster has no pre-existing data, external clients, TLS, or
network latency. Production numbers will vary with storage latency, database
topology, event/tag sizes, filters, reverse proxy, and concurrent subscriber
fanout. M8's one-hour local soak is recorded in
[`2026-08-05-m8-soak-4a22930.json`](records/2026-08-05-m8-soak-4a22930.json).
It covers sustained two-relay behavior on this workstation; target Debian
capacity still requires its own measurement.

## Reproduction

```sh
./scripts/test-postgres.sh
```

The harness prints one `M4_BENCHMARK_JSON=...` line containing sample counts,
medians, and ranges so a manually captured conformance log retains
machine-readable evidence. It asserts correct protocol responses but
deliberately has no fixed performance threshold: heterogeneous contributor
machines are suitable for regression observation, not a stable latency
service-level objective.
