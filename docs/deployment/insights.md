# Production Insights from *Zero To Production In Rust*

Source: *Zero To Production In Rust* by Luca Palmieri, 2024-09-03 edition
(cited below as "ZTP, ch. N"). The book builds an email-newsletter API on
actix-web, sqlx, and a broad crate stack, and deploys it to DigitalOcean App
Platform. Immortal is a hardened Nostr relay with seven direct dependencies
and a one-binary-one-database rule. Each insight below states what the book
says, then how Immortal honors the principle without the book's crates.

Dependency rule reminder: allowed direct dependencies are `tokio`,
`tokio-tungstenite`, `tokio-postgres`, `secp256k1`, `sha2`, `serde`,
`serde_json`. Anything else "requires owner sign-off per AGENTS.md rule 2".

---

## 1. Configuration

**Book (ZTP, ch. 3 and ch. 5).** Use a typed configuration struct
deserialized at startup with the `config` crate. Layer the sources: a base
file, an environment-specific file (`local.yaml`, `production.yaml`) chosen
by an `APP_ENVIRONMENT` variable, and finally environment-variable overrides
(prefix `APP`, `__` separator) so a platform can inject values such as the
database URL without a rebuild. Fail immediately with a clear panic if
configuration cannot be read. Bind `127.0.0.1` in development and `0.0.0.0`
in production; this difference alone breaks naive deployments, so make it
explicit configuration, not code.

**Immortal.** The principles survive; the crate does not.

- Environment variables only. No config files, no layering engine, no extra
  crate. A container platform, systemd `EnvironmentFile`, or a shell can set
  them. The full contract is in [`configuration.md`](configuration.md).
- One typed `Config` struct in `src/`, filled from `std::env` at startup,
  parsed into real types (ports, byte counts, durations) with `serde` where
  useful.
- Fail fast: if a required variable is missing or any value does not parse,
  print one clear line to stderr and exit non-zero before binding a socket
  or touching the database. A relay that starts with a half-read
  configuration fails open; Immortal fails closed.
- The bind address is explicit (`IMMORTAL_BIND_ADDR`), defaulting to
  `127.0.0.1` so a bare start is private by default. Deployments behind a
  proxy on the same host keep the default; containers set `0.0.0.0`.

## 2. Secrets

**Book (ZTP, ch. 4, ch. 5, ch. 10).** Wrap secrets in `secrecy::Secret` so
the type system stops accidental `Debug`/`Display` logging and marks
secret-bearing fields for the reader. Inject production secrets (database
password, HMAC keys) as platform environment variables or a secret store,
never in the repository. Treat any connection string that embeds a password
as a secret.

**Immortal.** `secrecy` is a wrapper, not a capability; discipline plus a
narrow surface replaces it.

- The database password enters only through `DATABASE_URL` or `PGPASSWORD`.
  The `Config` struct never implements `Debug` for the credential field (or
  redacts it by hand in any manual `Debug` impl). Nothing else in the relay
  is a secret: Immortal holds no signing keys, no API tokens, no session
  store.
- Log lines never include the connection string. When logging database
  errors, log the error, not the DSN.
- Secrets never appear in argv. `ps` shows argv to every local user;
  environment variables of a systemd service do not leak the same way when
  the unit file and environment file are root-owned `0600`.
- The repository is public and contains no secrets (AGENTS.md rule 10).
  Runbooks use `<YOUR_DB_PASSWORD>`-style placeholders.

## 3. Telemetry and observability

**Book (ZTP, ch. 4).** Production failures are "unknown unknowns"; you
cannot debug them by reproduction, only by evidence. Therefore emit
structured, machine-parsable logs (the book uses `tracing` +
`tracing-bunyan-formatter` for JSON), attach a correlation id (request id)
to every log line of a unit of work, record elapsed time and outcome, and
control verbosity with an environment variable. Never log personally
identifying data or credentials. Instrument at the boundaries: one span per
request, with the interesting fields recorded once.

**Immortal.** The principle is: one JSON object per line on stdout, with
enough correlation to reconstruct any connection's story. No `tracing`, no
subscriber stack.

- Hand-roll a tiny logger over `serde_json`: each log call serializes a
  small struct `{ts, level, event, conn_id, ...fields}` to one line on
  stdout. journald, Docker, and Cloud Logging all collect stdout; Cloud
  Logging even parses JSON lines into structured entries natively.
- The correlation id is the connection id (a counter or random u64 assigned
  at accept time), plus the subscription id where relevant. Every line for
  that WebSocket carries `conn_id`. This is the book's request-id insight
  mapped to a connection-oriented protocol.
- Log the lifecycle events that answer real questions: connection open and
  close (with duration, frames in/out), `EVENT` accepted or rejected (with
  event id and reason), `REQ` received (with filter count and cost), rate
  limit trips, database errors, catch-up lag, and shutdown.
- Never log full event content at info level. Event ids and pubkeys are
  public data on Nostr; raw content is noise and can be large. Never log
  credentials or the DSN (see Secrets).
- `IMMORTAL_LOG_LEVEL` (error|warn|info|debug) replaces `RUST_LOG`. The
  check is one integer comparison; no filtering language is needed.
- Timing: record elapsed milliseconds on query completion and on connection
  close using `std::time::Instant`. That is the book's "record the elapsed
  time" insight without span machinery.

## 4. Database and migrations

**Book (ZTP, ch. 3, ch. 5, ch. 7).** Keep schema changes as versioned SQL
migration files (`sqlx migrate add/run`) applied in order and recorded in a
migrations table. Run migrations as a deliberate step, and design them to be
backwards compatible with the running application version, because during a
rolling deploy old and new code run against the same schema (ch. 5 deploys
by pushing to DigitalOcean, where the old instance drains while the new one
starts). Use compile-time-checked queries where possible; wrap multi-step
writes in a transaction so admission is all-or-nothing (ch. 7 makes the
subscriber insert + token insert a single transaction). Use connection
pooling; connect lazily so the binary can start before the database accepts
connections, then fail on first use with a clear error.

**Immortal.** Postgres is the whole storage layer, so this theme is load
bearing.

- Migrations are hand-rolled and boring: numbered files
  `migrations/0001_init.sql`, `0002_....sql` in the repository. The relay
  (or an `immortal migrate` subcommand) applies each pending file inside a
  single transaction and records `(version, sha256, applied_at)` in a
  `schema_migrations` table. `sha2` is already an allowed dependency, so the
  applied file hash is verified: a changed historical migration is a hard
  startup error. No `sqlx-cli` needed.
- Migrations run before the relay serves traffic. On a single box the
  ordering is trivial. With many relay processes, the first process to take
  a Postgres advisory lock applies migrations; the others wait on the lock,
  then verify the version. Fail closed: a relay that observes a schema
  version newer than it understands exits instead of guessing.
- Backwards compatibility: additive migrations first (new column, new
  index), destructive cleanup in a later release, so old and new relay
  processes can overlap during an upgrade. This is the book's rolling-deploy
  discipline (ZTP, ch. 5).
- Event admission is one transaction, and `OK` is sent only after commit
  (ZTP ch. 7's transactional-admission insight, already an Immortal
  invariant). Replaceable-event head updates, tag index rows, and deletion
  tombstones commit atomically with the event row.
- Prepared statements only (AGENTS.md rule 4). The book gets injection
  safety from sqlx's macros; Immortal gets it from `tokio_postgres::
  Client::prepare` + typed parameters. No SQL is ever built from strings at
  run time.
- `tokio-postgres` has no built-in pool, and Immortal does not add one
  (`deadpool`/`bb8` are outside the allowlist). The relay owns a small fixed
  set of connections: one dedicated `LISTEN/NOTIFY` connection, and N worker
  connections (default small, see `configuration.md`) handed out through a
  `tokio::sync` channel or semaphore. That is a pool in forty lines, sized
  deliberately — the book's ch. 5 point that connection counts must be
  chosen, not inherited.
- Lazy-connect behavior: at startup Immortal *does* verify connectivity and
  schema version once (fail fast beats fail late for an operator following a
  runbook), then treats later disconnections as a fail-closed event:
  reconnect with backoff, and if the process cannot become current with
  `ingest_seq`, close client connections so clients re-sync by reconnecting.

## 5. Docker and build optimization

**Book (ZTP, ch. 5).** Use a multi-stage Dockerfile: a heavy builder stage
compiles; a minimal runtime stage carries only the binary and CA
certificates. Docker layer caching cannot cache Cargo dependencies naively
because `COPY . .` invalidates everything, so use `cargo-chef` to build a
dependency-only layer first (`prepare` a recipe, `cook` dependencies, then
copy sources and build). Slim the runtime image (the book moves from
`rust:latest` ~GBs to `debian:bookworm-slim` ~100 MB or smaller); strip what
the runtime does not need; set `SQLX_OFFLINE` so builds do not need a live
database.

**Immortal.**

- The same multi-stage shape applies. `cargo-chef` is a build tool, not a
  runtime dependency, so it is acceptable in CI and in the builder stage; it
  never appears in `Cargo.toml`. If you prefer zero extra tooling, the
  manual variant of the same principle works: copy `Cargo.toml` +
  `Cargo.lock` with a stub `src/main.rs`, `cargo build --release` to cache
  dependencies, then copy real sources and build again.
- Immortal makes no outbound TLS connections in the default deployment (TLS
  terminates at the proxy; Postgres is local or reached over a private
  socket), so the runtime stage can be `gcr.io/distroless/cc-debian12` —
  or even `scratch` with a `x86_64-unknown-linux-musl` static build, since
  `secp256k1` and `sha2` compile fine with musl and no runtime asset is
  needed. Include `ca-certificates` only if a TLS-to-database path is ever
  approved.
- There is no compile-time query checking to keep offline (`sqlx`'s
  `SQLX_OFFLINE` concern does not exist); prepared statements are validated
  against the real schema by integration tests instead.
- A concrete Dockerfile lives in
  [`runbook-google-cloud.md`](runbook-google-cloud.md).

## 6. Deployment strategy

**Book (ZTP, ch. 5).** Prefer a boring, declarative deployment: the book
commits a `spec.yaml` for DigitalOcean App Platform, sets `deploy_on_push`,
injects secrets as scoped environment variables, and lets the platform
handle TLS, rolling restarts, and health checking. The application must be
environment-agnostic: same binary, different environment variables.

**Immortal.** The binary is deliberately platform-agnostic: it reads
environment variables, listens on one port, logs to stdout, and keeps all
state in Postgres. That makes three deployment shapes equally valid:

- A Debian VPS with systemd and Caddy/nginx — the canonical path
  (AGENTS.md rule 9: a new Debian server plus apt Postgres plus this binary
  is a running relay in minutes). See
  [`runbook-debian-vps.md`](runbook-debian-vps.md).
- DigitalOcean, either a Droplet (same as the VPS runbook) or App Platform
  with a spec file, matching the book's own path — with honest caveats
  about WebSockets and managed-Postgres TLS. See
  [`runbook-digitalocean.md`](runbook-digitalocean.md).
- Google Cloud Run + Cloud SQL, because the relay process is stateless:
  many relay processes against one Postgres is an explicit design goal
  (`LISTEN/NOTIFY` + `ingest_seq`). See
  [`runbook-google-cloud.md`](runbook-google-cloud.md).

Configuration is identical across all three; only the injection mechanism
differs (EnvironmentFile, spec `envs`, Cloud Run `--set-env-vars`).

## 7. Zero-downtime deployment

**Book (ZTP, ch. 5).** Users should not notice a deploy. Rolling restarts
require: a health check the platform can probe, graceful handling of
in-flight work, and — the part people forget — database migrations that are
compatible with both the old and the new application version, because both
run concurrently for a window.

**Immortal.** Nostr makes this easier than HTTP request/response, and the
architecture leans into it.

- Disconnection is safe by protocol. Clients reconnect and re-send `REQ`;
  a relay process that cannot become current must close its connections
  anyway (fail closed). So a deploy is: start new process, health-check it,
  shift traffic at the proxy, stop the old process. Brief WebSocket drops
  are acceptable and expected.
- Graceful shutdown: on SIGTERM, stop accepting connections, send `CLOSED`
  /close frames, finish in-flight `EVENT` transactions (bounded by
  `IMMORTAL_SHUTDOWN_GRACE_SECONDS`), then exit. systemd (`TimeoutStopSec`)
  and Cloud Run (SIGTERM then ~10 s) both follow this pattern.
- Because `OK` is sent only after commit, a kill at any moment never
  acknowledges an unstored event. The client retries; admission is
  idempotent (see theme 12). This is the crash-safety half of zero-downtime.
- Migration compatibility: additive first, destructive later (theme 4). Two
  relay versions may serve one database during the overlap window.

## 8. Health checks

**Book (ZTP, ch. 3 and ch. 5).** Add a `/health_check` endpoint returning
`200 OK` before anything else; it is the first thing to build and the hook
for every platform probe (the App Platform spec points
`health_check.http_path` at it). Keep it dependency-light so probes measure
liveness, not incidental load.

**Immortal.** The binary already serves HTTP for NIP-11, so a health
endpoint is nearly free.

- `GET /health` returns `200` with a small JSON body when the process is
  live *and current*: database reachable, catch-up lag within bounds. A
  relay that cannot become current is not healthy — reporting healthy while
  failing closed would make the proxy route traffic into instant closes.
- The NIP-11 document (`GET /` with `Accept: application/nostr+json`)
  doubles as a functional smoke test after deploy.
- Every runbook wires this endpoint into its probe: systemd watchdog or a
  cron curl on the VPS, `health_check.http_path` on App Platform, startup
  and liveness probes on Cloud Run.

## 9. Error handling

**Book (ZTP, ch. 8).** Errors serve two audiences: operators (internal,
detailed, logged, `Debug` with the full source chain) and callers (external,
stable, minimal, `Display`). Never leak internals to callers; never swallow
the chain in logs. Model errors as enums so the type states what can fail;
convert at boundaries; reserve 500-style responses for genuinely unexpected
failures and log them at error level with the full cause chain.

**Immortal.** The caller-facing surface is the Nostr protocol, which has its
own error vocabulary.

- Operator-facing: internal error enums per module (`domain`, `db`, `ws`),
  each preserving its source (`std::error::Error::source` by hand;
  `thiserror` is convenience, not capability). Log the full chain as
  structured fields.
- Client-facing: `OK` `false` with a machine-readable prefixed reason
  (`invalid:`, `blocked:`, `rate-limited:`, `error:` per NIP-01), `CLOSED`
  with a reason for subscriptions, and NOTICE sparingly. A database failure
  is `error: could not store event` to the client and a full cause chain in
  the log — never the SQL, never the DSN, never internal details.
- Fail closed maps to the book's "500 on unexpected": on any doubt
  (deserialization failure, invariant violation, storage uncertainty) the
  relay rejects or disconnects rather than acknowledging work it cannot
  prove happened.
- Panics are for invariant violations only, never for input handling; a
  malformed client frame must never take the process down (ZTP ch. 8's
  panic-vs-error line, sharpened by relay threat models).

## 10. Security and auth hardening

**Book (ZTP, ch. 10).** Defense in depth: enforce TLS everywhere; store
passwords as salted Argon2id PHC strings with OWASP parameters; make
credential checks constant-time-ish to resist timing side channels and user
enumeration; run CPU-heavy verification on a blocking thread so the async
runtime is not starved; validate untrusted input at the boundary with typed
parsing ("parse, don't validate", ch. 6); HTML-encode or MAC anything echoed
back (XSS, HMAC-tagged messages); rotate session tokens; generate tokens
from a CSPRNG; least privilege for cookies and everything else.

**Immortal.** No passwords, no sessions, no cookies — but every principle
has a relay-shaped twin.

- TLS everywhere: terminated at the reverse proxy (repo invariant). The
  proxy speaks `wss://`; the binary listens on a private address. Plain
  `ws://` is exposed only on localhost for debugging.
- Typed parsing at the boundary: incoming frames parse through
  `serde_json` into strict domain types in `src/domain/` (owned Nostr
  primitives, AGENTS.md rule 3) before any logic runs. Unknown or oversized
  input is rejected early — the ch. 6 insight applied to the relay's only
  untrusted input.
- CPU-heavy work off the reactor: Schnorr signature verification
  (`secp256k1`) and sha256 id checks run under `tokio::task::
  spawn_blocking` or a bounded worker set when under load, exactly the
  ch. 10 `spawn_blocking` pattern for Argon2, so verification storms cannot
  starve the event loop.
- Identity is signature-based (NIP-42 auth challenges instead of
  passwords). Challenges must be unpredictable: generate them from
  `getrandom`-quality randomness (via the OS through `std`; if a dedicated
  RNG crate is ever wanted, that requires owner sign-off per AGENTS.md
  rule 2 — `sha2` over an OS-random seed and counter is an allowlisted
  interim). Bind challenges to the connection and expire them; validate the
  `relay` tag against `IMMORTAL_RELAY_URL` — the ch. 10 token-rotation and
  session-fixation lessons mapped to NIP-42.
- Enumeration and side channels: rejection reasons are uniform where a
  distinction would leak policy internals.
- Limits are security controls, not tuning knobs: frame size,
  subscriptions per connection, filters per `REQ`, query cost, rate limits
  per IP and per pubkey (AGENTS.md rule 5). The book's fair-usage footnote
  on idempotency-key abuse (ch. 11) generalizes: every unauthenticated
  resource needs a cap.
- systemd hardening flags sandbox the process on the VPS path (see the
  Debian runbook) — the deployment-layer half of defense in depth.

## 11. Fault tolerance

**Book (ZTP, ch. 11).** Enumerate failure modes honestly: invalid input,
network I/O to the database, external API errors, application crashes,
impatient users retrying. Partial execution is the enemy; drive workflows to
a sensible terminal state via backward recovery (compensating actions) or
forward recovery (checkpoints, background workers). The book converts
newsletter delivery to a Postgres-backed task queue consumed by a background
worker using `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1`, deleting each task
in the same transaction as its completion, with sleep-and-retry backoff and
an idle sleep on empty queue. It runs API and worker as sibling tokio tasks
(`tokio::spawn` + `tokio::select!`) and stresses that transactionality is
recovered by keeping state transitions inside one database.

**Immortal.** Immortal's core failure-mode analysis is already in the
architecture; the book confirms the shape and adds patterns.

- One database means workflow state transitions are transactional by
  construction — the exact property the book had to *recover* by moving its
  queue into Postgres. Do not add a broker: `LISTEN/NOTIFY` plus
  `ingest_seq` is the delivery mechanism, and the sequence number is the
  checkpoint for forward recovery. A relay process that missed
  notifications catches up by scanning `ingest_seq` from its last seen
  value; if it cannot catch up, it fails closed.
- `FOR UPDATE SKIP LOCKED` is the sanctioned pattern for any future
  multi-process maintenance work (retention sweeps, index rebuilds) so
  processes never contend or duplicate work. Advisory locks serve the
  same role for one-shot coordination (migrations).
- Background maintenance runs as tokio tasks inside the same binary
  (`tokio::spawn`, supervised via `tokio::select!` with exit logging, as in
  ch. 11) — never as a second service.
- Retry with backoff on transient database errors; sleep on idle instead of
  busy-polling (`worker_loop` pattern, ch. 11.10.4.5). Distinguish
  transient from fatal errors so the loop reacts appropriately.
- Crash analysis (ch. 11.3.3) applied: a crash mid-admission never emitted
  `OK`, so the client retries; a crash mid-broadcast is healed by clients
  reconnecting and re-subscribing. Both paths end in a consistent state
  without operator action.

## 12. Idempotency

**Book (ZTP, ch. 11).** An endpoint is retry-safe (idempotent) if the caller
cannot observe whether a request was processed once or several times.
Callers signal intent with idempotency keys; the server stores the key with
the outcome and replays the stored response on retry. Concurrent duplicates
need cross-request synchronization — the book inserts the key row first
(`INSERT ... ON CONFLICT DO NOTHING` inside a transaction) so the second
request blocks on Postgres row locks under `READ COMMITTED`, then either
processes or replays. Expire stored keys.

**Immortal.** Nostr has a built-in idempotency key: the event id (sha256 of
the canonical serialization, signed).

- `EVENT` admission is idempotent by design: insert with
  `ON CONFLICT (id) DO NOTHING`; a duplicate returns `OK true` with
  `duplicate:` — the caller observes success either way, which is exactly
  the book's definition. No key store, no response cache, no expiry problem:
  the event row *is* the record.
- Concurrent duplicate submissions of one event id are serialized by the
  same unique-constraint-plus-transaction mechanics the book builds by hand
  (ch. 11.9): Postgres row locking under `READ COMMITTED` makes the second
  writer wait, then observe the winner. Replaceable-event races resolve
  the same way on the head row: newest `created_at` wins, ties broken by
  lowest id, decided inside the admission transaction.
- Deletion tombstones make deletes idempotent and order-independent: a
  delete arriving before its target still wins, because admission checks
  tombstones transactionally.
- Ephemeral events short-circuit before storage (never stored — repo
  invariant), so their redelivery semantics are the client's concern, as the
  protocol intends.

## 13. CI

**Book (ZTP, ch. 1).** A CI pipeline should gate every change with: `cargo
test`, `cargo fmt --check`, `cargo clippy -- -D warnings` (deny warnings in
CI, not necessarily locally), code-coverage reporting (`cargo tarpaulin`) as
information, and `cargo audit` for known-vulnerable dependencies. Fast
feedback beats thorough-but-slow; keep the pipeline runnable by every
contributor.

**Immortal.**

- The same five gates apply unchanged — they are toolchain, not
  dependencies. `cargo audit` (or `cargo deny`) is cheap here because the
  dependency tree is tiny; it also guards the allowlist: CI can diff
  `cargo metadata` direct dependencies against the seven allowed names and
  fail on drift, mechanically enforcing AGENTS.md rule 2.
- Integration tests run against a real Postgres (the book launches one in
  Docker; a GitHub Actions `services:` container or a local
  `scripts/init_db`-style script both work). Each test creates a
  randomized-name logical database for isolation, then applies the
  migration files — the ch. 3 test-isolation pattern, using our own
  migration runner instead of `sqlx::migrate!`.
- Protocol fixtures are part of the gate: each implemented NIP has a fixture
  corpus (AGENTS.md rule 8), and CI runs them like unit tests.
- The deployment test stays green (AGENTS.md rule 9): a scripted
  check that a fresh Debian container + apt Postgres + the release binary
  serves NIP-11 and accepts an event, mirroring the book's insistence that
  the deploy path itself is tested, not assumed.
