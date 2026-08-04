# AI Provenance

This file records which AI agents wrote this repository, and which agent
does what. Update this file when an agent joins, leaves, or changes role.

## Record to date

As of commit `0efe8e0` (2026-08-03; superseded by the work log below —
Codex's first implementation commit is `8c22cc2`, M1 domain):

- **100% of the repository content was written by Anthropic Claude**
  (Claude Fable 5 / Opus 5, one Claude Code session), directed and
  reviewed by the human owner.
- 5 of 6 commits carry the trailer
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
  Later Claude commits may carry `Co-Authored-By: Claude Fable 5
  <noreply@anthropic.com>`. Both name the same Claude session lineage.
- The remaining commit (`e95bafd`, "Initial commit") is the GitHub
  repository creation with the LICENSE file only.

## Who does what

| Actor | Role |
| --- | --- |
| Human owner | Direction and decisions. Dependency approvals (AGENTS.md rule 2). NIP adoption decisions. Final review. |
| Claude (Anthropic) | Foundation to date: doctrine, NIP source policy and sync, roadmap, inspiration reviews, deployment docs. Ongoing: architecture, policy documents, and review. |
| Codex (OpenAI) | Implementation of the roadmap milestones (`docs/ROADMAP.md`, M1 and later): domain, store, gateway, conformance, under the AGENTS.md rules. Handoff date: 2026-08-03. |

## Active work log

### 2026-08-03 — Codex 5.6 Sol (Extra High), M1 Domain

- Accepted the implementation handoff from Claude Fable 5 at commit
  `15e736b` on `main`.
- Read the binding repository rules and pinned NIP-01, NIP-09, and NIP-40
  specifications before implementation.
- Scope: the complete M1 domain milestone — owned event and tag types,
  canonical IDs, Schnorr verification, exact filter matching, kind and
  replacement semantics, expiration, deletion tombstones, timestamp bounds,
  and attributed fixture corpora.
- Dependency decision: use only the already-approved `secp256k1`, `sha2`,
  `serde`, and `serde_json` entries from the `AGENTS.md` allowlist. No owner
  approval or rule change is required. `secp256k1` is CC0-1.0 (the same
  license as Immortal) and explicitly allowlisted; the other three are dual
  MIT/Apache-2.0.
- Concurrent-work note: Claude completed and pushed the deployment-doc set as
  commit `b74a5e8` while M1 was in progress. The shared worktree advanced
  cleanly; Codex did not modify those files.
- Implemented the owned `src/domain/` library with explicit validation layers
  and pure replacement/deletion decisions suitable for the M2 admission
  transaction.
- Added committed NIP-01, NIP-09, and NIP-40 fixture files with source and
  license attribution. The first complete run passed 14 fixture tests in both
  debug and release modes; follow-up review added canonical escaping coverage
  and aligned malformed expiration tags with the pinned spec/reference
  behavior (ignored rather than treated as event-invalid).
- Milestone-close verification: 15 optimized fixture tests pass;
  `cargo clippy --all-targets -- -D warnings`, rustdoc with warnings denied,
  formatting, and `git diff --check` are clean. Updated the README and roadmap
  to distinguish the completed domain milestone from the still-skeletal
  store, gateway, and executable server.

### 2026-08-03 — Human owner: first dependency approval

- Approved `tokio-postgres-rustls` (with its `rustls` chain) as an
  optional TLS backend for managed Postgres services that require TLS.
  The approval is recorded in `AGENTS.md` rule 2, which stays the
  canonical approval list. The dependency is not in the tree yet; it
  enters only when the TLS deployment path is implemented, behind a
  feature flag.
- Context: the deployment review (commit `b74a5e8`) surfaced the blocker
  — DigitalOcean Managed Postgres mandates TLS, which `tokio-postgres`
  alone cannot speak. Claude surfaced it; the owner decided.

### 2026-08-03 — Codex 5.6 Sol (Extra High), M2 Store

- Began M2 from commit `c8b6053` after reconciling the owner's optional
  Postgres-TLS approval. M2 uses only the original allowlisted `tokio` and
  `tokio-postgres`; the approved TLS backend remains out of the dependency
  tree until its deployment path is implemented.
- Scope: versioned transactional migrations; event, tag, replacement,
  deletion-tombstone, and policy tables; prepared runtime statements;
  admission with cross-process race serialization; ingest sequencing and
  transactional `NOTIFY`; NIP-01 query/catch-up reads; full-text-search
  storage; and least-privilege operations documentation.
- Verification plan: deterministic unit/fixture checks plus an isolated
  temporary PostgreSQL 16 cluster on this workstation, with no persistent
  service or second database added to the product architecture.
- Implemented the version-1 schema and migration ledger. Migration names and
  SHA-256 hashes are verified under a database-wide advisory lock; immutable
  embedded DDL is the only non-prepared execution path. Added a verification-
  only connection mode for a split least-privilege runtime role.
- Implemented prepared admission and read statements. Conflicting event IDs
  and replacement addresses take sorted transaction-scoped advisory locks;
  the event, tag indexes, head transition, tombstones, deletions, ingest
  sequence, and `NOTIFY` commit as one unit. Ephemeral events are checked but
  never inserted, with a database constraint as a second barrier.
- The first disposable-Postgres run passed the live M2 contract, including
  idempotent migration, hash verification, post-commit notification, FTS,
  exact tag lookup, replacement tie races, deletion-before-event, and a
  concurrent deletion/arrival race across independent connections.
- Reconciled Claude's concurrent production-parity audit at commit `aedb027`
  into the active M2 implementation. The database-owned admission pipeline now
  includes optional pubkey and kind allowlists, pubkey and kind blocklists,
  closed membership, UTF-8 content-byte and tag-count limits, and configurable
  future and past timestamp bounds. Each branch has a live-Postgres contract
  assertion and the split runtime role remains read-only over policy state.
- Milestone-close verification: 15 optimized domain fixture tests and the M2
  static contract pass; `cargo clippy --all-targets -- -D warnings`, rustdoc
  with warnings denied, formatting, and `git diff --check` are clean. The final
  disposable-Postgres run passed migration application and idempotence, hash-
  drift failure, runtime-role grants, transactional notification, query and
  FTS reads, ephemeral and expiration handling, replacement/deletion races,
  and every configurable policy branch. The destructive live suite requires
  its disposable-database guard, preventing accidental use against an
  operator database.

### 2026-08-03 — Claude: production-parity audit and roadmap update

- Audited the operator's existing production relay
  (`relay.openagents.com`, currently hosted from the prior TypeScript
  implementation) and its two client applications (the OpenAgents
  monorepo surfaces and the Omega desktop client) to enumerate the
  relay-side surface actually in use.
- Findings: wire verbs EVENT, REQ, CLOSE, and AUTH; NIP-42
  authentication; NIP-29 relay-managed groups with `h`-tag scoping,
  pre-store membership enforcement, moderation and join/leave kinds, and
  relay-signed 39000-range metadata; gift-wrapped private messages
  (kinds 13/14/1059) that need recipient-gated delivery; NIP-78 and
  NIP-51 addressable data plus several custom kinds admitted by policy;
  a policy pipeline (allow/block kinds and pubkeys, closed membership,
  size and timestamp bounds); NIP-11. COUNT and negentropy are served by
  the current host but no client uses them.
- Roadmap updated so a defined point reaches functional parity for a
  cutover: the M2 policy pipeline is now explicit, M6 gains NIP-17
  delivery gating, NIP-29 groups, and the NIP-86 management API ahead of
  COUNT/search, and a new M9 milestone defines the drop-in replacement
  kit (bulk import, NIP-11 parity, policy mapping, shadow mode, cutover
  and rollback runbook).
- Known adjacency, deliberately out of scope: the current host's NIP-29
  module also serves group-call well-known endpoints for a media
  service. That stays a reverse-proxy concern on the operator side; it
  does not enter this binary.

### 2026-08-03 — Codex 5.6 Sol (Extra High), M3 Gateway

- Began M3 from commit `5acb0ff` on a clean `main`, current with
  `origin/main`, after rereading the repository doctrine, configuration
  contract, M2 store interfaces, and pinned NIP-01, NIP-11, and NIP-42 texts.
- Scope: the complete WebSocket/HTTP gateway milestone — owned wire parsing,
  NIP-11, per-connection NIP-42 state, indexed subscriptions, race-free
  history/live handoff, durable and ephemeral cross-process fanout, bounded
  resources and rate limits, cancellable queries, graceful shutdown, and
  executable startup.
- Dependency decision: add `tokio-tungstenite` 0.30.0 with only its handshake
  feature and expand the existing `tokio` feature set for networking, signals,
  and I/O utilities. Both direct dependencies are already explicitly allowed
  by `AGENTS.md`; no new approval is required. The crate is MIT-licensed, and
  disabling default features avoids pulling a client connector or TLS stack
  into the relay server.
- Implemented fail-fast environment parsing and the runnable binary; migration
  and fixed runtime workers become current before bind. One bounded gateway
  serves health, NIP-11 with CORS, and WebSocket upgrades on the same listener,
  accepts every path consistently, and drains on SIGINT/SIGTERM.
- Implemented owned NIP-01/AUTH wire parsing, per-connection unpredictable
  NIP-42 challenges, fixed-window IP/pubkey limits, query-cost and shape
  bounds, cancellable historical jobs, bounded outbound queues, and an indexed
  subscription hub keyed by event ID, author, kind, and tag.
- Made the EOSE boundary explicit: durable sequence allocation is serialized
  at the end of admission, subscriptions enter buffering before their query,
  history reads through a sampled high-water mark, and the hub deduplicates and
  flushes later durable plus ephemeral events after EOSE.
- Implemented the ephemeral lane without storage: immediate in-process fanout
  follows the completed admission transaction, while validated hexadecimal
  chunks travel over Postgres `NOTIFY` to other relay processes. A bounded
  recent-ID window suppresses the publisher process's notification echo.
- The first fresh-Postgres M3 run passed a real two-process HTTP/WebSocket
  contract: NIP-11/CORS, per-connection AUTH and auth-required refusal,
  historical EOSE, durable cross-delivery, duplicate suppression, a chunked
  12 KB ephemeral event with no historical result, CLOSE, and graceful
  shutdown.
- Milestone-close hardening bounded configuration values, malformed response
  identifiers, historical batches, EOSE buffers, notification reassembly, and
  every local queue; AUTH shares the EVENT rate budgets and oversized outbound
  events close only their slow/incompatible client. Final verification passed
  formatting, all-target checks and tests, Clippy with warnings denied,
  rustdoc with warnings denied, and an optimized build. The final disposable-
  Postgres deployment run passed the M2 store contract, the two-gateway M3
  contract, and a real binary startup/health/NIP-11/SIGTERM smoke test.

### 2026-08-03 — Codex 5.6 Sol (Extra High), M4 Conformance

- Began M4 from commit `3e920ee` on a clean `main`, current with
  `origin/main`. Scope: wire every implemented NIP and M1–M3 invariant into
  CI, prove multi-process recovery and failure behavior with actual relay
  binaries, and publish repeatable events/sec, connect-p99, and
  REQ-to-EOSE-p99 numbers.
- Dependency decision: M4 uses only the existing allowlisted dependency tree.
  The proof harnesses use the relay's own `tokio-tungstenite`,
  `tokio-postgres`, cryptography, and JSON stack; no approval or new crate is
  required.
- Added a durable notification cursor. `LISTEN` becomes current before the
  startup high-water sample; every later notification advances through a
  bounded prepared catch-up query. Missing positions caused by an omitted
  notification or a rolled-back/deleted row are safe, while an unprovable or
  greater-than-4,096-position gap closes clients and exits non-zero.
- Added an actual-process proof using two independently spawned Immortal
  binaries and one Postgres database. It verifies cross-process delivery,
  replays an intentionally unnotified committed row, kills one relay and
  proves the survivor remains current, then injects an unbounded gap and
  proves fail-closed connection teardown and non-zero exit.
- Expanded M3 coverage for NOTICE, malformed signatures, filter and
  subscription limits, oversized frames, query cancellation, every
  subscription-index lane, and send-queue overflow. Added a coverage matrix
  and a GitHub Actions workflow that runs formatting, warnings-denied Clippy,
  every pinned fixture/static test, fresh-Postgres contracts, process chaos,
  the load proof, and the binary deployment smoke test. M5 subsequently
  deletes that workflow under the owner's no-GitHub-automation invariant;
  this sentence remains as the historical M4 record.
- Published the five-run optimized workstation baseline: 6,849.89 committed
  events/sec median, 0.41 ms WebSocket-connect p99 median, and 2.12 ms
  REQ-to-EOSE p99 median for ten historical events. The committed report names
  samples, ranges, hardware, durable Postgres settings, exclusions, and the
  exact reproduction command rather than presenting the result as a
  production capacity promise.
- Milestone-close verification passed formatting, locked all-target checks and
  tests, Clippy with warnings denied, rustdoc with warnings denied, optimized
  build, shell syntax, workflow-YAML parsing, and `git diff --check`. The final
  durable disposable-Postgres run passed M2 storage, expanded M3 gateway, M4
  two-binary gap/chaos, five-run release load, and actual binary
  startup/health/NIP-11/SIGTERM contracts; its independent load sample stayed
  within the published baseline ranges.

### 2026-08-03 — Human owner: no GitHub automation invariant

- Directed that Immortal must not use GitHub workflows for any purpose and
  that no required check may depend on GitHub billing. Required conformance
  must be manual or use separately approved non-GitHub infrastructure.
- The decision is binding as `AGENTS.md` rule 11. M5 removes the M4 GitHub
  Actions workflow and replaces its required gate with a committed local
  command; no GitHub-hosted check remains part of the project contract.

### 2026-08-03 — Codex 5.6 Sol (Extra High), M5 Deployment Kit

- Began M5 from commit `c2a91e9` on a clean `main`, current with
  `origin/main`, and accepted the handoff under the identity Codex 5.6 Sol
  (Extra High). Scope: prove a new Debian host from package-manager
  dependencies through a real relay and database restore; commit hardened
  service, proxy, container, and backup assets; and make the Debian,
  DigitalOcean, and Google Cloud runbooks operationally honest.
- Reconciled the owner's no-GitHub-automation decision first. Deleted
  `.github/workflows/conformance.yml`, added the repository invariant, and
  moved the complete required gate to `scripts/test-conformance.sh`, which a
  contributor runs locally. The deployment acceptance wrapper selects a
  local Apple Container, Podman, or Docker runtime and has two explicit
  disposable-environment guards before its destructive inner script runs.
- Added the deployment kit: a reproducible multi-stage root `Dockerfile`, a
  fail-fast environment template, a hardened single-box systemd unit, Caddy
  and nginx WebSocket proxy templates, and an atomic custom-format `pg_dump`
  program with a sandboxed systemd service and persistent nightly timer.
  Static deployment tests pin the security and architecture invariants,
  including the absence of a GitHub workflow directory.
- The first fresh-Debian build exposed that the code used Rust syntax newer
  than Debian 13's package-manager Rust 1.85. Declared that minimum supported
  version and rewrote the handful of let-chain and integer-helper expressions
  into semantically equivalent Rust 1.85 forms. No dependency was added and
  no protocol behavior changed.
- The disposable Debian 13 proof installs apt PostgreSQL and Rust, builds the
  locked release, validates the committed systemd units, starts the actual
  relay, checks health and NIP-11, publishes and queries a pinned signed event
  over a raw WebSocket client, shuts down with SIGTERM, then creates and
  restores a real dump and verifies the restored `nostr_event` row.
- Reworked the runbooks around paths the current binary can actually support.
  Debian 13 is the canonical single-box deployment. DigitalOcean's supported
  path is a Debian Droplet because Managed PostgreSQL requires TLS and the
  owner-approved optional TLS backend has not landed. Google Cloud documents
  the Cloud Run/Cloud SQL Unix-socket path and its WebSocket timeout/reconnect
  behavior plus a Debian GCE alternative. Restore, upgrade, and rollback
  instructions now account for Immortal's migration ledger and its deliberate
  refusal to run an old binary against an unknown schema.
- Milestone-close verification rebuilt the final multi-stage image as
  `immortal:m5`, then passed the complete committed manual gate: formatting,
  locked all-target checks and tests, Clippy and rustdoc with warnings denied,
  shell/Python/static checks, M2 live storage, M3 live gateway, M4 two-process
  gap/chaos, five-run release load, and M5 fresh-Debian acceptance. The load
  sample reported 6,555.07 committed events/sec median, 0.43 ms connect-p99
  median, and 2.08 ms REQ-to-EOSE-p99 median. The disposable Debian 13 image
  used apt Rust 1.85 and PostgreSQL 17; systemd verification, signed-event
  publish/query, graceful shutdown, and the real backup restore all passed.

### 2026-08-03 — Codex 5.6 Sol (Extra High), M6 NIP Expansion

- Began M6 from commit `172c4bc` on a clean `main`, current with
  `origin/main`, and continued the owner-directed handoff as Codex 5.6 Sol
  (Extra High). Read the binding repository doctrine and the pinned official
  NIP-17, NIP-29, NIP-40, NIP-45, NIP-50, NIP-65, NIP-70, NIP-77, NIP-86,
  and NIP-98 specifications before changing the implementation. NIP-91 is not
  present in the pinned official lane.
- Dependency and architecture decision: M6 adds no crate, service, cache,
  broker, sync engine, or second database. Relay signing, NIP-98 Base64 and
  payload verification, group semantics, COUNT, and search use the existing
  allowlisted Rust dependencies. Expiration cleanup is an in-process task on
  a dedicated connection to the same Postgres database and fails the process
  closed if it cannot remain current.
- Added migration 2 and prepared statements for authoritative group members,
  invites, metadata, and management replay protection. Admission now applies
  group state and signed metadata atomically, while query and count paths
  apply expiry, full-text search, and authenticated gift-wrap recipient
  gating. The scheduled NIP-40 sweep physically removes expired rows.
- Added owned domain validation and signing for NIP-17 routing lists and gift
  wraps, the supported NIP-29 moderation/join/leave subset, NIP-70 protected
  events, and NIP-98 HTTP authorization. Accepted group joins/leaves also
  create relay-signed 9000/9001 history events; current signed 39000–39005
  documents are regenerated after state transitions.
- Expanded the one-listener gateway with bounded exact NIP-45 COUNT,
  Postgres-backed NIP-50 search, same-connection protected publication, and a
  65,536-byte NIP-86 JSON-RPC path authenticated by exact URL, method, payload
  hash, timestamp, signature, configured owner pubkey, and one-use event ID.
  Standard policy methods and explicit group administration extensions change
  the same tables used by admission.
- Recorded exact source-lane decisions and deliberate subsets: NIP-65 relay
  lists remain client routing metadata; NIP-77 stays watched without adding a
  sync engine; absent NIP-91 is not advertised; all Block specs stay parked;
  and the OpenAgents lane remains postponed by its recorded owner direction.
  Added committed fixture corpora for each implemented M6 protocol surface.
- The pre-close audit added relay-signed join/leave history, validated recent
  group timeline references and NIP-65 relay lists, covered generic protected
  reposts, made duplicate group creation a non-fatal management error, and
  preserved deletion tombstones after an expiring deletion event is physically
  swept. Each issue became a fixture or live contract assertion before close.
- The first complete manual-gate invocation stopped immediately on a formatting
  diff introduced during that audit. After formatting, the clean rerun passed
  all locked all-target tests, warnings-denied Clippy and rustdoc, shell/static
  checks, fresh-Postgres store and expanded two-gateway contracts, two-process
  gap/chaos, release load, and fresh-Debian acceptance. The five-run load sample
  was 6,240.41 committed events/sec median, 0.40 ms connect-p99 median, and
  2.52 ms REQ-to-EOSE-p99 median. Debian 13's apt Rust 1.85 and PostgreSQL 17
  built and ran the relay, published/queried a signed event, shut down cleanly,
  and restored a real backup. The final `immortal:m6` production image also
  rebuilt successfully.

## Rules

1. Every AI-authored commit carries a `Co-Authored-By` trailer that names
   the agent.
2. The AGENTS.md rules bind every agent equally. No agent adds a
   dependency, a service, or an unfixtured protocol change.
3. An agent's work is not accepted by authorship. It is accepted by the
   fixtures, the checks, and the owner's review.
4. Update the record in this file at each milestone, or when the set of
   contributing agents changes.
