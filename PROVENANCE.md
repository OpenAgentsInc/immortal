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

### 2026-08-06 — Codex 5.6 Sol, executable browser requester / issue #34

- Added the ordinary `immortal-client-web` zero-import WASM artifact over the
  production MKT-SWP requester dispatcher, plus a dependency-free JavaScript/
  TypeScript adapter. The versioned ABI pins its requester contract and build
  source revision, bounds requests, transfers no raw pointers, and fails closed
  on ABI, source, or contract mismatch.
- Exposed Offering and signed-delivery validation, external-signature checks,
  RFQ/Order/Contract/Cancel/Close construction, exit-package inspection,
  session ingest/persist/restore, and two-phase verify-before-fund funding
  requests whose authorization must echo the exact prepared request. The
  host retains entropy, signing, wrapping, transport, storage, observations,
  wallet execution, and every secret or node credential.
- Extended the separate relay/provider smoke so the shipped dispatcher drives
  all three no-spend swap shapes through bilateral Contracts, cancellation,
  exact zero-loss Close, stable reload, and idempotent replay. Added no external
  dependency, service, database, event kind, relay behavior, custody authority,
  NIP-11 advertisement, workflow, or billed automation.
- Normalized three existing match/iterator expressions for the Rust 1.95
  workspace-wide `-D warnings` Clippy gate; those mechanical edits do not
  change MKT-LSP validation or funded-provider behavior.

### 2026-08-06 — Codex 5.6 Sol, M13 zero-confirmation policy / issue #30

- Added an off-by-default, direction-bounded provider policy for requester-
  funded Bitcoin submarine and chain source legs. Quotes bind the local-view,
  non-RBF policy; admission requires no unconfirmed ancestors and both
  per-swap and durable aggregate exposure caps.
- Added explicit zero-conf acceptance and confirmation-required Status
  validation without changing requester finality, verify-before-fund, or
  refund authority. The funded provider rechecks before its risk effect and
  uses a deterministic risk-reservation session scope distinct from the hard
  Quote reservation.
- Extended the closed adversarial ledger to 46 cases. The three new regtest
  process cases pass full-RBF replacement, non-RBF competing spend, and
  ancestor invalidation with an unpaid invoice and no provider settlement
  effect. Added no dependency, event kind, relay behavior, relay database
  schema, custody material, NIP-11 advertisement, workflow, or billed
  automation.

### 2026-08-05 — Codex 5.6 Sol, M12 migration closing packet / issue #19

- Added the provider drain state shared by the native actor, compatibility
  listener, health endpoint, and funded process. Draining pauses discovery,
  refuses new sessions, retains relay recovery and watchtower work for active
  sessions, and publishes bounded public counters until zero.
- Added the immutable client provider-route tuple, committed Debian provider
  environment/systemd/backup/TLS assets, and a clean-host acceptance gate that
  verifies the release build, file modes, systemd graph, database backup digest,
  and restore before running the funded smoke.
- Added an append-only provider migration that schema-qualifies recursive
  public-state safety checks, allowing `pg_dump` restores to replay table data
  under PostgreSQL's empty restore search path without changing prior
  migration bytes.
- Added the seven-route GET-only Boltz shadow recorder and the swap-network
  stand-up, cutover, drain, rollback, and claim-boundary runbook. Deployment,
  live operator independence, and public replacement remain false until their
  separate evidence gates pass.
- At source commit `764d119`, the fresh Debian 13 arm64 install, systemd,
  backup/restore, and funded gate passed; the live Boltz shadow returned seven
  bounded successes with five retained shape divergences; and the #18-backed
  cutover rehearsal passed. The resulting record asserts local replacement
  capability while keeping all three live/public claims false.

### 2026-08-05 — Codex 5.6 Sol, M12 multi-provider negotiation / issue #32

- Added the reusable three-CLN-role, two-relay, two-provider process gate. One
  requester discovers both independently keyed no-spend providers, retains the
  exact wrapped deliveries privately, reconstructs both production requester
  Quote views, and applies a fixture-pinned total ordering.
- Added bounded success and failure records that retain only public topology
  counts and identifiers, normalized Quote terms, and the selected Quote. The
  live macOS run passed with both channels normal on every CLN node and removed
  all disposable containers and the mode-0700 private root afterward.
- Added a separate funded gate with two provider databases and provider-owned
  CLN socket/seed boundaries. It compares hard Quotes before Orders, cancels
  and releases rank two with zero spend, and settles rank one through confirmed
  Bitcoin claim and paid Lightning invoice. Clean-host, deployment, and public
  replacement claims remain open.

### 2026-08-05 — Codex 5.6 Sol, M12 Boltz compatibility handoff / issue #15

- Added a fixture-pinned released-client route profile and an off-by-default,
  exact-digest relay handoff to an independently deployed provider origin.
  Safe `307` construction preserves method and body while the relay reads no
  body and persists no compatibility session state.
- Added the pre-broadcast submarine finalize route required to retain matching
  bilateral MKT-SWP Contracts, plus explicit script-path client settings and a
  sensitive-body non-read proof. No provider, client, wallet, spend, preimage,
  signer, node, or rail dependency entered the relay crate.
- Recorded all 53 pinned v2 route dispositions and the released-client gate.
  Redirects count as 0 emulated endpoints; the external provider API and
  adapted-client process proof remain blockers, so no replacement or issue
  completion claim is made.

### 2026-08-04 — Codex 5.6 Sol, M12 MKT-SWP provider sessions / issue #14

- Implemented the transport-neutral provider engine in
  `crates/immortal-provider`: rotating discovery requests, complete
  indicative/soft/hard Quote construction, reserve-before-hard-signing and
  release callbacks with exact replay, bilateral contract binding, Status
  projection, mutual cancellation, and exact no-spend Close accounting.
- Added bounded custody-free snapshots and provider self-recovery, plus the
  `immortal-provider --no-spend` actor for all three swap shapes. The actor
  signs no funding action and owns no wallet, rail, node credential, database,
  preimage, or settlement authority; funded execution remains issue #25.
- Added a closed 30-case provider fixture, production requester reconstruction
  of provider negotiations, native/no-default/zero-import WASM conformance,
  separate provider fixture-manifest scope, and the relay dependency-tree
  boundary check. Relay CLI, contract JSON, NIP-11, executable profiles, and
  Postgres behavior remain unchanged.

### 2026-08-04 — Codex 5.6 Sol, M12 coordination handler / issue #13

- Implemented the optional, exact-conformance MKT-SWP handler in the existing
  relay binary and Postgres: provider-signed none/soft/hard reservation
  accounting, capacity and commitment-fork refusal, covenant reserve as the
  strongest hard proof class, dense Status gap/fork views, and bounded
  reservation-only timeout release.
- Added the measured Bitcoin-transaction verification hook and relay-signed
  NIP-32 observations labeled `observation_not_authority`. Decrypted records
  and raw transactions remain in memory only; the schema stores bounded
  identifiers, accounting fields, and hashes, with custody-member tripwires.
- Added migration 0011, fixture and deterministic contract sections,
  off-by-default NIP-11 gating, source/deployment/protocol documentation, and
  a two-relay-process/one-Postgres proof of allocation, fork projection,
  replay, and idempotent expiry consistency. No kind allocation, dependency,
  service, database, wallet, node credential, participant key, or settlement
  authority was added.

### 2026-08-04 — Codex 5.6 Sol, M12 MKT-SWP client engine / issue #12

- Implemented the native/WASM transport-neutral requester engine for all
  three MKT-SWP v1 flows: deterministic external signing requests, bilateral
  RFC 8785-compatible contract binding, per-signer lifecycle projection, and
  structural verify-before-fund authorization.
- Added wallet-owned claim/refund transaction signing, deterministic external
  effect replay, crash restore that always re-enters verification, typed
  recovery actions, pre-signed keyless Esplora broadcast, and recursive
  custody-material tripwires. No dependency, service, database, private key,
  preimage, macaroon, signing nonce, or broadcast authority was added.
- Added the deterministic client fixture, machine-contract export, protocol
  and source-lane decisions, and native/no-default/WASM/manual conformance
  coverage. The relay executable-profile and NIP-11 claims remain unchanged.
- Closed the client audit with snapshot-v2 typed effect-request replay,
  funding-gated crash-restorable terminal observations, signer-local Close
  ancestry, balanced unknown-loss bounds, reverse-refund recovery branches,
  and a 62-case production-API replay corpus backed by exact sessions.

### 2026-08-04 — Codex 5.6 Sol, M12 MKT-SWP relay adoption / issue #11

- Synced the released MKT-SWP and MKT-PFI drafts from OpenAgents commit
  `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682` and repeated the required
  official/Block/OpenAgents/registry collision review before allocating
  private immutable Swap Contract kind `39610`.
- Implemented the relay-observable MKT-SWP v1 contract: Offering asset,
  network, amount, side, fee, proof, and confirmation grammar; exact
  kind-to-profile binding; typed evidence references; receipt outcomes;
  immutable NIP-59-only storage; and custody-material tripwires. RFC 8785
  contract recomputation and bilateral/lifecycle execution remain client or
  configured-handler work.
- Added migration 0010, the complete 70-name upstream fixture manifest,
  deterministic contract export, source/protocol/deployment documentation,
  and the locally gated `mkt-swp:1` NIP-11 extension. No dependency, service,
  database, wallet, key, preimage, node credential, or settlement authority
  was added.

### 2026-08-04 — Codex 5.6 Sol, M12 tbDEX compatibility / issue #16

- Harvested the Apache-2.0 hosted schema vocabulary and all ten protocol parse
  vectors from frozen `TBD54566975/tbdex` protocol 1.0 at commit
  `7546a079bb860e7ede8125739b7970810a2df314`. The exact nine schema files and
  ten parse-vector files are pinned under the test-only fixture tree with
  their source paths and byte digests; the separate Immortal fixture uses
  non-sensitive adapted values.
- Added a bounded transport-neutral legacy translator that emits deterministic
  provenance and complete mapped/dropped/defaulted/ambiguous-field accounting.
  Historical DID/JOSE authority and unrepresentable payment/terminal states
  produce machine refusals; no target event, signature, reservation, custody,
  or settlement authority is created.
- Added Cancel request-only and OrderInstructions protected-channel laws plus
  exact-byte replay, closed nested-shape checks, complete optional-metadata
  loss accounting, and attached, detached, mismatch, empty-commitment, and
  unsupported-number RFQ privacy fixtures.
  The JCS `[salt, value]` rule is corroborated against tbdex-rs v4.0.0 at
  `c3d49855b4099fa663ca14c5c79e8b1e6cd8bc65`. No dependency, service,
  database state, relay behavior, kind allocation, or NIP-11 claim was added.

### 2026-08-04 — Codex 5.6 Sol, M11 local NIP-MKT development / issue #9

- Added the transport-neutral NIP-44 v2 and NIP-59 client core with bounded
  plaintexts, authenticated decryption, exact signed-inner preservation,
  signer/kind/recipient binding, official-vector coverage, and an exported
  client transport fixture.
- Added `immortal dev-market-seed` and its shell wrapper. Two throwaway actors
  publish Provider and Offering heads, authenticate recipient subscriptions,
  and complete wrapped RFQ, Quote, Order, Status, and Close records. Every
  record has independently randomized counterparty and recovery wraps; both
  are decrypted and checked against the original event ID.
- Added the disposable local relay launcher for native/Homebrew Postgres with
  Docker or Podman fallback, plus the local runbook. The live macOS proof
  completed all five stages against `ws://127.0.0.1:18080`; output contains no
  private keys and labels completion as coordination rather than settlement.

### 2026-08-04 — Codex 5.6 Sol, M10 NIP-MKT common grammar / issue #5

- Continued from the reviewed issue #4 implementation at `2b9c59e` in the
  isolated `/Users/christopherdavid/work/immortal-codex-mkt` worktree.
- Added profile-neutral validation for visible private records after durable
  replay/conflict lookup: exact common tags, lower-hex and identifier grammar,
  recursive duplicate-free JSON, private envelope agreement, references, and
  inclusive size/tag/reference/profile/hint bounds. Public MKT content remains
  a duplicate-free JSON object without inheriting the private session envelope.
- Added an exact raw-byte validator that parses one signed record and verifies
  its event structure and signature before base grammar. A separate
  profile-aware API takes explicit caller-pinned contracts; runtime exports no
  executable profiles, and synthetic fixture profile `conformance` is not a
  capability or advertisement.
- Documented the observable boundary: the relay cannot inspect encrypted
  NIP-59 inner records, prove randomness or business authority, or enforce
  profile state/settlement semantics. Those cases remain client/future-handler
  work for the M11 exported corpus.

### 2026-08-04 — Codex 5.6 Sol, M10 NIP-MKT immutable admission / issue #4

- Continued from the reviewed issue #3 implementation at `dd9fc38` in the
  isolated `/Users/christopherdavid/work/immortal-codex-mkt` worktree.
- Implemented the distinct private-kind store path for RFQ through Close
  (`39604-39609`). A durable coordinate binds `(pubkey, kind, d)` to both the
  event ID and signature, so an exact replay returns the prior successful
  duplicate result while any changed ID or valid alternate signature fails
  with the pinned `invalid: idempotency-conflict` reason.
- The binding deliberately has no event foreign key and survives NIP-09
  deletion and NIP-40 cleanup. Private MKT records do not use generic
  `replaceable_head` state. The binding lookup precedes replay-sensitive
  expiry, tombstone, and policy checks; a first rejected candidate creates no
  binding, and the accepted event plus binding commit atomically after an
  address advisory lock.
- Added fixture anchors, live sequential/concurrent/deletion/expiry/policy
  proofs, complete `39600-39699` classification pins, and an independent
  bounded reference model that exhausts admission, deletion, expiration, and
  restart action histories while checking binding and visibility invariants.

### 2026-08-04 — Codex 5.6 Sol, M10 NIP-MKT public discovery / issue #3

- Began from `ad223aa` in the isolated worktree
  `/Users/christopherdavid/work/immortal-codex-mkt` and repeated the required
  `39600-39699` collision review against all three revisions in
  `nips/manifest.json` plus `nostr-protocol/registry-of-kinds` commit
  `2483e752146d171524dcb10dffd06de2aa271bf3`. No collision was present;
  official kind `39701` remains outside the reservation.
- Implemented strict public-admission validation for Provider Profile
  `39600`, Offering `39601`, Market Profile Descriptor `39602`, and Public
  Market Receipt `39603`, preserving ordinary NIP-01 addressable replacement
  for all four kinds. The validators enforce required tag cardinality and
  shape, identifiers and profile versions, enumerations, signer-bound provider
  addresses, descriptor digests and retrieval URLs, and the specified content
  byte limits.
- Added the attributed `nipmkt/public-heads.json` corpus and focused fixture
  tests for every required field, malformed tag, enumeration, digest, URL,
  identifier, bound, and addressable-classification case. NIP-MKT remains
  absent from NIP-11 until the M10 closing conformance gate in issue #7.

### 2026-08-04 — Codex 5.6 Sol (Extra High), Operation Diamond Hands Phase 0 / issue #1

- Began from the then-current `origin/main` commit `5dfe786` in the isolated
  worktree `/tmp/immortal-issue-1.sA6ljv`, following the owner's sequential
  issue order and no-GitHub-workflow invariant.
- Read the pinned OpenAgents NIP-OT and NIP-PG contracts and adopted only the
  four records required for the first public project read path: Organization
  `32100`, Project `32222`, Project Status `32223`, and Project Update `32226`.
  NIP-BT credits remain postponed. No numeric NIP-11 claim was added for these
  proposal identifiers.
- Packaging decision: retain one Cargo package and one server binary. The
  default `server` feature owns Tokio/Postgres/gateway code; disabling it
  exposes a transport-neutral client core usable by both native and wasm
  applications. No direct dependency was added and no owner dependency
  approval was required.
- The client owns bounded REQ construction, local canonical-ID and Schnorr
  verification, NIP-OT/PG validation, EOSE snapshot truth, live folding,
  deterministic newest-event selection, reconnect/stale states, diagnostics,
  and preservation of verified unknown project-address activity. The host
  application owns the WebSocket, keeping the browser path direct to
  `wss://relay.openagents.com`.
- Measured the target boundary twice: server dependencies were first isolated
  successfully, then Apple clang failed because it has no wasm backend. The
  repository now uses a small Zig wrapper for the existing allowlisted
  `secp256k1-sys` C build and supplies the standard `memmove` prototype omitted
  by that crate's tiny wasm sysroot. Native and wasm client checks then passed.
- Added the attributed `nipotpg` fixture corpus and six focused tests covering
  positive/negative OT/PG records, filter bounds, EOSE/live behavior,
  cryptographic fail-closed behavior, forward-compatible activity, and fresh
  reconnect snapshots. Omega/OpenAgents browser integration and live proof
  remain in progress before issue #1 is closed.

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

### 2026-08-03 — Codex 5.6 Sol (Extra High), M7 Media

- Began M7 from commit `36cc758` on a clean `main`, current with
  `origin/main`, under the owner-directed Codex 5.6 Sol (Extra High)
  handoff. Read the repository doctrine plus pinned NIP-B7, NIP-94, and
  NIP-98 texts. Because NIP-B7 delegates the server HTTP contract, also
  reviewed Blossom BUD-01/02/03/08/11 at upstream commit
  `b5bd2801d1763aa635fc8fea7a76597e0eb18990` and recorded the source and
  compatibility decision in `docs/protocol/media.md`.
- Dependency and architecture decision: no new crate, service, SDK, cache,
  broker, credential protocol, sync engine, database, or GitHub automation.
  The existing allowlisted `tokio` dependency enables its filesystem module.
  The default backend is a private POSIX filesystem; the one optional cloud
  adapter is an operator-mounted object store with public redirect delivery
  and the same atomic-rename contract.
- Implemented streaming `PUT /upload`, public content-addressed GET/HEAD and
  single-range reads, owner-scoped DELETE, CORS and immutable response
  metadata on the existing listener. Upload/delete require exact one-use
  NIP-98 events, use independent IP/pubkey rates, and enforce pre-allocation
  blob bounds plus a transactional per-pubkey byte quota. Responses include
  a NIP-94 tag array; kind-1063 metadata and kind-10063 server lists gained
  owned validation and fixtures.
- Added migration 3 and prepared statements for media metadata, shared
  ownership, quotas, and authorization replay protection. The implementation
  audit replaced an initial file-first publication with pending/ready state:
  registration commits before atomic file install, public reads select only
  ready rows, and quota or replay failures remove only their private temporary
  file. A process interruption cannot expose a partial upload; a new
  authorization can retry or delete pending ownership.
- The first complete local fixture run passed. The first fresh-Postgres run
  found that PostgreSQL returns `SUM(bigint)` as `numeric`; the quota statement
  now performs an explicit checked bigint cast and the rerun passed store,
  two-gateway media, two-process gap/chaos, release load, and binary smoke
  contracts. The live media proof covers exact upload hash/auth, replay
  refusal, NIP-94 descriptor shape, HEAD, ranged GET, shared ownership through
  first-owner deletion, last-owner deletion, and subsequent absence.
- The pre-close concurrency audit added immutable per-generation storage keys.
  Last-owner deletion now removes the exact retired file, so a concurrent
  re-upload of the same content hash cannot lose its newly ready bytes. A
  delete racing pending finalization removes that exact generation, while an
  ambiguous database failure leaves it for safe retry. Media mutations now
  also lock the owner pubkey inside the transaction, preventing simultaneous
  different-hash uploads from racing the byte quota; the live store test
  exercises that race. Scheme-only media and server URLs are rejected by new
  fixture cases. Uploads also gained a five-minute total timeout and one-hour
  stale-temporary cleanup; per-IP concurrent connection limits now cover HTTP
  as well as WebSockets.
- Fresh Debian 13 acceptance passed with apt Rust 1.85 and PostgreSQL 17: the
  release binary enabled its filesystem media root, served the existing
  signed-event smoke test, stopped cleanly, created both the Postgres dump and
  private media tar, restored the dump, and verified the committed hardened
  systemd assets.
- The first complete manual-gate invocation stopped immediately on a formatting
  diff from the final audit. After formatting, the clean rerun passed all
  locked all-target tests, warnings-denied Clippy and rustdoc, shell/static
  checks, fresh-Postgres store and two-gateway media contracts, two-process
  gap/chaos, release load, and fresh-Debian acceptance. Its load sample was
  745.12 committed events/sec median, 0.32 ms connect-p99 median, and 4.11 ms
  REQ-to-EOSE-p99 median; an immediate independent rerun measured 911.52,
  0.29 ms, and 3.87 ms. Those throughput samples are retained here but not
  treated as a new baseline: the host load average was 51 and multiple
  unrelated optimized LTO Rust builds were each consuming a core. An earlier
  unobstructed same-tree run measured 6,233.29 committed events/sec, 0.40 ms
  connect-p99, and 2.57 ms REQ-to-EOSE-p99. The owner-lock regression's first
  full-gate compile then found borrowed temporary strings in the test harness;
  explicit bindings fixed it. The final clean rerun passed the entire gate,
  including the quota race, two-owner media path, and a new Debian acceptance,
  at 4,075.45 committed events/sec, 0.31 ms connect-p99, and 2.74 ms
  REQ-to-EOSE-p99. After the final URL-authority fixtures, the exact final tree
  passed the entire gate again, including another fresh-Debian proof. Its
  1,026.09 events/sec sample ran at host load average 35 alongside unrelated
  Rust and Node test builds, so it is retained as pass evidence rather than a
  replacement baseline.

### 2026-08-03 — Codex 5.6 Sol (Extra High), Block NIP Server Lane

- Began from commit `ce4addc21298a9de86f607eac35788763fb64026` on a clean
  `main`, current with `origin/main`, and accepted the owner-directed phase as
  Codex 5.6 Sol (Extra High). Read the binding repository doctrine and the
  exact pinned Block NIP-OA, NIP-AA, NIP-AO, and NIP-AM texts before changing
  runtime behavior. The owner then expanded the pass to every pinned Block
  NIP and every server-side handler, so all 15 texts were reviewed: NIP-AA,
  AE, AM, AO, AP, CW, DV, ER, GS, IA, MP, OA, PL, RS, and WP.
- Reviewed `/Users/christopherdavid/work/projects/repos/buzz` and refreshed its
  upstream objects without changing its checked-out branch. The Immortal NIP
  snapshot commit `027a74a61c8643a1d1086d3e8307fad89d7735f7` is an ancestor
  of current `block/buzz` main, and the specs plus their relevant relay,
  database, SDK, and migration handlers are unchanged between those points.
  Buzz itself contains the public server implementation; its documented
  sibling organization repositories provide internal build, release, and
  deployment machinery rather than another public relay handler source.
- Implementation inputs selected from Buzz are its first-mint agent-owner
  mapping, signed NIP-OA preimage and strict conditions grammar, NIP-AA
  membership fallback, NIP-AO direction/unknown-frame/freshness/rate shape,
  NIP-AM envelope and owner-only read rules, and the generated-FTS-column
  exclusion migration. These contracts are being adapted into Immortal's
  owned domain types, prepared `tokio-postgres` statements, existing in-memory
  subscription hub, and Postgres `LISTEN/NOTIFY` lane. No Buzz service, Redis,
  SQLx, Nostr crate, or dependency was imported. The exact Apache-2.0 review,
  borrow table, and rejected topology are recorded in
  `docs/inspiration/buzz.md`.
- Added owned domain constants, strict public-envelope/tag validators, NIP-OA
  and NIP-AA attestation verification, NIP-AO routing, and NIP-AM owner
  extraction. Added first-mint agent-owner state, closed-relay virtual
  membership, owner-aggregated publication rates, and independent bounded
  observer rates. NIP-AO stays ephemeral; unknown frames are silently dropped;
  NIP-AM and encrypted/private Block kinds stay out of FTS and behind the same
  historical, COUNT, and live-fanout ACLs.
- Added prepared transactional state for NIP-IA identity archive/unarchive,
  NIP-DV per-viewer DM visibility, and NIP-WP workspace profile commands.
  Accepted IA and DV commands atomically write relay-signed deltas/snapshots;
  relay-only kinds cannot be client-forged. NIP-11 reads the workspace icon
  from Postgres for correct multi-process visibility. NIP-AE, AP, ER, and MP
  validate and use the repository's normal addressable replacement path, with
  explicit private/shared read rules applied before ordering and limits.
- Recorded the three server-semantics cases precisely: NIP-CW's WebSocket-safe
  degradation discards extension fields and protects its relay-only overlay
  kinds; NIP-RS uses existing addressable ordering and the race-free
  high-water/EOSE/live barrier; NIP-GS defines no Nostr kind or relay handler.
  NIP-PL reaches authenticated-author, signature, public-envelope, expiry, and
  author-private read gates, then fails closed because Immortal advertises no
  executor descriptor/key and has no configured platform push transport. It
  is not advertised or stored. This pass added no service, broker, cache,
  database, dependency, GitHub workflow, or GitHub-billed check.
- Added one committed corpus for each Block NIP and new domain/static/live
  Postgres contracts. Updated NIP-11 extension discovery, deployment limits,
  source-lane decisions, the roadmap, conformance map, fixture provenance,
  README, and the public Block server contract.
- Verification before the final documentation pass: `cargo test --locked
  --all-targets` passed all ordinary targets (including 4 agent and 11 Block
  corpus tests), and `./scripts/test-postgres.sh` passed the live store and
  gateway contracts, two-process chaos, release load gate, and a new disposable
  Debian acceptance. The five-run load sample measured 1,104.70 median
  committed events/sec, 0.33 ms connect-p99, and 4.35 ms REQ-to-EOSE-p99.
- The exact final tree then passed `./scripts/test-conformance.sh`: formatting,
  locked all-target check/tests, warnings-denied Clippy and rustdoc,
  shell/static checks, fresh-Postgres store and two-gateway Block contracts,
  two-process gap/chaos, optimized five-run load proof, binary smoke, and a new
  fresh-Debian 13 relay plus backup/restore acceptance. A final NIP-AA audit
  then bound closed-relay `EVENT` authorization to the event author, with a
  live cross-identity rejection, and the strengthened exact tree passed that
  entire gate again. Its final load sample measured 4,376.44 committed
  events/sec median, 0.29 ms connect-p99 median, and 3.08 ms
  REQ-to-EOSE-p99 median. The only stopped attempts were a missing test-module
  `json!` import and one redundant-closure lint; both were fixed before the
  complete clean reruns.

### 2026-08-03 — Codex 5.6 Sol (Extra High), OpenAgents production replacement

- Accepted the owner-directed production deployment and hostname cutover from
  the completed Block server lane on clean `main` at `a8f3cf9`, current with
  `origin/main`. Identity for this pass: Codex GPT-5.6 Sol, Extra High.
- Read the Immortal Google Cloud runbook and the OpenAgents production relay,
  Google Cloud, DNS, release, and authority runbooks. Inspected the live
  environment without exporting secrets: project `openagentsgemini`, region
  `us-central1`, Cloud Run service `openagents-nostr-relay`, Cloud SQL instance
  `khala-sync-pg`, and the existing Cloud Run custom-domain mapping behind
  `relay.openagents.com`. The existing service revision remains the rollback
  target; the hostname is staying on the same Cloud Run service, so this pass
  uses revision traffic instead of a DNS or certificate mutation.
- Queried the public relay protocol before mutation. The nostr-effect relay
  returned 946 signed stored events across 43 kinds, from 2026-07-26 through
  2026-08-03. A blind binary flip would leave those rows in nostr-effect's
  `public.events` table and present an empty Immortal store, so preserving the
  history is a release gate.
- Added migration 6 and an explicitly enabled nostr-effect compatibility
  importer. It uses bounded prepared reads, decodes legacy JSONB tags, passes
  every event through Immortal's normal cryptographic and stateful admission,
  and records an outcome per source ID in an additive Postgres ledger. Startup
  drains before socket bind; bounded tail sweeps close the write race while
  the old revision remains live. Import errors fail the process closed, and a
  nonzero rejected count blocks production promotion. No source row is
  changed, no dependency or service was added, and no secret value entered the
  repository or command output.
- Added static and disposable-Postgres coverage for migration idempotency and
  a signed legacy event's one-time admission. Ordinary all-target tests,
  warnings-denied Clippy, formatting, and diff checks passed before the live
  database gate and production canary. Updated M9 and the Google Cloud runbook
  with the no-DNS, no-GitHub-automation shadow/cutover/rollback procedure.
- Production mutation, canary evidence, traffic promotion, canonical-domain
  verification, and final commit hashes are recorded below as they complete.
- Pushed the first compatibility candidate as `166b954` and built it manually
  with Google Cloud Build `ce317d84-239f-4571-ad63-a6b876031379`; no GitHub
  automation ran. The pre-cutover Cloud SQL on-demand backup operation
  `49b5afb5-6dae-47d4-a273-d73200000032` completed before schema mutation.
  A first zero-traffic revision failed closed because nostr-effect's
  authority-less Node `DATABASE_URL` is not a valid `tokio-postgres` config;
  the next revision used the already-deployed Cloud SQL socket variables and
  password secret without reading either secret value.
- Zero-traffic revision `openagents-nostr-relay-00014-niy` became healthy on
  the immutable `166b954` image. Its full source-table drain exposed 5,963
  legacy rows rather than the old relay's public-query sample of 946; 5,013
  entered Immortal and 950 were rejected. Production stayed on nostr-effect
  revision `00011-57g`. Promotion is blocked while the rejected rows are
  classified. The follow-up candidate adds bounded retry and safe aggregate
  reason codes so state-order rejections can be separated from invalid source
  data without logging event content, IDs, or secrets.
- Diagnostic revision `00015-loh` on pushed commit `b52855b` classified the
  950 rows exactly: 90 were expired, 820 referenced groups nostr-effect never
  materialized, 12 had NIP-29 `previous` references outside Immortal's recent
  group state, 27 were group actions or metadata not authored by Immortal's
  relay key, and one historical file-metadata event predates the strict `x`
  tag rule. All are cryptographically signed; there were no invalid IDs,
  signatures, hex fields, size/policy violations, or decode failures.
- The follow-up compatibility contract therefore preserves active historical
  rows after cryptographic, replacement, deletion, and relay-policy checks but
  bypasses newer extension validation and group-derived writes only inside the
  explicit legacy importer. Public WebSocket admission remains unchanged and
  strict. Migration 7 gives already-expired source rows a terminal ledger
  state, matching nostr-effect's own query suppression instead of retrying or
  serving them. The disposable-Postgres fixture now proves a valid legacy
  group event is retained, an expired event is terminally skipped, and neither
  weakens subsequent ordinary admission.
- Pushed the final compatibility implementation as `9103bca`. Its exact tree
  passed locked all-target tests, warnings-denied Clippy, formatting and diff
  checks, plus the disposable-Postgres store, two-process fail-closed, and load
  gates. The local production candidate measured 5,062.1 committed events/sec
  median, 0.34 ms connect p99, and 2.49 ms REQ-to-EOSE p99. Google Cloud Build
  `ccef31d9-389d-4028-baf8-8cded0d506c0` manually produced immutable image
  digest `sha256:74c80c053d10ed644c3fd8aa3fa9e4011df06d2af72b787f7c5986102c5bbc42`;
  no GitHub workflow or GitHub-billed automation ran.
- Zero-traffic revision `openagents-nostr-relay-00016-fib` completed the final
  compatibility pass with 950 rows scanned, 860 stored, 90 terminally expired,
  and zero rejected. Its health endpoint, NIP-11 identity, `nak` client parse,
  broad and per-kind history checks, private-kind access rules, and signed
  publish/read all passed. Event
  `9dd818b30ef4746df84e7f48d9161904f16d6e0d05f9c95729a8ea7dbf27c685`
  was accepted and read back on the canary while remaining absent from the old
  relay. The OpenAgents 30-second remote load proof passed with 996/996
  publishes and 694/694 subscriptions: 33.1 and 23.0 operations/sec, 86.9/165.9
  ms publish median/p99, 67.0/138.1 ms subscribe median/p99, and zero errors.
- Final revision `openagents-nostr-relay-00017-nij` restored the normal
  two-second startup probe on the same image and configuration. It reported an
  empty import sweep (`scanned=0`, `rejected=0`), listened in about two seconds,
  and received 100% of service traffic at approximately 2026-08-04 02:50 UTC.
  The existing `relay.openagents.com` Cloud Run domain mapping, certificate,
  and `relay CNAME ghs.googlehosted.com` record stayed Ready and were not
  changed. The previous nostr-effect revision
  `openagents-nostr-relay-00011-57g` remains deployed and Ready as the recorded
  immediate rollback target; rollback may require replaying post-cutover
  Immortal-only events as the runbook states. Temporary canary tags were
  cleared after verification so their revision-level minimums cannot keep
  extra paid instances warm; both revisions remain retained.
- Canonical production verification passed `/health`, NIP-11 with Immortal's
  software URL and preserved relay pubkey, WebSocket COUNT, NIP-42
  pre-authentication, and a fresh signed publish/read. The post-cutover event is
  `6da2b4313e15feeb75882515c0caff2761f39b3ade7f9653139809da533c301a`.
  A second 30-second OpenAgents load proof through
  `wss://relay.openagents.com` passed with 969/969 publishes and 677/677
  subscriptions: 32.2 and 22.5 operations/sec, 88.3/236.7 ms publish
  median/p99, 66.2/222.0 ms subscribe median/p99, and zero errors. No error log
  entry was present for the final revision during deployment or either proof.
- Database reconciliation after more than two tail intervals found 6,882
  nostr-effect source rows and exactly 6,882 import-ledger rows: 6,792 stored,
  90 expired, zero rejected, and zero unresolved. Immortal held 8,761 rows
  after preserved history, live traffic, and acceptance/load events. The 919
  source rows beyond the initial 5,963-row drain were admitted by bounded tail
  sweeps while nostr-effect was still serving. The pre-cutover backup operation
  `49b5afb5-6dae-47d4-a273-d73200000032` remains `DONE`; automated backups and
  seven-day point-in-time recovery were also confirmed enabled.

### 2026-08-04 — Claude Fable 5: NIP lane READMEs and openagents lane refresh

- Owner-directed documentation pass, no runtime change. Added the
  repo-owned `nips/block/README.md` summarizing all 15 pinned Buzz
  specifications, taught `scripts/sync-nips.sh` to preserve a repo-owned
  lane README when the upstream does not publish one (an upstream README
  always wins), and recorded the convention in `nips/README.md`.
- Refreshed the `openagents` lane to upstream commit `514b47bda` — the
  owner lifted the recorded postponement note there and replaced the
  lane README with per-specification summaries — and updated
  `nips/manifest.json` plus the `docs/protocol/source-lanes.md` decision
  row. Runtime adoption of the OpenAgents specifications still requires
  its own named decision, fixtures, and conformance gate.

### 2026-08-04 — Codex 5.6 Sol (Extra High), hardening NIP sync

- Accepted the owner-directed documentation and source-lane handoff as Codex
  5.6 Sol (Extra High). Wrote and reviewed the five OpenAgents Bitcoin OSS
  hardening drafts, then pushed their source repository before syncing the
  exact published tree into Immortal.
- Source revision: OpenAgents commit
  `d3bb7c51219e2473965ff6f576c1492b2aa99d31`. The new pinned drafts are
  NIP-SP (`32450`-`32451`), NIP-SC (`32460`-`32462`), NIP-FD
  (`32470`-`32473`), NIP-SI (`32480`-`32482`), and NIP-BT
  (`32490`-`32492`); the remainder of each ten-kind block stays reserved by
  its draft. The OpenAgents lane now contains 38 Markdown files.
- Reviewed the `32450`-`32499` allocation against the pinned official, Block,
  and pre-existing OpenAgents lanes; no collision exists. Verified that the
  synced OpenAgents directory is byte-for-byte identical to the pushed source
  tree and that every local Markdown link in the changed source documents
  resolves.
- This is a specification sync only. Immortal does not implement, advertise,
  admit, or fixture these five draft protocols in this change, and no roadmap
  milestone is marked complete. A later adoption needs its own owner decision,
  domain and server work, fixture corpus, NIP-11 update, and conformance gate.
- The OpenAgents manual fast-policy and SOL-documentation checks passed before
  its push. Immortal validation is run locally under the repository's
  no-GitHub-automation invariant; no GitHub workflow or GitHub-billed check is
  introduced or required.

### 2026-08-04 — Codex 5.6 Sol (Extra High), Operation Diamond Hands Phase 0

- Accepted issue #1 sequentially from fresh `origin/main` worktrees as Codex
  5.6 Sol (Extra High). Immortal commit `98e1dd57529f7917e40f52e88bb8d95da4fee61b`
  is already on `main`: it added the fixture-backed OT/PG domain contract and
  transport-neutral native/wasm project client without a new dependency,
  service, binary, database, or GitHub automation.
- The consumer is being integrated in
  `openagents/apps/openagents.com/apps/diamond-hands`, not Omega. It pins Omega
  `b4fac63a2c90d77d6630d9df7eb9cb8a5983bac8` for GPUI, WebGPU, `ui`, and
  `theme`, and pins the Immortal client commit above. The browser owns the
  `WebSocket`; project content is not in the wasm bundle.
- The local release build now links the existing secp256k1 C backend for wasm
  through Zig compiler, archiver, and ranlib wrappers, installs an app-local
  browser theme provider with the exact UI-facing Aiur values, retains the
  GPUI app with `run_embedded`, and degrades invalid configuration without a
  panic. The Start public tree carries stable HTML/JS/wasm artifacts while the
  Cloud Run adapter maps `/dh` to the static entry and adds wasm MIME, COOP,
  COEP, CORP, and a relay-only connect policy.
- Manual evidence so far: native and wasm Immortal tests passed; the GPUI app
  passed wasm check, warnings-denied no-deps Clippy, and release Trunk build;
  48 focused OpenAgents route/header tests passed; the Start build and API
  typecheck passed. Headless Chromium loaded the release page, directly opened
  `wss://relay.openagents.com`, sent `dh-project-v1`, observed `EOSE`, and made
  zero `/api` requests.
- Added a bounded `sign-openagents-project-events` mode to the existing
  Immortal binary for production seeding. It accepts only 1–32 adopted OT/PG
  events under 65,536 bytes, reads the signing key only from the environment,
  validates every signed result, and performs no network or database I/O. Its
  unit tests and the repository's locked all-target test and warnings-denied
  Clippy gates pass. The follow-up client gate derives the NIP-11 HTTPS URL,
  caps and parses the discovery document, pins its relay identity, requires
  NIP-01/NIP-11, and refuses subscription limits incompatible with the exact
  project configuration before a browser opens the WebSocket.
- At approximately 01:39 America/Chicago the owner stood down from Operation
  Diamond Hands and the broader forensics effort. No `/dh` Cloud Run deploy
  occurred. No project event reached the relay: signing completed locally, but
  the publisher failed on a missing local Node module before it constructed a
  WebSocket. The local signed-event artifacts were discarded.
- Preserved the reusable infrastructure already on `main`: strict OT/PG
  validation and fixtures, the native/wasm client, NIP-11 identity pinning,
  bounded operator signing, GPUI/wasm page source and assets, route/header
  integration, and browser proof. The Google Secret Manager helper retains the
  key only in one shell variable, validates its shape, passes it only through
  the signer environment, and unsets it on exit. It never prints or writes the
  secret.
- Issues #1 and #2 are being closed as cancelled rather than completed. Any
  publication, deployment, or contributor-admission work requires a fresh
  owner decision. The repository-wide ban on GitHub workflows and
  GitHub-billed automation remains unchanged.

### 2026-08-04 — Codex 5.6 Sol (Extra High), protocol-totality and Liquidity Market directive

- Accepted the owner directive that every specification pinned across
  Immortal's official, Block, and OpenAgents lanes is active implementation
  scope. Earlier deferrals, current fail-closed handlers, client-only role
  classifications, and non-advertisement remain honest deployment facts but
  no longer express permanent scope exclusions.
- Defined role-correct completion: relay NIPs receive domain/server handlers;
  client NIPs receive transport-neutral native/browser implementations; and
  operator, provider, or executor profiles receive bounded configured behavior
  in the one binary where required. Deprecated or unrecommended NIPs such as
  NIP-90 retain full pinned compatibility and fixtures while new products use
  focused successor microstandards.
- Read OpenAgents Episode 213 and made the product hierarchy explicit: Agent
  Markets is the five-market umbrella; the **OpenAgents Liquidity Market** is
  this product lane; NIP-MKT is the planned negotiated-market fabric; and the
  first technical system is a multi-provider noncustodial Bitcoin liquidity
  network. Companion OpenAgents documentation commit: `d345ad3c34`.
- Expanded the roadmap through the noncustodial Boltz/tbDEX boundary:
  discovery, Offering/RFQ/Quote/Order/Status/Close, signed reservations,
  routing, script/invoice and public-evidence verification, timers, recovery,
  disputes, and compatibility APIs belong in scope. Funds, spend authority,
  wallet/LP secrets, node and bank credentials, and final settlement authority
  remain with independent clients, providers, and rails.
- Updated the README, NIP source contract, source-lane decision record, Block
  handler contract, Buzz adaptation, and deployment wording. This pass changes
  documentation and owner intent only: it adds no runtime behavior,
  dependency, service, database, secret, GitHub workflow, or GitHub-billed
  automation.

### 2026-08-04 — Codex 5.6 Sol (Extra High), Boltz and tbDEX inspiration records

- Converted the prior OpenAgents Boltz/tbDEX research into two Immortal-owned
  inspiration reviews, following this repository's source/Borrow/Reject/
  Follow-ups contract. The Boltz record pins the primary backend, core,
  client, web, hold, and documentation revisions; the tbDEX record pins the
  local v0.2 whitepaper at `62c466774f36671ce89649b9507f6802a3b60475`.
- Recorded the product and architecture split: OpenAgents Liquidity Market,
  NIP-MKT negotiated-market fabric, and a first multi-provider noncustodial
  Bitcoin liquidity network. Boltz contributes atomic swap and recovery laws;
  tbDEX contributes heterogeneous-provider negotiation and explicit trust,
  custody, credential, reversibility, and recourse terms.
- Preserved Immortal's boundary: absorb discovery, private negotiation,
  provider-signed reservation, coordination, evidence verification, timers,
  recovery, and compatibility APIs while funds, spend authority, secrets, and
  settlement truth remain with clients, providers, and underlying rails.
- Updated both the inspiration index and top-level README. This documentation
  pass copies no external code, adds no dependency, runtime, service,
  database, secret, GitHub workflow, or GitHub-billed automation.

### 2026-08-04 — Codex 5.6 Sol, NIP-MKT gateway policy

- Implemented issue #6's relay-observable privacy boundary: stable rejection
  of bare private MKT records, authenticated recipient-scoped gift-wrap
  filters, SQL and live-fanout recipient gates, and search-index exclusion.
- Added bounded rate accounting for the client IP, signed outer wrapper
  pubkey, and recipient. The encrypted logical sender remains opaque and is
  not inferred from the randomized wrapper key.
- Added the MKT gateway-policy fixture, migration 0009, live PostgreSQL surface
  proofs, deployment configuration, and protocol/conformance documentation.

### 2026-08-04 — Codex 5.6 Sol, NIP-MKT M10 closing packet

- Completed the relay-observable corpus and a structured, explicitly
  client-only manifest for downstream SDK conformance at the pinned
  OpenAgents commit.
- Documented the complete server/non-enforcement boundary and recorded M10
  source-lane adoption completion without claiming an executable profile.
- Gated the nonnumeric `nip-mkt` NIP-11 extension on configured NIP-42
  recipient transport and added unit plus live advertisement proofs.

### 2026-08-04 — Codex 5.6 Sol, deterministic contract export

- Added the database-free `immortal contract` command with a versioned stable
  descriptor for source identity, supported lanes, NIP-MKT kinds, grammar,
  bounds, configuration defaults, and machine reasons.
- Added a macOS/Linux export script and checked-in contract plus SHA-256
  fixture manifest. Two consecutive exports must be byte-identical, and the
  conformance gate verifies the checked-in artifacts without rewriting them.
- Documented the OpenAgents TypeScript SDK/web and Omega Rust consumers while
  preserving their transport and relay-enforcement boundaries.

### 2026-08-04 — Codex 5.6 Sol, workspace custody-boundary conversion

- Converted the single package into a virtual Cargo workspace with separate
  `immortal-core`, `immortal-client`, `immortal-relay`, and
  `immortal-provider` shell crates. The relay package still builds the
  `immortal` library and binary names and retains its CLI, configuration,
  migrations, NIP-11 behavior, and deployment target paths.
- Moved pure domain, NIP-44, market wrapping, and MKT-SWP verification into
  the wasm-safe core; moved the project reader, swap engine, and tbDEX audit
  into the wasm-safe client; and kept gateway, store, coordination, and
  contract export in the relay. The relay dependency tree has no client or
  provider edge.
- Kept the canonical root fixture corpus and both tracked contract artifacts
  byte-identical, rewrote local gates and deployment build contexts for the
  workspace, and generalized the agent rules to per-product allowlists and a
  structural custody boundary. This packet adds no protocol behavior,
  dependency version, service, database, secret, advertisement, or GitHub
  automation.

### 2026-08-05 — Codex 5.6 Sol, adversarial lab closure and MuSig2 activation

- Executed the complete 33-case #18 matrix from pushed `main` `67efec7` with
  two funded providers, two relays, separate provider databases/seed mounts,
  two peered Bitcoin nodes, three CLN nodes, and fresh owned topology per case.
- Published the bounded aggregate record under `docs/conformance/records/`.
  Its claims exclude live deployment, operator independence, Liquid/chain
  swaps, zero-confirmation settlement, and public replacement.
- Enabled the off-by-default production submarine MuSig2 process gate and
  provider contract capability flags after both provider key paths,
  abort-to-script fallback, crash-cut recovery, and doomsday execution passed.
  Reverse cooperation and relay NIP-11 remain unchanged.
- Added no dependency, event kind, relay behavior, service, custody material,
  GitHub workflow, or GitHub-billed automation.

### 2026-08-05 — Codex 5.6 Sol, admission state model

- Added an independent bounded reference model for regular, replaceable,
  ephemeral, and deletion-event admission and compared it with the production
  domain classification, replacement, and tombstone primitives over 111,111
  histories.
- Pinned counterexample traces for timestamp ties, deletion before arrival,
  author ownership, address-deletion horizons, deletion-request permanence,
  ephemeral replay, stale replacement, and restart persistence.
- Added the checker to the manual conformance suite and deterministic fixture
  manifest without adding a dependency, service, database, protocol behavior,
  advertisement, workflow, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, wire and filter fuzzing

- Added a dependency-free deterministic mutation harness that drives 20,000
  bounded raw inputs through the production WebSocket parser, covers every
  client verb and eight mutation operators, and checks panic freedom plus
  repeatable outcomes.
- Added 20,000 generated filter/event pairs checked against an independent
  matcher and 20,000 mutated filter JSON cases, with exact execution counts
  pinned in the fixture corpus.
- Added both harnesses to manual conformance and the fixture manifest without
  changing protocol behavior, dependencies, services, databases,
  advertisements, workflows, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, long-run soak harness

- Added a manual, dependency-free two-process soak against disposable
  Postgres. It checks a 4,096-event cross-process notification burst,
  sustained replacement admission, repeated WebSocket connection churn,
  relay RSS growth, database growth per admission, dead/live tuple counts,
  and the fixed Postgres connection bound.
- Pinned a one-hour qualification plan and a 30-minute minimum for evidence;
  shorter development runs require an explicit non-qualification override.
- Added no protocol behavior, dependency, service, database, advertisement,
  workflow, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, M8 security review

- Reviewed every `AGENTS.md` product, dependency, SQL, bounds, fail-closed,
  fixture, deployment, custody, secret, automation, and license rule and
  published the evidence and limitations.
- Added a local static gate for exact direct dependency closures, the relay
  custody dependency boundary, prepared-SQL call shapes, custody schema
  fields, common live-secret shapes, CC0, and the workflow prohibition.
- Corrected README language that still described the completed #19 closing
  evidence as future work. Added no protocol behavior, dependency, service,
  database, advertisement, workflow, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, M8 soak harness hardening

- Preserved subscription-reader errors at the qualification boundary and
  labeled churn, replacement, heartbeat, and notification-wait failures with
  the exact cycle and phase.
- Aligned the long-lived subscription socket timeout with the fixture's
  60-second notification evidence bound. The previous 10-second transport
  timeout could fail under concurrent local release builds before the outer
  evidence bound expired.
- Treated an already-completed WebSocket close handshake as successful client
  churn. A clean 180-second development run passed 2,880 churn connections and
  5,717 observed notifications; the one-hour qualification remains required.

### 2026-08-05 — Codex 5.6 Sol, M9 signed-event JSONL import

- Added the bounded `immortal import-jsonl` operator command for strict signed
  NIP-01 event objects in source admission order. It preserves every signed
  field and applies cryptographic, policy, replacement, and deletion checks
  through the historical admission lane.
- Added fixture and disposable-Postgres coverage for the shipped command,
  ordered replacement/deletion outcomes, expired and ephemeral events, strict
  JSON members, partial-prefix failure semantics, and durable full-file replay
  without new sequence allocation.
- Documented offline operation, report reconciliation, cutover verification,
  and the live-ephemeral notification boundary. Added no dependency, event
  kind, service, database, secret, advertisement, workflow, or billed
  automation.

### 2026-08-05 — Codex 5.6 Sol, M9 NIP-11 parity configuration

- Added a bounded supported-NIP override so an operator can reproduce an
  incumbent discovery list and ordering while retaining the configured relay
  identity and enforced policy/gateway limits.
- Refused empty, duplicate, inactive, and unsupported NIP claims. The override
  can only narrow capabilities implemented under the active configuration; it
  cannot activate a handler or advertise an unproved capability.
- Added fixture, unit, live-process, and disposable-Postgres coverage for the
  exact configured NIP-11 response. Added no dependency, event kind, service,
  database, secret, extension, workflow, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, M9 policy and read-shadow migration kit

- Added the incumbent-policy reconciliation ledger for allow/block lists,
  closed membership, enforced limits, authentication, private visibility, and
  rules without an M2 equivalent. Looser or unmapped admission behavior remains
  an explicit cutover blocker.
- Added a bounded dependency-free public WebSocket shadow client. It sends only
  `REQ` and `COUNT`, validates the upgrade and frames, compares canonical event
  sets and counts, and emits a content-free digest-bound result.
- Added a fixture workload and a two-relay live proof over seeded disposable
  Postgres. Added no dependency, event kind, service, database, secret,
  advertisement, workflow, or billed automation.

### 2026-08-05 — Codex 5.6 Sol, M13 MKT-SWP Liquid source sync

- Synced the exact OpenAgents MKT-SWP cooperative-signing reconciliation and
  Liquid addendum at `4ca362b6050c1762f5f8a383c0c18f50acf02ba0`.
- Recorded the existing-kind, no-advertisement adoption boundary before
  starting issue #27 runtime work. Added no dependency, event kind, service,
  database, secret, workflow, or billed automation.

### 2026-08-06 — Codex 5.6 Sol, M13 MKT-SWP Liquid sequencing sync

- Synced the exact OpenAgents MKT-SWP chain correction at
  `340ebc1d0401bacfbebd30495e2fb7e34f75c9ec`, requiring the signed Liquid
  destination and local mempool preflight before Bitcoin source broadcast.
- Recorded the corrected state and signer order for issue #27. Contract
  exports were deliberately deferred until the adoption gates; the source
  sync itself changed no event kind, relay behavior, dependency, custody
  boundary, advertisement, workflow, or billed automation.

### 2026-08-06 — Codex 5.6 Sol, M13 cross-domain timeout sync

- Authored and pushed the MKT-SWP correction at OpenAgents commit
  `d776a0aa08ebc5b27446f376a3f32bd89d585b88`, then synced its exact
  `MKT-SWP.md` bytes into the pinned lane.
- Separated Liquid chain heights from Lightning's Bitcoin CLTV height and
  required signed, recomputable cross-domain timing assumptions and a safety
  margin for reverse swaps. Contract exports remain deferred until the #27
  runtime and lab gates pass. Added no dependency, kind, relay behavior,
  custody material, advertisement, workflow, or billed automation.

### 2026-08-06 — Codex 5.6 Sol, M13 Status causality sync

- Authored and pushed the MKT-SWP correction at OpenAgents commit
  `f78bb0d04cce9ff3760f37a3b3b7cfb0efe813ef`, then synced its exact
  `MKT-SWP.md` bytes into the pinned lane.
- Bound effect-authorizing cross-participant Status transitions to exact
  signed prerequisite Status IDs. This removes author timestamps and record
  presence as execution authority. Contract exports remain deferred. Added
  no dependency, kind, relay behavior, custody material, advertisement,
  workflow, or billed automation.

### 2026-08-06 — Codex 5.6 Sol, M13 terminal refund causality sync

- Authored and pushed the terminal chain-refund correction at OpenAgents
  commit `7e9a7f13306cb5e515f7eca38eb8654ea3528bdc`, then synced its exact
  `MKT-SWP.md` bytes into the pinned lane.
- Required the provider terminal `refunded` Status to consume the exact
  requester `requester_source_refunded` Status after destination funding.
  This prevents terminal close until both funded principals have signed,
  verified release evidence. Contract exports remain deferred. Added no
  dependency, kind, relay behavior, custody material, advertisement,
  workflow, or billed automation.

### 2026-08-06 — Codex 5.6 Sol, M13 unfunded-destination evidence sync

- Authored and pushed the chain refund evidence clarification at OpenAgents
  commit `48db404cbb55f44ce51bf2cce4fecc056a2f8c5d`, then synced its exact
  `MKT-SWP.md` bytes into the pinned lane.
- Bound a source-only chain refund's destination leg to the exact released
  reservation and verified absence of destination funding. Source-chain
  evidence cannot be duplicated for that leg. Added fixture-backed client and
  provider enforcement. Contract exports remain deferred. Added no dependency,
  kind, relay behavior, custody material, advertisement, workflow, or billed
  automation.

## Rules

1. Every AI-authored commit carries a `Co-Authored-By` trailer that names
   the agent.
2. The AGENTS.md rules bind every agent equally. No agent adds a
   dependency, a service, or an unfixtured protocol change.
3. An agent's work is not accepted by authorship. It is accepted by the
   fixtures, the checks, and the owner's review.
4. Update the record in this file at each milestone, or when the set of
   contributing agents changes.
