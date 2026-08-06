# Immortal Roadmap

The order of work. Each milestone lands with its fixtures and leaves the
build green. Rules live in `AGENTS.md`; NIP sources live in `nips/`;
external-project reviews live in `docs/inspiration/`.

Milestone numbers are stable identifiers, not the execution order. M10
(NIP-MKT base) and M11 (contract/SDK export) are complete. The current
order of the remaining work is **M12 → M8 → M9** (owner direction,
2026-08-04), all under the immediate protocol-totality and
noncustodial-markets program below: M12 is the issue-backed Boltz/tbDEX
port program whose completion makes Immortal-based services able to
replace Boltz-class dependencies. Hardening (M8) and the drop-in kit (M9)
continue after, and any M8 finding that affects the market lane is fixed
in place.

## M0 — Foundation (done)

- [x] Repo, license (CC0), README, AGENTS.md doctrine
- [x] Compiling Cargo skeleton, edition 2024
- [x] NIP source lanes and sync script (`nips/`, three pinned upstreams)
- [x] First inspiration review (nostr-rs-relay)
- [x] Deployment docs (`docs/deployment/`)

## M1 — Domain (`crates/immortal-core/src/domain/`) (done)

The NIP-01 primitives, written from `nips/official/01.md`, with fixtures.

- [x] Event type, tag model, single-letter tag indexing rule
- [x] Canonical serialization and event ID (SHA-256)
- [x] Schnorr signature verification (secp256k1)
- [x] Filter model and matching (ids, authors, kinds, tags, since, until,
      limit) — no prefix matching
- [x] Classification: regular, replaceable, ephemeral, addressable;
      replacement address; expiration (NIP-40)
- [x] Deletion semantics (NIP-09), including deletion-before-event
- [x] Timestamp bounds (reject far-future events)
- [x] Fixture corpus: known event IDs, filter cases ported from
      nostr-rs-relay tests (MIT, attributed), replacement and deletion
      races

## M2 — Store (`crates/immortal-relay/src/store/`) (done)

Postgres owns everything. One admission transaction.

- [x] Schema migration files (versioned .sql, applied in a transaction)
- [x] Tables: `nostr_event` (with `ingest_seq`), `nostr_indexed_tag`,
      `replaceable_head`, `deletion_tombstone`, policy tables
- [x] Admission transaction: dedup, replacement compare-and-set,
      tombstones, policy, tag rows, `ingest_seq`, `NOTIFY`
- [x] Compound indexes for the NIP-01 access patterns
- [x] FTS: generated tsvector column + GIN index (for NIP-50 later)
- [x] Admission policy pipeline: allow/block lists for kinds and
      pubkeys, closed-membership mode, content-size, tag-count, and
      timestamp bounds — all configurable
- [x] Prepared statements only; least-privilege role documented

## M3 — Gateway (`crates/immortal-relay/src/gateway/`) (done)

The WebSocket protocol server.

- [x] WS handshake + NIP-11 document on HTTP GET
- [x] NIP-01 message flow: EVENT, REQ, CLOSE, OK, EOSE, CLOSED, NOTICE
- [x] NIP-42 per-connection challenge state
- [x] `SubscriptionIndex` (by id, author, kind, tag) — no linear scans
- [x] Race-free EOSE: buffer live events during the historical query,
      deduplicate, flush after EOSE
- [x] Ephemeral lane (kinds 20000–29999): in-process + `NOTIFY`, never
      stored
- [x] Limits: frame size, event bytes, subscriptions per connection,
      filters per REQ; per-IP and per-pubkey rate limits
- [x] Query cancel on client disconnect; bounded per-connection send
      queues; graceful shutdown

## M4 — Conformance (done)

- [x] Per-NIP fixture suite wired into the local conformance command; every
      M1–M3 behavior covered
- [x] Multi-process proof: two processes, one Postgres — cross-delivery,
      `ingest_seq` gap catch-up, kill-one chaos, fail-closed on gap
- [x] Load proof with published numbers (events/sec, connect p99,
      REQ-to-EOSE p99)

## M5 — Deployment kit (done)

- [x] Single-box acceptance: fresh Debian + apt Postgres + binary =
      running relay in minutes, README-only
- [x] Hardened systemd unit, nginx and Caddy snippets, backup and
      restore procedure, upgrade and rollback procedure
- [x] Runbooks final (`docs/deployment/`): Debian VPS, DigitalOcean,
      Google Cloud

## M6 — NIP expansion (done)

In order, each with fixtures before the next starts. The order puts the
items a production deployment depends on first, so M9 becomes reachable
as early as possible.

- [x] NIP-40 expiration sweep (scheduled delete + query-time exclusion)
- [x] NIP-70 protected events (with NIP-42 state)
- [x] NIP-17 private-message delivery gating: store gift wraps
      (kind 1059) but serve each only to its `p`-tagged recipient;
      honor kind 10050 relay lists
- [x] NIP-29 relay-managed groups: `h`-tag scoping, membership
      enforced before store, moderation kinds 9000–9010, join 9021 and
      leave 9022, relay-signed group metadata 39000–39005
- [x] NIP-86 relay management API (HTTP, NIP-98-authenticated) for
      policy and group administration without direct SQL
- [x] NIP-45 COUNT (bounded)
- [x] NIP-50 search (the FTS column from M2)
- [x] NIP-65 relay-list handling notes
- [x] Watch: NIP-77 (negentropy sync), NIP-91 (AND filters — implement
      when stable upstream)
- [x] `nips/block/` and `nips/openagents/` lanes: per-NIP owner decision,
      official lane wins on identifier conflict
- [x] Block agent identity and turns: NIP-OA owner attestations, NIP-AA
      agent authentication, NIP-AO ephemeral observer routing, and NIP-AM
      owner-private turn metrics
- [x] Block stored data: NIP-AE encrypted engrams, NIP-AP private/shared
      personas and team catalogs, NIP-ER lazy encrypted reminders, and NIP-MP
      project validation
- [x] Block relay commands and derived state: NIP-IA identity archival,
      NIP-DV DM visibility, and NIP-WP workspace profile icon
- [x] Block relay semantics: NIP-CW safe WebSocket degradation with relay-only
      overlay kinds, NIP-RS addressable read state and race-free full-state
      barrier, and NIP-GS's explicitly client-side Git signatures
- [x] NIP-PL public-envelope/auth/ACL handler fails closed while no executor
      key, lease descriptor, or push transport is configured or advertised;
      no second service was added

## M7 — Media

- [x] Blossom endpoint (NIP-B7, NIP-98 auth, NIP-94 metadata): filesystem
      storage default, one optional cloud-storage adapter

## Immediate program — protocol totality and noncustodial markets

**Owner directive, 2026-08-04:** implement every specification pinned under
`nips/official/`, `nips/block/`, and `nips/openagents/`. This program starts
now and runs alongside M8 and M9; those milestones are not prerequisites.
Earlier per-NIP deferrals and phrases such as “client-only,” “not currently
advertised,” or “compatibility-only” describe a deployment state or the
correct surface, not a permanent exclusion from implementation.

Product vocabulary follows OpenAgents Episode 213: this work delivers the
**OpenAgents Liquidity Market**, one of five interlocking Agent Markets. The
shared protocol layer is the NIP-MKT negotiated-market fabric; the first
technical system is a multi-provider noncustodial Bitcoin liquidity network.
It is not limited to a decentralized exchange and does not pool funds.

“Every” means every applicable role, not dishonest NIP-11 advertising. A
relay protocol gets domain and server handlers; a client protocol gets the
transport-neutral native/browser client behavior; operator, provider, and
executor profiles get bounded one-binary handlers where the specification
requires them. Each lands with a pinned decision, fixture corpus, negative
cases, live contract where applicable, documentation, and manual conformance.
Only behavior executable under the active configuration is advertised.
Deprecated or unrecommended NIPs—including NIP-90—receive complete pinned
compatibility and regression coverage, while new products use focused
successor microstandards.

- [ ] Build a generated three-lane implementation ledger: every pinned file,
      role, event kind/message, dependency, privacy law, authority, current
      coverage, missing handler, fixture, and advertisement condition
- [ ] Finish the complete official lane, including relay, HTTP, client,
      encryption, discovery, wallet, payment, media, sync, and compatibility
      surfaces supported by the pinned texts
- [ ] Finish the complete Block lane, including the optional NIP-CW HTTP
      profile and a fully executable NIP-PL lease/decryption/dispatch path in
      this binary; retain fail-closed non-advertisement until each is usable
- [ ] Finish the complete OpenAgents lane, including the five hardening
      families and NIP-BT after the first liquidity slice; the earlier BT
      postponement is sequencing, not cancellation
- [ ] Draft, review, pin, and implement focused OpenAgents market NIPs:
      negotiated-market base (done — M10) plus atomic-swap, P2P,
      credentialed-PFI, mint/federation, LSP, and later risk/guarantee
      profiles; do not extend NIP-90 for new market semantics. SWP and PFI
      drafting is openagents#9311 in the M12 ledger; P2P/MINT/LSP/RISK
      follow after the Boltz-class replacement exists
- [ ] Absorb the noncustodial Boltz/tbDEX surface: provider profiles and
      discovery, Offering/RFQ/Quote/Order/Status/Close, signed quote
      reservation, multi-provider routing, privacy and credential policy,
      script/invoice verification, chain/LN evidence, timeout/refund
      recovery, monitoring, disputes/recourse, and Boltz REST/WebSocket plus
      tbDEX message compatibility where interoperability justifies it —
      now issue-backed as the M12 ledger below (#10-#17, #19)
- [ ] Prove browser and native clients, at least two independently keyed
      providers, multiple relays, partitions, crashes, duplicate/conflicting
      messages, reorg/RBF, noncooperation, refund, and secret-leak rejection
      in a manual adversarial regtest lab — now issue-backed as M12 #18

The noncustodial boundary is strict but deliberately ambitious. Immortal may
compute, validate, index, coordinate, route, reserve signed provider capacity,
run timers, publish relay-owned derived state, and automate recovery. It may
hold only relay/operator keys and encrypted coordination state required by a
pinned protocol. Spend authority, user/LP balances, wallet seeds, private
claim/refund keys, unreleased preimages, NWC secrets or node macaroons, bank
credentials, and final settlement authority remain with clients, providers,
or the underlying rail. All of this still obeys one binary, one Postgres,
prepared SQL, bounded work, fail-closed operation, and no GitHub workflows or
GitHub-billed automation.

M10 and M11 below were the first two concrete slices of this program and
are complete: the NIP-MKT base made the negotiated-market fabric real on
this relay, and the contract/SDK lane made it consumable from Omega and
`openagents.com` without hand-written drift. M12 is the third slice: the
issue ledger that ports the Boltz/tbDEX infrastructure itself.

## M10 — Negotiated markets (NIP-MKT base)

The first slice of the immediate program and the current top priority.
Implement the pinned `nips/openagents/MKT.md` base as a
transport-plus-validation lane: public discovery heads, gated gift-wrap
negotiation transport, and the base admission rules. Focused profiles
(MKT-SWP and the rest of `39610-39699`) and the broader Boltz/tbDEX
absorption items above are separate later slices; the optional
noncustodial handler role (routing, reservation accounting, timers) lands
after the base. NIP-90 job kinds are frozen per
`nips/openagents/NIP90-MIGRATION.md` — no new NIP-90 semantics land here.

- [x] Adoption decision recorded in `docs/protocol/source-lanes.md`: lane
      `openagents`, identifier NIP-MKT, kinds `39600-39609`, with
      `39610-39699` reserved and unallocated
- [x] Repeat the registry-of-kinds and three-lane collision review of
      `39600-39699` at the pinned manifest commits (the spec requires the
      re-check before implementation)
- [x] Domain: public head validation — Provider Profile `39600`, Offering
      `39601`, Profile Descriptor `39602` (required tags, status enums,
      16 KiB content bound) and Public Market Receipt `39603` (unique `d`,
      required `profile`/`outcome`/`x`/`role` tags, 4 KiB bound)
- [x] Domain: private record kinds `39604-39609` are
      **immutable-by-contract** — identical signed bytes under an existing
      `(pubkey, kind, d)` are idempotent replay returning the prior `OK`;
      different bytes are an idempotency conflict and fail closed. This
      deliberately overrides the generic NIP-01 addressable
      newest-head replacement for these six kinds and needs its own store
      path and fixtures
- [x] Domain: common-grammar checks — exactly-one `d`/`session`/`profile`/
      `alt`, at least one role-marked `p` tag, 64-lower-hex `session` and
      `d`, the `openagents.mkt.v1` content envelope with tag/body
      agreement, duplicate-JSON-member rejection, 32 KiB private-record
      bound, and the tag caps (64 tags, 8 `p`, 32 causal refs, 16
      profiles, 8 hints)
- [x] Store: MKT admission inside the existing single transaction with a
      distinct machine-readable `OK` reason for idempotency conflicts
- [x] Gateway: reject bare publication of `39604-39609` (private records
      travel only inside NIP-59 gift wraps); confirm wrapped negotiation
      rides the existing NIP-17 `1059` recipient gating on every read
      surface — REQ, id lookup, COUNT, search exclusion, live fanout —
      with MKT fixtures proving each surface
- [x] Limits: discovery-head rate limits per IP and pubkey; wrap-rate
      limits per IP, outer wrapper pubkey, and recipient reusing the
      existing 1059 machinery
- [x] Fixture corpus per the MKT conformance section (relay-observable
      subset): malformed events, duplicate JSON keys, unsupported
      profile/version, changed bytes under one `d`, rewrapped replay,
      bare-private publication, expired events, and never classifying
      `396xx` as ephemeral or regular. Client-only cases (quote
      supersession, double reservation, sequence gap/fork, signer
      mismatch, settlement overclaim) live in the exported corpus for SDK
      consumers (M11)
- [x] Formal model where the state space is bounded: the
      replay/conflict/immutability admission machine for `39604-39609`;
      counterexamples become fixtures
- [x] NIP-11: advertise NIP-MKT only after the local conformance gate
      passes, following the `supported_extensions` practice from the
      Block lane

## M11 — Contract export and TypeScript SDK lane

Downstream demo surfaces — the Omega market panel (`~/work/omega`, Rust/
GPUI) and the `openagents.com` web app — need typed clients that agree
with this relay byte-for-byte. The repeatable process: **Immortal emits a
machine-readable contract artifact; downstream repos generate their SDKs
from it and replay our fixtures.** The relay stays one binary and one
Postgres — the contract is something the binary prints, never a service.

- [x] `immortal contract` subcommand (serde/serde_json only — zero new
      dependencies): print a versioned, deterministic (stable key order)
      JSON descriptor of the implemented surface — supported NIPs by
      lane, the kind table with classifications and publication rules,
      configured limits and bounds, the NIP-MKT grammar (required tags;
      the status/quote/reservation/state/action/outcome enums; size
      caps), and the machine-readable `OK`/`CLOSED` reason strings
- [x] Contract identity: embed the crate version and the pinned
      `nips/manifest.json` commits, so any generated SDK names the exact
      protocol revision it was generated from
- [x] `scripts/export-contract.sh`: build, run the subcommand, write
      `contract/immortal-contract.json` plus a fixture-corpus manifest
      (paths and digests). Run it after every sync or adoption commit;
      review the contract diff like a spec diff
- [x] Fixtures are part of the contract artifact: the exported manifest
      covers the M10 corpus plus the client-only MKT cases, and a
      downstream SDK is conformant only when it replays them
      byte-for-byte
- [x] Document the downstream consumers and their boundaries (recorded
      here, implemented in their own repos):
      - the `openagents` monorepo generates an Effect Schema TypeScript
        SDK from the contract JSON, layered on the workspace `nostr-effect`
        primitives, with a test suite that replays the exported fixtures;
        regeneration triggers whenever the contract version changes
      - `openagents.com` builds the web market demo (provider discovery,
        RFQ → Quote → Order → Status → Close) on that SDK against a dev
        Immortal
      - Omega builds its market panel in Rust on this crate's
        transport-neutral client core (the non-`server` feature build
        proven natively and on `wasm32-unknown-unknown` in Diamond Hands
        Phase 0), reusing `domain` validation directly and speaking to
        the relay over its own WebSocket

## M12 — Boltz/tbDEX port program (issue ledger)

The concrete, issue-backed program that ports the relevant Boltz and tbDEX
infrastructure into Immortal's noncustodial boundary. **When every issue in
this ledger is closed, an Immortal-based deployment can replace a
Boltz-class swap dependency for a consuming service** — that is the
completion criterion, executed through the migration runbook (#19).
Replacement capability is what the ledger proves; a public replacement
claim additionally needs live deployment evidence.

Sources: the pinned inspiration reviews (`docs/inspiration/boltz.md`,
`docs/inspiration/tbdex.md`, `docs/inspiration/satora.md`), the workspace
teardowns
(`openagents/docs/teardowns/2026-08-03-boltz-ecosystem-nostr-rebuild-teardown.md`,
`...2026-08-04-tbdex-liquidity-protocol-teardown.md` §7 harvest map, and
`...2026-08-04-satora-lendaswap-outage-teardown.md`), and the frozen
`~/work/projects/tbd/` and `~/work/projects/satora/` reference lanes. The
Satora review adds the doomsday drill (#12/#18), the covenant-reservation
proof class (#13), and the reserved EVM-leg vocabulary (openagents#9311)
to the existing packets without new ledger rows. The noncustodial
boundary stated in the immediate program above governs every item.

| Issue | Packet | Depends on |
| --- | --- | --- |
| [openagents#9311](https://github.com/OpenAgentsInc/openagents/issues/9311) | Draft MKT-SWP and MKT-PFI profile NIPs upstream in `docs/nips/` (39610-39699 allocations, fresh collision review), then sync into this lane | — |
| [#9](https://github.com/OpenAgentsInc/immortal/issues/9) | Dev env: local relay + seeded NIP-MKT market on one machine (macOS quickstart) | — |
| [#10](https://github.com/OpenAgentsInc/immortal/issues/10) | Bitcoin/Lightning verification primitives, allowlist-only and in-repo: tx parse, Taproot trees, MuSig2 verification, BOLT11 parse, timelock ladders | — |
| [#11](https://github.com/OpenAgentsInc/immortal/issues/11) | Adopt MKT-SWP: sync, collision review, relay validation, fixtures, contract-export section, NIP-11 gate | 9311 |
| [#12](https://github.com/OpenAgentsInc/immortal/issues/12) | Client-core swap engine: submarine/reverse/chain requester flows, verify-before-fund enforced structurally, claim/refund assembly with embedder-held keys, crash recovery | #10, #11 |
| [#13](https://github.com/OpenAgentsInc/immortal/issues/13) | Noncustodial coordination handlers: reservation accounting, session timers, equivocation/fork surfacing, relay-verifiable evidence observations | #11 |
| [#14](https://github.com/OpenAgentsInc/immortal/issues/14) | Provider-side session logic plus the `--no-spend` provider mode, relocated into `crates/immortal-provider` (re-scoped 2026-08-04; the funded daemon is #25's rails around it) | #11, #12, #24 |
| [#15](https://github.com/OpenAgentsInc/immortal/issues/15) | Boltz-compatible REST/WebSocket facade: deterministic versioned mapping onto MKT-SWP sessions, fail-closed, off by default | #11, #13, #14, #25 |
| [#16](https://github.com/OpenAgentsInc/immortal/issues/16) | tbDEX schema/vector harvest into fixtures plus the fail-closed legacy message translator | #11 |
| [#17](https://github.com/OpenAgentsInc/immortal/issues/17) | Adopt MKT-PFI: credentialed-ramp validation, risk-classification vocabulary, PII-refusal fixtures | 9311, #16 |
| [#18](https://github.com/OpenAgentsInc/immortal/issues/18) | Adversarial regtest lab: two independently keyed funded `immortal-provider` instances on external regtest nodes, multiple relays, the full failure matrix, recovery from persistence | #9, #10-#15, #24, #25 |
| [#19](https://github.com/OpenAgentsInc/immortal/issues/19) | Migration closing packet — **complete**: swap-network and provider Debian runbooks, live-reference read-only shadow, cutover, rollback, and bounded evidence | #18 |

Downstream consumers regenerate as the ledger advances:
[openagents#9309](https://github.com/OpenAgentsInc/openagents/issues/9309)
(generated TypeScript SDK),
[openagents#9310](https://github.com/OpenAgentsInc/openagents/issues/9310)
(web market demo), and
[omega#244](https://github.com/OpenAgentsInc/omega/issues/244) (Omega
market panel). They consume the contract artifact and fixture manifests;
they are not gates on this ledger.

Sequencing inside the ledger: #9 and #10 start immediately (no
dependencies); the SWP spine (#11 → #12/#13 → #24 → #14 → #25 → #15) is the critical
path; #16/#17 are the tbDEX lane and can run beside it; #18 then #19
close the program. Profiles and rails beyond the Boltz-class replacement
are the M13 ledger below.

Current M12 replacement-capability status: #9, #10, upstream #9311, #11, #12,
#13, #14, #16, #17, #18, #19, #24, #25, #26, #28, and #29 are complete. The pushed-main adversarial
lab passed all 33 cases and published its bounded record under
`docs/conformance/records/`. At source commit `764d119`, #19 passed the fresh
Debian install/backup/restore/funded gate, seven public read-only GETs against
the live Boltz API, and the cutover/rollback rehearsal. Five response-shape
divergences are retained in the shadow record. The cutover record establishes
local replacement capability while retaining false claims for live deployment,
operator independence, and public replacement. The pinned relay exposes the
MKT-SWP and MKT-PFI v1 observable contracts and the off-by-default
exact-conformance coordination handler without claiming PFI external
authority or an executable profile. Verification primitives and the
transport-neutral SWP client now live in their own wasm-safe workspace
crates. The provider crate contains the transport-neutral session engine,
persistent no-spend process, funded rails, watchtower, reserve-gated reverse
funding precommitment, live pricing integration, CLN and feature-gated LND
rails, and provider contract/runtime
fixtures. Its disposable three-journey funded gate passed locally on
2026-08-04 with CLN and on 2026-08-05 with LND on macOS 26.4 arm64, and the
Debian 13 arm64 closing gate passed on 2026-08-05. The Boltz-parity rows #30
and #31 and the M13 rails remain separately tracked; live public claims still
require their stated deployment evidence.

The #15 compatibility packet now includes both halves: the relay's
off-by-default exact-digest `307` handoff and the funded provider's independent,
off-by-default HTTP/WebSocket listener. The relay still reads no sensitive body
and a redirect is not endpoint emulation. The provider projects signed native
sessions, requires bilateral Contracts for finalization and session-bound
broadcast, exposes released secrets only from public claim transactions, and
never advertises the surface in NIP-11. The measured results are **17/53 backend
routes emulated (32.08%)** and **19/19 released-profile dependent calls
emulated (100%)**. The adapted Go/web processes pass that union in the funded
smoke with script-path mode and direct provider WebSockets. The #18 lab and
#19 migration records now retain this local capability and its deployment
boundaries.

The fixture-first adapter packet supplies dependency-free Go and browser/Node
gates for that exact pre-broadcast sequence. Its static/unit gate proves the
13-call and 15-call subsets, exact 19-call union, bilateral Contract funding
binding, persisted script-path exit, unchanged-byte broadcast, and absence of
the stock one-shot paths. The funded smoke runs both adapted clients against
the provider listener before accepting its rail evidence.

### M12 provider-runtime subledger (2026-08-04)

The monorepo expansion decision (`docs/MONOREPO.md`): this repo ships the
runnable provider daemon, not only an embeddable library, so the remaining
M12 packets prove a shipped product. The workspace conversion is the
blocking first packet; nothing below it starts until its conformance
rerun is green.

| Issue | Packet | Depends on |
| --- | --- | --- |
| [#24](https://github.com/OpenAgentsInc/immortal/issues/24) | Workspace conversion: `crates/immortal-core` / `immortal-relay` / `immortal-client` / `immortal-provider`; per-product `AGENTS.md` rules; custody boundary as a build fact; pure code motion proven by full conformance rerun | — |
| [#14](https://github.com/OpenAgentsInc/immortal/issues/14) | Session logic + `--no-spend` mode in `crates/immortal-provider` (re-scoped) | #24 |
| [#25](https://github.com/OpenAgentsInc/immortal/issues/25) | Provider rails: hand-rolled bitcoind JSON-RPC + polling watcher, CLN unix-socket client, wallet and script-path Taproot settlement over in-repo primitives, watchtower, reservation ledger, provider contract export — same seven-dependency allowlist | #24, #14 |
| [#15](https://github.com/OpenAgentsInc/immortal/issues/15) | Boltz-compatible facade, rebased onto the workspace; verification backed by the external `immortal-provider` process (re-scoped) | #11, #13, #14, #25 |
| [#32](https://github.com/OpenAgentsInc/immortal/issues/32) | Lab prerequisites: wallet-side harness executable (scriptable step control, persisted-record restart) and regtest node provisioning scripts (bitcoind, CLN + hold plugin, topology manifest, extension hooks) | #25 |
| [#18](https://github.com/OpenAgentsInc/immortal/issues/18) | Adversarial lab consuming both shipped binaries (re-scoped; first pass proves submarine and reverse shapes, chain swaps enter with #27) | #15, #25, #32 |
| [#19](https://github.com/OpenAgentsInc/immortal/issues/19) | Closing packet + `runbook-provider-debian.md` (re-scoped) — **complete** | #18 |

### M12 Boltz-parity ledger (2026-08-04)

Owner direction: full parity with the Boltz-class operation, not only
minimal replacement capability. These packets close the gaps between the
subledger above and what Boltz actually shipped: cooperative settlement
economics, quoting, rail breadth, and the operational minimum-network
claim. The Liquid rail (#27) sits in the M13 table below but is
sequenced first among extensions for commercial parity.

| Issue | Packet | Depends on |
| --- | --- | --- |
| [#28](https://github.com/OpenAgentsInc/immortal/issues/28) | Provider pricing and quoting policy engine: configurable spread, miner-fee pass-through, dynamic min/max from the reservation ledger, deterministic derivation fixtures | #14, #25 |
| [#26](https://github.com/OpenAgentsInc/immortal/issues/26) | MuSig2 cooperative key-path settlement — **complete**: BIP-327 primitives and vectors, exact signed-Status provider actor, durable effect/watch recovery, provider-A/provider-B key-path proof, abort/crash script-path fallback, and an off-by-default production submarine opt-in. Reverse preimage-release vocabulary remains deferred | #25 |
| [#29](https://github.com/OpenAgentsInc/immortal/issues/29) | LND provider rail via REST behind the `rustls` feature: pinned cert, macaroons, native hold invoices, mixed CLN/LND lab pairs | #25 |
| [#30](https://github.com/OpenAgentsInc/immortal/issues/30) | 0-conf acceptance policy: opt-in, direction-bounded, RBF/conflict downgrade, explicit non-confirmed status vocabulary | #25, #18 |
| [#31](https://github.com/OpenAgentsInc/immortal/issues/31) | Second operator-independent relay deployment: infrastructure-independent host, own identity and backups, relay-set docs; operator independence honestly deferred to recruitment | — |

The production user-facing swap surface is tracked downstream as
[openagents#9324](https://github.com/OpenAgentsInc/openagents/issues/9324)
(live-network swap UI on the SDK, gated on #18 and a funded provider).
The #15 compatibility target is the pinned Go/web source adapted to its exact
19-call profile. Stock URL-only builds cannot satisfy the pre-funding Contract
law or the direct-provider WebSocket boundary. A standalone
boltz-client-style CLI is deliberately not scheduled.

## M13 — Market extension ledger (post-replacement)

The issue-backed extensions that grow the market after M12's replacement
capability exists. They may be drafted (specs) in parallel with M12, but
adoption lands after the SWP spine. Donor evidence: the market-rails
teardown
(`openagents/docs/teardowns/2026-08-04-ark-solver-mostro-cashu-rails-teardown.md`),
`docs/inspiration/arkade.md`, and the `projects/arkade`, `projects/ark`,
`projects/mostro`, `projects/cashu`, and `projects/tether` reference
lanes.

| Issue | Packet | Depends on |
| --- | --- | --- |
| [openagents#9312](https://github.com/OpenAgentsInc/openagents/issues/9312) | Draft MKT-P2P, MKT-MINT, and MKT-LSP profile NIPs upstream; decide the intent-market shape (Arkade solver model); shared vocabulary harvest (asset-id pairs, decimal-string amounts, price-feed pinning) | — |
| [#27](https://github.com/OpenAgentsInc/immortal/issues/27) | Liquid rail: elementsd leg for BTC↔L-BTC swaps — provider RPC client, bounded confidential-transaction handling, client-engine Liquid legs, elementsd in the lab. First among extensions: core Boltz volume | M12 #25, #18 |
| [#20](https://github.com/OpenAgentsInc/immortal/issues/20) | Ark rail leg: VTXO/operator/exit verification, pre-signed exit packages as the doomsday-drill shape, covenant-reserve evidence, arkd in the lab | M12 #10, #12, #13 |
| [#21](https://github.com/OpenAgentsInc/immortal/issues/21) | Adopt MKT-P2P: Mostro/NIP-69 bridge, bonds, disputes, per-trade key rotation — **complete**: upstream 9312 drafted `MKT-P2P.md`; the 2026-08-04 sync pinned it, and the relay now enforces the relay-observable v1 subset (Offering grammar, immutable wrapped kind-39620 Resolutions via migration 0012, source-reference mapping, admitted Status states, PII refusal, per-trade-key fixtures) with the 26-case manifest exported and gated `nip-mkt-p2p:1` discovery. Bond/dispute/settlement authority stays external | 9312 |
| [#22](https://github.com/OpenAgentsInc/immortal/issues/22) | Adopt MKT-MINT: Cashu NUTs / Fedimint gateway quotes, NIP-87 cross-reference, custody disclosure — relay-observable v1 adopted (kind 39640, `nip-mkt-mint:1`, 29-case manifest; see `docs/protocol/nip-mkt-validation.md`); the optional cdk-mintd lab leg stays with #18 | 9312 |
| [#23](https://github.com/OpenAgentsInc/immortal/issues/23) | Adopt MKT-LSP: channel/JIT liquidity negotiation aligned with bLIP-50/51/52 — **complete**: upstream 9312 drafted `MKT-LSP.md`; the 2026-08-04 sync pinned it, and the relay now enforces the relay-observable v1 subset (Offering node/network/lsps/market/side/channel-type/zero-conf/lease/payment-method/custody/reservation-class grammar, immutable wrapped kind-39650 Service Contracts via migration 0013, LSPS0/1/2 source-reference mapping, admitted Status states, custody-material refusal) with the 30-case manifest exported and gated `nip-mkt-lsp:1` discovery. Channel open, JIT execution, LSP node operation, fee settlement, and reservation-proof authority stay client/external | 9312 |

Distribution surfaces (WDK swidge provider, BTCPay plugin, embed widget)
are tracked downstream as
[openagents#9313](https://github.com/OpenAgentsInc/openagents/issues/9313).
MKT-RISK remains deliberately unscheduled: it requires an actual
guarantor/underwriter and claims authority before a draft is honest.

## M8 — Hardening and formal work

- [ ] Formal model of the admission/replacement/deletion state machine;
      checker run in the local conformance suite; counterexamples become
      fixtures
- [ ] Fuzzing on the wire parser and filter matcher
- [ ] Long-run soak: memory, connection churn, Postgres bloat,
      `NOTIFY` storm behavior
- [ ] Security pass against the AGENTS.md rules; publish the results

## Operation Diamond Hands

**Stood down by owner direction on 2026-08-04.** Do not publish program records,
deploy `/dh`, or continue Phase 1 without a new owner decision. The generic
OT/PG validation, NIP-11-pinned client, bounded signer, browser transport, and
GPUI/wasm build infrastructure remain available for unrelated future use.
NIP-BT credits remain postponed for this stood-down program and the first
liquidity slice; they remain part of the full OpenAgents-lane target above.

### Phase 0 — read-only project surface

- [x] Adopt and fixture the NIP-OT Organization (`32100`) and NIP-PG Project
      (`32222`), Project Status (`32223`), and Project Update (`32226`) read
      contract from the pinned OpenAgents lane
- [x] Expose one transport-neutral client core from the existing crate, with
      the server-only Tokio/Postgres closure behind the default `server`
      feature
- [x] Build bounded direct-relay filters, local event ID/signature checks,
      EOSE snapshot/live folding, deterministic replacement selection,
      reconnect/stale states, malformed-event exclusion, and forward-
      compatible unknown project activity
- [x] Prove the library natively and on `wasm32-unknown-unknown` with a manual
      local command; no GitHub workflow or billed runner
- [ ] Cancelled: deploy the completed local WebSocket adapter and `/dh`
      GPUI/wasm artifact (issue #1 closed by stand-down)

### Phase 1 — joinable project

- [ ] Cancelled: select and implement a contributor admission path
- [ ] Cancelled: add project-specific identity, publication, read-after-write,
      rollback, and public runbook work (issue #2 closed by stand-down)

## M9 — Drop-in replacement kit

Everything an operator needs to replace an existing production relay with
Immortal behind the same hostname, with no client changes. Can start once
M6 reaches the NIP-29 item; does not wait for M7 or M8.

- [ ] Signed-event bulk import: JSONL in, idempotent, preserves ids and
      signatures, replays replacement and deletion rules in `ingest_seq`
      order
- [x] nostr-effect compatibility import: explicitly enabled, bounded prepared
      reads from its existing `public.events` table; cryptographic,
      replacement, deletion, and policy checks; historical-only bypass for
      extension/group rules the source never enforced; durable per-event
      ledger; startup drain plus bounded tail sweeps during a traffic cutover
- [ ] NIP-11 parity configuration: name, description, pubkey, limits,
      and supported-NIP list fully operator-configurable
- [ ] Policy parity checklist: map an existing relay's allow/block and
      membership rules onto the M2 policy pipeline
- [ ] Shadow mode guide: run Immortal read-only beside the existing
      relay, replay traffic, diff responses
- [x] Cutover and rollback runbook addition in `docs/deployment/`:
      hostname switch, import, verify, roll back

## Standing rules

- A specification change (NIP sync) is normative only after review plus a
  fixture update.
- A milestone is done when its fixtures and the guarded local deployment
  test pass. GitHub workflows and GitHub-billed automation are prohibited.
- New dependencies: owner sign-off first, recorded in AGENTS.md.
