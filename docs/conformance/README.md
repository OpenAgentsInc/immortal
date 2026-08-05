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
| NIP-01 canonical event IDs, escaping, signatures, tags, exact filters, time bounds, kind classes, and replacement ordering | `tests/fixtures/nip01/` + `crates/immortal-core/tests/domain_fixtures.rs` |
| NIP-01 EVENT/REQ/CLOSE and EVENT/OK/EOSE/CLOSED/NOTICE shapes | `nip01/gateway_messages.json`, gateway wire unit tests, and `crates/immortal-relay/tests/gateway_postgres.rs` |
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
| Block NIP-OA/AA/AO/AM agent ownership, closed-relay authentication, ephemeral observer routing/rates, and owner-private turn metrics | `tests/fixtures/nipoa/`, `nipaa/`, `nipao/`, `nipam/`, `crates/immortal-core/tests/agent_fixtures.rs`, and the live gateway contract |
| Block NIP-AE/AP/ER/MP/PL stored-envelope validation and authenticated author/owner/shared ACLs, including fail-closed push-executor refusal | the matching `tests/fixtures/nip*/server.json` corpora, `crates/immortal-core/tests/block_fixtures.rs`, and the live gateway contract |
| Block NIP-IA/DV/WP authenticated commands, transactional derived state, relay-signed deltas/snapshots, and cross-process NIP-11 workspace icon | the matching Block fixtures plus the live gateway contract |
| Block NIP-CW safe WebSocket degradation, NIP-RS addressable/barrier semantics, and NIP-GS no-handler classification | `nipcw/`, `niprs/`, `nipgs/`, filter/store unit tests, and the live gateway contract |
| OpenAgents NIP-OT Organization plus NIP-PG Project, Project Status, and Project Update validation; direct-relay filter bounds; EOSE/live projection; reconnect replacement; malformed-event exclusion; unknown activity preservation | `tests/fixtures/nipotpg/project-read.json`, `crates/immortal-client/tests/openagents_project_fixtures.rs`, and `scripts/test-project-client.sh` on native + `wasm32-unknown-unknown` |
| OpenAgents NIP-MKT public Provider Profile, Offering, Profile Descriptor, and Public Market Receipt required tags, enums, identifiers, content bounds, and ordinary NIP-01 addressable replacement classification | `tests/fixtures/nipmkt/public-heads.json` and `crates/immortal-core/tests/mkt_fixtures.rs` |
| OpenAgents NIP-MKT private RFQ through Close immutable-coordinate admission, exact replay, changed-ID/signature conflicts, deletion/expiry persistence, concurrent first writers, and complete `39600-39699` addressable classification | `tests/fixtures/nipmkt/immutability.json`, `crates/immortal-core/tests/mkt_immutability_model.rs`, and the live store contract |
| OpenAgents NIP-MKT common public/private bounds, duplicate-free JSON, private envelope agreement, stable error codes, exact raw signed-record bytes and crypto, explicit profile support, gateway wire-byte bounds, and observable/client boundary | `tests/fixtures/nipmkt/common-grammar.json`, `crates/immortal-core/tests/mkt_common_fixtures.rs`, gateway wire tests, the live store contract, and `docs/protocol/nip-mkt-validation.md` |
| OpenAgents NIP-MKT gateway gift-wrap policy, bounded bare-private attempts, imported-private hiding, authenticated self-scoped reads, exact-one legacy recipients, SQL history/ID/COUNT/search gates, live fanout, upgrade-safe search-index exclusion, post-signature IP/outer-wrapper/recipient rate dimensions | `tests/fixtures/nipmkt/gateway-policy.json`, gateway/rate unit tests, migration 0009, and the live store/gateway contracts |
| OpenAgents NIP-MKT closing corpus, inclusive public/wrapper expiration, rewrapped opaque delivery, complete kind classification, structured client-only SDK cases, and gated `nip-mkt` NIP-11 advertisement | `tests/fixtures/nipmkt/relay-closing.json`, `client-only-cases.json`, `crates/immortal-core/tests/mkt_closing_fixtures.rs`, NIP-11 unit/live contracts, and `docs/protocol/nip-mkt-validation.md` |
| Deterministic machine contract identity, MKT grammar/kinds/limits/reasons, exact fixture SHA-256 manifest, database-free CLI, and repeatable export | `crates/immortal-relay/src/contract.rs`, `crates/immortal-relay/tests/contract.rs`, `contract/`, and `scripts/export-contract.sh --check` |
| MKT-SWP bounded Bitcoin transaction/script parsing, txid/wtxid, BIP-341 Taproot commitments/control blocks, BIP-327 MuSig2 key aggregation and partial/final-signature verification, BOLT-11 invoice signatures/payment hashes/amounts, and preimage/CLTV/CSV ladders | `tests/fixtures/nipmkt/swp-verification.json` and `crates/immortal-core/tests/mkt_swp_verification.rs`, enabled by `mkt-swp-verify` on native and `wasm32-unknown-unknown` |
| MKT-SWP v1 relay-observable adoption: Offering asset/network/amount/fee/side grammar and pair binding, exact kind-39610 profile binding, immutable NIP-59-only Swap Contracts, typed evidence refs, public receipt outcomes/privacy, full-envelope custody tripwires, complete 70-case exported manifest, and gated `mkt-swp:1` NIP-11 extension | `tests/fixtures/nipmkt/swp-profile-v1.json`, `crates/immortal-core/tests/mkt_swp_profile.rs`, migration 0010, contract/NIP-11/live-fanout tests, and the live Postgres gateway contract |
| MKT-PFI v1 relay-observable adoption: closed digest-bound kind-39630 policies, Offering asset-pair/market/amount/fee/policy/risk/rail grammar, public PII/bearer refusal, redacted receipts, bounded private commitments/evidence/dispute/recourse, complete 41-case exported manifest, and gated `nip-mkt-pfi:1` NIP-11 extension | `tests/fixtures/nipmkt/pfi-profile-v1.json`, `crates/immortal-core/tests/mkt_pfi_profile.rs`, contract/NIP-11 tests, and the live Postgres replacement/gateway contracts |
| MKT-MINT v1 relay-observable adoption: NIP-87 cross-reference grammar with kind-38000 refusal, discovery-duplication refusal, Offering rail/market/side/operation/protocol/custody-disclosure grammar (a3-mint/a2-federation only), immutable NIP-59-only kind-39640 Route Contracts with causal/digest/signer binding, bounded evidence references with overclaim floors, bearer ecash tripwires, complete 29-case exported manifest, and gated `nip-mkt-mint:1` NIP-11 extension | `tests/fixtures/nipmkt/mint-profile-v1.json`, `crates/immortal-core/tests/mkt_mint_profile.rs`, contract/NIP-11 tests, and the live Postgres gateway contract |
| MKT-P2P v1 relay-observable adoption: Offering registry-asset/side/amount/payment-method/bridge/custody/bond/dispute-digest grammar, immutable NIP-59-only kind-39620 Resolutions with role/previous/recipient/decision/evidence grammar, closed NIP-69/Mostro source-reference mapping without signature upgrade, exact admitted Status states, public PII refusal, per-trade-key non-linkage fixtures, complete 26-case exported manifest, and gated `nip-mkt-p2p:1` NIP-11 extension | `tests/fixtures/nipmkt/p2p-profile-v1.json`, `crates/immortal-core/tests/mkt_p2p_profile.rs`, migration 0012, contract/NIP-11 tests, and the live Postgres gateway/immutability contracts |
| MKT-LSP v1 relay-observable adoption: Offering node/network/lsps/market/side/channel-type/zero-conf/lease/payment-method/custody/reservation-class grammar, immutable NIP-59-only kind-39650 Service Contracts with causal/digest/signer/firm-versus-indicative binding, closed LSPS0/1/2 source-reference mapping without signature upgrade, exact admitted Status states, recursive custody-material and public invoice/SCID/channel-plan refusal, complete 30-case exported manifest, and gated `nip-mkt-lsp:1` NIP-11 extension | `tests/fixtures/nipmkt/lsp-profile-v1.json`, `crates/immortal-core/tests/mkt_lsp_profile.rs`, migration 0013, contract/NIP-11 tests, and the live Postgres gateway/immutability contracts |
| tbDEX 1.0 exact nine-schema/ten-vector byte replay, closed nested validation, deterministic non-executable projection audits, complete optional-metadata loss accounting, explicit DID/JOSE and state refusals, Cancel and OrderInstructions boundaries, and attached/detached RFQ commitment checks | `tests/fixtures/nipmkt/tbdex-legacy.json`, `tests/fixtures/nipmkt/tbdex-upstream/`, `crates/immortal-client/tests/tbdex_legacy_fixtures.rs`, and `docs/protocol/tbdex-legacy-translation.md` |
| Optional MKT-SWP coordination: exact-digest activation and NIP-11 gate, provider-signed none/soft/hard accounting, covenant-reserve proof ordering and double-use refusal, over-allocation and commitment forks, dense Status gaps/forks, reservation-only timeout sweeps, custody rejection, bounded measured-transaction observations labeled observation-not-authority, and two-relay/one-Postgres consistency | `tests/fixtures/nipmkt/swp-coordination-v1.json`, `crates/immortal-relay/tests/mkt_swp_coordination.rs`, migration 0011, gateway/contract tests, and `crates/immortal-relay/tests/multiprocess_postgres.rs` |
| MKT-SWP transport-neutral requester execution: typed Lightning readiness/progression, exact external signing and persisted rail-evidence requests, bilateral contract and inherited Order selection, crash-complete exits, immutable signed-record ingestion, signer-local terminal Status ancestry, balanced per-asset loss claims, mutual cancellation with typed effect disposition, contradiction-safe recovery, recursive custody tripwires, and closed-world 62-case production-API replay of all six completed/refunded flows plus bounded negatives | `tests/fixtures/nipmkt/swp-client-engine-v1.json`, `tests/fixtures/nipmkt/swp-full-sessions-v1.json`, `crates/immortal-client/tests/mkt_swp_client.rs`, `docs/protocol/mkt-swp-client.md`, and `scripts/test-swp-verification.sh` on native and an invoked zero-import `wasm32-unknown-unknown` probe |
| MKT-SWP provider sessions: rotating discovery records, complete RFQ-bound indicative/soft/hard Quote terms, reserve-before-hard-signing and release effects, bilateral contract equality, retained Status gaps/forks, exact no-spend cancellation/Close accounting, bounded custody-free persistence, and closed 30-case replay across submarine/reverse/chain | `tests/fixtures/nipmkt/swp-provider-engine-v1.json`, `crates/immortal-provider/tests/mkt_swp_provider.rs`, `docs/protocol/mkt-swp-provider.md`, and `scripts/test-swp-verification.sh` on native, no-default, and an invoked zero-import `wasm32-unknown-unknown` probe |
| Funded provider runtime: reserve-gated exact reverse funding precommitment, production client verify-before-fund and `ExitPackage`, BIP-341/342 claim/refund construction bytes, exclusive chain deadlines, held-HTLC refusal/cancellation, cooperative refund-watch retirement, signer-local terminal Close, and deterministic closed-limit provider contract | `tests/fixtures/provider/provider-runtime-v1.json`, `tests/fixtures/provider/settlement-construction-v1.json`, `crates/immortal-provider/tests/provider_settlement.rs`, funded-mode unit tests, `crates/immortal-provider/tests/funded_live.rs`, `scripts/export-provider-contract.sh --check`, and the pending `scripts/test-provider-funded.sh` process gate |
| M2 migrations, hash drift, prepared admission/query paths, least privilege, policy branches, FTS, transactional NOTIFY, replacement/deletion concurrency, and ephemeral non-storage | `crates/immortal-relay/tests/store_static.rs` and `crates/immortal-relay/tests/store_postgres.rs` |
| M3 indexed fanout by ID/author/kind/tag, broad lane, race-free EOSE, deduplication, queue overflow, query cancellation, limits, rates, frame bounds, and graceful shutdown | gateway unit tests and `crates/immortal-relay/tests/gateway_postgres.rs` |
| M4 two binaries/one Postgres, cross-delivery, bounded sequence-gap recovery, kill-one survival, and fail-closed unbounded gap | `crates/immortal-relay/tests/multiprocess_postgres.rs` |
| M4 events/sec, WebSocket connect p99, and REQ-to-EOSE p99 | `crates/immortal-relay/tests/load_postgres.rs` and [`load-report.md`](load-report.md) |
| M6 and Block migrations, expiration sweep, group state, management replay, main-agent ownership, and relay-derived Block state | `crates/immortal-relay/tests/store_static.rs`, `crates/immortal-relay/tests/store_postgres.rs`, and `crates/immortal-relay/tests/gateway_postgres.rs` |
| M7 migration, pending/ready publication, media ownership, quota, and authorization replay state | `crates/immortal-relay/tests/store_static.rs` and `crates/immortal-relay/tests/gateway_postgres.rs` |

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
cargo test --locked --workspace --all-targets
```

The complete proof creates a temporary local Postgres cluster and disposable
databases, then removes them on exit:

```sh
./scripts/test-postgres.sh
```

The destructive live tests require both a dedicated database URL and
`IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1`; without that guard they skip. The load
test is additionally ignored unless the script selects it explicitly.

The Operation Diamond Hands client-only target gate is separate from the
server/deployment gate because the relay host does not need a wasm toolchain:

```sh
./scripts/test-project-client.sh
```

It uses the repository's Zig C-compiler wrapper only for the allowlisted
`secp256k1` dependency on `wasm32-unknown-unknown`. This remains a manual local
proof and does not invoke GitHub automation.

The no-spend provider's separate-process transport, restart, and all-shape
proof is:

```sh
./scripts/test-dev-market-provider.sh
```

It creates disposable local relay state and exercises no custody or rail API.

The funded provider has a fixture/contract prerequisite and a separate
process-level gate:

```sh
cargo test --locked -p immortal-provider --lib provider_runtime_fixture
./scripts/export-provider-contract.sh --check
./scripts/test-provider-funded.sh
```

The three-journey bitcoind/CLN process result is pending. Passing the first two
commands does not constitute funded-provider conformance.
