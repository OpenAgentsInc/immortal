# Immortal as a Hardened-Software Monorepo

Decision record and migration analysis. Owner direction, 2026-08-04:
Immortal expands beyond the single relay binary to offer the daemons the
swap network needs — starting with a runnable liquidity-provider daemon —
so that becoming a network participant means *run this binary and it
works*, not *integrate this library*. Every new product is built under
the same just-the-basics Rust principles as the relay.

This document analyzes what that means, what changes, and in what order.
The workspace and successor rules landed in the first migration packet;
later product behavior still lands only with its implementation packet.

## 1. Why the expansion is necessary

`docs/deployment/swap-network-infrastructure.md` inventories the three
roles of the decentralized swap network. Two of the three already have
runnable or embeddable artifacts in this repo: the relay (deployed) and
the client engine (issue #12, consumed by the openagents SDK). The third
role — the liquidity provider, the party that actually holds and moves
money — has only an embeddable session library planned (#14), with the
funded daemon explicitly pushed out of the repo.

That boundary produced a design that cannot bootstrap. Every network
that acquired independent operators shipped the operator software as a
runnable artifact: bitcoind, LND, `arkd`, Mostro's daemon, and Boltz
itself, whose ecosystem existed because `boltz-backend` is a complete
deployable stack. tbDEX shipped a protocol and SDKs without a runnable
provider and died on the resulting chicken-and-egg. A library-only
provider story asks strangers to build our missing component with their
own capital at risk. Whether OpenAgents operates the first funded
instance or recruits independents, the same software must exist; the
run-versus-recruit question decides who operates instance #1, not
whether the daemon gets built.

So the repo's identity changes from "a hardened Nostr relay" to "hardened
infrastructure for the open swap network": multiple small, severe,
independently deployable binaries sharing one discipline and one set of
audited primitives.

## 2. What the monorepo offers

| Product | Form | Role | Holds |
| --- | --- | --- | --- |
| `immortal` (relay) | binary, unchanged name | Coordination fabric: Nostr relay, MKT lanes, optional no-spend coordination handler | Relay key, signed/wrapped coordination records. Never funds or spend keys |
| `immortal-provider` | binary, new | The liquidity-provider daemon: publishes Offerings, answers RFQs, signs Quotes, reserves capacity, executes swaps against its own rail nodes, runs the refund watchtower | Seed, hot wallet, claim/refund keys, unreleased preimages, node credentials — the money |
| client engine | library crate (+ wasm), existing code | Verify-before-fund swap engine embedded by wallets; source of the generated TypeScript SDK | Nothing; the embedding wallet holds the user's keys |
| shared core | library crate, existing code | Event/tag/filter/canonical-ID domain, NIP-44, MKT grammar, Bitcoin/Lightning verification primitives (taproot tagged hashes, output-key and control-block verification, invoice parsing) | Nothing; pure logic, fixture-tested |
| regtest lab | dev harness (#18) | Adversarial multi-provider, multi-relay lab driving both binaries against external regtest nodes | Regtest coins only |

Future hardened products (beyond swaps) follow the same pattern: one
crate, one binary, its own dependency allowlist, its own runbook, its
own conformance corpus, shared audited primitives.

## 3. The principles, restated per product

The relay's rules generalize. `AGENTS.md` applies these principles to each
workspace product:

1. **One binary and one Postgres database per product.** No product
   adds a broker, cache, sync engine, or second database. The provider
   daemon additionally speaks to the external rail nodes it exists to
   drive — its bitcoind and its Lightning node. Those are the operator's
   market-facing rails, declared in the runbook, not hidden support
   services; nothing else runs. The relay's own dependency list is
   unchanged: it never grows a rail connection.
2. **Per-crate dependency allowlists, owner-approved.** The relay keeps
   exactly its current seven. The provider daemon launches with the
   *same seven* (analysis in §4) — no new dependencies are required for
   the default CLN rail. The conditionally approved `rustls` chain extends to
   the provider's LND REST path behind the off-by-default `lnd` feature; the
   default and CLN dependency trees remain unchanged.
3. **Write the primitives in this repository.** Already extended in
   practice by #10: the Nostr primitives rule now also covers Bitcoin
   and Lightning primitives (tagged hashes, taproot key/tree logic,
   script and control-block verification, bolt11 parsing live in
   `crates/immortal-core/src/mkt_swp_verify.rs`). The provider adds the authoring
   side — transaction construction, sighash, schnorr signing, PSBT-free
   in-repo serialization — fixture-tested against upstream BIP-341/342
   and bolt11 vectors. No `rust-bitcoin`, no third-party Nostr crate.
4. **Prepared SQL only; fail closed; set limits.** Unchanged, applied
   to the provider's own database and connections identically.
5. **Deployment test per product.** Rule 9 generalizes: a new Debian
   server plus the product's declared prerequisites must yield a
   running instance in minutes with only the README and runbook. For
   the relay: apt Postgres. For the provider: apt Postgres, bitcoind,
   and the selected CLN or feature-gated LND node — real prerequisites,
   honestly declared.
6. **No secrets in the repo; no GitHub-billed automation.** Unchanged.
7. **Custody boundary as a rule, not a convention.** New rule: the
   relay crate must never link wallet, signing, or spend-capable code;
   the provider's seed and keys live in operator-owned files/env
   (mode 0600), never in its database; the shared core crate contains
   verification and construction logic but no key storage. Crate
   boundaries make this checkable: `cargo tree` on the relay binary
   must show no wallet module, which is precisely why this is a
   workspace and not one crate with more feature flags (§5).

## 4. Can a real provider daemon honor the seven-dependency allowlist?

Yes, deliberately, with two explicit trade-offs. This is the load-bearing
analysis; if it were false the expansion would import a stack and the
"same principles" claim would be marketing.

**bitcoind (required rail).** Spoken over JSON-RPC on localhost. HTTP/1.1
with basic auth over a `tokio` TcpStream is a hand-rolled client of a
few hundred lines — the same posture as the relay writing its own Nostr
primitives. `serde_json` covers the wire. No TLS needed on localhost.
*Trade-off 1:* no ZMQ. Boltz watches chains via bitcoind ZMQ push
notifications; a ZMQ dependency (or an in-repo ZMTP implementation) is
not justified for v1. The daemon polls `getbestblockhash` /
`getrawmempool` / `gettxout` with bounded backoff. Swap timescales are
confirmations and timelock ladders — minutes and blocks, not
milliseconds — so seconds-granularity polling is honest. The poller is
a watchtower input, so its failure mode must be loud (alerting, §6),
never silent.

**Lightning (required rail): CLN or feature-gated LND.** Core Lightning's native
interface is JSON-RPC over a Unix socket — `tokio::net::UnixStream`
plus `serde_json`, zero new dependencies. Hold-invoice semantics on CLN
come from a plugin (Boltz maintains `hold` precisely because vanilla
CLN lacks it); the runbook declares the plugin as a rail prerequisite,
exactly as it declares bitcoind. The optional LND adapter uses bounded REST
over TLS with an operator-pinned certificate and separate readonly, invoices,
and router macaroons. It adds only the approved `tokio-rustls`/rustls/ring/
zeroize chain behind the `lnd` feature. LND native hold invoices need no
plugin; gRPC/`tonic` remains rejected.

**Postgres.** `tokio-postgres`, prepared statements, transactional
state transitions, idempotency bindings between Order IDs and every
external effect. Same crate, same discipline, separate database from
any co-located relay.

**Signing.** `secp256k1` 0.31 provides schnorr signing and the key
tweaking used by the existing taproot primitives; `sha2` provides the
tagged hashes already implemented. Entropy comes from the OS directly
(`/dev/urandom`) rather than a `rand` crate. *Trade-off 2:* the pinned
`secp256k1` exposes no MuSig2 module. The original v1 decision therefore
shipped script-path Taproot settlement first. Issue #26 supersedes the
implementation deferral without changing the dependency decision: BIP-327
nonce, scalar, partial-signature, and aggregation logic is implemented
in-repo over the allowlisted point/tweak operations and official vectors.
The client transcript and provider signed actor support the cooperative key
path, while the unilateral claim and refund paths remain mandatory. FundedMode
owns the submarine actor/effect lifecycle: it persists the exact
public provider exit package plus the signing and chain-claim requests before
nonce allocation, accepts only signed Status Events already in session
storage, and releases a final transaction through its durable
watch-before-broadcast path. Restart
aborts an unfinished transcript without recreating a nonce and can reconstruct
public final transaction bytes from a signed final Status. After the #18
two-provider process lab passed all 33 cases, the provider contract exposes
submarine signer/runtime capability behind the explicit off-by-default
`IMMORTAL_PROVIDER_COOPERATIVE_SIGNING=true` gate. Reverse cooperation still
needs a signed preimage-release binding before a key-path claim can settle its
held Lightning invoice.

**Price feeds.** MKT-SWP §3.4 pinning requires fetching an exact HTTPS
URL. Outbound HTTPS needs TLS: either the `rustls` chain (already
conditionally approved) behind the same feature flag as LND, or v1
providers quote without a feed term (legal per the spec — a
Bitcoin/Lightning-only provider does not need an exchange rate).

Conclusion: the default CLN `immortal-provider` profile uses the same seven
crates, one new binary, hand-written HTTP and Unix-socket clients, mandatory
script-path exits plus the in-repo cooperative-signing foundation, and CLN +
bitcoind rails. The optional LND profile adds only the approved rustls chain
for its in-repo HTTPS REST client. Every dependency the Boltz stack
carries and we refuse (ZMQ, gRPC, ORM, Redis, a web framework) is
refused by a named decision above, not by omission.

## 5. Repository mechanics: workspace, not feature flags

The former single crate with feature gates could not express the custody
boundary: a `server`-featured build linked relay, coordination, and client
code into one dependency tree, so "the relay contains no spend code" was a
code-review claim. The Cargo workspace makes it structural:

```
Cargo.toml                 workspace root (virtual manifest)
crates/
  immortal-core/           domain, nip44, MKT grammar, verification
                           primitives; no tokio; wasm-safe
  immortal-relay/          gateway, store, coordination handler;
                           [[bin]] name = "immortal" (unchanged)
  immortal-client/         swap engine; wasm target; feeds the
                           TypeScript SDK and contract fixtures
  immortal-provider/       session logic (#14) + rail executors +
                           wallet + watchtower; [[bin]] immortal-provider
```

Invariants of the conversion:

- The relay binary keeps the name `immortal`, its CLI (including
  `immortal contract`), its configuration contract, and its NIP-11
  behavior. Deployed instances upgrade without operational change.
- `immortal-core` and `immortal-client` preserve the existing
  wasm-compatibility split (today's `cfg(not(target_arch = "wasm32"))`
  gating) so the openagents contract/SDK lane (M11) is unaffected.
- Each crate carries its own allowlist header; the workspace
  `Cargo.toml` uses `workspace.dependencies` so versions pin once.
- The provider gets its own `immortal-provider contract` export with the
  first runnable provider-rails packet, so the conformance-and-SDK pattern
  (M11) applies before funded deployment.
- Test ownership splits by crate. The canonical fixture corpus remains at
  the byte-identical root `tests/fixtures/` paths used by the exported
  manifest.

## 6. What the provider daemon must contain (v1 scope)

Mapping the eight-item infrastructure list from
`swap-network-infrastructure.md` onto the binary:

1. **Session logic** — the #14 library (Offering rotation, RFQ intake,
   Quote signing with none/soft/hard reservation, Order acceptance,
   Status progression, Close reconciliation) becomes the heart of the
   provider crate rather than a separate deliverable. The no-spend
   provider actor remains as the daemon's `--no-spend` mode: the same
   binary, spend paths disabled — useful for the demo counterparty and
   for operators rehearsing before funding.
2. **Rail executors** — bitcoind RPC client, CLN Unix-socket client, optional
   LND pinned-certificate REST client, and chain poller with confirmation
   policy and reorg handling.
3. **Wallet** — key file loading, address derivation, UTXO tracking in
   Postgres (state, never keys), transaction construction and schnorr
   signing via the in-repo primitives, script-path claim and refund
   spends.
4. **Watchtower loop** — the spending half of the timeout ladder:
   refund execution at expiry, rescue paths, explicit unresolved states
   that page rather than rot. Complements the relay's no-spend
   coordination handler (#13); never depends on it.
5. **Reservation ledger** — capacity accounting the session library
   consults so a `hard` reservation is never emitted without a
   confirmed reserve (already an invariant in #14's spec).
6. **Operational surface** — a plaintext metrics/health endpoint on a
   private address (hand-rolled HTTP, no framework) and an alerting
   hook (an operator-supplied webhook URL invoked on stuck-swap and
   poller-failure conditions). A stuck swap is money on a timelock;
   rule-level requirement, not polish.
7. **Configuration** — environment variables only, fail-fast
   validation, same contract style as the relay
   (`docs/deployment/configuration.md`).
8. **Runbook** — `docs/deployment/runbook-provider-debian.md`: Debian,
   apt Postgres, bitcoind, either CLN + hold plugin or LND native hold
   invoices, the binary, systemd hardening, backup timer, funding procedure,
   and drain/exit procedure.

Explicitly out of the first funded release: Liquid (`elementsd`), Ark
(`arkd`), EVM and Cashu rails (extension issues #20-#23), cooperative reverse
settlement before a signed preimage-release binding, and autoswap/inventory
strategy beyond the reservation ledger (operator policy, not daemon authority).

## 7. What changes where

| Surface | Change |
| --- | --- |
| `AGENTS.md` | Rewrite rules per §3 (per-product phrasing, per-crate allowlists, custody-boundary rule). Lands with the workspace conversion packet |
| `Cargo.toml` / `crates/` | Workspace conversion per §5; code moves, no behavior change; full conformance rerun proves it |
| `README.md` | Repo identity: hardened infrastructure for the open swap network; one section per product with its one-line "run it" promise |
| `docs/ROADMAP.md` | A provider-runtime subledger *inside M12* (M13 is already the market-extension ledger): #24 workspace conversion, #25 provider rails, plus the #14/#15/#18/#19 re-scopes below |
| Issue #14 | Superseded in one respect: the funded daemon now lives *in this repo* as `immortal-provider`. The library/daemon split survives as crate-internal structure; the no-spend actor becomes `--no-spend` mode |
| Issue #18 | The lab consumes both binaries from this workspace against external regtest nodes; topology unchanged |
| Issue #19 | The runbook ships `runbook-provider-debian.md` as its provider half; "independent providers" now means independently *operated and keyed* instances of our daemon (or anyone else's implementation of the NIPs — the wire stays the boundary) |
| `docs/deployment/` | Add the provider runbook; README table row; configuration contract section for provider env vars |
| Workspace root docs (`~/work/CLAUDE.md`) | The umbrella description "one Rust binary plus one Postgres database, nothing else" must be updated to the per-product phrasing when the conversion lands (separate repo, separate commit) |
| Live deploy | Independent of this expansion but outstanding: relay.openagents.com runs a pre-MKT build and must be redeployed from `main` (finding recorded 2026-08-04) |

## 8. Migration order

Each step keeps the tree green and the deployed relay upgradeable:

1. **Workspace conversion.** Virtual manifest, move the existing crate
   to `crates/immortal-relay` + `crates/immortal-core` +
   `crates/immortal-client` split along the existing module and wasm
   seams. Binary name, CLI, contract digests, and fixtures unchanged;
   rerun the full conformance corpus as proof. `AGENTS.md` and
   `README.md` rewrites land here.
2. **Provider crate, no-spend first.** `immortal-provider` embedding
   the session logic (#14's scope, relocated), `--no-spend` actor
   parity with the seeded dev-market actor, and session fixtures.
3. **Rails.** bitcoind RPC client + poller; default CLN client and optional
   feature-gated LND client; wallet and script-path claim/refund construction
   over the in-repo primitives; watchtower; reservation ledger against real
   Postgres; deterministic provider contract export.
4. **Lab.** #18 executes with two funded `immortal-provider` instances
   (independent keys), multiple relays, and the failure matrix, on
   regtest.
5. **Runbook and release.** Provider runbook proven on a clean Debian
   box; #19's shadow/cutover work proceeds with both halves of the
   network now shippable from this repo.

Sequencing note: step 1 is pure motion and the only step that touches
the relay; steps 2-3 are where the new engineering lives; nothing in
steps 2-5 can regress the relay because the crates share only
`immortal-core`, whose changes remain fixture-gated.
The issue order is #24 → #14 → #25 → #15; the compatibility facade is
verified against the funded provider process rather than preceding it.

## 9. What this deliberately does not change

- The relay's dependency list, storage model, or NIP surface.
- The custody law: the relay still never holds funds, spend keys, or
  unreleased preimages; the daemon holding them is a *different binary*
  a *different party* runs, and the workspace exists to keep that
  provable.
- The wire as the boundary: `immortal-provider` is a reference
  implementation of the provider role, not a privileged one. Anyone
  implementing the pinned NIPs interoperates; the network claim still
  requires operator-independent relays and independently keyed
  providers (`swap-network-infrastructure.md`, "Minimum honest
  network").
- CC0 licensing and the no-GitHub-automation rule, which now cover
  every product in the workspace.
