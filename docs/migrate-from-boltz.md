# Migrating a wallet off Boltz

This document is for teams whose product depended on Boltz for
Bitcoin/Lightning/Liquid swaps and who are evaluating what to run instead.
It states what Immortal is, the three ways a wallet can adopt it, what is
proven today with machine-checkable records, and what is honestly not
proven yet. It makes no liquidity, availability, or replacement claim
beyond the cited records.

## The one-paragraph version

Boltz was a single coordinator; when it shut down in August 2026, every
wallet that treated it as default plumbing lost swap functionality at
once. Immortal unbundles that role into three separately deployed pieces
so no single operator can take the network down: a **relay** that
coordinates but never holds funds, a **provider daemon** any operator can
run with their own nodes and their own money, and a **client engine**
wallets embed that verifies every script, amount, hash, and timelock
before funds move. All of it is from-scratch Rust, CC0 public domain, one
binary and one Postgres per product, with a pinned dependency allowlist.
Kill the relay mid-swap and funds still come home through script-path
refunds.

## Who holds what

| Piece | Holds | Run by |
| --- | --- | --- |
| Relay (`immortal`) | No funds, no spend keys, no unreleased preimages. Signed market events only. | Anyone; OpenAgents runs one today, and the design requires no single operator |
| Provider (`immortal-provider`) | Its operator's own liquidity, on its operator's own bitcoind + CLN/LND (+ optional Liquid) | Independent operators — including you |
| Client engine (`immortal-client`, `immortal-client-web`) | The user's keys, preimages, funding inputs, and unilateral exit packages | Embedded in your wallet |

The wire protocol (the NIP-MKT / MKT-SWP family, in `nips/` and
`docs/protocol/`) is the interoperability boundary — not our binaries. Any
conformant implementation interoperates.

## Three adoption paths

### Path A — keep your existing Boltz integration (fastest evaluation)

The relay ships an off-by-default, digest-gated **Boltz-compatible
handoff** and the provider ships the corresponding HTTP/WebSocket API,
projected from signed native MKT-SWP sessions. Coverage is pinned against
the routes the released Boltz clients actually call: **19/19
dependent-call coverage** of the pinned `boltz-client` (Go) and
`boltz-web-app` profiles, including submarine and reverse creation,
status streams, finalize, and broadcast. See
[`docs/protocol/boltz-facade.md`](protocol/boltz-facade.md) for the full
endpoint matrix and the activation contract.

Honest constraints of the v1 profile:

- Bitcoin + Lightning only; chain swaps (BTC↔L-BTC) are not yet in the
  compatibility profile (the provider's Liquid rail exists; the facade
  profile is issue [#53](https://github.com/OpenAgentsInc/immortal/issues/53)).
- Script-path claim/refund only; cooperative partial-signature routes are
  refused by design in this profile.
- An unmodified, URL-only stock client is **not** sufficient for
  submarine swaps: the client must not broadcast funding before the
  bilateral contract exchange. The dependency-free, CC0 adapter seams
  under [`adapters/`](../adapters/) (`boltz-client-go/adapter.go`,
  `boltz-web-app/adapter.mjs`) implement exactly that gate at the pinned
  upstream call sites.

This path exists so evaluation is cheap and cutover is survivable. It is
not the end state; the native engine is.

### Path B — embed the native client engine (the durable path)

`immortal-client` is the verify-before-fund swap engine:
submarine, reverse, and chain flows over signed RFQ → Quote → Order →
bilateral Contract sessions, with multi-provider discovery, explicit
lifecycle states, signed receipts, and a persisted unilateral exit for
every session before funds move. `immortal-client-web` exposes the same
production engine to browsers/JS through a bounded, pointer-free WASM
ABI with a dependency-free TypeScript adapter. Your wallet keeps signing,
transport, persistence, and policy; the engine owns verification and
session correctness.

This is what "in-house your swap stack" means on the client side: your
users stop trusting any coordinator's code quality with their funds,
because your wallet verifies everything locally.

### Path C — run your own provider (in-house the liquidity too)

`immortal-provider` is the runnable liquidity daemon: your bitcoind, your
CLN (or feature-gated LND REST), optionally your elementsd for BTC↔L-BTC,
your keys, your inventory, your pricing policy (external price-feed input
supported). No-spend mode rehearses complete sessions with zero rail
effects before funded mode ever holds money. Script-path recovery,
watchtower, drain/exit procedure, and systemd hardening are documented in
[`docs/deployment/runbook-provider-debian.md`](deployment/runbook-provider-debian.md).

A wallet that ran its own Boltz instance still shared Boltz's code and
its holes — copies of the same code are the same vulnerability
multiplied, which is why self-hosting Boltz did not save anyone in
August. Running your own provider on an independent implementation, with
clients that verify regardless, is a different posture: implementation
diversity plus a skeptical client.

You can also run your own relay (or several). Nothing in the protocol
privileges ours.

## What is proven today (machine-checkable)

Conformance records live in
[`docs/conformance/records/`](conformance/records/). As of 2026-08-10:

- **Funded regtest swaps end to end** — submarine and reverse, prepared-
  bytes finalize handoff, idempotent broadcast, same-txid witness-mutation
  refusal — on macOS and clean Debian boxes, through both adapter seams.
- **Read-only shadow comparison against the live Boltz API** with a
  published field-level divergence report
  (`2026-08-05-boltz-readonly-shadow-764d119.json`).
- **Cutover rehearsal** for a Boltz-class dependent service
  (`2026-08-05-swap-network-cutover-764d119.json`) per
  [`runbook-swap-network.md`](deployment/runbook-swap-network.md):
  freeze/identify a release, shadow, switch endpoints for new sessions,
  verification checklist, rollback. In-flight sessions never move between
  providers.
- **Adversarial regtest lab**: two providers, multiple relays, failure
  matrix (records on 2026-08-05/06).
- **A public regtest network you can join right now** with one command —
  relays, funded providers, faucet, public P2P endpoint
  ([`join-regtest.md`](join-regtest.md); records 2026-08-08), plus an
  operator-independent second relay record.
- **Hardening**: formal model of the admission state machine with a
  checker, wire-parser and filter fuzzing, a two-relay soak record, and a
  published security pass (`security-review-2026-08-05.md`); MuSig2
  key-path settlement, 0-conf acceptance policy, and the NIP-MKT
  hardening rev (protocol acks, idempotent intents, re-drive, replay
  protection, response keys, signed receipts, multi-relay + key
  rotation) are all landed.

## What is honestly not proven

- **No live mainnet swap deployment exists.** Everything funded so far is
  regtest. The mainnet path — OpenAgents-run relay, third-party-run
  funded providers, and the gates for both — is issue
  [#54](https://github.com/OpenAgentsInc/immortal/issues/54).
- **No liquidity claim.** Liquidity depth, spend authority, and
  settlement finality live with providers and rails, not with this
  software. OpenAgents does not operate a funded mainnet provider; the
  model is that operators like you do.
- **Chain swaps are not yet in the Boltz-compat profile** (#53); they
  exist natively (provider Liquid rail + client chain flows).
- **A hosted Boltz-compat evaluation endpoint is not yet public** (#52);
  today, evaluating Path A means running the stack locally or joining
  the public regtest network.
- EVM and Ark compatibility routes are deferred; the Ark rail has a
  local funded proof only.

## The 30-minute evaluation

1. Read the protocol: [`docs/protocol/mkt-swp-coordination.md`](protocol/mkt-swp-coordination.md),
   [`mkt-swp-client.md`](protocol/mkt-swp-client.md),
   [`mkt-swp-verification.md`](protocol/mkt-swp-verification.md), and the
   facade matrix in [`boltz-facade.md`](protocol/boltz-facade.md).
2. Join the public regtest network as a provider with one command
   ([`join-regtest.md`](join-regtest.md)) — Docker, ~15 minutes, faucet-
   funded, ends with your signed offering live on the public relays.
3. Or run the whole network locally: the one-command two-provider lab
   (`immortal-lab`), then the adapter smoke
   (`scripts/test-boltz-client-adapters.sh`) to watch the 19-call gate
   pass against a funded provider.
4. Diff our claims against the records in
   [`docs/conformance/records/`](conformance/records/). Every claim above
   is either in a record or marked unproven.

## Contact

OpenAgents · chris@openagents.com · relay at `wss://relay.openagents.com`.
The code is CC0 — you owe nothing to evaluate it, fork it, or run it in
production without ever talking to us. Talk to us anyway: coordinated
cutover support, the hosted evaluation endpoint (#52), and the mainnet
gates (#54) are being prioritized by real wallet demand.
