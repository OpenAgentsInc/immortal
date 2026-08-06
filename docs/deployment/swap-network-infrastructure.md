# Swap Network Infrastructure

What it actually takes to run the full flow of a Boltz-class swap service
in the decentralized shape this repository targets: an Immortal relay
coordinating, independent liquidity providers executing, and clients
verifying. This document inventories the infrastructure each role needs,
what each role holds, and what none of them may hold. It is the
infrastructure companion to [`runbook-swap-network.md`](runbook-swap-network.md),
which owns the step-by-step stand-up, shadow, cutover, drain, and rollback
procedure.

Background: `docs/inspiration/boltz.md` (what we borrow and reject from
Boltz), `nips/openagents/MKT.md` and `nips/openagents/MKT-SWP.md` (the
wire), `docs/protocol/mkt-swp-coordination.md` (the relay-side handler),
`docs/protocol/mkt-swp-client.md` (the client engine).

## The shape

Boltz ran the market maker, the coordination surface, and the product UI
as one operator. The replacement splits those into three roles that fail
independently:

| Role | What it is | What it holds |
| --- | --- | --- |
| Relay | Coordination fabric: discovery heads, gift-wrapped negotiation transport, reservation accounting, timers, bounded public evidence observations | Relay signing key and signed/wrapped coordination records. Never funds, wallet seeds, node credentials, private claim/refund keys, or unreleased preimages (`docs/inspiration/boltz.md`, Reject table) |
| Liquidity provider | The market maker: publishes Offerings, answers RFQs, signs Quotes, reserves capacity, executes and settles swaps on real rails | Seed, hot wallet, claim/refund keys, unreleased preimages, node credentials, inventory — the money |
| Client | Wallet, browser, or app embedding the swap engine: verifies every script, amount, hash binding, and timeout before funding; claims; refunds | The user's own keys, never leaving the device |

If the relay dies, in-flight swaps still complete or refund from the
client's persisted session records — that is the doomsday drill. If a
provider dies, its swaps still refund through the client's unilateral
exit path. If a client dies, the provider's refund ladder returns its
own funds. No role's failure strands another role's money.

## Relay: what Immortal needs alongside it

One Rust binary, one Postgres database, a reverse proxy that terminates
TLS. That is the entire dependency list, and it is deliberate
(`AGENTS.md` rule 1: if a feature needs another running service, the
feature is wrong). Add the committed backup timer and ordinary host
monitoring from the deployment runbooks. Nothing about the swap market
adds a service: the market lane is code inside the same binary and
tables inside the same database.

Two configuration gates matter for the market lane:

1. **Market wire.** With `IMMORTAL_RELAY_URL` and the relay signer
   configured, NIP-11 advertises `nip-mkt`, `mkt-swp:1`, and
   `nip-mkt-pfi:1` and the relay validates the MKT kind ranges
   (39600-39699).
2. **Coordination handler.** The optional no-spend coordination half —
   reservation accounting, Status gap and fork surfacing, expired
   reservation release, bounded public evidence observations
   ([#13](https://github.com/OpenAgentsInc/immortal/issues/13)) —
   activates only when
   `IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256` matches the
   compiled digest (`docs/protocol/mkt-swp-coordination.md`). Only then
   does NIP-11 add `mkt-swp-coordination:1`.

A deployment claim is checkable from outside: fetch NIP-11 and look for
those extensions. A running relay whose NIP-11 lacks `nip-mkt` and
`mkt-swp:1` is a working relay but not yet a market coordinator — it is
running a build or configuration that predates the lane.

```sh
curl -s -H "Accept: application/nostr+json" https://<relay-host> \
  | jq .supported_extensions
```

## Liquidity provider: where the node infrastructure lives

This is the role Boltz performed. The daemon that performs it ships
from this repository as `immortal-provider` (`../MONOREPO.md`); the rail
nodes it drives — listed below — are operator-run infrastructure,
distinct from the relay and never deployed beside it. Independent LPs
are market participants, not support services hidden behind the relay
(`docs/inspiration/boltz.md`, Reject table). From the Boltz backend configuration and its regtest
topology (`boltz-backend`, `regtest/docker-compose.yml` in the pinned
review set), a real swap provider runs roughly eight things:

1. **Bitcoin Core.** The base node: broadcast, mempool and ZMQ
   notifications, reorg awareness, confirmation policy.
2. **A chain indexer** (electrs/Esplora; Boltz's regtest topology also
   carries nbxplorer). The Boltz backend does its core watching straight
   from bitcoind over ZMQ, but address-indexed lookup is what makes
   client restore/rescan, swap-script watching at scale, and the web
   surfaces workable. Plan for it as a required component of a serious
   provider even though a minimal daemon can start without it.
3. **A Lightning node** — LND or CLN — with hold-invoice support (Boltz
   maintains its dedicated `hold` plugin for CLN precisely because CLN
   does not ship it; LND has native hold invoices). The Lightning leg
   also needs inbound/outbound liquidity managed continuously. That is
   an ongoing operational job, not a setup step.
4. **Postgres for provider state.** Swaps, the reservation ledger, and
   the idempotency bindings between Order identifiers and every external
   effect. A separate database from the relay's — the two roles must not
   share storage.
5. **A hot wallet and key management.** The actual money: seed, claim
   and refund keys, signing. This is the piece that must never touch the
   relay.
6. **A watchtower/timer loop.** Timeout ladders, refund execution,
   rescue paths. The relay's coordination handler performs the
   noncustodial half (accounting, due timers, fork surfacing); the
   provider performs the half that spends.
7. **Observability with alerting that pages a human.** Boltz runs
   Prometheus/OpenTelemetry and pages a chat channel. A stuck swap is
   money sitting on a timelock, so alerting is load-bearing, not
   optional polish.
8. **A price/rate source.** When a feed is part of quoted terms, the
   exact feed URL, RFC 6901 pointer, observed value, and response digest
   are pinned into the Quote (`nips/openagents/MKT-SWP.md` §3.4, adopted
   from the Arkade discovery law). Substituting a semantically
   equivalent feed is a term mismatch; the feed is never a settlement
   authority.

Per additional rail, add: `elementsd` for Liquid, `arkd` (plus its
wallet) for the Ark leg
([#20](https://github.com/OpenAgentsInc/immortal/issues/20)), an EVM RPC
endpoint for a stablecoin leg, a Cashu mint for MKT-MINT
([#22](https://github.com/OpenAgentsInc/immortal/issues/22)). All of
these appear in Boltz's own regtest compose file; none of them ever runs
beside the relay.

How the provider relates to the relay: it publishes its Provider Profile
(`kind:39600`) and Offerings (`kind:39601`), receives gift-wrapped RFQs,
signs Quotes, accepts Orders, and reports sequenced Status — all over
relays. Separately and privately, it drives its own nodes. The relay
never learns a spend key and cannot move a satoshi.

What this repository contributes to the role is the provider-side
session logic ([#14](https://github.com/OpenAgentsInc/immortal/issues/14))
and — per the owner decision of 2026-08-04 recorded in
[`../MONOREPO.md`](../MONOREPO.md) — a runnable reference provider
daemon, `immortal-provider`, shipped from this repo as its own hardened
binary under the same minimal-dependency principles as the relay.
Becoming a provider means running that binary against your own nodes
and funding its wallet, not integrating a library. Who operates funded
instances (OpenAgents itself, independent operators, or both) remains a
capital decision separate from the software. The adversarial regtest
lab ([#18](https://github.com/OpenAgentsInc/immortal/issues/18))
exercises funded providers on regtest with valueless coins — it proves
the code, not the business.

## Client: what the verifying side needs

Nothing beyond the wallet or app itself. The client engine
([#12](https://github.com/OpenAgentsInc/immortal/issues/12),
`docs/protocol/mkt-swp-client.md`) re-derives scripts, trees, addresses,
payment-hash bindings, amounts, fees, and timeout ladders before
exposing any fund action; relay acceptance never authorizes funding.
The client persists its own session records so that claim and refund
survive relay loss, and every quoted route binds a unilateral exit the
client can execute without the provider's cooperation. Chain
verification uses the client's own trusted source (its node, its
provider-independent indexer, or the bounded relay observations as
evidence — never as authority). The TypeScript SDK generated from the
relay contract (openagents#9309, `packages/nip-mkt` in the openagents
monorepo) and the deployed swap-demo document are consumers of this
role.

## Minimum honest network

Replacing a centralized exchange with one relay and one provider
rebuilds the single point of failure with better slogans. The launch
claim needs:

- **At least two operator-independent relays.** One Immortal deployment
  is useful infrastructure, not decentralization. Clients select relay
  sets (NIP-65); the coordination handler is per-relay and optional.
- **At least two independently operated and keyed provider daemons**, each
  running `immortal-provider` with its own nodes and funds. This is the
  acceptance criterion written into the migration issue
  ([#19](https://github.com/OpenAgentsInc/immortal/issues/19)).
- **A client surface** people can actually use: the SDK plus at least
  one wallet/web integration.

Completion of the M12 ledger is replacement *capability*; any public
replacement claim additionally needs the live deployment evidence —
the #19 runbook executed on the regtest lab plus a read-only shadow run
against a live Boltz-class endpoint, with the divergence report
published under `docs/conformance/`.
