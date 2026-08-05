# Immortal

Hardened Rust infrastructure for the open swap network: one binary and one
Postgres database per product. The provider connects to operator-declared
rail nodes.

License: CC0-1.0. Public domain.

## What Immortal is

Immortal ships small, severe, independently deployable programs that
share one discipline — a minimal owner-approved dependency allowlist,
primitives written in this repository, prepared SQL only, fail-closed
behavior, and manually executed conformance — so that joining the
network means running a binary, not integrating a stack.

The products:

- **The relay** (`immortal`, shipped and deployed): a Nostr relay that
  is also the coordination fabric of the negotiated-market (NIP-MKT)
  protocol family — discovery heads, gift-wrapped negotiation
  transport, and the optional no-spend swap coordination handler. It
  never holds funds, spend keys, or unreleased preimages.
- **The provider daemon** (`immortal-provider`): the runnable
  liquidity-provider daemon for the swap network. Its no-spend mode publishes
  Offerings, receives RFQs, signs complete Quotes and bilateral contracts,
  persists recovery history, and closes mutually cancelled sessions without
  funding. Issue #25 adds settlement against the operator's bitcoind and
  Lightning node. That funded mode holds the operator's money and remains a
  different program run by a different party than the relay.
- **The client engine** (library): the verify-before-fund swap engine
  wallets embed, and the source of the generated TypeScript SDK.

The virtual Cargo workspace makes those roles explicit:
`crates/immortal-core` owns shared pure primitives,
`crates/immortal-client` owns wallet-embedded client engines,
`crates/immortal-relay` builds the existing `immortal` binary, and
`crates/immortal-provider` owns the provider session engine and no-spend
daemon; the funded rail executors land in the next provider packet.

The expansion from single relay to this monorepo is a recorded owner
decision with a full migration analysis: see
[`docs/MONOREPO.md`](docs/MONOREPO.md). The role-by-role infrastructure
of the network each product serves is
[`docs/deployment/swap-network-infrastructure.md`](docs/deployment/swap-network-infrastructure.md).

The relay runs as one program and keeps all data in one Postgres
database. It does not need other services. You can run it on one small
server, or many relay processes against one database; the design is the
same in both cases.

## Architecture

```text
Nostr clients  <=>  immortal (one binary: WebSocket + HTTP + media)
                     |                                  |
                  Postgres                     media filesystem
                    events, tag indexes, replaceable heads,
                    deletion tombstones, policy, groups, full-text search,
                    LISTEN/NOTIFY, ingest sequence
```

Postgres does all protocol-state and indexing work:

- It stores events.
- It indexes tags for queries.
- It keeps the current replaceable-event heads.
- It keeps deletion tombstones.
- It does full-text search with a generated column and a GIN index.
- It tells all relay processes about new events with `LISTEN/NOTIFY`.
- It gives each event a sequence number (`ingest_seq`).
- It owns media visibility, ownership, quota, and authorization state; the
  content-addressed bytes stay in the configured filesystem directory.

Event admission is one database transaction. The relay sends `OK` to the
client only after the commit.

A relay process uses the sequence number to fetch committed notifications and
to define stable historical/live boundaries. If its database or notification
stream cannot remain current, it closes its connections. Clients reconnect.
This is safe in the Nostr protocol.

Ephemeral events (kinds 20000–29999) do not go to storage.

TLS is the job of the reverse proxy (nginx or Caddy).

## Design rules

1. **Standard.** Rust, tokio, and Postgres only.
2. **Hardened.** Prepared SQL statements only. Limits on frame size,
   subscriptions, filters, and query cost. Rate limits per IP and per
   pubkey. Fail closed.
3. **Simple.** One binary per product, each with its own owner-approved
   dependency allowlist (seven direct dependencies for the relay; see
   `AGENTS.md`). The workspace split (`docs/MONOREPO.md`, issue #24)
   makes the custody boundary between relay and provider a build fact;
   the transport-neutral client and core remain separate wasm-safe crates.
4. **Easy to deploy.** A new Debian server, Postgres from the package
   manager, and this binary make a relay in minutes.
5. **Locally proved.** Conformance and deployment acceptance run manually;
   GitHub workflows and GitHub-billed automation are prohibited.

## Status

M1 through M7, the M10 NIP-MKT relay base, and the adopted M12 packets are
complete: the protocol domain, Postgres store,
HTTP/WebSocket gateway, pinned per-NIP fixtures, locally executable
conformance, actual-process chaos and load proofs, and the production
deployment kit. The relay also provides expiration cleanup, protected and
recipient-gated events, relay-managed groups, authenticated management,
bounded COUNT, full-text search, and bounded Blossom media. The pinned Block
extension lane is also active for agent ownership/authentication, observer
and turn traffic, private agent data, reminders, projects,
identity/DM/workspace commands, and relay state. NIP-MKT now provides public
discovery, immutable internal validation, private wrapped transport, and a
complete relay/client conformance boundary, and M11's deterministic contract
export (`immortal contract`, `scripts/export-contract.sh`) is the generation
source for downstream SDKs. M12 now includes the owned Bitcoin/Lightning
verification primitives and the relay-observable MKT-SWP, MKT-PFI, and
MKT-P2P v1 adoptions: public Offering grammar, immutable wrapped Swap
Contracts on kind `39610` and P2P Resolutions on kind `39620`, public
Qualification Policy heads on kind `39630`, bounded commitment/evidence
shapes, exported fixtures, and gated profile discovery. It
also includes the transport-neutral MKT-SWP client engine with verify-before-
fund transitions, wallet-owned signing, and keyless recovery, plus the off-by-
default `mkt-swp-coordination:1` handler for signed capacity accounting,
reservation timeouts, Status gaps/forks, and public observation-not-authority
evidence. The executable-profile set remains empty. See `docs/ROADMAP.md`,
`docs/conformance/`, and `docs/deployment/`.

The current feature list is a deployment snapshot, not Immortal's scope
ceiling. The immediate protocol-totality program targets **every specification
currently pinned in all three lanes** under `nips/`: official, Block, and
OpenAgents. That means the applicable relay/server, domain, client,
operator, and provider-facing behavior for each NIP, with fixtures and manual
conformance before it is advertised. Deprecated or unrecommended protocols
remain compatibility surfaces rather than foundations for new designs;
client-only specifications are implemented and tested in the client surface
without being falsely advertised as relay capabilities.

Immortal absorbs the noncustodial coordination surface of Boltz- and
tbDEX-shaped markets into the relay, and ships the custody-bearing
provider role as its own separate binary. The boundary is custody, not
computation: the relay binary may validate, index, route, reserve
provider-signed capacity, coordinate state machines, verify public
settlement evidence, schedule recovery, and expose compatibility
protocols. It must not hold user or liquidity-provider funds, wallet
seeds, spend/refund keys, unreleased preimages, node-control secrets,
bank credentials, or claim that relay state is settlement truth. Those
things live only in `immortal-provider`, run by the operator whose money
they are (`docs/MONOREPO.md`). Where the pinned lanes lack a safe
primitive, we will write a focused NIP and fixture it here.

In OpenAgents product language, this is the **Liquidity Market**, one of the
five interlocking Agent Markets. NIP-MKT is the reusable negotiated-market
protocol family beneath it, and the first concrete system is a multi-provider
noncustodial Bitcoin liquidity network. It is broader than an exchange and is
not a pooled-custody product.

The external architecture donors are documented in
[`docs/inspiration/`](docs/inspiration/README.md). The
[`tbDEX` review](docs/inspiration/tbdex.md) supplies the provider-neutral
Offering/RFQ/Quote/Order/Status/Close grammar and heterogeneous trust model.
The [`Boltz` review](docs/inspiration/boltz.md) supplies atomic-swap lifecycle,
client verification, claim/refund, and recovery laws. Immortal implements the
combined noncustodial coordination surface from its pinned NIPs and owned
fixtures; neither external runtime becomes a dependency or authority.

Operation Diamond Hands Phase 0 adds a bounded, transport-neutral Nostr
project reader for native and browser/WASM applications. It verifies event IDs
and signatures locally, understands the adopted NIP-OT Organization and NIP-PG
Project/Status/Update records, and makes EOSE the snapshot boundary. The
embedding application first fetches and validates the relay's bounded NIP-11
document, then owns its WebSocket, so a browser connects straight to the relay
without an Immortal HTTP proxy. See
[`docs/protocol/openagents-project.md`](docs/protocol/openagents-project.md).
That contract also documents the single binary's bounded manual command for
signing the initial authority-owned records without placing a private key in
argv or source.

The adopted NIP-MKT relay contract is documented in
[`docs/protocol/nip-mkt-validation.md`](docs/protocol/nip-mkt-validation.md).
It covers public discovery, immutable internal records, wrapped transport,
recipient-gated reads, rate limits, and the client-only boundary. NIP-11
advertises `nip-mkt` only when `IMMORTAL_RELAY_URL` enables authenticated
recipient transport. The same gate advertises `mkt-swp:1`,
`nip-mkt-pfi:1`, `nip-mkt-mint:1`, and `nip-mkt-p2p:1` for their
relay-observable v1 grammar.
The separate
[`coordination handler`](docs/protocol/mkt-swp-coordination.md) advertises
`mkt-swp-coordination:1` only with its exact compiled conformance digest; the
machine contract separately records the completed MKT-SWP client engine, and
the executable-profile set remains empty.

The transport-neutral client core also exposes a fail-closed
[`tbDEX legacy translation audit`](docs/protocol/tbdex-legacy-translation.md).
It harvests the archived tbDEX 1.0 schema/vector vocabulary while refusing
DID/JOSE authority upgrades, retaining explicit translation losses, and
verifying detached RFQ privacy commitments without persisting private data.

`immortal contract` prints the deterministic machine contract used by SDK
generators without connecting to Postgres or starting a service. The reviewed
artifacts live under [`contract/`](contract/README.md); regenerate or verify
them with `scripts/export-contract.sh` after every protocol sync or adoption
change.

For local NIP-MKT development, `scripts/dev-relay.sh` starts a loopback relay
and disposable Postgres, `scripts/dev-market-seed.sh` drives a wrapped RFQ
through Close between two throwaway actors, and
`scripts/test-dev-market-provider.sh` proves the separate no-spend provider
through restart and all three swap shapes. See the
[`local development runbook`](docs/deployment/runbook-local-dev.md).

## Quick start

On Debian 13, install the build toolchain and Postgres, then create a dedicated
database owner:

```sh
sudo apt-get update
sudo apt-get install -y postgresql curl ca-certificates cargo build-essential
sudo -u postgres createuser --pwprompt immortal
sudo -u postgres createdb --owner=immortal immortal
```

Build and start the relay. The embedded migration runner applies and verifies
the schema before the network listener binds:

```sh
cargo build --locked --release
DATABASE_URL='postgres://immortal:<YOUR_DB_PASSWORD>@127.0.0.1:5432/immortal' \
  ./target/release/immortal
```

In another terminal, verify health and NIP-11:

```sh
curl -fsS http://127.0.0.1:8080/health
curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:8080/
```

Put Caddy or nginx in front for public TLS, then set `IMMORTAL_RELAY_URL` to
the public `wss://` URL to enable NIP-42. The production path installs the
committed files under `deploy/`; follow
`docs/deployment/runbook-debian-vps.md` for systemd, TLS proxy, backups,
restore, upgrade, and rollback.

The production environment template also enables the filesystem Blossom
endpoint at `/var/lib/immortal/media`. Upload and delete use NIP-98; reads are
public and content-addressed. See [`docs/protocol/media.md`](docs/protocol/media.md).

The exact Block NIP handler and advertisement contract is documented in
[`docs/protocol/block-nips.md`](docs/protocol/block-nips.md). Draft extensions
that cannot be executed under the configured one-binary deployment fail
closed and are not advertised.

Reproduce the full fresh-Debian proof manually with a running Apple Container,
Podman, or Docker runtime:

```sh
./scripts/run-debian-acceptance.sh
```

Run the complete manual M1–M7 conformance gate with
`./scripts/test-conformance.sh`. No GitHub workflow or billed GitHub runner is
used.

Check the project client on both targets (Zig is required for the existing
`secp256k1` C backend on `wasm32-unknown-unknown`):

```sh
./scripts/test-project-client.sh
```

## Provenance

AI agents write this repository under human direction. `PROVENANCE.md`
records which agent does what, and the trailer rules for commits.

## License

CC0-1.0. Public domain. No permission is necessary.
