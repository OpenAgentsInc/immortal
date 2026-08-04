# Immortal

A hardened Nostr relay. One Rust binary and one Postgres database. Nothing
else.

License: CC0-1.0. Public domain.

## What Immortal is

Immortal is a relay for the Nostr protocol. It runs as one program. It keeps
all data in one Postgres database. It does not need other services.

You can run it on one small server. You can also run many relay processes
against one database. The design is the same in both cases.

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
3. **Simple.** One crate. One server binary. The same crate exposes a
   transport-neutral client library when built without the `server` feature.
   Seven direct dependencies (see `AGENTS.md`).
4. **Easy to deploy.** A new Debian server, Postgres from the package
   manager, and this binary make a relay in minutes.
5. **Locally proved.** Conformance and deployment acceptance run manually;
   GitHub workflows and GitHub-billed automation are prohibited.

## Status

M1 through M7 are complete: the protocol domain, Postgres store,
HTTP/WebSocket gateway, pinned per-NIP fixtures, locally executable
conformance, actual-process chaos and load proofs, and the production
deployment kit. The relay also provides expiration cleanup, protected and
recipient-gated events, relay-managed groups, authenticated management,
bounded COUNT, full-text search, and bounded Blossom media. M8 hardening and
formal work is next. The pinned Block extension lane is also active for agent
ownership/authentication, observer and turn traffic, private agent data,
reminders, projects, identity/DM/workspace commands, and relay state. See
`docs/ROADMAP.md`, `docs/conformance/`, and `docs/deployment/`.

The current feature list is a deployment snapshot, not Immortal's scope
ceiling. The immediate protocol-totality program targets **every specification
currently pinned in all three lanes** under `nips/`: official, Block, and
OpenAgents. That means the applicable relay/server, domain, client,
operator, and provider-facing behavior for each NIP, with fixtures and manual
conformance before it is advertised. Deprecated or unrecommended protocols
remain compatibility surfaces rather than foundations for new designs;
client-only specifications are implemented and tested in the client surface
without being falsely advertised as relay capabilities.

Immortal is also intended to absorb the noncustodial coordination surface of
Boltz- and tbDEX-shaped markets. The boundary is custody, not computation:
the one binary may validate, index, route, reserve provider-signed capacity,
coordinate state machines, verify public settlement evidence, schedule
recovery, and expose compatibility protocols. It must not hold user or
liquidity-provider funds, wallet seeds, spend/refund keys, unreleased
preimages, node-control secrets, bank credentials, or claim that relay state
is settlement truth. Where the pinned lanes lack a safe primitive, we will
write a focused NIP and fixture it here.

In OpenAgents product language, this is the **Liquidity Market**, one of the
five interlocking Agent Markets. NIP-MKT is the reusable negotiated-market
protocol family beneath it, and the first concrete system is a multi-provider
noncustodial Bitcoin liquidity network. It is broader than an exchange and is
not a pooled-custody product.

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
