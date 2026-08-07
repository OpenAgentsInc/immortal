# Persistent Public Regtest Sandbox

This profile keeps Immortal's qualified multi-node regtest topology online for
a public browser demo. It is a single-operator sandbox, not mainnet and not a
claim of independent providers or relays.

## Boundary

The profile runs two peered Bitcoin Core nodes, three Core Lightning nodes,
two independently keyed `immortal-provider` processes with separate Postgres
databases, and two relay processes with separate Postgres databases. Named
volumes retain chain, Lightning, and database state. Generated credentials,
provider identities, wallet seeds, and the requester seed live only in one
operator-selected directory with mode `0700`; files use mode `0600`.

Only two plain relay ports are published, both on numeric IPv4 loopback. Put a
TLS reverse proxy on the host and publish only the corresponding `wss://`
authorities. Bitcoin RPC/P2P, Lightning RPC/P2P, Postgres, provider health,
plugin, miner, and wallet control traffic stay on the private Compose network.
The capability gateway is a separate process and contract. Dynamic session
execution is qualified by #43, but it is intentionally not auto-started by
this topology until the shared-service qualification packet (#44) lands. Follow
[`public-regtest-gateway.md`](../conformance/public-regtest-gateway.md) for its
closed configuration and process gate; never substitute the local adapter.

## Prerequisites

- a clean Immortal checkout at the revision to deploy;
- Docker Engine with Compose v2, `git`, `jq`, and Python 3;
- an absolute private state path outside the checkout;
- two distinct DNS names with TLS certificates terminating on this host.

Review `deploy/public-regtest/Caddyfile.example`, replace its example names,
and ensure the host firewall exposes only TCP 443 (and the operator's SSH
policy). Do not expose ports `18080` or `18081`; Caddy reaches them on
loopback.

## Start

Run this from the repository root. The first invocation builds pinned images,
generates secrets, creates and funds the owned regtest chain, establishes all
three Lightning edges, starts both providers, and writes a bounded public-safe
readiness manifest. Later invocations reuse the same identities and volumes.

```sh
sudo env \
  IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  IMMORTAL_PUBLIC_REGTEST_RELAY_A_URL=wss://relay-a.example.org \
  IMMORTAL_PUBLIC_REGTEST_RELAY_B_URL=wss://relay-b.example.org \
  scripts/public-regtest-topology.sh up
```

Install the reviewed Caddy configuration only after `up` succeeds. Validate
the current topology and print its public-safe state with:

```sh
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh ready
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh status
```

Readiness fails closed unless both Bitcoin nodes are peered at the same tip,
both relays and providers are healthy, all three Lightning nodes are synced
with two normal channels, no provider alert exists, and provider public keys
are available. `public-ready.json` contains no credentials or raw effects.

## Restart and host recovery

Durable services use `restart: unless-stopped`. After a Docker or host restart,
run `up` again; bootstrap operations are idempotent and readiness is reproved.
To replace one service and wait for the complete topology to recover:

```sh
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh restart provider-a
```

The allowlist also accepts `provider-b`, either relay, either Bitcoin node, or
any of the three CLN roles. Compare `status` before and after: provider public
keys and Lightning node IDs must not change. Inspect Compose logs and stop if
an alert file appears; never delete evidence to force readiness.

## Backup and restore

Backups are deliberately offline. Stop containers while retaining all named
volumes, then write a new absolute backup directory:

```sh
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh down
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh backup /var/backups/immortal-regtest/2026-08-07
```

The archive contains custody material. Keep it encrypted and access-restricted.
Restoration is an operator procedure: on a stopped replacement host, restore
the private-state archive to its exact absolute path and each named-volume
archive to the Compose project and volume recorded in `ownership.json`. Run
`config`, then `up`, and require the old provider keys, Lightning IDs, chain
tip, and readiness checks before republishing DNS.

## Upgrade and rollback

1. Take an offline backup and retain the old checkout/image cache.
2. Fetch the reviewed Immortal revision in a separate checkout.
3. Run `scripts/test-public-regtest-topology.sh` and the release gates there.
4. Point `ownership.json.repository` only by performing a reviewed migration;
   the ownership check intentionally prevents a different checkout from
   controlling existing state.
5. Run `config`, then `up`, and verify stable identities and the complete
   readiness manifest before restoring public traffic.

For rollback, stop the new revision and restore the matching code plus backup
as one unit. Never run an older binary against databases already migrated by a
newer incompatible revision.

## Stop and destructive reset

`down` preserves all state. Permanent removal requires the exact confirmation
token and a matching ownership marker:

```sh
sudo env IMMORTAL_PUBLIC_REGTEST_STATE_DIR=/var/lib/immortal-public-regtest \
  scripts/public-regtest-topology.sh reset CONFIRM_PUBLIC_REGTEST_RESET
```

Reset removes only this profile's Compose project, named volumes, and private
state directory. It is irreversible unless the offline backup is usable.

## Verification and claims

Run the deterministic contract/config gate with:

```sh
scripts/test-public-regtest-topology.sh
```

For a deployment acceptance, additionally prove cold start, warm `up`, one
provider restart, one Bitcoin restart, one CLN restart, retained identities,
stable provider database state, matching tips, two channels per Lightning
node, loopback-only published ports, backup, and owned reset. The fixture at
`tests/fixtures/lab/public-regtest-topology-v1.json` is the machine-readable
claim boundary. It does not claim public browser effects, independent
operators, production value, Liquid, or mainnet safety.
