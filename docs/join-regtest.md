# Join the public regtest network

One command on a fresh machine with Docker gives you a funded provider or a
relay joined to the public regtest sandbox. Regtest coins have no value; this
proves operation, not production liquidity.

## Prerequisites

- Docker with Compose, `git`, `jq`, `python3`, `curl`
- this repository cloned at the revision you intend to run
- a directory you own for private state (default `/var/lib/immortal-join`)

## Join as a provider

```sh
sudo scripts/join-regtest.sh provider \
  --relays wss://relay-a.example,wss://relay-b.example \
  --addnode bitcoin.example:18444 \
  --gateway https://gateway.example \
  --state-dir /var/lib/immortal-join
```

The script initializes owned state once (idempotent re-runs), starts
bitcoind/CLN/Postgres/`immortal-provider` from this repository's images,
peers and syncs the chain against `--addnode`, requests regtest funding from
the gateway faucet for two fresh wallet addresses, then starts the provider,
which publishes its signed kind `39600` profile and `39601` offering to the
first relay. It finishes by printing a bounded JSON health summary and a
prefilled GitHub issue URL to request a listing. Open that URL to move from
the discovered tier to a pinned listing; pinning stays a signed human
decision.

The faucet refuses non-regtest addresses and enforces per-IP, per-address,
and queue budgets (2 requests per IP per 10 minutes; 2,000,000 sat per
address per day; amounts 10,000–1,000,000 sat).

## Join as a relay

```sh
sudo scripts/join-regtest.sh relay --port 18080 --url wss://relay.example
```

This starts `immortal` with its own Postgres, publishes only loopback port
18080, generates a fresh relay signing identity, activates the exact compiled
MKT-SWP coordination digest, and runs the NIP-11 self-check it prints:

```sh
curl --fail --silent -H 'Accept: application/nostr+json' http://127.0.0.1:18080/
```

Front the loopback port with your own TLS proxy (see
`deploy/public-regtest/Caddyfile.example`) before announcing the wss URL.
The public NIP-11 document must contain a 64-character relay `pubkey` and the
`nip-mkt`, `mkt-swp:1`, and `mkt-swp-coordination:1` extensions.

### Relay operations

The joined relay owns one Postgres database. Check both processes and its
market identity, create a private custom-format backup, and prove that backup
in a disposable database with:

```sh
scripts/operate-joined-relay.sh status --state-dir /var/lib/immortal-join
scripts/operate-joined-relay.sh backup --state-dir /var/lib/immortal-join
scripts/operate-joined-relay.sh restore-test --state-dir /var/lib/immortal-join
```

Run `status` from ordinary host monitoring at least every five minutes and
`backup` daily. The backup command validates each dump before publication,
keeps mode-0600 files under `STATE/backups`, and retains the newest 14. Run a
restore test after deployment and at least monthly. A successful restore test
reports migration and event counts but never database credentials or relay
secrets.

The current public-regtest relay inventory is:

- `wss://relay-a.34-41-78-122.nip.io` — OpenAgents-operated GCP VM
- `wss://relay-b.34-41-78-122.sslip.io` — OpenAgents-operated GCP VM
- `wss://macbook-pro-m5.tailaeab8f.ts.net:8443` — OpenAgents-operated
  development host, published through Tailscale Funnel

The third relay is independent of the GCP VM, Postgres, and reverse proxy, so
it provides an infrastructure failure boundary for the public demo. It is not
operator-independent: all three are currently run by OpenAgents. NIP-65
clients should publish and consume explicit relay lists, retain at least two
reachable write/read relays, and treat an operator-independent relay as still
required before making a decentralization claim.

## Custody

All keys are generated fresh into your state directory and never leave your
machine: the provider identity secret, wallet seed, Postgres passwords, and
bitcoind RPC credentials live only in mode-0600 files under `--state-dir`.
Nothing in the join path uploads a credential, seed, or preimage, and the
faucet never learns anything beyond a destination address.
