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
18080, and runs the NIP-11 self-check it prints:

```sh
curl --fail --silent -H 'Accept: application/nostr+json' http://127.0.0.1:18080/
```

Front the loopback port with your own TLS proxy (see
`deploy/public-regtest/Caddyfile.example`) before announcing the wss URL.

## Custody

All keys are generated fresh into your state directory and never leave your
machine: the provider identity secret, wallet seed, Postgres passwords, and
bitcoind RPC credentials live only in mode-0600 files under `--state-dir`.
Nothing in the join path uploads a credential, seed, or preimage, and the
faucet never learns anything beyond a destination address.
