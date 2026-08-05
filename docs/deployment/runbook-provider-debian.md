# Runbook: funded provider on Debian

This is the operator contract for the custody-bearing `immortal-provider` v1
binary. It runs as a product separate from the `immortal` relay, owns a
separate Postgres database, and drives operator-owned Bitcoin Core and either
Core Lightning or LND. The wallet seed, Lightning wallet, node credentials,
private keys, and unreleased preimages never enter provider Postgres or relay
state.

The M12 closing packet (#19) records the clean-host execution evidence and
adds the network shadow/cutover procedure. The commands and boundaries here
are the configuration needed by the #25 funded smoke and by that later proof.

## 1. Prerequisites

Use Debian 13 on amd64 or arm64 with:

- Postgres 17 from apt;
- Bitcoin Core with JSON-RPC reachable only on loopback;
- a separately configured loopback Immortal relay product.

Choose one Lightning rail:

- Core Lightning with its native Unix JSON-RPC socket and Boltz `hold` plugin
  v0.3.3; or
- LND v0.20.1-beta with its TLS REST listener bound to loopback, native hold
  invoices, and separate readonly, invoices, and router macaroons.

The local conformance gate pins Bitcoin Core 31.1, Core Lightning v26.06.6,
and `hold` v0.3.3. Its independently checked hold archives and hashes are in
`scripts/support/provider-funded/Dockerfile.cln-hold`. When installing a
release manually, download it from the upstream release, verify the matching
SHA-256 before extraction, and install the binary root-owned and mode `0755`.

For CLN, the provider uses the Unix socket only. Disable the hold plugin's optional
gRPC/TLS listener and configure it as a normal `lightningd` plugin:

```ini
plugin=/usr/local/bin/hold
hold-grpc-port=-1
```

Before starting the provider, these commands must all be present in CLN's
`help` response:

```text
holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice
invoice pay listinvoices listpays listfunds getinfo
```

CLN startup performs the same ten probes and exits on the first missing
capability. Its first `getinfo` must name the configured network and contain
neither sync warning. Quote construction then waits in bounded 250 ms polls
when CLN temporarily trails bitcoind, and defers the Quote after 40 attempts;
an RFQ is not rejected merely because the local rails are converging.

For LND, bind REST TLS to loopback and leave its native hold-invoice service
enabled. The provider pins the exact operator-supplied leaf certificate,
authenticates each operation with the least-privilege macaroon, validates the
TLS handshake signature, and refuses a public resolved or connected peer. It
probes `getinfo` and the block notifier before becoming ready. No gRPC client,
LND admin macaroon, or hold plugin is used. ZMQ, HTTPS price feeds, and public
`wss://` provider transport remain excluded.

## 2. Build and install

Install the build and database packages, then build only the provider product:

```sh
sudo apt-get update
sudo apt-get install -y postgresql curl ca-certificates cargo build-essential
# CLN/default build
cargo build --locked --release -p immortal-provider --bin immortal-provider

# LND build; the optional rustls chain is present only in this product build
cargo build --locked --release -p immortal-provider --bin immortal-provider --features lnd
```

Create a service account and immutable release directory:

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin immortal-provider
sudo install -d -o root -g root -m 0755 /opt/immortal-provider/releases/<VERSION>
sudo install -o root -g root -m 0755 target/release/immortal-provider \
  /opt/immortal-provider/releases/<VERSION>/immortal-provider
sudo ln -sfn /opt/immortal-provider/releases/<VERSION> \
  /opt/immortal-provider/current
```

Verify the deterministic public contract without reading configuration or
custody material:

```sh
/opt/immortal-provider/current/immortal-provider contract >/tmp/provider-contract.json
cmp /tmp/provider-contract.json tests/fixtures/provider/provider-contract-v1.json
rm /tmp/provider-contract.json
```

## 3. Create the separate provider database

Create a role and database that are not shared with a relay:

```sh
sudo -u postgres createuser --pwprompt immortal_provider
sudo -u postgres createdb --owner=immortal_provider immortal_provider
```

The first funded start applies the embedded provider migration under an
advisory lock. Do not run files under `migrations/provider/` manually.

## 4. Create and protect the wallet seed

The seed is a 32-byte operator secret encoded as 64 lowercase hexadecimal
characters. Generate it directly into the provider-owned file without
printing it:

```sh
sudo install -d -o immortal-provider -g immortal-provider -m 0700 \
  /var/lib/immortal-provider
sudo -u immortal-provider sh -c \
  'umask 077; od -An -N32 -tx1 /dev/urandom | tr -d " \n" > /var/lib/immortal-provider/wallet.seed; printf "\n" >> /var/lib/immortal-provider/wallet.seed'
sudo chmod 0600 /var/lib/immortal-provider/wallet.seed
```

The process rejects symlinks, nonregular files, paths changed between metadata
and open, weak permissions, and malformed seed bytes. Back up the seed through
the operator's encrypted custody system. Never copy it into Postgres, the
relay, a shell command, a support bundle, or this repository.

## 5. Configure the environment

Create `/etc/immortal-provider/provider.env`, owned `root:immortal-provider`
and mode `0640`. Replace every placeholder with the operator's value:

```ini
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:<DB_PASSWORD>@127.0.0.1:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:8080
IMMORTAL_PROVIDER_IDENTITY_SECRET=<64_LOWERCASE_HEX>
IMMORTAL_PROVIDER_BITCOIN_NETWORK=mainnet
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=8332
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=<BITCOIND_RPC_USER>
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=<BITCOIND_RPC_PASSWORD>
IMMORTAL_PROVIDER_LIGHTNING_RAIL=cln
IMMORTAL_PROVIDER_CLN_RPC_PATH=/run/lightning/bitcoin/lightning-rpc
IMMORTAL_PROVIDER_WALLET_SEED_FILE=/var/lib/immortal-provider/wallet.seed
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:9091
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=5
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=30
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=1
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=6
IMMORTAL_PROVIDER_SPREAD_BPS=25
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=300
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=1000
```

The Boltz compatibility listener is optional and absent unless all three
values below are present. Read the digest from the installed bytes, paste that
exact value into the environment file, bind the daemon to a private or loopback
address, and set the one browser origin allowed to call it:

```sh
/opt/immortal-provider/current/immortal-provider contract \
  | jq -r '.operations.boltz_compatibility.conformance_sha256'
```

```ini
IMMORTAL_PROVIDER_BOLTZ_BIND=127.0.0.1:9093
IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256=<OUTPUT_FROM_PROVIDER_CONTRACT>
IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN=https://wallet.example.com
```

Expose that private plaintext listener only through the operator's authenticated
TLS reverse proxy. Configure the relay handoff origin to the proxy's HTTPS
origin and configure adapted clients to use its `wss://.../v2/ws` endpoint
directly. Do not make the provider bind public. The surface is a compatibility
API and is never advertised in relay NIP-11.

For LND, replace the CLN selector/path with the following values. Copy or
provision the certificate and least-privilege macaroon files through the
operator's custody system; each macaroon file must be a nonsymlink regular
file owned by the provider service account and mode `0600`.

```ini
IMMORTAL_PROVIDER_LIGHTNING_RAIL=lnd
IMMORTAL_PROVIDER_LND_HOST=127.0.0.1
IMMORTAL_PROVIDER_LND_PORT=8080
IMMORTAL_PROVIDER_LND_TLS_CERT_FILE=/etc/immortal-provider/lnd/tls.cert
IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE=/etc/immortal-provider/lnd/readonly.macaroon
IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE=/etc/immortal-provider/lnd/invoices.macaroon
IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE=/etc/immortal-provider/lnd/router.macaroon
```

Do not configure `admin.macaroon`. The certificate is a public identity pin,
but its reviewed bytes must still be changed only as an explicit LND
certificate rotation. The macaroons are custody-bearing node credentials and
must never enter provider Postgres, relay state, logs, fixtures, or backups of
the provider database.

Do not set `IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB` in this production
example. The daemon uses bitcoind's conservative two-block `estimatesmartfee`
result and refuses new Quotes when no estimate exists. An operator may set an
explicit 1–2,000 sat/vB fallback after treating it as a pricing policy override;
the regtest lab sets it because regtest has no fee history.

Install it without exposing its contents:

```sh
sudo install -d -o root -g immortal-provider -m 0750 /etc/immortal-provider
sudo install -o root -g immortal-provider -m 0640 /dev/null \
  /etc/immortal-provider/provider.env
sudoedit /etc/immortal-provider/provider.env
if sudo grep -q '<' /etc/immortal-provider/provider.env; then
  echo 'ERROR: unresolved provider placeholder remains' >&2
  false
fi
```

The complete bounds and defaults are in [`configuration.md`](configuration.md)
and in `immortal-provider contract`.

## 6. Install the service

Create `/etc/systemd/system/immortal-provider.service`:

```ini
[Unit]
Description=Immortal liquidity provider
After=network-online.target postgresql.service bitcoind.service lightningd.service immortal.service
Wants=network-online.target
Requires=postgresql.service bitcoind.service lightningd.service immortal.service

[Service]
Type=simple
User=immortal-provider
Group=immortal-provider
EnvironmentFile=/etc/immortal-provider/provider.env
ExecStart=/opt/immortal-provider/current/immortal-provider run
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
ReadOnlyPaths=/var/lib/immortal-provider/wallet.seed

[Install]
WantedBy=multi-user.target
```

For CLN, adjust the Lightning unit name and socket path to match the installed
service. For LND, replace `lightningd.service` with the local LND unit and add
all four configured credential paths to `ReadOnlyPaths`. Keep Postgres,
bitcoind, relay, Lightning REST, health, and alert traffic on loopback. Then
verify and start:

```sh
sudo systemd-analyze verify /etc/systemd/system/immortal-provider.service
sudo systemctl daemon-reload
sudo systemctl enable --now immortal-provider.service
systemctl status immortal-provider.service --no-pager
journalctl -u immortal-provider.service -n 30 --no-pager
```

Startup must fail if the configured networks disagree, bitcoind lacks the
required RPCs, the selected Lightning rail lacks a required capability, an
LND certificate or macaroon is unsafe, the wallet file is unsafe, the provider
migration is unknown, or any endpoint exceeds its allowed scope.

## 7. Health, funding, and liquidity

Check readiness and public-only metrics locally:

```sh
curl -fsS http://127.0.0.1:9091/healthz
curl -fsS http://127.0.0.1:9091/metrics
```

Do not send funds until `/healthz` returns `ready`. Derive the first BIP-86
receiving address without opening Postgres or contacting either rail:

```sh
sudo -u immortal-provider env \
  IMMORTAL_PROVIDER_BITCOIN_NETWORK=mainnet \
  IMMORTAL_PROVIDER_WALLET_SEED_FILE=/var/lib/immortal-provider/wallet.seed \
  /opt/immortal-provider/current/immortal-provider address
```

Fund that address according to the operator's hot-wallet policy. Lightning
inventory remains in the operator's Lightning wallet and channels; the
provider reads the selected rail's channel balance and will not issue a hard
reservation without durable capacity. Channel balancing, fee policy, and
capital limits remain operator responsibilities.

The reverse hard-reservation gate selects exact controlled UTXOs before the
Quote binds a signed funding transaction, its SHA-256 digest, and output index.
Both participants sign that transaction commitment. The provider rebuilds it
from the recovered reservation immediately before broadcast and refuses any
byte change. Do not add an operational bypass: the requester must first pass
the client engine's bilateral-contract, `ExitPackage`, and verify-before-fund
checks and publish its authorization Status.

Signed funding, claim, and reverse-lock heights are exclusive deadlines. At
the exact height, the provider stops the irreversible action and enters the
specified cancellation/recovery path. A cooperative reverse claim retires the
persisted refund watch only after finality and hold settlement reconciliation;
the noncooperative path keeps that watch active through confirmed refund. A
journey is not terminal until the client accepts the provider-signed Close and
the reservation release is durable.

## 8. Stop, backup, restore, and upgrade

Before a planned stop, wait until metrics show no active reservations,
pending effects, unresolved effects, pending watch jobs, or unresolved watch
jobs. There is no v1 force-drain command. Stopping with an active timelock is
an operator incident; the persisted watchtower state exists for restart, not
as permission to stop casually.

Back up the provider database with `pg_dump` and immediately test restore into
a disposable database. Back up the wallet seed and Lightning recovery material
separately through the operator's encrypted custody system. Database backups
must never contain either. Restore the selected Lightning node through its
supported recovery procedure; copying only provider Postgres cannot recover
Lightning funds.

For an upgrade:

1. wait for the zero-active-work metrics above;
2. stop `immortal-provider.service`;
3. take and verify the provider Postgres backup;
4. install the new binary in a new immutable release directory;
5. compare `immortal-provider contract` with the reviewed release artifact;
6. switch `/opt/immortal-provider/current`, start, and require `/healthz` to
   return `ready` before allowing new swaps.

An older binary rejects an unknown provider migration. If an upgrade applies a
new migration, rollback requires both the old binary and the pre-upgrade
database restore. Keep the failed database until the restored process is
ready and the operator has reconciled every public execution record.

## 9. Local funded proof

Before handling value, execute the disposable regtest proof on the target
architecture:

```sh
cargo test --locked -p immortal-provider --lib provider_runtime_fixture
./scripts/export-provider-contract.sh --check
./scripts/test-provider-funded.sh
IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd ./scripts/test-provider-funded.sh
```

The runtime fixture command exercises the held-HTLC, signed-deadline,
hold-cancellation, and cooperative watch-retirement transitions through the
production helpers. The contract check binds that fixture's exact digest. A
passing process gate then proves submarine settlement, reverse settlement, and
a noncooperative reverse refund with real bitcoind, the selected Lightning
rail, relay, provider database, and watchtower processes. Its public evidence rules are
documented in
[`provider-funded-smoke.md`](../conformance/provider-funded-smoke.md).

Current local result: **passed on macOS 26.4 arm64 on 2026-08-04**, with
`test-provider-funded: submarine, reverse, and noncooperative refund passed`.
That result validates the disposable regtest topology and does not validate a
clean Debian installation or a live deployment. Issue #19 must execute and
record those release proofs before a deployment claim.
