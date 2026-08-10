# Runbook: funded provider on Debian

This is the operator contract for the custody-bearing `immortal-provider` v1
binary. It runs as a product separate from the `immortal` relay, owns a
separate Postgres database, and drives operator-owned Bitcoin Core and either
Core Lightning or LND. An optional Liquid rail drives an operator-owned
elementsd wallet over loopback. The wallet seed, Lightning and Elements
wallets, node credentials, private keys, and unreleased preimages never enter
provider Postgres or relay state.

The M12 closing packet (#19) binds this runbook to committed deployment
assets, fresh-host execution evidence, and the network shadow/cutover procedure
in [`runbook-swap-network.md`](runbook-swap-network.md).

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

For BTC↔L-BTC service, also install Elements Core 23.3.3 with JSON-RPC bound
to loopback and a dedicated provider wallet. Keep Liquid disabled when this
node and its funded wallet are unavailable; the daemon then omits every
Liquid Offering side. The Elements node is an optional rail prerequisite, not
a relay dependency.

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

For Elements, enable wallet and transaction indexing, bind RPC to loopback,
and create a wallet dedicated to this provider. The daemon uses the same
bounded hand-written HTTP/1.1 JSON-RPC transport as bitcoind. It checks the
genesis-derived BIP-122 network identifier and `getsidechaininfo.pegged_asset`
before serving Liquid sides. It may unblind only its own wallet outputs. Do
not export the wallet's private keys, blinding keys, value blinders, or asset
blinders into the provider environment, Postgres, relay, or support bundles.

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

Install the committed example as `/etc/immortal-provider/provider.env`, owned
by root and mode `0600`, then replace every placeholder with the operator's
value:

```sh
sudo install -d -o root -g root -m 0700 /etc/immortal-provider
sudo install -o root -g root -m 0600 deploy/immortal-provider.env.example \
  /etc/immortal-provider/provider.env
sudoedit /etc/immortal-provider/provider.env
```

The installed file has this production shape:

```ini
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:<DB_PASSWORD>@127.0.0.1:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URLS=ws://127.0.0.1:8080,ws://127.0.0.1:8081
# Set public NIP-42 authorities positionally when they differ from the local
# proxy endpoints:
IMMORTAL_PROVIDER_RELAY_AUTH_URLS=wss://relay-a.example,wss://relay-b.example
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

Zero-confirmation admission remains disabled with the configuration above.
An operator who accepts the replacement and double-spend exposure may enable
one or both requester-funded Bitcoin directions and must set both hard caps:

```ini
IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE=true
# IMMORTAL_PROVIDER_ZERO_CONF_CHAIN=true
IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT=100000
IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT=500000
```

Start with caps that the operator can lose in full. The provider requires its
own local bitcoind mempool view, rejects RBF signaling and unconfirmed
ancestors, durably accounts aggregate exposure, and rechecks immediately
before its rail effect. A signed zero-conf-accepted Status is not finality.
Removing both direction flags requires removing both cap values; partial or
cap-only configuration fails startup.

To enable Liquid, append every value below. Derive both identifiers from the
exact local node; do not substitute a network label or ticker:

```sh
elements-cli -rpcwallet=provider-liquid getblockhash 0
elements-cli -rpcwallet=provider-liquid getsidechaininfo \
  | jq -r '.pegged_asset'
```

The BIP-122 value is `bip122:` followed by the first 32 lowercase hexadecimal
characters of the displayed genesis hash.

```ini
IMMORTAL_PROVIDER_LIQUID_ENABLED=true
IMMORTAL_PROVIDER_ELEMENTSD_HOST=127.0.0.1
IMMORTAL_PROVIDER_ELEMENTSD_PORT=7041
IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER=<ELEMENTSD_RPC_USER>
IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD=<ELEMENTSD_RPC_PASSWORD>
IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-liquid
IMMORTAL_PROVIDER_LIQUID_NETWORK_ID=bip122:<32_LOWERCASE_HEX>
IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET=<64_LOWERCASE_HEX>
```

Use a distinct elementsd RPC credential and protect its configuration as
custody-adjacent operator state. The provider environment contains the RPC
password but never the Elements wallet keys. Omitting
`IMMORTAL_PROVIDER_LIQUID_ENABLED` disables the rail; partial or stray Liquid
settings fail startup.

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

Expose that private plaintext listener only through the operator's TLS reverse
proxy. Configure the relay handoff origin to the proxy's HTTPS
origin and configure adapted clients to use its `wss://.../v2/ws` endpoint
directly. Do not make the provider bind public. The surface is a compatibility
API and is never advertised in relay NIP-11.

Startup applies the provider database migrations before the listener opens.
The Boltz invoice-binding migration adds only the signed public BOLT11,
payment hash, session ID, and Status event ID. It stores no preimage, wallet
key, macaroon, or node credential. On startup, the provider keyset-pages
candidate sessions and populates missing rows only after checking provider
authorship, exact bilateral reverse Contracts, and the parsed BOLT11 payment
hash. Back up Postgres before upgrading and keep the old binary available
until `immortal-provider contract` and the local provider conformance gate pass
against the migrated database.

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

Verify it without exposing its contents:

```sh
if sudo grep -q '<' /etc/immortal-provider/provider.env; then
  echo 'ERROR: unresolved provider placeholder remains' >&2
  false
fi
```

The complete bounds and defaults are in [`configuration.md`](configuration.md)
and in `immortal-provider contract`.

## 6. Install the service

Install the committed unit:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/immortal-provider.service \
  /etc/systemd/system/immortal-provider.service
```

For CLN, adjust the Lightning unit name and socket path to match the installed
service. For LND, replace `lightningd.service` with the local LND unit and add
all four configured credential paths to `ReadOnlyPaths`. When Liquid is
enabled, order the provider after the local elementsd unit without binding its
lifetime to the relay unit. Keep Postgres, bitcoind, elementsd, relay,
Lightning REST, health, and alert traffic on loopback. Then verify and start:

```sh
sudo systemd-analyze verify /etc/systemd/system/immortal-provider.service
sudo systemctl daemon-reload
sudo systemctl enable --now immortal-provider.service
systemctl status immortal-provider.service --no-pager
journalctl -u immortal-provider.service -n 30 --no-pager
```

The provider unit requires its database and rail nodes, but it does not
require or bind to `immortal.service`. Relay failure must not stop the provider
watchtower. SIGUSR1, SIGTERM, and SIGINT begin the same drain: discovery moves
to `paused`, new sessions are refused, existing sessions and recovery
continue, and the process exits after its active-session count reaches zero.
The unit deliberately has no forced stop timeout or SIGKILL fallback.

Startup must fail if the configured networks disagree, bitcoind or an enabled
elementsd lacks the required RPCs, the selected Lightning rail lacks a
required capability, an LND certificate or macaroon is unsafe, the wallet
file is unsafe, the provider migration is unknown, or any endpoint exceeds
its allowed scope.

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

When Liquid is enabled, obtain a confidential receiving address from the
dedicated Elements wallet and fund it with L-BTC according to the same hot
inventory policy:

```sh
elements-cli -rpcwallet=provider-liquid getnewaddress
```

Verify the wallet's available pegged-asset balance and the daemon's readiness
before allowing Liquid RFQs. The wallet is the unblinding and signing
authority for provider-owned outputs. Back up and drain it using Elements
Core's wallet procedures separately from provider Postgres. Never copy a
wallet backup into the provider database-backup directory.

Liquid v1 prices a one-input confidential funding transaction. Maintain at
least one confirmed provider-wallet output per intended provider-funded swap
that alone covers the swap amount plus the full signed fee budget. The funding
transaction may spend only its weight-proportional share of that budget; the
larger admission bound leaves the unilateral exit funded. The daemon does not
combine smaller outputs: doing so would exceed the fixture-pinned 1,700-vbyte
funding weight. Consolidate and confirm inventory before opening discovery,
then let the reservation gate select the exact output.

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

Elements Core 23.3.3 has no `gettxspendingprevout` RPC. Liquid recovery scans
the bounded mempool and 144 most recent blocks for the exact spending input,
then checks `gettxout`. If the output is spent but its spender is older than
that window, the provider fails the observation and remains unavailable; it
does not infer an unspent output. Page on the resulting unresolved effect and
restore the exact public transaction history before resuming new sessions.
At startup, readiness also probes the configured wallet and the exact methods
used for `listunspent`, descriptor/address derivation, PSBT funding, wallet
signing, finalization, unblinding, observation, and broadcast. A partial wallet
surface does not advertise Liquid sides. Every funding transaction must spend
the exact durable reservation inputs and carry one explicit fee output equal
to the node-reported fee under the signed Quote maximum.

Before deploying or re-enabling Liquid, run the disposable local rail and
expanded process gates from the exact release bytes:

```sh
scripts/test-provider-liquid.sh
scripts/test-lab-adversarial.sh --all
```

The Liquid record must show exact funding and exit bytes, submarine and
reverse settlement on both rails, both chain directions through both provider
identities, restart recovery, the provider-absent and coordinator-absent exit
paths, settled outpoints, and zero wrapper-owned artifacts after teardown. A
local pass is conformance evidence; it is not proof of live liquidity or
deployment.

## 8. Stop, backup, restore, and upgrade

Begin a planned drain with SIGUSR1 and watch the public-only metrics:

```sh
sudo systemctl kill --signal=SIGUSR1 immortal-provider.service
curl -fsS http://127.0.0.1:9091/metrics \
  | grep -E 'immortal_provider_(draining|sessions_active|reservations_active|effects_pending|effects_unresolved|watch_jobs_pending|watch_jobs_unresolved)'
```

The process refuses new sessions, continues existing sessions and watchtower
work, and exits only after the active-session count reaches zero. SIGTERM from
`systemctl stop` has the same behavior. Do not force-kill a process with an
active timelock.

When Liquid is enabled, keep elementsd and its selected wallet available until
`sessions_active`, `effects_pending`, `effects_unresolved`,
`watch_jobs_pending`, and `watch_jobs_unresolved` are all zero. Back up or stop
the Elements node only after that drain completes; provider Postgres cannot
replace the wallet's signing and unblinding state.

Install and start the committed database backup timer:

```sh
sudo install -d -o postgres -g postgres -m 0700 /var/backups/immortal-provider
sudo install -o root -g root -m 0755 deploy/backup/immortal-provider-backup \
  /usr/local/sbin/immortal-provider-backup
sudo install -o root -g root -m 0644 \
  deploy/backup/immortal-provider-backup.service \
  deploy/backup/immortal-provider-backup.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now immortal-provider-backup.timer
sudo systemctl start immortal-provider-backup.service
```

Back up the provider database with `pg_dump` and immediately test restore into
a disposable database. Back up the Bitcoin wallet seed, Lightning recovery
material, and optional Elements wallet separately through the operator's
encrypted custody system. Database backups must never contain any of them.
Restore the selected Lightning and Elements nodes through their supported
recovery procedures; copying only provider Postgres cannot recover rail funds.

Verify a database backup and its digest before an upgrade:

```sh
cd /var/backups/immortal-provider
sha256sum --check immortal-provider-<TIMESTAMP>.dump.sha256
sudo -u postgres createdb immortal_provider_restore_test
sudo -u postgres pg_restore --dbname=immortal_provider_restore_test \
  immortal-provider-<TIMESTAMP>.dump
sudo -u postgres psql --dbname=immortal_provider_restore_test \
  --command='SELECT version, name FROM provider_schema_migrations ORDER BY version;'
sudo -u postgres dropdb immortal_provider_restore_test
```

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

The closing-packet acceptance also exercises the committed install, systemd,
backup, and restore assets inside fresh Debian 13 before running the funded
smoke:

```sh
./scripts/run-debian-provider-funded.sh \
  --receipt docs/conformance/records/<DATE>-debian-provider-<COMMIT>.json
```

The outer acceptance container uses apt Postgres and the release provider
binary. Its systemd verification supplies named acceptance stubs for bitcoind
and lightningd because the live nodes and hold plugin run inside the nested
funded smoke; the receipt records that boundary. Operators must replace those
names with their installed node units and run the same verification on the
target host.

The runtime fixture command exercises the held-HTLC, signed-deadline,
hold-cancellation, and cooperative watch-retirement transitions through the
production helpers. The contract check binds that fixture's exact digest. A
passing process gate then proves submarine settlement, reverse settlement, and
a noncooperative reverse refund with real bitcoind, the selected Lightning
rail, relay, provider database, and watchtower processes. Its public evidence rules are
documented in
[`provider-funded-smoke.md`](../conformance/provider-funded-smoke.md).

Current closing result: **passed on Debian 13 arm64 at source commit
`764d119736035134c3cb0e0e5fc4fe803d946bf6`**. The acceptance installed the
release and committed assets, verified systemd and file modes, checked the
database-backup digest, restored all three provider migrations, and passed the
submarine, reverse, and noncooperative-refund smoke. The bounded receipt is
[`2026-08-05-debian-provider-764d119.json`](../conformance/records/2026-08-05-debian-provider-764d119.json).
It does not establish a live provider or public replacement claim.

## 10. Ark external-process qualification

Ark execution is off by default and has no native provider session or
advertised pair. Before enabling the fixture-gated regtest adapter on a build
host, run:

```sh
./scripts/test-provider-ark-transfer.sh
./scripts/test-lab-adversarial.sh --case doomsday-ark-operator-gone
./scripts/export-provider-contract.sh --check
```

The first gate proves durable persist-before-RPC transfer execution and exact
restart behavior against a bounded loopback Arkd adapter. The second builds
the pinned Arkd sources, creates an actual participant VTXO and funded exit,
permanently removes the operator/indexer/wallet state, and reaches the final
participant Bitcoin output through the retained package and Esplora alone.
Neither gate imports Ark wallet credentials or exit-package bytes into the
provider database. Production Ark activation needs a separate reviewed
session/pair packet and deployment evidence.
