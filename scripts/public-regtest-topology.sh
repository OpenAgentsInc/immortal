#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/public-regtest-topology-v1.json"
base_compose="scripts/support/provider-funded/adversarial-compose.yaml"
deployment_compose="deploy/public-regtest/compose.yaml"
state_dir="${IMMORTAL_PUBLIC_REGTEST_STATE_DIR:-/var/lib/immortal-public-regtest}"
gateway_state="${IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR:-${state_dir}/gateway}"
export IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR="${gateway_state}"
relay_a_url="${IMMORTAL_PUBLIC_REGTEST_RELAY_A_URL:-}"
relay_b_url="${IMMORTAL_PUBLIC_REGTEST_RELAY_B_URL:-}"
relay_a_port="${IMMORTAL_PUBLIC_REGTEST_RELAY_A_PORT:-18080}"
relay_b_port="${IMMORTAL_PUBLIC_REGTEST_RELAY_B_PORT:-18081}"
bitcoin_p2p_port="${IMMORTAL_PUBLIC_REGTEST_BITCOIN_P2P_PORT:-18444}"
marker="${state_dir}/ownership.json"
manifest="${state_dir}/public-ready.json"
postgres_image="postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
provider_utxo_target=8

usage() {
  cat <<'USAGE'
usage: scripts/public-regtest-topology.sh <command> [arguments]

commands:
  init                         create owned private configuration once
  config                       validate the merged Compose configuration
  up                           initialize, start, bootstrap, and prove readiness
  ready                        fail unless every topology readiness check passes
  status                       print the bounded public-safe readiness manifest
  restart <service>            replace one allowlisted durable service and recheck
  resolve-alert <provider> CONFIRM_RECOVERED_PROVIDER_ALERT
                               archive one recovered provider alert and recheck
  backup <absolute-directory>  stop the topology and back up secrets plus volumes
  down                         stop containers but retain all state and volumes
  reset CONFIRM_PUBLIC_REGTEST_RESET
                               remove only this profile's owned containers,
                               volumes, and private state
  contract                     print the public topology machine contract

required for init/up:
  IMMORTAL_PUBLIC_REGTEST_RELAY_A_URL=wss://relay-a.example
  IMMORTAL_PUBLIC_REGTEST_RELAY_B_URL=wss://relay-b.example

optional:
  IMMORTAL_PUBLIC_REGTEST_STATE_DIR   absolute private state directory
  IMMORTAL_PUBLIC_REGTEST_RELAY_A_PORT loopback proxy port (default 18080)
  IMMORTAL_PUBLIC_REGTEST_RELAY_B_PORT loopback proxy port (default 18081)
  IMMORTAL_PUBLIC_REGTEST_BITCOIN_P2P_PORT public regtest P2P port (default 18444)
USAGE
}

fail() {
  echo "public-regtest-topology: $1" >&2
  exit 1
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "${command_name}" >/dev/null 2>&1 || fail "required command ${command_name} is unavailable"
  done
}

validate_state_path() {
  case "${state_dir}" in
    /*) ;;
    *) fail "state directory must be absolute" ;;
  esac
  case "${state_dir}" in
    /|/Users|/home|/var|/tmp|"$(pwd -P)"|"$(pwd -P)"/*)
      fail "state directory is too broad or inside the repository"
      ;;
  esac
  if test -L "${state_dir}"; then
    fail "state directory must not be a symlink"
  fi
}

validate_public_configuration() {
  python3 - "${relay_a_url}" "${relay_b_url}" "${relay_a_port}" "${relay_b_port}" "${bitcoin_p2p_port}" <<'PY'
import sys
import urllib.parse

urls = sys.argv[1:3]
if urls[0] == urls[1]:
    raise SystemExit("public relay URLs must be distinct")
for value in urls:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit("public relay URL must be an exact wss authority")
ports = []
for value in sys.argv[3:6]:
    if not value.isascii() or not value.isdigit() or not 1024 <= int(value) <= 65535:
        raise SystemExit("plain relay port must be in 1024..65535")
    ports.append(int(value))
if len(set(ports)) != len(ports):
    raise SystemExit("public and plain relay ports must be distinct")
PY
}

require_owned_state() {
  validate_state_path
  test -f "${marker}" || fail "owned state is absent; run init first"
  test ! -L "${marker}" || fail "ownership marker must not be a symlink"
  python3 - "${marker}" "$(pwd -P)" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("ownership marker exceeds its bound")
value = json.loads(path.read_text(encoding="utf-8"))
if value.get("schema") != "openagents.immortal.public-regtest-owner.v1":
    raise SystemExit("ownership marker has another schema")
if value.get("repository") != sys.argv[2]:
    raise SystemExit("ownership marker belongs to another checkout")
project = value.get("compose_project")
if not isinstance(project, str) or not project.startswith("immortal-public-regtest-") or len(project) > 63:
    raise SystemExit("ownership marker has an invalid Compose project")
PY
  if test -z "${relay_a_url}" || test -z "${relay_b_url}"; then
    read -r relay_a_url relay_b_url < <(python3 - "${marker}" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(*value["relay_urls"])
PY
    )
  fi
  validate_public_configuration
}

project_name() {
  python3 - "${marker}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["compose_project"])
PY
}

compose_prefix() {
  printf '%s\0' docker compose \
    --env-file "${state_dir}/compose.env" \
    --file "${base_compose}" \
    --file "${deployment_compose}" \
    --project-name "$(project_name)"
}

compose() {
  local -a command=()
  while IFS= read -r -d '' value; do command+=("${value}"); done < <(compose_prefix)
  "${command[@]}" "$@"
}

random_hex() {
  local bytes="$1"
  LC_ALL=C od -An -N "${bytes}" -tx1 /dev/urandom | tr -d ' \n'
}

write_secret() {
  local path="$1" value="$2"
  (umask 077; printf '%s\n' "${value}" >"${path}")
  chmod 0600 "${path}"
}

write_cln_config() {
  local path="$1" rpc_user="$2" rpc_password="$3" bind_port="$4" announce="$5" hold="$6"
  cat >"${path}" <<EOF
network=regtest
lightning-dir=/root/.lightning
rpc-file=/rail-rpc/lightning-rpc
rpc-file-mode=0660
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18443
bitcoin-rpcuser=${rpc_user}
bitcoin-rpcpassword=${rpc_password}
bind-addr=0.0.0.0:${bind_port}
announce-addr=${announce}:${bind_port}
log-level=info
EOF
  if test "${hold}" = true; then
    cat >>"${path}" <<'EOF'
plugin=/usr/local/bin/hold
hold-grpc-port=-1
hold-expiry-deadline=30
EOF
  fi
  chmod 0600 "${path}"
}

write_provider_env() {
  local path="$1" suffix="$2" database_password="$3" relay_port="$4" identity="$5"
  local rpc_user="$6" rpc_password="$7" socket_path="$8" seed_path="$9" health_port="${10}" spread="${11}"
  cat >"${path}" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${database_password}@provider-${suffix}-postgres:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:${relay_port}
IMMORTAL_PROVIDER_RELAY_AUTH_URL=$([ "${suffix}" = a ] && printf '%s' "${relay_a_url}" || printf '%s' "${relay_b_url}")
IMMORTAL_PROVIDER_IDENTITY_SECRET=${identity}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=${rpc_user}
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${rpc_password}
IMMORTAL_PROVIDER_CLN_RPC_PATH=${socket_path}
IMMORTAL_PROVIDER_WALLET_SEED_FILE=${seed_path}
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:${health_port}
IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND=127.0.0.1:$((health_port + 100))
IMMORTAL_PROVIDER_ALERT_URL=http://127.0.0.1:19092/provider-alert
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=30
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=1
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=2
IMMORTAL_PROVIDER_SPREAD_BPS=${spread}
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=20
IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE=true
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=300
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
EOF
  chmod 0600 "${path}"
}

reconcile_public_provider_pricing() {
  python3 - "${state_dir}/provider-a.env" "${state_dir}/provider-b.env" <<'PY'
import os, pathlib, sys
changed = False
for name in sys.argv[1:]:
    path = pathlib.Path(name)
    lines = path.read_text(encoding="utf-8").splitlines()
    file_changed = False
    values = {
        "IMMORTAL_PROVIDER_SPREAD_BPS": "100",
        "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB": "20",
        "IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE": "true",
    }
    rewritten = []
    seen = set()
    for line in lines:
        key = line.partition("=")[0]
        seen.add(key)
        replacement = f"{key}={values[key]}" if key in values else line
        file_changed |= replacement != line
        rewritten.append(replacement)
    for key in sorted(values.keys() - seen):
        rewritten.append(f"{key}={values[key]}")
        file_changed = True
    if file_changed:
        changed = True
        metadata = path.stat()
        temporary = path.with_name(path.name + ".pricing-next")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write("\n".join(rewritten) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
raise SystemExit(0 if changed else 1)
PY
}

initialize() {
  require_commands git jq od python3
  validate_state_path
  if test -e "${state_dir}"; then
    require_owned_state
    echo "public-regtest-topology: owned state already initialized at ${state_dir}"
    return
  fi
  validate_public_configuration
  umask 077
  install -d -m 0700 "${state_dir}" "${state_dir}/evidence" "${state_dir}/state"

  local project revision
  project="immortal-public-regtest-$(random_hex 5)"
  revision="$(git rev-parse HEAD)"
  python3 - "${marker}" "$(pwd -P)" "${project}" "${revision}" "${relay_a_url}" "${relay_b_url}" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
value = {
    "schema": "openagents.immortal.public-regtest-owner.v1",
    "repository": sys.argv[2],
    "compose_project": sys.argv[3],
    "source_revision": sys.argv[4],
    "relay_urls": [sys.argv[5], sys.argv[6]],
    "created_at": int(time.time()),
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(value, output, indent=2, sort_keys=True)
    output.write("\n")
PY

  local bitcoin_a_user bitcoin_b_user bitcoin_a_password bitcoin_b_password
  local relay_a_password relay_b_password provider_a_password provider_b_password
  local provider_a_identity provider_b_identity provider_a_seed provider_b_seed client_seed
  bitcoin_a_user="immortal-a"
  bitcoin_b_user="immortal-b"
  bitcoin_a_password="$(random_hex 32)"
  bitcoin_b_password="$(random_hex 32)"
  relay_a_password="$(random_hex 32)"
  relay_b_password="$(random_hex 32)"
  provider_a_password="$(random_hex 32)"
  provider_b_password="$(random_hex 32)"
  read -r provider_a_identity provider_b_identity < <(python3 <<'PY'
import secrets
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
values = []
while len(values) < 2:
    value = secrets.randbelow(order)
    if value and value not in values:
        values.append(value)
print(*(f"{value:064x}" for value in values))
PY
  )
  provider_a_seed="$(random_hex 32)"
  provider_b_seed="$(random_hex 32)"
  client_seed="$(random_hex 32)"

  write_secret "${state_dir}/relay-a-postgres-password" "${relay_a_password}"
  write_secret "${state_dir}/relay-b-postgres-password" "${relay_b_password}"
  write_secret "${state_dir}/provider-a-postgres-password" "${provider_a_password}"
  write_secret "${state_dir}/provider-b-postgres-password" "${provider_b_password}"
  write_secret "${state_dir}/provider-a-wallet-seed" "${provider_a_seed}"
  write_secret "${state_dir}/provider-b-wallet-seed" "${provider_b_seed}"
  write_secret "${state_dir}/client-wallet-seed" "${client_seed}"

  cat >"${state_dir}/bitcoin-a.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
[regtest]
bind=0.0.0.0:18444
addnode=bitcoin-b:18444
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_a_user}
rpcpassword=${bitcoin_a_password}
EOF
  cat >"${state_dir}/bitcoin-b.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
[regtest]
bind=0.0.0.0:18444
addnode=bitcoin-a:18444
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_b_user}
rpcpassword=${bitcoin_b_password}
EOF
  chmod 0600 "${state_dir}/bitcoin-a.conf" "${state_dir}/bitcoin-b.conf"
  write_cln_config "${state_dir}/cln-provider-a.conf" "${bitcoin_a_user}" "${bitcoin_a_password}" 19846 bitcoin-a true
  write_cln_config "${state_dir}/cln-provider-b.conf" "${bitcoin_b_user}" "${bitcoin_b_password}" 19847 bitcoin-b true
  write_cln_config "${state_dir}/cln-wallet.conf" "${bitcoin_a_user}" "${bitcoin_a_password}" 19848 wallet-gateway false

  cat >"${state_dir}/relay-a.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_a_password}@relay-a-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18080
IMMORTAL_RELAY_URL=${relay_a_url}
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF
  cat >"${state_dir}/relay-b.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_b_password}@relay-b-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18081
IMMORTAL_RELAY_URL=${relay_b_url}
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF
  write_provider_env "${state_dir}/provider-a.env" a "${provider_a_password}" 18080 \
    "${provider_a_identity}" "${bitcoin_a_user}" "${bitcoin_a_password}" \
    /rail/cln-provider-a/lightning-rpc /run/immortal-private/provider-a-wallet-seed 9091 100
  write_provider_env "${state_dir}/provider-b.env" b "${provider_b_password}" 18081 \
    "${provider_b_identity}" "${bitcoin_b_user}" "${bitcoin_b_password}" \
    /rail/cln-provider-b/lightning-rpc /run/immortal-private/provider-b-wallet-seed 9092 100
  cat >"${state_dir}/esplora.env" <<EOF
IMMORTAL_ESPLORA_BITCOIND_RPC_USER=${bitcoin_a_user}
IMMORTAL_ESPLORA_BITCOIND_RPC_PASSWORD=${bitcoin_a_password}
EOF
  cat >"${state_dir}/wallet-driver.env" <<EOF
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_URLS=ws://127.0.0.1:18080,ws://127.0.0.1:18081
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_AUTH_URLS=${relay_a_url},${relay_b_url}
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_HEALTH_URLS=http://127.0.0.1:9091/healthz,http://127.0.0.1:9092/healthz
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_USER=${bitcoin_a_user}
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_PASSWORD=${bitcoin_a_password}
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_A_HOST=127.0.0.1
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_A_PORT=18443
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_A_RPC_USER=${bitcoin_a_user}
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_A_RPC_PASSWORD=${bitcoin_a_password}
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_HOST=127.0.0.1
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_PORT=18444
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_USER=${bitcoin_b_user}
IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_PASSWORD=${bitcoin_b_password}
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLN_RPC_PATH=/rail/cln-wallet/lightning-rpc
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLIENT_WALLET_SEED_FILE=/run/immortal-private/client-wallet-seed
IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE=/evidence/public-regtest-driver.json
IMMORTAL_PROVIDER_FUNDED_SMOKE_TERMINAL_CONFIRMATIONS=3
IMMORTAL_LAB_STATE_DIR=/state
EOF
  : >"${state_dir}/lnd-provider.conf"
  cat >"${state_dir}/compose.env" <<EOF
IMMORTAL_ADVERSARIAL_PRIVATE_DIR=${state_dir}
IMMORTAL_ADVERSARIAL_PROVIDER_IMAGE=${project}-provider:local
IMMORTAL_PUBLIC_REGTEST_RELAY_A_PORT=${relay_a_port}
IMMORTAL_PUBLIC_REGTEST_RELAY_B_PORT=${relay_b_port}
EOF
  chmod 0600 "${state_dir}"/*.env "${state_dir}"/*.conf
  echo "public-regtest-topology: initialized owned state at ${state_dir}"
}

bitcoin_cli() {
  local node="$1"
  shift
  compose exec -T "bitcoin-${node}" bitcoin-cli \
    "-conf=/run/immortal-private/bitcoin-${node}.conf" -datadir=/var/lib/bitcoin "$@"
}

cln_cli() {
  local service="$1"
  shift
  compose exec -T "${service}" lightning-cli --network=regtest \
    --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc "$@"
}

wait_for() {
  local description="$1"
  shift
  local attempt
  for attempt in $(seq 1 300); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  fail "${description} did not become ready"
}

chains_synced() {
  test "$(bitcoin_cli a getbestblockhash)" = "$(bitcoin_cli b getbestblockhash)" \
    && test "$(bitcoin_cli a getblockcount)" = "$(bitcoin_cli b getblockcount)"
}

bitcoin_peered() {
  test "$(bitcoin_cli a getconnectioncount)" -ge 1 \
    && test "$(bitcoin_cli b getconnectioncount)" -ge 1
}

cln_ready() {
  local service="$1"
  cln_cli "${service}" getinfo | jq -e '.network == "regtest" and .warning_bitcoind_sync == null and .warning_lightningd_sync == null'
}

channel_count() {
  cln_cli "$1" listpeerchannels | jq \
    '[.channels[] | select(.state == "CHANNELD_NORMAL" and .peer_connected == true)] | length'
}

channels_ready() {
  test "$(channel_count "$1")" -ge 2
}

open_channel_if_absent() {
  local source="$1" target="$2" target_host="$3" amount="$4" push="$5" target_id
  target_id="$(cln_cli "${target}" getinfo | jq -er .id)"
  if cln_cli "${source}" listpeerchannels "${target_id}" | jq -e '.channels | length > 0' >/dev/null; then
    if ! cln_cli "${source}" listpeerchannels "${target_id}" | \
      jq -e 'any(.channels[]; .peer_connected == true)' >/dev/null; then
      cln_cli "${source}" connect "${target_id}@${target_host}" >/dev/null
    fi
    return
  fi
  cln_cli "${source}" connect "${target_id}@${target_host}" >/dev/null
  cln_cli "${source}" -k fundchannel id="${target_id}" amount="${amount}sat" \
    feerate=253perkw announce=false push_msat="${push}msat" >/dev/null
}

ensure_channel() {
  local source="$1" target="$2" target_host="$3" amount="$4" push="$5"
  wait_for "${source} to ${target} channel" open_channel_if_absent \
    "${source}" "${target}" "${target_host}" "${amount}" "${push}"
}

reconnect_lightning_peers() {
  local service
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service}" cln_ready "${service}"
  done
  ensure_channel cln-provider-a cln-wallet wallet-gateway:19848 2000000 1000000000
  ensure_channel cln-provider-b cln-wallet wallet-gateway:19848 2000000 1000000000
  ensure_channel cln-provider-a cln-provider-b bitcoin-b:19847 1000000 500000000
}

fund_cln_if_empty() {
  local service="$1" address
  if cln_cli "${service}" listfunds | jq -e 'any(.outputs[]; .status == "confirmed")' >/dev/null; then
    return
  fi
  address="$(cln_cli "${service}" newaddr bech32 | jq -er .bech32)"
  bitcoin_cli a -rpcwallet=public-regtest-miner sendtoaddress "${address}" 3.0 >/dev/null
}

miner_wallet_ready() {
  bitcoin_cli a -rpcwallet=public-regtest-miner getwalletinfo >/dev/null 2>&1
}

load_existing_miner_wallet() {
  if miner_wallet_ready; then return; fi
  bitcoin_cli a loadwallet public-regtest-miner >/dev/null 2>&1
}

ensure_existing_miner_wallet() {
  wait_for "public regtest miner wallet" load_existing_miner_wallet
}

cln_wallet_funded() {
  cln_cli "$1" listfunds | jq -e 'any(.outputs[]; .status == "confirmed")'
}

confirmed_address_utxos() {
  local node="$1" address="$2"
  bitcoin_cli "${node}" scantxoutset start "[\"addr(${address})\"]" |
    jq -er '.unspents | length'
}

ensure_provider_utxos() {
  local node="$1" address="$2" count missing
  count="$(confirmed_address_utxos "${node}" "${address}")"
  [[ "${count}" =~ ^[0-9]+$ ]] || fail "provider UTXO count is invalid"
  if test "${count}" -ge "${provider_utxo_target}"; then return; fi
  missing=$((provider_utxo_target - count))
  for _ in $(seq 1 "${missing}"); do
    bitcoin_cli a -rpcwallet=public-regtest-miner sendtoaddress "${address}" 0.1 >/dev/null
  done
}

bootstrap() {
  wait_for "Bitcoin A" bitcoin_cli a getblockchaininfo
  wait_for "Bitcoin B" bitcoin_cli b getblockchaininfo
  wait_for "Bitcoin peering" bitcoin_peered
  if ! bitcoin_cli a -rpcwallet=public-regtest-miner getwalletinfo >/dev/null 2>&1; then
    if ! bitcoin_cli a loadwallet public-regtest-miner >/dev/null 2>&1; then
      bitcoin_cli a createwallet public-regtest-miner >/dev/null
    fi
  fi
  local height miner_address needed
  height="$(bitcoin_cli a getblockcount)"
  miner_address="$(bitcoin_cli a -rpcwallet=public-regtest-miner getnewaddress)"
  if test "${height}" -lt 110; then
    needed=$((110 - height))
    bitcoin_cli a -rpcwallet=public-regtest-miner generatetoaddress "${needed}" "${miner_address}" >/dev/null
  fi
  wait_for "Bitcoin tip convergence" chains_synced

  local service method
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service}" cln_ready "${service}"
    fund_cln_if_empty "${service}"
  done
  bitcoin_cli a -rpcwallet=public-regtest-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "funding tip convergence" chains_synced
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} funded wallet" cln_wallet_funded "${service}"
  done
  for service in cln-provider-a cln-provider-b; do
    for method in holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice; do
      cln_cli "${service}" -J -k help command="${method}" | jq -e \
        --arg method "${method}" '.help | any(.[]; .command | startswith($method))' >/dev/null
    done
  done

  ensure_channel cln-provider-a cln-wallet wallet-gateway:19848 2000000 1000000000
  ensure_channel cln-provider-b cln-wallet wallet-gateway:19848 2000000 1000000000
  bitcoin_cli a -rpcwallet=public-regtest-miner generatetoaddress 1 "${miner_address}" >/dev/null
  wait_for "first channel funding convergence" chains_synced
  ensure_channel cln-provider-a cln-provider-b bitcoin-b:19847 1000000 500000000
  bitcoin_cli a -rpcwallet=public-regtest-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "channel tip convergence" chains_synced
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} channel graph" channels_ready "${service}"
  done

  local provider_a_address provider_b_address
  provider_a_address="$(compose run --rm --no-deps provider-a address | tail -1)"
  provider_b_address="$(compose run --rm --no-deps provider-b address | tail -1)"
  ensure_provider_utxos a "${provider_a_address}"
  ensure_provider_utxos b "${provider_b_address}"
  bitcoin_cli a -rpcwallet=public-regtest-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "provider funding convergence" chains_synced
}

provider_ready() {
  local service="$1" port="$2"
  compose exec -T "${service}" /usr/bin/curl --fail --silent "http://127.0.0.1:${port}/healthz"
}

relay_ready() {
  local service="$1" port="$2" probe_service
  case "${service}" in
    relay-a) probe_service=provider-a ;;
    relay-b) probe_service=provider-b ;;
    *) return 1 ;;
  esac
  compose exec -T "${probe_service}" /usr/bin/curl --fail --silent \
    "http://127.0.0.1:${port}/health"
}

public_port_ready() {
  local service="$1" target="$2" expected_port="$3" published
  published="$(compose port "${service}" "${target}")" || return 1
  test "${published}" = "127.0.0.1:${expected_port}"
}

provider_pubkey() {
  local service="$1"
  compose logs --no-color "${service}" 2>/dev/null | sed -n \
    's/.*ready relay=.* pubkey=\([0-9a-f]\{64\}\).*/\1/p' | tail -1
}

write_manifest() {
  local hash height pubkey_a pubkey_b node_a node_b node_wallet revision
  hash="$(bitcoin_cli a getbestblockhash)"
  height="$(bitcoin_cli a getblockcount)"
  pubkey_a="$(provider_pubkey provider-a)"
  pubkey_b="$(provider_pubkey provider-b)"
  node_a="$(cln_cli cln-provider-a getinfo | jq -er .id)"
  node_b="$(cln_cli cln-provider-b getinfo | jq -er .id)"
  node_wallet="$(cln_cli cln-wallet getinfo | jq -er .id)"
  revision="$(python3 - "${marker}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["source_revision"])
PY
  )"
  python3 - "${manifest}" "${revision}" "${relay_a_url}" "${relay_b_url}" \
    "${hash}" "${height}" "${pubkey_a}" "${pubkey_b}" "${node_a}" "${node_b}" "${node_wallet}" <<'PY'
import json, os, pathlib, re, sys, time
path = pathlib.Path(sys.argv[1])
revision, relay_a, relay_b, block_hash, height = sys.argv[2:7]
provider_a, provider_b, node_a, node_b, node_wallet = sys.argv[7:12]
for value in (provider_a, provider_b):
    if re.fullmatch(r"[0-9a-f]{64}", value or "") is None:
        raise SystemExit("provider public key is unavailable")
value = {
    "schema": "openagents.immortal.public-regtest-ready.v1",
    "network": "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4",
    "source_revision": revision,
    "checked_at": int(time.time()),
    "chain": {"height": int(height), "best_block_hash": block_hash, "nodes": 2, "peered": True},
    "relays": [
        {"role": "relay-a", "websocket_url": relay_a, "health": "ready"},
        {"role": "relay-b", "websocket_url": relay_b, "health": "ready"},
    ],
    "providers": [
        {"role": "provider-a", "pubkey": provider_a, "offering_coordinate": f"39601:{provider_a}:immortal-funded-btc-lightning", "health": "ready"},
        {"role": "provider-b", "pubkey": provider_b, "offering_coordinate": f"39601:{provider_b}:immortal-funded-btc-lightning", "health": "ready"},
    ],
    "lightning": {
        "nodes": [
            {"role": "provider-a", "node_id": node_a},
            {"role": "provider-b", "node_id": node_b},
            {"role": "requester", "node_id": node_wallet},
        ],
        "required_channels_per_node": 2,
    },
    "authority": {"public_effect_gateway": False, "mainnet": False, "operator_independence": False},
}
encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > 32768:
    raise SystemExit("public readiness manifest exceeds its bound")
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o644)
PY
}

topology_services_ready() {
  test "$(bitcoin_cli a getconnectioncount)" -ge 1 || return 1
  test "$(bitcoin_cli b getconnectioncount)" -ge 1 || return 1
  chains_synced || return 1
  miner_wallet_ready || return 1
  relay_ready relay-a 18080 >/dev/null || return 1
  relay_ready relay-b 18081 >/dev/null || return 1
  public_port_ready relay-a-public 18080 "${relay_a_port}" || return 1
  public_port_ready relay-b-public 18081 "${relay_b_port}" || return 1
  provider_ready provider-a 9091 >/dev/null || return 1
  provider_ready provider-b 9092 >/dev/null || return 1
  local service
  for service in cln-provider-a cln-provider-b cln-wallet; do
    cln_ready "${service}" >/dev/null || return 1
    test "$(channel_count "${service}")" -ge 2 || return 1
  done
}

readiness_probe() {
  topology_services_ready || return 1
  test ! -e "${state_dir}/evidence/provider-a-alert.json" || return 1
  test ! -e "${state_dir}/evidence/provider-b-alert.json" || return 1
}

check_ready() {
  require_owned_state
  require_commands docker jq python3
  readiness_probe || fail "topology is not ready; inspect docker compose logs"
  write_manifest
  echo "public-regtest-topology: ready manifest ${manifest}"
}

resolve_provider_alert() {
  require_owned_state
  require_commands docker jq python3
  local provider="${1:-}" confirmation="${2:-}" alert archive_dir timestamp destination
  case "${provider}" in
    provider-a|provider-b) ;;
    *) fail "alert provider must be provider-a or provider-b" ;;
  esac
  test "${confirmation}" = CONFIRM_RECOVERED_PROVIDER_ALERT || \
    fail "recovered provider alert confirmation token is required"
  alert="${state_dir}/evidence/${provider}-alert.json"
  test -f "${alert}" || fail "provider alert is absent"
  test ! -L "${alert}" || fail "provider alert must not be a symlink"
  test "$(wc -c < "${alert}")" -le 65536 || fail "provider alert exceeds its bound"
  jq -e '
    type == "object" and
    .schema == "openagents.immortal.provider-alert.v1" and
    (.alert_type | type == "string" and length > 0) and
    ((.session_id == null) or (.session_id | type == "string")) and
    (.observed_at | type == "number") and
    (.detail | type == "string") and
    (keys | sort) == ["alert_type", "detail", "observed_at", "schema", "session_id"]
  ' "${alert}" >/dev/null || fail "provider alert has an invalid envelope"
  topology_services_ready || \
    fail "provider services have not recovered; alert remains active"
  archive_dir="${state_dir}/evidence/resolved"
  install -d -m 0700 "${archive_dir}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  destination="${archive_dir}/${timestamp}-${provider}-alert.json"
  test ! -e "${destination}" || fail "provider alert archive destination already exists"
  mv "${alert}" "${destination}"
  chmod 0600 "${destination}"
  check_ready
  echo "public-regtest-topology: archived recovered ${provider} alert as $(basename "${destination}")"
}

reconcile_warm_topology() {
  # restart: unless-stopped does not order network_mode dependencies after a
  # host reboot. Reconcile every durable service in dependency order so a
  # provider that raced its Bitcoin network namespace is started again before
  # the warm readiness wait.
  compose up --detach bitcoin-a bitcoin-b relay-a-postgres relay-b-postgres \
    provider-a-postgres provider-b-postgres
  compose up --detach relay-a relay-b cln-provider-a cln-provider-b \
    alert-sink-a alert-sink-b
  compose up --detach bitcoin-a-rpc-forwarder bitcoin-b-rpc-forwarder \
    wallet-gateway cln-wallet
  compose up --detach provider-a provider-b provider-a-egress provider-b-egress
  compose up --detach relay-a-public relay-b-public
}

start_topology() {
  initialize
  require_owned_state
  require_commands docker jq python3
  local pricing_changed=false
  if reconcile_public_provider_pricing; then pricing_changed=true; fi
  docker info >/dev/null 2>&1 || fail "Docker is unavailable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable"
  compose config --quiet
  if test -f "${manifest}" && test -n "$(compose ps --services --status running)"; then
    if test "${pricing_changed}" = true; then
      compose stop provider-a provider-b
      sleep 1
      compose up --detach --force-recreate provider-a provider-b
    fi
    reconcile_warm_topology
    bootstrap
    wait_for "existing persistent topology" readiness_probe
    check_ready
    return
  fi
  compose build bitcoin-a bitcoin-b relay-a relay-b cln-provider-a cln-provider-b \
    cln-wallet provider-a provider-b alert-sink-a alert-sink-b provider-a-egress \
    provider-b-egress bitcoin-a-rpc-forwarder bitcoin-b-rpc-forwarder wallet-gateway \
    relay-a-public relay-b-public wallet-driver
  compose up --detach bitcoin-a bitcoin-b relay-a-postgres relay-b-postgres \
    provider-a-postgres provider-b-postgres
  compose up --detach relay-a relay-b cln-provider-a cln-provider-b \
    alert-sink-a alert-sink-b
  compose up --detach bitcoin-a-rpc-forwarder bitcoin-b-rpc-forwarder wallet-gateway cln-wallet
  bootstrap
  compose up --detach provider-a provider-b provider-a-egress provider-b-egress
  compose up --detach relay-a-public relay-b-public
  wait_for "provider A" provider_ready provider-a 9091
  wait_for "provider B" provider_ready provider-b 9092
  check_ready
}

validate_config() {
  require_owned_state
  require_commands docker
  compose config --quiet
  local rendered
  rendered="$(compose config)"
  if grep -Eq '0\.0\.0\.0:[0-9]+:1808[01]' <<<"${rendered}"; then
    fail "plain relay port is not loopback-bound"
  fi
  if grep -Eq 'published:.*(18443|5432|909[12]|1984[678])' <<<"${rendered}"; then
    fail "private RPC, database, health, or Lightning port is published"
  fi
  echo "public-regtest-topology: Compose configuration passed"
}

restart_service() {
  require_owned_state
  local service="${1:-}"
  case "${service}" in
    relay-a|relay-b|provider-a|provider-b|bitcoin-a|bitcoin-b|cln-provider-a|cln-provider-b|cln-wallet)
      ;;
    *) fail "restart service is not allowlisted" ;;
  esac
  case "${service}" in
    bitcoin-a)
      compose stop provider-a provider-a-egress relay-a cln-provider-a \
        alert-sink-a bitcoin-a-rpc-forwarder
      compose up --detach --force-recreate bitcoin-a
      compose up --detach --force-recreate relay-a cln-provider-a alert-sink-a \
        bitcoin-a-rpc-forwarder
      sleep 1
      compose up --detach --force-recreate provider-a provider-a-egress
      ;;
    bitcoin-b)
      compose stop provider-b provider-b-egress relay-b cln-provider-b \
        alert-sink-b bitcoin-b-rpc-forwarder
      compose up --detach --force-recreate bitcoin-b
      compose up --detach --force-recreate relay-b cln-provider-b alert-sink-b \
        bitcoin-b-rpc-forwarder
      sleep 1
      compose up --detach --force-recreate provider-b provider-b-egress
      ;;
    provider-a|provider-b)
      # Graceful shutdown publishes a `paused` replaceable head. Keep the new
      # `active` head in a later Nostr second so the relay's equal-time event-ID
      # tie-break cannot retain the shutdown state.
      compose stop "${service}"
      sleep 1
      compose up --detach --force-recreate "${service}"
      ;;
    *)
      compose up --detach --force-recreate "${service}"
      ;;
  esac
  if test "${service}" = bitcoin-a; then
    ensure_existing_miner_wallet
  fi
  reconnect_lightning_peers
  wait_for "topology after ${service} restart" readiness_probe
  check_ready
}

backup_topology() {
  require_owned_state
  require_commands docker tar
  local destination="${1:-}"
  case "${destination}" in
    /*) ;;
    *) fail "backup destination must be absolute" ;;
  esac
  test ! -e "${destination}" || fail "backup destination already exists"
  if test -n "$(compose ps --services --status running)"; then
    fail "backup requires a stopped topology; run down first"
  fi
  install -d -m 0700 "${destination}" "${destination}/volumes"
  tar -C "${state_dir}" -czf "${destination}/private-state.tgz" .
  chmod 0600 "${destination}/private-state.tgz"
  local volume full_volume
  while IFS= read -r volume; do
    test -n "${volume}" || continue
    full_volume="$(project_name)_${volume}"
    docker volume inspect "${full_volume}" >/dev/null
    docker run --rm \
      --mount "type=volume,src=${full_volume},dst=/source,readonly" \
      --mount "type=bind,src=${destination}/volumes,dst=/backup" \
      "${postgres_image}" tar -C /source -czf "/backup/${volume}.tgz" .
    chmod 0600 "${destination}/volumes/${volume}.tgz"
  done < <(compose config --volumes)
  cp "${marker}" "${destination}/ownership.json"
  chmod 0600 "${destination}/ownership.json"
  echo "public-regtest-topology: offline backup ${destination}"
}

stop_topology() {
  require_owned_state
  compose down --remove-orphans
  echo "public-regtest-topology: stopped; named volumes and private state retained"
}

reset_topology() {
  require_owned_state
  test "${1:-}" = CONFIRM_PUBLIC_REGTEST_RESET || fail "reset confirmation token is required"
  local repository
  repository="$(pwd -P)"
  compose down --volumes --remove-orphans
  python3 - "${state_dir}" "${marker}" "${repository}" <<'PY'
import json, os, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
value = json.loads(marker.read_text(encoding="utf-8"))
if (
    value.get("schema") != "openagents.immortal.public-regtest-owner.v1"
    or value.get("repository") != sys.argv[3]
    or root.is_symlink()
    or root == pathlib.Path("/")
):
    raise SystemExit("owned reset boundary changed")
shutil.rmtree(root)
PY
  echo "public-regtest-topology: removed owned containers, volumes, and ${state_dir}"
}

command="${1:-}"
case "${command}" in
  init) test "$#" -eq 1 || fail "init takes no arguments"; initialize ;;
  config) test "$#" -eq 1 || fail "config takes no arguments"; validate_config ;;
  up) test "$#" -eq 1 || fail "up takes no arguments"; start_topology ;;
  ready) test "$#" -eq 1 || fail "ready takes no arguments"; check_ready ;;
  status) test "$#" -eq 1 || fail "status takes no arguments"; check_ready >/dev/null; cat "${manifest}" ;;
  restart) test "$#" -eq 2 || fail "restart requires one service"; restart_service "$2" ;;
  resolve-alert) test "$#" -eq 3 || fail "resolve-alert requires provider and confirmation"; resolve_provider_alert "$2" "$3" ;;
  backup) test "$#" -eq 2 || fail "backup requires one destination"; backup_topology "$2" ;;
  down) test "$#" -eq 1 || fail "down takes no arguments"; stop_topology ;;
  reset) test "$#" -eq 2 || fail "reset requires confirmation"; reset_topology "$2" ;;
  contract) test "$#" -eq 1 || fail "contract takes no arguments"; cat "${fixture}" ;;
  help|-h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
