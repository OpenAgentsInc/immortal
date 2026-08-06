#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

support_dir="scripts/support/provider-funded"
compose_file="${support_dir}/compose.yaml"
manifest_file="tests/fixtures/provider/funded-smoke-v1.json"
checkpoint_manifest_file="tests/fixtures/lab/funded-checkpoints-v1.json"
matrix_manifest_file="tests/fixtures/lab/funded-matrix-v1.json"
postgres_preflight_image="postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
private_root=""
project_name=""
compose_ready=false
compose_prefix=()
container_runtime=()
compose_runtime=""
current_phase=initialization
restart_at="${IMMORTAL_PROVIDER_FUNDED_RESTART_AT:-}"
injection="${IMMORTAL_PROVIDER_FUNDED_INJECTION:-}"
inject_at="${IMMORTAL_PROVIDER_FUNDED_INJECT_AT:-}"
driver_outcome=complete
expected_driver_error=""
injection_timeout_seconds="${IMMORTAL_PROVIDER_FUNDED_INJECTION_TIMEOUT_SECONDS:-300}"
lightning_rail="${IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL:-cln}"
shadow_reference_origin="${IMMORTAL_PROVIDER_FUNDED_SHADOW_REFERENCE_ORIGIN:-}"
shadow_output="${IMMORTAL_PROVIDER_FUNDED_SHADOW_OUTPUT:-}"
if { test -n "${shadow_reference_origin}" && test -z "${shadow_output}"; } \
  || { test -z "${shadow_reference_origin}" && test -n "${shadow_output}"; }; then
  echo "test-provider-funded: shadow reference and output must be configured together" >&2
  exit 1
fi
boltz_publish_host="${IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST:-127.0.0.1}"
provider_service=provider
if test "${lightning_rail}" = lnd; then
  provider_service=provider-lnd
elif test "${lightning_rail}" != cln; then
  echo "test-provider-funded: Lightning rail must be cln or lnd" >&2
  exit 1
fi

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test "${exit_status}" -ne 0; then
    echo "test-provider-funded: failed during ${current_phase}" >&2
  fi
  if test "${compose_ready}" = true; then
    if ! "${compose_prefix[@]}" logs --no-color >"${private_root}/runtime.log" 2>&1; then
      echo "test-provider-funded: could not capture private runtime diagnostics" >&2
    fi
    if ! "${compose_prefix[@]}" down --volumes --remove-orphans --rmi local >/dev/null 2>&1; then
      echo "test-provider-funded: disposable container cleanup failed" >&2
      exit_status=1
    fi
  fi
  if test -n "${private_root}"; then
    case "$(basename "${private_root}")" in
      immortal-provider-funded.*) ;;
      *)
        echo "test-provider-funded: refused to remove an unexpected temporary directory" >&2
        exit 1
        ;;
    esac
    if ! rm -rf -- "${private_root}"; then
      echo "test-provider-funded: private temporary directory cleanup failed" >&2
      exit_status=1
    fi
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

umask 077
if ! python3 - "${boltz_publish_host}" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
private_networks = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
if (
    address.version != 4
    or address.is_unspecified
    or address.is_multicast
    or address.is_reserved
    or not (address.is_loopback or any(address in network for network in private_networks))
):
    raise SystemExit(1)
PY
then
  echo "test-provider-funded: Boltz publish host must be a non-wildcard loopback or RFC1918 IPv4 address" >&2
  exit 1
fi
repository_physical_path="$(CDPATH= cd -- . && pwd -P)"
dedicated_private_root_parent="${IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT:-}"
if test -n "${dedicated_private_root_parent}"; then
  private_root_parent="${dedicated_private_root_parent}"
else
  private_root_parent="${TMPDIR:-/tmp}"
fi
case "${private_root_parent}" in
  /*) ;;
  *)
    echo "test-provider-funded: private root parent must be absolute" >&2
    exit 1
    ;;
esac
if ! test -d "${private_root_parent}" \
  || ! test -w "${private_root_parent}" \
  || ! test -x "${private_root_parent}"; then
  echo "test-provider-funded: private root parent must exist and be writable/searchable" >&2
  exit 1
fi
private_root_parent_physical="$(CDPATH= cd -- "${private_root_parent}" && pwd -P)"
case "${private_root_parent_physical}" in
  "${repository_physical_path}"|"${repository_physical_path}"/*)
    echo "test-provider-funded: private root parent must be outside the repository" >&2
    exit 1
    ;;
esac
receipt_physical_path=""
if test -n "${IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY:-}"; then
  if ! test -d "${IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY}"; then
    echo "test-provider-funded: Debian receipt directory is unavailable" >&2
    exit 1
  fi
  receipt_physical_path="$(CDPATH= cd -- "${IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY}" && pwd -P)"
  case "${private_root_parent_physical}" in
    "${receipt_physical_path}"|"${receipt_physical_path}"/*)
      echo "test-provider-funded: private root parent must be outside the Debian receipt mount" >&2
      exit 1
      ;;
  esac
fi
if test -n "${dedicated_private_root_parent}"; then
  global_tmpdir="${TMPDIR:-/tmp}"
  case "${global_tmpdir}" in
    /*) ;;
    *)
      echo "test-provider-funded: global TMPDIR must be absolute when a dedicated private parent is set" >&2
      exit 1
      ;;
  esac
  if ! test -d "${global_tmpdir}"; then
    echo "test-provider-funded: global TMPDIR is unavailable" >&2
    exit 1
  fi
  global_tmpdir_physical="$(CDPATH= cd -- "${global_tmpdir}" && pwd -P)"
  case "${global_tmpdir_physical}" in
    "${private_root_parent_physical}"|"${private_root_parent_physical}"/*)
      echo "test-provider-funded: global TMPDIR must not be inside the dedicated private root parent" >&2
      exit 1
      ;;
  esac
fi
unset IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT
private_root="$(mktemp -d "${private_root_parent_physical}/immortal-provider-funded.XXXXXX")"
private_physical_path="$(CDPATH= cd -- "${private_root}" && pwd -P)"
case "${private_physical_path}" in
  "${private_root_parent_physical}"/*) ;;
  *)
    echo "test-provider-funded: private runtime directory is outside its parent" >&2
    rmdir "${private_root}" || true
    exit 1
    ;;
esac
if ! chmod 0700 "${private_root}"; then
  echo "test-provider-funded: could not set private runtime directory permissions" >&2
  rmdir "${private_root}" || true
  exit 1
fi
if stat --version >/dev/null 2>&1; then
  private_root_mode="$(stat -c '%a' "${private_root}")"
else
  private_root_mode="$(stat -f '%Lp' "${private_root}")"
fi
if test "${private_root_mode}" != 700; then
  echo "test-provider-funded: private runtime directory permissions are not 0700" >&2
  rmdir "${private_root}" || true
  exit 1
fi
if test -n "${receipt_physical_path}"; then
  case "${private_physical_path}" in
    "${receipt_physical_path}"|"${receipt_physical_path}"/*)
      echo "test-provider-funded: private runtime directory is inside the Debian receipt mount" >&2
      exit 1
      ;;
  esac
fi
if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  container_runtime=(docker)
  compose_runtime=docker
elif podman info >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  container_runtime=(podman)
  compose_runtime=podman
else
  echo "test-provider-funded: start Docker Desktop or a Podman compose service" >&2
  exit 1
fi
current_phase=private-root-bind-preflight
if ! "${container_runtime[@]}" run --rm \
  --mount "type=bind,src=${private_root},dst=/run/immortal-private,readonly" \
  "${postgres_preflight_image}" true >/dev/null; then
  echo "test-provider-funded: container runtime cannot read the private root at its exact path" >&2
  exit 1
fi
mkdir -m 0700 "${private_root}/evidence" \
  "${private_root}/evidence/chain" \
  "${private_root}/evidence/lightning" \
  "${private_root}/state" \
  "${private_root}/lnd-credentials"
for credential_name in tls.cert readonly.macaroon invoice.macaroon router.macaroon; do
  : >"${private_root}/lnd-credentials/${credential_name}"
done
chmod 0600 "${private_root}/lnd-credentials"/*

random_hex() {
  local byte_count="$1"
  LC_ALL=C od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

if test -n "${restart_at}" && test -n "${injection}"; then
  echo "test-provider-funded: restart and injection cases are mutually exclusive" >&2
  exit 1
fi
if [[ ! "${injection_timeout_seconds}" =~ ^[0-9]{1,4}$ ]] \
  || test "${injection_timeout_seconds}" -lt 1 \
  || test "${injection_timeout_seconds}" -gt 3600; then
  echo "test-provider-funded: injection timeout is outside 1..=3600 seconds" >&2
  exit 1
fi
if test -z "${restart_at}" && test -z "${injection}"; then
  restart_at="$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
print(manifest["default_case"]["restart_at"])
' "${matrix_manifest_file}")"
fi
if ! node --experimental-websocket -e 'if (typeof WebSocket !== "function") process.exit(1)'; then
  echo "test-provider-funded: Node must expose its built-in WebSocket with --experimental-websocket" >&2
  exit 1
fi

control_metadata="$(python3 -c '
import json, sys

checkpoint_path, matrix_path, restart_at, injection, inject_at = sys.argv[1:]
with open(checkpoint_path, encoding="utf-8") as source:
    checkpoints = json.load(source)
with open(matrix_path, encoding="utf-8") as source:
    matrix = json.load(source)

restartable = {
    f"{journey}:{label}"
    for journey, contract in checkpoints.get("journeys", {}).items()
    for label in contract.get("restartable", [])
}
injection_contracts = {
    contract.get("name"): contract
    for contract in checkpoints.get("injections", [])
}
matrix_injections = matrix.get("injection_cases", {})

if restart_at:
    if inject_at:
        raise SystemExit("restart cases cannot set an injection checkpoint")
    if restart_at not in restartable:
        raise SystemExit("restart checkpoint is absent from the checkpoint manifest")
    print("complete\t")
elif injection:
    contract = injection_contracts.get(injection)
    matrix_case = matrix_injections.get(injection)
    if contract is None or matrix_case is None:
        raise SystemExit("injection is absent from the checkpoint or matrix manifest")
    if contract.get("owner") == "external_script":
        if inject_at not in restartable:
            raise SystemExit("external injection requires a restartable checkpoint")
    elif inject_at:
        raise SystemExit("harness-owned injection cannot set an external checkpoint")
    outcome = matrix_case.get("driver_outcome")
    error = matrix_case.get("expected_driver_error", "")
    if outcome not in {"complete", "expected_rejection"}:
        raise SystemExit("matrix injection has an unsupported driver outcome")
    if outcome == "expected_rejection" and not error:
        raise SystemExit("rejection case has no expected driver error")
    if any(character in error for character in "\t\r\n"):
        raise SystemExit("expected driver error is not one bounded line")
    print(f"{outcome}\t{error}")
else:
    raise SystemExit("no funded smoke control was selected")
' "${checkpoint_manifest_file}" "${matrix_manifest_file}" \
  "${restart_at}" "${injection}" "${inject_at}")" || {
  echo "test-provider-funded: invalid matrix control" >&2
  exit 1
}
IFS=$'\t' read -r driver_outcome expected_driver_error <<<"${control_metadata}"

confirmation_policy="$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
policy = manifest.get("confirmation_policy")
if not isinstance(policy, dict) or set(policy) != {
    "minimum_confirmations", "reorg_safety_blocks", "terminal_confirmations"
}:
    raise SystemExit("funded-smoke confirmation policy is invalid")
minimum = policy["minimum_confirmations"]
reorg = policy["reorg_safety_blocks"]
terminal = policy["terminal_confirmations"]
if (
    isinstance(minimum, bool)
    or isinstance(reorg, bool)
    or isinstance(terminal, bool)
    or not all(isinstance(value, int) for value in (minimum, reorg, terminal))
    or not 1 <= minimum <= 144
    or not 0 <= reorg <= 144
    or terminal != minimum + reorg
):
    raise SystemExit("funded-smoke confirmation policy is inconsistent")
print(minimum, reorg, terminal)
' "${manifest_file}")"
read -r minimum_confirmations reorg_safety_blocks terminal_confirmations \
  <<<"${confirmation_policy}"

project_name="immortal-provider-funded-$(random_hex 6)"
bitcoin_rpc_password="$(random_hex 32)"
provider_postgres_password="$(random_hex 32)"
relay_postgres_password="$(random_hex 32)"
provider_identity_secret="$(random_hex 32)"
provider_wallet_seed="$(random_hex 32)"
client_wallet_seed="$(random_hex 32)"
boltz_conformance_sha256="$(
  cargo run --locked --quiet -p immortal-provider -- contract |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["operations"]["boltz_compatibility"]["conformance_sha256"])'
)"

printf '%s\n' "${provider_postgres_password}" >"${private_root}/provider-postgres-password"
printf '%s\n' "${relay_postgres_password}" >"${private_root}/relay-postgres-password"
printf '%s\n' "${provider_wallet_seed}" >"${private_root}/provider-wallet-seed"
printf '%s\n' "${client_wallet_seed}" >"${private_root}/client-wallet-seed"
chmod 0600 "${private_root}"/*-password "${private_root}"/*-seed

cat >"${private_root}/bitcoin.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
[regtest]
rpcbind=0.0.0.0
rpcallowip=0.0.0.0/0
rpcport=18443
rpcuser=immortal-smoke
rpcpassword=${bitcoin_rpc_password}
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
EOF

cat >"${private_root}/cln-provider.conf" <<EOF
network=regtest
lightning-dir=/root/.lightning
rpc-file=/rail-rpc/lightning-rpc
rpc-file-mode=0660
bitcoin-rpcconnect=bitcoin
bitcoin-rpcport=18443
bitcoin-rpcuser=immortal-smoke
bitcoin-rpcpassword=${bitcoin_rpc_password}
bind-addr=0.0.0.0:19846
announce-addr=cln-provider:19846
log-level=info
plugin=/usr/local/bin/hold
hold-grpc-port=-1
hold-expiry-deadline=3
EOF

cat >"${private_root}/cln-peer.conf" <<EOF
network=regtest
lightning-dir=/root/.lightning
rpc-file=/rail-rpc/lightning-rpc
rpc-file-mode=0660
bitcoin-rpcconnect=bitcoin
bitcoin-rpcport=18443
bitcoin-rpcuser=immortal-smoke
bitcoin-rpcpassword=${bitcoin_rpc_password}
bind-addr=0.0.0.0:19847
announce-addr=cln-peer:19847
log-level=info
EOF

cat >"${private_root}/lnd-provider.conf" <<EOF
[Application Options]
debuglevel=info
listen=0.0.0.0:19735
rpclisten=127.0.0.1:10009
restlisten=127.0.0.1:18081
noseedbackup=1
tlsextraip=127.0.0.1
protocol.wumbo-channels=1

[Bitcoin]
bitcoin.active=1
bitcoin.regtest=1
bitcoin.node=bitcoind

[Bitcoind]
bitcoind.rpchost=127.0.0.1:18443
bitcoind.rpcuser=immortal-smoke
bitcoind.rpcpass=${bitcoin_rpc_password}
bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333
EOF

cat >"${private_root}/relay.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_postgres_password}@relay-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18080
IMMORTAL_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF

cat >"${private_root}/provider.env" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${provider_postgres_password}@provider-postgres:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_PROVIDER_IDENTITY_SECRET=${provider_identity_secret}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=immortal-smoke
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${bitcoin_rpc_password}
IMMORTAL_PROVIDER_CLN_RPC_PATH=/rail/cln-provider/lightning-rpc
IMMORTAL_PROVIDER_WALLET_SEED_FILE=/run/immortal-private/provider-wallet-seed
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:9091
IMMORTAL_PROVIDER_ALERT_URL=http://127.0.0.1:19092/provider-alert
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=10
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=${minimum_confirmations}
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=${reorg_safety_blocks}
IMMORTAL_PROVIDER_SPREAD_BPS=100
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=600
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
EOF

cat >"${private_root}/provider-lnd.env" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${provider_postgres_password}@provider-postgres:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_PROVIDER_IDENTITY_SECRET=${provider_identity_secret}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=immortal-smoke
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${bitcoin_rpc_password}
IMMORTAL_PROVIDER_LIGHTNING_RAIL=lnd
IMMORTAL_PROVIDER_LND_HOST=127.0.0.1
IMMORTAL_PROVIDER_LND_PORT=18081
IMMORTAL_PROVIDER_LND_TLS_CERT_FILE=/run/immortal-lnd/tls.cert
IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE=/run/immortal-lnd/readonly.macaroon
IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE=/run/immortal-lnd/invoice.macaroon
IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE=/run/immortal-lnd/router.macaroon
IMMORTAL_PROVIDER_WALLET_SEED_FILE=/run/immortal-private/provider-wallet-seed
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:9091
IMMORTAL_PROVIDER_ALERT_URL=http://127.0.0.1:19092/provider-alert
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=10
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=${minimum_confirmations}
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=${reorg_safety_blocks}
IMMORTAL_PROVIDER_SPREAD_BPS=100
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=600
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
EOF

cat >"${private_root}/driver.env" <<EOF
IMMORTAL_PROVIDER_FUNDED_SMOKE_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_PROVIDER_FUNDED_SMOKE_PROVIDER_HEALTH_URL=http://127.0.0.1:9091/healthz
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_USER=immortal-smoke
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_PASSWORD=${bitcoin_rpc_password}
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLN_RPC_PATH=/rail/cln-peer/lightning-rpc
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLIENT_WALLET_SEED_FILE=/run/immortal-private/client-wallet-seed
IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE=/evidence/funded-smoke.json
IMMORTAL_PROVIDER_FUNDED_SMOKE_TERMINAL_CONFIRMATIONS=${terminal_confirmations}
IMMORTAL_LAB_STATE_DIR=/state
EOF

cat >"${private_root}/compose.env" <<EOF
IMMORTAL_PROVIDER_SMOKE_PRIVATE_DIR=${private_root}
IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST=${boltz_publish_host}
EOF
chmod 0600 "${private_root}"/*.conf "${private_root}"/*.env

if test "${compose_runtime}" = docker; then
  compose_prefix=(
    docker compose
    --env-file "${private_root}/compose.env"
    --file "${compose_file}"
    --project-name "${project_name}"
  )
elif test "${compose_runtime}" = podman; then
  compose_prefix=(
    podman compose
    --env-file "${private_root}/compose.env"
    --file "${compose_file}"
    --project-name "${project_name}"
  )
else
  echo "test-provider-funded: selected container runtime is unavailable" >&2
  exit 1
fi
compose_ready=true

compose() {
  "${compose_prefix[@]}" "$@"
}

wait_for() {
  local description="$1"
  shift
  for _ in $(seq 1 180); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "test-provider-funded: ${description} did not become ready" >&2
  return 1
}

bitcoin_cli() {
  compose exec -T bitcoin bitcoin-cli \
    -conf=/run/immortal-private/bitcoin.conf \
    -datadir=/var/lib/bitcoin \
    "$@"
}

cln_cli() {
  local service_name="$1"
  shift
  compose exec -T "${service_name}" lightning-cli \
    --network=regtest \
    --lightning-dir=/root/.lightning \
    --rpc-file=/rail-rpc/lightning-rpc \
    "$@"
}

lnd_cli() {
  compose exec -T lnd-provider lncli \
    --network=regtest \
    --lnddir=/root/.lnd \
    "$@"
}

lnd_wallet_ready() {
  local expected_height="$1"
  local actual_height
  actual_height="$(lnd_cli getinfo | json_field block_height)"
  if test "${actual_height}" -lt "${expected_height}"; then
    return 1
  fi
  lnd_cli walletbalance | python3 -c '
import json, sys
balance = json.load(sys.stdin).get("confirmed_balance", "0")
raise SystemExit(0 if int(balance) > 0 else 1)
'
}

lnd_channel_ready() {
  local peer_node_id="$1"
  lnd_cli listchannels | python3 -c '
import json, sys
peer = sys.argv[1]
channels = json.load(sys.stdin).get("channels", [])
raise SystemExit(0 if any(channel.get("remote_pubkey") == peer and channel.get("active") is True for channel in channels) else 1)
' "${peer_node_id}"
}

cln_channel_ready() {
  local peer_node_id="$1"
  cln_cli cln-provider listpeerchannels | python3 -c '
import json, sys
peer = sys.argv[1]
channels = json.load(sys.stdin).get("channels", [])
raise SystemExit(0 if any(channel.get("peer_id") == peer and channel.get("state") == "CHANNELD_NORMAL" for channel in channels) else 1)
' "${peer_node_id}"
}

cln_wallet_ready() {
  local service_name="$1"
  local expected_height="$2"
  local actual_height
  actual_height="$(cln_cli "${service_name}" getinfo | json_field blockheight)"
  if test "${actual_height}" -lt "${expected_height}"; then
    return 1
  fi
  cln_cli "${service_name}" listfunds | python3 -c '
import json, sys
outputs = json.load(sys.stdin).get("outputs", [])
raise SystemExit(0 if any(output.get("status") == "confirmed" for output in outputs) else 1)
'
}

json_field() {
  local field_name="$1"
  python3 -c 'import json,sys; value=json.load(sys.stdin); print(value[sys.argv[1]])' \
    "${field_name}"
}

wait_for_provider() {
  for _ in $(seq 1 180); do
    if compose exec -T "${provider_service}" /usr/bin/curl \
      --fail --silent --show-error http://127.0.0.1:9091/healthz \
      >/dev/null 2>&1; then
      return 0
    fi
    if ! compose ps --services --status running | grep -qx "${provider_service}"; then
      echo "test-provider-funded: funded provider daemon exited before readiness" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "test-provider-funded: funded provider daemon did not become ready" >&2
  return 1
}

wait_for_injection_request() {
  local request_file="$1"
  local maximum_attempts=$((injection_timeout_seconds * 5))
  local attempt
  for ((attempt = 0; attempt < maximum_attempts; attempt += 1)); do
    if test -f "${request_file}"; then
      return 0
    fi
    sleep 0.2
  done
  echo "test-provider-funded: funded injection request did not arrive" >&2
  return 1
}

assert_no_swap_rail_effects() {
  if ! bitcoin_cli getrawmempool | python3 -c '
import json, sys
transactions = json.load(sys.stdin)
raise SystemExit(0 if transactions == [] else 1)
'; then
    echo "test-provider-funded: rejected injection left a Bitcoin transaction in the mempool" >&2
    return 1
  fi
  if test "${lightning_rail}" = cln; then
    provider_payments="$(cln_cli cln-provider listpays)"
  else
    provider_payments="$(lnd_cli listpayments)"
  fi
  if ! python3 -c '
import json, sys
response = json.load(sys.stdin)
pays = response.get("pays", response.get("payments", []))
raise SystemExit(0 if pays == [] else 1)
' <<<"${provider_payments}"; then
    echo "test-provider-funded: rejected injection started a provider Lightning payment" >&2
    return 1
  fi
  if test -e "${private_root}/state/funded-checkpoint.json"; then
    echo "test-provider-funded: rejected injection crossed a funded checkpoint" >&2
    return 1
  fi
}

acknowledge_external_injection() {
  local request_file="${private_root}/state/funded-injection.json"
  local acknowledgement_file="${private_root}/state/funded-continue"
  local request_metadata
  local request_run_id
  local request_sha256
  if ! wait_for_injection_request "${request_file}"; then
    return 1
  fi

  request_metadata="$(python3 - "${request_file}" "${injection}" "${inject_at}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

request_path = pathlib.Path(sys.argv[1])
expected_injection = sys.argv[2]
expected_checkpoint = sys.argv[3]
request_bytes = request_path.read_bytes()
if not request_bytes or len(request_bytes) > 4096:
    raise SystemExit("injection request is empty or unbounded")
if stat.S_IMODE(request_path.stat().st_mode) != 0o600:
    raise SystemExit("injection request is not mode 0600")
request = json.loads(request_bytes)
if set(request) != {
    "schema", "run_id", "journey", "checkpoint", "injection", "requested_at"
}:
    raise SystemExit("injection request has another shape")
if (
    request["schema"] != "openagents.immortal.lab-injection.v1"
    or request["checkpoint"] != expected_checkpoint
    or request["injection"] != expected_injection
    or request["journey"] != expected_checkpoint.split(":", 1)[0]
    or not isinstance(request["requested_at"], int)
):
    raise SystemExit("injection request does not bind the selected case")
run_id = request["run_id"]
if (
    not isinstance(run_id, str)
    or not 1 <= len(run_id) <= 128
    or any(not (character.isascii() and (character.isalnum() or character in "-_")) for character in run_id)
):
    raise SystemExit("injection request has an invalid run id")
print(run_id, hashlib.sha256(request_bytes).hexdigest(), sep="\t")
PY
)" || {
    echo "test-provider-funded: funded injection request failed validation" >&2
    return 1
  }
  IFS=$'\t' read -r request_run_id request_sha256 <<<"${request_metadata}"

  case "${injection}" in
    relay_loss)
      current_phase=relay-loss-injection
      compose stop relay >/dev/null
      if compose ps --services --status running | grep -qx relay; then
        echo "test-provider-funded: relay remained running during relay-loss injection" >&2
        return 1
      fi
      compose up --detach relay >/dev/null
      wait_for "restored relay" compose run --rm --no-deps --entrypoint /usr/bin/curl "${provider_service}" \
        --fail --silent --show-error http://127.0.0.1:18080/health
      compose up --detach --force-recreate "${provider_service}" >/dev/null
      wait_for_provider
      ;;
    provider_crash)
      current_phase=provider-crash-injection
      compose kill "${provider_service}" >/dev/null
      if compose ps --services --status running | grep -qx "${provider_service}"; then
        echo "test-provider-funded: provider remained running after the crash injection" >&2
        return 1
      fi
      compose up --detach "${provider_service}" >/dev/null
      wait_for_provider
      ;;
    *)
      echo "test-provider-funded: external acknowledgement requested for another injection" >&2
      return 1
      ;;
  esac

  current_phase=injection-acknowledgement
  python3 - "${request_file}" "${acknowledgement_file}" \
    "${request_run_id}" "${request_sha256}" "${injection}" "${inject_at}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

request_path = pathlib.Path(sys.argv[1])
acknowledgement_path = pathlib.Path(sys.argv[2])
expected_run_id = sys.argv[3]
expected_sha256 = sys.argv[4]
expected_injection = sys.argv[5]
expected_checkpoint = sys.argv[6]
request_bytes = request_path.read_bytes()
if hashlib.sha256(request_bytes).hexdigest() != expected_sha256:
    raise SystemExit("injection request changed during process recovery")
request = json.loads(request_bytes)
if (
    request["schema"] != "openagents.immortal.lab-injection.v1"
    or request["run_id"] != expected_run_id
    or request["checkpoint"] != expected_checkpoint
    or request["injection"] != expected_injection
):
    raise SystemExit("injection request no longer binds the selected case")
acknowledgement = {
    "schema": "openagents.immortal.lab-injection-ack.v1",
    "run_id": expected_run_id,
    "checkpoint": expected_checkpoint,
    "injection": expected_injection,
    "restored": True,
}
encoded = json.dumps(acknowledgement, separators=(",", ":")).encode()
temporary_path = acknowledgement_path.with_name(acknowledgement_path.name + ".tmp")
descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary_path, acknowledgement_path)
    directory_descriptor = os.open(acknowledgement_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
except BaseException:
    try:
        temporary_path.unlink()
    except FileNotFoundError:
        pass
    raise
PY
}

if ! compose config --quiet; then
  echo "test-provider-funded: disposable compose configuration is invalid" >&2
  exit 1
fi
current_phase=image-build
build_services=(bitcoin cln-peer relay driver alert-sink "${provider_service}")
if test "${lightning_rail}" = cln; then
  build_services+=(cln-provider)
fi
if ! compose build "${build_services[@]}" >"${private_root}/build.log" 2>&1; then
  echo "test-provider-funded: disposable images did not build" >&2
  exit 1
fi
current_phase=base-startup
if ! compose up --detach bitcoin relay-postgres provider-postgres \
  >"${private_root}/startup.log" 2>&1; then
  echo "test-provider-funded: base rail services did not start" >&2
  exit 1
fi

wait_for "provider Postgres" compose exec -T provider-postgres \
  pg_isready -U immortal_provider -d immortal_provider
wait_for "relay Postgres" compose exec -T relay-postgres \
  pg_isready -U immortal_relay -d immortal_relay
wait_for "Bitcoin Core regtest" bitcoin_cli getblockchaininfo
boltz_bind_address="$(compose exec -T bitcoin cat /etc/hosts | python3 -c '
import ipaddress, sys
for line in sys.stdin:
    fields = line.split()
    if not fields:
        continue
    try:
        address = ipaddress.ip_address(fields[0])
    except ValueError:
        continue
    if address.version == 4 and address.is_private and not address.is_loopback:
        print(address)
        raise SystemExit(0)
raise SystemExit("shared provider namespace has no private IPv4 address")
')"
for provider_environment in provider.env provider-lnd.env; do
  cat >>"${private_root}/${provider_environment}" <<EOF
IMMORTAL_PROVIDER_BOLTZ_BIND=${boltz_bind_address}:19093
IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256=${boltz_conformance_sha256}
IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN=http://127.0.0.1
EOF
done
current_phase=rail-startup
lightning_services=(cln-peer)
if test "${lightning_rail}" = cln; then
  lightning_services+=(cln-provider)
else
  lightning_services+=(lnd-provider)
fi
if ! compose up --detach relay "${lightning_services[@]}" alert-sink \
  >>"${private_root}/startup.log" 2>&1; then
  echo "test-provider-funded: relay and Lightning services did not start" >&2
  exit 1
fi
wait_for "peer CLN" cln_cli cln-peer getinfo
if test "${lightning_rail}" = cln; then
  wait_for "provider CLN" cln_cli cln-provider getinfo
else
  wait_for "provider LND" lnd_cli getinfo
  compose cp "lnd-provider:/root/.lnd/tls.cert" \
    "${private_root}/lnd-credentials/tls.cert" >/dev/null
  compose cp "lnd-provider:/root/.lnd/data/chain/bitcoin/regtest/readonly.macaroon" \
    "${private_root}/lnd-credentials/readonly.macaroon" >/dev/null
  compose cp "lnd-provider:/root/.lnd/data/chain/bitcoin/regtest/invoices.macaroon" \
    "${private_root}/lnd-credentials/invoice.macaroon" >/dev/null
  compose cp "lnd-provider:/root/.lnd/data/chain/bitcoin/regtest/router.macaroon" \
    "${private_root}/lnd-credentials/router.macaroon" >/dev/null
  chmod 0600 "${private_root}/lnd-credentials"/*
fi
wait_for "relay" compose run --rm --no-deps --entrypoint /usr/bin/curl "${provider_service}" \
  --fail --silent --show-error http://127.0.0.1:18080/health
wait_for "provider alert sink" compose exec -T alert-sink python3 -c '
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:19092/healthz", timeout=2) as response:
    raise SystemExit(0 if response.status == 200 and response.read() == b"ready\n" else 1)
'

if test "${lightning_rail}" = cln; then
  for method_name in holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice; do
    if ! cln_cli cln-provider help "${method_name}" >/dev/null 2>&1; then
      echo "test-provider-funded: provider CLN hold-plugin capability probe failed" >&2
      exit 1
    fi
  done
fi

current_phase=rail-funding
bitcoin_cli createwallet smoke-miner >/dev/null
miner_address="$(bitcoin_cli -rpcwallet=smoke-miner getnewaddress)"
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 110 "${miner_address}" >/dev/null

current_phase=rail-funding-cln-addresses
peer_cln_address="$(cln_cli cln-peer newaddr bech32 | json_field bech32)"
if test "${lightning_rail}" = cln; then
  provider_lightning_address="$(cln_cli cln-provider newaddr bech32 | json_field bech32)"
else
  provider_lightning_address="$(lnd_cli newaddress p2wkh | json_field address)"
fi
current_phase=rail-funding-cln-wallets
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${provider_lightning_address}" 3.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${peer_cln_address}" 1.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null
chain_height="$(bitcoin_cli getblockcount)"
wait_for "peer CLN wallet" cln_wallet_ready cln-peer "${chain_height}"
if test "${lightning_rail}" = cln; then
  wait_for "provider CLN wallet" cln_wallet_ready cln-provider "${chain_height}"
else
  wait_for "provider LND wallet" lnd_wallet_ready "${chain_height}"
fi

current_phase=rail-funding-connect
peer_node_id="$(cln_cli cln-peer getinfo | json_field id)"
current_phase=rail-funding-channel
if test "${lightning_rail}" = cln; then
  cln_cli cln-provider connect "${peer_node_id}@cln-peer:19847" >/dev/null
  cln_cli cln-provider -k fundchannel \
    id="${peer_node_id}" \
    amount=2000000sat \
    feerate=253perkw \
    announce=false \
    push_msat=1000000000msat >/dev/null
else
  lnd_cli connect "${peer_node_id}@cln-peer:19847" >/dev/null
  lnd_cli openchannel --private --min_confs=1 --sat_per_vbyte=2 \
    --push_amt=1000000 "${peer_node_id}" 2000000 >/dev/null
fi
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null

current_phase=rail-funding-channel-readiness
if test "${lightning_rail}" = cln; then
  wait_for "balanced CLN channel" cln_channel_ready "${peer_node_id}"
else
  wait_for "balanced LND channel" lnd_channel_ready "${peer_node_id}"
fi

current_phase=provider-funding
provider_address_log="${private_root}/provider-address.log"
if ! compose run --rm --no-deps "${provider_service}" address \
  >"${provider_address_log}" 2>"${private_root}/provider-address-error.log"; then
  echo "test-provider-funded: provider address command failed" >&2
  exit 1
fi
provider_address="$(tr -d '\r\n' <"${provider_address_log}")"
if [[ ! "${provider_address}" =~ ^bcrt1p[023456789ac-hj-np-z]{58}$ ]]; then
  echo "test-provider-funded: provider address command returned a non-regtest address" >&2
  exit 1
fi
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${provider_address}" 1.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 2 "${miner_address}" >/dev/null

current_phase=provider-startup
if ! compose up --detach "${provider_service}" >>"${private_root}/startup.log" 2>&1; then
  echo "test-provider-funded: provider container did not start" >&2
  exit 1
fi
wait_for_provider
compose exec -T "${provider_service}" /usr/bin/curl --fail --silent --show-error \
  http://127.0.0.1:9091/metrics >"${private_root}/evidence/metrics-before.txt"
if ! grep -qx 'immortal_provider_ready 1' "${private_root}/evidence/metrics-before.txt"; then
  echo "test-provider-funded: provider metrics did not report readiness" >&2
  exit 1
fi

if test -n "${injection}"; then
  driver_arguments=(
    run --rm --no-deps
    --env "IMMORTAL_LAB_INJECTION=${injection}"
  )
  if test -n "${inject_at}"; then
    driver_arguments+=(
      --env "IMMORTAL_LAB_INJECT_AT=${inject_at}"
      --env "IMMORTAL_LAB_INJECTION_TIMEOUT_SECONDS=${injection_timeout_seconds}"
    )
  fi
  driver_arguments+=(driver)

  if test "${driver_outcome}" = expected_rejection; then
    current_phase=harness-injection-rejection
    assert_no_swap_rail_effects
    if compose "${driver_arguments[@]}" >"${private_root}/driver-injection.log" 2>&1; then
      echo "test-provider-funded: harness accepted a rejection injection" >&2
      exit 1
    fi
    if ! grep -F -- "${expected_driver_error}" "${private_root}/driver-injection.log" >/dev/null; then
      echo "test-provider-funded: harness returned another injection refusal" >&2
      exit 1
    fi
    assert_no_swap_rail_effects
    current_phase=complete
    echo "test-provider-funded: ${injection} rejected before swap rail effects"
    exit 0
  fi

  if test -n "${inject_at}"; then
    current_phase=harness-external-injection
    compose "${driver_arguments[@]}" >"${private_root}/driver-injection.log" 2>&1 &
    driver_process=$!
    if ! acknowledge_external_injection; then
      if kill -TERM "${driver_process}" >/dev/null 2>&1; then
        if wait "${driver_process}" >/dev/null 2>&1; then
          echo "test-provider-funded: driver exited cleanly while fault recovery failed" >&2
        fi
      elif wait "${driver_process}" >/dev/null 2>&1; then
        echo "test-provider-funded: driver exited before fault recovery failed" >&2
      fi
      exit 1
    fi
    if ! wait "${driver_process}"; then
      echo "test-provider-funded: driver failed after the acknowledged external injection" >&2
      exit 1
    fi
  else
    current_phase=harness-injection
    if ! compose "${driver_arguments[@]}" >"${private_root}/driver-injection.log" 2>&1; then
      echo "test-provider-funded: funded driver failed during the bounded injection" >&2
      exit 1
    fi
  fi
else
  current_phase=harness-controlled-stop
  if compose run --rm --no-deps \
    --env "IMMORTAL_LAB_STOP_AFTER=${restart_at}" \
    driver >"${private_root}/driver-stop.log" 2>&1; then
    echo "test-provider-funded: harness ignored the controlled stop" >&2
    exit 1
  fi
  if ! python3 -c '
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
journey, label = sys.argv[2].split(":", 1)
with (state / "funded-checkpoint.json").open(encoding="utf-8") as source:
    checkpoint = json.load(source)
if checkpoint.get("journey") != journey:
    raise SystemExit("controlled-stop checkpoint has another journey")
if checkpoint.get("label") != label:
    raise SystemExit("controlled-stop checkpoint has another label")
if checkpoint.get("safe_to_stop") is not True:
    raise SystemExit("controlled-stop checkpoint is not money-safe")
snapshot = state / f"funded-{journey}-session.json"
if not snapshot.is_file():
    raise SystemExit("controlled-stop session snapshot is absent")
' "${private_root}/state" "${restart_at}"; then
    echo "test-provider-funded: harness did not persist its safe restart boundary" >&2
    exit 1
  fi

  current_phase=harness-restart
  if ! compose run --rm --no-deps driver \
    >"${private_root}/driver.log" 2>&1; then
    echo "test-provider-funded: external funded-swap driver failed" >&2
    exit 1
  fi
fi

current_phase=boltz-provider-process-gate
boltz_provider_container_url="http://${boltz_bind_address}:19093"
wait_for "Boltz provider compatibility listener inside the smoke network" \
  compose exec -T "${provider_service}" /usr/bin/curl \
    --fail --silent --show-error "${boltz_provider_container_url}/v2/version"
if ! boltz_published_endpoint="$(compose port bitcoin 19093)"; then
  echo "test-provider-funded: could not resolve the Boltz published endpoint" >&2
  exit 1
fi
case "${boltz_published_endpoint}" in
  "${boltz_publish_host}":*)
    boltz_published_port="${boltz_published_endpoint#*:}"
    ;;
  *)
    echo "test-provider-funded: Boltz published endpoint has another host" >&2
    exit 1
    ;;
esac
if [[ ! "${boltz_published_port}" =~ ^[0-9]{1,5}$ ]] \
  || test "${boltz_published_port}" -lt 1 \
  || test "${boltz_published_port}" -gt 65535; then
  echo "test-provider-funded: Boltz published endpoint has an invalid port" >&2
  exit 1
fi
boltz_provider_url="http://${boltz_published_endpoint}"
wait_for "Boltz provider compatibility published endpoint" \
  curl --fail --silent --show-error "${boltz_provider_url}/v2/version"
if test -n "${shadow_reference_origin}"; then
  current_phase=boltz-readonly-live-shadow
  python3 scripts/boltz-readonly-shadow.py \
    --reference-origin "${shadow_reference_origin}" \
    --candidate-origin "${boltz_provider_url}" \
    --source-commit "$(git rev-parse HEAD)" \
    --output "${shadow_output}"
fi

current_phase=boltz-go-client-engine-callback
compose run --rm --no-deps \
  --env IMMORTAL_LAB_BOLTZ_ADAPTER_CLIENT=go \
  driver boltz-adapter >"${private_root}/boltz-go-driver.log" 2>&1 &
boltz_driver_process=$!
if ! wait_for "Go adapter client-engine preparation" \
  test -f "${private_root}/state/boltz-go-prepared.json"; then
  kill -TERM "${boltz_driver_process}" >/dev/null 2>&1 || true
  wait "${boltz_driver_process}" >/dev/null 2>&1 || true
  exit 1
fi
if ! (cd adapters/boltz-client-go && \
  IMMORTAL_BOLTZ_PROVIDER_PROCESS_URL="${boltz_provider_url}" \
    IMMORTAL_BOLTZ_PROVIDER_PROCESS_STATE_DIR="${private_root}/state" \
    go test -v ./... -run TestAdaptedGoClientAgainstProviderProcess -count=1); then
  kill -TERM "${boltz_driver_process}" >/dev/null 2>&1 || true
  wait "${boltz_driver_process}" >/dev/null 2>&1 || true
  echo "test-provider-funded: adapted Go client failed against the provider process" >&2
  exit 1
fi
if ! wait "${boltz_driver_process}"; then
  echo "test-provider-funded: Go adapter client-engine callback failed" >&2
  exit 1
fi

current_phase=boltz-web-client-engine-callback
compose run --rm --no-deps \
  --env IMMORTAL_LAB_BOLTZ_ADAPTER_CLIENT=web \
  driver boltz-adapter >"${private_root}/boltz-web-driver.log" 2>&1 &
boltz_driver_process=$!
if ! wait_for "web adapter client-engine preparation" \
  test -f "${private_root}/state/boltz-web-prepared.json"; then
  kill -TERM "${boltz_driver_process}" >/dev/null 2>&1 || true
  wait "${boltz_driver_process}" >/dev/null 2>&1 || true
  exit 1
fi
if ! IMMORTAL_BOLTZ_PROVIDER_PROCESS_URL="${boltz_provider_url}" \
  IMMORTAL_BOLTZ_PROVIDER_PROCESS_STATE_DIR="${private_root}/state" \
  node --experimental-websocket --test adapters/boltz-web-app/provider-process.test.mjs; then
  kill -TERM "${boltz_driver_process}" >/dev/null 2>&1 || true
  wait "${boltz_driver_process}" >/dev/null 2>&1 || true
  echo "test-provider-funded: adapted web client failed against the provider process" >&2
  exit 1
fi
if ! wait "${boltz_driver_process}"; then
  echo "test-provider-funded: web adapter client-engine callback failed" >&2
  exit 1
fi

evidence_file="${private_root}/evidence/funded-smoke.json"
if ! test -f "${evidence_file}"; then
  echo "test-provider-funded: driver produced no funded-swap evidence" >&2
  exit 1
fi
chmod 0600 "${evidence_file}"

evidence_value() {
  local journey_name="$1"
  local field_name="$2"
  python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    evidence = json.load(source)
print(evidence["journeys"][sys.argv[2]][sys.argv[3]])
' "${evidence_file}" "${journey_name}" "${field_name}"
}

manifest_value() {
  local journey_name="$1"
  local field_name="$2"
  python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
print(manifest["journeys"][sys.argv[2]][sys.argv[3]])
' "${manifest_file}" "${journey_name}" "${field_name}"
}

current_phase=evidence-collection
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 1 "${miner_address}" >/dev/null
for journey_name in submarine reverse reverse_refund; do
  lockup_txid="$(evidence_value "${journey_name}" lockup_txid)"
  terminal_field="$(manifest_value "${journey_name}" chain_terminal_field)"
  terminal_txid="$(evidence_value "${journey_name}" "${terminal_field}")"
  bitcoin_cli getrawtransaction "${lockup_txid}" true \
    >"${private_root}/evidence/chain/${journey_name}-lockup.json"
  bitcoin_cli getrawtransaction "${terminal_txid}" true \
    >"${private_root}/evidence/chain/${journey_name}-terminal.json"
  payment_hash="$(evidence_value "${journey_name}" payment_hash)"
  lightning_owner="$(manifest_value "${journey_name}" lightning_owner)"
  lightning_kind="$(manifest_value "${journey_name}" lightning_kind)"
  case "${lightning_owner}:${lightning_kind}" in
    peer:ordinary)
      cln_cli cln-peer -k listinvoices payment_hash="${payment_hash}" \
        >"${private_root}/evidence/lightning/${journey_name}.json"
      ;;
    provider:hold)
      if test "${lightning_rail}" = cln; then
        cln_cli cln-provider listholdinvoices "${payment_hash}" \
          >"${private_root}/evidence/lightning/${journey_name}.json"
      else
        lnd_cli lookupinvoice --rhash "${payment_hash}" | python3 -c '
import json, sys
payment_hash, output_path = sys.argv[1:]
invoice = json.load(sys.stdin)
states = {"SETTLED": "paid", "CANCELED": "cancelled"}
state = states.get(invoice.get("state"))
if state is None:
    raise SystemExit("LND hold invoice is not terminal")
with open(output_path, "w", encoding="utf-8") as output:
    json.dump({"holdinvoices": [{"payment_hash": payment_hash, "state": state}]}, output, separators=(",", ":"))
    output.write("\n")
' "${payment_hash}" "${private_root}/evidence/lightning/${journey_name}.json"
      fi
      ;;
    *)
      echo "test-provider-funded: manifest has an unsupported Lightning evidence owner or kind" >&2
      exit 1
      ;;
  esac
done
chmod 0600 "${private_root}/evidence/chain"/*.json \
  "${private_root}/evidence/lightning"/*.json

compose exec -T "${provider_service}" /usr/bin/curl --fail --silent --show-error \
  http://127.0.0.1:9091/metrics >"${private_root}/evidence/metrics-after.txt"
if ! grep -qx 'immortal_provider_ready 1' "${private_root}/evidence/metrics-after.txt" \
  || ! grep -qx 'immortal_provider_watch_jobs_pending 0' "${private_root}/evidence/metrics-after.txt" \
  || ! grep -qx 'immortal_provider_watch_jobs_unresolved 0' "${private_root}/evidence/metrics-after.txt"; then
  echo "test-provider-funded: provider retained unresolved money after the smoke" >&2
  exit 1
fi
if test -e "${private_root}/evidence/provider-alert.json"; then
  echo "test-provider-funded: provider emitted an operator alert during the smoke" >&2
  exit 1
fi

current_phase=durable-evidence-collection
submarine_order_id="$(evidence_value submarine order_id)"
reverse_order_id="$(evidence_value reverse order_id)"
reverse_refund_order_id="$(evidence_value reverse_refund order_id)"
for funded_order_id in \
  "${submarine_order_id}" \
  "${reverse_order_id}" \
  "${reverse_refund_order_id}"; do
  if [[ ! "${funded_order_id}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "test-provider-funded: funded-swap evidence has an invalid order ID" >&2
    exit 1
  fi
done

durable_evidence_file="${private_root}/evidence/provider-postgres.json"
if ! compose exec -T provider-postgres psql \
  -X --quiet --tuples-only --no-align --set=ON_ERROR_STOP=1 \
  -U immortal_provider -d immortal_provider \
  --set="submarine_order_id=${submarine_order_id}" \
  --set="reverse_order_id=${reverse_order_id}" \
  --set="reverse_refund_order_id=${reverse_refund_order_id}" \
  --set="terminal_confirmations=${terminal_confirmations}" \
  <"${support_dir}/durable_evidence.sql" \
  >"${durable_evidence_file}" \
  2>"${private_root}/evidence/provider-postgres-error.log"; then
  echo "test-provider-funded: provider Postgres evidence query failed" >&2
  exit 1
fi
chmod 0600 "${durable_evidence_file}"

current_phase=evidence-validation
python3 "${support_dir}/validate_evidence.py" \
  --manifest "${manifest_file}" \
  --evidence "${evidence_file}" \
  --durable-evidence "${durable_evidence_file}" \
  --chain-directory "${private_root}/evidence/chain" \
  --lightning-directory "${private_root}/evidence/lightning"

current_phase=complete
echo "test-provider-funded: submarine, reverse, and noncooperative refund passed"
