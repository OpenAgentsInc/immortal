#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

support_dir="scripts/support/provider-funded"
compose_file="${support_dir}/compose.yaml"
manifest_file="tests/fixtures/provider/funded-smoke-v1.json"
private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-provider-funded.XXXXXX")"
project_name=""
compose_ready=false
compose_prefix=()
current_phase=initialization

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
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

umask 077
mkdir -m 0700 "${private_root}/evidence" \
  "${private_root}/evidence/chain" \
  "${private_root}/evidence/lightning" \
  "${private_root}/state"

random_hex() {
  local byte_count="$1"
  LC_ALL=C od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

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
EOF
chmod 0600 "${private_root}"/*.conf "${private_root}"/*.env

if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_prefix=(
    docker compose
    --env-file "${private_root}/compose.env"
    --file "${compose_file}"
    --project-name "${project_name}"
  )
elif podman info >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  compose_prefix=(
    podman compose
    --env-file "${private_root}/compose.env"
    --file "${compose_file}"
    --project-name "${project_name}"
  )
else
  echo "test-provider-funded: start Docker Desktop or a Podman compose service" >&2
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
    if compose exec -T provider /usr/bin/curl \
      --fail --silent --show-error http://127.0.0.1:9091/healthz \
      >/dev/null 2>&1; then
      return 0
    fi
    if ! compose ps --services --status running | grep -qx provider; then
      echo "test-provider-funded: funded provider daemon exited before readiness" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "test-provider-funded: funded provider daemon did not become ready" >&2
  return 1
}

if ! compose config --quiet; then
  echo "test-provider-funded: disposable compose configuration is invalid" >&2
  exit 1
fi
current_phase=image-build
if ! compose build bitcoin cln-provider cln-peer relay provider driver alert-sink \
  >"${private_root}/build.log" 2>&1; then
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
current_phase=rail-startup
if ! compose up --detach relay cln-provider cln-peer alert-sink \
  >>"${private_root}/startup.log" 2>&1; then
  echo "test-provider-funded: relay and Lightning services did not start" >&2
  exit 1
fi
wait_for "provider CLN" cln_cli cln-provider getinfo
wait_for "peer CLN" cln_cli cln-peer getinfo
wait_for "relay" compose run --rm --no-deps --entrypoint /usr/bin/curl provider \
  --fail --silent --show-error http://127.0.0.1:18080/health
wait_for "provider alert sink" compose exec -T alert-sink python3 -c '
import urllib.request
with urllib.request.urlopen("http://127.0.0.1:19092/healthz", timeout=2) as response:
    raise SystemExit(0 if response.status == 200 and response.read() == b"ready\n" else 1)
'

for method_name in holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice; do
  if ! cln_cli cln-provider help "${method_name}" >/dev/null 2>&1; then
    echo "test-provider-funded: provider CLN hold-plugin capability probe failed" >&2
    exit 1
  fi
done

current_phase=rail-funding
bitcoin_cli createwallet smoke-miner >/dev/null
miner_address="$(bitcoin_cli -rpcwallet=smoke-miner getnewaddress)"
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 110 "${miner_address}" >/dev/null

current_phase=rail-funding-cln-addresses
provider_cln_address="$(cln_cli cln-provider newaddr bech32 | json_field bech32)"
peer_cln_address="$(cln_cli cln-peer newaddr bech32 | json_field bech32)"
current_phase=rail-funding-cln-wallets
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${provider_cln_address}" 3.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${peer_cln_address}" 1.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null
chain_height="$(bitcoin_cli getblockcount)"
wait_for "provider CLN wallet" cln_wallet_ready cln-provider "${chain_height}"
wait_for "peer CLN wallet" cln_wallet_ready cln-peer "${chain_height}"

current_phase=rail-funding-connect
peer_node_id="$(cln_cli cln-peer getinfo | json_field id)"
cln_cli cln-provider connect "${peer_node_id}@cln-peer:19847" >/dev/null
current_phase=rail-funding-channel
cln_cli cln-provider -k fundchannel \
  id="${peer_node_id}" \
  amount=2000000sat \
  feerate=253perkw \
  announce=false \
  push_msat=1000000000msat >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null

current_phase=rail-funding-channel-readiness
wait_for "balanced CLN channel" cln_channel_ready "${peer_node_id}"

current_phase=provider-funding
provider_address_log="${private_root}/provider-address.log"
if ! compose run --rm --no-deps provider address \
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
if ! compose up --detach provider >>"${private_root}/startup.log" 2>&1; then
  echo "test-provider-funded: provider container did not start" >&2
  exit 1
fi
wait_for_provider
compose exec -T provider /usr/bin/curl --fail --silent --show-error \
  http://127.0.0.1:9091/metrics >"${private_root}/evidence/metrics-before.txt"
if ! grep -qx 'immortal_provider_ready 1' "${private_root}/evidence/metrics-before.txt"; then
  echo "test-provider-funded: provider metrics did not report readiness" >&2
  exit 1
fi

current_phase=harness-controlled-stop
if compose run --rm --no-deps \
  --env IMMORTAL_LAB_STOP_AFTER=submarine:funding_authorized \
  driver >"${private_root}/driver-stop.log" 2>&1; then
  echo "test-provider-funded: harness ignored the controlled stop" >&2
  exit 1
fi
if ! python3 -c '
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
with (state / "funded-checkpoint.json").open(encoding="utf-8") as source:
    checkpoint = json.load(source)
if checkpoint.get("journey") != "submarine":
    raise SystemExit("controlled-stop checkpoint has another journey")
if checkpoint.get("label") != "funding_authorized":
    raise SystemExit("controlled-stop checkpoint has another label")
if checkpoint.get("safe_to_stop") is not True:
    raise SystemExit("controlled-stop checkpoint is not money-safe")
snapshot = state / "funded-submarine-session.json"
if not snapshot.is_file():
    raise SystemExit("controlled-stop session snapshot is absent")
' "${private_root}/state"; then
  echo "test-provider-funded: harness did not persist its safe restart boundary" >&2
  exit 1
fi

current_phase=harness-restart
if ! compose run --rm --no-deps driver \
  >"${private_root}/driver.log" 2>&1; then
  echo "test-provider-funded: external funded-swap driver failed" >&2
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
      cln_cli cln-provider listholdinvoices "${payment_hash}" \
        >"${private_root}/evidence/lightning/${journey_name}.json"
      ;;
    *)
      echo "test-provider-funded: manifest has an unsupported Lightning evidence owner or kind" >&2
      exit 1
      ;;
  esac
done
chmod 0600 "${private_root}/evidence/chain"/*.json \
  "${private_root}/evidence/lightning"/*.json

compose exec -T provider /usr/bin/curl --fail --silent --show-error \
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
