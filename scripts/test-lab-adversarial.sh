#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/adversarial-v1.json"
support_dir="scripts/support/provider-funded"
compose_file="${support_dir}/adversarial-compose.yaml"
record_dir="${IMMORTAL_LAB_ADVERSARIAL_RECORD_DIR:-target/lab-evidence/adversarial-cases}"

usage() {
  cat <<'USAGE'
Usage: scripts/test-lab-adversarial.sh --list
       scripts/test-lab-adversarial.sh --case CASE_ID
       scripts/test-lab-adversarial.sh --all

Every executed case receives a fresh two-provider, two-bitcoind, two-relay
regtest topology. This is a manual local gate and does not use GitHub automation.
USAGE
}

manifest_cases() {
  python3 - "${fixture}" <<'PY'
import json
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if fixture.get("schema") != "openagents.immortal.adversarial-lab.v1":
    raise SystemExit("adversarial fixture has another schema")
groups = fixture.get("scenario_groups")
if not isinstance(groups, dict):
    raise SystemExit("adversarial fixture has no scenario groups")
seen = set()
maximum = fixture.get("execution", {}).get("maximum_cases")
rows = []
for group, cases in groups.items():
    if not isinstance(cases, list):
        raise SystemExit("adversarial scenario group is not a list")
    for case in cases:
        case_id = case.get("id")
        expected = case.get("expected")
        provider = case.get("provider", "")
        if (
            not isinstance(case_id, str)
            or not case_id
            or len(case_id.encode()) > 128
            or any(not (character.isascii() and (character.isalnum() or character in "-_")) for character in case_id)
            or case_id in seen
            or not isinstance(expected, str)
            or not expected
            or provider not in {"", "provider-a", "provider-b"}
        ):
            raise SystemExit("adversarial scenario row is invalid")
        seen.add(case_id)
        rows.append((case_id, group, expected, provider))
if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= len(rows) <= maximum <= 40:
    raise SystemExit("adversarial scenario count is outside its bound")
for row in rows:
    print(*row, sep="\t")
PY
}

selection=""
selected_case=""
case "${1:-}" in
  --list)
    test "$#" -eq 1 || { usage >&2; exit 2; }
    selection=list
    ;;
  --case)
    test "$#" -eq 2 || { usage >&2; exit 2; }
    selection=case
    selected_case="$2"
    ;;
  --all)
    test "$#" -eq 1 || { usage >&2; exit 2; }
    selection=all
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

case_file="$(mktemp "${TMPDIR:-/tmp}/immortal-adversarial-cases.XXXXXX")"
cleanup_case_file() {
  local exit_status=$?
  trap - EXIT INT TERM
  case "$(basename "${case_file}")" in
    immortal-adversarial-cases.*) rm -f -- "${case_file}" || exit_status=1 ;;
    *) echo "test-lab-adversarial: refused unexpected case file" >&2; exit_status=1 ;;
  esac
  exit "${exit_status}"
}
trap cleanup_case_file EXIT INT TERM
umask 077
manifest_cases >"${case_file}"

if test "${selection}" = list; then
  cut -f1 "${case_file}"
  exit 0
fi
if test "${selection}" = case \
  && ! cut -f1 "${case_file}" | grep -Fx -- "${selected_case}" >/dev/null; then
  echo "test-lab-adversarial: unknown case ${selected_case}" >&2
  exit 2
fi

for command_name in docker jq python3; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "test-lab-adversarial: required command ${command_name} is unavailable" >&2
    exit 1
  fi
done
if ! docker info >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "test-lab-adversarial: start Docker Desktop with Compose support" >&2
  exit 1
fi

random_hex() {
  local byte_count="$1"
  LC_ALL=C od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

run_case() (
  set -euo pipefail
  local case_id="$1" group="$2" expected="$3" selected_provider="$4"
  local private_root project_name current_phase compose_ready infrastructure_proven
  local maximum_seconds case_deadline failure_reason record_path
  private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-adversarial-case.XXXXXX")"
  project_name="immortal-18-$(printf '%s' "${case_id}" | cut -c1-24)-$(random_hex 5)"
  current_phase=initialization
  compose_ready=false
  infrastructure_proven=false
  failure_reason=case_failed
  record_path="${record_dir}/${case_id}.json"
  maximum_seconds="$(python3 - "${fixture}" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["execution"]["maximum_case_runtime_seconds"]
if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3600:
    raise SystemExit("case runtime bound is invalid")
print(value)
PY
)"
  case_deadline=$(($(date +%s) + maximum_seconds))
  local -a compose_prefix=(
    docker compose
    --file "${compose_file}"
    --project-name "${project_name}"
  )

  compose() {
    IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" "${compose_prefix[@]}" "$@"
  }

  write_failure_record() {
    local exit_status="$1"
    python3 - "${fixture}" "${record_path}" "${case_id}" "${current_phase}" \
      "${failure_reason}" "${exit_status}" "${infrastructure_proven}" <<'PY'
import json
import os
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
path = pathlib.Path(sys.argv[2])
record = {
    "schema": fixture["evidence"]["retained_record"]["failure_schema"],
    "case_id": sys.argv[3],
    "phase": sys.argv[4],
    "reason": sys.argv[5],
    "exit_status": int(sys.argv[6]),
    "infrastructure_proven": sys.argv[7] == "true",
    "scenario_executed": False,
}
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > fixture["evidence"]["retained_record"]["maximum_bytes"]:
    raise SystemExit("failure record exceeds fixture bound")
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(path.parent, 0o700)
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY
  }

  cleanup() {
    local exit_status=$?
    trap - EXIT INT TERM
    if test "${compose_ready}" = true; then
      compose logs --no-color >"${private_root}/runtime.log" 2>&1 || true
      if ! compose down --volumes --remove-orphans --rmi local >/dev/null 2>&1; then
        echo "test-lab-adversarial: ${case_id}: Compose cleanup failed" >&2
        exit_status=1
      fi
      if test -n "$(docker ps --all --quiet --filter "label=com.docker.compose.project=${project_name}")"; then
        echo "test-lab-adversarial: ${case_id}: project containers survived cleanup" >&2
        exit_status=1
      fi
      if test -n "$(docker volume ls --quiet --filter "label=com.docker.compose.project=${project_name}")"; then
        echo "test-lab-adversarial: ${case_id}: project volumes survived cleanup" >&2
        exit_status=1
      fi
      if test -n "$(docker image ls --quiet --filter "label=com.docker.compose.project=${project_name}")"; then
        echo "test-lab-adversarial: ${case_id}: project images survived cleanup" >&2
        exit_status=1
      fi
    fi
    if test "${exit_status}" -ne 0; then
      write_failure_record "${exit_status}" || true
    fi
    case "$(basename "${private_root}")" in
      immortal-adversarial-case.*)
        if test -f "${private_root}/owned"; then
          rm -rf -- "${private_root}" || exit_status=1
        else
          echo "test-lab-adversarial: ${case_id}: private root lost ownership marker" >&2
          exit_status=1
        fi
        ;;
      *)
        echo "test-lab-adversarial: ${case_id}: refused unexpected private root" >&2
        exit_status=1
        ;;
    esac
    exit "${exit_status}"
  }
  trap cleanup EXIT INT TERM

  check_deadline() {
    if test "$(date +%s)" -ge "${case_deadline}"; then
      failure_reason=case_runtime_exceeded
      echo "test-lab-adversarial: ${case_id}: exceeded ${maximum_seconds}s runtime bound" >&2
      return 1
    fi
  }

  wait_for() {
    local description="$1"
    shift
    for _ in $(seq 1 600); do
      check_deadline
      if "$@" >/dev/null 2>&1; then
        return 0
      fi
      sleep 0.2
    done
    echo "test-lab-adversarial: ${case_id}: ${description} did not become ready" >&2
    return 1
  }

  bitcoin_cli() {
    local node="$1"
    shift
    compose exec -T "bitcoin-${node}" bitcoin-cli \
      "-conf=/run/immortal-private/bitcoin-${node}.conf" \
      -datadir=/var/lib/bitcoin "$@"
  }

  cln_cli() {
    local service="$1"
    shift
    compose exec -T "${service}" lightning-cli --network=regtest \
      --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc "$@"
  }

  chains_synced() {
    local height_a height_b hash_a hash_b
    height_a="$(bitcoin_cli a getblockcount)"
    height_b="$(bitcoin_cli b getblockcount)"
    hash_a="$(bitcoin_cli a getbestblockhash)"
    hash_b="$(bitcoin_cli b getbestblockhash)"
    test "${height_a}" = "${height_b}" && test "${hash_a}" = "${hash_b}"
  }

  bitcoin_peered() {
    test "$(bitcoin_cli a getconnectioncount)" -ge 1 \
      && test "$(bitcoin_cli b getconnectioncount)" -ge 1
  }

  cln_wallet_ready() {
    local service="$1" expected_height="$2" actual_height
    actual_height="$(cln_cli "${service}" getinfo | jq -er .blockheight)"
    test "${actual_height}" -ge "${expected_height}" \
      && cln_cli "${service}" listfunds | jq -e 'any(.outputs[]; .status == "confirmed")'
  }

  cln_channels_ready() {
    local service="$1"
    cln_cli "${service}" listpeerchannels \
      | jq -e '[.channels[] | select(.state == "CHANNELD_NORMAL")] | length == 2'
  }

  provider_ready() {
    local provider="$1" port="$2"
    compose exec -T "provider-${provider}" /usr/bin/curl --fail --silent \
      "http://127.0.0.1:${port}/healthz"
  }

  umask 077
  touch "${private_root}/owned"
  mkdir -m 0700 "${private_root}/evidence" "${private_root}/state"

  current_phase=credential-generation
  local bitcoin_a_user bitcoin_b_user bitcoin_a_password bitcoin_b_password
  local relay_a_password relay_b_password provider_a_password provider_b_password
  local provider_a_identity provider_b_identity provider_a_seed provider_b_seed client_seed
  bitcoin_a_user="immortal-a-$(random_hex 8)"
  bitcoin_b_user="immortal-b-$(random_hex 8)"
  bitcoin_a_password="$(random_hex 32)"
  bitcoin_b_password="$(random_hex 32)"
  relay_a_password="$(random_hex 32)"
  relay_b_password="$(random_hex 32)"
  provider_a_password="$(random_hex 32)"
  provider_b_password="$(random_hex 32)"
  provider_a_seed="$(random_hex 32)"
  provider_b_seed="$(random_hex 32)"
  client_seed="$(random_hex 32)"
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

  printf '%s\n' "${relay_a_password}" >"${private_root}/relay-a-postgres-password"
  printf '%s\n' "${relay_b_password}" >"${private_root}/relay-b-postgres-password"
  printf '%s\n' "${provider_a_password}" >"${private_root}/provider-a-postgres-password"
  printf '%s\n' "${provider_b_password}" >"${private_root}/provider-b-postgres-password"
  printf '%s\n' "${provider_a_seed}" >"${private_root}/provider-a-wallet-seed"
  printf '%s\n' "${provider_b_seed}" >"${private_root}/provider-b-wallet-seed"
  printf '%s\n' "${client_seed}" >"${private_root}/client-wallet-seed"

  current_phase=configuration-generation
  cat >"${private_root}/bitcoin-a.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
bind=0.0.0.0:18444
[regtest]
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_a_user}
rpcpassword=${bitcoin_a_password}
EOF
  cat >"${private_root}/bitcoin-b.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
bind=0.0.0.0:18444
[regtest]
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_b_user}
rpcpassword=${bitcoin_b_password}
EOF

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
      cat >>"${path}" <<EOF
plugin=/usr/local/bin/hold
hold-grpc-port=-1
hold-expiry-deadline=3
EOF
    fi
  }
  write_cln_config "${private_root}/cln-provider-a.conf" \
    "${bitcoin_a_user}" "${bitcoin_a_password}" 19846 bitcoin-a true
  write_cln_config "${private_root}/cln-provider-b.conf" \
    "${bitcoin_b_user}" "${bitcoin_b_password}" 19847 bitcoin-b true
  write_cln_config "${private_root}/cln-wallet.conf" \
    "${bitcoin_a_user}" "${bitcoin_a_password}" 19848 wallet-gateway false

  cat >"${private_root}/relay-a.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_a_password}@relay-a-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18080
IMMORTAL_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF
  cat >"${private_root}/relay-b.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_b_password}@relay-b-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18081
IMMORTAL_RELAY_URL=ws://127.0.0.1:18081
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF

  write_provider_env() {
    local path="$1" suffix="$2" database_password="$3" relay_port="$4" identity="$5"
    local rpc_user="$6" rpc_password="$7" socket_path="$8" seed_path="$9" health_port="${10}"
    cat >"${path}" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${database_password}@provider-${suffix}-postgres:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:${relay_port}
IMMORTAL_PROVIDER_IDENTITY_SECRET=${identity}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_LAB_PROFILE=regtest_adversarial
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=${rpc_user}
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${rpc_password}
IMMORTAL_PROVIDER_CLN_RPC_PATH=${socket_path}
IMMORTAL_PROVIDER_WALLET_SEED_FILE=${seed_path}
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:${health_port}
IMMORTAL_PROVIDER_ALERT_URL=http://127.0.0.1:19092/provider-alert
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=10
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=1
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=2
IMMORTAL_PROVIDER_SPREAD_BPS=100
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
EOF
  }
  write_provider_env "${private_root}/provider-a.env" a "${provider_a_password}" 18080 \
    "${provider_a_identity}" "${bitcoin_a_user}" "${bitcoin_a_password}" \
    /rail/cln-provider-a/lightning-rpc /run/immortal-private/provider-a-wallet-seed 9091
  write_provider_env "${private_root}/provider-b.env" b "${provider_b_password}" 18081 \
    "${provider_b_identity}" "${bitcoin_b_user}" "${bitcoin_b_password}" \
    /rail/cln-provider-b/lightning-rpc /run/immortal-private/provider-b-wallet-seed 9092

  cat >"${private_root}/wallet-driver.env" <<EOF
IMMORTAL_LAB_ADVERSARIAL_CASE_ID=${case_id}
IMMORTAL_LAB_ADVERSARIAL_SELECTED_PROVIDER=${selected_provider}
IMMORTAL_LAB_ADVERSARIAL_EXPECTED=${expected}
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_URLS=ws://127.0.0.1:18080,ws://127.0.0.1:18081
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
IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE=/evidence/driver-evidence.json
IMMORTAL_PROVIDER_FUNDED_SMOKE_TERMINAL_CONFIRMATIONS=3
IMMORTAL_LAB_STATE_DIR=/state
EOF

  current_phase=compose-validation
  compose_ready=true
  compose config --quiet
  current_phase=image-build
  compose build bitcoin-a bitcoin-b cln-provider-a cln-provider-b cln-wallet \
    relay-a relay-b provider-a provider-b wallet-driver alert-sink-a alert-sink-b \
    provider-a-egress provider-b-egress wallet-gateway \
    >"${private_root}/build.log" 2>&1

  current_phase=base-startup
  compose up --detach bitcoin-a bitcoin-b relay-a-postgres relay-b-postgres \
    provider-a-postgres provider-b-postgres >"${private_root}/startup.log" 2>&1
  wait_for "Bitcoin A" bitcoin_cli a getblockchaininfo
  wait_for "Bitcoin B" bitcoin_cli b getblockchaininfo
  wait_for "relay A Postgres" compose exec -T relay-a-postgres pg_isready -U immortal_relay -d immortal_relay
  wait_for "relay B Postgres" compose exec -T relay-b-postgres pg_isready -U immortal_relay -d immortal_relay
  wait_for "provider A Postgres" compose exec -T provider-a-postgres pg_isready -U immortal_provider -d immortal_provider
  wait_for "provider B Postgres" compose exec -T provider-b-postgres pg_isready -U immortal_provider -d immortal_provider

  current_phase=bitcoin-peering
  bitcoin_cli a addnode bitcoin-b:18444 onetry >/dev/null
  wait_for "reciprocal Bitcoin P2P peering" bitcoin_peered
  bitcoin_cli a createwallet adversarial-miner >/dev/null
  local miner_address
  miner_address="$(bitcoin_cli a -rpcwallet=adversarial-miner getnewaddress)"
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 110 "${miner_address}" >/dev/null
  wait_for "initial A/B chain synchronization" chains_synced

  current_phase=credential-isolation
  bitcoin_cli a getblockchaininfo >/dev/null
  bitcoin_cli b getblockchaininfo >/dev/null
  if compose exec -T bitcoin-a bitcoin-cli -rpcconnect=127.0.0.1 -rpcport=18443 \
    "-rpcuser=${bitcoin_b_user}" "-rpcpassword=${bitcoin_b_password}" getblockchaininfo \
    >"${private_root}/wrong-a-rpc.log" 2>&1; then
    echo "test-lab-adversarial: Bitcoin A accepted Bitcoin B credentials" >&2
    exit 1
  fi
  if compose exec -T bitcoin-b bitcoin-cli -rpcconnect=127.0.0.1 -rpcport=18443 \
    "-rpcuser=${bitcoin_a_user}" "-rpcpassword=${bitcoin_a_password}" getblockchaininfo \
    >"${private_root}/wrong-b-rpc.log" 2>&1; then
    echo "test-lab-adversarial: Bitcoin B accepted Bitcoin A credentials" >&2
    exit 1
  fi
  if compose exec -T bitcoin-a bitcoin-cli -rpcconnect=bitcoin-b -rpcport=18443 \
    "-rpcuser=${bitcoin_b_user}" "-rpcpassword=${bitcoin_b_password}" getblockchaininfo \
    >"${private_root}/cross-a-to-b-rpc.log" 2>&1; then
    echo "test-lab-adversarial: Bitcoin B exposed RPC outside its namespace" >&2
    exit 1
  fi
  if compose exec -T bitcoin-b bitcoin-cli -rpcconnect=bitcoin-a -rpcport=18443 \
    "-rpcuser=${bitcoin_a_user}" "-rpcpassword=${bitcoin_a_password}" getblockchaininfo \
    >"${private_root}/cross-b-to-a-rpc.log" 2>&1; then
    echo "test-lab-adversarial: Bitcoin A exposed RPC outside its namespace" >&2
    exit 1
  fi

  current_phase=rail-startup
  compose up --detach --no-deps provider-a-egress provider-b-egress \
    >>"${private_root}/startup.log" 2>&1
  compose up --detach wallet-gateway cln-provider-a cln-provider-b cln-wallet \
    relay-a relay-b alert-sink-a alert-sink-b >>"${private_root}/startup.log" 2>&1
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service}" cln_cli "${service}" getinfo
  done
  for service in cln-provider-a cln-provider-b; do
    for method in \
      holdinvoice holdinvoiceimmortalregtest \
      listholdinvoices settleholdinvoice cancelholdinvoice; do
      cln_cli "${service}" -J -k help command="${method}" \
        | jq -e --arg method "${method}" '.help | any(.[]; .command | startswith($method))' >/dev/null
    done
  done
  wait_for "relay A" compose run --rm --no-deps --entrypoint /usr/bin/curl provider-a \
    --fail --silent http://127.0.0.1:18080/health
  wait_for "relay B" compose run --rm --no-deps --entrypoint /usr/bin/curl provider-b \
    --fail --silent http://127.0.0.1:18081/health

  current_phase=rail-funding
  local service address chain_height
  for service in cln-provider-a cln-provider-b cln-wallet; do
    address="$(cln_cli "${service}" newaddr bech32 | jq -er .bech32)"
    bitcoin_cli a -rpcwallet=adversarial-miner sendtoaddress "${address}" 3.0 >/dev/null
  done
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "funding chain synchronization" chains_synced
  chain_height="$(bitcoin_cli a getblockcount)"
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} wallet funding" cln_wallet_ready "${service}" "${chain_height}"
  done

  current_phase=channel-provisioning
  local wallet_id provider_b_id
  wallet_id="$(cln_cli cln-wallet getinfo | jq -er .id)"
  provider_b_id="$(cln_cli cln-provider-b getinfo | jq -er .id)"
  cln_cli cln-provider-a connect "${wallet_id}@wallet-gateway:19848" >/dev/null
  cln_cli cln-provider-a -k fundchannel id="${wallet_id}" amount=2000000sat \
    feerate=253perkw announce=false push_msat=1000000000msat >/dev/null
  cln_cli cln-provider-b connect "${wallet_id}@wallet-gateway:19848" >/dev/null
  cln_cli cln-provider-b -k fundchannel id="${wallet_id}" amount=2000000sat \
    feerate=253perkw announce=false push_msat=1000000000msat >/dev/null
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 1 "${miner_address}" >/dev/null
  wait_for "paired channel chain synchronization" chains_synced
  cln_cli cln-provider-a connect "${provider_b_id}@bitcoin-b:19847" >/dev/null
  cln_cli cln-provider-a -k fundchannel id="${provider_b_id}" amount=1000000sat \
    feerate=253perkw announce=false push_msat=500000000msat >/dev/null
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "triangle channel chain synchronization" chains_synced
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} balanced channels" cln_channels_ready "${service}"
  done

  current_phase=provider-funding
  local provider_a_address provider_b_address
  provider_a_address="$(compose run --rm --no-deps provider-a address | tr -d '\r\n')"
  provider_b_address="$(compose run --rm --no-deps provider-b address | tr -d '\r\n')"
  [[ "${provider_a_address}" =~ ^bcrt1p[023456789ac-hj-np-z]{58}$ ]]
  [[ "${provider_b_address}" =~ ^bcrt1p[023456789ac-hj-np-z]{58}$ ]]
  bitcoin_cli a -rpcwallet=adversarial-miner sendtoaddress "${provider_a_address}" 1.0 >/dev/null
  bitcoin_cli a -rpcwallet=adversarial-miner sendtoaddress "${provider_b_address}" 1.0 >/dev/null
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 2 "${miner_address}" >/dev/null
  wait_for "provider funding chain synchronization" chains_synced

  current_phase=provider-startup
  compose up --detach provider-a provider-b \
    >>"${private_root}/startup.log" 2>&1
  wait_for "provider A" provider_ready a 9091
  wait_for "provider B" provider_ready b 9092
  compose exec -T provider-a sh -c \
    'test "$IMMORTAL_PROVIDER_RELAY_URL" = ws://127.0.0.1:18080'
  compose exec -T provider-b sh -c \
    'test "$IMMORTAL_PROVIDER_RELAY_URL" = ws://127.0.0.1:18081'

  current_phase=topology-assertions
  local namespace_a namespace_b namespace_wallet member_namespace
  namespace_a="$(compose exec -T bitcoin-a readlink /proc/1/ns/net | tr -d '\r')"
  namespace_b="$(compose exec -T bitcoin-b readlink /proc/1/ns/net | tr -d '\r')"
  namespace_wallet="$(compose exec -T wallet-gateway readlink /proc/1/ns/net | tr -d '\r')"
  test "${namespace_a}" != "${namespace_b}"
  test "${namespace_a}" != "${namespace_wallet}"
  test "${namespace_b}" != "${namespace_wallet}"
  for service in relay-a provider-a alert-sink-a provider-a-egress cln-provider-a; do
    member_namespace="$(compose exec -T "${service}" readlink /proc/1/ns/net | tr -d '\r')"
    test "${member_namespace}" = "${namespace_a}"
  done
  for service in relay-b provider-b alert-sink-b provider-b-egress cln-provider-b; do
    member_namespace="$(compose exec -T "${service}" readlink /proc/1/ns/net | tr -d '\r')"
    test "${member_namespace}" = "${namespace_b}"
  done
  member_namespace="$(compose exec -T cln-wallet readlink /proc/1/ns/net | tr -d '\r')"
  test "${member_namespace}" = "${namespace_wallet}"

  local bitcoin_a_container bitcoin_b_container provider_a_container provider_b_container
  bitcoin_a_container="$(compose ps --quiet bitcoin-a)"
  bitcoin_b_container="$(compose ps --quiet bitcoin-b)"
  provider_a_container="$(compose ps --quiet provider-a)"
  provider_b_container="$(compose ps --quiet provider-b)"
  test -n "${bitcoin_a_container}" && test -n "${bitcoin_b_container}"
  test "${bitcoin_a_container}" != "${bitcoin_b_container}"
  docker inspect "${provider_a_container}" "${provider_b_container}" \
    >"${private_root}/provider-inspect.json"
  python3 - "${private_root}/provider-inspect.json" <<'PY'
import json, pathlib, sys
containers = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if len(containers) != 2:
    raise SystemExit("provider inspection did not return two containers")
expected = [
    ("/rail/cln-provider-a", "/run/immortal-private/provider-a-wallet-seed"),
    ("/rail/cln-provider-b", "/run/immortal-private/provider-b-wallet-seed"),
]
for container, own in zip(containers, expected):
    mounts = {mount["Destination"]: mount for mount in container.get("Mounts", [])}
    for destination in own:
        if destination not in mounts or mounts[destination].get("RW") is not False:
            raise SystemExit("provider own custody mount is absent or writable")
    forbidden = set(expected[0] + expected[1] + ("/rail/cln-wallet",)) - set(own)
    if forbidden & mounts.keys():
        raise SystemExit("provider has a cross-party custody mount")
if containers[0].get("Image") != containers[1].get("Image"):
    raise SystemExit("providers do not run the same shipped image")
PY

  local cln_a_id cln_b_id cln_wallet_id provider_a_pubkey provider_b_pubkey
  cln_a_id="$(cln_cli cln-provider-a getinfo | jq -er .id)"
  cln_b_id="$(cln_cli cln-provider-b getinfo | jq -er .id)"
  cln_wallet_id="$(cln_cli cln-wallet getinfo | jq -er .id)"
  test "$(printf '%s\n' "${cln_a_id}" "${cln_b_id}" "${cln_wallet_id}" | sort -u | wc -l | tr -d ' ')" = 3
  provider_a_pubkey="$(compose logs --no-color provider-a | sed -n 's/.*ready relay=.* pubkey=\([0-9a-f]\{64\}\).*/\1/p' | tail -1)"
  provider_b_pubkey="$(compose logs --no-color provider-b | sed -n 's/.*ready relay=.* pubkey=\([0-9a-f]\{64\}\).*/\1/p' | tail -1)"
  [[ "${provider_a_pubkey}" =~ ^[0-9a-f]{64}$ ]]
  [[ "${provider_b_pubkey}" =~ ^[0-9a-f]{64}$ ]]
  test "${provider_a_pubkey}" != "${provider_b_pubkey}"
  chains_synced
  local chain_height_final chain_hash_final running_count provider_image
  chain_height_final="$(bitcoin_cli a getblockcount)"
  chain_hash_final="$(bitcoin_cli a getbestblockhash)"
  running_count="$(docker ps --quiet --filter "label=com.docker.compose.project=${project_name}" | wc -l | tr -d ' ')"
  test "${running_count}" = 18
  provider_image="$(docker inspect --format '{{.Image}}' "${provider_a_container}")"

  current_phase=infrastructure-evidence
  python3 - "${private_root}/evidence/infrastructure.json" "${case_id}" "${group}" \
    "${namespace_a}" "${namespace_b}" "${namespace_wallet}" "${chain_height_final}" \
    "${chain_hash_final}" "${cln_a_id}" "${cln_b_id}" "${cln_wallet_id}" \
    "${provider_a_pubkey}" "${provider_b_pubkey}" "${provider_image}" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
record = {
    "schema": "openagents.immortal.adversarial-infrastructure.v1",
    "case_id": sys.argv[2],
    "scenario_group": sys.argv[3],
    "bitcoin": {
        "node_count": 2,
        "separate_namespaces": True,
        "separate_rpc_credentials": True,
        "peered": True,
        "height": int(sys.argv[7]),
        "best_block_hash": sys.argv[8],
    },
    "network_namespaces": {
        "provider_a": sys.argv[4],
        "provider_b": sys.argv[5],
        "wallet": sys.argv[6],
    },
    "cln": {
        "provider_a_node_id": sys.argv[9],
        "provider_b_node_id": sys.argv[10],
        "wallet_node_id": sys.argv[11],
        "normal_channels_per_node": 2,
        "separate_rpc_mounts": True,
    },
    "providers": {
        "provider_a_pubkey": sys.argv[12],
        "provider_b_pubkey": sys.argv[13],
        "same_image": sys.argv[14],
        "separate_databases": True,
        "separate_seed_mounts": True,
    },
    "relays": {
        "relay_count": 2,
        "separate_databases": True,
        "assignments": {"provider-a": "relay-a", "provider-b": "relay-b"},
    },
    "host_ports_published": False,
}
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > 8192:
    raise SystemExit("infrastructure evidence exceeds its bound")
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
PY
  infrastructure_proven=true

  current_phase=wallet-driver
  local remaining_seconds driver_status
  remaining_seconds=$((case_deadline - $(date +%s)))
  if test "${remaining_seconds}" -le 0; then
    failure_reason=case_runtime_exceeded
    exit 1
  fi
  set +e
  IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" python3 - \
    "${remaining_seconds}" "${compose_prefix[@]}" run --rm --no-deps wallet-driver \
    >"${private_root}/evidence/driver.json" 2>"${private_root}/driver-error.log" <<'PY'
import subprocess
import sys

timeout = int(sys.argv[1])
try:
    result = subprocess.run(sys.argv[2:], timeout=timeout, check=False)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(result.returncode)
PY
  driver_status=$?
  set -e
  if test "${driver_status}" -ne 0; then
    if grep -F 'immortal-lab: unknown command: adversarial-case' \
      "${private_root}/driver-error.log" >/dev/null 2>&1; then
      current_phase=runtime-command-unavailable
      failure_reason=runtime_command_unavailable
      echo "test-lab-adversarial: ${case_id}: infrastructure passed; immortal-lab adversarial-case is not implemented" >&2
      exit 78
    fi
    if test "${driver_status}" -eq 124; then
      failure_reason=case_runtime_exceeded
    else
      failure_reason=wallet_driver_failed
    fi
    echo "test-lab-adversarial: ${case_id}: wallet driver failed" >&2
    exit "${driver_status}"
  fi

  current_phase=sanitized-evidence
  python3 - "${fixture}" "${private_root}" "${private_root}/evidence/infrastructure.json" \
    "${private_root}/evidence/driver.json" "${record_path}" "${case_id}" "${expected}" <<'PY'
import json
import os
import pathlib
import re
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
private_root = pathlib.Path(sys.argv[2])
infrastructure = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
driver_path = pathlib.Path(sys.argv[4])
if driver_path.stat().st_size > 16384:
    raise SystemExit("driver evidence exceeds its input bound")
driver = json.loads(driver_path.read_text(encoding="utf-8"))
case_id = sys.argv[6]
expected = sys.argv[7]
if (
    driver.get("schema") != "openagents.immortal.adversarial-case-result.v1"
    or driver.get("case_id") != case_id
    or driver.get("expected") != expected
    or driver.get("passed") is not True
):
    raise SystemExit("wallet driver did not prove the selected manifest case")
banned = {
    "claim_key", "macaroon", "password", "preimage", "private_key",
    "raw_signed_event", "raw_transaction", "raw_wrap_event", "refund_key",
    "seed", "secret", "musig_secret_nonce",
}
def scan(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower().replace("-", "_") in banned:
                raise SystemExit(f"retained evidence contains banned member {key}")
            scan(child)
    elif isinstance(value, list):
        for child in value:
            scan(child)
scan(driver)
record = {
    "schema": fixture["evidence"]["retained_record"]["schema"],
    "case_id": case_id,
    "expected": expected,
    "infrastructure": infrastructure,
    "result": driver,
    "local_only": True,
}
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
for name in (
    "relay-a-postgres-password", "relay-b-postgres-password",
    "provider-a-postgres-password", "provider-b-postgres-password",
    "provider-a-wallet-seed", "provider-b-wallet-seed", "client-wallet-seed",
):
    secret = (private_root / name).read_bytes().strip()
    if secret and secret in encoded:
        raise SystemExit("retained evidence contains an exact private value")
maximum = min(32768, fixture["evidence"]["retained_record"]["maximum_bytes"])
if len(encoded) > maximum:
    raise SystemExit("case evidence exceeds its retained bound")
path = pathlib.Path(sys.argv[5])
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(path.parent, 0o700)
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY
  current_phase=complete
  echo "test-lab-adversarial: ${case_id}: passed; sanitized record ${record_path}"
)

aggregate_records() {
  local aggregate_path
  aggregate_path="$(python3 - "${fixture}" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["evidence"]["retained_record"]["default_path"])
PY
)"
  python3 - "${fixture}" "${case_file}" "${record_dir}" "${aggregate_path}" <<'PY'
import json
import os
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = [line.rstrip("\n").split("\t") for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()]
record_dir = pathlib.Path(sys.argv[3])
records = []
for case_id, _, expected, _ in rows:
    record = json.loads((record_dir / f"{case_id}.json").read_text(encoding="utf-8"))
    if record.get("case_id") != case_id or record.get("expected") != expected:
        raise SystemExit("case record does not bind the manifest row")
    records.append(record)
aggregate = {
    "schema": fixture["evidence"]["retained_record"]["schema"],
    "case_count": len(records),
    "cases": records,
    "claims": fixture["claims"],
}
encoded = (json.dumps(aggregate, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > fixture["evidence"]["retained_record"]["maximum_bytes"]:
    raise SystemExit("aggregate adversarial record exceeds its bound")
path = pathlib.Path(sys.argv[4])
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(path.parent, 0o700)
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY
  echo "test-lab-adversarial: full sanitized record ${aggregate_path}"
}

if test "${selection}" = case; then
  while IFS=$'\t' read -r case_id group expected provider; do
    if test "${case_id}" = "${selected_case}"; then
      run_case "${case_id}" "${group}" "${expected}" "${provider}"
      exit 0
    fi
  done <"${case_file}"
fi

while IFS=$'\t' read -r case_id group expected provider; do
  run_case "${case_id}" "${group}" "${expected}" "${provider}"
done <"${case_file}"
aggregate_records
