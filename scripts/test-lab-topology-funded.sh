#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

support_dir="scripts/support/provider-funded"
base_compose="${support_dir}/compose.yaml"
topology_compose="${support_dir}/topology-compose.yaml"
dynamic_mode="${IMMORTAL_LAB_DYNAMIC_TOPOLOGY:-0}"
if ! [[ "${dynamic_mode}" =~ ^[01]$ ]]; then
  echo "test-lab-topology-funded: dynamic mode must be 0 or 1" >&2
  exit 1
fi
if test "${dynamic_mode}" = 1; then
  fixture="tests/fixtures/lab/dynamic-public-regtest-v1.json"
  record_path="${IMMORTAL_LAB_FUNDED_TOPOLOGY_RECORD:-target/lab-evidence/dynamic-public-regtest-v1.json}"
  topology_command=dynamic-funded-topology
else
  fixture="tests/fixtures/lab/topology-funded-v1.json"
  record_path="${IMMORTAL_LAB_FUNDED_TOPOLOGY_RECORD:-target/lab-evidence/topology-funded-v1.json}"
  topology_command=funded-topology
fi
private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-funded-topology.XXXXXX")"
project_name="immortal-funded-topology-$(LC_ALL=C od -An -N 6 -tx1 /dev/urandom | tr -d ' \n')"
compose_ready=false
compose_prefix=()
current_phase=initialization

write_failure_record() {
  local exit_status="$1"
  python3 - "${fixture}" "${record_path}" "${current_phase}" "${exit_status}" <<'PY'
import json, os, pathlib, sys
fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
path = pathlib.Path(sys.argv[2])
failure_schema = fixture.get("retained_record", {}).get(
    "failure_schema", "openagents.immortal.dynamic-funded-topology-failure.v1"
)
record = {
    "schema": failure_schema,
    "phase": sys.argv[3],
    "exit_status": int(sys.argv[4]),
    "private_artifacts_retained": False,
}
path.parent.mkdir(parents=True, exist_ok=True)
os.chmod(path.parent, 0o700)
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(record, output, indent=2, sort_keys=True)
    output.write("\n")
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
    "${compose_prefix[@]}" logs --no-color >"${private_root}/runtime.log" 2>&1 || true
    if ! "${compose_prefix[@]}" down --volumes --remove-orphans --rmi local >/dev/null 2>&1; then
      echo "test-lab-topology-funded: disposable container cleanup failed" >&2
      exit_status=1
    fi
  fi
  if test "${exit_status}" -ne 0; then
    write_failure_record "${exit_status}" || true
    if test -s "${private_root}/driver-error.log"; then
      echo "test-lab-topology-funded: bounded driver error follows" >&2
      sed -n '1,120p' "${private_root}/driver-error.log" >&2
    elif test -s "${private_root}/evidence/driver.json"; then
      echo "test-lab-topology-funded: bounded driver output follows" >&2
      sed -n '1,120p' "${private_root}/evidence/driver.json" >&2
    fi
  fi
  case "$(basename "${private_root}")" in
  immortal-funded-topology.*)
    if test -f "${private_root}/owned"; then
      rm -rf -- "${private_root}"
    else
      echo "test-lab-topology-funded: private root lost its ownership marker" >&2
      exit_status=1
    fi
    ;;
  *)
    echo "test-lab-topology-funded: refused to remove an unexpected private root" >&2
    exit_status=1
    ;;
  esac
  if test "${exit_status}" -ne 0; then
    echo "test-lab-topology-funded: failed during ${current_phase}" >&2
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

umask 077
touch "${private_root}/owned"
mkdir -m 0700 "${private_root}/evidence" "${private_root}/state" \
  "${private_root}/lnd-credentials"
for credential_name in tls.cert readonly.macaroon invoice.macaroon router.macaroon; do
  : >"${private_root}/lnd-credentials/${credential_name}"
done

random_hex() {
  local byte_count="$1"
  LC_ALL=C od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

python3 - "${fixture}" "${dynamic_mode}" <<'PY'
import json, pathlib, sys
fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if sys.argv[2] == "1":
    if (
        fixture.get("schema") != "openagents.immortal.dynamic-public-regtest-fixture.v1"
        or fixture.get("live_journeys") != ["reverse", "submarine"]
        or fixture.get("quote_count") != 2
    ):
        raise SystemExit("dynamic topology fixture has another contract")
    raise SystemExit(0)
if fixture.get("schema") != "openagents.immortal.lab-funded-topology.v1":
    raise SystemExit("funded topology fixture has another schema")
if fixture.get("selection", {}).get("ordering") != [
    "output_amount_desc", "maximum_total_fee_asc", "provider_pubkey_asc", "quote_id_asc"
]:
    raise SystemExit("funded topology fixture has another selection policy")
if fixture.get("unselected", {}).get("reservation_release_cause") != "terminal_close":
    raise SystemExit("funded topology fixture has another durable release contract")
PY

bitcoin_rpc_password="$(random_hex 32)"
relay_a_postgres_password="$(random_hex 32)"
relay_b_postgres_password="$(random_hex 32)"
provider_a_postgres_password="$(random_hex 32)"
provider_b_postgres_password="$(random_hex 32)"
provider_a_identity="$(random_hex 32)"
provider_b_identity="$(random_hex 32)"
provider_a_seed="$(random_hex 32)"
provider_b_seed="$(random_hex 32)"
client_seed="$(random_hex 32)"
terminal_confirmations=3

printf '%s\n' "${relay_a_postgres_password}" >"${private_root}/relay-postgres-password"
printf '%s\n' "${relay_b_postgres_password}" >"${private_root}/relay-b-postgres-password"
printf '%s\n' "${provider_a_postgres_password}" >"${private_root}/provider-postgres-password"
printf '%s\n' "${provider_b_postgres_password}" >"${private_root}/provider-b-postgres-password"
printf '%s\n' "${provider_a_seed}" >"${private_root}/provider-wallet-seed"
printf '%s\n' "${provider_b_seed}" >"${private_root}/provider-b-wallet-seed"
printf '%s\n' "${client_seed}" >"${private_root}/client-wallet-seed"

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

write_cln_config() {
  local path="$1" bind_port="$2" announce_name="$3" hold="$4"
  cat >"${path}" <<EOF
network=regtest
lightning-dir=/root/.lightning
rpc-file=/rail-rpc/lightning-rpc
rpc-file-mode=0660
bitcoin-rpcconnect=bitcoin
bitcoin-rpcport=18443
bitcoin-rpcuser=immortal-smoke
bitcoin-rpcpassword=${bitcoin_rpc_password}
bind-addr=0.0.0.0:${bind_port}
announce-addr=${announce_name}:${bind_port}
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
write_cln_config "${private_root}/cln-provider.conf" 19846 cln-provider true
write_cln_config "${private_root}/cln-provider-b.conf" 19847 cln-provider-b true
write_cln_config "${private_root}/cln-peer.conf" 19848 cln-peer false
: >"${private_root}/lnd-provider.conf"

cat >"${private_root}/relay.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_a_postgres_password}@relay-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18080
IMMORTAL_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF
cat >"${private_root}/relay-b.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${relay_b_postgres_password}@relay-b-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=127.0.0.1
IMMORTAL_PORT=18081
IMMORTAL_RELAY_URL=ws://127.0.0.1:18081
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF

write_provider_env() {
  local path="$1" database_host="$2" database_password="$3" relay_port="$4"
  local identity="$5" socket_path="$6" seed_path="$7" health_port="$8" spread="$9" boltz_port="${10}"
  cat >"${path}" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${database_password}@${database_host}:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:${relay_port}
IMMORTAL_PROVIDER_IDENTITY_SECRET=${identity}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=immortal-smoke
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${bitcoin_rpc_password}
IMMORTAL_PROVIDER_CLN_RPC_PATH=${socket_path}
IMMORTAL_PROVIDER_WALLET_SEED_FILE=${seed_path}
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:${health_port}
IMMORTAL_PROVIDER_ALERT_URL=http://127.0.0.1:19092/provider-alert
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=10
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=1
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=2
IMMORTAL_PROVIDER_SPREAD_BPS=${spread}
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=600
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
IMMORTAL_PROVIDER_BOLTZ_BIND=127.0.0.1:${boltz_port}
IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256=$(cargo run --locked --quiet -p immortal-provider -- contract | jq -er '.operations.boltz_compatibility.conformance_sha256')
IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN=http://127.0.0.1
EOF
}
write_provider_env "${private_root}/provider.env" provider-postgres \
  "${provider_a_postgres_password}" 18080 "${provider_a_identity}" \
  /rail/cln-provider/lightning-rpc /run/immortal-private/provider-wallet-seed 9091 100 19093
write_provider_env "${private_root}/provider-b.env" provider-b-postgres \
  "${provider_b_postgres_password}" 18081 "${provider_b_identity}" \
  /rail/cln-provider-b/lightning-rpc /run/immortal-private/provider-b-wallet-seed 9092 100 19094
cp "${private_root}/provider.env" "${private_root}/provider-lnd.env"

cat >"${private_root}/driver-topology.env" <<EOF
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_URLS=ws://127.0.0.1:18080,ws://127.0.0.1:18081
IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_HEALTH_URLS=http://127.0.0.1:9091/healthz,http://127.0.0.1:9092/healthz
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_USER=immortal-smoke
IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_PASSWORD=${bitcoin_rpc_password}
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLN_RPC_PATH=/rail/cln-peer/lightning-rpc
IMMORTAL_LAB_DYNAMIC_PROVIDER_CLN_RPC_PATHS=/rail/cln-provider/lightning-rpc,/rail/cln-provider-b/lightning-rpc
IMMORTAL_PROVIDER_FUNDED_SMOKE_CLIENT_WALLET_SEED_FILE=/run/immortal-private/client-wallet-seed
IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE=/evidence/topology-funded-driver.json
IMMORTAL_PROVIDER_FUNDED_SMOKE_TERMINAL_CONFIRMATIONS=${terminal_confirmations}
IMMORTAL_LAB_STATE_DIR=/state
EOF
cp "${private_root}/driver-topology.env" "${private_root}/driver.env"
cat >"${private_root}/compose.env" <<EOF
IMMORTAL_PROVIDER_SMOKE_PRIVATE_DIR=${private_root}
IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST=127.0.0.1
IMMORTAL_LAB_TOPOLOGY_COMMAND=${topology_command}
EOF

if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_prefix=(docker compose --env-file "${private_root}/compose.env" \
    --file "${base_compose}" --file "${topology_compose}" --project-name "${project_name}")
elif podman info >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
  compose_prefix=(podman compose --env-file "${private_root}/compose.env" \
    --file "${base_compose}" --file "${topology_compose}" --project-name "${project_name}")
else
  echo "test-lab-topology-funded: start Docker Desktop or Podman Compose" >&2
  exit 1
fi
compose_ready=true
compose() { "${compose_prefix[@]}" "$@"; }
wait_for() {
  local description="$1"
  shift
  for _ in $(seq 1 240); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "test-lab-topology-funded: ${description} did not become ready" >&2
  return 1
}
bitcoin_cli() {
  compose exec -T bitcoin bitcoin-cli -conf=/run/immortal-private/bitcoin.conf \
    -datadir=/var/lib/bitcoin "$@"
}
cln_cli() {
  local service="$1"
  shift
  compose exec -T "${service}" lightning-cli --network=regtest \
    --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc "$@"
}
cln_channels_ready() {
  local service="$1"
  cln_cli "${service}" listpeerchannels |
    jq -e '[.channels[] | select(.state == "CHANNELD_NORMAL")] | length == 2'
}
cln_wallet_ready() {
  local service="$1" expected_height="$2" actual_height
  actual_height="$(cln_cli "${service}" getinfo | jq -er .blockheight)"
  if test "${actual_height}" -lt "${expected_height}"; then return 1; fi
  cln_cli "${service}" listfunds |
    jq -e 'any(.outputs[]; .status == "confirmed")'
}

current_phase=compose-validation
compose config --quiet
current_phase=image-build
compose build bitcoin cln-provider cln-provider-b cln-peer relay relay-b provider provider-b driver alert-sink \
  >"${private_root}/build.log" 2>&1
current_phase=base-startup
compose up --detach bitcoin relay-postgres relay-b-postgres provider-postgres provider-b-postgres \
  >"${private_root}/startup.log" 2>&1
wait_for "Bitcoin Core" bitcoin_cli getblockchaininfo
wait_for "relay A Postgres" compose exec -T relay-postgres pg_isready -U immortal_relay -d immortal_relay
wait_for "relay B Postgres" compose exec -T relay-b-postgres pg_isready -U immortal_relay -d immortal_relay
wait_for "provider A Postgres" compose exec -T provider-postgres pg_isready -U immortal_provider -d immortal_provider
wait_for "provider B Postgres" compose exec -T provider-b-postgres pg_isready -U immortal_provider -d immortal_provider

current_phase=rail-startup
compose up --detach relay relay-b cln-provider cln-provider-b cln-peer alert-sink \
  >>"${private_root}/startup.log" 2>&1
for service in cln-provider cln-provider-b cln-peer; do
  wait_for "${service}" cln_cli "${service}" getinfo
done
for service in cln-provider cln-provider-b; do
  for method in holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice; do
    cln_cli "${service}" -J -k help command="${method}" | jq -e \
      --arg method "${method}" '.help | any(.[]; .command | startswith($method))' >/dev/null
  done
done
wait_for "relay A" compose run --rm --no-deps --entrypoint /usr/bin/curl provider \
  --fail --silent http://127.0.0.1:18080/health
wait_for "relay B" compose run --rm --no-deps --entrypoint /usr/bin/curl provider \
  --fail --silent http://127.0.0.1:18081/health

current_phase=rail-funding
bitcoin_cli createwallet smoke-miner >/dev/null
miner_address="$(bitcoin_cli -rpcwallet=smoke-miner getnewaddress)"
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 110 "${miner_address}" >/dev/null
for service in cln-provider cln-provider-b cln-peer; do
  address="$(cln_cli "${service}" newaddr bech32 | jq -er .bech32)"
  bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${address}" 3.0 >/dev/null
done
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null
chain_height="$(bitcoin_cli getblockcount)"
for service in cln-provider cln-provider-b cln-peer; do
  wait_for "${service} wallet funding" cln_wallet_ready "${service}" "${chain_height}"
done

current_phase=channel-a-wallet
wallet_id="$(cln_cli cln-peer getinfo | jq -er .id)"
provider_b_id="$(cln_cli cln-provider-b getinfo | jq -er .id)"
cln_cli cln-provider connect "${wallet_id}@cln-peer:19848" >/dev/null
cln_cli cln-provider -k fundchannel id="${wallet_id}" amount=2000000sat \
  feerate=253perkw announce=false push_msat=1000000000msat >/dev/null
current_phase=channel-b-wallet
cln_cli cln-provider-b connect "${wallet_id}@cln-peer:19848" >/dev/null
cln_cli cln-provider-b -k fundchannel id="${wallet_id}" amount=2000000sat \
  feerate=253perkw announce=false push_msat=1000000000msat >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 1 "${miner_address}" >/dev/null
post_pair_height="$(bitcoin_cli getblockcount)"
wait_for "provider A channel change" cln_wallet_ready cln-provider "${post_pair_height}"
current_phase=channel-a-b
if ! cln_cli cln-provider connect "${provider_b_id}@cln-provider-b:19847" \
  >"${private_root}/channel-a-b-connect.log" 2>&1; then
  sed -n '1,20p' "${private_root}/channel-a-b-connect.log" >&2
  exit 1
fi
if ! cln_cli cln-provider -k fundchannel id="${provider_b_id}" amount=1000000sat \
  feerate=253perkw announce=false push_msat=500000000msat \
  >"${private_root}/channel-a-b-fund.log" 2>&1; then
  sed -n '1,20p' "${private_root}/channel-a-b-fund.log" >&2
  exit 1
fi
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 6 "${miner_address}" >/dev/null
current_phase=channel-readiness
for service in cln-provider cln-provider-b cln-peer; do
  wait_for "${service} balanced channels" cln_channels_ready "${service}"
  cln_cli "${service}" getinfo >"${private_root}/evidence/${service}-info.json"
  cln_cli "${service}" listpeerchannels >"${private_root}/evidence/${service}-channels.json"
done

current_phase=provider-wallet-funding
provider_a_address="$(compose run --rm --no-deps provider address | tr -d '\r\n')"
provider_b_address="$(compose run --rm --no-deps provider-b address | tr -d '\r\n')"
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${provider_a_address}" 1.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner sendtoaddress "${provider_b_address}" 1.0 >/dev/null
bitcoin_cli -rpcwallet=smoke-miner generatetoaddress 2 "${miner_address}" >/dev/null

current_phase=provider-startup
compose up --detach provider provider-b >>"${private_root}/startup.log" 2>&1
wait_for "provider A" compose exec -T provider /usr/bin/curl --fail --silent http://127.0.0.1:9091/healthz
wait_for "provider B" compose exec -T provider-b /usr/bin/curl --fail --silent http://127.0.0.1:9092/healthz

current_phase=funded-driver
set +e
compose run --no-deps -T driver >"${private_root}/evidence/driver.json" \
  2>"${private_root}/driver-error.log"
driver_status=$?
set -e
if test "${driver_status}" -ne 0; then
  compose logs --no-color driver >"${private_root}/driver-container.log" 2>&1 || true
  compose logs --no-color provider provider-b >"${private_root}/provider-container.log" 2>&1 || true
  echo "test-lab-topology-funded: driver exited ${driver_status}" >&2
  sed -n '1,120p' "${private_root}/driver-error.log" >&2
  sed -n '1,160p' "${private_root}/evidence/driver.json" >&2
  sed -n '1,160p' "${private_root}/driver-container.log" >&2
  sed -n '1,240p' "${private_root}/provider-container.log" >&2
  exit "${driver_status}"
fi
if test "${dynamic_mode}" = 1; then
  current_phase=dynamic-evidence
  jq -e '
    .schema == "openagents.immortal.dynamic-funded-topology-result.v1" and
    .network == "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4" and
    .amount_sat == 150000 and
    (.provider_pubkeys | length) == 2 and
    (.provider_pubkeys | unique | length) == 2 and
    (.journeys | length) == 2 and
    ([.journeys[].swap_type] | sort) == ["reverse", "submarine"] and
    all(.journeys[];
      (.quotes | length) == 2 and
      ([.quotes[].provider_pubkey] | unique | length) == 2 and
      .unselected.outcome == "cancelled" and
      .unselected.external_spend_effects == 0 and
      .terminal.result == "claimed" and
      .terminal_authority == "requester_admitted_bitcoin_and_lightning_evidence" and
      (.request.destination_commitment_sha256 | length) == 64
    ) and
    (first(.journeys[] | select(.swap_type == "reverse")) |
      .request.destination_kind == "bitcoin_address" and
      .request.destination_amount_sat == null and
      (.destination_output.amount_sat > 0) and
      (.destination_output.commitment_sha256 == .request.destination_commitment_sha256)
    ) and
    (first(.journeys[] | select(.swap_type == "submarine")) |
      .request.destination_kind == "bolt11_invoice" and
      (.request.destination_amount_sat > 0) and
      (.request.payment_hash == .terminal.payment_hash)
    )
  ' "${private_root}/evidence/driver.json" >/dev/null
  if grep -Eiq '"(invoice|preimage|raw_transaction|wallet_seed|rpc_password|macaroon)"[[:space:]]*:' \
    "${private_root}/evidence/driver.json"; then
    echo "test-lab-topology-funded: dynamic public evidence contains custody material" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${record_path}")"
  chmod 0700 "$(dirname "${record_path}")"
  cp "${private_root}/evidence/driver.json" "${record_path}"
  chmod 0600 "${record_path}"
  echo "test-lab-topology-funded: dynamic reverse and submarine two-provider gate passed"
  exit 0
fi
selected_order_id="$(jq -er .selected.order_id "${private_root}/evidence/driver.json")"
unselected_order_id="$(jq -er .unselected.order_id "${private_root}/evidence/driver.json")"
lockup_txid="$(jq -er .selected.lockup_txid "${private_root}/evidence/driver.json")"
claim_txid="$(jq -er .selected.claim_txid "${private_root}/evidence/driver.json")"
payment_hash="$(jq -er .selected.payment_hash "${private_root}/evidence/driver.json")"
cancel_request_id="$(jq -er .unselected.cancel_request_id "${private_root}/evidence/driver.json")"
cancel_accepted_id="$(jq -er .unselected.cancel_accepted_id "${private_root}/evidence/driver.json")"
cancel_effective_id="$(jq -er .unselected.cancel_effective_id "${private_root}/evidence/driver.json")"
cancel_close_id="$(jq -er .unselected.close_id "${private_root}/evidence/driver.json")"

current_phase=evidence-collection
bitcoin_cli getrawtransaction "${lockup_txid}" true >"${private_root}/evidence/lockup.json"
bitcoin_cli getrawtransaction "${claim_txid}" true >"${private_root}/evidence/claim.json"
bitcoin_cli getrawmempool >"${private_root}/evidence/mempool.json"
cln_cli cln-peer -k listinvoices payment_hash="${payment_hash}" \
  >"${private_root}/evidence/wallet-invoice.json"
cln_cli cln-provider -k listpays payment_hash="${payment_hash}" \
  >"${private_root}/evidence/provider-a-pays.json"
cln_cli cln-provider-b -k listpays payment_hash="${payment_hash}" \
  >"${private_root}/evidence/provider-b-pays.json"
for provider in a b; do
  if test "${provider}" = a; then database_service=provider-postgres; else database_service=provider-b-postgres; fi
  compose exec -T "${database_service}" psql -X --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 -U immortal_provider -d immortal_provider \
    --set="selected_order_id=${selected_order_id}" \
    --set="unselected_order_id=${unselected_order_id}" \
    --set="cancel_request_id=${cancel_request_id}" \
    --set="cancel_accepted_id=${cancel_accepted_id}" \
    --set="cancel_effective_id=${cancel_effective_id}" \
    --set="cancel_close_id=${cancel_close_id}" \
    <"${support_dir}/topology_evidence.sql" \
    >"${private_root}/evidence/provider-${provider}-database.json"
done
compose exec -T provider /usr/bin/curl --fail --silent http://127.0.0.1:9091/metrics \
  >"${private_root}/evidence/provider-a-metrics.txt"
compose exec -T provider-b /usr/bin/curl --fail --silent http://127.0.0.1:9092/metrics \
  >"${private_root}/evidence/provider-b-metrics.txt"

current_phase=sanitized-record
python3 - "${fixture}" "${private_root}/evidence" "${record_path}" <<'PY'
import json, os, pathlib, platform, sys
fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
evidence = pathlib.Path(sys.argv[2])
record_path = pathlib.Path(sys.argv[3])
driver = json.loads((evidence / "driver.json").read_text(encoding="utf-8"))
if driver.get("schema") != "openagents.immortal.funded-topology-result.v1":
    raise SystemExit("funded topology driver returned another schema")

roles = [("provider-a", "cln-provider"), ("provider-b", "cln-provider-b"), ("wallet", "cln-peer")]
cln = []
for role, service in roles:
    info = json.loads((evidence / f"{service}-info.json").read_text(encoding="utf-8"))
    channels = json.loads((evidence / f"{service}-channels.json").read_text(encoding="utf-8"))["channels"]
    normal = sum(channel.get("state") == "CHANNELD_NORMAL" for channel in channels)
    if normal != 2:
        raise SystemExit(f"{role} does not have two normal channels")
    cln.append({"role": role, "node_id": info["id"], "normal_channel_count": normal})
if len({row["node_id"] for row in cln}) != 3:
    raise SystemExit("funded topology CLN identities are not distinct")

databases = {}
for provider in ("a", "b"):
    value = json.loads((evidence / f"provider-{provider}-database.json").read_text(encoding="utf-8"))
    if value.get("matched_role_count") != 1:
        raise SystemExit(f"provider {provider} database did not resolve exactly one role")
    if value.get("allocated_capacity") != 0:
        raise SystemExit(f"provider {provider} retained allocated capacity")
    role, row = next(iter(value["roles"].items()))
    expected_disposition = "provider_close_completed" if role == "selected" else "provider_close_cancelled"
    if (
        row["disposition"] != expected_disposition
        or row["reservation_total"] != 1
        or row["reservation_released"] != 1
        or row["reservation_active"] != 0
        or row["reservation_unresolved"] != 0
        or row["release_cause"] != "terminal_close"
        or row["effect_pending"] != 0
        or row["effect_unresolved"] != 0
        or row["watch_pending"] != 0
        or row["watch_unresolved"] != 0
        or (role == "unselected" and row["watch_total"] != 0)
        or (role == "unselected" and row["cancel_record_count"] != 4)
        or (role == "selected" and row["cancel_record_count"] != 0)
    ):
        raise SystemExit(f"provider {provider} durable evidence is incomplete")
    databases[f"provider-{provider}"] = {"role": role, **row}
if {value["role"] for value in databases.values()} != {"selected", "unselected"}:
    raise SystemExit("provider databases did not split selected and unselected roles")

lockup = json.loads((evidence / "lockup.json").read_text(encoding="utf-8"))
claim = json.loads((evidence / "claim.json").read_text(encoding="utf-8"))
if lockup.get("confirmations", 0) < 1 or claim.get("confirmations", 0) < 3:
    raise SystemExit("selected chain evidence lacks confirmations")
if not any(row.get("txid") == lockup.get("txid") for row in claim.get("vin", [])):
    raise SystemExit("selected claim does not spend the selected lockup")
if json.loads((evidence / "mempool.json").read_text(encoding="utf-8")):
    raise SystemExit("funded topology left a transaction in the mempool")
invoice = json.loads((evidence / "wallet-invoice.json").read_text(encoding="utf-8"))["invoices"]
if len(invoice) != 1 or invoice[0].get("status") != "paid":
    raise SystemExit("wallet invoice is not paid")
selected_provider = driver["selection"]["selected_provider_pubkey"]
selected_candidate = next(row for row in driver["candidates"] if row["provider_pubkey"] == selected_provider)
selected_service = "a" if selected_candidate["relay_url"].endswith(":18080") else "b"
unselected_service = "b" if selected_service == "a" else "a"
selected_pays = json.loads((evidence / f"provider-{selected_service}-pays.json").read_text(encoding="utf-8"))["pays"]
unselected_pays = json.loads((evidence / f"provider-{unselected_service}-pays.json").read_text(encoding="utf-8"))["pays"]
if (
    len(selected_pays) != 1
    or selected_pays[0].get("status") != "complete"
    or selected_pays[0].get("payment_hash") != driver["selected"]["payment_hash"]
    or unselected_pays
):
    raise SystemExit("provider Lightning effects do not match the selection")
for provider in ("a", "b"):
    metrics = (evidence / f"provider-{provider}-metrics.txt").read_text(encoding="utf-8")
    for line in ("immortal_provider_ready 1", "immortal_provider_watch_jobs_pending 0", "immortal_provider_watch_jobs_unresolved 0"):
        if line not in metrics.splitlines():
            raise SystemExit(f"provider {provider} metrics are not terminal")

record = {
    "schema": fixture["retained_record"]["schema"],
    "platform": {"os": platform.system(), "release": platform.release(), "machine": platform.machine()},
    "topology": {"cln": cln, "relay_count": 2, "provider_count": 2, "provider_database_count": 2},
    "selection": driver["selection"] | {"candidates": driver["candidates"]},
    "selected": {
        "provider_pubkey": selected_provider,
        "order_id": driver["selected"]["order_id"],
        "lockup_txid": driver["selected"]["lockup_txid"],
        "claim_txid": driver["selected"]["claim_txid"],
        "payment_hash": driver["selected"]["payment_hash"],
        "result": driver["selected"]["result"],
        "lockup_confirmations": lockup["confirmations"],
        "claim_confirmations": claim["confirmations"],
        "lightning_state": "paid",
    },
    "unselected": driver["unselected"],
    "provider_databases": databases,
}
if set(record) != {"schema", *fixture["retained_record"]["allowed_sections"]}:
    raise SystemExit("retained funded topology record has an unapproved section")
banned = {"seed", "secret", "preimage", "macaroon", "password", "private_key", "raw_transaction", "raw_signed_event", "raw_wrap_event"}
def scan(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("-", "_") in banned:
                raise SystemExit(f"retained record contains banned member {key}")
            scan(child)
    elif isinstance(value, list):
        for child in value: scan(child)
scan(record)
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > fixture["bounds"]["maximum_retained_record_bytes"]:
    raise SystemExit("retained funded topology record exceeds its bound")
record_path.parent.mkdir(parents=True, exist_ok=True)
os.chmod(record_path.parent, 0o700)
temporary = record_path.with_name(record_path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded); output.flush(); os.fsync(output.fileno())
os.replace(temporary, record_path)
os.chmod(record_path, 0o600)
PY

if test -e "${private_root}/evidence/provider-alert.json"; then
  echo "test-lab-topology-funded: provider emitted an operator alert" >&2
  exit 1
fi
current_phase=complete
echo "test-lab-topology-funded: two hard Quotes, rank-two cancellation, and rank-one funded settlement passed"
echo "test-lab-topology-funded: sanitized record ${record_path}"
