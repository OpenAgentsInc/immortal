#!/usr/bin/env bash
# Disposable Elements regtest rail gate. Provider-daemon process wiring is a
# separate acceptance boundary.
set -euo pipefail
cd "$(dirname "$0")/.."

lab_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-liquid-XXXXXX")"
case "${lab_root}" in
  "${TMPDIR:-/tmp}"/immortal-liquid-*) ;;
  *) echo "provider-liquid: unsafe temporary directory" >&2; exit 1 ;;
esac
active=false
current_phase=initialization

cleanup() {
  local status=$?
  set +e
  if test "${status}" -ne 0; then
    echo "provider-liquid: failed during ${current_phase}" >&2
    if test -f "${result_file:-}"; then
      jq 'to_entries | map({key, type:(.value | type)})' "${result_file}" >&2 || true
    fi
  fi
  if test "${active}" = true; then
    if IMMORTAL_LAB_DIR="${lab_root}" scripts/lab-extensions.sh down elementsd >/dev/null; then
      active=false
    else
      echo "provider-liquid: teardown failed; retained ${lab_root}" >&2
      if test "${status}" -eq 0; then
        status=1
      fi
    fi
  fi
  if test "${active}" = false; then
    if test -d "${lab_root}/extensions" && ! rmdir "${lab_root}/extensions" >/dev/null 2>&1; then
      echo "provider-liquid: unexpected state remains under ${lab_root}/extensions" >&2
      status=1
    fi
    if ! rmdir "${lab_root}" >/dev/null 2>&1; then
      echo "provider-liquid: temporary root is not empty: ${lab_root}" >&2
      status=1
    fi
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

current_phase=elements-startup
IMMORTAL_LAB_DIR="${lab_root}" scripts/lab-extensions.sh up elementsd
active=true
IMMORTAL_LAB_DIR="${lab_root}" scripts/lab-extensions.sh status elementsd >/dev/null

extension_dir="${lab_root}/extensions/elementsd"
connection_file="${extension_dir}/connection.env"
record_file="${extension_dir}/elementsd-process.json"
test -f "${connection_file}"
test "$(stat -f '%Lp' "${connection_file}" 2>/dev/null || stat -c '%a' "${connection_file}")" = 600
container_name="$(jq -er '.container_name' "${record_file}")"
run_id="$(jq -er '.run_id' "${record_file}")"

set -a
# Generated in the mode-0600 extension state and removed during teardown.
source "${connection_file}"
set +a
export -n \
  IMMORTAL_PROVIDER_LIQUID_ENABLED \
  IMMORTAL_PROVIDER_ELEMENTSD_HOST \
  IMMORTAL_PROVIDER_ELEMENTSD_PORT \
  IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER \
  IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD \
  IMMORTAL_PROVIDER_ELEMENTSD_WALLET \
  IMMORTAL_PROVIDER_LIQUID_NETWORK_ID \
  IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET
test "$(jq -er '.rpc_host_port' "${record_file}")" = "${IMMORTAL_PROVIDER_ELEMENTSD_PORT}"

elements_cli() {
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest "$@"
}

wallet_cli() {
  local wallet="$1"
  shift
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet="${wallet}" "$@"
}

elements_cli_stdin() {
  docker exec -i "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -stdin "$@"
}

wallet_cli_stdin() {
  local wallet="$1"
  shift
  docker exec -i "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet="${wallet}" -stdin "$@"
}

current_phase=wallet-seeding
wallet_result="$(elements_cli -named createwallet wallet_name=requester-liquid descriptors=true)"
printf '%s' "${wallet_result}" | jq -e '.name == "requester-liquid"' >/dev/null

requester_address="$(wallet_cli requester-liquid getnewaddress)"
requester_confidential="$(wallet_cli requester-liquid getaddressinfo "${requester_address}" | jq -er '.confidential')"
requester_funding_txid="$(wallet_cli provider-liquid sendtoaddress "${requester_confidential}" 1.0)"
requester_funding_raw="$(wallet_cli provider-liquid gettransaction "${requester_funding_txid}" | jq -er '.hex')"
test "$(elements_cli sendrawtransaction "${requester_funding_raw}")" = "${requester_funding_txid}"
mining_address="$(wallet_cli provider-liquid getnewaddress)"
wallet_cli provider-liquid generatetoaddress 1 "${mining_address}" >/dev/null

confidential_address="$(wallet_cli provider-liquid getnewaddress)"
confidential_script="$(wallet_cli provider-liquid getaddressinfo "${confidential_address}" | jq -er '.scriptPubKey')"
confidential_amount_sats=1000000
confidential_txid="$(wallet_cli requester-liquid sendtoaddress "${confidential_address}" 0.01000000)"
confidential_raw="$(wallet_cli requester-liquid gettransaction "${confidential_txid}" | jq -er '.hex')"
test "$(elements_cli sendrawtransaction "${confidential_raw}")" = "${confidential_txid}"
confidential_output_index="$(elements_cli decoderawtransaction "${confidential_raw}" | \
  jq -er --arg script "${confidential_script}" \
  '[.vout[] | select(.scriptPubKey.hex == $script) | .n] | if length == 1 then .[0] else error("confidential output") end')"
wallet_seed_hex=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
wallet_seed_file="${extension_dir}/provider-wallet-seed"
result_file="${extension_dir}/live-result.json"
umask 077
printf '%s\n' "${wallet_seed_hex}" >"${wallet_seed_file}"
chmod 600 "${wallet_seed_file}"

live_test() {
  local test_name="$1"
  local output_file="${extension_dir}/live-test-output"
  umask 077
  if ! IMMORTAL_LIQUID_LIVE_RPC_PORT="${IMMORTAL_PROVIDER_ELEMENTSD_PORT}" \
    IMMORTAL_LIQUID_LIVE_RPC_USER="${IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER}" \
    IMMORTAL_LIQUID_LIVE_RPC_PASSWORD="${IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD}" \
    IMMORTAL_LIQUID_LIVE_NETWORK_ID="${IMMORTAL_PROVIDER_LIQUID_NETWORK_ID}" \
    IMMORTAL_LIQUID_LIVE_ASSET_ID="${IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET}" \
    IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_RAW="${confidential_raw}" \
    IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_OUTPUT_INDEX="${confidential_output_index}" \
    IMMORTAL_LIQUID_LIVE_CONFIDENTIAL_AMOUNT="${confidential_amount_sats}" \
    IMMORTAL_LIQUID_LIVE_SEED_FILE="${wallet_seed_file}" \
    IMMORTAL_LIQUID_LIVE_RESULT_FILE="${result_file}" \
      cargo test --locked -p immortal-provider --test provider_liquid "${test_name}" -- \
        --ignored --exact --nocapture >"${output_file}" 2>&1; then
    for secret in "${wallet_seed_hex}" "${IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD}"; do
      if printf '%s\n' "${secret}" | rg -Fq -f - "${output_file}"; then
        echo "provider-liquid: ${test_name} failed; output contains protected material" >&2
        return 1
      fi
    done
    echo "provider-liquid: ${test_name} failed" >&2
    sed -n '1,200p' "${output_file}" >&2
    if test -f "${result_file}" && jq -e '.refund_raw | type == "string"' "${result_file}" >/dev/null; then
      elements_cli testmempoolaccept "$(jq -c '[.refund_raw]' "${result_file}")" >&2 || true
    fi
    return 1
  fi
  for secret in "${wallet_seed_hex}" "${IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD}"; do
    if printf '%s\n' "${secret}" | rg -Fq -f - "${output_file}"; then
      echo "provider-liquid: ${test_name} output contains custody or credential material" >&2
      return 1
    fi
  done
  rm "${output_file}"
}

current_phase=confidential-unblind
live_test provider_liquid_live_unblinds_own_output
current_height="$(elements_cli getblockcount)"
if test "${current_height}" -lt 17; then
  wallet_cli provider-liquid generatetoaddress "$((17 - current_height))" "${mining_address}" >/dev/null
fi
current_phase=explicit-funding-and-refund
live_test provider_liquid_live_funds_and_broadcasts_signed_refund
current_phase=result-verification
test -f "${result_file}"
funding_txid="$(jq -er '.funding_txid' "${result_file}")"
funding_output_index="$(jq -er '.funding_output_index' "${result_file}")"
refund_txid="$(jq -er '.refund_txid' "${result_file}")"
test "$(elements_cli getrawmempool | jq -er 'length')" = 2
elements_cli getrawtransaction "${confidential_txid}" >/dev/null
elements_cli getrawtransaction "${funding_txid}" >/dev/null
elements_cli getrawtransaction "${refund_txid}" >/dev/null
wallet_cli provider-liquid generatetoaddress 1 "${mining_address}" >/dev/null
test "$(elements_cli getrawtransaction "${refund_txid}" true | jq -er '.confirmations')" -ge 1
elements_cli gettxout "${funding_txid}" "${funding_output_index}" | jq -s -e 'length == 0 or .[0] == null' >/dev/null

current_phase=record-publication
record="$(jq -nc \
  --arg run_id "${run_id}" \
  --arg network_id "${IMMORTAL_PROVIDER_LIQUID_NETWORK_ID}" \
  --arg asset_id "${IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET}" \
  --arg funding_txid "${funding_txid}" \
  --arg refund_txid "${refund_txid}" \
  '{schema:"openagents.immortal.provider-liquid-live.v1",gate_scope:"liquid_provider_rail_component",provider_daemon_process:false,run_id:$run_id,network_id:$network_id,asset_id:$asset_id,funding_txid:$funding_txid,refund_txid:$refund_txid,confidential_own_output:true,provider_exact_broadcast:true,funding_exact_known_replay:true,exit_exact_known_replay:true,unilateral_script_path:true,retains_custody_material:false,live_deployment:false}')"
for forbidden in seed preimage macaroon private_key blinding_key value_blinder asset_blinder rpc_password; do
  if printf '%s' "${record}" | rg -qi "${forbidden}"; then
    echo "provider-liquid: retained record contains forbidden custody vocabulary" >&2
    exit 1
  fi
done
printf 'M13_LIQUID_JSON=%s\n' "${record}"

current_phase=teardown
IMMORTAL_LAB_DIR="${lab_root}" scripts/lab-extensions.sh down elementsd >/dev/null
active=false
rmdir "${lab_root}/extensions" "${lab_root}"
trap - EXIT INT TERM
