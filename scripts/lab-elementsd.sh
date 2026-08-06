#!/usr/bin/env bash
# Repo-owned Elements regtest process for the #27 extension boundary.
set -euo pipefail
cd "$(dirname "$0")/.."

state_dir="${IMMORTAL_LAB_EXTENSION_STATE_DIR:?missing extension state directory}"
run_id="${IMMORTAL_LAB_EXTENSION_RUN_ID:?missing extension run ID}"
ports_json="${IMMORTAL_LAB_EXTENSION_PORTS_JSON:?missing extension ports}"
dockerfile="scripts/support/provider-funded/Dockerfile.elements"
container_name="${run_id}"
image_name="${run_id}:local"
rpc_container_port="$(printf '%s' "${ports_json}" | jq -er '.rpc')"
p2p_container_port="$(printf '%s' "${ports_json}" | jq -er '.p2p')"
data_dir="${state_dir}/data"
record_file="${state_dir}/elementsd-process.json"
connection_file="${state_dir}/connection.env"

validate() {
  test "${IMMORTAL_LAB_EXTENSION_ID:?missing extension ID}" = elementsd
  test "${IMMORTAL_LAB_EXTENSION_ISSUE:?missing extension issue}" = 27
  test -f "${dockerfile}"
  case "${run_id}" in
    immortal-lab-elementsd-[a-zA-Z0-9-]*) ;;
    *) echo "lab-elementsd: invalid run identifier" >&2; exit 1 ;;
  esac
  for port in "${rpc_container_port}" "${p2p_container_port}"; do
    case "${port}" in
      ''|*[!0-9]*) echo "lab-elementsd: invalid port" >&2; exit 1 ;;
    esac
    if test "${port}" -lt 1024 || test "${port}" -gt 65535; then
      echo "lab-elementsd: port is outside the unprivileged range" >&2
      exit 1
    fi
  done
  if test "${rpc_container_port}" = "${p2p_container_port}"; then
    echo "lab-elementsd: RPC and P2P ports must differ" >&2
    exit 1
  fi
}

random_hex() {
  local byte_count="$1"
  LC_ALL=C od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

container_exists() {
  local output
  if output="$(docker container inspect "${container_name}" 2>&1)"; then
    return 0
  fi
  case "${output}" in
    *"No such container"*|*"No such object"*) return 1 ;;
    *) echo "lab-elementsd: unable to determine whether ${container_name} exists" >&2; return 2 ;;
  esac
}

image_exists() {
  local output
  if output="$(docker image inspect "${image_name}" 2>&1)"; then
    return 0
  fi
  case "${output}" in
    *"No such image"*|*"No such object"*) return 1 ;;
    *) echo "lab-elementsd: unable to determine whether ${image_name} exists" >&2; return 2 ;;
  esac
}

resources_absent() {
  local status
  if container_exists; then
    return 1
  else
    status=$?
    if test "${status}" -ne 1; then
      return 1
    fi
  fi
  if image_exists; then
    return 1
  else
    status=$?
    test "${status}" -eq 1
  fi
}

container_label() {
  docker container inspect --format '{{ index .Config.Labels "org.openagents.immortal.lab.run-id" }}' "${container_name}"
}

image_label() {
  docker image inspect --format '{{ index .Config.Labels "org.openagents.immortal.lab.run-id" }}' "${image_name}"
}

write_initial_record() {
  jq -n \
    --arg run_id "${run_id}" \
    --arg container_name "${container_name}" \
    --arg image_name "${image_name}" \
    --argjson rpc_container_port "${rpc_container_port}" \
    --argjson p2p_container_port "${p2p_container_port}" \
    '{schema:"openagents.immortal.lab-elementsd-process.v1",run_id:$run_id,container_name:$container_name,container_id:null,image_name:$image_name,image_id:null,rpc_container_port:$rpc_container_port,p2p_container_port:$p2p_container_port,rpc_host_port:null,p2p_host_port:null}' \
    >"${record_file}"
  chmod 600 "${record_file}"
}

record_image() {
  local image_id="$1" temporary="${record_file}.tmp"
  jq --arg image_id "${image_id}" '.image_id = $image_id' "${record_file}" >"${temporary}"
  chmod 600 "${temporary}"
  mv "${temporary}" "${record_file}"
}

record_container() {
  local container_id="$1" rpc_host_port="$2" p2p_host_port="$3"
  local temporary="${record_file}.tmp"
  jq \
    --arg container_id "${container_id}" \
    --argjson rpc_host_port "${rpc_host_port}" \
    --argjson p2p_host_port "${p2p_host_port}" \
    '.container_id = $container_id | .rpc_host_port = $rpc_host_port | .p2p_host_port = $p2p_host_port' \
    "${record_file}" >"${temporary}"
  chmod 600 "${temporary}"
  mv "${temporary}" "${record_file}"
}

published_port() {
  local container_port="$1"
  docker container inspect "${container_name}" | jq -er \
    --arg port "${container_port}/tcp" \
    '.[0].NetworkSettings.Ports[$port] | if length == 1 and .[0].HostIp == "127.0.0.1" then .[0].HostPort else error("non-loopback or ambiguous published port") end'
}

require_owned_container() {
  local recorded_name recorded_id observed_id
  recorded_name="$(jq -er '.container_name' "${record_file}")"
  recorded_id="$(jq -r '.container_id // empty' "${record_file}")"
  observed_id="$(docker container inspect --format '{{.Id}}' "${container_name}")"
  test "${recorded_name}" = "${container_name}"
  test "$(container_label "${container_name}")" = "${run_id}"
  if test -n "${recorded_id}"; then
    test "${recorded_id}" = "${observed_id}"
  fi
}

require_owned_image() {
  local recorded_name recorded_id observed_id
  recorded_name="$(jq -er '.image_name' "${record_file}")"
  recorded_id="$(jq -r '.image_id // empty' "${record_file}")"
  observed_id="$(docker image inspect --format '{{.Id}}' "${image_name}")"
  test "${recorded_name}" = "${image_name}"
  test "$(image_label "${image_name}")" = "${run_id}"
  if test -n "${recorded_id}"; then
    test "${recorded_id}" = "${observed_id}"
  fi
}

wait_ready() {
  local attempt
  for attempt in $(seq 1 90); do
    if docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
      getblockchaininfo >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "lab-elementsd: node did not become ready" >&2
  return 1
}

up() {
  if test -e "${record_file}" || test -e "${connection_file}" || test -e "${data_dir}"; then
    echo "lab-elementsd: refusing existing process state" >&2
    exit 1
  fi
  mkdir -p "${data_dir}"
  chmod 700 "${data_dir}"
  local rpc_user rpc_password image_id container_id rpc_host_port p2p_host_port
  local genesis_hash network_id pegged_asset wallet_result
  rpc_user="lab-$(random_hex 8)"
  rpc_password="$(random_hex 32)"
  umask 077
  write_initial_record
  if ! resources_absent; then
    echo "lab-elementsd: generated resource name already exists; refusing replacement" >&2
    return 1
  fi
  {
    printf 'chain=elementsregtest\n'
    printf 'server=1\nlisten=1\ntxindex=1\nvalidatepegin=0\n'
    printf 'persistmempool=0\nwalletbroadcast=0\n'
    printf 'initialfreecoins=2100000000000000\nfallbackfee=0.0002\n'
    printf 'rpcuser=%s\nrpcpassword=%s\n' "${rpc_user}" "${rpc_password}"
    printf '[elementsregtest]\n'
    printf 'rpcbind=0.0.0.0\nrpcallowip=0.0.0.0/0\n'
    printf 'rpcport=%s\nport=%s\n' "${rpc_container_port}" "${p2p_container_port}"
  } >"${data_dir}/elements.conf"
  chmod 600 "${data_dir}/elements.conf"

  docker build --quiet \
    --build-arg "IMMORTAL_LAB_RUN_ID=${run_id}" \
    --file "${dockerfile}" \
    --tag "${image_name}" . >/dev/null
  image_id="$(docker image inspect --format '{{.Id}}' "${image_name}")"
  test "$(image_label "${image_name}")" = "${run_id}"
  record_image "${image_id}"
  docker run --detach \
    --name "${container_name}" \
    --label "org.openagents.immortal.lab.run-id=${run_id}" \
    --publish "127.0.0.1::${rpc_container_port}" \
    --publish "127.0.0.1::${p2p_container_port}" \
    --mount "type=bind,src=${data_dir},dst=/data" \
    "${image_name}" -datadir=/data -printtoconsole >/dev/null
  container_id="$(docker container inspect --format '{{.Id}}' "${container_name}")"
  rpc_host_port="$(published_port "${rpc_container_port}")"
  p2p_host_port="$(published_port "${p2p_container_port}")"
  record_container "${container_id}" "${rpc_host_port}" "${p2p_host_port}"
  wait_ready
  wallet_result="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -named createwallet wallet_name=provider-liquid descriptors=false)"
  printf '%s' "${wallet_result}" | jq -e '.name == "provider-liquid"' >/dev/null
  wallet_result="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -named createwallet wallet_name=initial-free-coins disable_private_keys=true blank=true descriptors=true)"
  printf '%s' "${wallet_result}" | jq -e '.name == "initial-free-coins"' >/dev/null
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet=initial-free-coins importdescriptors \
    '[{"desc":"raw(51)#8lvh9jxk","timestamp":0}]' \
    | jq -e 'length == 1 and .[0].success == true' >/dev/null
  local funding_address funding_outputs funding_options funding_psbt funding_final mining_address
  funding_address="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet=provider-liquid getnewaddress)"
  funding_outputs="$(jq -nc --arg address "${funding_address}" '[{($address):1000}]')"
  funding_options="$(jq -nc --arg address "${funding_address}" \
    '{includeWatching:true,changeAddress:$address}')"
  funding_psbt="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet=initial-free-coins walletcreatefundedpsbt '[]' "${funding_outputs}" 0 \
    "${funding_options}" true | jq -er '.psbt')"
  funding_final="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    finalizepsbt "${funding_psbt}")"
  printf '%s' "${funding_final}" | jq -e '.complete == true' >/dev/null
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    sendrawtransaction "$(printf '%s' "${funding_final}" | jq -er '.hex')" >/dev/null
  mining_address="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest -rpcwallet=provider-liquid getnewaddress)"
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet=provider-liquid generatetoaddress 1 "${mining_address}" >/dev/null
  docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest \
    -rpcwallet=provider-liquid getbalances \
    | jq -e '.mine.trusted.bitcoin > 1000' >/dev/null
  genesis_hash="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest getblockhash 0)"
  network_id="bip122:${genesis_hash:0:32}"
  pegged_asset="$(docker exec "${container_name}" elements-cli -datadir=/data -chain=elementsregtest getsidechaininfo | jq -er '.pegged_asset')"
  {
    printf 'IMMORTAL_PROVIDER_LIQUID_ENABLED=true\n'
    printf 'IMMORTAL_PROVIDER_ELEMENTSD_HOST=127.0.0.1\n'
    printf 'IMMORTAL_PROVIDER_ELEMENTSD_PORT=%s\n' "${rpc_host_port}"
    printf 'IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER=%s\n' "${rpc_user}"
    printf 'IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD=%s\n' "${rpc_password}"
    printf 'IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-liquid\n'
    printf 'IMMORTAL_PROVIDER_LIQUID_NETWORK_ID=%s\n' "${network_id}"
    printf 'IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET=%s\n' "${pegged_asset}"
  } >"${connection_file}"
  chmod 600 "${connection_file}"
}

status() {
  test -f "${record_file}"
  test -f "${connection_file}"
  require_owned_container
  require_owned_image
  test "$(docker container inspect --format '{{.State.Running}}' "${container_name}")" = true
  wait_ready
  echo "lab-elementsd: active run=${run_id} rpc=127.0.0.1:$(jq -er '.rpc_host_port' "${record_file}")"
}

down() {
  local status
  if ! test -f "${record_file}"; then
    if ! resources_absent; then
      echo "lab-elementsd: resources exist without an ownership record; refusing teardown" >&2
      return 1
    fi
    return 0
  fi
  if container_exists; then
    require_owned_container
    docker rm --force "${container_name}" >/dev/null
  else
    status=$?
    if test "${status}" -ne 1; then
      return 1
    fi
  fi
  if image_exists; then
    require_owned_image
    docker image rm "${image_name}" >/dev/null
  else
    status=$?
    if test "${status}" -ne 1; then
      return 1
    fi
  fi
  if ! resources_absent; then
    echo "lab-elementsd: owned resources remain after teardown" >&2
    return 1
  fi
}

validate
case "${1:-}" in
  up) up ;;
  status) status ;;
  down) down ;;
  *) echo "usage: scripts/lab-elementsd.sh up|status|down" >&2; exit 2 ;;
esac
