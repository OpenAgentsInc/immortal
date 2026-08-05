#!/usr/bin/env bash
# Two provider-owned CLN nodes and one wallet-side CLN node wired to the lab
# bitcoind from scripts/lab-bitcoind.sh (immortal#32/#18). Uses lightningd
# from PATH when available, otherwise a Docker/Podman container. Teardown
# removes only resources recorded by this script.
set -euo pipefail
cd "$(dirname "$0")/.."

lab_dir="${IMMORTAL_LAB_DIR:-${TMPDIR:-/tmp}/immortal-lab}"
btc_dir="${lab_dir}/bitcoind"
rpc_port="${IMMORTAL_LAB_BITCOIND_RPC_PORT:-18543}"
rpc_user="${IMMORTAL_LAB_BITCOIND_RPC_USER:-immortal}"
rpc_password="${IMMORTAL_LAB_BITCOIND_RPC_PASSWORD:-immortal-lab-regtest}"
cln1_port="${IMMORTAL_LAB_CLN1_PORT:-19846}"
cln2_port="${IMMORTAL_LAB_CLN2_PORT:-19847}"
cln3_port="${IMMORTAL_LAB_CLN3_PORT:-19848}"
container_image="${IMMORTAL_LAB_CLN_IMAGE:-immortal-lab-cln-hold:v0.3.3-cln-v26.06.6}"
container_dockerfile="scripts/support/provider-funded/Dockerfile.cln-hold"
network_name="immortal-lab"
bitcoind_container="immortal-lab-bitcoind"
channel_sat="${IMMORTAL_LAB_CLN_CHANNEL_SAT:-1000000}"
rebalance_msat="${IMMORTAL_LAB_CLN_REBALANCE_MSAT:-450000000}"

usage() {
  cat <<'USAGE'
usage: scripts/lab-cln.sh <command> [arguments]

commands:
  up                 start provider-a, provider-b, and wallet CLN nodes;
                     provider nodes require a verified hold plugin from
                     IMMORTAL_LAB_CLN_HOLD_PLUGIN or `hold` on PATH
  fund               send on-chain coins from the lab bitcoind wallet to all
                     three nodes and confirm them
  channel            open and balance provider-a <-> wallet,
                     provider-b <-> wallet, and provider-a <-> provider-b
  cli <1|2|3> <args> run lightning-cli against provider-a (1), provider-b (2),
                     or wallet (3)
  status             print runtime, ports, node ids, and channel state
  down               stop all three nodes and remove only what `up` created

environment:
  IMMORTAL_LAB_DIR              lab state root (default ${TMPDIR:-/tmp}/immortal-lab)
  IMMORTAL_LAB_CLN1_PORT        cln1 P2P port (default 19846)
  IMMORTAL_LAB_CLN2_PORT        cln2 P2P port (default 19847)
  IMMORTAL_LAB_CLN3_PORT        wallet CLN P2P port (default 19848)
  IMMORTAL_LAB_CLN_IMAGE        container image with /usr/local/bin/hold
                                (default built from the pinned funded-smoke Dockerfile)
  IMMORTAL_LAB_CLN_HOLD_PLUGIN  native-runtime path to the hold executable
USAGE
}

detect_runtime() {
  if command -v lightningd >/dev/null && command -v lightning-cli >/dev/null &&
    test -n "$(resolve_hold_plugin)"; then
    echo native
    return
  fi
  for candidate in docker podman; do
    if command -v "${candidate}" >/dev/null && "${candidate}" info >/dev/null 2>&1; then
      echo "${candidate}"
      return
    fi
  done
  echo none
}

recorded_runtime() {
  if test -f "${lab_dir}/cln-runtime"; then
    cat "${lab_dir}/cln-runtime"
  else
    echo none
  fi
}

require_up() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" = none; then
    echo "lab-cln: no lab CLN nodes are recorded; run 'scripts/lab-cln.sh up' first" >&2
    exit 1
  fi
  echo "${runtime}"
}

bitcoind_runtime() {
  if test -f "${btc_dir}/runtime"; then
    cat "${btc_dir}/runtime"
  else
    echo none
  fi
}

node_dir() {
  echo "${lab_dir}/cln$1"
}

node_container() {
  echo "immortal-lab-cln$1"
}

node_port() {
  if test "$1" = 1; then
    echo "${cln1_port}"
  elif test "$1" = 2; then
    echo "${cln2_port}"
  else
    echo "${cln3_port}"
  fi
}

node_role() {
  case "$1" in
  1) echo provider-a ;;
  2) echo provider-b ;;
  3) echo wallet ;;
  *) echo unknown ;;
  esac
}

node_marker() {
  echo "${lab_dir}/cln$1-created"
}

cln_cli() {
  local runtime="$1" node="$2"
  shift 2
  case "${runtime}" in
  native)
    lightning-cli --network=regtest --lightning-dir="$(node_dir "${node}")" "$@"
    ;;
  docker | podman)
    "${runtime}" exec "$(node_container "${node}")" \
      lightning-cli --network=regtest "$@"
    ;;
  *)
    echo "lab-cln: unknown recorded runtime '${runtime}'" >&2
    exit 1
    ;;
  esac
}

wait_node_ready() {
  local runtime="$1" node="$2"
  for _ in $(seq 1 300); do
    if cln_cli "${runtime}" "${node}" getinfo >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "lab-cln: node ${node} did not become ready" >&2
  exit 1
}

verify_hold_plugin() {
  local runtime="$1" node="$2" command
  if ! cln_cli "${runtime}" "${node}" plugin list |
    jq -e '.plugins[] | select(.active == true and (.name | test("hold"; "i")))' >/dev/null; then
    echo "lab-cln: $(node_role "${node}") did not report an active hold plugin" >&2
    return 1
  fi
  for command in holdinvoice listholdinvoices settleholdinvoice cancelholdinvoice; do
    if ! cln_cli "${runtime}" "${node}" help "${command}" |
      jq -e --arg command "${command}" '.help | length > 0 and any(.[]; .command | startswith($command))' >/dev/null; then
      echo "lab-cln: $(node_role "${node}") hold plugin does not expose ${command}" >&2
      return 1
    fi
  done
}

resolve_hold_plugin() {
  if test -n "${IMMORTAL_LAB_CLN_HOLD_PLUGIN:-}" && test -x "${IMMORTAL_LAB_CLN_HOLD_PLUGIN}"; then
    echo "${IMMORTAL_LAB_CLN_HOLD_PLUGIN}"
    return
  fi
  if command -v hold >/dev/null; then
    command -v hold
    return
  fi
  echo ""
}

ensure_container_image() {
  local runtime="$1"
  if "${runtime}" image inspect "${container_image}" >/dev/null 2>&1; then
    return 0
  fi
  "${runtime}" build --file "${container_dockerfile}" --tag "${container_image}" .
  touch "${lab_dir}/cln-image-created"
  "${runtime}" image inspect --format '{{.Id}}' "${container_image}" >"${lab_dir}/cln-image-id"
}

start_native_node() {
  local node="$1" hold_plugin="$2" directory port
  directory="$(node_dir "${node}")"
  port="$(node_port "${node}")"
  mkdir -p "${directory}"
  local plugin_args=()
  if test -n "${hold_plugin}"; then
    plugin_args=(--plugin="${hold_plugin}")
  fi
  lightningd --network=regtest --lightning-dir="${directory}" \
    --bitcoin-rpcconnect=127.0.0.1 --bitcoin-rpcport="${rpc_port}" \
    --bitcoin-rpcuser="${rpc_user}" --bitcoin-rpcpassword="${rpc_password}" \
    --bind-addr="127.0.0.1:${port}" \
    --log-file="${directory}/lightningd.log" \
    ${plugin_args[@]+"${plugin_args[@]}"} \
    --daemon
}

start_container_node() {
  local runtime="$1" node="$2" hold_plugin="$3" container port
  container="$(node_container "${node}")"
  port="$(node_port "${node}")"
  mkdir -p "$(node_dir "${node}")"
  local plugin_args=()
  if test -n "${hold_plugin}"; then
    plugin_args=(--plugin=/usr/local/bin/hold)
  fi
  "${runtime}" run -d --name "${container}" --network "${network_name}" \
    -p "127.0.0.1:${port}:9735" \
    "${container_image}" \
    --network=regtest \
    --bitcoin-rpcconnect="${bitcoind_container}" --bitcoin-rpcport=18443 \
    --bitcoin-rpcuser="${rpc_user}" --bitcoin-rpcpassword="${rpc_password}" \
    --bind-addr=0.0.0.0:9735 \
    ${plugin_args[@]+"${plugin_args[@]}"} >/dev/null
  "${runtime}" container inspect --format '{{.Id}}' "${container}" >"${lab_dir}/cln${node}-container-id"
}

cmd_up() {
  if test "$#" -ne 0; then
    echo "lab-cln: up takes no options; the hold plugin is mandatory" >&2
    exit 1
  fi
  if test "$(recorded_runtime)" != none; then
    echo "lab-cln: lab CLN nodes are already recorded under ${lab_dir}; run 'down' first" >&2
    exit 1
  fi
  local btc_runtime
  btc_runtime="$(bitcoind_runtime)"
  if test "${btc_runtime}" = none; then
    echo "lab-cln: the lab bitcoind is not up; run 'scripts/lab-bitcoind.sh up' first" >&2
    exit 1
  fi
  local runtime
  runtime="$(detect_runtime)"
  if test "${runtime}" = none; then
    echo "lab-cln: install Core Lightning plus the hold plugin, or Docker/Podman for the pinned CLN-plus-hold image" >&2
    exit 1
  fi
  if test "${runtime}" != native && test "${btc_runtime}" = native; then
    echo "lab-cln: container CLN cannot reach a native loopback bitcoind; install lightningd natively or run lab-bitcoind in container mode" >&2
    exit 1
  fi

  local hold_plugin=""
  if test "${runtime}" = native; then
    hold_plugin="$(resolve_hold_plugin)"
    if test -z "${hold_plugin}"; then
      echo "lab-cln: native bring-up requires IMMORTAL_LAB_CLN_HOLD_PLUGIN or 'hold' on PATH" >&2
      exit 1
    fi
  else
    hold_plugin=/usr/local/bin/hold
  fi

  mkdir -p "${lab_dir}"
  local node directory container
  for node in 1 2 3; do
    directory="$(node_dir "${node}")"
    if test -e "${directory}" || test -e "$(node_marker "${node}")"; then
      echo "lab-cln: refusing to reuse unrecorded path ${directory}" >&2
      exit 1
    fi
    if test "${runtime}" != native; then
      container="$(node_container "${node}")"
      if "${runtime}" container inspect "${container}" >/dev/null 2>&1; then
        echo "lab-cln: refusing to replace existing container ${container}" >&2
        exit 1
      fi
    fi
  done

  echo "${runtime}" >"${lab_dir}/cln-runtime"
  printf '%s\n' "${container_image}" >"${lab_dir}/cln-image-name"
  trap 'cmd_down >/dev/null 2>&1 || true' EXIT
  if test "${runtime}" != native; then
    ensure_container_image "${runtime}"
  fi
  for node in 1 2 3; do
    mkdir -p "$(node_dir "${node}")"
    touch "$(node_marker "${node}")"
    local node_hold_plugin=""
    if test "${node}" != 3; then
      node_hold_plugin="${hold_plugin}"
    fi
    case "${runtime}" in
    native)
      if ! start_native_node "${node}" "${node_hold_plugin}"; then
        cmd_down
        exit 1
      fi
      ;;
    docker | podman)
      if ! start_container_node "${runtime}" "${node}" "${node_hold_plugin}"; then
        cmd_down
        exit 1
      fi
      ;;
    esac
  done
  for node in 1 2 3; do
    if ! wait_node_ready "${runtime}" "${node}"; then
      cmd_down
      exit 1
    fi
  done
  for node in 1 2; do
    if ! verify_hold_plugin "${runtime}" "${node}"; then
      cmd_down
      exit 1
    fi
  done
  echo "lab-cln: ${runtime} regtest nodes up with provider hold RPCs verified"
  for node in 1 2 3; do
    echo "lab-cln: $(node_role "${node}") (cln${node}) id $(cln_cli "${runtime}" "${node}" getinfo | jq -r .id) port $(node_port "${node}")"
  done
  echo "lab-cln: hold plugin LOADED and VERIFIED on provider-a and provider-b from ${hold_plugin}"
  trap - EXIT
}

cmd_fund() {
  local runtime
  runtime="$(require_up)"
  for node in 1 2 3; do
    local address
    address="$(cln_cli "${runtime}" "${node}" newaddr | jq -r .bech32)"
    scripts/lab-bitcoind.sh cli -rpcwallet=lab sendtoaddress "${address}" 1.0 >/dev/null
    echo "lab-cln: sent 1.0 BTC to cln${node} (${address})"
  done
  scripts/lab-bitcoind.sh mine 6 >/dev/null
  for node in 1 2 3; do
    for _ in $(seq 1 150); do
      if test "$(cln_cli "${runtime}" "${node}" listfunds | jq '[.outputs[] | select(.status == "confirmed")] | length')" -gt 0; then
        break
      fi
      sleep 0.2
    done
    echo "lab-cln: cln${node} confirmed on-chain funds $(cln_cli "${runtime}" "${node}" listfunds | jq '[.outputs[] | select(.status == "confirmed") | .amount_msat] | add // 0') msat"
  done
}

node_host() {
  local runtime="$1" node="$2"
  if test "${runtime}" = native; then
    echo "127.0.0.1:$(node_port "${node}")"
  else
    echo "$(node_container "${node}"):9735"
  fi
}

open_and_balance_channel() {
  local runtime="$1" source="$2" destination="$3"
  local destination_id destination_host label invoice channel_state to_us_msat
  destination_id="$(cln_cli "${runtime}" "${destination}" getinfo | jq -er .id)"
  destination_host="$(node_host "${runtime}" "${destination}")"
  cln_cli "${runtime}" "${source}" connect "${destination_id}@${destination_host}" >/dev/null
  cln_cli "${runtime}" "${source}" fundchannel "${destination_id}" "${channel_sat}" >/dev/null
  scripts/lab-bitcoind.sh mine 6 >/dev/null
  for _ in $(seq 1 300); do
    channel_state="$(cln_cli "${runtime}" "${source}" listpeerchannels "${destination_id}" | jq -r '.channels[0].state // ""')"
    if test "${channel_state}" = CHANNELD_NORMAL; then
      break
    fi
    sleep 0.2
  done
  if test "${channel_state}" != CHANNELD_NORMAL; then
    echo "lab-cln: $(node_role "${source}") -> $(node_role "${destination}") channel did not reach CHANNELD_NORMAL" >&2
    return 1
  fi
  echo "lab-cln: channel $(node_role "${source}") -> $(node_role "${destination}") open (${channel_sat} sat)"
  label="lab-rebalance-${source}-${destination}-$(date +%s)"
  invoice="$(cln_cli "${runtime}" "${destination}" invoice "${rebalance_msat}" "${label}" "lab channel balancing" | jq -er .bolt11)"
  cln_cli "${runtime}" "${source}" pay "${invoice}" >/dev/null
  to_us_msat="$(cln_cli "${runtime}" "${source}" listpeerchannels "${destination_id}" | jq -er '.channels[0].to_us_msat.msat')"
  if test "${to_us_msat}" -ge "$((channel_sat * 1000))"; then
    echo "lab-cln: balancing payment did not move liquidity on the direct $(node_role "${source}") -> $(node_role "${destination}") channel" >&2
    return 1
  fi
  echo "lab-cln: pushed ${rebalance_msat} msat to $(node_role "${destination}"); direct channel is balanced"
  cln_cli "${runtime}" "${source}" listpeerchannels "${destination_id}" |
    jq '{state: .channels[0].state, total_msat: .channels[0].total_msat, to_us_msat: .channels[0].to_us_msat}'
}

cmd_channel() {
  local runtime
  runtime="$(require_up)"
  # Establish the wallet spokes before the provider-to-provider edge so each
  # initial balancing payment has only one available route.
  open_and_balance_channel "${runtime}" 1 3
  open_and_balance_channel "${runtime}" 2 3
  open_and_balance_channel "${runtime}" 1 2
}

cmd_status() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" = none; then
    echo "lab-cln: down (no recorded nodes under ${lab_dir})"
    return 0
  fi
  echo "lab-cln: runtime ${runtime}"
  for node in 1 2 3; do
    local info
    info="$(cln_cli "${runtime}" "${node}" getinfo)"
    echo "lab-cln: cln${node} id $(echo "${info}" | jq -r .id) port $(node_port "${node}") dir $(node_dir "${node}")$(test "${runtime}" = native || echo " (node data inside container $(node_container "${node}"))")"
    if cln_cli "${runtime}" "${node}" plugin list | jq -er '.plugins[] | select(.active == true and (.name | test("hold"; "i")))' >/dev/null 2>&1; then
      echo "lab-cln: cln${node} hold plugin LOADED"
    else
      if test "${node}" = 3; then
        echo "lab-cln: cln${node} wallet role (hold plugin not required)"
      else
        echo "lab-cln: cln${node} hold plugin ABSENT (invalid topology)"
      fi
    fi
  done
  for node in 1 2 3; do
    echo "lab-cln: $(node_role "${node}") channels"
    cln_cli "${runtime}" "${node}" listpeerchannels |
      jq '[.channels[] | {peer_id, state, total_msat, to_us_msat}]'
  done
}

cmd_down() {
  local runtime recorded_container_id current_container_id recorded_image_id current_image_id recorded_image_name
  runtime="$(recorded_runtime)"
  case "${runtime}" in
  none)
    echo "lab-cln: nothing recorded to tear down"
    ;;
  native)
    for node in 1 2 3; do
      if test -f "$(node_marker "${node}")"; then
        cln_cli native "${node}" stop >/dev/null 2>&1 || true
        rm -rf "$(node_dir "${node}")"
        rm -f "$(node_marker "${node}")"
      fi
    done
    rm -f "${lab_dir}/cln-runtime" "${lab_dir}/cln-image-name"
    echo "lab-cln: native nodes stopped and their directories removed"
    ;;
  docker | podman)
    for node in 1 2 3; do
      if test -f "$(node_marker "${node}")"; then
        recorded_container_id="$(cat "${lab_dir}/cln${node}-container-id" 2>/dev/null || true)"
        current_container_id="$("${runtime}" container inspect --format '{{.Id}}' "$(node_container "${node}")" 2>/dev/null || true)"
        if test -n "${current_container_id}" && test "${current_container_id}" != "${recorded_container_id}"; then
          echo "lab-cln: $(node_container "${node}") no longer matches the created container; refusing teardown" >&2
          exit 1
        fi
        if test -n "${current_container_id}"; then
          "${runtime}" rm -f "$(node_container "${node}")" >/dev/null
        fi
        rm -rf "$(node_dir "${node}")"
        rm -f "$(node_marker "${node}")" "${lab_dir}/cln${node}-container-id"
      fi
    done
    if test -f "${lab_dir}/cln-image-created"; then
      recorded_image_name="$(cat "${lab_dir}/cln-image-name")"
      recorded_image_id="$(cat "${lab_dir}/cln-image-id" 2>/dev/null || true)"
      current_image_id="$("${runtime}" image inspect --format '{{.Id}}' "${recorded_image_name}" 2>/dev/null || true)"
      if test -n "${current_image_id}" && test "${current_image_id}" != "${recorded_image_id}"; then
        echo "lab-cln: ${recorded_image_name} no longer matches the created image; refusing teardown" >&2
        exit 1
      fi
      if test -n "${current_image_id}"; then
        "${runtime}" image rm "${recorded_image_name}" >/dev/null
      fi
      rm -f "${lab_dir}/cln-image-created" "${lab_dir}/cln-image-id"
    fi
    rm -f "${lab_dir}/cln-runtime" "${lab_dir}/cln-image-name"
    echo "lab-cln: containers removed and node directories removed"
    ;;
  *)
    echo "lab-cln: unknown recorded runtime '${runtime}'; refusing to guess at teardown" >&2
    exit 1
    ;;
  esac
}

command="${1:-}"
shift || true
case "${command}" in
up) cmd_up "$@" ;;
fund) cmd_fund "$@" ;;
channel) cmd_channel "$@" ;;
cli)
  node="${1:-}"
  shift || true
  if test "${node}" != 1 && test "${node}" != 2 && test "${node}" != 3; then
    echo "lab-cln: cli requires a node number (1, 2, or 3)" >&2
    exit 1
  fi
  runtime="$(require_up)"
  cln_cli "${runtime}" "${node}" "$@"
  ;;
status) cmd_status "$@" ;;
down) cmd_down "$@" ;;
help | --help | -h | "") usage ;;
*)
  echo "lab-cln: unknown command '${command}'" >&2
  usage >&2
  exit 1
  ;;
esac
