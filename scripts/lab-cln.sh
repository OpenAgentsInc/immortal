#!/usr/bin/env bash
# Two disposable CLN (lightningd) regtest nodes wired to the lab bitcoind
# from scripts/lab-bitcoind.sh (immortal#32/#18). Uses lightningd from PATH
# when available, otherwise a Docker/Podman container. Teardown removes only
# what this script created.
#
# Hold-invoice plugin: the reverse-swap scenarios need the CLN hold plugin
# (a rail prerequisite of immortal#25, e.g. github.com/BoltzExchange/hold).
# It is optional here: pass --with-hold to `up` with
# IMMORTAL_LAB_CLN_HOLD_PLUGIN pointing at the plugin executable, or have
# `hold` on PATH. When absent, the nodes come up without it and this script
# says so clearly.
set -euo pipefail
cd "$(dirname "$0")/.."

lab_dir="${IMMORTAL_LAB_DIR:-${TMPDIR:-/tmp}/immortal-lab}"
btc_dir="${lab_dir}/bitcoind"
rpc_port="${IMMORTAL_LAB_BITCOIND_RPC_PORT:-18543}"
rpc_user="${IMMORTAL_LAB_BITCOIND_RPC_USER:-immortal}"
rpc_password="${IMMORTAL_LAB_BITCOIND_RPC_PASSWORD:-immortal-lab-regtest}"
cln1_port="${IMMORTAL_LAB_CLN1_PORT:-19846}"
cln2_port="${IMMORTAL_LAB_CLN2_PORT:-19847}"
container_image="${IMMORTAL_LAB_CLN_IMAGE:-elementsproject/lightningd:v25.05}"
network_name="immortal-lab"
bitcoind_container="immortal-lab-bitcoind"
channel_sat="${IMMORTAL_LAB_CLN_CHANNEL_SAT:-1000000}"
rebalance_msat="${IMMORTAL_LAB_CLN_REBALANCE_MSAT:-450000000}"

usage() {
  cat <<'USAGE'
usage: scripts/lab-cln.sh <command> [arguments]

commands:
  up [--with-hold]   start two CLN regtest nodes wired to the lab bitcoind
                     (--with-hold loads the hold plugin from
                     IMMORTAL_LAB_CLN_HOLD_PLUGIN or `hold` on PATH)
  fund               send on-chain coins from the lab bitcoind wallet to both
                     nodes and confirm them
  channel            open a channel cln1 -> cln2, confirm it, and balance it
                     with a payment for about half the capacity
  cli <1|2> <args>   run lightning-cli against node 1 or 2
  status             print runtime, ports, node ids, and channel state
  down               stop both nodes and remove only what `up` created

environment:
  IMMORTAL_LAB_DIR              lab state root (default ${TMPDIR:-/tmp}/immortal-lab)
  IMMORTAL_LAB_CLN1_PORT        cln1 P2P port (default 19846)
  IMMORTAL_LAB_CLN2_PORT        cln2 P2P port (default 19847)
  IMMORTAL_LAB_CLN_IMAGE        container image fallback (default elementsproject/lightningd:v25.05)
  IMMORTAL_LAB_CLN_HOLD_PLUGIN  path to the CLN hold plugin executable
USAGE
}

detect_runtime() {
  if command -v lightningd >/dev/null && command -v lightning-cli >/dev/null; then
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
  else
    echo "${cln2_port}"
  fi
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
  local mount_args=() plugin_args=()
  if test -n "${hold_plugin}"; then
    mount_args=(-v "${hold_plugin}:/opt/hold-plugin:ro")
    plugin_args=(--plugin=/opt/hold-plugin)
  fi
  "${runtime}" run -d --name "${container}" --network "${network_name}" \
    -p "127.0.0.1:${port}:9735" \
    ${mount_args[@]+"${mount_args[@]}"} \
    "${container_image}" \
    --network=regtest \
    --bitcoin-rpcconnect="${bitcoind_container}" --bitcoin-rpcport=18443 \
    --bitcoin-rpcuser="${rpc_user}" --bitcoin-rpcpassword="${rpc_password}" \
    --bind-addr=0.0.0.0:9735 \
    ${plugin_args[@]+"${plugin_args[@]}"} >/dev/null
}

cmd_up() {
  local with_hold=0
  while test "$#" -gt 0; do
    case "$1" in
    --with-hold) with_hold=1 ;;
    *)
      echo "lab-cln: unknown up option '$1'" >&2
      exit 1
      ;;
    esac
    shift
  done
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
    echo "lab-cln: install Core Lightning (macOS: brew install core-lightning; Debian: apt-get install lightningd) or Docker/Podman" >&2
    exit 1
  fi
  if test "${runtime}" != native && test "${btc_runtime}" = native; then
    echo "lab-cln: container CLN cannot reach a native loopback bitcoind; install lightningd natively or run lab-bitcoind in container mode" >&2
    exit 1
  fi

  local hold_plugin=""
  if test "${with_hold}" = 1; then
    hold_plugin="$(resolve_hold_plugin)"
    if test -z "${hold_plugin}"; then
      echo "lab-cln: hold plugin REQUESTED but ABSENT (set IMMORTAL_LAB_CLN_HOLD_PLUGIN or put 'hold' on PATH); starting without it" >&2
      with_hold=0
    fi
  fi

  for node in 1 2; do
    case "${runtime}" in
    native) start_native_node "${node}" "${hold_plugin}" ;;
    docker | podman) start_container_node "${runtime}" "${node}" "${hold_plugin}" ;;
    esac
  done
  echo "${runtime}" >"${lab_dir}/cln-runtime"
  for node in 1 2; do
    wait_node_ready "${runtime}" "${node}"
  done
  echo "lab-cln: ${runtime} regtest nodes up"
  for node in 1 2; do
    echo "lab-cln: cln${node} id $(cln_cli "${runtime}" "${node}" getinfo | jq -r .id) port $(node_port "${node}")"
  done
  if test "${with_hold}" = 1; then
    echo "lab-cln: hold plugin LOADED from ${hold_plugin}"
  else
    echo "lab-cln: hold plugin ABSENT — hold-invoice (reverse swap) scenarios are unavailable until it is installed (see immortal#25 rail prerequisites)"
  fi
}

cmd_fund() {
  local runtime
  runtime="$(require_up)"
  for node in 1 2; do
    local address
    address="$(cln_cli "${runtime}" "${node}" newaddr | jq -r .bech32)"
    scripts/lab-bitcoind.sh cli -rpcwallet=lab sendtoaddress "${address}" 1.0 >/dev/null
    echo "lab-cln: sent 1.0 BTC to cln${node} (${address})"
  done
  scripts/lab-bitcoind.sh mine 6 >/dev/null
  for node in 1 2; do
    for _ in $(seq 1 150); do
      if test "$(cln_cli "${runtime}" "${node}" listfunds | jq '[.outputs[] | select(.status == "confirmed")] | length')" -gt 0; then
        break
      fi
      sleep 0.2
    done
    echo "lab-cln: cln${node} confirmed on-chain funds $(cln_cli "${runtime}" "${node}" listfunds | jq '[.outputs[] | select(.status == "confirmed") | .amount_msat] | add // 0') msat"
  done
}

cmd_channel() {
  local runtime cln2_id cln2_host
  runtime="$(require_up)"
  cln2_id="$(cln_cli "${runtime}" 2 getinfo | jq -r .id)"
  if test "${runtime}" = native; then
    cln2_host="127.0.0.1:${cln2_port}"
  else
    cln2_host="$(node_container 2):9735"
  fi
  cln_cli "${runtime}" 1 connect "${cln2_id}@${cln2_host}" >/dev/null
  cln_cli "${runtime}" 1 fundchannel "${cln2_id}" "${channel_sat}" >/dev/null
  scripts/lab-bitcoind.sh mine 6 >/dev/null
  for _ in $(seq 1 300); do
    if test "$(cln_cli "${runtime}" 1 listpeerchannels "${cln2_id}" | jq -r '.channels[0].state')" = CHANNELD_NORMAL; then
      break
    fi
    sleep 0.2
  done
  if test "$(cln_cli "${runtime}" 1 listpeerchannels "${cln2_id}" | jq -r '.channels[0].state')" != CHANNELD_NORMAL; then
    echo "lab-cln: channel did not reach CHANNELD_NORMAL" >&2
    exit 1
  fi
  echo "lab-cln: channel cln1 -> cln2 open (${channel_sat} sat)"
  local invoice
  invoice="$(cln_cli "${runtime}" 2 invoice "${rebalance_msat}" "lab-rebalance-$(date +%s)" "lab channel balancing" | jq -r .bolt11)"
  cln_cli "${runtime}" 1 pay "${invoice}" >/dev/null
  echo "lab-cln: pushed ${rebalance_msat} msat to cln2; channel is roughly balanced"
  cln_cli "${runtime}" 1 listpeerchannels "${cln2_id}" |
    jq '{state: .channels[0].state, total_msat: .channels[0].total_msat, to_us_msat: .channels[0].to_us_msat}'
}

cmd_status() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" = none; then
    echo "lab-cln: down (no recorded nodes under ${lab_dir})"
    return 0
  fi
  echo "lab-cln: runtime ${runtime}"
  for node in 1 2; do
    local info
    info="$(cln_cli "${runtime}" "${node}" getinfo)"
    echo "lab-cln: cln${node} id $(echo "${info}" | jq -r .id) port $(node_port "${node}") dir $(node_dir "${node}")$(test "${runtime}" = native || echo " (node data inside container $(node_container "${node}"))")"
    if cln_cli "${runtime}" "${node}" plugin list | jq -er '.plugins[] | select(.name | test("hold"))' >/dev/null 2>&1; then
      echo "lab-cln: cln${node} hold plugin LOADED"
    else
      echo "lab-cln: cln${node} hold plugin ABSENT"
    fi
  done
  cln_cli "${runtime}" 1 listpeerchannels |
    jq '[.channels[] | {peer_id, state, total_msat, to_us_msat}]'
}

cmd_down() {
  local runtime
  runtime="$(recorded_runtime)"
  case "${runtime}" in
  none)
    echo "lab-cln: nothing recorded to tear down"
    ;;
  native)
    for node in 1 2; do
      cln_cli native "${node}" stop >/dev/null 2>&1 || true
      rm -rf "$(node_dir "${node}")"
    done
    rm -f "${lab_dir}/cln-runtime"
    echo "lab-cln: native nodes stopped and their directories removed"
    ;;
  docker | podman)
    for node in 1 2; do
      "${runtime}" rm -f "$(node_container "${node}")" >/dev/null 2>&1 || true
      rm -rf "$(node_dir "${node}")"
    done
    rm -f "${lab_dir}/cln-runtime"
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
  if test "${node}" != 1 && test "${node}" != 2; then
    echo "lab-cln: cli requires a node number (1 or 2)" >&2
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
