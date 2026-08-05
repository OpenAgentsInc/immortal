#!/usr/bin/env bash
# Disposable regtest bitcoind for the adversarial lab (immortal#32/#18).
# Uses bitcoind from PATH when available, otherwise a Docker/Podman
# container. Teardown removes only what this script created.
#
# The RPC credential below is a throwaway loopback regtest fixture, not a
# secret: it guards a disposable chain with no value on 127.0.0.1 only.
set -euo pipefail
cd "$(dirname "$0")/.."

lab_dir="${IMMORTAL_LAB_DIR:-${TMPDIR:-/tmp}/immortal-lab}"
btc_dir="${lab_dir}/bitcoind"
rpc_port="${IMMORTAL_LAB_BITCOIND_RPC_PORT:-18543}"
p2p_port="${IMMORTAL_LAB_BITCOIND_P2P_PORT:-18544}"
rpc_user="${IMMORTAL_LAB_BITCOIND_RPC_USER:-immortal}"
rpc_password="${IMMORTAL_LAB_BITCOIND_RPC_PASSWORD:-immortal-lab-regtest}"
container_image="${IMMORTAL_LAB_BITCOIND_IMAGE:-bitcoin/bitcoin:29.0}"
container_name="immortal-lab-bitcoind"
network_name="immortal-lab"
wallet_name="lab"
rbf_initial_fee_rate="${IMMORTAL_LAB_RBF_INITIAL_FEE_RATE:-2}"
rbf_replacement_fee_rate="${IMMORTAL_LAB_RBF_REPLACEMENT_FEE_RATE:-4}"

usage() {
  cat <<'USAGE'
usage: scripts/lab-bitcoind.sh <command> [arguments]

commands:
  up                     start disposable regtest bitcoind, create the "lab"
                         wallet, mine past coin maturity (101 blocks)
  mine <n> [address]     mine n blocks (default: to a lab wallet address)
  mine-past <height>     mine until the chain height exceeds <height>
                         (timelock-ladder helper)
  invalidate <hash|tip>  invalidate a block (reorg helper)
  rbf-send <address> <amount-btc> [sat/vB]
                         create and broadcast an unconfirmed opt-in-RBF wallet
                         payment (default fee rate: 2 sat/vB)
  rbf-replace <txid> [sat/vB]
                         replace an unconfirmed lab-wallet payment at a higher
                         explicit fee rate (default: 4 sat/vB)
  cli <arguments...>     run bitcoin-cli against the lab node
  status                 print runtime, ports, height, and wallet balance
  down                   stop the node and remove only what `up` created

environment:
  IMMORTAL_LAB_DIR                  lab state root (default ${TMPDIR:-/tmp}/immortal-lab)
  IMMORTAL_LAB_BITCOIND_RPC_PORT    loopback RPC port (default 18543)
  IMMORTAL_LAB_BITCOIND_P2P_PORT    loopback P2P port (default 18544)
  IMMORTAL_LAB_BITCOIND_IMAGE      container image fallback (default bitcoin/bitcoin:29.0)
  IMMORTAL_LAB_RBF_INITIAL_FEE_RATE       rbf-send fee rate in sat/vB (default 2)
  IMMORTAL_LAB_RBF_REPLACEMENT_FEE_RATE   rbf-replace fee rate in sat/vB (default 4)
USAGE
}

detect_runtime() {
  if command -v bitcoind >/dev/null && command -v bitcoin-cli >/dev/null; then
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
  if test -f "${btc_dir}/runtime"; then
    cat "${btc_dir}/runtime"
  else
    echo none
  fi
}

require_up() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" = none; then
    echo "lab-bitcoind: no lab node is recorded; run 'scripts/lab-bitcoind.sh up' first" >&2
    exit 1
  fi
  echo "${runtime}"
}

btc_cli() {
  local runtime="$1"
  shift
  case "${runtime}" in
  native)
    bitcoin-cli -regtest -datadir="${btc_dir}/data" -rpcport="${rpc_port}" \
      -rpcuser="${rpc_user}" -rpcpassword="${rpc_password}" "$@"
    ;;
  docker | podman)
    "${runtime}" exec "${container_name}" bitcoin-cli -regtest \
      -rpcuser="${rpc_user}" -rpcpassword="${rpc_password}" "$@"
    ;;
  *)
    echo "lab-bitcoind: unknown recorded runtime '${runtime}'" >&2
    exit 1
    ;;
  esac
}

wallet_cli() {
  local runtime="$1"
  shift
  btc_cli "${runtime}" -rpcwallet="${wallet_name}" "$@"
}

wait_ready() {
  local runtime="$1"
  for _ in $(seq 1 300); do
    if btc_cli "${runtime}" getblockchaininfo >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "lab-bitcoind: node did not become ready" >&2
  exit 1
}

cmd_up() {
  if test "$(recorded_runtime)" != none; then
    echo "lab-bitcoind: a lab node is already recorded under ${btc_dir}; run 'down' first" >&2
    exit 1
  fi
  if test -e "${btc_dir}"; then
    echo "lab-bitcoind: refusing to reuse unrecorded path ${btc_dir}" >&2
    exit 1
  fi
  local runtime
  runtime="$(detect_runtime)"
  if test "${runtime}" = none; then
    echo "lab-bitcoind: install bitcoind (macOS: brew install bitcoin; Debian: apt-get install bitcoind) or Docker/Podman" >&2
    exit 1
  fi
  if test "${runtime}" != native && "${runtime}" container inspect "${container_name}" >/dev/null 2>&1; then
    echo "lab-bitcoind: refusing to replace existing container ${container_name}" >&2
    exit 1
  fi
  mkdir -p "${btc_dir}"
  touch "${btc_dir}/created"
  echo "${runtime}" >"${btc_dir}/runtime"
  trap 'cmd_down >/dev/null 2>&1 || true' EXIT
  case "${runtime}" in
  native)
    mkdir -p "${btc_dir}/data"
    bitcoind -regtest -datadir="${btc_dir}/data" \
      -rpcport="${rpc_port}" -port="${p2p_port}" \
      -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1/32 \
      -rpcuser="${rpc_user}" -rpcpassword="${rpc_password}" \
      -fallbackfee=0.0001 -daemonwait
    ;;
  docker | podman)
    if ! "${runtime}" network inspect "${network_name}" >/dev/null 2>&1; then
      "${runtime}" network create "${network_name}" >/dev/null
      touch "${btc_dir}/network-created"
      "${runtime}" network inspect --format '{{.Id}}' "${network_name}" >"${btc_dir}/network-id"
    fi
    "${runtime}" run -d --name "${container_name}" --network "${network_name}" \
      -p "127.0.0.1:${rpc_port}:18443" -p "127.0.0.1:${p2p_port}:18444" \
      "${container_image}" \
      -regtest=1 -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
      -rpcuser="${rpc_user}" -rpcpassword="${rpc_password}" \
      -fallbackfee=0.0001 -printtoconsole >/dev/null
    "${runtime}" container inspect --format '{{.Id}}' "${container_name}" >"${btc_dir}/container-id"
    echo "lab-bitcoind: note: container mode keeps the chain datadir inside ${container_name}; teardown removes the container"
    ;;
  esac
  wait_ready "${runtime}"
  if ! btc_cli "${runtime}" loadwallet "${wallet_name}" >/dev/null 2>&1; then
    btc_cli "${runtime}" createwallet "${wallet_name}" >/dev/null
  fi
  local address
  address="$(wallet_cli "${runtime}" getnewaddress)"
  wallet_cli "${runtime}" generatetoaddress 101 "${address}" >/dev/null
  echo "lab-bitcoind: ${runtime} regtest node up"
  echo "lab-bitcoind: rpc 127.0.0.1:${rpc_port} p2p 127.0.0.1:${p2p_port} wallet ${wallet_name}"
  echo "lab-bitcoind: height $(btc_cli "${runtime}" getblockcount) (coin maturity reached)"
  trap - EXIT
}

cmd_mine() {
  local blocks="${1:-}"
  if ! [[ "${blocks}" =~ ^[0-9]+$ ]]; then
    echo "lab-bitcoind: mine requires a block count" >&2
    exit 1
  fi
  local runtime
  runtime="$(require_up)"
  local address="${2:-}"
  if test -z "${address}"; then
    address="$(wallet_cli "${runtime}" getnewaddress)"
  fi
  wallet_cli "${runtime}" generatetoaddress "${blocks}" "${address}" >/dev/null
  echo "lab-bitcoind: mined ${blocks} blocks to ${address}; height $(btc_cli "${runtime}" getblockcount)"
}

cmd_mine_past() {
  local target="${1:-}"
  if ! [[ "${target}" =~ ^[0-9]+$ ]]; then
    echo "lab-bitcoind: mine-past requires a target height" >&2
    exit 1
  fi
  local runtime height needed address
  runtime="$(require_up)"
  height="$(btc_cli "${runtime}" getblockcount)"
  if test "${height}" -gt "${target}"; then
    echo "lab-bitcoind: height ${height} already exceeds ${target}"
    return 0
  fi
  needed=$((target + 1 - height))
  address="$(wallet_cli "${runtime}" getnewaddress)"
  wallet_cli "${runtime}" generatetoaddress "${needed}" "${address}" >/dev/null
  echo "lab-bitcoind: mined ${needed} blocks; height $(btc_cli "${runtime}" getblockcount) exceeds ${target}"
}

cmd_invalidate() {
  local block="${1:-}"
  if test -z "${block}"; then
    echo "lab-bitcoind: invalidate requires a block hash or 'tip'" >&2
    exit 1
  fi
  local runtime
  runtime="$(require_up)"
  if test "${block}" = tip; then
    block="$(btc_cli "${runtime}" getbestblockhash)"
  fi
  btc_cli "${runtime}" invalidateblock "${block}"
  echo "lab-bitcoind: invalidated ${block}; height $(btc_cli "${runtime}" getblockcount)"
}

valid_fee_rate() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]] && test -n "${1//[0.]/}"
}

cmd_rbf_send() {
  local address="${1:-}" amount="${2:-}" fee_rate="${3:-${rbf_initial_fee_rate}}"
  if test -z "${address}" || test -z "${amount}"; then
    echo "lab-bitcoind: rbf-send requires an address and BTC amount" >&2
    exit 1
  fi
  if ! [[ "${amount}" =~ ^[0-9]+([.][0-9]+)?$ ]] || test -z "${amount//[0.]/}"; then
    echo "lab-bitcoind: rbf-send amount must be a positive decimal BTC value" >&2
    exit 1
  fi
  if ! valid_fee_rate "${fee_rate}"; then
    echo "lab-bitcoind: rbf-send fee rate must be a positive decimal sat/vB value" >&2
    exit 1
  fi
  local runtime address_valid result transaction_id
  runtime="$(require_up)"
  address_valid="$(btc_cli "${runtime}" validateaddress "${address}" | jq -r '.isvalid')"
  if test "${address_valid}" != true; then
    echo "lab-bitcoind: rbf-send address is not valid for regtest" >&2
    exit 1
  fi
  result="$(wallet_cli "${runtime}" -named sendtoaddress \
    address="${address}" amount="${amount}" replaceable=true \
    fee_rate="${fee_rate}" verbose=true)"
  transaction_id="$(printf '%s' "${result}" | jq -er '.txid')"
  echo "lab-bitcoind: broadcast opt-in-RBF payment ${transaction_id} at ${fee_rate} sat/vB"
  printf '%s\n' "${result}"
}

cmd_rbf_replace() {
  local transaction_id="${1:-}" fee_rate="${2:-${rbf_replacement_fee_rate}}"
  if ! [[ "${transaction_id}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "lab-bitcoind: rbf-replace requires a 64-character transaction id" >&2
    exit 1
  fi
  if ! valid_fee_rate "${fee_rate}"; then
    echo "lab-bitcoind: rbf-replace fee rate must be a positive decimal sat/vB value" >&2
    exit 1
  fi
  local runtime transaction confirmations replaceable result replacement_id
  runtime="$(require_up)"
  transaction="$(wallet_cli "${runtime}" gettransaction "${transaction_id}")"
  confirmations="$(printf '%s' "${transaction}" | jq -er '.confirmations')"
  replaceable="$(printf '%s' "${transaction}" | jq -er '.["bip125-replaceable"]')"
  if test "${confirmations}" != 0; then
    echo "lab-bitcoind: rbf-replace refuses confirmed transaction ${transaction_id}" >&2
    exit 1
  fi
  if test "${replaceable}" != yes; then
    echo "lab-bitcoind: transaction ${transaction_id} is not opt-in-RBF replaceable" >&2
    exit 1
  fi
  result="$(wallet_cli "${runtime}" bumpfee "${transaction_id}" "{\"fee_rate\":${fee_rate}}")"
  replacement_id="$(printf '%s' "${result}" | jq -er '.txid')"
  btc_cli "${runtime}" getmempoolentry "${replacement_id}" >/dev/null
  echo "lab-bitcoind: replaced ${transaction_id} with ${replacement_id} at ${fee_rate} sat/vB"
  printf '%s\n' "${result}"
}

cmd_status() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" = none; then
    echo "lab-bitcoind: down (no recorded node under ${btc_dir})"
    return 0
  fi
  echo "lab-bitcoind: runtime ${runtime}"
  echo "lab-bitcoind: rpc 127.0.0.1:${rpc_port} p2p 127.0.0.1:${p2p_port}"
  echo "lab-bitcoind: datadir ${btc_dir}$(test "${runtime}" = native || echo " (chain data inside container ${container_name})")"
  echo "lab-bitcoind: height $(btc_cli "${runtime}" getblockcount)"
  echo "lab-bitcoind: ${wallet_name} wallet balance $(wallet_cli "${runtime}" getbalance) BTC"
}

cmd_down() {
  local runtime
  runtime="$(recorded_runtime)"
  if test "${runtime}" != none && ! test -f "${btc_dir}/created"; then
    echo "lab-bitcoind: runtime record has no ownership marker; refusing teardown" >&2
    exit 1
  fi
  case "${runtime}" in
  none)
    echo "lab-bitcoind: nothing recorded to tear down"
    ;;
  native)
    if btc_cli native stop >/dev/null 2>&1; then
      for _ in $(seq 1 100); do
        if ! btc_cli native getblockcount >/dev/null 2>&1; then
          break
        fi
        sleep 0.2
      done
    fi
    rm -rf "${btc_dir}"
    echo "lab-bitcoind: native node stopped and ${btc_dir} removed"
    ;;
  docker | podman)
    local recorded_container_id current_container_id
    recorded_container_id="$(cat "${btc_dir}/container-id" 2>/dev/null || true)"
    current_container_id="$("${runtime}" container inspect --format '{{.Id}}' "${container_name}" 2>/dev/null || true)"
    if test -n "${current_container_id}" && test "${current_container_id}" != "${recorded_container_id}"; then
      echo "lab-bitcoind: ${container_name} no longer matches the created container; refusing teardown" >&2
      exit 1
    fi
    if test -n "${current_container_id}"; then
      "${runtime}" rm -f "${container_name}" >/dev/null
    fi
    if test -f "${btc_dir}/network-created"; then
      local recorded_network_id current_network_id
      recorded_network_id="$(cat "${btc_dir}/network-id" 2>/dev/null || true)"
      current_network_id="$("${runtime}" network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
      if test -n "${current_network_id}" && test "${current_network_id}" != "${recorded_network_id}"; then
        echo "lab-bitcoind: ${network_name} no longer matches the created network; refusing teardown" >&2
        exit 1
      fi
      if test -n "${current_network_id}"; then
        "${runtime}" network rm "${network_name}" >/dev/null
      fi
    fi
    rm -rf "${btc_dir}"
    echo "lab-bitcoind: container removed and ${btc_dir} removed"
    ;;
  *)
    echo "lab-bitcoind: unknown recorded runtime '${runtime}'; refusing to guess at teardown" >&2
    exit 1
    ;;
  esac
}

command="${1:-}"
shift || true
case "${command}" in
up) cmd_up "$@" ;;
mine) cmd_mine "$@" ;;
mine-past) cmd_mine_past "$@" ;;
invalidate) cmd_invalidate "$@" ;;
rbf-send) cmd_rbf_send "$@" ;;
rbf-replace) cmd_rbf_replace "$@" ;;
cli)
  runtime="$(require_up)"
  btc_cli "${runtime}" "$@"
  ;;
status) cmd_status "$@" ;;
down) cmd_down "$@" ;;
help | --help | -h | "") usage ;;
*)
  echo "lab-bitcoind: unknown command '${command}'" >&2
  usage >&2
  exit 1
  ;;
esac
