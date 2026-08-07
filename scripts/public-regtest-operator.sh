#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

state_dir="${IMMORTAL_PUBLIC_REGTEST_STATE_DIR:-}"
gateway_state="${IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR:-${state_dir}/gateway}"
interval="${IMMORTAL_PUBLIC_REGTEST_OPERATOR_INTERVAL_SECONDS:-10}"

fail() { echo "public-regtest-operator: $*" >&2; exit 1; }

case "${state_dir}" in /*) ;; *) fail "IMMORTAL_PUBLIC_REGTEST_STATE_DIR must be absolute" ;; esac
case "${gateway_state}" in /*) ;; *) fail "gateway state directory must be absolute" ;; esac
export IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR="${gateway_state}"
test -f "${state_dir}/ownership.json" || fail "owned topology state is not initialized"
for command_name in docker jq python3; do
  command -v "${command_name}" >/dev/null 2>&1 || fail "${command_name} is required"
done

compose_project="$(jq -er .compose_project "${state_dir}/ownership.json")"
[[ "${compose_project}" =~ ^immortal-public-regtest-[0-9a-f]{10}$ ]] ||
  fail "owned topology has an invalid Compose project"

compose=(docker compose --project-directory . --project-name "${compose_project}"
  --env-file "${state_dir}/compose.env"
  -f scripts/support/provider-funded/adversarial-compose.yaml
  -f deploy/public-regtest/compose.yaml)

lightning_balance() {
  local service="$1"
  "${compose[@]}" exec -T "${service}" lightning-cli --network=regtest \
    --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc \
    listpeerchannels | jq -er '
      def msat: if type == "object" then .msat else . end;
      . as $root |
      [$root.channels[] | select(.state == "CHANNELD_NORMAL") | (.to_us_msat | msat)] | add as $local |
      [$root.channels[] | select(.state == "CHANNELD_NORMAL") | ((.total_msat | msat) - (.to_us_msat | msat))] | add as $remote |
      [$local, $remote] | @tsv'
}

cln() {
  local service="$1"; shift
  "${compose[@]}" exec -T "${service}" lightning-cli --network=regtest \
    --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc "$@"
}

mine_once() {
  compgen -G "${gateway_state}/sessions/*/admission-*.json" >/dev/null || {
    echo '{"schema":"openagents.immortal.public-regtest-mining.v1","blocks":0,"reason":"no_admitted_effect"}'
    return
  }
  local mempool address
  mempool="$("${compose[@]}" exec -T bitcoin-a bitcoin-cli \
    -conf=/run/immortal-private/bitcoin-a.conf -datadir=/var/lib/bitcoin getmempoolinfo | jq -er .size)"
  test "${mempool}" -gt 0 || {
    echo '{"schema":"openagents.immortal.public-regtest-mining.v1","blocks":0,"reason":"empty_mempool"}'
    return
  }
  address="$("${compose[@]}" exec -T bitcoin-a bitcoin-cli \
    -conf=/run/immortal-private/bitcoin-a.conf -datadir=/var/lib/bitcoin \
    -rpcwallet=public-regtest-miner getnewaddress)"
  "${compose[@]}" exec -T bitcoin-a bitcoin-cli \
    -conf=/run/immortal-private/bitcoin-a.conf -datadir=/var/lib/bitcoin \
    -rpcwallet=public-regtest-miner generatetoaddress 6 "${address}" >/dev/null
  echo '{"schema":"openagents.immortal.public-regtest-mining.v1","blocks":6,"reason":"admitted_effect_with_mempool"}'
}

rebalance_provider() {
  local provider="$1" label invoice
  read -r local_msat remote_msat < <(lightning_balance "${provider}")
  label="public-regtest-rebalance-${provider}-$(date +%s)-$RANDOM"
  if test "${local_msat}" -lt 250000000; then
    invoice="$(cln "${provider}" invoice 100000000 "${label}" public-regtest-rebalance | jq -er .bolt11)"
    cln cln-wallet pay "${invoice}" >/dev/null
  elif test "${remote_msat}" -lt 250000000; then
    invoice="$(cln cln-wallet invoice 100000000 "${label}" public-regtest-rebalance | jq -er .bolt11)"
    cln "${provider}" pay "${invoice}" >/dev/null
  fi
}

rebalance() {
  write_readiness >/dev/null
  test "$(jq -er .active_sessions "${gateway_state}/readiness.json")" -eq 0 || fail "cannot rebalance with active sessions"
  test "$(jq -er .outstanding_sat "${gateway_state}/readiness.json")" -eq 0 || fail "cannot rebalance with outstanding effects"
  rebalance_provider cln-provider-a
  rebalance_provider cln-provider-b
  write_readiness
}

write_readiness() {
  install -d -m 0700 "${gateway_state}"
  local manifest_file failures_file topology_log free_kib free_bytes revision
  manifest_file="$(mktemp "${gateway_state}/operator-manifest.XXXXXX")"
  failures_file="$(mktemp "${gateway_state}/operator-failures.XXXXXX")"
  topology_log="$(mktemp "${gateway_state}/operator-topology.XXXXXX")"

  if ! IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${state_dir}" \
    scripts/public-regtest-topology.sh status >"${manifest_file}" 2>"${topology_log}"; then
    printf '%s\n' topology_unready >>"${failures_file}"
  fi
  for service in cln-provider-a cln-provider-b cln-wallet; do
    if balance="$(lightning_balance "${service}" 2>/dev/null)"; then
      local_msat="${balance%%$'\t'*}"
      remote_msat="${balance##*$'\t'}"
      if test "${local_msat}" -lt 250000000 || test "${remote_msat}" -lt 250000000; then
        printf 'lightning_liquidity_%s\n' "${service}" >>"${failures_file}"
      fi
      if test "$((local_msat + remote_msat))" -gt 10000000000; then
        printf 'lightning_capacity_%s\n' "${service}" >>"${failures_file}"
      fi
    else
      printf 'lightning_unavailable_%s\n' "${service}" >>"${failures_file}"
    fi
  done
  free_kib="$(df -Pk "${state_dir}" | awk 'NR==2 {print $4}')"
  [[ "${free_kib}" =~ ^[0-9]+$ ]] || fail "free disk capacity is not an integer"
  free_bytes="$((free_kib * 1024))"
  if test "${free_bytes}" -lt 1073741824; then printf '%s\n' disk_space_low >>"${failures_file}"; fi
  test ! -e "${gateway_state}/maintenance" || printf '%s\n' maintenance >>"${failures_file}"
  revision="$(jq -er .source_revision "${state_dir}/ownership.json")"

  if ! python3 - "${gateway_state}" "${manifest_file}" "${failures_file}" \
    "${revision}" <<'PY'
import json, os, pathlib, sys, time
root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
failures_path = pathlib.Path(sys.argv[3])
revision = sys.argv[4]
failures = sorted(set(line.strip().split()[-1] for line in failures_path.read_text().splitlines() if line.strip()))
try:
    manifest = json.loads(manifest_path.read_text())
except Exception:
    manifest = {}
    failures.append("topology_manifest_unavailable")
providers = sorted(item.get("pubkey", "") for item in manifest.get("providers", []))
nodes = [item.get("node_id", "") for item in manifest.get("lightning", {}).get("nodes", [])]
height = manifest.get("chain", {}).get("height", 0)
active = outstanding = 0
sessions = root / "sessions"
now = int(time.time())
if sessions.exists():
    for entry in sessions.iterdir():
        try:
            state = json.loads((entry / "session.json").read_text())
        except Exception:
            failures.append("session_state_unavailable")
            continue
        if state.get("revoked_at") is None and now < state.get("expires_at", 0):
            active += 1
            for effect in state.get("authorizations", []):
                effect_id = effect.get("effect", {}).get("effect_id", "")
                if not (entry / f"receipt-{effect_id}.json").exists():
                    outstanding += int(effect.get("effect", {}).get("amount_sat", 0))
if active > 16: failures.append("active_session_capacity")
if outstanding > 5_000_000: failures.append("outstanding_value_capacity")
value = {
    "schema":"openagents.immortal.public-regtest-service-readiness.v1",
    "ready":not failures,
    "checked_at":now,
    "revision":revision,
    "failures":sorted(set(failures)),
    "active_sessions":active,
    "outstanding_sat":outstanding,
    "provider_pubkeys":providers,
    "lightning_node_ids":nodes,
    "bitcoin_height":height,
    "receipt_store_writable":os.access(root, os.W_OK),
}
temporary = root / "readiness.json.tmp"
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump(value, output, sort_keys=True, separators=(",", ":")); output.write("\n")
    output.flush(); os.fsync(output.fileno())
os.replace(temporary, root / "readiness.json")
os.chmod(root / "readiness.json", 0o600)
print(json.dumps(value, sort_keys=True))
PY
  then
    rm -f -- "${manifest_file}" "${failures_file}" "${topology_log}"
    return 1
  fi
  rm -f -- "${manifest_file}" "${failures_file}" "${topology_log}"
}

cleanup_sessions() {
  python3 - "${gateway_state}" <<'PY'
import json, pathlib, re, shutil, sys, time
root = pathlib.Path(sys.argv[1]); sessions = root / "sessions"; now = int(time.time())
if root.is_symlink() or sessions.is_symlink(): raise SystemExit("cleanup root is a symlink")
if not sessions.exists(): raise SystemExit(0)
removed = 0
for entry in sessions.iterdir():
    if entry.is_symlink() or not entry.is_dir() or re.fullmatch(r"[0-9a-f]{64}", entry.name) is None: continue
    try: state = json.loads((entry / "session.json").read_text())
    except Exception: continue
    admissions = {p.name.removeprefix("admission-").removesuffix(".json") for p in entry.glob("admission-*.json")}
    receipts = {p.name.removeprefix("receipt-").removesuffix(".json") for p in entry.glob("receipt-*.json")}
    if not admissions.issubset(receipts): continue
    terminal_at = state.get("revoked_at") or state.get("expires_at", now + 1)
    retention = 604800 if receipts else 86400
    if now - int(terminal_at) < retention: continue
    shutil.rmtree(entry); removed += 1
print(json.dumps({"schema":"openagents.immortal.public-regtest-cleanup.v1","removed_sessions":removed}))
PY
}

process_dynamic_requests() {
  local request session_id worker_lock session_state owner_pid now
  shopt -s nullglob
  for request in "${gateway_state}"/sessions/*/private-dynamic-request.json; do
    session_id="$(basename "$(dirname "${request}")")"
    [[ "${session_id}" =~ ^[0-9a-f]{64}$ ]] || continue
    session_state="${gateway_state}/sessions/${session_id}/session.json"
    test -f "${session_state}" || continue
    jq -e '.revoked_at == null and (.journey.stage // "") != "completed"' \
      "${session_state}" >/dev/null 2>&1 || continue
    now="$(date +%s)"
    jq -e --argjson now "${now}" \
      '.request.expires_at | type == "number" and . > $now' \
      "${request}" >/dev/null 2>&1 || continue
    worker_lock="${gateway_state}/sessions/${session_id}/dynamic-worker.lock"
    if test -d "${worker_lock}"; then
      owner_pid="$(cat "${worker_lock}/pid" 2>/dev/null || true)"
      if [[ "${owner_pid}" =~ ^[0-9]+$ ]] && kill -0 "${owner_pid}" 2>/dev/null; then
        continue
      fi
      rm -f -- "${worker_lock}/pid"
      rmdir "${worker_lock}" 2>/dev/null || continue
    fi
    if ! mkdir "${worker_lock}" 2>/dev/null; then continue; fi
    install -d -m 0700 "${state_dir}/state/public-sessions/${session_id}"
    (
      printf '%s\n' "${BASHPID}" >"${worker_lock}/pid"
      if ! "${compose[@]}" --profile acceptance run --rm \
        --user "$(id -u):$(id -g)" \
        -e "IMMORTAL_PUBLIC_REGTEST_SESSION_ID=${session_id}" \
        -e "IMMORTAL_LAB_STATE_DIR=/state/public-sessions/${session_id}" \
        wallet-driver public-regtest-dynamic-worker-once >/dev/null 2>&1; then
        echo "public-regtest-operator: dynamic worker failed for ${session_id}" >&2
      fi
      rm -f -- "${worker_lock}/pid"
      rmdir "${worker_lock}" 2>/dev/null || true
    ) &
    break
  done
  shopt -u nullglob
}

process_demo_inputs() {
  local request session_id worker_lock response
  shopt -s nullglob
  for request in "${gateway_state}"/sessions/*/demo-input-request.json; do
    session_id="$(basename "$(dirname "${request}")")"
    [[ "${session_id}" =~ ^[0-9a-f]{64}$ ]] || continue
    response="${gateway_state}/sessions/${session_id}/demo-input-response.json"
    test ! -e "${response}" || continue
    worker_lock="${gateway_state}/sessions/${session_id}/demo-input-worker.lock"
    if ! mkdir "${worker_lock}" 2>/dev/null; then continue; fi
    install -d -m 0700 "${state_dir}/state/public-sessions/${session_id}"
    if ! "${compose[@]}" --profile acceptance run --rm \
      --user "$(id -u):$(id -g)" \
      -e "IMMORTAL_PUBLIC_REGTEST_SESSION_ID=${session_id}" \
      -e "IMMORTAL_LAB_STATE_DIR=/state/public-sessions/${session_id}" \
      wallet-driver public-regtest-demo-input-once >/dev/null 2>&1; then
      echo "public-regtest-operator: demo input worker failed for ${session_id}" >&2
    fi
    rmdir "${worker_lock}" 2>/dev/null || true
    break
  done
  shopt -u nullglob
}

case "${1:-}" in
  once) write_readiness; process_demo_inputs; process_dynamic_requests; cleanup_sessions ;;
  status) test -f "${gateway_state}/readiness.json" || fail "readiness has not been published"; cat "${gateway_state}/readiness.json" ;;
  loop)
    while true; do
      write_readiness || true
      process_demo_inputs || true
      process_dynamic_requests || true
      mine_once || true
      cleanup_sessions || true
      if jq -e '
        .active_sessions == 0 and .outstanding_sat == 0 and
        any(.failures[]; startswith("lightning_liquidity_"))
      ' "${gateway_state}/readiness.json" >/dev/null 2>&1; then
        rebalance || true
      fi
      sleep "${interval}"
    done
    ;;
  maintenance)
    case "${2:-}" in
      on) install -d -m 0700 "${gateway_state}"; install -m 0600 /dev/null "${gateway_state}/maintenance" ;;
      off) rm -f -- "${gateway_state}/maintenance" ;;
      *) fail "maintenance requires on or off" ;;
    esac
    write_readiness ;;
  cleanup) cleanup_sessions ;;
  mine) mine_once ;;
  rebalance) rebalance ;;
  *) echo "usage: scripts/public-regtest-operator.sh {once|status|loop|maintenance on|maintenance off|cleanup|mine|rebalance}" >&2; exit 2 ;;
esac
