#!/usr/bin/env bash
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."

command_name="${1:-run}"
state_dir="${IMMORTAL_DEMO_STATE_DIR:-target/immortal-no-spend-demo-state}"
relay_port="${IMMORTAL_DEMO_RELAY_PORT:-18080}"
manifest_path="${state_dir}/manifest.json"

validate_state_path() {
  python3 - "${state_dir}" "$(pwd -P)" <<'PY'
import os
import pathlib
import sys

candidate = pathlib.Path(sys.argv[1])
repo = pathlib.Path(sys.argv[2]).resolve()
if candidate.is_symlink():
    raise SystemExit("demo state directory must not be a symlink")
resolved = candidate.resolve(strict=False)
home = pathlib.Path.home().resolve()
for forbidden in (pathlib.Path("/"), home, repo, repo.parent):
    if resolved == forbidden:
        raise SystemExit(f"refusing unsafe demo state directory {resolved}")
if resolved.name != "immortal-no-spend-demo-state" and not resolved.name.startswith(
    "immortal-no-spend-demo-"
):
    raise SystemExit(
        "demo state directory basename must be immortal-no-spend-demo-state or start with immortal-no-spend-demo-"
    )
print(resolved)
PY
}

state_dir="$(validate_state_path)"
manifest_path="${state_dir}/manifest.json"

validate_owner() {
  python3 - "${state_dir}/owner.json" "${state_dir}" "$(pwd -P)" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
    raise SystemExit("demo state has no bounded regular ownership record")
owner = json.loads(path.read_text(encoding="utf-8"))
if owner != {
    "schema": "openagents.immortal.no-spend-demo-owner.v1",
    "repository": sys.argv[3],
    "state_directory": sys.argv[2],
}:
    raise SystemExit("demo state ownership record does not match this checkout")
PY
}

process_matches() {
  local process_id="$1" expected="$2"
  test -n "${process_id}" \
    && kill -0 "${process_id}" 2>/dev/null \
    && ps -p "${process_id}" -o command= 2>/dev/null | grep -Fq -- "${expected}"
}

stop_pid_file() {
  local label="$1" file="$2" expected="$3"
  local process_id=""
  if test -f "${file}"; then
    process_id="$(tr -d '\r\n' <"${file}")"
  fi
  if test -z "${process_id}"; then
    return 0
  fi
  case "${process_id}" in
    *[!0-9]*)
      echo "dev-no-spend-demo: ${label} pid is invalid; refusing to signal it" >&2
      return 1
      ;;
  esac
  if process_matches "${process_id}" "${expected}"; then
    kill -TERM "${process_id}" 2>/dev/null || true
  elif kill -0 "${process_id}" 2>/dev/null; then
    echo "dev-no-spend-demo: ${label} pid no longer matches its owned process; refusing to signal it" >&2
    return 1
  fi
}

remove_owned_state() {
  validate_owner
  rm -rf -- "${state_dir}"
}

if test "${command_name}" = "status"; then
  validate_owner
  test -f "${manifest_path}"
  exec sed -n '1,260p' "${manifest_path}"
fi

if test "${command_name}" = "restart"; then
  validate_owner
  role="${2:-}"
  case "${role}" in
    provider-a|provider-b)
      : >"${state_dir}/control/restart-${role}"
      echo "dev-no-spend-demo: requested restart of ${role}"
      exit 0
      ;;
    *)
      echo "usage: scripts/dev-no-spend-demo.sh restart <provider-a|provider-b>" >&2
      exit 2
      ;;
  esac
fi

if test "${command_name}" = "down"; then
  validate_owner
  supervisor_pid="$(tr -d '\r\n' <"${state_dir}/supervisor.pid" 2>/dev/null || true)"
  if test -n "${supervisor_pid}" && process_matches "${supervisor_pid}" "dev-no-spend-demo.sh"; then
    kill -TERM "${supervisor_pid}"
    for _ in $(seq 1 100); do
      test ! -e "${state_dir}" && exit 0
      sleep 0.1
    done
    echo "dev-no-spend-demo: supervisor did not finish teardown" >&2
    exit 1
  fi
  stop_pid_file provider-a "${state_dir}/provider-a.pid" "immortal-provider --no-spend"
  stop_pid_file provider-b "${state_dir}/provider-b.pid" "immortal-provider --no-spend"
  stop_pid_file relay "${state_dir}/relay.pid" "dev-relay.sh"
  for _ in $(seq 1 100); do
    remaining=false
    for file in "${state_dir}/provider-a.pid" "${state_dir}/provider-b.pid" "${state_dir}/relay.pid"; do
      process_id="$(tr -d '\r\n' <"${file}" 2>/dev/null || true)"
      if test -n "${process_id}" && kill -0 "${process_id}" 2>/dev/null; then
        remaining=true
      fi
    done
    test "${remaining}" = false && break
    sleep 0.1
  done
  if test "${remaining:-false}" != false; then
    echo "dev-no-spend-demo: owned processes did not stop; preserving state for recovery" >&2
    exit 1
  fi
  remove_owned_state
  exit 0
fi

if test "${command_name}" != "run"; then
  echo "usage: scripts/dev-no-spend-demo.sh [run|status|down|restart <provider-a|provider-b>]" >&2
  exit 2
fi

case "${relay_port}" in
  *[!0-9]*)
    echo "dev-no-spend-demo: IMMORTAL_DEMO_RELAY_PORT must be an integer" >&2
    exit 2
    ;;
esac
if test "${relay_port}" -lt 1024 || test "${relay_port}" -gt 65535; then
  echo "dev-no-spend-demo: relay port must be between 1024 and 65535" >&2
  exit 2
fi
if test -e "${state_dir}"; then
  echo "dev-no-spend-demo: ${state_dir} already exists; run the down command if it is stale" >&2
  exit 1
fi

cargo build --locked -p immortal-relay --bin immortal \
  -p immortal-provider --bin immortal-provider

mkdir -m 700 "${state_dir}"
mkdir -m 700 "${state_dir}/control"
python3 - "${state_dir}/owner.json" "${state_dir}" "$(pwd -P)" <<'PY'
import json
import os
import sys

path = sys.argv[1]
document = {
    "schema": "openagents.immortal.no-spend-demo-owner.v1",
    "repository": sys.argv[3],
    "state_directory": sys.argv[2],
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(document, output, sort_keys=True)
    output.write("\n")
PY
early_cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test -e "${state_dir}"; then
    remove_owned_state || exit_status=1
  fi
  exit "${exit_status}"
}
trap early_cleanup EXIT INT TERM
printf '%s\n' "$$" >"${state_dir}/supervisor.pid"
chmod 600 "${state_dir}/supervisor.pid"

python3 - "${state_dir}/provider-a.secret" "${state_dir}/provider-b.secret" <<'PY'
import os
import secrets
import sys

order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
for path in sys.argv[1:]:
    while True:
        value = secrets.randbelow(order)
        if value:
            break
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(f"{value:064x}\n")
PY

target/debug/immortal contract >"${state_dir}/relay-contract.json"
chmod 600 "${state_dir}/relay-contract.json"
relay_contract_sha256="$(shasum -a 256 "${state_dir}/relay-contract.json" | awk '{print $1}')"
source_revision="$(git rev-parse HEAD)"
relay_url="ws://127.0.0.1:${relay_port}"
relay_pid=""
provider_a_pid=""
provider_b_pid=""
provider_a_pubkey=""
provider_b_pubkey=""
provider_a_restarts=0
provider_b_restarts=0
provider_a_state="starting"
provider_b_state="starting"
relay_state="starting"

write_manifest() {
  python3 - "${state_dir}/relay-contract.json" "${manifest_path}" \
    "${source_revision}" "${relay_url}" "${relay_contract_sha256}" \
    "${relay_state}" "${provider_a_pubkey}" "${provider_a_state}" "${provider_a_restarts}" \
    "${provider_b_pubkey}" "${provider_b_state}" "${provider_b_restarts}" <<'PY'
import json
import os
import pathlib
import re
import sys

contract_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
providers = []
rows = [
    ("provider-a", sys.argv[7], sys.argv[8], int(sys.argv[9]), "default", "immortal-no-spend-swaps", 600, 0),
    ("provider-b", sys.argv[10], sys.argv[11], int(sys.argv[12]), "demo_alternate", "immortal-no-spend-swaps-demo-alternate", 420, 120),
]
for role, pubkey, state, restarts, variant, offering_id, lifetime, discount in rows:
    if pubkey and re.fullmatch(r"[0-9a-f]{64}", pubkey) is None:
        raise SystemExit(f"{role} readiness emitted an invalid public key")
    providers.append({
        "role": role,
        "pubkey": pubkey or None,
        "offering_coordinate": f"39601:{pubkey}:{offering_id}" if pubkey else None,
        "policy": {
            "variant": variant,
            "quote_class": "firm",
            "reservation_class": "soft",
            "quote_lifetime_seconds": lifetime,
            "completion_discount_seconds": discount,
            "settlement_claim": "coordination only; no external spend effects",
        },
        "health": {"state": state, "restart_count": restarts},
    })
document = {
    "schema": "openagents.immortal.no-spend-demo-manifest.v1",
    "source_revision": sys.argv[3],
    "network": "regtest",
    "mode": "no_spend",
    "relay": {
        "websocket_url": sys.argv[4],
        "health_url": sys.argv[4].replace("ws://", "http://") + "/health",
        "contract_sha256": sys.argv[5],
        "contract_identity": contract["identity"],
        "health": {"state": sys.argv[6]},
    },
    "providers": providers,
    "lifecycle": {
        "terminal_path": "bilateral_contract_then_mutual_cancel",
        "external_spend_effects": 0,
        "close_loss_classification": "none",
    },
    "bounds": {"relay_count": 1, "provider_count": 2, "maximum_manifest_bytes": 32768},
}
encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > 32768:
    raise SystemExit("public demo manifest exceeds its bound")
temporary = output_path.with_suffix(".json.tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, output_path)
os.chmod(output_path, 0o644)
PY
}

wait_for_relay() {
  for _ in $(seq 1 600); do
    if curl --fail --silent --show-error "http://127.0.0.1:${relay_port}/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${relay_pid}" 2>/dev/null; then
      wait "${relay_pid}" || true
      echo "dev-no-spend-demo: relay exited before readiness" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "dev-no-spend-demo: relay did not become ready" >&2
  return 1
}

wait_for_provider() {
  local role="$1" process_id="$2" log_path="$3"
  for _ in $(seq 1 600); do
    if grep -Fq "no-spend ready relay=${relay_url} pubkey=" "${log_path}"; then
      sed -n "s/.*no-spend ready relay=.* pubkey=\([0-9a-f]\{64\}\).*/\1/p" "${log_path}" | tail -1
      return 0
    fi
    if ! kill -0 "${process_id}" 2>/dev/null; then
      wait "${process_id}" || true
      echo "dev-no-spend-demo: ${role} exited before readiness" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "dev-no-spend-demo: ${role} did not become ready" >&2
  return 1
}

start_provider_a() {
  : >"${state_dir}/provider-a.log"
  IMMORTAL_PROVIDER_IDENTITY_SECRET="$(tr -d '\r\n' <"${state_dir}/provider-a.secret")" \
    IMMORTAL_PROVIDER_RELAY_URL="${relay_url}" \
    IMMORTAL_PROVIDER_NO_SPEND_VARIANT=default \
    target/debug/immortal-provider --no-spend \
    >"${state_dir}/provider-a.log" 2>&1 &
  provider_a_pid=$!
  printf '%s\n' "${provider_a_pid}" >"${state_dir}/provider-a.pid"
  chmod 600 "${state_dir}/provider-a.pid"
  provider_a_pubkey="$(wait_for_provider provider-a "${provider_a_pid}" "${state_dir}/provider-a.log")"
  provider_a_state="ready"
}

start_provider_b() {
  : >"${state_dir}/provider-b.log"
  IMMORTAL_PROVIDER_IDENTITY_SECRET="$(tr -d '\r\n' <"${state_dir}/provider-b.secret")" \
    IMMORTAL_PROVIDER_RELAY_URL="${relay_url}" \
    IMMORTAL_PROVIDER_NO_SPEND_VARIANT=demo_alternate \
    target/debug/immortal-provider --no-spend \
    >"${state_dir}/provider-b.log" 2>&1 &
  provider_b_pid=$!
  printf '%s\n' "${provider_b_pid}" >"${state_dir}/provider-b.pid"
  chmod 600 "${state_dir}/provider-b.pid"
  provider_b_pubkey="$(wait_for_provider provider-b "${provider_b_pid}" "${state_dir}/provider-b.log")"
  provider_b_state="ready"
}

stop_child() {
  local process_id="$1"
  if test -n "${process_id}" && kill -0 "${process_id}" 2>/dev/null; then
    kill -TERM "${process_id}" 2>/dev/null || true
    wait "${process_id}" 2>/dev/null || true
  fi
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  stop_child "${provider_b_pid}"
  stop_child "${provider_a_pid}"
  stop_child "${relay_pid}"
  if test -e "${state_dir}"; then
    remove_owned_state || exit_status=1
  fi
  exit "${exit_status}"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

IMMORTAL_DEV_RELAY_PORT="${relay_port}" scripts/dev-relay.sh \
  >"${state_dir}/relay.log" 2>&1 &
relay_pid=$!
printf '%s\n' "${relay_pid}" >"${state_dir}/relay.pid"
chmod 600 "${state_dir}/relay.pid"
write_manifest
wait_for_relay
relay_state="ready"
write_manifest
start_provider_a
write_manifest
start_provider_b
write_manifest

echo "dev-no-spend-demo: ready ${relay_url}"
echo "dev-no-spend-demo: public manifest ${manifest_path}"
sed -n '1,260p' "${manifest_path}"
echo "dev-no-spend-demo: Ctrl-C removes only this topology"

while true; do
  if ! kill -0 "${relay_pid}" 2>/dev/null; then
    wait "${relay_pid}" || true
    echo "dev-no-spend-demo: relay stopped; tearing down topology" >&2
    exit 1
  fi
  if test -f "${state_dir}/control/restart-provider-a"; then
    rm -f -- "${state_dir}/control/restart-provider-a"
    stop_child "${provider_a_pid}"
  fi
  if test -f "${state_dir}/control/restart-provider-b"; then
    rm -f -- "${state_dir}/control/restart-provider-b"
    stop_child "${provider_b_pid}"
  fi
  if ! kill -0 "${provider_a_pid}" 2>/dev/null; then
    wait "${provider_a_pid}" 2>/dev/null || true
    provider_a_state="restarting"
    provider_a_restarts=$((provider_a_restarts + 1))
    write_manifest
    start_provider_a
    write_manifest
  fi
  if ! kill -0 "${provider_b_pid}" 2>/dev/null; then
    wait "${provider_b_pid}" 2>/dev/null || true
    provider_b_state="restarting"
    provider_b_restarts=$((provider_b_restarts + 1))
    write_manifest
    start_provider_b
    write_manifest
  fi
  sleep 0.2
done
