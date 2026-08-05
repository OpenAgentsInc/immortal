#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/topology-quotes-v1.json"
relay_a_port="${IMMORTAL_LAB_RELAY_A_PORT:-18080}"
relay_b_port="${IMMORTAL_LAB_RELAY_B_PORT:-18081}"
relay_a_url="ws://127.0.0.1:${relay_a_port}"
relay_b_url="ws://127.0.0.1:${relay_b_port}"
record_path="${IMMORTAL_LAB_TOPOLOGY_QUOTE_RECORD:-target/lab-evidence/topology-quotes-v1.json}"
private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-lab-topology-quotes.XXXXXX")"
chmod 700 "${private_root}"
touch "${private_root}/owned"
chmod 600 "${private_root}/owned"
lab_dir="${private_root}/rails"
wallet_state="${private_root}/wallet"
relay_a_pid=""
relay_b_pid=""
provider_a_pid=""
provider_b_pid=""
rails_up=false
current_phase=build

stop_process() {
  local process_id="$1"
  if test -n "${process_id}" && kill -0 "${process_id}" 2>/dev/null; then
    kill -TERM "${process_id}" 2>/dev/null || true
    wait "${process_id}" 2>/dev/null || true
  fi
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  stop_process "${provider_b_pid}"
  stop_process "${provider_a_pid}"
  stop_process "${relay_b_pid}"
  stop_process "${relay_a_pid}"
  if test "${rails_up}" = true; then
    IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh down >/dev/null 2>&1 || true
    IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-bitcoind.sh down >/dev/null 2>&1 || true
  fi
  if test "${exit_status}" -ne 0; then
    python3 - "${fixture}" "${record_path}" "${current_phase}" "${exit_status}" "${private_root}" <<'PY'
import json
import os
import pathlib
import re
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
record_path = pathlib.Path(sys.argv[2])
phase = sys.argv[3]
private_root = pathlib.Path(sys.argv[5])
reason = None
if phase == "wallet-comparison":
    error_path = private_root / "wallet-error.log"
    if error_path.is_file() and error_path.stat().st_size <= 8192:
        candidate = error_path.read_text(encoding="utf-8", errors="replace").strip()
        if candidate and re.search(
            r"seed|secret|preimage|macaroon|private[_ -]?key|claim[_ -]?key|refund[_ -]?key|raw[_ -]?(signed|wrap)",
            candidate,
            re.IGNORECASE,
        ) is None:
            reason = candidate[-1024:]
record = {
    "schema": fixture["retained_record"]["failure_schema"],
    "phase": phase,
    "exit_status": int(sys.argv[4]),
    "private_artifacts_retained": False,
    "reason": reason,
}
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
record_path.parent.mkdir(parents=True, exist_ok=True)
os.chmod(record_path.parent, 0o700)
temporary = record_path.with_name(record_path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, record_path)
os.chmod(record_path, 0o600)
PY
  fi
  case "$(basename "${private_root}")" in
  immortal-lab-topology-quotes.*)
    if test -f "${private_root}/owned"; then
      rm -rf -- "${private_root}"
    else
      echo "test-lab-topology-quotes: private root lost its ownership marker" >&2
      exit_status=1
    fi
    ;;
  *)
    echo "test-lab-topology-quotes: refused to remove an unexpected private root" >&2
    exit_status=1
    ;;
  esac
  if test "${exit_status}" -ne 0; then
    echo "test-lab-topology-quotes: failed during ${current_phase}" >&2
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

wait_for_http() {
  local label="$1" url="$2" process_id="$3"
  for _ in $(seq 1 600); do
    if curl --fail --silent --show-error "${url}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${process_id}" 2>/dev/null; then
      wait "${process_id}" || true
      echo "test-lab-topology-quotes: ${label} exited before readiness" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "test-lab-topology-quotes: ${label} did not become ready" >&2
  return 1
}

wait_for_provider() {
  local label="$1" process_id="$2" log_file="$3" relay_url="$4"
  for _ in $(seq 1 600); do
    if grep -Fq "no-spend ready relay=${relay_url} pubkey=" "${log_file}"; then
      return 0
    fi
    if ! kill -0 "${process_id}" 2>/dev/null; then
      wait "${process_id}" || true
      echo "test-lab-topology-quotes: ${label} exited before readiness" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "test-lab-topology-quotes: ${label} did not become ready" >&2
  return 1
}

python3 - "${fixture}" <<'PY'
import json
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if fixture.get("schema") != "openagents.immortal.lab-topology-quotes.v1":
    raise SystemExit("topology Quote fixture has another schema")
if fixture.get("process_gate") != "scripts/test-lab-topology-quotes.sh":
    raise SystemExit("topology Quote fixture points to another process gate")
if fixture.get("topology", {}).get("cln_roles") != ["provider-a", "provider-b", "wallet"]:
    raise SystemExit("topology Quote fixture has another CLN role set")
if fixture.get("quote_comparison", {}).get("ordering") != [
    "output_amount_desc",
    "maximum_total_fee_asc",
    "provider_pubkey_asc",
    "quote_id_asc",
]:
    raise SystemExit("topology Quote fixture has another ordering policy")
PY

cargo build --locked -p immortal-relay --bin immortal \
  -p immortal-provider --bin immortal-provider \
  -p immortal-lab --bin immortal-lab

rails_up=true
current_phase=bitcoind-provisioning
IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-bitcoind.sh up \
  >"${private_root}/bitcoind.log" 2>&1
current_phase=cln-provisioning
IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh up \
  >"${private_root}/cln-up.log" 2>&1
current_phase=cln-funding
IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh fund \
  >"${private_root}/cln-fund.log" 2>&1
current_phase=cln-channel-balancing
IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh channel \
  >"${private_root}/cln-channel.log" 2>&1

for node in 1 2 3; do
  IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh cli "${node}" getinfo \
    >"${private_root}/cln-${node}-info.json"
  IMMORTAL_LAB_DIR="${lab_dir}" scripts/lab-cln.sh cli "${node}" listpeerchannels \
    >"${private_root}/cln-${node}-channels.json"
done

current_phase=identity-provisioning
python3 - "${private_root}/provider-a-secret" "${private_root}/provider-b-secret" <<'PY'
import os
import secrets
import sys

order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
for name in sys.argv[1:]:
    while True:
        value = secrets.randbelow(order)
        if value != 0:
            break
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        output.write(f"{value:064x}\n")
        output.flush()
        os.fsync(output.fileno())
PY

current_phase=relay-startup
IMMORTAL_DEV_RELAY_PORT="${relay_a_port}" scripts/dev-relay.sh \
  >"${private_root}/relay-a.log" 2>&1 &
relay_a_pid=$!
IMMORTAL_DEV_RELAY_PORT="${relay_b_port}" scripts/dev-relay.sh \
  >"${private_root}/relay-b.log" 2>&1 &
relay_b_pid=$!
wait_for_http relay-a "http://127.0.0.1:${relay_a_port}/health" "${relay_a_pid}"
wait_for_http relay-b "http://127.0.0.1:${relay_b_port}/health" "${relay_b_pid}"

current_phase=provider-startup
IMMORTAL_PROVIDER_IDENTITY_SECRET="$(tr -d '\r\n' <"${private_root}/provider-a-secret")" \
  IMMORTAL_PROVIDER_RELAY_URL="${relay_a_url}" \
  target/debug/immortal-provider --no-spend \
  >"${private_root}/provider-a.log" 2>&1 &
provider_a_pid=$!
IMMORTAL_PROVIDER_IDENTITY_SECRET="$(tr -d '\r\n' <"${private_root}/provider-b-secret")" \
  IMMORTAL_PROVIDER_RELAY_URL="${relay_b_url}" \
  target/debug/immortal-provider --no-spend \
  >"${private_root}/provider-b.log" 2>&1 &
provider_b_pid=$!
wait_for_provider provider-a "${provider_a_pid}" "${private_root}/provider-a.log" "${relay_a_url}"
wait_for_provider provider-b "${provider_b_pid}" "${private_root}/provider-b.log" "${relay_b_url}"

current_phase=wallet-comparison
IMMORTAL_LAB_STATE_DIR="${wallet_state}" \
  IMMORTAL_LAB_RELAY_URLS="${relay_a_url},${relay_b_url}" \
  IMMORTAL_LAB_QUOTE_WAIT_SECONDS=60 \
  target/debug/immortal-lab topology-quotes \
  >"${private_root}/selection.json" 2>"${private_root}/wallet-error.log"

current_phase=sanitized-record
python3 - "${fixture}" "${private_root}" "${record_path}" <<'PY'
import json
import os
import pathlib
import platform
import re
import sys

fixture_path = pathlib.Path(sys.argv[1])
private_root = pathlib.Path(sys.argv[2])
record_path = pathlib.Path(sys.argv[3])
fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
selection = json.loads((private_root / "selection.json").read_text(encoding="utf-8"))
if selection.get("schema") != "openagents.immortal.lab-topology-quote-selection.v1":
    raise SystemExit("wallet emitted another topology selection schema")

roles = ["provider-a", "provider-b", "wallet"]
cln = []
node_ids = set()
for index, role in enumerate(roles, 1):
    info = json.loads((private_root / f"cln-{index}-info.json").read_text(encoding="utf-8"))
    channels = json.loads((private_root / f"cln-{index}-channels.json").read_text(encoding="utf-8"))
    node_id = info.get("id")
    if not isinstance(node_id, str) or re.fullmatch(r"[0-9a-f]{66}", node_id) is None:
        raise SystemExit(f"{role} CLN id is invalid")
    if node_id in node_ids or info.get("network") != "regtest":
        raise SystemExit(f"{role} CLN identity or network is invalid")
    node_ids.add(node_id)
    channel_rows = channels.get("channels")
    if not isinstance(channel_rows, list):
        raise SystemExit(f"{role} channel result is invalid")
    normal = sum(1 for channel in channel_rows if channel.get("state") == "CHANNELD_NORMAL")
    if normal != 2:
        raise SystemExit(f"{role} does not have both expected normal channels")
    cln.append({"role": role, "node_id": node_id, "normal_channel_count": normal})

candidates = selection.get("candidates")
if not isinstance(candidates, list) or len(candidates) != 2:
    raise SystemExit("wallet did not compare exactly two Quotes")
if [candidate.get("rank") for candidate in candidates] != [1, 2]:
    raise SystemExit("wallet Quote ranks are invalid")
providers = {candidate.get("provider_pubkey") for candidate in candidates}
relays = {candidate.get("relay_url") for candidate in candidates}
if len(providers) != 2 or len(relays) != 2:
    raise SystemExit("wallet candidates are not from two providers and two relays")
if not all(isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key) for key in providers):
    raise SystemExit("wallet candidate provider key is invalid")
if not all(isinstance(url, str) and re.fullmatch(r"ws://127[.]0[.]0[.]1:[0-9]+", url) for url in relays):
    raise SystemExit("wallet candidate relay is not numeric loopback")
policy = fixture["quote_comparison"]["ordering"]
if selection.get("selection", {}).get("policy") != policy:
    raise SystemExit("wallet selection policy drifted from the fixture")
if selection["selection"].get("selected_quote_id") != candidates[0].get("quote_id"):
    raise SystemExit("wallet selected Quote differs from rank one")

record = {
    "schema": fixture["retained_record"]["schema"],
    "platform": {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "recorded_at": selection.get("observed_at"),
    },
    "cln": cln,
    "wallet": selection.get("wallet"),
    "candidates": candidates,
    "selection": selection.get("selection"),
}
expected_keys = {"schema", *fixture["retained_record"]["allowed_sections"]}
if set(record) != expected_keys:
    raise SystemExit("retained topology record has an unapproved section")

banned = {
    "seed", "secret", "preimage", "macaroon", "claim_key", "refund_key",
    "private_key", "raw_signed_event", "raw_wrap_event", "credential", "password",
}
def reject_private(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in banned:
                raise SystemExit(f"retained topology record contains banned member {key}")
            reject_private(child)
    elif isinstance(value, list):
        for child in value:
            reject_private(child)

reject_private(record)
encoded = (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
maximum_bytes = fixture["bounds"]["maximum_retained_record_bytes"]
if len(encoded) > maximum_bytes:
    raise SystemExit("retained topology record exceeds its fixture bound")

record_path.parent.mkdir(parents=True, exist_ok=True)
os.chmod(record_path.parent, 0o700)
temporary = record_path.with_name(record_path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, record_path)
os.chmod(record_path, 0o600)
PY

echo "test-lab-topology-quotes: three CLN roles, two relays, two providers, and deterministic Quote comparison passed"
echo "test-lab-topology-quotes: sanitized record ${record_path}"
