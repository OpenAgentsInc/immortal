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
if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= len(rows) <= maximum <= 48:
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
  local private_root project_name provider_image_ref current_phase compose_ready infrastructure_proven
  local maximum_seconds case_deadline failure_reason record_path
  local external_injection external_checkpoint external_target cooperative_signing liquid_case zero_conf_case
  local wallet_driver_container_name
  local -a doomsday_stopped_targets=()
  private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-adversarial-case.XXXXXX")"
  project_name="immortal-18-$(printf '%s' "${case_id}" | cut -c1-24)-$(random_hex 5)"
  provider_image_ref="${project_name}-provider:local"
  current_phase=initialization
  compose_ready=false
  infrastructure_proven=false
  failure_reason=case_failed
  record_path="${record_dir}/${case_id}.json"
  external_injection=""
  external_checkpoint=""
  external_target=""
  cooperative_signing=false
  liquid_case=false
  zero_conf_case=false
  case "${case_id}" in
    relay-a-partition)
      external_injection=relay_loss
      external_checkpoint=submarine:funding_execution_ready
      external_target=relay-a
      ;;
    relay-b-partition)
      external_injection=relay_loss
      external_checkpoint=submarine:funding_execution_ready
      external_target=relay-b
      ;;
    provider-a-crash-restart)
      external_injection=provider_crash
      external_checkpoint=submarine:funding_effect_recorded
      external_target=provider-a
      ;;
    provider-b-crash-restart)
      external_injection=provider_crash
      external_checkpoint=submarine:funding_effect_recorded
      external_target=provider-b
      ;;
    wallet-crash-restart)
      external_injection=wallet_crash
      external_checkpoint=submarine:funding_effect_recorded
      external_target=wallet-driver
      ;;
    submarine-provider-noncooperative-refund)
      external_injection=provider_noncooperative
      external_checkpoint=submarine_refund:funding_effect_recorded
      external_target=provider-a
      ;;
    funding-reorg)
      external_injection=funding_reorg
      external_checkpoint=submarine:funding_reorg_control
      external_target=provider-a
      ;;
    claim-reorg)
      external_injection=claim_reorg
      external_checkpoint=submarine:claim_reorg_control
      external_target=provider-a
      ;;
    musig2-crash-cut-recovery)
      external_injection=cooperative_crash_cut
      external_checkpoint=cooperative_crash_cut:provider_public_nonce_persisted
      external_target=provider-a
      ;;
    route-chain-btc-to-lbtc-provider-a|route-chain-lbtc-to-btc-provider-a)
      external_injection=provider_crash
      external_checkpoint=chain:provider_funding_effect_recorded
      external_target=provider-a
      liquid_case=true
      ;;
    route-chain-btc-to-lbtc-provider-b|route-chain-lbtc-to-btc-provider-b)
      external_injection=provider_crash
      external_checkpoint=chain:provider_funding_effect_recorded
      external_target=provider-b
      liquid_case=true
      ;;
    route-liquid-submarine-provider-a)
      external_injection=provider_crash
      external_checkpoint=liquid_submarine:provider_claim_effect_recorded
      external_target=provider-a
      liquid_case=true
      ;;
    route-liquid-submarine-provider-b)
      external_injection=provider_crash
      external_checkpoint=liquid_submarine:provider_claim_effect_recorded
      external_target=provider-b
      liquid_case=true
      ;;
    route-liquid-reverse-provider-a)
      external_injection=provider_crash
      external_checkpoint=liquid_reverse:provider_funding_effect_recorded
      external_target=provider-a
      liquid_case=true
      ;;
    route-liquid-reverse-provider-b)
      external_injection=provider_crash
      external_checkpoint=liquid_reverse:provider_funding_effect_recorded
      external_target=provider-b
      liquid_case=true
      ;;
    doomsday-liquid-submarine-provider-gone|doomsday-liquid-reverse-coordinator-gone)
      liquid_case=true
      ;;
    zero-conf-rbf-replacement|zero-conf-double-spend-race|zero-conf-ancestor-eviction)
      zero_conf_case=true
      ;;
  esac
  case "${case_id}" in
    musig2-submarine-provider-a|musig2-submarine-provider-b|musig2-abort-script-path|musig2-crash-cut-recovery)
      cooperative_signing=true
      ;;
  esac
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
  if test "${liquid_case}" = true; then
    compose_prefix+=(--profile liquid)
  fi

  compose() {
    IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" \
      IMMORTAL_ADVERSARIAL_PROVIDER_IMAGE="${provider_image_ref}" \
      "${compose_prefix[@]}" "$@"
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

  print_bounded_diagnostic() {
    local label="$1" path="$2"
    python3 - "${label}" "${path}" <<'PY' >&2
import pathlib
import re
import sys

label = sys.argv[1]
path = pathlib.Path(sys.argv[2])
encoded = path.read_bytes()[-4096:] if path.exists() else b""
text = encoded.decode("utf-8", errors="replace")
if re.search(r"(?i)(claim.key|macaroon|password|preimage|private.key|refund.key|seed|secret)", text):
    print(f"test-lab-adversarial: {label} diagnostic contained a custody term and was redacted")
else:
    text = re.sub(r"\b[0-9a-f]{64}\b", "<hex64>", text)
    lines = text.splitlines()[-12:]
    if lines:
        print(f"test-lab-adversarial: bounded {label} diagnostic:")
        print("\n".join(lines))
PY
  }

  write_doomsday_control_audit() {
    local inspect_path="${1:-}"
    python3 - "${private_root}/evidence/doomsday-control.json" "${case_id}" \
      "${inspect_path}" <<'PY'
import json
import os
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
case_id = sys.argv[2]
inspect_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
if case_id in {
    "doomsday-reverse-coordinator-gone",
    "doomsday-liquid-reverse-coordinator-gone",
}:
    stopped_targets = ["provider-b", "relay-a", "relay-b"]
    direct_recovery_retained = True
elif case_id in {
    "doomsday-submarine-provider-gone",
    "doomsday-liquid-submarine-provider-gone",
    "doomsday-keyless-esplora-broadcast",
}:
    stopped_targets = ["provider-a", "provider-b", "relay-a", "relay-b"]
    direct_recovery_retained = False
else:
    raise SystemExit("controller audit received another case")

keyless = None
if case_id == "doomsday-keyless-esplora-broadcast":
    if inspect_path is None or inspect_path.stat().st_size > 65536:
        raise SystemExit("keyless runtime inspection is absent or oversized")
    inspected = json.loads(inspect_path.read_text(encoding="utf-8"))
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise SystemExit("keyless runtime inspection has another shape")
    container = inspected[0]
    environment = container.get("Config", {}).get("Env", [])
    mounts = container.get("Mounts", [])
    if not isinstance(environment, list) or not isinstance(mounts, list):
        raise SystemExit("keyless runtime environment or mounts are invalid")
    environment_names = sorted(value.split("=", 1)[0] for value in environment)
    application_names = [name for name in environment_names if name.startswith("IMMORTAL_")]
    credential_terms = re.compile(
        r"(?i)(password|macaroon|preimage|private.?key|refund.?key|claim.?key|seed|rpc.?user|identity.?secret|wallet)"
    )
    forbidden_environment_names = [
        name for name in environment_names if credential_terms.search(name)
    ]
    mount_targets = sorted(
        mount.get("Destination") for mount in mounts
        if isinstance(mount, dict) and isinstance(mount.get("Destination"), str)
    )
    forbidden_mount_targets = [
        target for target in mount_targets if credential_terms.search(target)
    ]
    expected_environment_names = sorted([
        "IMMORTAL_LAB_KEYLESS_REQUEST_FILE",
        "IMMORTAL_LAB_KEYLESS_RESULT_FILE",
        "PATH",
    ])
    if (
        environment_names != expected_environment_names
        or mount_targets != ["/keyless"]
        or forbidden_environment_names
        or forbidden_mount_targets
    ):
        raise SystemExit("keyless runtime environment or mounts exceed their allowlist")
    keyless = {
        "separate_container": True,
        "application_environment_names": application_names,
        "mount_targets": mount_targets,
        "observed_environment_count": len(environment_names),
        "observed_mount_count": len(mount_targets),
        "environment_allowlist_exact": True,
        "mount_allowlist_exact": True,
        "rail_access": False,
        "runtime_environment_scan_passed": True,
        "exact_presigned_request_only": True,
    }

record = {
    "schema": "openagents.immortal.doomsday-controller-audit.v1",
    "case_id": case_id,
    "stopped_targets": stopped_targets,
    "stopped_targets_absent_before_recovery": True,
    "stopped_targets_absent_after_recovery": False,
    "relay_services_absent": True,
    "provider_http_websocket_api_absent": True,
    "direct_recovery_retained": direct_recovery_retained,
    "direct_recovery_only_session_surface": direct_recovery_retained,
    "keyless_process": keyless,
}
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
if len(encoded) > 8192:
    raise SystemExit("doomsday controller audit exceeds its bound")
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
PY
  }

  mark_doomsday_services_absent_after_recovery() {
    python3 - "${private_root}/evidence/doomsday-control.json" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 8192:
    raise SystemExit("doomsday controller audit exceeds its bound")
record = json.loads(path.read_text(encoding="utf-8"))
if record.get("stopped_targets_absent_before_recovery") is not True:
    raise SystemExit("doomsday controller audit lacks its pre-recovery check")
record["stopped_targets_absent_after_recovery"] = True
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY
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

  elements_cli() {
    local node="$1" service configuration
    shift
    case "${node}" in
      a)
        service=elements-provider-a
        configuration=/run/immortal-private/elements-provider-a.conf
        ;;
      b)
        service=elements-provider-b
        configuration=/run/immortal-private/elements-provider-b.conf
        ;;
      wallet)
        service=elements-wallet
        configuration=/run/immortal-private/elements-wallet.conf
        ;;
      *)
        echo "test-lab-adversarial: unsupported Elements node ${node}" >&2
        return 2
        ;;
    esac
    compose exec -T "${service}" elements-cli -chain=elementsregtest \
      "-conf=${configuration}" -datadir=/var/lib/elements "$@"
  }

  elements_peered() {
    test "$(elements_cli a getconnectioncount)" -ge 2 \
      && test "$(elements_cli b getconnectioncount)" -ge 1 \
      && test "$(elements_cli wallet getconnectioncount)" -ge 1
  }

  elements_synced() {
    local height_a height_b height_wallet hash_a hash_b hash_wallet
    height_a="$(elements_cli a getblockcount)"
    height_b="$(elements_cli b getblockcount)"
    height_wallet="$(elements_cli wallet getblockcount)"
    hash_a="$(elements_cli a getbestblockhash)"
    hash_b="$(elements_cli b getbestblockhash)"
    hash_wallet="$(elements_cli wallet getbestblockhash)"
    test "${height_a}" = "${height_b}" \
      && test "${height_a}" = "${height_wallet}" \
      && test "${hash_a}" = "${hash_b}" \
      && test "${hash_a}" = "${hash_wallet}"
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

  bitcoin_mempool_contains() {
    local node="$1" transaction_id="$2"
    bitcoin_cli "${node}" getmempoolentry "${transaction_id}"
  }

  cln_wallet_ready() {
    local service="$1" expected_height="$2" actual_height
    actual_height="$(cln_cli "${service}" getinfo | jq -er .blockheight)"
    test "${actual_height}" -ge "${expected_height}" \
      && cln_cli "${service}" listfunds | jq -e 'any(.outputs[]; .status == "confirmed")'
  }

  cln_chain_ready() {
    local service="$1" expected_height="$2" actual_height
    actual_height="$(cln_cli "${service}" getinfo | jq -er .blockheight)"
    test "${actual_height}" -ge "${expected_height}"
  }

  cln_channels_ready() {
    local service="$1"
    cln_cli "${service}" listpeerchannels \
      | jq -e '[.channels[] | select(.state == "CHANNELD_NORMAL")] | length == 2'
  }

  cln_channel_count_ready() {
    local service="$1" expected_count="$2"
    cln_cli "${service}" listpeerchannels \
      | jq -e --argjson expected_count "${expected_count}" \
        '[.channels[] | select(.state == "CHANNELD_NORMAL")] | length == $expected_count'
  }

  provider_ready() {
    local provider="$1" port="$2"
    compose exec -T "provider-${provider}" /usr/bin/curl --fail --silent \
      "http://127.0.0.1:${port}/healthz"
  }

  provider_status_exists() {
    local state="$1" count
    count="$(compose exec -T provider-a-postgres psql -X -A -t \
      -U immortal_provider -d immortal_provider -v state="${state}" <<'SQL'
SELECT EXISTS (
    SELECT 1
    FROM provider_session_record
    WHERE kind = 39607
      AND (signed_event ->> 'content')::jsonb #>> '{mkt_swp,swp_state}' = :'state'
)::integer;
SQL
)"
    test "$(printf '%s' "${count}" | tr -d '\r\n ')" = 1
  }

  provider_claim_watch_matches() {
    local expected_state="$1" minimum_confirmations="$2" expected_event="$3" row
    row="$(compose exec -T provider-a-postgres psql -X -A -t -F $'\t' \
      -U immortal_provider -d immortal_provider <<'SQL'
SELECT state, confirmations, COALESCE(last_chain_event, '')
FROM provider_watch_job
WHERE job_kind = 'claim_broadcast'
ORDER BY updated_at DESC, job_id
LIMIT 1;
SQL
)"
    python3 - "${expected_state}" "${minimum_confirmations}" "${expected_event}" \
      "${row}" <<'PY'
import sys

fields = sys.argv[4].strip().split("\t")
if len(fields) != 3:
    raise SystemExit(1)
state, confirmations, event = fields
if state != sys.argv[1] or not confirmations.isdigit():
    raise SystemExit(1)
if int(confirmations) < int(sys.argv[2]) or event != sys.argv[3]:
    raise SystemExit(1)
PY
  }

  disconnect_bitcoin_peers() {
    local peer_id
    while IFS= read -r peer_id; do
      test -n "${peer_id}" || continue
      bitcoin_cli a -named disconnectnode nodeid="${peer_id}" >/dev/null
    done < <(bitcoin_cli a getpeerinfo | jq -er '.[].id')
    wait_for "Bitcoin peer disconnection" bitcoin_disconnected a
    wait_for "reciprocal Bitcoin peer disconnection" bitcoin_disconnected b
  }

  bitcoin_disconnected() {
    test "$(bitcoin_cli "$1" getconnectioncount)" = 0
  }

  reconnect_bitcoin_peers() {
    bitcoin_cli a addnode bitcoin-b:18444 onetry >/dev/null
    wait_for "Bitcoin competing-branch convergence" chains_synced
  }

  generate_controlled_block() {
    local node="$1" transaction_id="${2:-}" result
    if test -n "${transaction_id}"; then
      result="$(bitcoin_cli "${node}" generateblock "${miner_address}" \
        "[\"${transaction_id}\"]")"
    else
      result="$(bitcoin_cli "${node}" generateblock "${miner_address}" '[]')"
    fi
    jq -er 'if type == "string" then . else .hash end' <<<"${result}"
  }

  checkpoint_transaction_id() {
    local request_file="$1" checkpoint_file="${private_root}/state/funded-checkpoint.json"
    python3 - "${request_file}" "${checkpoint_file}" "${external_injection}" \
      "${external_checkpoint}" <<'PY'
import json
import pathlib
import re
import sys

request = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
checkpoint = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
transaction_id = checkpoint.get("details", {}).get("external_identifier")
if (
    request.get("run_id") != checkpoint.get("run_id")
    or request.get("injection") != sys.argv[3]
    or request.get("checkpoint") != sys.argv[4]
    or checkpoint.get("label") != sys.argv[4].split(":", 1)[1]
    or not isinstance(transaction_id, str)
    or re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None
):
    raise SystemExit("chain checkpoint does not bind one transaction")
print(transaction_id)
PY
  }

  container_pid() {
    local service="$1" container
    container="$(compose ps --quiet "${service}")"
    test -n "${container}"
    docker inspect --format '{{.State.Pid}}' "${container}"
  }

  wallet_driver_container() {
    if test -z "${wallet_driver_container_name}" \
      || ! docker inspect --type container "${wallet_driver_container_name}" >/dev/null 2>&1; then
      return 1
    fi
    printf '%s\n' "${wallet_driver_container_name}"
  }

  provider_state_boundary_digest() {
    local service="$1" container
    container="$(compose ps --quiet "${service}")"
    test -n "${container}"
    docker inspect "${container}" | python3 -c '
import hashlib, json, sys
container = json.load(sys.stdin)[0]
database = next(
    value for value in container["Config"]["Env"]
    if value.startswith("IMMORTAL_PROVIDER_DATABASE_URL=")
)
wallet = next(
    mount["Source"] for mount in container["Mounts"]
    if mount["Destination"].endswith("wallet-seed")
)
print(hashlib.sha256((database + "\0" + wallet).encode()).hexdigest())
'
  }

  wait_for_injection_request() {
    local request_file="$1" expected_driver_process="$2"
    for _ in $(seq 1 600); do
      check_deadline
      if test -f "${request_file}"; then
        return 0
      fi
      if ! jobs -pr | grep -Fx "${expected_driver_process}" >/dev/null; then
        current_phase=wallet-driver-before-injection
        failure_reason=wallet_driver_failed_before_injection
        print_bounded_diagnostic "wallet driver before injection" \
          "${private_root}/driver-error.log"
        return 1
      fi
      sleep 0.2
    done
    echo "test-lab-adversarial: ${case_id}: injection request did not arrive" >&2
    print_bounded_diagnostic "wallet driver before injection" \
      "${private_root}/driver-error.log"
    return 1
  }

  controlled_block_contains() {
    local node="$1" block_hash="$2" transaction_id="$3"
    bitcoin_cli "${node}" getblock "${block_hash}" 1 \
      | jq -e --arg transaction_id "${transaction_id}" \
        '.tx | index($transaction_id) != null' >/dev/null
  }

  block_is_invalidated() {
    local node="$1" block_hash="$2"
    bitcoin_cli "${node}" getblockheader "${block_hash}" \
      | jq -e '.confirmations == -1' >/dev/null
  }

  write_chain_injection_acknowledgement() {
    local request_file="$1" acknowledgement_file="$2" request_run_id="$3"
    local request_sha256="$4" transaction_id="$5" orphaned_block_hash="$6"
    local competing_tip_hash="$7" reconfirmed_block_hash="$8" transition="$9"
    local wait_state="${10}" recovery_state="${11}"
    python3 - "${request_file}" "${acknowledgement_file}" "${request_run_id}" \
      "${request_sha256}" "${external_injection}" "${external_checkpoint}" \
      "${external_target}" "${transaction_id}" "${orphaned_block_hash}" \
      "${competing_tip_hash}" "${reconfirmed_block_hash}" "${transition}" \
      "${wait_state}" "${recovery_state}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

request_path = pathlib.Path(sys.argv[1])
acknowledgement_path = pathlib.Path(sys.argv[2])
encoded = request_path.read_bytes()
if hashlib.sha256(encoded).hexdigest() != sys.argv[4]:
    raise SystemExit("injection request changed during chain recovery")
request = json.loads(encoded)
if (
    request.get("schema") != "openagents.immortal.lab-injection.v1"
    or request.get("run_id") != sys.argv[3]
    or request.get("injection") != sys.argv[5]
    or request.get("checkpoint") != sys.argv[6]
):
    raise SystemExit("injection request no longer binds the chain recovery")
acknowledgement = {
    "schema": "openagents.immortal.lab-injection-ack.v1",
    "run_id": sys.argv[3],
    "checkpoint": sys.argv[6],
    "injection": sys.argv[5],
    "restored": True,
    "evidence": {
        "target": sys.argv[7],
        "transaction_id": sys.argv[8],
        "orphaned_block_hash": sys.argv[9],
        "competing_tip_hash": sys.argv[10],
        "reconfirmed_block_hash": sys.argv[11],
        "transition": sys.argv[12],
        "wait_state": sys.argv[13],
        "recovery_state": sys.argv[14],
    },
}
output = json.dumps(acknowledgement, separators=(",", ":")).encode()
if len(output) > 4096:
    raise SystemExit("chain recovery acknowledgement exceeds its bound")
temporary = acknowledgement_path.with_name(acknowledgement_path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, acknowledgement_path)
    os.chmod(acknowledgement_path, 0o600)
except BaseException:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    raise
PY
  }

  perform_funding_reorg() {
    local request_file="$1" acknowledgement_file="$2" request_run_id="$3" request_sha256="$4"
    local transaction_id before_pid after_pid orphaned_block_hash competing_tip_hash
    local reconfirmed_block_hash
    transaction_id="$(checkpoint_transaction_id "${request_file}")"
    before_pid="$(container_pid provider-a)"
    compose stop provider-a >/dev/null 2>&1
    disconnect_bitcoin_peers
    orphaned_block_hash="$(generate_controlled_block a "${transaction_id}")"
    controlled_block_contains a "${orphaned_block_hash}" "${transaction_id}"
    generate_controlled_block b >/dev/null
    competing_tip_hash="$(generate_controlled_block b)"
    bitcoin_cli a invalidateblock "${orphaned_block_hash}" >/dev/null
    block_is_invalidated a "${orphaned_block_hash}"
    reconnect_bitcoin_peers
    test "$(bitcoin_cli a getbestblockhash)" = "${competing_tip_hash}"
    compose up --detach provider-a >/dev/null 2>&1
    wait_for "provider A after funding reorg" provider_ready a 9091
    after_pid="$(container_pid provider-a)"
    test "${before_pid}" != "${after_pid}"
    wait_for "provider funding wait state" provider_status_exists funding_observed
    if provider_status_exists funding_final; then
      echo "test-lab-adversarial: funding reorg advanced before reconfirmation" >&2
      return 1
    fi
    reconfirmed_block_hash="$(generate_controlled_block a "${transaction_id}")"
    controlled_block_contains a "${reconfirmed_block_hash}" "${transaction_id}"
    wait_for "funding reconfirmation synchronization" chains_synced
    wait_for "provider funding resume state" provider_status_exists funding_final
    write_chain_injection_acknowledgement \
      "${request_file}" "${acknowledgement_file}" "${request_run_id}" \
      "${request_sha256}" "${transaction_id}" "${orphaned_block_hash}" \
      "${competing_tip_hash}" "${reconfirmed_block_hash}" \
      funding_reorg_waited_and_resumed funding_observed_without_finality \
      funding_final_after_reconfirmation
  }

  perform_claim_reorg() {
    local request_file="$1" acknowledgement_file="$2" request_run_id="$3" request_sha256="$4"
    local transaction_id orphaned_block_hash competing_tip_hash reconfirmed_block_hash
    transaction_id="$(checkpoint_transaction_id "${request_file}")"
    disconnect_bitcoin_peers
    orphaned_block_hash="$(generate_controlled_block a "${transaction_id}")"
    controlled_block_contains a "${orphaned_block_hash}" "${transaction_id}"
    wait_for "provider claim watch confirmation" \
      provider_claim_watch_matches confirmed 1 confirmation
    generate_controlled_block b >/dev/null
    competing_tip_hash="$(generate_controlled_block b)"
    bitcoin_cli a invalidateblock "${orphaned_block_hash}" >/dev/null
    block_is_invalidated a "${orphaned_block_hash}"
    reconnect_bitcoin_peers
    test "$(bitcoin_cli a getbestblockhash)" = "${competing_tip_hash}"
    wait_for "provider claim watch reorg" \
      provider_claim_watch_matches broadcast 0 reorg
    reconfirmed_block_hash="$(generate_controlled_block a "${transaction_id}")"
    controlled_block_contains a "${reconfirmed_block_hash}" "${transaction_id}"
    bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 2 "${miner_address}" >/dev/null
    wait_for "claim reconfirmation synchronization" chains_synced
    wait_for "provider claim watch reconfirmation" \
      provider_claim_watch_matches confirmed 3 confirmation
    write_chain_injection_acknowledgement \
      "${request_file}" "${acknowledgement_file}" "${request_run_id}" \
      "${request_sha256}" "${transaction_id}" "${orphaned_block_hash}" \
      "${competing_tip_hash}" "${reconfirmed_block_hash}" \
      claim_watch_reorged_and_reconfirmed claim_watch_confirmed \
      claim_watch_reorg_then_reconfirmed
  }

  acknowledge_external_injection() {
    local request_file acknowledgement_file request_metadata request_run_id request_sha256
    local before_pid after_pid target_suffix target_port target_provider target_container
    local restored transition
    local before_state_boundary after_state_boundary state_boundary_unchanged
    request_file="${private_root}/state/funded-injection.json"
    acknowledgement_file="${private_root}/state/funded-continue"
    if ! wait_for_injection_request "${request_file}" "${driver_process}"; then
      return 1
    fi
    request_metadata="$(python3 - "${request_file}" "${external_injection}" \
      "${external_checkpoint}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
encoded = path.read_bytes()
if not encoded or len(encoded) > 4096 or stat.S_IMODE(path.stat().st_mode) != 0o600:
    raise SystemExit("injection request is empty, unbounded, or not mode 0600")
request = json.loads(encoded)
if set(request) != {"schema", "run_id", "journey", "checkpoint", "injection", "requested_at"}:
    raise SystemExit("injection request has another shape")
if (
    request["schema"] != "openagents.immortal.lab-injection.v1"
    or request["checkpoint"] != sys.argv[3]
    or request["injection"] != sys.argv[2]
    or request["journey"] != sys.argv[3].split(":", 1)[0]
    or not isinstance(request["requested_at"], int)
):
    raise SystemExit("injection request does not bind the selected case")
run_id = request["run_id"]
if (
    not isinstance(run_id, str)
    or not 1 <= len(run_id) <= 128
    or any(not (character.isascii() and (character.isalnum() or character in "-_") ) for character in run_id)
):
    raise SystemExit("injection request has an invalid run id")
print(run_id, hashlib.sha256(encoded).hexdigest(), sep="\t")
PY
    )"
    IFS=$'\t' read -r request_run_id request_sha256 <<<"${request_metadata}"

    case "${external_injection}" in
      funding_reorg)
        current_phase=funding-reorg-control
        perform_funding_reorg "${request_file}" "${acknowledgement_file}" \
          "${request_run_id}" "${request_sha256}"
        current_phase=injection-acknowledgement
        return
        ;;
      claim_reorg)
        current_phase=claim-reorg-control
        perform_claim_reorg "${request_file}" "${acknowledgement_file}" \
          "${request_run_id}" "${request_sha256}"
        current_phase=injection-acknowledgement
        return
        ;;
    esac

    restored=true
    transition=process_replaced_and_ready
    state_boundary_unchanged=false
    after_pid=""
    case "${external_injection}" in
      relay_loss)
        before_pid="$(container_pid "${external_target}")"
        [[ "${before_pid}" =~ ^[1-9][0-9]*$ ]]
        current_phase="${external_target}-partition"
        compose stop "${external_target}" >/dev/null
        if compose ps --services --status running | grep -Fx "${external_target}" >/dev/null; then
          echo "test-lab-adversarial: ${case_id}: relay remained running during partition" >&2
          return 1
        fi
        compose up --detach "${external_target}" >/dev/null
        target_suffix="${external_target#relay-}"
        target_port=18080
        target_provider=provider-a
        if test "${target_suffix}" = b; then
          target_port=18081
          target_provider=provider-b
        fi
        wait_for "restored ${external_target}" compose run --rm --no-deps \
          --entrypoint /usr/bin/curl "${target_provider}" --fail --silent \
          "http://127.0.0.1:${target_port}/health"
        after_pid="$(container_pid "${external_target}")"
        ;;
      provider_crash)
        before_pid="$(container_pid "${external_target}")"
        [[ "${before_pid}" =~ ^[1-9][0-9]*$ ]]
        current_phase="${external_target}-crash-restart"
        compose kill "${external_target}" >/dev/null
        if compose ps --services --status running | grep -Fx "${external_target}" >/dev/null; then
          echo "test-lab-adversarial: ${case_id}: provider remained running after crash" >&2
          return 1
        fi
        compose up --detach "${external_target}" >/dev/null
        target_suffix="${external_target#provider-}"
        target_port=9091
        if test "${target_suffix}" = b; then
          target_port=9092
        fi
        wait_for "restored ${external_target}" provider_ready "${target_suffix}" "${target_port}"
        after_pid="$(container_pid "${external_target}")"
        ;;
      wallet_crash)
        current_phase=wallet-driver-crash
        target_container="$(wallet_driver_container)"
        before_pid="$(docker inspect --format '{{.State.Pid}}' "${target_container}")"
        [[ "${before_pid}" =~ ^[1-9][0-9]*$ ]]
        docker kill "${target_container}" >/dev/null
        if wait "${driver_process}" >/dev/null 2>&1; then
          echo "test-lab-adversarial: ${case_id}: killed wallet driver returned success" >&2
          return 1
        fi
        if docker ps --quiet --filter "name=^/${target_container}$" | grep -q .; then
          echo "test-lab-adversarial: ${case_id}: wallet driver survived process kill" >&2
          return 1
        fi
        current_phase=wallet-driver-restart
        wallet_driver_container_name="${project_name}-wallet-driver-replacement"
        compose run --name "${wallet_driver_container_name}" --rm --no-deps wallet-driver \
          >"${private_root}/evidence/driver.json" 2>"${private_root}/driver-error.log" &
        driver_process=$!
        wait_for "replacement wallet driver container" wallet_driver_container
        target_container="$(wallet_driver_container)"
        after_pid="$(docker inspect --format '{{.State.Pid}}' "${target_container}")"
        ;;
      cooperative_crash_cut)
        current_phase="${external_target}-cooperative-crash-cut"
        before_pid="$(container_pid "${external_target}")"
        [[ "${before_pid}" =~ ^[1-9][0-9]*$ ]]
        before_state_boundary="$(provider_state_boundary_digest "${external_target}")"
        compose kill "${external_target}" >/dev/null
        if compose ps --services --status running | grep -Fx "${external_target}" >/dev/null; then
          echo "test-lab-adversarial: ${case_id}: provider remained running after SIGKILL" >&2
          return 1
        fi
        compose up --detach "${external_target}" >/dev/null
        target_suffix="${external_target#provider-}"
        target_port=9091
        if test "${target_suffix}" = b; then
          target_port=9092
        fi
        wait_for "restored ${external_target}" provider_ready "${target_suffix}" "${target_port}"
        after_state_boundary="$(provider_state_boundary_digest "${external_target}")"
        test "${before_state_boundary}" = "${after_state_boundary}"
        transition=process_replaced_same_database_and_wallet_file
        state_boundary_unchanged=true
        ;;
      provider_noncooperative)
        before_pid="$(container_pid "${external_target}")"
        [[ "${before_pid}" =~ ^[1-9][0-9]*$ ]]
        current_phase="${external_target}-noncooperative-stop"
        compose stop "${external_target}" >/dev/null
        if compose ps --services --status running | grep -Fx "${external_target}" >/dev/null; then
          echo "test-lab-adversarial: ${case_id}: provider remained running after noncooperative stop" >&2
          return 1
        fi
        restored=false
        transition=process_stopped
        ;;
      *)
        echo "test-lab-adversarial: ${case_id}: unsupported external injection" >&2
        return 1
        ;;
    esac
    if test "${restored}" = true; then
      if test -z "${after_pid}"; then
        after_pid="$(container_pid "${external_target}")"
      fi
      [[ "${after_pid}" =~ ^[1-9][0-9]*$ ]]
      test "${before_pid}" != "${after_pid}"
    fi

    current_phase=injection-acknowledgement
    python3 - "${request_file}" "${acknowledgement_file}" "${request_run_id}" \
      "${request_sha256}" "${external_injection}" "${external_checkpoint}" \
      "${external_target}" "${before_pid}" "${after_pid}" "${restored}" \
      "${transition}" "${state_boundary_unchanged}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

request_path = pathlib.Path(sys.argv[1])
acknowledgement_path = pathlib.Path(sys.argv[2])
encoded = request_path.read_bytes()
if hashlib.sha256(encoded).hexdigest() != sys.argv[4]:
    raise SystemExit("injection request changed during process recovery")
request = json.loads(encoded)
if (
    request["schema"] != "openagents.immortal.lab-injection.v1"
    or request["run_id"] != sys.argv[3]
    or request["injection"] != sys.argv[5]
    or request["checkpoint"] != sys.argv[6]
):
    raise SystemExit("injection request no longer binds the selected case")
acknowledgement = {
    "schema": "openagents.immortal.lab-injection-ack.v1",
    "run_id": sys.argv[3],
    "checkpoint": sys.argv[6],
    "injection": sys.argv[5],
    "restored": sys.argv[10] == "true",
    "evidence": {
        "target": sys.argv[7],
        "before_pid": int(sys.argv[8]),
        "transition": sys.argv[11],
    },
}
if sys.argv[9]:
    acknowledgement["evidence"]["after_pid"] = int(sys.argv[9])
if sys.argv[12] == "true":
    acknowledgement["evidence"]["state_boundary_unchanged"] = True
output = json.dumps(acknowledgement, separators=(",", ":")).encode()
temporary = acknowledgement_path.with_name(acknowledgement_path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, acknowledgement_path)
    os.chmod(acknowledgement_path, 0o600)
except BaseException:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
    raise
PY
  }

  wait_for_driver_process() {
    local driver_process="$1"
    while jobs -pr | grep -Fx "${driver_process}" >/dev/null; do
      if ! check_deadline; then
        kill -TERM "${driver_process}" >/dev/null 2>&1 || true
        wait "${driver_process}" >/dev/null 2>&1 || true
        return 124
      fi
      sleep 0.2
    done
    wait "${driver_process}"
  }

  umask 077
  touch "${private_root}/owned"
  mkdir -m 0700 "${private_root}/evidence" "${private_root}/state"

  current_phase=credential-generation
  local bitcoin_a_user bitcoin_b_user bitcoin_a_password bitcoin_b_password
  local elements_a_user elements_b_user elements_wallet_user
  local elements_a_password elements_b_password elements_wallet_password
  local relay_a_password relay_b_password provider_a_password provider_b_password
  local provider_a_identity provider_b_identity provider_a_seed provider_b_seed client_seed
  bitcoin_a_user="immortal-a-$(random_hex 8)"
  bitcoin_b_user="immortal-b-$(random_hex 8)"
  bitcoin_a_password="$(random_hex 32)"
  bitcoin_b_password="$(random_hex 32)"
  elements_a_user="immortal-elements-a-$(random_hex 8)"
  elements_b_user="immortal-elements-b-$(random_hex 8)"
  elements_wallet_user="immortal-elements-wallet-$(random_hex 8)"
  elements_a_password="$(random_hex 32)"
  elements_b_password="$(random_hex 32)"
  elements_wallet_password="$(random_hex 32)"
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
  if test "${liquid_case}" = true; then
    printf '%s\n' "${elements_a_password}" >"${private_root}/elements-provider-a-rpc-password"
    printf '%s\n' "${elements_b_password}" >"${private_root}/elements-provider-b-rpc-password"
    printf '%s\n' "${elements_wallet_password}" >"${private_root}/elements-wallet-rpc-password"
  fi

  current_phase=configuration-generation
  cat >"${private_root}/bitcoin-a.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
[regtest]
bind=0.0.0.0:18444
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_a_user}
rpcpassword=${bitcoin_a_password}
EOF
  if test "${zero_conf_case}" = true; then
    printf '%s\n' 'mempoolfullrbf=1' >>"${private_root}/bitcoin-a.conf"
  fi
  cat >"${private_root}/bitcoin-b.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
[regtest]
bind=0.0.0.0:18444
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=${bitcoin_b_user}
rpcpassword=${bitcoin_b_password}
EOF

  write_elements_config() {
    local path="$1" rpc_user="$2" rpc_password="$3"
    cat >"${path}" <<EOF
chain=elementsregtest
server=1
listen=1
txindex=1
validatepegin=0
persistmempool=0
walletbroadcast=0
initialfreecoins=2100000000000000
fallbackfee=0.0002
rpcuser=${rpc_user}
rpcpassword=${rpc_password}
[elementsregtest]
bind=0.0.0.0:18886
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18884
port=18886
EOF
  }
  if test "${liquid_case}" = true; then
    write_elements_config "${private_root}/elements-provider-a.conf" \
      "${elements_a_user}" "${elements_a_password}"
    write_elements_config "${private_root}/elements-provider-b.conf" \
      "${elements_b_user}" "${elements_b_password}"
    write_elements_config "${private_root}/elements-wallet.conf" \
      "${elements_wallet_user}" "${elements_wallet_password}"
  fi

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
IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND=127.0.0.1:$((health_port + 100))
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
    if test "${cooperative_signing}" = true; then
      printf '%s\n' 'IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING=true' >>"${path}"
    fi
  }
  write_provider_env "${private_root}/provider-a.env" a "${provider_a_password}" 18080 \
    "${provider_a_identity}" "${bitcoin_a_user}" "${bitcoin_a_password}" \
    /rail/cln-provider-a/lightning-rpc /run/immortal-private/provider-a-wallet-seed 9091
  write_provider_env "${private_root}/provider-b.env" b "${provider_b_password}" 18081 \
    "${provider_b_identity}" "${bitcoin_b_user}" "${bitcoin_b_password}" \
    /rail/cln-provider-b/lightning-rpc /run/immortal-private/provider-b-wallet-seed 9092
  if test "${zero_conf_case}" = true; then
    cat >>"${private_root}/provider-a.env" <<'EOF'
IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE=true
IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT=200000
IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT=400000
EOF
  fi

  cat >"${private_root}/esplora.env" <<EOF
IMMORTAL_ESPLORA_BITCOIND_RPC_USER=${bitcoin_a_user}
IMMORTAL_ESPLORA_BITCOIND_RPC_PASSWORD=${bitcoin_a_password}
EOF

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
IMMORTAL_LAB_DOOMSDAY_DIRECT_RECOVERY=127.0.0.1:9191
IMMORTAL_LAB_DOOMSDAY_ESPLORA_URL=http://127.0.0.1:3002/api
IMMORTAL_LAB_DOOMSDAY_CONTROL_FILE=/evidence/doomsday-control.json
IMMORTAL_LAB_KEYLESS_REQUEST_FILE=/evidence/doomsday-keyless-request.json
IMMORTAL_LAB_KEYLESS_RESULT_FILE=/evidence/doomsday-keyless-result.json
EOF
  if test -n "${external_injection}"; then
    cat >>"${private_root}/wallet-driver.env" <<EOF
IMMORTAL_LAB_INJECT_AT=${external_checkpoint}
IMMORTAL_LAB_INJECTION_TIMEOUT_SECONDS=300
EOF
  fi

  current_phase=compose-validation
  compose_ready=true
  compose config --quiet
  current_phase=image-build
  local -a build_services=(
    bitcoin-a bitcoin-b cln-provider-a cln-provider-b cln-wallet
    relay-a relay-b provider-a provider-b wallet-driver keyless-executor
    alert-sink-a alert-sink-b esplora-broadcast
    provider-a-egress provider-b-egress wallet-gateway
  )
  if test "${liquid_case}" = true; then
    build_services+=(elements-provider-a elements-provider-b elements-wallet)
  fi
  if ! compose build "${build_services[@]}" >"${private_root}/build.log" 2>&1; then
    failure_reason=image_build_failed
    print_bounded_diagnostic "image build" "${private_root}/build.log"
    exit 1
  fi

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
  local liquid_network_id="" liquid_pegged_asset="" liquid_height="" liquid_best_hash=""
  current_phase=rail-startup
  compose up --detach --no-deps provider-a-egress provider-b-egress \
    >>"${private_root}/startup.log" 2>&1
  compose up --detach wallet-gateway cln-provider-a cln-provider-b cln-wallet \
    relay-a relay-b alert-sink-a alert-sink-b esplora-broadcast \
    >>"${private_root}/startup.log" 2>&1
  if test "${liquid_case}" = true; then
    compose up --detach elements-provider-a elements-provider-b elements-wallet \
      >>"${private_root}/startup.log" 2>&1
  fi
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
  wait_for "Esplora-compatible broadcaster" compose run --rm --no-deps \
    --entrypoint /usr/bin/curl provider-a --fail --silent http://127.0.0.1:3002/healthz

  if test "${liquid_case}" = true; then
    current_phase=liquid-node-startup
    wait_for "Elements provider A" elements_cli a getblockchaininfo
    wait_for "Elements provider B" elements_cli b getblockchaininfo
    wait_for "Elements wallet" elements_cli wallet getblockchaininfo
    elements_cli a addnode bitcoin-b:18886 onetry >/dev/null
    elements_cli a addnode wallet-gateway:18886 onetry >/dev/null
    wait_for "three-node Elements peering" elements_peered
    if compose exec -T elements-provider-a elements-cli -chain=elementsregtest \
      -rpcconnect=bitcoin-b -rpcport=18884 -rpcuser=invalid -rpcpassword=invalid \
      getblockchaininfo >"${private_root}/cross-elements-a-to-b-rpc.log" 2>&1; then
      echo "test-lab-adversarial: Elements provider B exposed RPC outside its namespace" >&2
      exit 1
    fi
    if compose exec -T elements-provider-b elements-cli -chain=elementsregtest \
      -rpcconnect=bitcoin-a -rpcport=18884 -rpcuser=invalid -rpcpassword=invalid \
      getblockchaininfo >"${private_root}/cross-elements-b-to-a-rpc.log" 2>&1; then
      echo "test-lab-adversarial: Elements provider A exposed RPC outside its namespace" >&2
      exit 1
    fi

    current_phase=liquid-wallet-funding
    elements_cli a -named createwallet wallet_name=provider-a-liquid descriptors=true \
      | jq -e '.name == "provider-a-liquid"' >/dev/null
    elements_cli a -named createwallet wallet_name=initial-free-coins \
      disable_private_keys=true blank=true descriptors=true \
      | jq -e '.name == "initial-free-coins"' >/dev/null
    elements_cli a -rpcwallet=initial-free-coins importdescriptors \
      '[{"desc":"raw(51)#8lvh9jxk","timestamp":0}]' \
      | jq -e 'length == 1 and .[0].success == true' >/dev/null
    elements_cli b -named createwallet wallet_name=provider-b-liquid descriptors=true \
      | jq -e '.name == "provider-b-liquid"' >/dev/null
    elements_cli wallet -named createwallet wallet_name=requester-liquid descriptors=true \
      | jq -e '.name == "requester-liquid"' >/dev/null
    local liquid_miner_address liquid_provider_b_address liquid_wallet_address
    local liquid_provider_b_seed_txid liquid_provider_b_seed_raw
    local liquid_wallet_seed_txid liquid_wallet_seed_raw
    local initial_outputs initial_options initial_psbt initial_final
    liquid_miner_address="$(elements_cli a -rpcwallet=provider-a-liquid getnewaddress)"
    initial_outputs="$(jq -nc --arg address "${liquid_miner_address}" \
      '[{($address):1000}]')"
    initial_options="$(jq -nc --arg address "${liquid_miner_address}" \
      '{includeWatching:true,changeAddress:$address}')"
    initial_psbt="$(elements_cli a -rpcwallet=initial-free-coins \
      walletcreatefundedpsbt '[]' "${initial_outputs}" 0 "${initial_options}" true \
      | jq -er .psbt)"
    initial_final="$(elements_cli a finalizepsbt "${initial_psbt}")"
    jq -e '.complete == true' <<<"${initial_final}" >/dev/null
    elements_cli a sendrawtransaction "$(jq -er .hex <<<"${initial_final}")" >/dev/null
    elements_cli a -rpcwallet=provider-a-liquid generatetoaddress 1 \
      "${liquid_miner_address}" >/dev/null
    wait_for "initial Elements chain synchronization" elements_synced
    elements_cli a -rpcwallet=provider-a-liquid getbalances \
      | jq -e '.mine.trusted.bitcoin > 100' >/dev/null
    liquid_provider_b_address="$(elements_cli b -rpcwallet=provider-b-liquid getnewaddress)"
    liquid_wallet_address="$(elements_cli wallet -rpcwallet=requester-liquid getnewaddress)"
    liquid_provider_b_seed_txid="$(elements_cli a -rpcwallet=provider-a-liquid \
      sendtoaddress "${liquid_provider_b_address}" 10)"
    liquid_provider_b_seed_raw="$(elements_cli a -rpcwallet=provider-a-liquid \
      gettransaction "${liquid_provider_b_seed_txid}" | jq -er .hex)"
    test "$(elements_cli a sendrawtransaction "${liquid_provider_b_seed_raw}")" \
      = "${liquid_provider_b_seed_txid}"
    liquid_wallet_seed_txid="$(elements_cli a -rpcwallet=provider-a-liquid \
      sendtoaddress "${liquid_wallet_address}" 10)"
    liquid_wallet_seed_raw="$(elements_cli a -rpcwallet=provider-a-liquid \
      gettransaction "${liquid_wallet_seed_txid}" | jq -er .hex)"
    test "$(elements_cli a sendrawtransaction "${liquid_wallet_seed_raw}")" \
      = "${liquid_wallet_seed_txid}"
    elements_cli a -rpcwallet=provider-a-liquid generatetoaddress 6 \
      "${liquid_miner_address}" >/dev/null
    wait_for "funded Elements chain synchronization" elements_synced

    current_phase=liquid-network-binding
    local liquid_genesis liquid_genesis_b liquid_genesis_wallet
    local liquid_pegged_asset_b liquid_pegged_asset_wallet
    liquid_genesis="$(elements_cli a getblockhash 0)"
    liquid_genesis_b="$(elements_cli b getblockhash 0)"
    liquid_genesis_wallet="$(elements_cli wallet getblockhash 0)"
    test "${liquid_genesis}" = "${liquid_genesis_b}"
    test "${liquid_genesis}" = "${liquid_genesis_wallet}"
    [[ "${liquid_genesis}" =~ ^[0-9a-f]{64}$ ]]
    liquid_network_id="bip122:${liquid_genesis:0:32}"
    liquid_pegged_asset="$(elements_cli a getsidechaininfo | jq -er '.pegged_asset | select(test("^[0-9a-f]{64}$"))')"
    liquid_pegged_asset_b="$(elements_cli b getsidechaininfo | jq -er .pegged_asset)"
    liquid_pegged_asset_wallet="$(elements_cli wallet getsidechaininfo | jq -er .pegged_asset)"
    test "${liquid_pegged_asset}" = "${liquid_pegged_asset_b}"
    test "${liquid_pegged_asset}" = "${liquid_pegged_asset_wallet}"
    liquid_height="$(elements_cli a getblockcount)"
    liquid_best_hash="$(elements_cli a getbestblockhash)"

    cat >>"${private_root}/provider-a.env" <<EOF
IMMORTAL_PROVIDER_LIQUID_ENABLED=true
IMMORTAL_PROVIDER_ELEMENTSD_HOST=127.0.0.1
IMMORTAL_PROVIDER_ELEMENTSD_PORT=18884
IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER=${elements_a_user}
IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD=${elements_a_password}
IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-a-liquid
IMMORTAL_PROVIDER_LIQUID_NETWORK_ID=${liquid_network_id}
IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET=${liquid_pegged_asset}
EOF
    cat >>"${private_root}/provider-b.env" <<EOF
IMMORTAL_PROVIDER_LIQUID_ENABLED=true
IMMORTAL_PROVIDER_ELEMENTSD_HOST=127.0.0.1
IMMORTAL_PROVIDER_ELEMENTSD_PORT=18884
IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER=${elements_b_user}
IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD=${elements_b_password}
IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-b-liquid
IMMORTAL_PROVIDER_LIQUID_NETWORK_ID=${liquid_network_id}
IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET=${liquid_pegged_asset}
EOF
    cat >>"${private_root}/wallet-driver.env" <<EOF
IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_HOST=127.0.0.1
IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_PORT=18884
IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_RPC_USER=${elements_wallet_user}
IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_RPC_PASSWORD=${elements_wallet_password}
IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_WALLET=requester-liquid
IMMORTAL_LAB_ADVERSARIAL_LIQUID_NETWORK_ID=${liquid_network_id}
IMMORTAL_LAB_ADVERSARIAL_LIQUID_PEGGED_ASSET=${liquid_pegged_asset}
EOF
  fi

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

  current_phase=channel-provider-a-wallet
  local wallet_id provider_b_id paired_channel_height
  local provider_a_wallet_channel provider_b_wallet_channel provider_a_wallet_txid provider_b_wallet_txid
  wallet_id="$(cln_cli cln-wallet getinfo | jq -er .id)"
  provider_b_id="$(cln_cli cln-provider-b getinfo | jq -er .id)"
  cln_cli cln-provider-a connect "${wallet_id}@wallet-gateway:19848" >/dev/null
  provider_a_wallet_channel="$(cln_cli cln-provider-a -k fundchannel id="${wallet_id}" \
    amount=2000000sat feerate=253perkw announce=false push_msat=1000000000msat)"
  provider_a_wallet_txid="$(jq -er .txid <<<"${provider_a_wallet_channel}")"
  current_phase=channel-provider-b-wallet
  cln_cli cln-provider-b connect "${wallet_id}@wallet-gateway:19848" >/dev/null
  provider_b_wallet_channel="$(cln_cli cln-provider-b -k fundchannel id="${wallet_id}" \
    amount=2000000sat feerate=253perkw announce=false push_msat=1000000000msat)"
  provider_b_wallet_txid="$(jq -er .txid <<<"${provider_b_wallet_channel}")"
  wait_for "provider A wallet channel transaction at miner" \
    bitcoin_mempool_contains a "${provider_a_wallet_txid}"
  wait_for "provider B wallet channel transaction at miner" \
    bitcoin_mempool_contains a "${provider_b_wallet_txid}"
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "paired channel chain synchronization" chains_synced
  paired_channel_height="$(bitcoin_cli a getblockcount)"
  wait_for "provider A wallet channel" cln_channel_count_ready cln-provider-a 1
  wait_for "provider B wallet channel" cln_channel_count_ready cln-provider-b 1
  wait_for "wallet paired channels" cln_channel_count_ready cln-wallet 2
  wait_for "provider A confirmed channel change" cln_wallet_ready cln-provider-a "${paired_channel_height}"

  current_phase=channel-connect-provider-a-provider-b
  if ! cln_cli cln-provider-a connect "${provider_b_id}@bitcoin-b:19847" \
    >"${private_root}/channel-provider-a-provider-b-connect.log" 2>&1; then
    sed -n '1,20p' "${private_root}/channel-provider-a-provider-b-connect.log" >&2
    exit 1
  fi
  current_phase=channel-fund-provider-a-provider-b
  local provider_triangle_channel provider_triangle_txid
  if ! provider_triangle_channel="$(cln_cli cln-provider-a -k fundchannel \
    id="${provider_b_id}" amount=1000000sat feerate=253perkw announce=false \
    push_msat=500000000msat 2>"${private_root}/channel-provider-a-provider-b-fund.log")"; then
    sed -n '1,20p' "${private_root}/channel-provider-a-provider-b-fund.log" >&2
    exit 1
  fi
  provider_triangle_txid="$(jq -er .txid <<<"${provider_triangle_channel}")"
  wait_for "provider triangle channel transaction at miner" \
    bitcoin_mempool_contains a "${provider_triangle_txid}"
  bitcoin_cli a -rpcwallet=adversarial-miner generatetoaddress 6 "${miner_address}" >/dev/null
  wait_for "triangle channel chain synchronization" chains_synced

  current_phase=channel-readiness
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} balanced channels" cln_channels_ready "${service}"
    cln_cli "${service}" getinfo >"${private_root}/evidence/${service}-info.json"
    cln_cli "${service}" listpeerchannels >"${private_root}/evidence/${service}-channels.json"
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
  chain_height="$(bitcoin_cli a getblockcount)"
  for service in cln-provider-a cln-provider-b cln-wallet; do
    wait_for "${service} provider-funding chain height" cln_chain_ready "${service}" "${chain_height}"
  done

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
  if test "${liquid_case}" = true; then
    member_namespace="$(compose exec -T elements-provider-a readlink /proc/1/ns/net | tr -d '\r')"
    test "${member_namespace}" = "${namespace_a}"
    member_namespace="$(compose exec -T elements-provider-b readlink /proc/1/ns/net | tr -d '\r')"
    test "${member_namespace}" = "${namespace_b}"
    member_namespace="$(compose exec -T elements-wallet readlink /proc/1/ns/net | tr -d '\r')"
    test "${member_namespace}" = "${namespace_wallet}"
    local elements_a_container elements_b_container elements_wallet_container
    elements_a_container="$(compose ps --quiet elements-provider-a)"
    elements_b_container="$(compose ps --quiet elements-provider-b)"
    elements_wallet_container="$(compose ps --quiet elements-wallet)"
    docker inspect "${elements_a_container}" "${elements_b_container}" \
      "${elements_wallet_container}" >"${private_root}/elements-inspect.json"
    python3 - "${private_root}/elements-inspect.json" <<'PY'
import json
import pathlib
import sys

containers = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if len(containers) != 3 or len({container.get("Id") for container in containers}) != 3:
    raise SystemExit("Elements topology does not contain three separate processes")
volume_sources = []
for container in containers:
    mounts = {mount["Destination"]: mount for mount in container.get("Mounts", [])}
    data = mounts.get("/var/lib/elements")
    configuration = next(
        (mount for destination, mount in mounts.items() if destination.startswith("/run/immortal-private/elements-")),
        None,
    )
    if data is None or data.get("Type") != "volume" or data.get("RW") is not True:
        raise SystemExit("Elements process has no separate writable data volume")
    if configuration is None or configuration.get("RW") is not False:
        raise SystemExit("Elements process has no read-only private configuration")
    volume_sources.append(data.get("Name"))
if len(set(volume_sources)) != 3 or any(not source for source in volume_sources):
    raise SystemExit("Elements processes share a data volume")
PY
  fi

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
  if test "${liquid_case}" = true; then
    test "${running_count}" = 22
  else
    test "${running_count}" = 19
  fi
  provider_image="$(docker inspect --format '{{.Image}}' "${provider_a_container}")"

  current_phase=infrastructure-evidence
  python3 - "${private_root}/evidence/infrastructure.json" "${case_id}" "${group}" \
    "${namespace_a}" "${namespace_b}" "${namespace_wallet}" "${chain_height_final}" \
    "${chain_hash_final}" "${cln_a_id}" "${cln_b_id}" "${cln_wallet_id}" \
    "${provider_a_pubkey}" "${provider_b_pubkey}" "${provider_image}" \
    "${liquid_case}" "${liquid_network_id}" "${liquid_pegged_asset}" \
    "${liquid_height}" "${liquid_best_hash}" <<'PY'
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
liquid_enabled = sys.argv[15] == "true"
if liquid_enabled:
    if not (
        sys.argv[16].startswith("bip122:")
        and len(sys.argv[16]) == 39
        and len(sys.argv[17]) == 64
        and len(sys.argv[19]) == 64
    ):
        raise SystemExit("Liquid infrastructure evidence has invalid network identifiers")
    record["liquid"] = {
        "implementation": "elementsd",
        "network": "elementsregtest",
        "node_count": 3,
        "provider_nodes": 2,
        "wallet_nodes": 1,
        "separate_processes": True,
        "separate_data_volumes": True,
        "separate_rpc_credentials": True,
        "cross_provider_rpc_access": False,
        "network_id": sys.argv[16],
        "pegged_asset": sys.argv[17],
        "height": int(sys.argv[18]),
        "best_block_hash": sys.argv[19],
        "confidential_scope": "own-output-unblinding",
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
  local remaining_seconds driver_status driver_process
  remaining_seconds=$((case_deadline - $(date +%s)))
  if test "${remaining_seconds}" -le 0; then
    failure_reason=case_runtime_exceeded
    exit 1
  fi
  if test "${group}" = doomsday; then
    current_phase=doomsday-requester-prepare
    if ! compose run --rm --no-deps wallet-driver doomsday-prepare \
      >"${private_root}/evidence/doomsday-prepared.json" \
      2>"${private_root}/doomsday-prepare-error.log"; then
      failure_reason=doomsday_preparation_failed
      print_bounded_diagnostic "doomsday prepare" \
        "${private_root}/doomsday-prepare-error.log"
      exit 1
    fi
    python3 - "${private_root}/evidence/doomsday-prepared.json" "${case_id}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 8192:
    raise SystemExit("doomsday preparation evidence exceeds its bound")
value = json.loads(path.read_text(encoding="utf-8"))
if (
    value.get("schema") != "openagents.immortal.doomsday-prepared.v1"
    or value.get("case_id") != sys.argv[2]
    or value.get("requester_process_exit") is not True
):
    raise SystemExit("doomsday preparation did not bind the selected case")
PY
    current_phase=doomsday-permanent-removal
    compose stop relay-a relay-b >/dev/null
    if test "${case_id}" = doomsday-reverse-coordinator-gone \
      || test "${case_id}" = doomsday-liquid-reverse-coordinator-gone; then
      compose stop provider-b >/dev/null
      doomsday_stopped_targets=(provider-b relay-a relay-b)
    else
      compose stop provider-a provider-b >/dev/null
      doomsday_stopped_targets=(provider-a provider-b relay-a relay-b)
    fi
    for service in "${doomsday_stopped_targets[@]}"; do
      if compose ps --services --status running | grep -Fx "${service}" >/dev/null; then
        echo "test-lab-adversarial: ${case_id}: ${service} survived permanent removal" >&2
        exit 1
      fi
    done
    for provider_env in "${private_root}/provider-a.env" "${private_root}/provider-b.env"; do
      if grep -F 'IMMORTAL_PROVIDER_BOLTZ_BIND=' "${provider_env}" >/dev/null; then
        echo "test-lab-adversarial: ${case_id}: provider HTTP/WebSocket API was enabled" >&2
        exit 1
      fi
    done
    if test "${case_id}" = doomsday-keyless-esplora-broadcast; then
      current_phase=doomsday-keyless-planner
      if ! compose run --rm --no-deps wallet-driver doomsday-keyless-request \
          >"${private_root}/evidence/doomsday-keyless-planner.json" \
          2>"${private_root}/doomsday-keyless-planner-error.log"; then
        failure_reason=doomsday_keyless_planner_failed
        print_bounded_diagnostic "doomsday keyless planner" \
          "${private_root}/doomsday-keyless-planner-error.log"
        exit 1
      fi
      current_phase=doomsday-keyless-process
      local keyless_container_id keyless_status keyless_wait_status
      if ! keyless_container_id="$(compose run --no-deps \
          --name "${project_name}-keyless-executor" -d keyless-executor \
          2>"${private_root}/doomsday-keyless-process-error.log")"; then
        failure_reason=doomsday_keyless_process_failed
        print_bounded_diagnostic "doomsday keyless process" \
          "${private_root}/doomsday-keyless-process-error.log"
        exit 1
      fi
      docker inspect "${keyless_container_id}" \
        >"${private_root}/keyless-container-inspect.json"
      set +e
      keyless_status="$(docker wait "${keyless_container_id}")"
      keyless_wait_status=$?
      set -e
      docker logs "${keyless_container_id}" \
        >"${private_root}/evidence/doomsday-keyless-process.json" \
        2>>"${private_root}/doomsday-keyless-process-error.log"
      docker rm "${keyless_container_id}" >/dev/null
      if test "${keyless_wait_status}" -ne 0 || test "${keyless_status}" != 0; then
        failure_reason=doomsday_keyless_process_failed
        print_bounded_diagnostic "doomsday keyless process" \
          "${private_root}/doomsday-keyless-process-error.log"
        compose logs --no-color esplora-broadcast \
          >"${private_root}/doomsday-esplora-error.log" 2>&1
        print_bounded_diagnostic "doomsday Esplora adapter" \
          "${private_root}/doomsday-esplora-error.log"
        exit 1
      fi
      write_doomsday_control_audit "${private_root}/keyless-container-inspect.json"
    else
      write_doomsday_control_audit
    fi
    current_phase=doomsday-fresh-requester-recovery
    remaining_seconds=$((case_deadline - $(date +%s)))
    if test "${remaining_seconds}" -le 0; then
      failure_reason=case_runtime_exceeded
      exit 1
    fi
    set +e
    IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" \
      IMMORTAL_ADVERSARIAL_PROVIDER_IMAGE="${provider_image_ref}" python3 - \
        "${remaining_seconds}" "${compose_prefix[@]}" run --rm --no-deps wallet-driver \
        >"${private_root}/evidence/driver.json" 2>"${private_root}/driver-error.log" <<'PY'
import subprocess
import sys

try:
    result = subprocess.run(sys.argv[2:], timeout=int(sys.argv[1]), check=False)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(result.returncode)
PY
    driver_status=$?
    set -e
  elif test -n "${external_injection}"; then
    wallet_driver_container_name="${project_name}-wallet-driver-initial"
    set +e
    compose run --name "${wallet_driver_container_name}" --rm --no-deps wallet-driver \
      >"${private_root}/evidence/driver.json" 2>"${private_root}/driver-error.log" &
    driver_process=$!
    set -e
    if ! acknowledge_external_injection; then
      if test "${failure_reason}" = case_failed; then
        failure_reason=external_injection_failed
      fi
      kill -TERM "${driver_process}" >/dev/null 2>&1 || true
      wait "${driver_process}" >/dev/null 2>&1 || true
      exit 1
    fi
    current_phase=wallet-driver-recovery
    set +e
    wait_for_driver_process "${driver_process}"
    driver_status=$?
    set -e
  else
    set +e
  IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" \
    IMMORTAL_ADVERSARIAL_PROVIDER_IMAGE="${provider_image_ref}" python3 - \
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
  fi
  if test "${driver_status}" -ne 0; then
    print_bounded_diagnostic "wallet driver" "${private_root}/driver-error.log"
    compose logs --no-color provider-a provider-b \
      >"${private_root}/provider-error.log" 2>&1 || true
    print_bounded_diagnostic "provider" "${private_root}/provider-error.log"
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

  if test "${liquid_case}" = true; then
    current_phase=independent-chain-byte-equality
    local leg phase expected_transaction_id expected_transaction_hex observed_transaction_hex
    local node
    while IFS= read -r leg; do
      for phase in lockup exit; do
        expected_transaction_id="$(jq -er \
          ".proof.liquid_case.rails.${leg}.${phase}.transaction_id" \
          "${private_root}/evidence/driver.json")"
        expected_transaction_hex="$(jq -er \
          ".proof.liquid_case.rails.${leg}.${phase}.transaction_hex" \
          "${private_root}/evidence/driver.json")"
        if test "${leg}" = bitcoin; then
          for node in a b; do
            observed_transaction_hex="$(bitcoin_cli "${node}" getrawtransaction \
              "${expected_transaction_id}" false)"
            test "${observed_transaction_hex}" = "${expected_transaction_hex}"
          done
        else
          for node in a b wallet; do
            observed_transaction_hex="$(elements_cli "${node}" getrawtransaction \
              "${expected_transaction_id}" false)"
            test "${observed_transaction_hex}" = "${expected_transaction_hex}"
          done
        fi
      done
    done < <(jq -er '.proof.liquid_case.rails | keys[]' \
      "${private_root}/evidence/driver.json")
  fi

  if test "${case_id}" = double-reservation; then
    current_phase=double-reservation-process-audit
    local active_quote_id active_reservation_id active_session_id refused_session_id refused_rfq_id
    local provider_audit
    active_quote_id="$(jq -er '.proof.active.quote_id | select(test("^[0-9a-f]{64}$"))' \
      "${private_root}/evidence/driver.json")"
    active_reservation_id="$(jq -er '.proof.daemon_reservation_id | select(test("^[0-9a-f]{64}$"))' \
      "${private_root}/evidence/driver.json")"
    active_session_id="$(jq -er '.proof.active.session_id | select(test("^[0-9a-f]{64}$"))' \
      "${private_root}/evidence/driver.json")"
    refused_session_id="$(jq -er '.proof.refused.session_id | select(test("^[0-9a-f]{64}$"))' \
      "${private_root}/evidence/driver.json")"
    refused_rfq_id="$(jq -er '.proof.refused.rfq_id | select(test("^[0-9a-f]{64}$"))' \
      "${private_root}/evidence/driver.json")"
    for _ in $(seq 1 50); do
      provider_audit="$(compose exec -T provider-a-postgres psql \
        --username immortal_provider --dbname immortal_provider --tuples-only --no-align \
        --set ON_ERROR_STOP=1 --set reservation_id="${active_reservation_id}" \
        --set active_session="${active_session_id}" --set active_quote="${active_quote_id}" \
        --set refused_session="${refused_session_id}" --set refused_rfq="${refused_rfq_id}" <<'SQL'
SELECT
  count(*) FILTER (WHERE reservation_id = :'reservation_id'),
  count(*),
  (SELECT count(*) FROM provider_effect WHERE operation = 'reserve' AND state = 'applied'),
  (SELECT count(*) FROM provider_session_disposition
    WHERE session_id = :'refused_session'
      AND reason_code = 'swp_reservation_overallocated'),
  (SELECT count(*) FROM provider_session_record
    WHERE session_id = :'refused_session' AND event_id = :'refused_rfq' AND kind = 39604),
  (SELECT count(*) FROM provider_session_record
    WHERE session_id = :'refused_session' AND kind = 39605),
  (SELECT count(*) FROM provider_session_record
    WHERE session_id = :'active_session' AND event_id = :'active_quote' AND kind = 39605),
  (SELECT count(*) FROM provider_effect WHERE session_id = :'refused_session')
FROM provider_reservation;
SQL
)"
      if test "${provider_audit}" = "1|1|1|1|1|0|1|0"; then
        break
      fi
      sleep 0.1
    done
    python3 - "${private_root}/evidence/driver.json" "${provider_audit}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
provider = [int(value) for value in sys.argv[2].strip().split("|")]
if provider != [1, 1, 1, 1, 1, 0, 1, 0]:
    raise SystemExit(
        "provider process did not retain the exact over-allocation outcome: "
        + ",".join(str(value) for value in provider)
    )
document = json.loads(path.read_text(encoding="utf-8"))
proof = document.get("proof")
if not isinstance(proof, dict) or "process_audit" in proof:
    raise SystemExit("double-reservation driver proof has another shape")
refused = proof.get("refused")
if not isinstance(refused, dict) or refused.get("provider_wire_refusal") is not None:
    raise SystemExit("double-reservation proof invented a provider wire refusal")
refused["surface"] = "provider_session_disposition"
proof["process_audit"] = {
    "schema": "openagents.immortal.double-reservation-process-audit.v1",
    "manifest_code": "swp_reservation_overallocated",
    "durable_disposition": "swp_reservation_overallocated",
    "provider_wire_refusal": None,
    "provider_reservations": 1,
    "provider_reserve_effects": 1,
    "refused_session_records": 1,
    "refused_quote_records": 0,
    "refused_external_effects": 0,
}
encoded = (json.dumps(document, separators=(",", ":")) + "\n").encode()
if len(encoded) > 16384:
    raise SystemExit("audited double-reservation proof exceeds its input bound")
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY
  fi

  if test "${group}" = doomsday; then
    current_phase=doomsday-post-recovery-removal-audit
    for service in "${doomsday_stopped_targets[@]}"; do
      if compose ps --services --status running | grep -Fx "${service}" >/dev/null; then
        echo "test-lab-adversarial: ${case_id}: ${service} restarted during recovery" >&2
        exit 1
      fi
    done
    mark_doomsday_services_absent_after_recovery
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
case_id = sys.argv[6]
liquid_case_contracts = fixture["evidence"]["liquid_case_record"]["cases"]
liquid_case = case_id in liquid_case_contracts
if driver_path.stat().st_size > (32768 if liquid_case else 16384):
    raise SystemExit("driver evidence exceeds its input bound")
driver = json.loads(driver_path.read_text(encoding="utf-8"))
expected = sys.argv[7]
if (
    driver.get("schema") != "openagents.immortal.adversarial-case-result.v1"
    or driver.get("case_id") != case_id
    or driver.get("expected") != expected
    or driver.get("passed") is not True
):
    raise SystemExit("wallet driver did not prove the selected manifest case")
if liquid_case:
    case_contract = liquid_case_contracts[case_id]
    proof = driver.get("proof")
    liquid = proof.get("liquid_case") if isinstance(proof, dict) else None
    if not isinstance(liquid, dict):
        raise SystemExit("Liquid case has no process proof")
    required_liquid_members = {
        "schema", "shape", "selected_provider", "signed_lifecycle_event_ids",
        "rails", "provider_effect_operations", "provider_status_anchors",
        "provider_restart", "liquid_terminal", "lightning_terminal", "recovery",
    }
    if (
        set(liquid) != required_liquid_members
        or liquid.get("schema") != fixture["evidence"]["liquid_case_record"]["schema"]
        or liquid.get("shape") != case_contract["shape"]
        or liquid.get("selected_provider") != case_contract["selected_provider"]
        or liquid.get("provider_effect_operations") != case_contract["provider_effect_operations"]
        or liquid.get("provider_status_anchors") != case_contract["provider_status_anchors"]
    ):
        raise SystemExit("Liquid proof does not bind its exact shape, provider, effects, and statuses")
    lifecycle = liquid.get("signed_lifecycle_event_ids")
    required_events = {
        "offering_id", "rfq_id", "quote_id", "order_id",
        "requester_contract_id", "provider_contract_id", "status_ids", "close_id",
    }
    if not isinstance(lifecycle, dict) or set(lifecycle) != required_events:
        raise SystemExit("Liquid proof does not contain the complete signed lifecycle")
    for name, event_id in lifecycle.items():
        if name == "close_id" and case_contract["recovery"] == "presigned-refund":
            if event_id is not None:
                raise SystemExit("coordinator-absent Liquid refund invented a provider Close")
            continue
        if name == "status_ids":
            if not isinstance(event_id, list) or len(event_id) < 2:
                raise SystemExit("Liquid proof has no signed Status progression")
            values = event_id
        else:
            values = [event_id]
        if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in values):
            raise SystemExit("Liquid proof contains an invalid signed event ID")
    rails = liquid.get("rails")
    if not isinstance(rails, dict) or list(rails) != case_contract["rails"]:
        raise SystemExit("Liquid proof does not contain its exact ordered rail set")
    expected_nodes = {
        "bitcoin": {"bitcoind-a", "bitcoind-b"},
        "liquid": {"elementsd-provider-a", "elementsd-provider-b", "elementsd-wallet"},
    }
    for leg_name, leg in rails.items():
        if not isinstance(leg, dict) or set(leg) != {"lockup", "exit"}:
            raise SystemExit("Liquid proof rail has another shape")
        lockup = leg["lockup"]
        exit_transaction = leg["exit"]
        for phase, transaction in (("lockup", lockup), ("exit", exit_transaction)):
            outpoint_member = "outpoint" if phase == "lockup" else "spends_outpoint"
            required_transaction_members = {
                "transaction_hex", "transaction_id", outpoint_member,
                "node_transaction_ids", "exact_node_byte_equality",
            }
            if not isinstance(transaction, dict) or set(transaction) != required_transaction_members:
                raise SystemExit("Liquid transaction evidence has another shape")
            transaction_hex = transaction["transaction_hex"]
            transaction_id = transaction["transaction_id"]
            outpoint = transaction[outpoint_member]
            node_transaction_ids = transaction["node_transaction_ids"]
            if (
                not isinstance(transaction_hex, str)
                or not transaction_hex
                or len(transaction_hex) % 2 != 0
                or re.fullmatch(r"[0-9a-f]+", transaction_hex) is None
                or not isinstance(transaction_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None
                or not isinstance(outpoint, str)
                or re.fullmatch(r"[0-9a-f]{64}:[0-9]+", outpoint) is None
                or transaction.get("exact_node_byte_equality") is not True
                or not isinstance(node_transaction_ids, dict)
                or set(node_transaction_ids) != expected_nodes[leg_name]
                or any(value != transaction_id for value in node_transaction_ids.values())
            ):
                raise SystemExit("Liquid transaction evidence is not exact across nodes")
        if not lockup["outpoint"].startswith(lockup["transaction_id"] + ":"):
            raise SystemExit("Liquid lockup outpoint does not bind its transaction")
        if exit_transaction["spends_outpoint"] != lockup["outpoint"]:
            raise SystemExit("Liquid exit does not spend the exact lockup outpoint")
    terminal = liquid.get("liquid_terminal")
    if terminal != {
        "actor": case_contract["liquid_terminal_actor"],
        "path": case_contract["liquid_terminal_path"],
        "effect_class": "liquid_spend",
        "confirmed": True,
    }:
        raise SystemExit("Liquid proof has another terminal spend actor, path, or effect class")
    lightning = liquid.get("lightning_terminal")
    expected_lightning = case_contract["lightning_terminal"]
    if expected_lightning is None:
        if lightning is not None:
            raise SystemExit("chain-only Liquid proof invented a Lightning disposition")
    else:
        if not isinstance(lightning, dict) or set(lightning) != set(expected_lightning) | {"payment_hash"}:
            raise SystemExit("Liquid proof has no exact Lightning terminal observation")
        payment_hash = lightning.get("payment_hash")
        if not isinstance(payment_hash, str) or re.fullmatch(r"[0-9a-f]{64}", payment_hash) is None:
            raise SystemExit("Liquid Lightning terminal observation has an invalid payment hash")
        observed_contract = dict(lightning)
        observed_contract.pop("payment_hash")
        if observed_contract != expected_lightning:
            raise SystemExit("Liquid proof has another Lightning effect, state, or authority")
    restart = liquid.get("provider_restart")
    if case_contract["provider_restart_required"]:
        if restart != {
            "target": case_contract["selected_provider"],
            "checkpoint_effect_operation": case_contract["provider_effect_operations"][0],
            "checkpoint_status_state": case_contract["provider_status_anchors"][0],
            "process_replaced": True,
            "restored_from_postgres": True,
            "exact_known_replay": True,
            "duplicate_external_effects": 0,
        }:
            raise SystemExit("Liquid proof does not contain exact provider restart recovery")
    elif restart is not None:
        raise SystemExit("Liquid doomsday proof claims an unrequired provider restart")
    recovery = liquid.get("recovery")
    if case_contract["recovery"] is None:
        if recovery is not None:
            raise SystemExit("Liquid route proof contains doomsday recovery evidence")
    elif case_contract["recovery"] == "presigned-refund":
        if recovery != {
            "mode": "presigned-refund",
            "fresh_requester_process": True,
            "signed_before_requester_contract": True,
            "signed_before_funding_broadcast": True,
            "provider_effect_operations": [],
            "refund_transaction_id": rails["liquid"]["exit"]["transaction_id"],
        }:
            raise SystemExit("Liquid submarine doomsday does not prove its exact pre-signed refund")
    elif case_contract["recovery"] == "direct-claim-and-hold-settlement":
        if recovery != {
            "mode": "direct-claim-and-hold-settlement",
            "fresh_requester_process": True,
            "direct_provider_retained": True,
            "claim_transaction_id": rails["liquid"]["exit"]["transaction_id"],
            "hold_invoice_terminal_state": "settled",
        }:
            raise SystemExit("Liquid reverse doomsday does not prove exact claim and hold settlement")
    else:
        raise SystemExit("Liquid case fixture contains another recovery requirement")
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
controller_path = private_root / "evidence" / "doomsday-control.json"
controller = None
if controller_path.exists():
    if controller_path.stat().st_size > 8192:
        raise SystemExit("doomsday controller evidence exceeds its bound")
    controller = json.loads(controller_path.read_text(encoding="utf-8"))
    if (
        controller.get("case_id") != case_id
        or controller.get("stopped_targets_absent_before_recovery") is not True
        or controller.get("stopped_targets_absent_after_recovery") is not True
    ):
        raise SystemExit("doomsday controller evidence does not prove durable removal")
    scan(controller)
record = {
    "schema": fixture["evidence"]["retained_record"]["schema"],
    "case_id": case_id,
    "expected": expected,
    "infrastructure": infrastructure,
    "result": driver,
    "local_only": True,
}
if controller is not None:
    record["controller_audit"] = controller
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
for name in (
    "relay-a-postgres-password", "relay-b-postgres-password",
    "provider-a-postgres-password", "provider-b-postgres-password",
    "provider-a-wallet-seed", "provider-b-wallet-seed", "client-wallet-seed",
    "elements-provider-a-rpc-password", "elements-provider-b-rpc-password",
    "elements-wallet-rpc-password",
):
    secret_path = private_root / name
    if not secret_path.exists():
        continue
    secret = secret_path.read_bytes().strip()
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
if fixture["evidence"]["retained_record"].get("aggregate_encoding") != "utf8-json-sort-keys-compact":
    raise SystemExit("aggregate adversarial record encoding is not pinned")
encoded = (json.dumps(aggregate, sort_keys=True, separators=(",", ":")) + "\n").encode()
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

while IFS=$'\t' read -r -u 3 case_id group expected provider; do
  run_case "${case_id}" "${group}" "${expected}" "${provider}"
done 3<"${case_file}"
aggregate_records
