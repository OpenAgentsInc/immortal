#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

checkpoint_manifest="tests/fixtures/lab/funded-checkpoints-v1.json"
matrix_manifest="tests/fixtures/lab/funded-matrix-v1.json"
smoke_runner="scripts/test-provider-funded.sh"
case_file="$(mktemp "${TMPDIR:-/tmp}/immortal-funded-matrix-cases.XXXXXX")"
selection=""
selected_case=""
active_smoke_pid=""

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test -n "${active_smoke_pid}"; then
    if kill -TERM "${active_smoke_pid}" >/dev/null 2>&1; then
      if wait "${active_smoke_pid}" >/dev/null 2>&1; then
        echo "test-provider-funded-matrix: active smoke exited during cleanup" >&2
      fi
    fi
    active_smoke_pid=""
  fi
  case "$(basename "${case_file}")" in
    immortal-funded-matrix-cases.*) ;;
    *)
      echo "test-provider-funded-matrix: refused to remove an unexpected temporary file" >&2
      exit 1
      ;;
  esac
  if ! rm -f -- "${case_file}"; then
    echo "test-provider-funded-matrix: could not remove its private case file" >&2
    exit_status=1
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM
umask 077

run_smoke() {
  "$@" </dev/null &
  active_smoke_pid=$!
  local smoke_status
  if wait "${active_smoke_pid}"; then
    smoke_status=0
  else
    smoke_status=$?
  fi
  active_smoke_pid=""
  return "${smoke_status}"
}

usage() {
  cat <<'USAGE'
Usage: scripts/test-provider-funded-matrix.sh --list
       scripts/test-provider-funded-matrix.sh --case CASE_ID
       scripts/test-provider-funded-matrix.sh --all

The matrix is manual and opt-in. Every selected case receives a fresh disposable
topology from scripts/test-provider-funded.sh; no case reuses rail or custody state.
USAGE
}

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

python3 - "${checkpoint_manifest}" "${matrix_manifest}" >"${case_file}" <<'PY'
import json
import pathlib
import sys

checkpoint_path = pathlib.Path(sys.argv[1])
matrix_path = pathlib.Path(sys.argv[2])
with checkpoint_path.open(encoding="utf-8") as source:
    checkpoints = json.load(source)
with matrix_path.open(encoding="utf-8") as source:
    matrix = json.load(source)

if matrix.get("schema") != "openagents.immortal.lab-funded-matrix.v1":
    raise SystemExit("matrix fixture has another schema")
if matrix.get("checkpoint_manifest") != checkpoint_path.as_posix():
    raise SystemExit("matrix fixture points to another checkpoint manifest")
if matrix.get("smoke_runner") != "scripts/test-provider-funded.sh":
    raise SystemExit("matrix fixture points to another smoke runner")
selection = matrix.get("selection")
if selection != {
    "restart_cases": "every_restartable_checkpoint",
    "injection_cases": "every_bounded_injection",
    "fresh_disposable_topology_per_case": True,
    "github_automation": False,
}:
    raise SystemExit("matrix selection contract is invalid")

restart_cases = []
for journey, contract in checkpoints.get("journeys", {}).items():
    for label in contract.get("restartable", []):
        qualified = f"{journey}:{label}"
        restart_cases.append((f"restart-{journey}-{label}", "restart", qualified, ""))

injection_contracts = {
    contract.get("name"): contract
    for contract in checkpoints.get("injections", [])
}
matrix_injections = matrix.get("injection_cases")
if not isinstance(matrix_injections, dict) or set(matrix_injections) != set(injection_contracts):
    raise SystemExit("matrix does not cover every bounded injection exactly once")

injection_cases = []
for name, contract in injection_contracts.items():
    matrix_case = matrix_injections[name]
    outcome = matrix_case.get("driver_outcome")
    expected_error = matrix_case.get("expected_driver_error", "")
    if outcome not in {"complete", "expected_rejection"}:
        raise SystemExit(f"injection {name} has an unsupported outcome")
    if (outcome == "expected_rejection") != bool(expected_error):
        raise SystemExit(f"injection {name} has an inconsistent rejection contract")
    inject_at = matrix_case.get("inject_at", "")
    if contract.get("owner") == "external_script":
        if inject_at not in {case[2] for case in restart_cases}:
            raise SystemExit(f"external injection {name} has no safe checkpoint")
    elif inject_at:
        raise SystemExit(f"harness-owned injection {name} has an external checkpoint")
    injection_cases.append((f"injection-{name.replace('_', '-')}", "injection", name, inject_at))

cases = restart_cases + injection_cases
limits = matrix.get("limits", {})
maximum_cases = limits.get("maximum_cases")
maximum_case_id_bytes = limits.get("maximum_case_id_bytes")
if (
    limits.get("maximum_request_bytes") != 4096
    or limits.get("maximum_acknowledgement_bytes") != 4096
    or limits.get("maximum_injection_wait_seconds")
    != checkpoints.get("controls", {}).get("maximum_injection_wait_seconds")
):
    raise SystemExit("matrix request, acknowledgement, or wait bounds have drifted")
if (
    isinstance(maximum_cases, bool)
    or not isinstance(maximum_cases, int)
    or not 1 <= len(cases) <= maximum_cases <= 32
    or isinstance(maximum_case_id_bytes, bool)
    or not isinstance(maximum_case_id_bytes, int)
    or not 1 <= maximum_case_id_bytes <= 128
):
    raise SystemExit("matrix case bounds are invalid")
if len({case[0] for case in cases}) != len(cases):
    raise SystemExit("matrix case ids are not unique")
for case_id, kind, value, inject_at in cases:
    if len(case_id.encode()) > maximum_case_id_bytes:
        raise SystemExit("matrix case id is unbounded")
    for field in (case_id, kind, value, inject_at):
        if any(character in field for character in "\t\r\n"):
            raise SystemExit("matrix case contains a control character")
    print(case_id, kind, value, inject_at, sep="\t")
PY

if test "${selection}" = list; then
  cut -f1 "${case_file}"
  exit 0
fi

if test "${selection}" = case && ! cut -f1 "${case_file}" | grep -Fx -- "${selected_case}" >/dev/null; then
  echo "test-provider-funded-matrix: unknown case ${selected_case}" >&2
  exit 2
fi

case_count="$(wc -l <"${case_file}" | tr -d ' ')"
case_index=0
while IFS=$'\t' read -r case_id kind value inject_at; do
  if test "${selection}" = case && test "${case_id}" != "${selected_case}"; then
    continue
  fi
  case_index=$((case_index + 1))
  if test "${selection}" = all; then
    echo "test-provider-funded-matrix: case ${case_index}/${case_count} ${case_id}"
  else
    echo "test-provider-funded-matrix: case ${case_id}"
  fi
  case "${kind}" in
    restart)
      run_smoke env IMMORTAL_PROVIDER_FUNDED_RESTART_AT="${value}" \
        "${smoke_runner}"
      ;;
    injection)
      if test -n "${inject_at}"; then
        run_smoke env IMMORTAL_PROVIDER_FUNDED_INJECTION="${value}" \
          IMMORTAL_PROVIDER_FUNDED_INJECT_AT="${inject_at}" \
          "${smoke_runner}"
      else
        run_smoke env IMMORTAL_PROVIDER_FUNDED_INJECTION="${value}" \
          "${smoke_runner}"
      fi
      ;;
    *)
      echo "test-provider-funded-matrix: fixture emitted an unsupported case" >&2
      exit 1
      ;;
  esac
done <"${case_file}"

expected_case_count=1
if test "${selection}" = all; then
  expected_case_count="${case_count}"
fi
if test "${case_index}" -ne "${expected_case_count}"; then
  echo "test-provider-funded-matrix: executed ${case_index} of ${expected_case_count} selected cases" >&2
  exit 1
fi

echo "test-provider-funded-matrix: selected disposable cases passed"
