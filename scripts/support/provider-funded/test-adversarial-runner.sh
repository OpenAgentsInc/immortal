#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."

runner="scripts/test-lab-adversarial.sh"
manifest_gate="scripts/test-lab-adversarial-manifest.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-adversarial-runner-test.XXXXXX")"

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  case "$(basename "${test_root}")" in
    immortal-adversarial-runner-test.*) rm -rf -- "${test_root}" || exit_status=1 ;;
    *) echo "test-adversarial-runner: refused unexpected test root" >&2; exit_status=1 ;;
  esac
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM
umask 077

bash -n "${runner}"
"${runner}" --list >"${test_root}/runner-cases"
"${manifest_gate}" --list >"${test_root}/manifest-cases"
diff -u "${test_root}/manifest-cases" "${test_root}/runner-cases"
if "${runner}" --case unknown-adversarial-case \
  >"${test_root}/unknown-output" 2>"${test_root}/unknown-error"; then
  echo "test-adversarial-runner: unknown case was accepted" >&2
  exit 1
fi
grep -Fx 'test-lab-adversarial: unknown case unknown-adversarial-case' \
  "${test_root}/unknown-error" >/dev/null
for required in \
  'IMMORTAL_PROVIDER_LAB_PROFILE=regtest_adversarial' \
  'holdinvoiceimmortalregtest' \
  'bitcoin-cli -rpcconnect=bitcoin-b -rpcport=18443' \
  'bitcoin-cli -rpcconnect=bitcoin-a -rpcport=18443' \
  'docker volume ls --quiet --filter "label=com.docker.compose.project=${project_name}"' \
  'docker image ls --quiet --filter "label=com.docker.compose.project=${project_name}"' \
  'maximum = min(32768, fixture["evidence"]["retained_record"]["maximum_bytes"])'; do
  if ! grep -F -- "${required}" "${runner}" >/dev/null; then
    echo "test-adversarial-runner: runner lost required closure ${required}" >&2
    exit 1
  fi
done
if grep -R -E 'github/workflows|gh workflow|workflow_dispatch' "${runner}" >/dev/null; then
  echo "test-adversarial-runner: runner contains GitHub automation" >&2
  exit 1
fi

echo "test-adversarial-runner: manifest-derived selection passed"
