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
  'external_checkpoint=submarine:funding_reorg_control' \
  'external_checkpoint=submarine:claim_reorg_control' \
  'generateblock "${miner_address}"' \
  'bitcoin_cli a invalidateblock "${orphaned_block_hash}"' \
  "WHERE job_kind = 'claim_broadcast'" \
  'funding_reorg_waited_and_resumed' \
  'claim_watch_reorged_and_reconfirmed' \
  'docker volume ls --quiet --filter "label=com.docker.compose.project=${project_name}"' \
  'docker image ls --quiet --filter "label=com.docker.compose.project=${project_name}"' \
  'maximum = min(32768, fixture["evidence"]["retained_record"]["maximum_bytes"])' \
  'separators=(",", ":")'; do
  if ! grep -F -- "${required}" "${runner}" >/dev/null; then
    echo "test-adversarial-runner: runner lost required closure ${required}" >&2
    exit 1
  fi
done
if grep -R -E 'github/workflows|gh workflow|workflow_dispatch' "${runner}" >/dev/null; then
  echo "test-adversarial-runner: runner contains GitHub automation" >&2
  exit 1
fi

python3 - "${runner}" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
network_bind = "[regtest]\nbind=0.0.0.0:18444\nrpcbind=127.0.0.1"
if runner.count(network_bind) != 2:
    raise SystemExit("bitcoind P2P bind is not scoped to both regtest sections")
PY

echo "test-adversarial-runner: manifest-derived selection passed"
