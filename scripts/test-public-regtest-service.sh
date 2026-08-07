#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/public-regtest-service-v1.json"
operator="scripts/public-regtest-operator.sh"

bash -n "${operator}"
if command -v shellcheck >/dev/null 2>&1; then shellcheck "${operator}"; fi

jq -e '
  .schema == "openagents.immortal.public-regtest-service-contract.v1" and
  .network == "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4" and
  .concurrency.minimum_simultaneous_browser_sessions == 5 and
  .concurrency.qualification_sequential_funded_sessions == 50 and
  .concurrency.maximum_active_sessions == 16 and
  .concurrency.maximum_connections == 32 and
  .concurrency.maximum_outstanding_sat == 5000000 and
  .operator.mining.public_rpc == false and
  .operator.mining.maximum_blocks_per_pass == 6 and
  .operator.lightning.accept_quotes_when_depleted == false and
  .operator.storage.receipt_retention_seconds == 604800 and
  .claims.regtest_only == true and .claims.mainnet == false
' "${fixture}" >/dev/null

grep -Fq 'lightning_liquidity_' "${operator}"
grep -Fq 'outstanding_value_capacity' "${operator}"
grep -Fq 'admissions.issubset(receipts)' "${operator}"
grep -Fq 'maximum_connections' "${fixture}"
grep -Fq 'header_up X-Immortal-Client-IP {remote_host}' deploy/public-regtest/Caddyfile.example
grep -Fq 'User=immortal-regtest-gateway' deploy/public-regtest/immortal-public-regtest-gateway.service
grep -Fq 'ReadWritePaths=/var/lib/immortal-public-regtest/gateway' deploy/public-regtest/immortal-public-regtest-gateway.service
grep -Fq 'SupplementaryGroups=docker' deploy/public-regtest/immortal-public-regtest-operator.service

service_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-service-cleanup.XXXXXX")"
trap 'rm -rf -- "${service_root}"' EXIT INT TERM
gateway_root="${service_root}/gateway"
mkdir -p "${gateway_root}/sessions"
printf '{}\n' >"${service_root}/ownership.json"
old_time="$(( $(date +%s) - 700000 ))"
empty_id="$(printf '11%.0s' $(seq 1 32))"
pending_id="$(printf '22%.0s' $(seq 1 32))"
receipted_id="$(printf '33%.0s' $(seq 1 32))"
for session_id in "${empty_id}" "${pending_id}" "${receipted_id}"; do
  mkdir "${gateway_root}/sessions/${session_id}"
  jq -cn --argjson old "${old_time}" '{revoked_at:$old,expires_at:$old}' \
    >"${gateway_root}/sessions/${session_id}/session.json"
done
printf '{}\n' >"${gateway_root}/sessions/${pending_id}/admission-effect.json"
printf '{}\n' >"${gateway_root}/sessions/${receipted_id}/admission-effect.json"
printf '{}\n' >"${gateway_root}/sessions/${receipted_id}/receipt-effect.json"
IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${service_root}" \
IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR="${gateway_root}" \
  "${operator}" cleanup >"${service_root}/cleanup.json"
jq -e '.removed_sessions == 2' "${service_root}/cleanup.json" >/dev/null
test ! -e "${gateway_root}/sessions/${empty_id}"
test -e "${gateway_root}/sessions/${pending_id}"
test ! -e "${gateway_root}/sessions/${receipted_id}"
rm -rf -- "${service_root}"
trap - EXIT INT TERM

scripts/test-public-regtest-gateway.sh

echo "test-public-regtest-service: readiness, capacity, retention, and gateway fault gates passed"
