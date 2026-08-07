#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for command_name in cargo curl jq mktemp; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "test-public-regtest-gateway: ${command_name} is required" >&2
    exit 1
  }
done

private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-public-gateway.XXXXXX")"
gateway_state="${private_root}/gateway"
signing_key="${private_root}/signing-key"
gateway_log="${private_root}/gateway.log"
origin="https://bazaar-regtest.example"
bind="127.0.0.1:19337"
url="http://${bind}"
client_ip="198.51.100.10"
provider="$(printf '55%.0s' $(seq 1 32))"
requester="$(printf '66%.0s' $(seq 1 32))"
revision="$(git rev-parse HEAD)"
contract_digest="$(printf '77%.0s' $(seq 1 32))"
gateway_process=""

cleanup() {
  if test -n "${gateway_process}" && kill -0 "${gateway_process}" >/dev/null 2>&1; then
    kill -TERM "${gateway_process}" >/dev/null 2>&1 || true
    wait "${gateway_process}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${private_root}"
}
trap cleanup EXIT INT TERM

umask 077
mkdir -p "${gateway_state}"
printf '01%.0s' $(seq 1 32) >"${signing_key}"
printf '\n' >>"${signing_key}"
chmod 0600 "${signing_key}"

write_readiness() {
  jq -cn \
    --arg revision "${revision}" \
    --arg provider "${provider}" \
    --argjson checked_at "$(date +%s)" \
    '{
      schema:"openagents.immortal.public-regtest-service-readiness.v1",
      ready:true,
      checked_at:$checked_at,
      revision:$revision,
      failures:[],
      active_sessions:0,
      outstanding_sat:0,
      provider_pubkeys:[$provider],
      lightning_node_ids:[
        "021111111111111111111111111111111111111111111111111111111111111111",
        "022222222222222222222222222222222222222222222222222222222222222222",
        "023333333333333333333333333333333333333333333333333333333333333333"
      ],
      bitcoin_height:101,
      receipt_store_writable:true
    }' >"${gateway_state}/readiness.json"
  chmod 0600 "${gateway_state}/readiness.json"
}

write_readiness

cargo build --locked --quiet \
  -p immortal-lab \
  -p immortal-public-regtest-gateway

dependency_tree="${private_root}/gateway-dependency-tree.txt"
cargo tree --locked -p immortal-public-regtest-gateway -e normal >"${dependency_tree}"
if grep -E 'immortal-(client|provider)|tokio-postgres|tokio-tungstenite' \
  "${dependency_tree}" >/dev/null; then
  echo "test-public-regtest-gateway: forbidden public-boundary dependency" >&2
  cat "${dependency_tree}" >&2
  exit 1
fi

gateway_env=(
  env
  "IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR=${gateway_state}"
  "IMMORTAL_PUBLIC_REGTEST_GATEWAY_BIND=${bind}"
  "IMMORTAL_PUBLIC_REGTEST_ORIGIN=${origin}"
  "IMMORTAL_PUBLIC_REGTEST_SIGNING_KEY_FILE=${signing_key}"
  "IMMORTAL_PUBLIC_REGTEST_SOURCE_REVISION=${revision}"
  "IMMORTAL_PUBLIC_REGTEST_REQUESTER_CONTRACT_DIGEST=${contract_digest}"
  "IMMORTAL_PUBLIC_REGTEST_PROVIDER_SET=${provider}"
  IMMORTAL_PUBLIC_REGTEST_SESSION_LIFETIME_SECONDS=300
  IMMORTAL_PUBLIC_REGTEST_EFFECT_TIMEOUT_SECONDS=30
)

start_gateway() {
  write_readiness
  "${gateway_env[@]}" target/debug/immortal-public-regtest-gateway \
    >>"${gateway_log}" 2>&1 &
  gateway_process=$!
  for _ in $(seq 1 100); do
    if ! kill -0 "${gateway_process}" >/dev/null 2>&1; then
      echo "test-public-regtest-gateway: gateway exited during startup" >&2
      sed -n '1,120p' "${gateway_log}" >&2
      return 1
    fi
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --header "Origin: ${origin}" \
      --header "X-Immortal-Client-IP: ${client_ip}" \
      "${url}/unknown" || true)"
    if test "${status}" = 404; then return 0; fi
    sleep 0.05
  done
  echo "test-public-regtest-gateway: gateway did not become reachable" >&2
  return 1
}

stop_gateway() {
  kill -TERM "${gateway_process}"
  wait "${gateway_process}" >/dev/null 2>&1 || true
  gateway_process=""
}

start_gateway

test "$(curl --silent --output "${private_root}/health.json" --write-out '%{http_code}' \
  --header "X-Immortal-Client-IP: ${client_ip}" "${url}/healthz")" = 200
test "$(curl --silent --output "${private_root}/ready.json" --write-out '%{http_code}' \
  --header "X-Immortal-Client-IP: ${client_ip}" "${url}/readyz")" = 200
jq -e '.schema == "openagents.immortal.public-regtest-service-readiness.v1" and .ready == true' \
  "${private_root}/ready.json" >/dev/null
test "$(curl --silent --output "${private_root}/metrics.json" --write-out '%{http_code}' \
  --header "X-Immortal-Client-IP: ${client_ip}" "${url}/metrics")" = 200
jq -e '.schema == "openagents.immortal.public-regtest-metrics.v1" and .active_sessions == 0' \
  "${private_root}/metrics.json" >/dev/null

create_request="${private_root}/create.json"
create_response="${private_root}/create-response.json"
jq -cn \
  --arg requester "${requester}" \
  --arg nonce "$(printf '88%.0s' $(seq 1 32))" \
  '{schema:"openagents.immortal.public-regtest-session-create.v1",requester_identity:$requester,client_nonce:$nonce}' \
  >"${create_request}"

jq '.checked_at = 1' "${gateway_state}/readiness.json" >"${gateway_state}/readiness-stale.json"
mv "${gateway_state}/readiness-stale.json" "${gateway_state}/readiness.json"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" --header "X-Immortal-Client-IP: ${client_ip}" \
  --header 'Content-Type: application/json' --data-binary "@${create_request}" \
  "${url}/v1/public-regtest/sessions")" = 503
write_readiness
touch "${gateway_state}/maintenance"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" --header "X-Immortal-Client-IP: ${client_ip}" \
  --header 'Content-Type: application/json' --data-binary "@${create_request}" \
  "${url}/v1/public-regtest/sessions")" = 503
rm "${gateway_state}/maintenance"
write_readiness

status="$(curl --silent --show-error --output "${create_response}" --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${create_request}" \
  "${url}/v1/public-regtest/sessions")"
test "${status}" = 201
jq -e '
  .schema == "openagents.immortal.public-regtest-session-response.v1" and
  (.capability | length) == 64 and
  .signed_manifest.manifest.network == "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4" and
  .signed_manifest.manifest.origin == "https://bazaar-regtest.example" and
  (.signed_manifest.signature_event.content | fromjson) == .signed_manifest.manifest
' "${create_response}" >/dev/null
python3 - "${create_response}" signed_manifest <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]
canonical = json.dumps(value["manifest"], sort_keys=True, separators=(",", ":"))
if value["signature_event"]["content"] != canonical:
    raise SystemExit("session manifest content is not canonical JSON")
PY
session_id="$(jq -r '.signed_manifest.manifest.sandbox_session_id' "${create_response}")"
capability="$(jq -r '.capability' "${create_response}")"
if grep -R -F "${capability}" "${gateway_state}" >/dev/null 2>&1; then
  echo "test-public-regtest-gateway: raw capability reached durable state" >&2
  exit 1
fi

dynamic_request="${private_root}/dynamic-request.json"
dynamic_destination="lnbcrt-private-destination-never-public"
jq -cn --arg session "${session_id}" --arg destination "${dynamic_destination}" '{
  schema:"openagents.immortal.public-regtest-dynamic-submission.v1",
  sandbox_session_id:$session,
  request:{schema:"openagents.immortal.dynamic-public-regtest-request.v1",destination:$destination}
}' >"${dynamic_request}"
for attempt in 1 2; do
  test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --header "Origin: ${origin}" \
    --header "X-Immortal-Client-IP: ${client_ip}" \
    --header "Authorization: ImmortalRegtest ${capability}" \
    --header 'Content-Type: application/json' \
    --data-binary "@${dynamic_request}" \
    "${url}/v1/public-regtest/sessions/${session_id}/requests")" = 202
done
test -s "${gateway_state}/sessions/${session_id}/private-dynamic-request.json"
changed_dynamic="${private_root}/changed-dynamic-request.json"
jq '.request.destination = "changed"' "${dynamic_request}" >"${changed_dynamic}"
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${changed_dynamic}" \
  "${url}/v1/public-regtest/sessions/${session_id}/requests")" = 409

effect_id="$(printf '33%.0s' $(seq 1 32))"
engine_session="$(printf '11%.0s' $(seq 1 32))"
order_id="$(printf '22%.0s' $(seq 1 32))"
idempotency="$(printf '44%.0s' $(seq 1 32))"
authorization="${private_root}/authorization.json"
env \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_WORKER=1 \
  "IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR=${gateway_state}" \
  "IMMORTAL_PUBLIC_REGTEST_SESSION_ID=${session_id}" \
  "IMMORTAL_PUBLIC_REGTEST_FIXTURE_REQUESTER=${requester}" \
  "IMMORTAL_PUBLIC_REGTEST_FIXTURE_PROVIDER=${provider}" \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_JOURNEY=submarine \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_METHOD=broadcast_bitcoin_funding \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_AMOUNT_SAT=100000 \
  "IMMORTAL_PUBLIC_REGTEST_FIXTURE_ENGINE_SESSION=${engine_session}" \
  "IMMORTAL_PUBLIC_REGTEST_FIXTURE_ORDER=${order_id}" \
  "IMMORTAL_PUBLIC_REGTEST_EFFECT_ID=${effect_id}" \
  "IMMORTAL_PUBLIC_REGTEST_FIXTURE_IDEMPOTENCY_DIGEST=${idempotency}" \
  target/debug/immortal-lab public-regtest-bind-fixture >"${authorization}"

manifest="${private_root}/manifest.json"
curl --fail --silent --show-error \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  "${url}/v1/public-regtest/sessions/${session_id}" >"${manifest}"
if grep -F "${dynamic_destination}" "${manifest}" >/dev/null; then
  echo "test-public-regtest-gateway: private dynamic destination reached signed manifest" >&2
  exit 1
fi
jq -e --arg provider "${provider}" --arg effect "${effect_id}" '
  .manifest.revoked == false and
  .manifest.dynamic_request == null and
  .manifest.journey == null and
  (.manifest.providers | index($provider)) != null and
  .manifest.effects == [{
    provider_pubkey:$provider,
    network:"bip122:0f9188f13cb7b2c9e5c72a6b65eeada4",
    session_id:"1111111111111111111111111111111111111111111111111111111111111111",
    order_id:"2222222222222222222222222222222222222222222222222222222222222222",
    effect_id:$effect,
    idempotency_digest:"4444444444444444444444444444444444444444444444444444444444444444",
    method:"broadcast_bitcoin_funding",
    amount_sat:100000,
    state:"authorized",
    receipt:null
  }] and
  (.signature_event.content | fromjson) == .manifest
' "${manifest}" >/dev/null
python3 - "${manifest}" root <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
canonical = json.dumps(value["manifest"], sort_keys=True, separators=(",", ":"))
if value["signature_event"]["content"] != canonical:
    raise SystemExit("refreshed manifest content is not canonical JSON")
PY

submission="${private_root}/submission.json"
jq -c '{schema:"openagents.immortal.public-regtest-effect.v1",sandbox_session_id,provider_pubkey,effect}' \
  "${authorization}" >"${submission}"

# Prove admission survives gateway replacement before the worker receipt.
first_response="${private_root}/first-response.json"
curl --silent --show-error --output "${first_response}" \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${submission}" \
  "${url}/v1/public-regtest/sessions/${session_id}/effects" 2>/dev/null &
first_curl=$!
for _ in $(seq 1 100); do
  test -s "${gateway_state}/sessions/${session_id}/admission-${effect_id}.json" && break
  sleep 0.05
done
test -s "${gateway_state}/sessions/${session_id}/admission-${effect_id}.json"
stop_gateway
wait "${first_curl}" >/dev/null 2>&1 || true

env \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_WORKER=1 \
  "IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR=${gateway_state}" \
  "IMMORTAL_PUBLIC_REGTEST_SESSION_ID=${session_id}" \
  "IMMORTAL_PUBLIC_REGTEST_EFFECT_ID=${effect_id}" \
  target/debug/immortal-lab public-regtest-worker-once >"${private_root}/worker.json"
env \
  IMMORTAL_PUBLIC_REGTEST_FIXTURE_WORKER=1 \
  "IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR=${gateway_state}" \
  "IMMORTAL_PUBLIC_REGTEST_SESSION_ID=${session_id}" \
  "IMMORTAL_PUBLIC_REGTEST_EFFECT_ID=${effect_id}" \
  target/debug/immortal-lab public-regtest-worker-once >"${private_root}/worker-replay.json"
cmp -s "${private_root}/worker.json" "${private_root}/worker-replay.json"
# Simulate a process dying while it owned a session lock. The single bound
# replacement gateway waits for a live owner, then recovers the stale marker.
mkdir "${gateway_state}/locks/${session_id}"
start_gateway

receipt="${private_root}/receipt.json"
curl --fail --silent --show-error \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${submission}" \
  "${url}/v1/public-regtest/sessions/${session_id}/effects" >"${receipt}"
jq -e --arg session "${session_id}" --arg effect "${effect_id}" '
  .schema == "openagents.immortal.public-regtest-effect-receipt.v1" and
  .sandbox_session_id == $session and .effect_id == $effect and .state == "admitted"
' "${receipt}" >/dev/null

# Two concurrent exact replays serialize and return identical prior bytes.
replay_processes=()
for number in 1 2; do
  curl --fail --silent --show-error \
    --header "Origin: ${origin}" \
    --header "X-Immortal-Client-IP: ${client_ip}" \
    --header "Authorization: ImmortalRegtest ${capability}" \
    --header 'Content-Type: application/json' \
    --data-binary "@${submission}" \
    "${url}/v1/public-regtest/sessions/${session_id}/effects" \
    >"${private_root}/replay-${number}.json" &
  replay_processes+=("$!")
done
for replay_process in "${replay_processes[@]}"; do wait "${replay_process}"; done
cmp -s "${receipt}" "${private_root}/replay-1.json"
cmp -s "${receipt}" "${private_root}/replay-2.json"

foreign_ip_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header 'X-Immortal-Client-IP: 198.51.100.11' \
  --header "Authorization: ImmortalRegtest ${capability}" \
  "${url}/v1/public-regtest/sessions/${session_id}")"
test "${foreign_ip_status}" = 403
foreign_origin_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header 'Origin: https://attacker.example' \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  "${url}/v1/public-regtest/sessions/${session_id}")"
test "${foreign_origin_status}" = 403

changed="${private_root}/changed.json"
jq '.provider_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "${submission}" >"${changed}"
changed_status="$(curl --silent --output "${private_root}/changed-response.json" --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${changed}" \
  "${url}/v1/public-regtest/sessions/${session_id}/effects")"
test "${changed_status}" = 409

wrong_network="${private_root}/wrong-network.json"
jq '.effect.network = "mainnet"' "${submission}" >"${wrong_network}"
wrong_network_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${wrong_network}" \
  "${url}/v1/public-regtest/sessions/${session_id}/effects")"
test "${wrong_network_status}" = 400

credential_field="${private_root}/credential-field.json"
jq '.effect.invoice = "lnbcrt-forbidden-at-public-boundary"' "${submission}" \
  >"${credential_field}"
credential_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${credential_field}" \
  "${url}/v1/public-regtest/sessions/${session_id}/effects")"
test "${credential_status}" = 400

duplicate_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header 'Content-Type: application/json' \
  --data-binary '{"schema":"openagents.immortal.public-regtest-session-create.v1","schema":"changed","requester_identity":"6666666666666666666666666666666666666666666666666666666666666666","client_nonce":"8888888888888888888888888888888888888888888888888888888888888888"}' \
  "${url}/v1/public-regtest/sessions")"
test "${duplicate_status}" = 400

rate_ip="198.51.100.99"
for number in $(seq 1 8); do
  rate_nonce="$(printf '%064x' "${number}")"
  jq -cn --arg requester "${requester}" --arg nonce "${rate_nonce}" \
    '{schema:"openagents.immortal.public-regtest-session-create.v1",requester_identity:$requester,client_nonce:$nonce}' \
    >"${private_root}/rate-create.json"
  rate_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --header "Origin: ${origin}" \
    --header "X-Immortal-Client-IP: ${rate_ip}" \
    --header 'Content-Type: application/json' \
    --data-binary "@${private_root}/rate-create.json" \
    "${url}/v1/public-regtest/sessions")"
  test "${rate_status}" = 201
done
rate_status="$(curl --silent --output "${private_root}/rate-response.json" --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${rate_ip}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${private_root}/rate-create.json" \
  "${url}/v1/public-regtest/sessions")"
test "${rate_status}" = 429
jq -e '.code == "rate_limited" and .retryable == true and (.retry_after_seconds >= 1)' \
  "${private_root}/rate-response.json" >/dev/null

revoke_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request DELETE \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  "${url}/v1/public-regtest/sessions/${session_id}")"
test "${revoke_status}" = 200
revoked_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Origin: ${origin}" \
  --header "X-Immortal-Client-IP: ${client_ip}" \
  --header "Authorization: ImmortalRegtest ${capability}" \
  "${url}/v1/public-regtest/sessions/${session_id}")"
test "${revoked_status}" = 410

if grep -Eiq '"(raw_transaction|invoice|preimage|wallet_seed|rpc_password|macaroon)"[[:space:]]*:' \
  "${gateway_log}" "${manifest}" "${receipt}"; then
  echo "test-public-regtest-gateway: public output crossed the custody boundary" >&2
  exit 1
fi
if grep -F "${capability}" "${gateway_log}" >/dev/null; then
  echo "test-public-regtest-gateway: raw capability reached the audit log" >&2
  exit 1
fi
grep -F '"capability_digest":"' "${gateway_log}" >/dev/null

echo "test-public-regtest-gateway: capability, origin/IP, replacement, replay, conflict, and custody gates passed"
