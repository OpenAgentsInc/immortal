#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

runner="scripts/public-regtest-topology.sh"
fixture="tests/fixtures/lab/public-regtest-topology-v1.json"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/immortal-public-regtest-static.XXXXXX")"
rmdir "${state_dir}"

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test -e "${state_dir}"; then
    python3 - "${state_dir}" "$(pwd -P)" <<'PY'
import json, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
marker = root / "ownership.json"
if (
    root.name.startswith("immortal-public-regtest-static.")
    and marker.is_file()
    and json.loads(marker.read_text(encoding="utf-8")).get("repository") == sys.argv[2]
):
    shutil.rmtree(root)
else:
    raise SystemExit("test cleanup lost its owned boundary")
PY
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

bash -n "${runner}"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "${runner}"
fi

jq -e '
  .schema == "openagents.immortal.public-regtest-topology.v1" and
  .issue == 41 and
  .network == "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4" and
  .topology.bitcoin_nodes == ["provider-a", "provider-b"] and
  .topology.bitcoin_nodes_peered == true and
  .topology.lightning_nodes == ["provider-a", "provider-b", "requester"] and
  (.topology.lightning_edges | length) == 3 and
  .topology.providers == ["provider-a", "provider-b"] and
  .topology.provider_databases == 2 and
  .topology.relays == ["relay-a", "relay-b"] and
  .topology.relay_databases == 2 and
  .topology.operator_independent_relay_issue == 31 and
  (.persistence.named_volumes | length) == 9 and
  .persistence.secret_state_mode == "0700" and
  .persistence.secret_file_mode == "0600" and
  .persistence.owned_reset_required == true and
  .exposure.public_protocols == ["https", "wss"] and
  .exposure.plain_relay_bind == "numeric_ipv4_loopback" and
  .exposure.public_rpc == false and
  .exposure.public_postgres == false and
  .readiness.same_bitcoin_tip == true and
  .readiness.required_lightning_channels_per_node == 2 and
  .claims.persistent_multi_node_regtest_profile == true and
  .claims.public_effect_gateway == false and
  .claims.public_browser_session == false and
  .claims.operator_independence == false and
  .claims.mainnet == false
' "${fixture}" >/dev/null

IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${state_dir}" \
IMMORTAL_PUBLIC_REGTEST_RELAY_A_URL=wss://relay-a.regtest.example \
IMMORTAL_PUBLIC_REGTEST_RELAY_B_URL=wss://relay-b.regtest.example \
  "${runner}" init >/dev/null

IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${state_dir}" "${runner}" contract | cmp - "${fixture}"
IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${state_dir}" "${runner}" config >/dev/null

python3 - "${state_dir}" <<'PY'
import json, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
if stat.S_IMODE(root.stat().st_mode) != 0o700:
    raise SystemExit("private state directory mode changed")
files = list(root.glob("*"))
if not files:
    raise SystemExit("private state is empty")
for path in files:
    if path.is_file() and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit(f"private file mode changed: {path.name}")
owner = json.loads((root / "ownership.json").read_text(encoding="utf-8"))
if owner.get("schema") != "openagents.immortal.public-regtest-owner.v1":
    raise SystemExit("ownership marker changed")
if owner.get("relay_urls") != [
    "wss://relay-a.regtest.example", "wss://relay-b.regtest.example"
]:
    raise SystemExit("public relay pins changed")
wallet_environment = (root / "wallet-driver.env").read_text(encoding="utf-8")
if "IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_AUTH_URLS=wss://relay-a.regtest.example,wss://relay-b.regtest.example\n" not in wallet_environment:
    raise SystemExit("wallet driver does not authenticate against the public relay authorities")
PY

grep -Fq 'provider_utxo_target=8' "${runner}"
grep -Fq 'sendtoaddress "${address}" 0.1' "${runner}"
grep -A3 'if test -f "${manifest}"' "${runner}" | grep -Fq 'bootstrap'

rendered="$(
  IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${state_dir}" \
  IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR="${state_dir}/gateway" \
    docker compose \
      --env-file "${state_dir}/compose.env" \
      --file scripts/support/provider-funded/adversarial-compose.yaml \
      --file deploy/public-regtest/compose.yaml \
      --project-name "$(jq -r .compose_project "${state_dir}/ownership.json")" \
      config --format json
)"
python3 - "${rendered}" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
services = value["services"]
required = {
    "bitcoin-a", "bitcoin-b", "relay-a", "relay-b", "provider-a", "provider-b",
    "cln-provider-a", "cln-provider-b", "cln-wallet", "wallet-gateway",
    "bitcoin-a-rpc-forwarder", "bitcoin-b-rpc-forwarder",
    "relay-a-public", "relay-b-public",
    "relay-a-postgres", "relay-b-postgres", "provider-a-postgres", "provider-b-postgres",
}
if not required.issubset(services):
    raise SystemExit("persistent Compose profile lacks required services")
published = []
for service in services.values():
    for port in service.get("ports", []):
        published.append((port.get("host_ip"), int(port.get("target", 0))))
if sorted(published) != [("127.0.0.1", 18080), ("127.0.0.1", 18081)]:
    raise SystemExit(f"public port allowlist changed: {published}")
if value.get("networks", {}).get("adversarial", {}).get("internal") is not True:
    raise SystemExit("rail network is no longer internal")
if value.get("networks", {}).get("public-edge", {}).get("internal") is True:
    raise SystemExit("public edge network unexpectedly became internal")
for name, service in services.items():
    if "public-edge" in service.get("networks", {}) and name not in {
        "relay-a-public", "relay-b-public"
    }:
        raise SystemExit(f"private service entered public edge network: {name}")
PY

invalid_state="${state_dir}.invalid"
if IMMORTAL_PUBLIC_REGTEST_STATE_DIR="${invalid_state}" \
  IMMORTAL_PUBLIC_REGTEST_RELAY_A_URL=ws://relay-a.regtest.example \
  IMMORTAL_PUBLIC_REGTEST_RELAY_B_URL=wss://relay-b.regtest.example \
  "${runner}" init >/dev/null 2>&1; then
  echo "test-public-regtest-topology: plain WebSocket relay was accepted" >&2
  exit 1
fi
test ! -e "${invalid_state}"

grep -Fq 'reset CONFIRM_PUBLIC_REGTEST_RESET' "${runner}"
grep -Fq '127.0.0.1:${IMMORTAL_PUBLIC_REGTEST_RELAY_A_PORT:-18080}:18080' \
  deploy/public-regtest/compose.yaml
grep -Fq '127.0.0.1:${IMMORTAL_PUBLIC_REGTEST_RELAY_B_PORT:-18081}:18081' \
  deploy/public-regtest/compose.yaml

echo "test-public-regtest-topology: contract, private state, Compose exposure, and refusal gates passed"
