#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

scripts=(
  scripts/lab-bitcoind.sh
  scripts/lab-cln.sh
  scripts/lab-extensions.sh
  scripts/lab-topology.sh
)
manifest="tests/fixtures/lab/provisioning-v1.json"

for script in "${scripts[@]}"; do
  bash -n "${script}"
done
if command -v shellcheck >/dev/null; then
  shellcheck "${scripts[@]}"
fi

jq -e '
  . as $root |
  .schema == "openagents.immortal.lab-provisioning-manifest.v1" and
  .loopback_only == true and
  (.bitcoin.helpers | index("rbf-send") != null) and
  (.bitcoin.helpers | index("rbf-replace") != null) and
  (.products.relays | length) == 2 and
  (.products.providers | length) == 2 and
  (all(.products.providers[]; .relay as $relay | ([$root.products.relays[].id] | index($relay)) != null)) and
  (all(.products.providers[]; .lightning_node as $node | ([$root.lightning.nodes[].id] | index($node)) != null)) and
  (all(.products.providers[]; .eligible_lightning_rails == ["cln", "lnd"])) and
  (all(.products.wallet_harness.relays[]; . as $relay | ([$root.products.relays[].id] | index($relay)) != null)) and
  (.lightning.nodes | length) == 3 and
  .lightning.container_image == "immortal-lab-cln-hold:v0.3.3-cln-v26.06.6" and
  .lightning.container_build_source == "scripts/support/provider-funded/Dockerfile.cln-hold" and
  ([.lightning.nodes[].p2p_port] | unique | length) == 3 and
  ([.lightning.nodes[] | select(.hold_plugin == "required-and-probed")] | length) == 2 and
  ([.lightning.hold_rpc_commands[]] == ["holdinvoice", "listholdinvoices", "settleholdinvoice", "cancelholdinvoice"]) and
  (.lightning.balanced_channels | length) == 3 and
  ([.provider_rail_variants[].id] == ["lnd"]) and
  ([.provider_rail_variants[].issue] == [29]) and
  ([.provider_rail_variants[].state] == ["implemented-feature-gated"]) and
  ([.provider_rail_variants[].cargo_feature] == ["lnd"]) and
  ([.provider_rail_variants[].native_hold_invoices] == [true]) and
  ([.provider_rail_variants[].provider_slot_eligible] == [true]) and
  ([.provider_rail_variants[].clean_host_evidence] == [false]) and
  ([.provider_rail_variants[].live_deployment_evidence] == [false]) and
  ([.provider_rail_variants[].image] == ["lightninglabs/lnd:v0.20.1-beta@sha256:f0a2bdc4b8bc89cb3b31b6e12d6b16ac5145defd916d8152cf0c1c07d8697cff"]) and
  ([.provider_rail_variants[].process_gate] == ["IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd scripts/test-provider-funded.sh"]) and
  ([.extensions[].id] == ["elementsd", "arkd"]) and
  ([.extensions[].issue] == [27, 20]) and
  ([.extensions[].hook_environment] == ["IMMORTAL_LAB_ELEMENTSD_HOOK", "IMMORTAL_LAB_ARKD_HOOK"]) and
  .custody_boundary.manifest_contains_credentials == false and
  .custody_boundary.extension_hook_receives_credentials == false and
  .teardown.ownership_markers_required == true and
  .teardown.container_identity_match_required == true
  and .teardown.created_image_identity_match_required == true
' "${manifest}" >/dev/null

scripts/lab-bitcoind.sh help | grep -q 'rbf-replace'
scripts/lab-cln.sh help | grep -q 'wallet (3)'
scripts/lab-extensions.sh manifest elementsd | jq -e '.issue == 27 and .state == "hook-only"' >/dev/null
test -f "$(jq -r '.lightning.container_build_source' "${manifest}")"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/immortal-lab-provisioning-test.XXXXXX")"
cleanup() {
  rm -rf "${test_dir}"
}
trap cleanup EXIT INT TERM

IMMORTAL_LAB_DIR="${test_dir}/lab" \
  IMMORTAL_LAB_STATE_DIR="${test_dir}/wallet" \
  scripts/lab-topology.sh >"${test_dir}/topology"
grep -q 'provider-a CLN' "${test_dir}/topology"
grep -q 'provider-b CLN' "${test_dir}/topology"
grep -q 'wallet CLN' "${test_dir}/topology"
grep -q 'LND (#29)' "${test_dir}/topology"
grep -q 'elementsd (#27)' "${test_dir}/topology"
grep -q 'arkd (#20)' "${test_dir}/topology"

set +e
IMMORTAL_LAB_DIR="${test_dir}/lab" scripts/lab-extensions.sh up arkd >"${test_dir}/absent-hook" 2>&1
absent_hook_status="$?"
set -e
test "${absent_hook_status}" -eq 2
test ! -e "${test_dir}/lab/extensions/arkd"

mkdir -p "${test_dir}/lab/extensions/arkd"
touch "${test_dir}/lab/extensions/arkd/unowned"
set +e
IMMORTAL_LAB_DIR="${test_dir}/lab" scripts/lab-extensions.sh down arkd >"${test_dir}/unowned-down" 2>&1
unowned_down_status="$?"
set -e
test "${unowned_down_status}" -eq 1
test -f "${test_dir}/lab/extensions/arkd/unowned"

hook="${test_dir}/extension-hook"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'test "${IMMORTAL_LAB_EXTENSION_ID}" = elementsd' \
  'test "${IMMORTAL_LAB_EXTENSION_ISSUE}" = 27' \
  'test -n "${IMMORTAL_LAB_EXTENSION_RUN_ID}"' \
  'printf "%s" "${IMMORTAL_LAB_EXTENSION_PORTS_JSON}" | jq -e ".rpc == 18884" >/dev/null' \
  'case "$1" in' \
  'up) touch "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/hook-owned" ;;' \
  'status) test -f "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/hook-owned"; echo hook-active ;;' \
  'down) rm "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/hook-owned" ;;' \
  '*) exit 1 ;;' \
  'esac' >"${hook}"
chmod 700 "${hook}"

IMMORTAL_LAB_DIR="${test_dir}/lab" IMMORTAL_LAB_ELEMENTSD_HOOK="${hook}" \
  scripts/lab-extensions.sh up elementsd >/dev/null
IMMORTAL_LAB_DIR="${test_dir}/lab" IMMORTAL_LAB_ELEMENTSD_HOOK="${hook}" \
  scripts/lab-extensions.sh status elementsd | grep -q hook-active
IMMORTAL_LAB_DIR="${test_dir}/lab" IMMORTAL_LAB_ELEMENTSD_HOOK="${hook}" \
  scripts/lab-extensions.sh down elementsd >/dev/null
test ! -e "${test_dir}/lab/extensions/elementsd"

echo "test-lab-provisioning: static manifest and extension ownership checks passed"
