#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

scripts=(
  scripts/lab-bitcoind.sh
  scripts/lab-cln.sh
  scripts/lab-elementsd.sh
  scripts/lab-extensions.sh
  scripts/lab-topology.sh
  scripts/public-regtest-topology.sh
  scripts/test-lab-adversarial-manifest.sh
  scripts/test-public-regtest-topology.sh
  scripts/test-public-regtest-gateway.sh
  scripts/test-lab-topology-quotes.sh
  scripts/test-lab-topology-funded.sh
  scripts/test-provider-liquid.sh
  scripts/test-provider-funded.sh
)
manifest="tests/fixtures/lab/provisioning-v1.json"
topology_quote_manifest="tests/fixtures/lab/topology-quotes-v1.json"
topology_funded_manifest="tests/fixtures/lab/topology-funded-v1.json"
adversarial_manifest="tests/fixtures/lab/adversarial-v1.json"

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
  (.extensions[0].state == "repo-owned-process") and
  (.extensions[0].default_hook == "scripts/lab-elementsd.sh") and
  (.extensions[0].version == "23.3.3") and
  (.extensions[0].image_build_source == "scripts/support/provider-funded/Dockerfile.elements") and
  (.extensions[0].rail_gate == "scripts/test-provider-liquid.sh") and
  (.extensions[0].host_port_allocation == "runtime-assigned-loopback") and
  (.extensions[1].state == "hook-only") and
  .custody_boundary.manifest_contains_credentials == false and
  .custody_boundary.extension_hook_receives_credentials == false and
  .teardown.ownership_markers_required == true and
  .teardown.container_identity_match_required == true
  and .teardown.created_image_identity_match_required == true
' "${manifest}" >/dev/null

jq -e '
  .schema == "openagents.immortal.lab-topology-quotes.v1" and
  .process_gate == "scripts/test-lab-topology-quotes.sh" and
  .wallet_command == "immortal-lab topology-quotes" and
  .topology.relay_count == 2 and
  .topology.provider_count == 2 and
  .topology.cln_roles == ["provider-a", "provider-b", "wallet"] and
  .topology.distinct_provider_keys == true and
  .topology.one_provider_per_relay == true and
  .topology.wallet_discovers_every_relay == true and
  .topology.provider_mode == "no_spend" and
  .quote_comparison.candidate_count == 2 and
  .quote_comparison.required_quote_class == "firm" and
  .quote_comparison.accepted_reservation_classes == ["soft", "hard"] and
  .quote_comparison.ordering == ["output_amount_desc", "maximum_total_fee_asc", "provider_pubkey_asc", "quote_id_asc"] and
  .quote_comparison.stale_quotes_eligible == false and
  .retained_record.contains_raw_signed_events == false and
  .retained_record.contains_raw_wrap_events == false and
  .retained_record.contains_credentials == false and
  .retained_record.contains_custody_material == false and
  .claims.funded_two_provider_execution == false and
  .claims.clean_host_evidence == false and
  .claims.live_deployment_evidence == false
' "${topology_quote_manifest}" >/dev/null

jq -e '
  .schema == "openagents.immortal.lab-funded-topology.v1" and
  .process_gate == "scripts/test-lab-topology-funded.sh" and
  .wallet_command == "immortal-lab funded-topology" and
  .topology.relay_count == 2 and
  .topology.provider_count == 2 and
  .topology.provider_database_count == 2 and
  .topology.cln_roles == ["provider-a", "provider-b", "wallet"] and
  .topology.shared_bitcoind_namespace == true and
  .topology.scope == "issue_32_local_selection_cancellation_gate" and
  .topology.issue_18_requires_separate_bitcoind_namespaces == true and
  .selection.candidate_count == 2 and
  .selection.required_reservation_class == "hard" and
  .selection.orders_created_after_comparison == true and
  .unselected.external_spend_effects == 0 and
  .unselected.reservation_release_cause == "terminal_close" and
  .retained_record.contains_raw_transactions == false and
  .retained_record.contains_custody_material == false and
  .claims.local_funded_two_provider_execution == true and
  .claims.clean_host_evidence == false and
  .claims.public_replacement == false
' "${topology_funded_manifest}" >/dev/null

test "${adversarial_manifest}" = "tests/fixtures/lab/adversarial-v1.json"
scripts/test-lab-adversarial-manifest.sh --check
scripts/test-public-regtest-topology.sh
scripts/test-public-regtest-gateway.sh

scripts/lab-bitcoind.sh help | grep -q 'rbf-replace'
scripts/lab-cln.sh help | grep -q 'wallet (3)'
scripts/lab-extensions.sh manifest elementsd | jq -e '.issue == 27 and .state == "repo-owned-process"' >/dev/null
test -x scripts/lab-elementsd.sh
test -x scripts/test-provider-liquid.sh
test -f "$(jq -r '.extensions[0].image_build_source' "${manifest}")"
grep -Fqx '    --publish "127.0.0.1::${rpc_container_port}" \' scripts/lab-elementsd.sh
grep -Fqx 'wallet_seed_file="${extension_dir}/provider-wallet-seed"' \
  scripts/test-provider-liquid.sh
grep -Fqx 'printf '\''%s\n'\'' "${wallet_seed_hex}" >"${wallet_seed_file}"' \
  scripts/test-provider-liquid.sh
grep -Fqx 'chmod 600 "${wallet_seed_file}"' scripts/test-provider-liquid.sh
grep -Fqx '    IMMORTAL_LIQUID_LIVE_SEED_FILE="${wallet_seed_file}" \' \
  scripts/test-provider-liquid.sh
if grep -F 'IMMORTAL_LIQUID_LIVE_SEED="${wallet_seed_hex}"' \
  scripts/test-provider-liquid.sh >/dev/null; then
  echo "test-lab-provisioning: Liquid wallet seed entered the process environment" >&2
  exit 1
fi
test "$(grep -Fc 'live_test provider_liquid_live_unblinds_own_output' scripts/test-provider-liquid.sh)" -eq 1
test "$(grep -Fc 'live_test provider_liquid_live_funds_and_broadcasts_signed_refund' scripts/test-provider-liquid.sh)" -eq 1
grep -Fq 'gate_scope:"liquid_provider_rail_component",provider_daemon_process:false' \
  scripts/test-provider-liquid.sh
test -f "$(jq -r '.lightning.container_build_source' "${manifest}")"
grep -q 'Command::TopologyQuotes' crates/immortal-lab/src/cli.rs
grep -q 'RequesterSessionView::from_signed_records' crates/immortal-lab/src/steps.rs
grep -q 'run_funded_topology' crates/immortal-lab/src/funded.rs
grep -q 'provider-b-postgres' scripts/support/provider-funded/topology-compose.yaml
grep -q 'PREPARE funded_topology_evidence' scripts/support/provider-funded/topology_evidence.sql
grep -Fq 'container_name="immortal-dev-postgres-$PPID-$$"' scripts/dev-relay.sh
grep -Fqx 'dedicated_private_root_parent="${IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT:-}"' \
  scripts/test-provider-funded.sh
grep -Fqx 'unset IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT' scripts/test-provider-funded.sh
grep -Fqx '  --mount "type=bind,src=${private_root},dst=/run/immortal-private,readonly" \' \
  scripts/test-provider-funded.sh
grep -Fqx 'postgres_preflight_image="postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"' \
  scripts/test-provider-funded.sh
grep -Fqx '  "${private_root_parent_physical}"/*) ;;' scripts/test-provider-funded.sh
grep -Fqx '      echo "test-provider-funded: global TMPDIR must not be inside the dedicated private root parent" >&2' \
  scripts/test-provider-funded.sh
grep -Fqx 'boltz_publish_host="${IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST:-127.0.0.1}"' \
  scripts/test-provider-funded.sh
grep -Fqx '    or address.is_unspecified' scripts/test-provider-funded.sh
grep -Fqx '    or address.is_multicast' scripts/test-provider-funded.sh
grep -Fqx '    or address.is_reserved' scripts/test-provider-funded.sh
grep -Fqx '    or not (address.is_loopback or any(address in network for network in private_networks))' \
  scripts/test-provider-funded.sh
grep -Fqx 'IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST=${boltz_publish_host}' \
  scripts/test-provider-funded.sh
grep -Fqx 'boltz_provider_container_url="http://${boltz_bind_address}:19093"' \
  scripts/test-provider-funded.sh
grep -Fqx 'wait_for "Boltz provider compatibility listener inside the smoke network" \' \
  scripts/test-provider-funded.sh
grep -Fqx 'if ! boltz_published_endpoint="$(compose port bitcoin 19093)"; then' \
  scripts/test-provider-funded.sh
grep -Fqx '  "${boltz_publish_host}":*)' scripts/test-provider-funded.sh
grep -Fqx '      - "${IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST:?Boltz publish host is required}::19093"' \
  scripts/support/provider-funded/compose.yaml
grep -Fqx 'IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST=127.0.0.1' \
  scripts/test-lab-topology-funded.sh
if grep -Eq '^docker\(\)' scripts/test-provider-funded.sh; then
  echo "test-lab-provisioning: funded provider harness must not wrap docker" >&2
  exit 1
fi

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/immortal-lab-provisioning-test.XXXXXX")"
test_dir="$(CDPATH= cd -- "${test_dir}" && pwd -P)"
cleanup() {
  rm -rf "${test_dir}"
}
trap cleanup EXIT INT TERM

bash -c 'printf "%s\n" "immortal-dev-postgres-$PPID-$$"' \
  >"${test_dir}/relay-a-postgres-name" &
relay_a_name_pid=$!
bash -c 'printf "%s\n" "immortal-dev-postgres-$PPID-$$"' \
  >"${test_dir}/relay-b-postgres-name" &
relay_b_name_pid=$!
wait "${relay_a_name_pid}"
wait "${relay_b_name_pid}"
test "$(cut -d- -f1-4 "${test_dir}/relay-a-postgres-name")" = \
  "immortal-dev-postgres-$$"
test "$(cut -d- -f1-4 "${test_dir}/relay-b-postgres-name")" = \
  "immortal-dev-postgres-$$"
test "$(cat "${test_dir}/relay-a-postgres-name")" != \
  "$(cat "${test_dir}/relay-b-postgres-name")"

mock_runtime_dir="${test_dir}/mock-runtime"
mkdir -m 0700 "${mock_runtime_dir}"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\n" "$*" >>"${IMMORTAL_DEV_RELAY_MOCK_COMMAND_LOG}"' \
  'case "${1:-}" in' \
  'run)' \
  '  test "${IMMORTAL_DEV_RELAY_MOCK_CASE}" != run-failure' \
  '  printf "%s\n" created-container-id' \
  '  ;;' \
  'exec) exit 1 ;;' \
  'container)' \
  '  test "${2:-}" = inspect' \
  '  if test "${IMMORTAL_DEV_RELAY_MOCK_CASE}" = mismatch; then' \
  '    printf "%s\n" replacement-container-id' \
  '  else' \
  '    printf "%s\n" created-container-id' \
  '  fi' \
  '  ;;' \
  'rm)' \
  '  printf "%s\n" "$*" >>"${IMMORTAL_DEV_RELAY_MOCK_DELETE_LOG}"' \
  '  ;;' \
  '*) exit 1 ;;' \
  'esac' >"${mock_runtime_dir}/docker"
printf '%s\n' '#!/bin/sh' 'exit 0' >"${mock_runtime_dir}/sleep"
chmod 0700 "${mock_runtime_dir}/docker" "${mock_runtime_dir}/sleep"

run_dev_relay_cleanup_case() {
  local case_name="$1" command_log delete_log output_log exit_status
  command_log="${test_dir}/${case_name}-commands"
  delete_log="${test_dir}/${case_name}-deletes"
  output_log="${test_dir}/${case_name}-output"
  : >"${command_log}"
  : >"${delete_log}"
  set +e
  (
    unset IMMORTAL_DEV_DATABASE_URL
    PATH="${mock_runtime_dir}:/usr/bin:/bin" \
      IMMORTAL_DEV_RELAY_MOCK_CASE="${case_name}" \
      IMMORTAL_DEV_RELAY_MOCK_COMMAND_LOG="${command_log}" \
      IMMORTAL_DEV_RELAY_MOCK_DELETE_LOG="${delete_log}" \
      scripts/dev-relay.sh
  ) >"${output_log}" 2>&1
  exit_status=$?
  set -e
  test "${exit_status}" -ne 0
}

run_dev_relay_cleanup_case run-failure
test ! -s "${test_dir}/run-failure-deletes"
test "$(grep -c '^run ' "${test_dir}/run-failure-commands")" -eq 1

run_dev_relay_cleanup_case mismatch
test ! -s "${test_dir}/mismatch-deletes"
grep -Fq 'no longer matches the created container; refusing teardown' \
  "${test_dir}/mismatch-output"

run_dev_relay_cleanup_case exact-match
test "$(grep -c '^rm -f immortal-dev-postgres-' "${test_dir}/exact-match-deletes")" -eq 1

provider_mock_runtime="${test_dir}/provider-mock-runtime"
mkdir -m 0700 "${provider_mock_runtime}"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "${1:-}" in' \
  'info) exit 0 ;;' \
  'compose)' \
  '  test "${2:-}" = version' \
  '  exit 0' \
  '  ;;' \
  'run)' \
  '  test -z "${IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT:-}"' \
  '  printf "%s\n" "$*" >>"${IMMORTAL_PROVIDER_FUNDED_MOCK_COMMAND_LOG}"' \
  '  exit 1' \
  '  ;;' \
  '*) exit 1 ;;' \
  'esac' >"${provider_mock_runtime}/docker"
chmod 0700 "${provider_mock_runtime}/docker"

provider_rejected_publish_parent="${test_dir}/provider-rejected-publish-parent"
mkdir -m 0700 "${provider_rejected_publish_parent}"
for provider_publish_host in 0.0.0.0 8.8.8.8 192.0.2.1 255.255.255.255; do
  set +e
  IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT="${provider_rejected_publish_parent}" \
    IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST="${provider_publish_host}" \
    scripts/test-provider-funded.sh >"${test_dir}/provider-publish-host-${provider_publish_host}-output" 2>&1
  provider_publish_host_status=$?
  set -e
  test "${provider_publish_host_status}" -ne 0
  grep -Fq 'Boltz publish host must be a non-wildcard loopback or RFC1918 IPv4 address' \
    "${test_dir}/provider-publish-host-${provider_publish_host}-output"
done
if find "${provider_rejected_publish_parent}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "test-lab-provisioning: rejected Boltz publish host created private state" >&2
  exit 1
fi

provider_valid_publish_log="${test_dir}/provider-private-publish-host-commands"
: >"${provider_valid_publish_log}"
set +e
PATH="${provider_mock_runtime}:/usr/bin:/bin" \
  IMMORTAL_PROVIDER_FUNDED_BOLTZ_PUBLISH_HOST=192.168.65.1 \
  IMMORTAL_PROVIDER_FUNDED_MOCK_COMMAND_LOG="${provider_valid_publish_log}" \
  scripts/test-provider-funded.sh >"${test_dir}/provider-private-publish-host-output" 2>&1
provider_valid_publish_status=$?
set -e
test "${provider_valid_publish_status}" -ne 0
grep -Fq 'container runtime cannot read the private root at its exact path' \
  "${test_dir}/provider-private-publish-host-output"
grep -Fq 'run --rm --mount type=bind,src=' "${provider_valid_publish_log}"

provider_private_parent="${test_dir}/provider-private-parent"
provider_command_log="${test_dir}/provider-private-parent-commands"
provider_output_log="${test_dir}/provider-private-parent-output"
mkdir -m 0700 "${provider_private_parent}"
: >"${provider_command_log}"
set +e
PATH="${provider_mock_runtime}:/usr/bin:/bin" \
  IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT="${provider_private_parent}" \
  IMMORTAL_PROVIDER_FUNDED_MOCK_COMMAND_LOG="${provider_command_log}" \
  scripts/test-provider-funded.sh >"${provider_output_log}" 2>&1
provider_preflight_status=$?
set -e
test "${provider_preflight_status}" -ne 0
grep -Fq 'container runtime cannot read the private root at its exact path' \
  "${provider_output_log}"
test "$(wc -l <"${provider_command_log}")" -eq 1
grep -Fq -- "--mount type=bind,src=${provider_private_parent}/immortal-provider-funded." \
  "${provider_command_log}"
grep -Fq ',dst=/run/immortal-private,readonly' "${provider_command_log}"
grep -Fq 'postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193 true' \
  "${provider_command_log}"
if find "${provider_private_parent}" -mindepth 1 -maxdepth 1 -name 'immortal-provider-funded.*' -print -quit | grep -q .; then
  echo "test-lab-provisioning: failed private-root preflight retained a child" >&2
  exit 1
fi

provider_global_tmpdir="${provider_private_parent}/global-tmpdir"
mkdir -m 0700 "${provider_global_tmpdir}"
set +e
TMPDIR="${provider_global_tmpdir}" \
  IMMORTAL_PROVIDER_FUNDED_PRIVATE_ROOT_PARENT="${provider_private_parent}" \
  scripts/test-provider-funded.sh >"${test_dir}/provider-global-tmpdir-output" 2>&1
provider_global_tmpdir_status=$?
set -e
test "${provider_global_tmpdir_status}" -ne 0
grep -Fq 'global TMPDIR must not be inside the dedicated private root parent' \
  "${test_dir}/provider-global-tmpdir-output"
if find "${provider_private_parent}" -mindepth 1 -maxdepth 1 -name 'immortal-provider-funded.*' -print -quit | grep -q .; then
  echo "test-lab-provisioning: nested TMPDIR rejection retained a child" >&2
  exit 1
fi

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

rollback_hook="${test_dir}/extension-rollback-hook"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "$1" in' \
  'up) touch "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/partial"; exit 1 ;;' \
  'down) rm -f "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/partial" ;;' \
  '*) exit 1 ;;' \
  'esac' >"${rollback_hook}"
chmod 700 "${rollback_hook}"
set +e
IMMORTAL_LAB_DIR="${test_dir}/rollback-lab" IMMORTAL_LAB_ELEMENTSD_HOOK="${rollback_hook}" \
  scripts/lab-extensions.sh up elementsd >"${test_dir}/rollback-output" 2>&1
rollback_status=$?
set -e
test "${rollback_status}" -ne 0
test ! -e "${test_dir}/rollback-lab/extensions/elementsd"
grep -Fq 'partial resources were removed' "${test_dir}/rollback-output"

retry_hook="${test_dir}/extension-retry-hook"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'case "$1" in' \
  'up) touch "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/partial"; exit 1 ;;' \
  'down)' \
  '  test -f "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/allow-down"' \
  '  rm -f "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/partial" "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/allow-down"' \
  '  ;;' \
  '*) exit 1 ;;' \
  'esac' >"${retry_hook}"
chmod 700 "${retry_hook}"
set +e
IMMORTAL_LAB_DIR="${test_dir}/retry-lab" IMMORTAL_LAB_ELEMENTSD_HOOK="${retry_hook}" \
  scripts/lab-extensions.sh up elementsd >"${test_dir}/retry-output" 2>&1
retry_status=$?
set -e
test "${retry_status}" -ne 0
test -f "${test_dir}/retry-lab/extensions/elementsd/partial"
test ! -f "${test_dir}/retry-lab/extensions/elementsd/active"
grep -Fq 'retained' "${test_dir}/retry-output"
touch "${test_dir}/retry-lab/extensions/elementsd/allow-down"
IMMORTAL_LAB_DIR="${test_dir}/retry-lab" scripts/lab-extensions.sh down elementsd >/dev/null
test ! -e "${test_dir}/retry-lab/extensions/elementsd"

elements_mock_runtime="${test_dir}/elements-mock-runtime"
mkdir -m 0700 "${elements_mock_runtime}"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'state="${IMMORTAL_ELEMENTSD_MOCK_STATE:?missing mock state}"' \
  'case_name="${IMMORTAL_ELEMENTSD_MOCK_CASE:-success}"' \
  'image="${state}/image"' \
  'container="${state}/container"' \
  'case "${1:-}" in' \
  'build)' \
  '  jq -e '\''.image_id == null and .container_id == null and .rpc_host_port == null and .p2p_host_port == null'\'' "${IMMORTAL_LAB_EXTENSION_STATE_DIR}/elementsd-process.json" >/dev/null' \
  '  touch "${image}"' \
  '  ;;' \
  'image)' \
  '  case "${2:-}" in' \
  '  inspect)' \
  '    if ! test -f "${image}"; then echo "No such image" >&2; exit 1; fi' \
  '    if test "${3:-}" = --format; then' \
  '      case "${4:-}" in' \
  '      *".Id"*) printf '\''%s\n'\'' mock-image-id ;;' \
  '      *"Config.Labels"*) printf '\''%s\n'\'' "${IMMORTAL_LAB_EXTENSION_RUN_ID}" ;;' \
  '      *) exit 1 ;;' \
  '      esac' \
  '    else' \
  '      printf '\''%s\n'\'' '\''[{}]'\''' \
  '    fi' \
  '    ;;' \
  '  rm)' \
  '    test -f "${image}"' \
  '    if test "${case_name}" = image-remove-once && ! test -f "${state}/image-remove-failed"; then' \
  '      touch "${state}/image-remove-failed"' \
  '      exit 1' \
  '    fi' \
  '    rm "${image}"' \
  '    ;;' \
  '  *) exit 1 ;;' \
  '  esac' \
  '  ;;' \
  'run)' \
  '  test -f "${image}"' \
  '  printf '\''%s\n'\'' "$*" | grep -F -- '\''--publish 127.0.0.1::18884'\'' >/dev/null' \
  '  printf '\''%s\n'\'' "$*" | grep -F -- '\''--publish 127.0.0.1::18886'\'' >/dev/null' \
  '  touch "${container}"' \
  '  if test "${case_name}" = run-created-failure; then exit 1; fi' \
  '  printf '\''%s\n'\'' mock-container-id' \
  '  ;;' \
  'container)' \
  '  test "${2:-}" = inspect' \
  '  if ! test -f "${container}"; then echo "No such container" >&2; exit 1; fi' \
  '  if test "${3:-}" = --format; then' \
  '    case "${4:-}" in' \
  '    *".Id"*) printf '\''%s\n'\'' mock-container-id ;;' \
  '    *"Config.Labels"*) printf '\''%s\n'\'' "${IMMORTAL_LAB_EXTENSION_RUN_ID}" ;;' \
  '    *"State.Running"*) printf '\''%s\n'\'' true ;;' \
  '    *) exit 1 ;;' \
  '    esac' \
  '  else' \
  '    printf '\''%s\n'\'' '\''[{"NetworkSettings":{"Ports":{"18884/tcp":[{"HostIp":"127.0.0.1","HostPort":"38184"}],"18886/tcp":[{"HostIp":"127.0.0.1","HostPort":"38186"}]}}}]'\''' \
  '  fi' \
  '  ;;' \
  'exec)' \
  '  case "$*" in' \
  '  *getblockchaininfo*) printf '\''%s\n'\'' '\''{}'\'' ;;' \
  '  *"createwallet wallet_name=provider-liquid"*) printf '\''%s\n'\'' '\''{"name":"provider-liquid"}'\'' ;;' \
  '  *"createwallet wallet_name=initial-free-coins"*) printf '\''%s\n'\'' '\''{"name":"initial-free-coins"}'\'' ;;' \
  '  *importdescriptors*) printf '\''%s\n'\'' '\''[{"success":true}]'\'' ;;' \
  '  *walletcreatefundedpsbt*) printf '\''%s\n'\'' '\''{"psbt":"mock-psbt"}'\'' ;;' \
  '  *finalizepsbt*) printf '\''%s\n'\'' '\''{"complete":true,"hex":"00"}'\'' ;;' \
  '  *sendrawtransaction*) printf '\''%064d\n'\'' 2 ;;' \
  '  *getnewaddress*) printf '\''%s\n'\'' ert1qqmock ;;' \
  '  *generatetoaddress*) printf '\''%s\n'\'' '\''[]'\'' ;;' \
  '  *getbalances*) printf '\''%s\n'\'' '\''{"mine":{"trusted":{"bitcoin":1001}}}'\'' ;;' \
  '  *"getblockhash 0"*) printf '\''%064d\n'\'' 0 ;;' \
  '  *getsidechaininfo*) printf '\''{"pegged_asset":"%064d"}\n'\'' 1 ;;' \
  '  *) exit 1 ;;' \
  '  esac' \
  '  ;;' \
  'rm)' \
  '  test "${2:-}" = --force' \
  '  test -f "${container}"' \
  '  rm "${container}"' \
  '  ;;' \
  '*) exit 1 ;;' \
  'esac' >"${elements_mock_runtime}/docker"
chmod 700 "${elements_mock_runtime}/docker"

elements_failure_state="${test_dir}/elements-failure-state"
mkdir -m 0700 "${elements_failure_state}"
set +e
PATH="${elements_mock_runtime}:${PATH}" \
  IMMORTAL_ELEMENTSD_MOCK_STATE="${elements_failure_state}" \
  IMMORTAL_ELEMENTSD_MOCK_CASE=run-created-failure \
  IMMORTAL_LAB_DIR="${test_dir}/elements-failure-lab" \
  scripts/lab-extensions.sh up elementsd >"${test_dir}/elements-failure-output" 2>&1
elements_failure_status=$?
set -e
test "${elements_failure_status}" -ne 0
test ! -e "${elements_failure_state}/container"
test ! -e "${elements_failure_state}/image"
test ! -e "${test_dir}/elements-failure-lab/extensions/elementsd"

elements_retry_state="${test_dir}/elements-retry-state"
mkdir -m 0700 "${elements_retry_state}"
PATH="${elements_mock_runtime}:${PATH}" \
  IMMORTAL_ELEMENTSD_MOCK_STATE="${elements_retry_state}" \
  IMMORTAL_ELEMENTSD_MOCK_CASE=image-remove-once \
  IMMORTAL_LAB_DIR="${test_dir}/elements-retry-lab" \
  scripts/lab-extensions.sh up elementsd >/dev/null
jq -e '.rpc_host_port == 38184 and .p2p_host_port == 38186' \
  "${test_dir}/elements-retry-lab/extensions/elementsd/elementsd-process.json" >/dev/null
set +e
PATH="${elements_mock_runtime}:${PATH}" \
  IMMORTAL_ELEMENTSD_MOCK_STATE="${elements_retry_state}" \
  IMMORTAL_ELEMENTSD_MOCK_CASE=image-remove-once \
  IMMORTAL_LAB_DIR="${test_dir}/elements-retry-lab" \
  scripts/lab-extensions.sh down elementsd >"${test_dir}/elements-retry-down-output" 2>&1
elements_retry_down_status=$?
set -e
test "${elements_retry_down_status}" -ne 0
test ! -e "${elements_retry_state}/container"
test -e "${elements_retry_state}/image"
test -e "${test_dir}/elements-retry-lab/extensions/elementsd"
PATH="${elements_mock_runtime}:${PATH}" \
  IMMORTAL_ELEMENTSD_MOCK_STATE="${elements_retry_state}" \
  IMMORTAL_ELEMENTSD_MOCK_CASE=image-remove-once \
  IMMORTAL_LAB_DIR="${test_dir}/elements-retry-lab" \
  scripts/lab-extensions.sh down elementsd >/dev/null
test ! -e "${elements_retry_state}/image"
test ! -e "${test_dir}/elements-retry-lab/extensions/elementsd"

echo "test-lab-provisioning: static manifest and extension ownership checks passed"
