#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/adversarial-v1.json"
mode="${1:---check}"
case "${mode}" in
  --check|--list) ;;
  *)
    echo "usage: scripts/test-lab-adversarial-manifest.sh [--check|--list]" >&2
    exit 2
    ;;
esac

python3 - "${fixture}" "${mode}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
fixture = json.loads(path.read_text(encoding="utf-8"))

if fixture.get("schema") != "openagents.immortal.adversarial-lab.v1":
    raise SystemExit("adversarial lab fixture has another schema")
if fixture.get("issue") != 18:
    raise SystemExit("adversarial lab fixture names another issue")
if fixture.get("manifest_gate") != "scripts/test-lab-adversarial-manifest.sh":
    raise SystemExit("adversarial lab fixture names another manifest gate")
if fixture.get("process_gate") != "scripts/test-lab-adversarial.sh":
    raise SystemExit("adversarial lab fixture names another process gate")

topology = fixture.get("topology", {})
expected_counts = {
    "provider_processes": 2,
    "provider_identities": 2,
    "provider_databases": 2,
    "relay_processes": 2,
    "relay_identities": 2,
    "relay_databases": 2,
    "wallet_processes": 1,
    "wallet_cln_nodes": 1,
    "provider_cln_nodes": 2,
    "provider_bitcoind_nodes": 2,
}
for key, expected in expected_counts.items():
    if topology.get(key) != expected:
        raise SystemExit(f"adversarial topology requires {key}={expected}")
if topology.get("provider_relay_sets") != {
    "provider-a": ["relay-a"],
    "provider-b": ["relay-b"],
}:
    raise SystemExit("provider relay sets are not distinct and exact")
bitcoin = topology.get("bitcoin", {})
if bitcoin != {
    "same_regtest_network": True,
    "nodes_peered": True,
    "shared_process": False,
    "shared_data_directory": False,
    "shared_rpc_credentials": False,
    "cross_provider_rpc_access": False,
}:
    raise SystemExit("provider bitcoind isolation contract changed")
lightning = topology.get("lightning", {})
if lightning != {
    "implementation": "cln",
    "hold_plugin_required": True,
    "shared_process": False,
    "shared_rpc_socket": False,
    "cross_provider_rpc_access": False,
}:
    raise SystemExit("provider Lightning isolation contract changed")

profile = fixture.get("lab_profile", {})
if profile != {
    "environment": "IMMORTAL_PROVIDER_LAB_PROFILE",
    "value": "regtest_adversarial",
    "network_gate": "regtest_only_fail_startup_elsewhere",
    "tiny_quote_expiry_seconds": 3,
    "tiny_hold_invoice_expiry_seconds": 30,
    "production_defaults_unchanged": True,
}:
    raise SystemExit("regtest-only timeout profile contract changed")

expected_ids = {
    "route-submarine-provider-a",
    "route-submarine-provider-b",
    "route-reverse-provider-a",
    "route-reverse-provider-b",
    "rank-two-cancelled-without-effect",
    "relay-a-partition",
    "relay-b-partition",
    "provider-a-crash-restart",
    "provider-b-crash-restart",
    "wallet-crash-restart",
    "replay-identical-order",
    "conflict-order-bytes",
    "stale-quote",
    "double-reservation",
    "status-gap",
    "status-fork",
    "funding-reorg",
    "claim-reorg",
    "rbf-conflict",
    "wrong-claim-key",
    "preimage-leak-rejected",
    "seed-leak-rejected",
    "macaroon-leak-rejected",
    "musig-nonce-leak-rejected",
    "submarine-provider-noncooperative-refund",
    "reverse-requester-noncooperative-provider-refund",
    "doomsday-submarine-provider-gone",
    "doomsday-reverse-coordinator-gone",
    "doomsday-keyless-esplora-broadcast",
    "musig2-submarine-provider-a",
    "musig2-submarine-provider-b",
    "musig2-abort-script-path",
    "musig2-crash-cut-recovery",
}
groups = fixture.get("scenario_groups")
if not isinstance(groups, dict) or set(groups) != {"routing", "failure_matrix", "doomsday", "cooperative"}:
    raise SystemExit("adversarial scenario groups changed")
cases = [case for group in groups.values() for case in group]
case_ids = [case.get("id") for case in cases]
if len(case_ids) != len(set(case_ids)):
    raise SystemExit("adversarial scenario IDs are not unique")
if set(case_ids) != expected_ids:
    missing = sorted(expected_ids - set(case_ids))
    extra = sorted(set(case_ids) - expected_ids)
    raise SystemExit(f"adversarial scenario closure changed: missing={missing}, extra={extra}")
if len(case_ids) > fixture.get("execution", {}).get("maximum_cases", 0):
    raise SystemExit("adversarial scenario count exceeds its bound")
for case in cases:
    if not isinstance(case.get("expected"), str) or not case["expected"]:
        raise SystemExit(f"scenario {case.get('id')} has no expected result")

doomsday = fixture.get("doomsday_contract", {})
if doomsday.get("database_or_ui_reconstruction") is not False:
    raise SystemExit("doomsday recovery permits reconstructed history")
if doomsday.get("keyless_broadcaster_accepts_signing_material") is not False:
    raise SystemExit("keyless broadcaster accepts signing material")
if "authenticated-direct-counterparty-channel" not in doomsday.get("retain_only", []):
    raise SystemExit("doomsday recovery has no direct authenticated channel")
requester_processes = doomsday.get("requester_processes", {})
if requester_processes != {
    "prepare": "persist_post_contract_recovery_state_then_exit",
    "recover": "fresh_process_restores_before_any_relay_connection",
    "shared_memory": False,
}:
    raise SystemExit("doomsday requester process cut is not closed")
if doomsday.get("direct_recovery") != {
    "wire": "bounded-nip59-gift-wraps",
    "durable_post_contract_only": True,
    "opens_rfq_or_new_session": False,
    "accepts_bare_private_events": False,
}:
    raise SystemExit("doomsday direct recovery surface is not closed")
if doomsday.get("submarine_refund") != {
    "package_mode": "presigned",
    "signer_ref": None,
    "signed_before_requester_contract": True,
    "signed_before_funding_broadcast": True,
    "broadcast_before_timeout": False,
}:
    raise SystemExit("doomsday submarine refund cut is not pre-signed")
if doomsday.get("reverse_claim") != {
    "package_mode": "wallet_sign",
    "preimage_release_requires_local_chain_and_lightning_observation": True,
}:
    raise SystemExit("doomsday reverse claim boundary changed")
if doomsday.get("keyless_process") != {
    "separate_process": True,
    "accepts_only_exact_esplora_request": True,
    "accepts_signing_material": False,
    "has_wallet_or_node_credentials": False,
    "has_custody_mounts": False,
    "maximum_request_bytes": 65536,
}:
    raise SystemExit("doomsday keyless process boundary changed")
if doomsday.get("recovery_planner_requires") != [
    "verified-local-chain-observation",
    "verified-local-lightning-observation",
    "bound-signed-records",
    "bound-exit-package",
]:
    raise SystemExit("doomsday planner does not require exact local observations")
if doomsday.get("real_regtest_terminal_proof") != [
    "exact-outpoint-spent",
    "transaction-confirmed",
    "lightning-terminal-state",
]:
    raise SystemExit("doomsday terminal proof is not bound to real rails")

claims = fixture.get("claims", {})
for forbidden in (
    "chain_swap",
    "liquid",
    "zero_confirmation",
    "live_deployment",
    "independent_operator_deployment",
    "public_replacement",
):
    if claims.get(forbidden) is not False:
        raise SystemExit(f"adversarial manifest overclaims {forbidden}")

if mode == "--list":
    for case_id in case_ids:
        print(case_id)
else:
    print(f"test-lab-adversarial-manifest: {len(case_ids)} closed-world scenarios passed")
PY

if ! grep -Fqx "while IFS=\$'\\t' read -r -u 3 case_id group expected provider; do" \
    scripts/test-lab-adversarial.sh \
  || ! grep -Fqx 'done 3<"${case_file}"' scripts/test-lab-adversarial.sh; then
  echo "test-lab-adversarial-manifest: aggregate runner does not isolate manifest input" >&2
  exit 1
fi

python3 - scripts/test-lab-adversarial.sh <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
branch = source.split("      cooperative_crash_cut)\n", 1)[1].split(
    "      provider_noncooperative)\n", 1
)[0]
if 'before_pid="$(container_pid "${external_target}")"' not in branch:
    raise SystemExit(
        "test-lab-adversarial-manifest: cooperative crash cut does not bind the replaced process"
    )
PY
