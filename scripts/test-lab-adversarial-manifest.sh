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
    "provider_elementsd_nodes": 2,
    "wallet_elementsd_nodes": 1,
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
liquid = topology.get("liquid", {})
liquid_case_ids = [
    "route-chain-btc-to-lbtc-provider-a",
    "route-chain-btc-to-lbtc-provider-b",
    "route-chain-lbtc-to-btc-provider-a",
    "route-chain-lbtc-to-btc-provider-b",
    "route-liquid-submarine-provider-a",
    "route-liquid-submarine-provider-b",
    "route-liquid-reverse-provider-a",
    "route-liquid-reverse-provider-b",
    "doomsday-liquid-submarine-provider-gone",
    "doomsday-liquid-reverse-coordinator-gone",
]
if liquid != {
    "implementation": "elementsd",
    "network": "elementsregtest",
    "node_count": 3,
    "provider_nodes": 2,
    "wallet_nodes": 1,
    "nodes_peered": True,
    "shared_process": False,
    "shared_data_directory": False,
    "shared_rpc_credentials": False,
    "cross_provider_rpc_access": False,
    "confidential_scope": "own-output-unblinding",
    "enabled_only_for_cases": liquid_case_ids,
}:
    raise SystemExit("Liquid three-node isolation contract changed")
ark = topology.get("ark", {})
if ark != {
    "implementation": "arkade",
    "network": "regtest",
    "operator_processes": 1,
    "operator_wallet_processes": 1,
    "operator_indexer_processes": 1,
    "source_revision": "8b34e352859595cc03ba22ffa35088ab88b87fd9",
    "client_revision": "dfa1af44274bae97bd184b499d7697ea5f5e4cd3",
    "keyless_executor_revision": "d9c949d3be7cc6eaab7551bc52cc502b90647b2d",
    "regtest_revision": "15354f994dbba032f856e9a8e02f33b69b8c0e8a",
    "enabled_only_for_cases": ["doomsday-ark-operator-gone"],
    "process_gate": "scripts/test-ark-operator-removal.sh",
}:
    raise SystemExit("Ark external-process topology contract changed")

profile = fixture.get("lab_profile", {})
if profile != {
    "environment": "IMMORTAL_PROVIDER_LAB_PROFILE",
    "value": "regtest_adversarial",
    "network_gate": "regtest_only_fail_startup_elsewhere",
    "tiny_quote_expiry_seconds": 3,
    "tiny_hold_invoice_expiry_seconds": 30,
    "production_defaults_unchanged": True,
    "pricing": {
        "source": "configured_fallback_only",
        "sat_per_vbyte": 2,
        "spread_bps": 100,
        "lightning_routing_fee_ppm": 2900,
        "min_swap_sat": 10000,
        "max_swap_sat": 1000000,
        "liquid_submarine_invoice_amount_sat": 98110,
    },
}:
    raise SystemExit("regtest-only timeout profile contract changed")

expected_ids = {
    "route-submarine-provider-a",
    "route-submarine-provider-b",
    "route-reverse-provider-a",
    "route-reverse-provider-b",
    "route-chain-btc-to-lbtc-provider-a",
    "route-chain-btc-to-lbtc-provider-b",
    "route-chain-lbtc-to-btc-provider-a",
    "route-chain-lbtc-to-btc-provider-b",
    "route-liquid-submarine-provider-a",
    "route-liquid-submarine-provider-b",
    "route-liquid-reverse-provider-a",
    "route-liquid-reverse-provider-b",
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
    "zero-conf-rbf-replacement",
    "zero-conf-double-spend-race",
    "zero-conf-ancestor-eviction",
    "wrong-claim-key",
    "preimage-leak-rejected",
    "seed-leak-rejected",
    "macaroon-leak-rejected",
    "musig-nonce-leak-rejected",
    "submarine-provider-noncooperative-refund",
    "reverse-requester-noncooperative-provider-refund",
    "doomsday-submarine-provider-gone",
    "doomsday-reverse-coordinator-gone",
    "doomsday-liquid-submarine-provider-gone",
    "doomsday-liquid-reverse-coordinator-gone",
    "doomsday-keyless-esplora-broadcast",
    "doomsday-ark-operator-gone",
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
if fixture.get("execution", {}).get("maximum_cases") != 48:
    raise SystemExit("adversarial scenario maximum is not 48")
if len(case_ids) != 47:
    raise SystemExit("adversarial scenario closure is not the exact 47-case matrix")
if [case["id"] for case in groups["routing"] if case["id"] in liquid_case_ids] != liquid_case_ids[:8]:
    raise SystemExit("Liquid routing cases are not the exact ordered extension")
if [case["id"] for case in groups["doomsday"] if case["id"] in liquid_case_ids] != liquid_case_ids[8:]:
    raise SystemExit("Liquid doomsday cases are not the exact ordered extension")
for case in cases:
    if not isinstance(case.get("expected"), str) or not case["expected"]:
        raise SystemExit(f"scenario {case.get('id')} has no expected result")

evidence = fixture.get("evidence", {})
for view in (
    "elementsd-provider-a",
    "elementsd-provider-b",
    "elementsd-wallet",
    "ark-participant",
    "bitcoin-esplora",
):
    if view not in evidence.get("independent_views", []):
        raise SystemExit(f"adversarial evidence omits independent view {view}")
for check in (
    "liquid-raw-transaction-and-id",
    "liquid-outpoint-spend-lineage",
    "liquid-provider-restart-exact-known-replay",
    "ark-received-vtxo-id-and-amount",
    "ark-exit-package-digest-and-step-order",
    "ark-operator-indexer-wallet-removal",
    "ark-final-participant-bitcoin-output",
):
    if check not in evidence.get("required_checks", []):
        raise SystemExit(f"adversarial evidence omits required check {check}")
def liquid_case(
    shape,
    selected_provider,
    rails,
    provider_effect_operations,
    provider_status_anchors,
    provider_restart_required,
    liquid_terminal_actor,
    liquid_terminal_path,
    recovery,
):
    if shape.startswith("chain-"):
        lightning_terminal = None
    elif recovery == "presigned-refund":
        lightning_terminal = {
            "actor": "requester",
            "effect_actor": None,
            "operation": None,
            "status_anchor": None,
            "state": "unpaid_final",
            "observation_authority": "requester-cln",
        }
    elif shape == "liquid-submarine":
        lightning_terminal = {
            "actor": "requester",
            "effect_actor": "provider",
            "operation": "invoice_pay",
            "status_anchor": "lightning_paid",
            "state": "settled",
            "observation_authority": "requester-cln",
        }
    else:
        lightning_terminal = {
            "actor": "requester",
            "effect_actor": "provider",
            "operation": "invoice_settle",
            "status_anchor": "lightning_paid",
            "state": "settled",
            "observation_authority": "requester-cln",
        }
    return {
        "shape": shape,
        "selected_provider": selected_provider,
        "rails": rails,
        "provider_effect_operations": provider_effect_operations,
        "provider_status_anchors": provider_status_anchors,
        "lightning_terminal": lightning_terminal,
        "provider_restart_required": provider_restart_required,
        "liquid_terminal_actor": liquid_terminal_actor,
        "liquid_terminal_path": liquid_terminal_path,
        "recovery": recovery,
    }

expected_liquid_cases = {
    "route-chain-btc-to-lbtc-provider-a": liquid_case(
        "chain-btc-to-lbtc", "provider-a", ["bitcoin", "liquid"],
        ["liquid_chain_fund", "chain_claim"], ["provider_destination_broadcast"],
        True, "requester", "claim", None,
    ),
    "route-chain-btc-to-lbtc-provider-b": liquid_case(
        "chain-btc-to-lbtc", "provider-b", ["bitcoin", "liquid"],
        ["liquid_chain_fund", "chain_claim"], ["provider_destination_broadcast"],
        True, "requester", "claim", None,
    ),
    "route-chain-lbtc-to-btc-provider-a": liquid_case(
        "chain-lbtc-to-btc", "provider-a", ["bitcoin", "liquid"],
        ["chain_fund", "liquid_chain_claim"], ["provider_destination_broadcast"],
        True, "provider", "claim", None,
    ),
    "route-chain-lbtc-to-btc-provider-b": liquid_case(
        "chain-lbtc-to-btc", "provider-b", ["bitcoin", "liquid"],
        ["chain_fund", "liquid_chain_claim"], ["provider_destination_broadcast"],
        True, "provider", "claim", None,
    ),
    "route-liquid-submarine-provider-a": liquid_case(
        "liquid-submarine", "provider-a", ["liquid"], ["liquid_submarine_claim"],
        ["provider_claim_pending", "provider_claimed"], True, "provider", "claim", None,
    ),
    "route-liquid-submarine-provider-b": liquid_case(
        "liquid-submarine", "provider-b", ["liquid"], ["liquid_submarine_claim"],
        ["provider_claim_pending", "provider_claimed"], True, "provider", "claim", None,
    ),
    "route-liquid-reverse-provider-a": liquid_case(
        "liquid-reverse", "provider-a", ["liquid"], ["liquid_reverse_fund"],
        ["provider_funding_broadcast"], True, "requester", "claim", None,
    ),
    "route-liquid-reverse-provider-b": liquid_case(
        "liquid-reverse", "provider-b", ["liquid"], ["liquid_reverse_fund"],
        ["provider_funding_broadcast"], True, "requester", "claim", None,
    ),
    "doomsday-liquid-submarine-provider-gone": liquid_case(
        "liquid-submarine", "provider-a", ["liquid"], [], [], False,
        "requester", "refund", "presigned-refund",
    ),
    "doomsday-liquid-reverse-coordinator-gone": liquid_case(
        "liquid-reverse", "provider-a", ["liquid"], ["liquid_reverse_fund"],
        ["provider_funding_broadcast"], False, "requester", "claim",
        "direct-claim-and-hold-settlement",
    ),
}
if evidence.get("liquid_case_record") != {
    "schema": "openagents.immortal.adversarial-liquid-case.v1",
    "case_count": 10,
    "signed_lifecycle": [
        "offering",
        "rfq",
        "quote",
        "order",
        "requester-contract",
        "provider-contract",
        "status",
        "close-or-explicit-coordinator-absent-null",
    ],
    "provider_signing_source": "immortal-provider-process",
    "relay_transport": "signed-gift-wrapped-lifecycle",
    "standalone_rail_probe": False,
    "transaction_encoding": "lowercase-hex",
    "exact_raw_transactions": True,
    "exact_outpoints": True,
    "three_node_byte_equality": True,
    "exact_known_replay_after_restart": True,
    "mine_after_exact_transaction_observation": True,
    "requester_claim_pending_signer": "requester-process",
    "requester_claim_pending_base_state": "executing",
    "liquid_exit_authorization": "retained-pre-fund-capability",
    "claim_finality": "contract-terminal-confirmations",
    "verification_boundaries": {
        "source_preflight_before": "requester_source_verified",
        "destination_preflight_after": "destination_lock_terms_ready",
        "combined_authorization_before": "requester_destination_verified",
    },
    "cases": expected_liquid_cases,
    "custody_material": False,
}:
    raise SystemExit("Liquid retained-case evidence schema changed")
if evidence.get("retained_record", {}).get("contains_raw_transactions") is not True:
    raise SystemExit("Liquid retained records do not admit exact transaction bytes")
if evidence.get("retained_record", {}).get("aggregate_encoding") != "utf8-json-sort-keys-compact":
    raise SystemExit("adversarial aggregate encoding is not pinned")

doomsday = fixture.get("doomsday_contract", {})
if doomsday.get("database_or_ui_reconstruction") is not False:
    raise SystemExit("doomsday recovery permits reconstructed history")
if doomsday.get("keyless_broadcaster_accepts_signing_material") is not False:
    raise SystemExit("keyless broadcaster accepts signing material")
if "authenticated-direct-counterparty-channel" not in doomsday.get("retain_only", []):
    raise SystemExit("doomsday recovery has no direct authenticated channel")
if "liquid-elements-access" not in doomsday.get("retain_only", []):
    raise SystemExit("Liquid doomsday recovery has no explicit Elements rail access")
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
if doomsday.get("ark_operator_removal") != {
    "actual_vtxo_transfer": True,
    "fully_presigned_funded_exit_before_removal": True,
    "remove_permanently": ["arkd", "arkd-wallet", "ark-indexer", "ark-postgres"],
    "retain_only": ["verified-exit-package", "bitcoin-esplora-access"],
    "execution_authority": "keyless-esplora",
    "final_output": "participant-bitcoin-address",
    "operator_endpoint_required_after_removal": False,
}:
    raise SystemExit("Ark permanent-operator-removal contract changed")
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
if claims.get("liquid_chain_local_capability") is not True:
    raise SystemExit("adversarial manifest omits bounded local Liquid chain capability")
if claims.get("ark_local_capability") is not True:
    raise SystemExit("adversarial manifest omits bounded local Ark capability")
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

for service in elements-provider-a elements-provider-b elements-wallet; do
  if ! grep -Fq "  ${service}:" scripts/support/provider-funded/adversarial-compose.yaml; then
    echo "test-lab-adversarial-manifest: missing ${service} process" >&2
    exit 1
  fi
done
if test "$(grep -Fc '    profiles: ["liquid"]' scripts/support/provider-funded/adversarial-compose.yaml)" -ne 3 \
  || ! grep -Fq '    compose_prefix+=(--profile liquid)' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'external_checkpoint=chain:provider_funding_effect_recorded' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-a-liquid' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'IMMORTAL_PROVIDER_ELEMENTSD_WALLET=provider-b-liquid' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_WALLET=requester-liquid' scripts/test-lab-adversarial.sh; then
  echo "test-lab-adversarial-manifest: Liquid process dispatch is incomplete" >&2
  exit 1
fi
if grep -Fq 'test-provider-liquid.sh' scripts/test-lab-adversarial.sh \
  || grep -Eq 'IMMORTAL_LAB_[A-Z0-9_]*PROVIDER[A-Z0-9_]*(SECRET|SEED|PRIVATE)' \
    scripts/test-lab-adversarial.sh; then
  echo "test-lab-adversarial-manifest: Liquid lab bypasses the shipped provider signer" >&2
  exit 1
fi
if ! grep -Fq 'scripts/test-ark-operator-removal.sh' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'doomsday-ark-operator-gone' scripts/test-lab-adversarial.sh \
  || ! grep -Fq 'openagents.immortal.ark-operator-removal-lab.v1' scripts/test-lab-adversarial.sh; then
  echo "test-lab-adversarial-manifest: Ark external-process dispatch is incomplete" >&2
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
