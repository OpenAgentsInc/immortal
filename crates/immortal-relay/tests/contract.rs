use std::{collections::BTreeSet, fs, path::Path, process::Command};

use immortal::{
    contract::{CONTRACT_SCHEMA, CONTRACT_VERSION, FIXTURE_MANIFEST_PATH, contract, contract_json},
    domain::{
        EventClass, MKT_CANCEL_ACTIONS, MKT_EXECUTABLE_PROFILES, MKT_OUTCOMES, MKT_QUOTE_CLASSES,
        MKT_RESERVATION_CLASSES, MKT_STATUS_STATES,
    },
    gateway::{GatewayLimits, MKT_PRIVATE_REQUIRES_GIFT_WRAP},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn contract_builder_is_deterministic_and_matches_the_checked_in_artifact() {
    let first = contract_json().unwrap();
    let second = contract_json().unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first,
        include_bytes!("../../../contract/immortal-contract.json")
    );

    let descriptor = contract().unwrap();
    assert_eq!(descriptor.identity.schema, CONTRACT_SCHEMA);
    assert_eq!(descriptor.identity.contract_version, CONTRACT_VERSION);
    assert_eq!(descriptor.fixture_manifest, FIXTURE_MANIFEST_PATH);
    assert_eq!(descriptor.identity.nips.len(), 3);
    assert_eq!(descriptor.kinds.len(), 20);
    assert!(descriptor.kinds.iter().any(|kind| {
        kind.kind == 32_170 && kind.identifier == "NIP-WK" && kind.enforcement_scope == "relay"
    }));
    assert!(descriptor.kinds.iter().any(|kind| {
        kind.kind == 32_200 && kind.identifier == "NIP-PI" && kind.enforcement_scope == "relay"
    }));
    assert!(
        descriptor
            .kinds
            .iter()
            .all(|kind| kind.classification == "addressable")
    );
    for kind in &descriptor.kinds {
        assert_eq!(EventClass::from_kind(kind.kind), EventClass::Addressable);
    }
    assert!(MKT_EXECUTABLE_PROFILES.is_empty());
    assert!(descriptor.mkt.executable_profiles.is_empty());
    assert_eq!(descriptor.mkt.relay_profiles.len(), 5);
    assert_eq!(descriptor.mkt.relay_profiles[0].id, "mkt-swp");
    assert_eq!(descriptor.mkt.relay_profiles[1].id, "mkt-pfi");
    assert_eq!(descriptor.mkt.relay_profiles[2].id, "mkt-mint");
    assert_eq!(descriptor.mkt.relay_profiles[3].id, "mkt-p2p");
    assert_eq!(descriptor.mkt.relay_profiles[4].id, "mkt-lsp");
    assert_eq!(descriptor.mkt.mkt_swp.swap_contract_kind, 39_610);
    assert_eq!(descriptor.mkt.mkt_swp.upstream_fixture_cases, 70);
    assert_eq!(descriptor.mkt.mkt_pfi.qualification_policy_kind, 39_630);
    assert_eq!(descriptor.mkt.mkt_pfi.upstream_fixture_cases, 41);
    assert_eq!(descriptor.mkt.mkt_mint.route_contract_kind, 39_640);
    assert_eq!(descriptor.mkt.mkt_mint.upstream_fixture_cases, 29);
    assert_eq!(descriptor.mkt.mkt_mint.custody_classes["cashu"], "a3-mint");
    assert_eq!(
        descriptor.mkt.mkt_mint.custody_classes["fedimint"],
        "a2-federation"
    );
    assert_eq!(
        descriptor.mkt.mkt_mint.nip87_recommendation_kind_rejected,
        "38000"
    );
    assert_eq!(descriptor.mkt.mkt_p2p.resolution_kind, 39_620);
    assert_eq!(descriptor.mkt.mkt_p2p.upstream_fixture_cases, 26);
    assert_eq!(descriptor.mkt.mkt_p2p.custody_class, "a1-coordinated-hold");
    assert_eq!(descriptor.mkt.mkt_lsp.service_contract_kind, 39_650);
    assert_eq!(descriptor.mkt.mkt_lsp.upstream_fixture_cases, 30);
    assert_eq!(descriptor.mkt.mkt_lsp.custody_class, "a1-coordinated-hold");
    assert!(!descriptor.mkt.mkt_swp.coordination.enabled_by_default);
    assert_eq!(
        descriptor
            .mkt
            .mkt_swp
            .coordination
            .reservation_proof_strength["covenant_reserve"],
        100
    );
    assert_eq!(
        descriptor.mkt.mkt_swp.coordination.observation_authority,
        "observation_not_authority"
    );
    assert!(
        !descriptor
            .mkt
            .mkt_swp
            .coordination
            .on_relay_output_orderbook
    );
    assert_eq!(
        descriptor.mkt.mkt_swp.client_engine.status,
        "implemented_client_only"
    );
    assert!(!descriptor.mkt.mkt_swp.boltz_facade.enabled_by_default);
    assert!(!descriptor.mkt.mkt_swp.boltz_facade.relay_reads_request_body);
    assert!(
        !descriptor
            .mkt
            .mkt_swp
            .boltz_facade
            .relay_persists_session_state
    );
    assert!(!descriptor.mkt.mkt_swp.boltz_facade.nip11_advertised);
    assert_eq!(
        descriptor.mkt.mkt_swp.boltz_facade.completion_gate,
        "external_provider_process_released_client_conformance"
    );
    assert_eq!(
        descriptor.mkt.mkt_swp.client_engine.requester_flows,
        ["submarine", "reverse", "chain"]
    );
    assert!(
        descriptor
            .mkt
            .mkt_swp
            .public_offering_forbidden_members
            .contains(&"live_inventory")
    );
    assert!(
        descriptor
            .mkt
            .mkt_swp
            .public_receipt_forbidden_members
            .contains(&"session_id")
    );
    assert!(
        descriptor
            .mkt
            .mkt_swp
            .evidence_reference_validation
            .contains("bitcoin_output_and_spend_txid_vout")
    );
    assert_eq!(descriptor.mkt.enums["quote"], MKT_QUOTE_CLASSES);
    assert_eq!(descriptor.mkt.enums["reservation"], MKT_RESERVATION_CLASSES);
    assert_eq!(descriptor.mkt.enums["status_state"], MKT_STATUS_STATES);
    assert_eq!(descriptor.mkt.enums["cancel_action"], MKT_CANCEL_ACTIONS);
    assert_eq!(descriptor.mkt.enums["close_outcome"], MKT_OUTCOMES);
    assert!(descriptor.reasons.ok.iter().any(|reason| {
        reason.code == "mkt_private_requires_gift_wrap"
            && reason.message == MKT_PRIVATE_REQUIRES_GIFT_WRAP
    }));

    let defaults = GatewayLimits::default();
    let recipient_limit = descriptor
        .limits
        .gateway
        .iter()
        .find(|limit| limit.name == "gift_wraps_per_minute_recipient")
        .unwrap();
    assert_eq!(
        recipient_limit.default,
        u64::from(defaults.gift_wraps_per_minute_recipient)
    );
}

#[test]
fn contract_cli_requires_no_database_or_service() {
    let output = Command::new(env!("CARGO_BIN_EXE_immortal"))
        .arg("contract")
        .env_remove("DATABASE_URL")
        .env_remove("IMMORTAL_DATABASE_URL")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, contract_json().unwrap());
}

#[test]
fn fixture_manifest_hashes_exact_sorted_committed_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: Value =
        serde_json::from_slice(include_bytes!("../../../contract/immortal-fixtures.json")).unwrap();
    let descriptor: Value =
        serde_json::from_slice(include_bytes!("../../../contract/immortal-contract.json")).unwrap();
    assert_eq!(
        manifest["schema"],
        "openagents.immortal.fixture-manifest.v1"
    );
    assert_eq!(manifest["algorithm"], "sha256");
    assert_eq!(manifest["contract_identity"], descriptor["identity"]);

    let entries = manifest["fixtures"].as_array().unwrap();
    let mut previous = None;
    let mut paths = BTreeSet::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        if let Some(previous) = previous {
            assert!(previous < path, "fixture paths must be strictly sorted");
        }
        previous = Some(path);
        assert!(paths.insert(path), "duplicate fixture path {path}");
        assert!(path.starts_with("tests/fixtures/") && path.ends_with(".json"));
        let bytes = fs::read(root.join(path)).unwrap();
        assert_eq!(entry["bytes"], bytes.len());
        assert_eq!(entry["sha256"], lower_hex(&Sha256::digest(&bytes)));
    }
    assert!(paths.contains("tests/fixtures/nipmkt/client-only-cases.json"));
    assert!(paths.contains("tests/fixtures/nipmkt/relay-closing.json"));
    assert!(paths.contains("tests/fixtures/nipmkt/swp-profile-v1.json"));
    assert!(paths.contains("tests/fixtures/nipmkt/mint-profile-v1.json"));
    assert!(paths.contains("tests/fixtures/nipmkt/swp-coordination-v1.json"));
    assert!(paths.contains("tests/fixtures/nipmkt/swp-client-engine-v1.json"));
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
