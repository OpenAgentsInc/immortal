use std::path::PathBuf;

use immortal_provider::contract::{
    ProviderContractError, arkd_provider_conformance_sha256, provider_contract_bytes,
    provider_contract_sha256, provider_contract_value, validate_provider_contract,
};
use immortal_provider::elementsd::ELEMENTSD_PRODUCTION_RUNTIME_METHODS;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const EXPORTED_CONTRACT: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/provider-contract-v1.json");
const RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/provider-runtime-v1.json");
const QUOTE_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/quote-builder-v1.json");
const SETTLEMENT_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/settlement-construction-v1.json");
const FUNDED_SMOKE_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/funded-smoke-v1.json");
const PRICING_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/nipmkt/swp-pricing-v1.json");
const COOPERATIVE_RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json");
const LND_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/provider/lnd-rest-v1.json");
const BOLTZ_API_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json");
const ADVERSARIAL_LAB_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/lab/adversarial-v1.json");
const CLN_ADVERSARIAL_HOLD_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/cln-adversarial-hold-v1.json");
const DIRECT_RECOVERY_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/direct-recovery-v1.json");
const LIQUID_FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/nipmkt/liquid-rail-v1.json");
const LIQUID_RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/liquid-runtime-v1.json");
const ZERO_CONF_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/zero-conf-v1.json");
const ARK_RUNTIME_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/ark-runtime-v1.json");
const ARKD_REST_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/arkd-rest-v1.json");
const ARKD_OPERATOR_FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/provider/arkd-operator-regtest-v1.json");

#[test]
fn provider_contract_is_canonical_byte_stable_and_matches_export() {
    let first = provider_contract_bytes().unwrap();
    let second = provider_contract_bytes().unwrap();
    assert_eq!(first, second);
    assert_eq!(first, EXPORTED_CONTRACT);
    assert!(first.ends_with(b"\n"));
    assert_eq!(
        provider_contract_sha256().unwrap(),
        lower_hex(&Sha256::digest(&first))
    );
}

#[test]
fn provider_contract_binds_the_exact_provider_fixtures() {
    let contract = provider_contract_value().unwrap();
    let entries = contract["fixtures"]["entries"].as_array().unwrap();
    for (path, bytes) in [
        (
            "tests/fixtures/provider/provider-runtime-v1.json",
            RUNTIME_FIXTURE,
        ),
        (
            "tests/fixtures/provider/quote-builder-v1.json",
            QUOTE_FIXTURE,
        ),
        (
            "tests/fixtures/provider/settlement-construction-v1.json",
            SETTLEMENT_FIXTURE,
        ),
        (
            "tests/fixtures/provider/funded-smoke-v1.json",
            FUNDED_SMOKE_FIXTURE,
        ),
        ("tests/fixtures/nipmkt/swp-pricing-v1.json", PRICING_FIXTURE),
        (
            "tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json",
            COOPERATIVE_RUNTIME_FIXTURE,
        ),
        ("tests/fixtures/provider/lnd-rest-v1.json", LND_FIXTURE),
        (
            "tests/fixtures/nipmkt/boltz-provider-api-v1.json",
            BOLTZ_API_FIXTURE,
        ),
        (
            "tests/fixtures/lab/adversarial-v1.json",
            ADVERSARIAL_LAB_FIXTURE,
        ),
        (
            "tests/fixtures/provider/cln-adversarial-hold-v1.json",
            CLN_ADVERSARIAL_HOLD_FIXTURE,
        ),
        (
            "tests/fixtures/provider/direct-recovery-v1.json",
            DIRECT_RECOVERY_FIXTURE,
        ),
        ("tests/fixtures/nipmkt/liquid-rail-v1.json", LIQUID_FIXTURE),
        (
            "tests/fixtures/provider/liquid-runtime-v1.json",
            LIQUID_RUNTIME_FIXTURE,
        ),
        (
            "tests/fixtures/provider/zero-conf-v1.json",
            ZERO_CONF_FIXTURE,
        ),
        (
            "tests/fixtures/provider/ark-runtime-v1.json",
            ARK_RUNTIME_FIXTURE,
        ),
        (
            "tests/fixtures/provider/arkd-rest-v1.json",
            ARKD_REST_FIXTURE,
        ),
        (
            "tests/fixtures/provider/arkd-operator-regtest-v1.json",
            ARKD_OPERATOR_FIXTURE,
        ),
    ] {
        let entry = entries.iter().find(|entry| entry["path"] == path).unwrap();
        assert_eq!(entry["bytes"], bytes.len());
        assert_eq!(entry["sha256"], lower_hex(&Sha256::digest(bytes)));
    }
    let cooperative: Value = serde_json::from_slice(COOPERATIVE_RUNTIME_FIXTURE).unwrap();
    assert_eq!(cooperative["process_gate"]["production_enabled"], true);
    assert_eq!(contract["execution"]["musig2_key_path"], true);
    assert_eq!(contract["execution"]["musig2_key_path_signer"], true);
    assert_eq!(
        contract["execution"]["musig2_key_path_enabled_by_default"],
        false
    );
    assert_eq!(
        contract["execution"]["musig2_key_path_swap_types"],
        json!(["submarine"])
    );
    assert_eq!(
        contract["execution"]["liquid_swap_types"],
        json!(["submarine", "reverse", "chain"])
    );
    assert_eq!(
        contract["rails"]["elementsd"]["confidential_authority"],
        "local_elementsd_unblind_own_outputs_only"
    );
    assert_eq!(
        contract["rails"]["elementsd"]["independent_range_proof_verification"],
        false
    );
    assert_eq!(
        contract["rails"]["elementsd"]["runtime_methods"],
        json!(ELEMENTSD_PRODUCTION_RUNTIME_METHODS)
    );
    assert_eq!(
        contract["rails"]["arkd"]["available_in"],
        "regtest_lab_only"
    );
    assert_eq!(contract["rails"]["arkd"]["session_execution_wired"], false);
    assert_eq!(contract["rails"]["arkd"]["transfer_effect_wired"], true);
    assert_eq!(contract["rails"]["arkd"]["pair_advertised"], false);
    assert_eq!(
        contract["rails"]["arkd"]["transfer_command_schema"],
        "openagents.immortal.ark-transfer-command.v1"
    );
    assert_eq!(contract["rails"]["arkd"]["nip11_advertised"], false);
    assert_eq!(
        contract["rails"]["arkd"]["conformance_sha256"],
        arkd_provider_conformance_sha256()
    );
}

#[test]
fn provider_contract_exports_closed_nonzero_runtime_limits() {
    let contract = provider_contract_value().unwrap();
    let limits = contract["limits"].as_object().unwrap();
    assert_eq!(
        limits.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "boltz_compatibility",
            "direct_recovery",
            "health",
            "price_feed",
            "quote",
            "rail_rpc",
            "relay_actor",
            "session",
            "store",
            "watchtower",
            "zero_conf",
        ]
    );
    assert_eq!(limits["relay_actor"]["active_sessions_per_requester"], 4);
    assert_eq!(limits["direct_recovery"]["request_wraps"], 32);
    assert_eq!(limits["direct_recovery"]["response_wraps"], 512);
    assert_eq!(limits["rail_rpc"]["arkd"]["command_bytes"], 4_194_304);
    assert_eq!(limits["price_feed"]["file_bytes"], 16_384);
    assert_eq!(
        contract["operations"]["pricing"]["venue_network_access"],
        false
    );
    assert_eq!(
        contract["operations"]["pricing"]["invalid_or_stale_action"],
        "static_spread_fallback"
    );
    assert_eq!(
        contract["identity"]["commands"],
        json!(["run", "address", "ark-transfer", "contract", "--no-spend"])
    );
    assert_eq!(
        contract["operations"]["ark_transfer"]["persist_before_rpc"],
        true
    );
    assert_eq!(
        contract["operations"]["ark_transfer"]["raw_artifacts_retained"],
        false
    );
    assert_eq!(contract["execution"]["ark_transfer_effect"], true);
    assert_eq!(contract["execution"]["ark_native_session_actor"], false);
    assert_eq!(
        contract["operations"]["drain"]["signals"],
        json!(["SIGUSR1", "SIGTERM", "SIGINT"])
    );
    assert_eq!(contract["operations"]["drain"]["required_mode"], "funded");
    assert_eq!(
        contract["operations"]["drain"]["accepts_new_native_sessions"],
        false
    );
    assert_eq!(
        contract["operations"]["drain"]["continues_existing_sessions"],
        true
    );
    assert!(all_limit_leaves_are_positive(&contract["limits"]));
    assert_eq!(
        contract["vocabulary"]["funded_terminal_outcomes"],
        json!(["completed", "refunded"])
    );
    assert_eq!(
        contract["operations"]["zero_confirmation"]["enabled_by_default"],
        false
    );
    assert_eq!(
        contract["execution"]["zero_confirmation_requester_finality_unchanged"],
        true
    );

    let mut zero_limit = contract.clone();
    zero_limit["limits"]["watchtower"]["watch_attempts"] = json!(0);
    assert_eq!(
        validate_provider_contract(&zero_limit),
        Err(ProviderContractError::InvalidShape)
    );

    let mut open_limits = contract;
    open_limits["limits"]["watchtower"]["unreviewed"] = json!(1);
    assert_eq!(
        validate_provider_contract(&open_limits),
        Err(ProviderContractError::InvalidShape)
    );
}

#[test]
fn provider_contract_rejects_custody_keys_and_configured_values() {
    let mut custody_member = provider_contract_value().unwrap();
    custody_member["wallet_seed"] = Value::String("forbidden".to_owned());
    assert_eq!(
        validate_provider_contract(&custody_member),
        Err(ProviderContractError::ForbiddenCustodyMember)
    );

    let mut configured_value = provider_contract_value().unwrap();
    configured_value["configuration"]["variables"][0]["value"] =
        Value::String("forbidden".to_owned());
    assert_eq!(
        validate_provider_contract(&configured_value),
        Err(ProviderContractError::ConfiguredValuePresent)
    );

    let mut unmarked_secret = provider_contract_value().unwrap();
    let variables = unmarked_secret["configuration"]["variables"]
        .as_array_mut()
        .unwrap();
    let password = variables
        .iter_mut()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD")
        .unwrap();
    password["secret"] = json!(false);
    assert_eq!(
        validate_provider_contract(&unmarked_secret),
        Err(ProviderContractError::SecretEnvironmentNotMarked)
    );
}

#[test]
fn provider_contract_distinguishes_required_and_optional_environment() {
    let contract = provider_contract_value().unwrap();
    let variables = contract["configuration"]["variables"].as_array().unwrap();
    let alert = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_ALERT_URL")
        .unwrap();
    assert_eq!(alert["optional_in_modes"], json!(["funded"]));
    assert_eq!(alert["defaulted"], json!(false));
    assert!(alert.get("required_in_modes").is_none());
    assert!(alert.get("value").is_none());
    assert!(alert.get("default").is_none());
    assert!(alert.get("default_value").is_none());

    let health = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_HEALTH_BIND")
        .unwrap();
    assert_eq!(health["optional_in_modes"], json!(["funded"]));
    assert_eq!(health["defaulted"], json!(true));

    let direct_recovery = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND")
        .expect("direct recovery environment contract");
    assert_eq!(direct_recovery["optional_in_modes"], json!(["funded"]));
    assert_eq!(direct_recovery["defaulted"], json!(false));
    assert_eq!(
        direct_recovery["format"],
        "private_or_loopback_socket_address"
    );
    assert_eq!(
        contract["operations"]["direct_recovery"]["opens_new_sessions"],
        false
    );
    assert_eq!(
        contract["operations"]["direct_recovery"]["admits_pre_contract_negotiation"],
        false
    );
    assert_eq!(
        contract["operations"]["direct_recovery"]["nip11_advertised"],
        false
    );

    assert!(variables.iter().any(|variable| {
        variable["name"] == "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB"
            && variable["optional_in_modes"] == json!(["funded"])
            && variable["defaulted"] == json!(false)
    }));
    let selector = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_LIGHTNING_RAIL")
        .unwrap();
    assert_eq!(selector["choices"], json!(["cln", "lnd"]));
    assert_eq!(selector["implicit_choice_when_absent"], "cln");

    let lab_profile = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_LAB_PROFILE")
        .unwrap();
    assert_eq!(lab_profile["choices"], json!(["regtest_adversarial"]));
    assert_eq!(lab_profile["required_network"], "regtest");
    assert_eq!(lab_profile["quote_expiry_seconds"], 3);
    assert_eq!(lab_profile["hold_invoice_expiry_seconds"], 30);
    assert_eq!(lab_profile["defaulted"], false);

    let lab_cooperative_signing = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING")
        .expect("provider contract must export the lab-only cooperative signing gate");
    assert_eq!(lab_cooperative_signing["choices"], json!(["true"]));
    assert_eq!(lab_cooperative_signing["required_network"], "regtest");
    assert_eq!(
        lab_cooperative_signing["required_lab_profile"],
        "regtest_adversarial"
    );
    assert_eq!(lab_cooperative_signing["lab_only"], true);
    assert_eq!(lab_cooperative_signing["defaulted"], false);

    let cooperative_signing = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING")
        .expect("provider contract must export the production cooperative signing gate");
    assert_eq!(cooperative_signing["choices"], json!(["true"]));
    assert_eq!(cooperative_signing["enabled_by_default"], false);
    assert_eq!(
        cooperative_signing["supported_swap_types"],
        json!(["submarine"])
    );
    assert_eq!(cooperative_signing["defaulted"], false);

    let cln = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_CLN_RPC_PATH")
        .unwrap();
    assert_eq!(
        cln["required_when"],
        json!({
            "environment":"IMMORTAL_PROVIDER_LIGHTNING_RAIL",
            "equals":"cln",
            "or_selector_absent":true,
        })
    );
    for name in [
        "IMMORTAL_PROVIDER_LND_HOST",
        "IMMORTAL_PROVIDER_LND_PORT",
        "IMMORTAL_PROVIDER_LND_TLS_CERT_FILE",
        "IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE",
        "IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE",
        "IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE",
    ] {
        let variable = variables
            .iter()
            .find(|variable| variable["name"] == name)
            .unwrap();
        assert_eq!(
            variable["required_when"],
            json!({
                "environment":"IMMORTAL_PROVIDER_LIGHTNING_RAIL",
                "equals":"lnd",
                "or_selector_absent":false,
            })
        );
    }
    let liquid_enabled = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_LIQUID_ENABLED")
        .expect("Liquid selector environment contract");
    assert_eq!(liquid_enabled["choices"], json!(["true"]));
    assert_eq!(liquid_enabled["defaulted"], false);
    for name in [
        "IMMORTAL_PROVIDER_ELEMENTSD_HOST",
        "IMMORTAL_PROVIDER_ELEMENTSD_PORT",
        "IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER",
        "IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD",
        "IMMORTAL_PROVIDER_ELEMENTSD_WALLET",
        "IMMORTAL_PROVIDER_LIQUID_NETWORK_ID",
        "IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET",
    ] {
        let variable = variables
            .iter()
            .find(|variable| variable["name"] == name)
            .expect("conditional Liquid environment contract");
        assert_eq!(
            variable["required_when"],
            json!({
                "environment":"IMMORTAL_PROVIDER_LIQUID_ENABLED",
                "equals":"true",
                "or_selector_absent":false,
            })
        );
    }
    let arkd_enabled = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_ARKD_ENABLED")
        .expect("arkd selector environment contract");
    assert_eq!(arkd_enabled["choices"], json!(["true"]));
    assert_eq!(arkd_enabled["defaulted"], false);
    assert_eq!(arkd_enabled["required_network"], "regtest");
    assert_eq!(arkd_enabled["required_lab_profile"], "regtest_adversarial");
    for name in [
        "IMMORTAL_PROVIDER_ARKD_HOST",
        "IMMORTAL_PROVIDER_ARKD_PORT",
        "IMMORTAL_PROVIDER_ARKD_OPERATOR_FILE",
        "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256",
    ] {
        let variable = variables
            .iter()
            .find(|variable| variable["name"] == name)
            .expect("conditional arkd environment contract");
        assert_eq!(
            variable["required_when"],
            json!({
                "environment":"IMMORTAL_PROVIDER_ARKD_ENABLED",
                "equals":"true",
                "or_selector_absent":false,
            })
        );
    }
    assert!(variables.iter().any(|variable| {
        variable["name"] == "IMMORTAL_PROVIDER_RESERVATION_TIER"
            && variable["choices"] == json!(["hard"])
            && variable["defaulted"] == json!(true)
    }));

    let database = variables
        .iter()
        .find(|variable| variable["name"] == "IMMORTAL_PROVIDER_DATABASE_URL")
        .unwrap();
    assert_eq!(database["required_in_modes"], json!(["funded"]));
    assert!(database.get("optional_in_modes").is_none());

    for name in [
        "IMMORTAL_PROVIDER_BOLTZ_BIND",
        "IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256",
        "IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN",
    ] {
        let variable = variables
            .iter()
            .find(|variable| variable["name"] == name)
            .unwrap();
        assert_eq!(variable["optional_in_modes"], json!(["funded"]));
        assert_eq!(variable["defaulted"], false);
    }
    assert_eq!(
        contract["operations"]["boltz_compatibility"]["dependent_call_emulated_routes"],
        19
    );
    assert_eq!(
        contract["operations"]["boltz_compatibility"]["requester_exit_package_modes"],
        json!(["presigned", "wallet_sign"])
    );
}

#[test]
fn provider_contract_keeps_the_adversarial_cln_policy_out_of_production() {
    let contract = provider_contract_value().unwrap();
    let policy = &contract["rails"]["cln"]["hold_invoice_policy"];
    assert_eq!(policy["production"]["rpc_method"], "holdinvoice");
    assert_eq!(policy["production"]["explicit_expiry_policy"], false);
    assert_eq!(
        policy["regtest_adversarial"]["rpc_method"],
        "holdinvoiceimmortalregtest"
    );
    assert_eq!(policy["regtest_adversarial"]["network"], "regtest");
    assert_eq!(policy["regtest_adversarial"]["expiry_seconds"], 30);
    assert_eq!(
        policy["regtest_adversarial"]["minimum_final_cltv_delta"],
        80
    );
}

#[test]
fn direct_recovery_fixture_closes_the_recovery_only_surface() {
    let fixture: Value =
        serde_json::from_slice(DIRECT_RECOVERY_FIXTURE).expect("direct recovery fixture");
    assert_eq!(
        fixture["schema"],
        "openagents.immortal.provider-direct-recovery-fixture.v1"
    );
    assert_eq!(fixture["activation"]["enabled_by_default"], false);
    assert_eq!(fixture["admission"]["new_rfq_allowed"], false);
    assert_eq!(fixture["admission"]["new_session_allowed"], false);
    assert_eq!(
        fixture["admission"]["pre_contract_negotiation_allowed"],
        false
    );
    assert_eq!(fixture["advertisement"]["nip11"], false);
    assert_eq!(fixture["advertisement"]["public_replacement_claim"], false);
    let case_ids = fixture["cases"]
        .as_array()
        .expect("direct recovery cases")
        .iter()
        .map(|case| case["id"].as_str().expect("direct recovery case ID"))
        .collect::<Vec<_>>();
    assert_eq!(
        case_ids,
        [
            "durable-bilateral-request-replays-provider-history",
            "identical-request-replay",
            "terminal-provider-close-after-actor-removal",
            "unknown-session-rfq",
            "request-rfq-differs-from-durable-rfq",
            "pre-contract-durable-session",
            "wrong-requester",
            "mixed-session",
            "provider-authored-inbound",
            "invalid-gift-wrap",
            "bare-private-record",
            "empty-wraps",
            "too-many-wraps",
            "oversized-frame",
            "duplicate-json-member",
            "unknown-json-member",
            "response-byte-bound",
        ]
    );
}

#[test]
fn provider_contract_identifies_the_crate_and_pinned_nip_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = provider_contract_value()?;
    let identity = &contract["identity"];
    assert_eq!(identity["crate_name"], "immortal_provider");
    assert_eq!(identity["crate_version"], env!("CARGO_PKG_VERSION"));
    let sources = identity["nips"].as_array().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "contract nips must be an array",
        )
    })?;
    assert_eq!(sources.len(), 3);
    let provider_source = sources.get(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "contract must contain the OpenAgents NIP source",
        )
    })?;
    assert_eq!(provider_source["lane"], "openagents");

    let manifest: Value = serde_json::from_str(include_str!("../../../nips/manifest.json"))?;
    let manifest_commit = manifest["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|source| source["name"] == "openagents"))
        .and_then(|source| source["commit"].as_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "manifest must contain the OpenAgents NIP source commit",
            )
        })?;
    assert_eq!(provider_source["commit"], manifest_commit);

    let mut changed = contract;
    changed["identity"]["nips"][2]["commit"] = Value::String("00".repeat(20));
    assert_eq!(
        validate_provider_contract(&changed),
        Err(ProviderContractError::InvalidShape)
    );
    Ok(())
}

#[test]
#[ignore = "invoked only by scripts/export-provider-contract.sh"]
fn export_provider_contract() {
    let destination = std::env::var_os("IMMORTAL_PROVIDER_CONTRACT_DESTINATION")
        .map(PathBuf::from)
        .expect("IMMORTAL_PROVIDER_CONTRACT_DESTINATION is required");
    std::fs::write(destination, provider_contract_bytes().unwrap()).unwrap();
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn all_limit_leaves_are_positive(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            !object.is_empty() && object.values().all(all_limit_leaves_are_positive)
        }
        Value::Number(number) => number.as_u64().is_some_and(|number| number > 0),
        _ => false,
    }
}
