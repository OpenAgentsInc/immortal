use std::path::PathBuf;

use immortal_provider::contract::{
    ProviderContractError, provider_contract_bytes, provider_contract_sha256,
    provider_contract_value, validate_provider_contract,
};
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
    ] {
        let entry = entries.iter().find(|entry| entry["path"] == path).unwrap();
        assert_eq!(entry["bytes"], bytes.len());
        assert_eq!(entry["sha256"], lower_hex(&Sha256::digest(bytes)));
    }
    let cooperative: Value = serde_json::from_slice(COOPERATIVE_RUNTIME_FIXTURE).unwrap();
    assert_eq!(cooperative["process_gate"]["production_enabled"], false);
    assert_eq!(contract["execution"]["musig2_key_path"], false);
    assert_eq!(contract["execution"]["musig2_key_path_signer"], false);
}

#[test]
fn provider_contract_exports_closed_nonzero_runtime_limits() {
    let contract = provider_contract_value().unwrap();
    let limits = contract["limits"].as_object().unwrap();
    assert_eq!(
        limits.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "health",
            "quote",
            "rail_rpc",
            "relay_actor",
            "session",
            "store",
            "watchtower",
        ]
    );
    assert_eq!(limits["relay_actor"]["active_sessions_per_requester"], 4);
    assert!(all_limit_leaves_are_positive(&contract["limits"]));
    assert_eq!(
        contract["vocabulary"]["funded_terminal_outcomes"],
        json!(["completed", "refunded"])
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

    assert!(variables.iter().any(|variable| {
        variable["name"] == "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB"
            && variable["optional_in_modes"] == json!(["funded"])
            && variable["defaulted"] == json!(false)
    }));
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
