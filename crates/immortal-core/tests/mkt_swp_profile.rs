use std::collections::BTreeSet;

use immortal_core::domain::{
    Event, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND,
    MktProfileSupport, MktValidationCode, Tag, is_mkt_private_kind, validate_mkt_private_base,
    validate_mkt_private_with_profiles, validate_mkt_public_event,
    validate_mkt_swp_evidence_reference,
};
use serde_json::Value;

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn mkt_swp_fixture_manifest_is_complete_and_explicitly_scoped() {
    let fixture = fixture();
    assert_eq!(fixture["source"]["profile"], MKT_SWP_PROFILE_ID);
    assert_eq!(fixture["source"]["version"], MKT_SWP_PROFILE_VERSION);
    assert_eq!(fixture["source"]["kind"], MKT_SWP_SWAP_CONTRACT_KIND);
    assert_eq!(fixture["client_only_requirements"]["relay_enforced"], false);

    let cases = fixture["upstream_fixture_manifest"].as_array().unwrap();
    let unique = cases
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 70);
    assert_eq!(unique.len(), cases.len());
    for required in [
        "swp-v1-negative-timeout-ladder",
        "swp-v1-negative-missing-exit-package",
        "swp-v1-reservation-sequence-fork",
        "swp-v1-status-gap",
        "swp-v1-status-fork",
        "swp-v1-doomsday-keyless-esplora-broadcast",
    ] {
        assert!(unique.contains(required), "missing {required}");
    }
    let categories = fixture["client_only_requirements"]["case_categories"]
        .as_object()
        .unwrap();
    for category in [
        "lifecycle_transitions",
        "timeout_ladder",
        "verify_before_fund_refusals",
        "equivocating_reservation",
    ] {
        let cases = categories[category].as_array().unwrap();
        assert!(!cases.is_empty(), "empty client category {category}");
        for case in cases {
            assert!(
                unique.contains(case.as_str().unwrap()),
                "client category {category} references an unknown case"
            );
        }
    }
}

#[test]
fn mkt_swp_offering_validates_relay_observable_fields() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["offering"]);
    assert_eq!(validate_mkt_public_event(&base), Ok(()));

    let mut liquid = base.clone();
    let mut content = serde_json::from_str::<Value>(&liquid.content).unwrap();
    content["mkt_swp"]["networks"] = serde_json::json!([
        "bip122:00000000000000000000000000000000",
        "bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ]);
    let liquid_asset = "swp:1:bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:elements:1111111111111111111111111111111111111111111111111111111111111111:liquid";
    let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
    let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
    content["mkt_swp"]["sides"] = serde_json::json!([
        {"input_asset_id":liquid_asset,"output_asset_id":lightning,"min":"10000","max":"1000000","fee_bps":"25"},
        {"input_asset_id":lightning,"output_asset_id":liquid_asset,"min":"10000","max":"1000000","fee_bps":"25"},
        {"input_asset_id":chain,"output_asset_id":liquid_asset,"min":"10000","max":"1000000","fee_bps":"25"},
        {"input_asset_id":liquid_asset,"output_asset_id":chain,"min":"10000","max":"1000000","fee_bps":"25"}
    ]);
    liquid.content = serde_json::to_string(&content).unwrap();
    assert_eq!(validate_mkt_public_event(&liquid), Ok(()));

    content["mkt_swp"]["sides"][0]["input_asset_id"] =
        Value::String("swp:1:bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:elements:L-BTC:liquid".into());
    liquid.content = serde_json::to_string(&content).unwrap();
    assert!(
        validate_mkt_public_event(&liquid)
            .unwrap_err()
            .starts_with("swp_invalid_asset_id")
    );

    for (mutation, expected_code) in fixture["relay_observable"]["offering_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let case = case.as_array().unwrap();
            (case[0].as_str().unwrap(), case[1].as_str().unwrap())
        })
    {
        let mut event = base.clone();
        mutate_offering(&mut event, mutation);
        let error = validate_mkt_public_event(&event).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_swp_liquid_evidence_uses_liquid_classes_and_references() {
    let base = serde_json::json!({
        "class":"liquid_transaction",
        "rung":"verified",
        "rail":"liquid",
        "reference":"11".repeat(32),
        "artifact_sha256":"22".repeat(32),
        "producer_pubkey":"33".repeat(32),
        "verifier_pubkey":null,
        "verifier_policy":null,
        "observed_at":1,
        "view":"local-elementsd"
    });
    assert_eq!(validate_mkt_swp_evidence_reference(&base), Ok(()));

    let mut output = base.clone();
    output["class"] = Value::String("liquid_output".into());
    output["reference"] = Value::String(format!("{}:0", "11".repeat(32)));
    assert_eq!(validate_mkt_swp_evidence_reference(&output), Ok(()));

    output["rail"] = Value::String("bitcoin".into());
    assert!(
        validate_mkt_swp_evidence_reference(&output)
            .unwrap_err()
            .starts_with("swp_evidence_mismatch")
    );
}

#[test]
fn mkt_swp_swap_contract_is_private_immutable_and_profile_validated() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["swap_contract"]);
    let support = swp_support();
    assert!(is_mkt_private_kind(MKT_SWP_SWAP_CONTRACT_KIND));
    assert!(validate_mkt_private_with_profiles(&base, &[support]).is_ok());

    let mut missing_order = base.clone();
    missing_order
        .tags
        .retain(|tag| tag.as_slice().get(3).map(String::as_str) != Some("order"));
    assert_profile_error(&missing_order, "swp_contract_terms_mismatch");

    let mut wrong_role = base.clone();
    replace_tag(&mut wrong_role, "role", vec!["role", "provider"]);
    assert_profile_error(&wrong_role, "swp_contract_signer_invalid");

    let mut expiration = base.clone();
    expiration
        .tags
        .push(Tag::new(vec!["expiration".into(), "1785859200".into()]));
    assert_profile_error(&expiration, "swp_contract_terms_mismatch");

    let mut wrong_digest = base.clone();
    replace_tag(&mut wrong_digest, "x", vec!["x", &"6".repeat(64)]);
    assert_profile_error(&wrong_digest, "swp_contract_digest_mismatch");

    for (mutation, expected_code) in fixture["relay_observable"]["swap_contract_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let case = case.as_array().unwrap();
            (case[0].as_str().unwrap(), case[1].as_str().unwrap())
        })
    {
        let mut event = base.clone();
        mutate_swap_contract(&mut event, mutation);
        assert_profile_error(&event, expected_code);
    }

    for member in fixture["relay_observable"]["forbidden_custody_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap())
    {
        let mut event = base.clone();
        let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
        content[member] = Value::String("forbidden fixture value".into());
        event.content = content.to_string();
        assert_profile_error(&event, "swp_secret_material_forbidden");
    }

    let mut wrong_profile = event_from_fixture(&fixture["relay_observable"]["swap_contract"]);
    replace_profile(&mut wrong_profile, "conformance", 1);
    let support = MktProfileSupport {
        profile_id: "conformance",
        version: 1,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    };
    assert_eq!(
        validate_mkt_private_with_profiles(&wrong_profile, &[support])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfile
    );
    assert_eq!(
        validate_mkt_private_base(&wrong_profile).unwrap_err().code,
        MktValidationCode::UnsupportedProfile
    );

    let mut wrong_version = event_from_fixture(&fixture["relay_observable"]["swap_contract"]);
    replace_profile(&mut wrong_version, MKT_SWP_PROFILE_ID, 2);
    let support = MktProfileSupport {
        version: 2,
        ..swp_support()
    };
    assert_eq!(
        validate_mkt_private_with_profiles(&wrong_version, &[support])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfileVersion
    );
    assert_eq!(
        validate_mkt_private_base(&wrong_version).unwrap_err().code,
        MktValidationCode::UnsupportedProfileVersion
    );
}

#[test]
fn mkt_swp_status_accepts_contract_marker_and_typed_evidence() {
    let fixture = fixture();
    let status =
        event_from_fixture(&fixture["relay_observable"]["status_with_contract_and_evidence"]);
    assert!(validate_mkt_private_base(&status).is_ok());
    assert!(validate_mkt_private_with_profiles(&status, &[swp_support()]).is_ok());

    let mut unknown_marker = status;
    let contract = unknown_marker
        .tags
        .iter_mut()
        .find(|tag| tag.as_slice().get(3).map(String::as_str) == Some("contract"))
        .unwrap();
    contract.0[3] = "unknown-contract".into();
    assert_eq!(
        validate_mkt_private_base(&unknown_marker).unwrap_err().code,
        MktValidationCode::InvalidReference
    );
}

#[test]
fn mkt_swp_evidence_reference_grammar_is_bounded_and_typed() {
    let fixture = fixture();
    let evidence = &fixture["relay_observable"]["evidence"];
    assert_eq!(
        validate_mkt_swp_evidence_reference(&evidence["valid"]),
        Ok(())
    );

    for class in evidence["invalid_classes"].as_array().unwrap() {
        let mut invalid = evidence["valid"].clone();
        invalid["class"] = class.clone();
        assert!(
            validate_mkt_swp_evidence_reference(&invalid)
                .unwrap_err()
                .starts_with("swp_evidence_mismatch")
        );
    }
    for rung in evidence["invalid_rungs"].as_array().unwrap() {
        let mut invalid = evidence["valid"].clone();
        invalid["rung"] = rung.clone();
        assert!(
            validate_mkt_swp_evidence_reference(&invalid)
                .unwrap_err()
                .starts_with("swp_settlement_overclaim")
        );
    }
    for case in evidence["typed_errors"].as_array().unwrap() {
        let case = case.as_array().unwrap();
        let mut invalid = evidence["valid"].clone();
        invalid["rail"] = case[1].clone();
        invalid["reference"] = case[2].clone();
        let error = validate_mkt_swp_evidence_reference(&invalid).unwrap_err();
        assert!(
            error.starts_with("swp_evidence_mismatch"),
            "{}: {error}",
            case[0].as_str().unwrap()
        );
    }

    let mut bearer = evidence["valid"].clone();
    bearer["reference"] = Value::String("https://user:secret@example.invalid/evidence".into());
    assert!(
        validate_mkt_swp_evidence_reference(&bearer)
            .unwrap_err()
            .starts_with("swp_privacy_violation")
    );
}

#[test]
fn mkt_swp_public_receipt_uses_only_profile_outcomes() {
    let fixture = fixture();
    let expected = fixture["relay_observable"]["public_receipt_outcomes"]
        .as_array()
        .unwrap();
    let mut receipt = Event {
        id: "0".repeat(64),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 1,
        kind: 39_603,
        tags: vec![
            Tag::new(vec!["d".into(), "receipt-one".into()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec!["outcome".into(), "completed".into()]),
            Tag::new(vec!["x".into(), "a".repeat(64)]),
            Tag::new(vec!["role".into(), "provider".into()]),
        ],
        content: "{}".into(),
        sig: "0".repeat(128),
    };
    for outcome in expected {
        replace_tag(
            &mut receipt,
            "outcome",
            vec!["outcome", outcome.as_str().unwrap()],
        );
        assert_eq!(validate_mkt_public_event(&receipt), Ok(()));
    }
    replace_tag(&mut receipt, "outcome", vec!["outcome", "rejected"]);
    assert!(validate_mkt_public_event(&receipt).is_err());

    replace_tag(&mut receipt, "outcome", vec!["outcome", "completed"]);
    for (mutation, expected_code) in fixture["relay_observable"]["public_receipt_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let case = case.as_array().unwrap();
            (case[0].as_str().unwrap(), case[1].as_str().unwrap())
        })
    {
        let mut invalid = receipt.clone();
        mutate_public_receipt(&mut invalid, mutation);
        let error = validate_mkt_public_event(&invalid).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

fn assert_profile_error(event: &Event, expected: &str) {
    let error = validate_mkt_private_with_profiles(event, &[swp_support()]).unwrap_err();
    assert!(
        error.detail.starts_with(expected),
        "expected {expected}, got {error}"
    );
}

fn swp_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }
}

fn event_from_fixture(value: &Value) -> Event {
    Event {
        id: "0".repeat(64),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 1,
        kind: u16::try_from(value["kind"].as_u64().unwrap()).unwrap(),
        tags: value["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| {
                Tag::new(
                    tag.as_array()
                        .unwrap()
                        .iter()
                        .map(|part| part.as_str().unwrap().to_owned())
                        .collect(),
                )
            })
            .collect(),
        content: value["content"].to_string(),
        sig: "0".repeat(128),
    }
}

fn mutate_offering(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "ticker_asset" => {
            content["mkt_swp"]["sides"][0]["input_asset_id"] = Value::String("BTC".into())
        }
        "json_number_amount" => content["mkt_swp"]["sides"][0]["min"] = Value::from(10_000),
        "leading_zero_amount" => {
            content["mkt_swp"]["sides"][0]["min"] = Value::String("010000".into())
        }
        "disabled_side_min_nonzero" => {
            content["mkt_swp"]["sides"][0]["max"] = Value::String("0".into())
        }
        "fee_over_10000" => {
            content["mkt_swp"]["sides"][0]["fee_bps"] = Value::String("10001".into())
        }
        "duplicate_swap_type" => {
            content["mkt_swp"]["swap_types"] = serde_json::json!(["submarine", "submarine"])
        }
        "unknown_script_mode" => content["mkt_swp"]["script_modes"] = serde_json::json!(["legacy"]),
        "nonnull_evm_extension" => content["mkt_swp"]["evm_extension"] = serde_json::json!({}),
        "public_live_inventory" => content["mkt_swp"]["live_inventory"] = serde_json::json!([]),
        "public_preimage" => content["mkt_swp"]["preimage"] = Value::String("00".repeat(32)),
        "sibling_live_inventory" => content["live_inventory"] = serde_json::json!([]),
        "sibling_preimage" => content["preimage"] = Value::String("00".repeat(32)),
        "sibling_seed" => content["seed"] = Value::String("seed".into()),
        "sibling_macaroon" => content["macaroon"] = Value::String("macaroon".into()),
        "unadvertised_side_network" => {
            content["mkt_swp"]["sides"][0]["output_asset_id"] =
                Value::String(format!("swp:1:bip122:{}:btc:lightning", "1".repeat(32)))
        }
        "cross_network_submarine" => {
            content["mkt_swp"]["networks"] = serde_json::json!([
                "bip122:00000000000000000000000000000000",
                format!("bip122:{}", "1".repeat(32))
            ]);
            content["mkt_swp"]["sides"][0]["output_asset_id"] =
                Value::String(format!("swp:1:bip122:{}:btc:lightning", "1".repeat(32)))
        }
        "side_swap_type_not_advertised" => {
            content["mkt_swp"]["swap_types"] = serde_json::json!(["reverse"])
        }
        other => panic!("unknown mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_swap_contract(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "self_counterparty" => replace_tag(event, "p", vec!["p", FIXTURE_PUBKEY, "", "provider"]),
        "same_role_counterparty" => {
            replace_tag(event, "p", vec!["p", &"2".repeat(64), "", "requester"])
        }
        "nonnull_contract_evm_leg" => {
            content["mkt_swp"]["contract"]["evm_leg"] = serde_json::json!({})
        }
        "sibling_preimage" => content["preimage"] = Value::String("00".repeat(32)),
        "sibling_seed" => content["seed"] = Value::String("seed".into()),
        "sibling_macaroon" => content["macaroon"] = Value::String("macaroon".into()),
        other => panic!("unknown mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_public_receipt(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-swp", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "sibling_live_inventory" => content["live_inventory"] = serde_json::json!([]),
        "sibling_preimage" => content["preimage"] = Value::String("00".repeat(32)),
        "sibling_seed" => content["seed"] = Value::String("seed".into()),
        "sibling_macaroon" => content["macaroon"] = Value::String("macaroon".into()),
        other => panic!("unknown mutation {other}"),
    }
    event.content = content.to_string();
}

fn replace_tag(event: &mut Event, name: &str, values: Vec<&str>) {
    let tag = event
        .tags
        .iter_mut()
        .find(|tag| tag.name() == Some(name))
        .unwrap();
    tag.0 = values.into_iter().map(str::to_owned).collect();
}

fn replace_profile(event: &mut Event, profile_id: &str, version: u64) {
    replace_tag(
        event,
        "profile",
        vec!["profile", profile_id, &version.to_string()],
    );
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    content["profile"] = Value::String(profile_id.to_owned());
    content["profile_version"] = Value::from(version);
    event.content = content.to_string();
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-profile-v1.json"
    ))
    .unwrap()
}
