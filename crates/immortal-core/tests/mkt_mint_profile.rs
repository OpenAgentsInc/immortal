use std::collections::BTreeSet;

use immortal_core::domain::{
    Event, MKT_MINT_PROFILE_ID, MKT_MINT_PROFILE_VERSION, MKT_MINT_ROUTE_CONTRACT_KIND,
    MktProfileSupport, Tag, validate_mkt_mint_evidence_reference,
    validate_mkt_private_with_profiles, validate_mkt_public_event,
};
use serde_json::{Value, json};

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn mkt_mint_fixture_manifest_is_complete_and_explicitly_scoped() {
    let fixture = fixture();
    assert_eq!(fixture["source"]["profile"], MKT_MINT_PROFILE_ID);
    assert_eq!(fixture["source"]["version"], MKT_MINT_PROFILE_VERSION);
    assert_eq!(
        fixture["source"]["route_contract_kind"],
        MKT_MINT_ROUTE_CONTRACT_KIND
    );
    assert_eq!(fixture["client_only_requirements"]["relay_enforced"], false);

    let cases = fixture["upstream_fixture_manifest"].as_array().unwrap();
    let unique = cases
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 29);
    assert_eq!(unique.len(), cases.len());
    for required in [
        "mint-positive-cashu-mint",
        "mint-positive-nip87-cashu-ref",
        "mint-positive-nip87-fedimint-ref",
        "mint-positive-route-contract",
        "mint-negative-nip87-recommendation-as-authority",
        "mint-negative-quote-is-settlement",
        "mint-negative-invoice-paid-is-issued",
        "mint-negative-public-invite",
        "mint-negative-bearer-proof",
        "mint-recovery-market-coordinator-gone",
        "mint-loss-mint-unavailable",
    ] {
        assert!(unique.contains(required), "missing {required}");
    }
    for cases in fixture["client_only_requirements"]["case_categories"]
        .as_object()
        .unwrap()
        .values()
    {
        for case in cases.as_array().unwrap() {
            assert!(unique.contains(case.as_str().unwrap()));
        }
    }
}

#[test]
fn mkt_mint_cashu_offering_binds_nip87_market_sides_operations_and_custody() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["offering_cashu"]);
    assert_eq!(validate_mkt_public_event(&base), Ok(()));

    for (mutation, expected_code) in fixture["relay_observable"]["offering_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
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
fn mkt_mint_fedimint_offering_disables_deposit_and_pins_the_federation_announcement() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["offering_fedimint"]);
    assert_eq!(validate_mkt_public_event(&base), Ok(()));

    for (mutation, expected_code) in fixture["relay_observable"]["offering_fedimint_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_fedimint_offering(&mut event, mutation);
        let error = validate_mkt_public_event(&event).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_mint_route_contract_binds_causal_tags_digest_rail_and_complementary_signers() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["route_contract"]);
    assert_eq!(base.kind, MKT_MINT_ROUTE_CONTRACT_KIND);
    assert!(validate_mkt_private_with_profiles(&base, &[mint_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["contract_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_contract(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[mint_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_mint_private_observable_subset_guards_custody_disclosure_and_provenance() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["status_record"]);
    assert!(validate_mkt_private_with_profiles(&base, &[mint_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["private_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_private(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[mint_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }

    let content = serde_json::from_str::<Value>(&base.content).unwrap();
    let evidence = &content["mkt_mint"]["evidence_refs"][0];
    assert_eq!(validate_mkt_mint_evidence_reference(evidence), Ok(()));
}

#[test]
fn mkt_mint_public_receipt_rejects_bearer_and_discovery_material() {
    let fixture = fixture();
    let base = Event {
        id: "0".repeat(64),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 1,
        kind: 39_603,
        tags: vec![
            Tag::new(vec!["d".into(), "receipt-mint".into()]),
            Tag::new(vec!["profile".into(), "mkt-mint".into(), "1".into()]),
            Tag::new(vec!["outcome".into(), "completed".into()]),
            Tag::new(vec!["x".into(), "a".repeat(64)]),
            Tag::new(vec!["role".into(), "provider".into()]),
        ],
        content: "{}".into(),
        sig: "0".repeat(128),
    };
    assert_eq!(validate_mkt_public_event(&base), Ok(()));

    for (mutation, expected_code) in fixture["relay_observable"]["receipt_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut receipt = base.clone();
        mutate_receipt(&mut receipt, mutation);
        let error = validate_mkt_public_event(&receipt).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

fn mint_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_MINT_PROFILE_ID,
        version: MKT_MINT_PROFILE_VERSION,
        critical_members: &["mkt_mint"],
        understood_members: &["mkt_mint"],
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
    if mutation == "unsupported_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-mint", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    let mint = &mut content["mkt_mint"];
    match mutation {
        "nip87_wrong_kind" => mint["nip87_ref"]["kind"] = Value::String("38173".into()),
        "nip87_recommendation" => mint["nip87_ref"]["kind"] = Value::String("38000".into()),
        "nip87_address_kind_mismatch" => {
            mint["nip87_ref"]["address"] =
                Value::String(format!("38173:{}:mint-announce-1", "3".repeat(64)))
        }
        "nip87_bad_event_id" => mint["nip87_ref"]["event_id"] = Value::String("not-hex".into()),
        "discovery_mint_url" => {
            mint["mint_url"] = Value::String("https://mint.example.invalid".into())
        }
        "json_number_amount" => mint["sides"]["mint"]["min"] = Value::from(1000),
        "disabled_side_min_nonzero" => mint["sides"]["melt"]["max"] = Value::String("0".into()),
        "missing_side" => {
            mint["sides"].as_object_mut().unwrap().remove("melt");
        }
        "min_over_max" => mint["sides"]["mint"]["min"] = Value::String("2000000".into()),
        "operation_side_mismatch" => {
            mint["sides"]["melt"] = json!({ "min": "0", "max": "0" });
        }
        "cashu_withdraw_operation" => {
            mint["operations"] = json!(["mint", "withdraw-lightning"]);
        }
        "ticker_asset" => mint["market"]["base_asset_id"] = Value::String("sat".into()),
        "custody_class_noncustodial" => {
            mint["custody_class"] = Value::String("noncustodial".into())
        }
        "custody_class_rail_mismatch" => {
            mint["custody_class"] = Value::String("a2-federation".into())
        }
        "unknown_member" => mint["display_name"] = Value::String("fixture".into()),
        "credential_burden_unknown" => mint["credential_burden"] = Value::String("basic".into()),
        "gateway_policy_unknown" => mint["gateway_policy"] = Value::String("best-effort".into()),
        "protocol_revisions_empty" => mint["protocol_revisions"] = json!([]),
        "public_invoice_member" => mint["invoice"] = Value::String("fixture".into()),
        "public_invite_value" => {
            mint["market"]["base_asset_id"] = Value::String("fed1qgemfixtureinvite".into())
        }
        "bearer_proof_value" => {
            mint["market"]["base_asset_id"] = Value::String("cashuAeyJmaXh0dXJl".into())
        }
        other => panic!("unknown Offering mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_fedimint_offering(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    let mint = &mut content["mkt_mint"];
    match mutation {
        "fedimint_deposit_enabled" => {
            mint["sides"]["deposit"] = json!({ "min": "1000", "max": "10000" });
        }
        "fedimint_deposit_omitted" => {
            mint["sides"].as_object_mut().unwrap().remove("deposit");
        }
        "fedimint_nip87_cashu_kind" => mint["nip87_ref"]["kind"] = Value::String("38172".into()),
        other => panic!("unknown Fedimint Offering mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_contract(event: &mut Event, mutation: &str) {
    match mutation {
        "wrong_profile" => {
            replace_tag(event, "profile", vec!["profile", "mkt-swp", "1"]);
            return;
        }
        "wrong_profile_version" => {
            replace_tag(event, "profile", vec!["profile", "mkt-mint", "2"]);
            return;
        }
        "expiration_tag" => {
            event
                .tags
                .push(Tag::new(vec!["expiration".into(), "1786000000".into()]));
            return;
        }
        "digest_mismatch" => {
            replace_tag(event, "x", vec!["x", &"0".repeat(64)]);
            return;
        }
        "missing_quote_ref" => {
            event
                .tags
                .retain(|tag| tag.as_slice().get(3).map(String::as_str) != Some("quote"));
            return;
        }
        "unknown_reference" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "6".repeat(64),
                String::new(),
                "evidence".into(),
            ]));
            return;
        }
        "status_tag_forbidden" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "9".repeat(64),
                String::new(),
                "status".into(),
            ]));
            return;
        }
        "alt_mismatch" => {
            replace_tag(event, "alt", vec!["alt", "MKT-MINT contract"]);
            return;
        }
        "rail_unknown" => {
            replace_tag(event, "rail", vec!["rail", "ecash"]);
            return;
        }
        "complementary_role_missing" => {
            replace_tag(event, "p", vec!["p", &"2".repeat(64), "", "requester"]);
            return;
        }
        "self_counterparty" => {
            replace_tag(event, "p", vec!["p", FIXTURE_PUBKEY, "", "provider"]);
            return;
        }
        _ => {}
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    let mint = &mut content["mkt_mint"];
    match mutation {
        "quote_id_mismatch" => mint["contract"]["quote_event_id"] = Value::String("0".repeat(64)),
        "accepted_status_missing_tag" => {
            mint["contract"]["accepted_status_event_id"] = Value::String("9".repeat(64))
        }
        "operation_rail_mismatch" => {
            mint["contract"]["operation"] = Value::String("withdraw-lightning".into())
        }
        "unknown_contract_member" => {
            mint["contract"]["native_endpoint"] = Value::String("fixture".into())
        }
        "signer_role_mismatch" => mint["signer_role"] = Value::String("provider".into()),
        "bearer_secret_member" => mint["secret"] = Value::String("fixture".into()),
        "cashu_token_value" => {
            mint["contract"]["native_quote_id_sha256"] = Value::String("cashuAfixturetoken".into())
        }
        other => panic!("unknown contract mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_private(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    let mint = &mut content["mkt_mint"];
    match mutation {
        "custody_class_noncustodial" => {
            mint["custody_class"] = Value::String("noncustodial".into())
        }
        "custody_class_rail_mismatch" => {
            mint["custody_class"] = Value::String("a2-federation".into())
        }
        "unknown_provenance" => {
            mint["evidence_refs"][0]["provenance"] = Value::String("guaranteed".into())
        }
        "quote_settled_overclaim" => {
            mint["evidence_refs"][0]["provenance"] = Value::String("settled".into())
        }
        "invoice_issued_overclaim" => {
            mint["evidence_refs"][1]["provenance"] = Value::String("issued".into())
        }
        "evidence_unknown_member" => {
            mint["evidence_refs"][0]["endpoint"] = Value::String("fixture".into())
        }
        "bearer_proofs_member" => mint["proofs"] = json!(["fixture"]),
        "blinding_factor_member" => mint["blinding_factor"] = Value::String("00".into()),
        "cashu_token_value" => {
            mint["evidence_refs"][0]["issuer"] = Value::String("cashuBfixture".into())
        }
        other => panic!("unknown private mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_receipt(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-mint", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "invoice_member" => content["invoice"] = Value::String("fixture".into()),
        "invite_value" => content["reference"] = Value::String("fed1qfixtureinvite".into()),
        "mint_url_member" => {
            content["mint_url"] = Value::String("https://mint.example.invalid".into())
        }
        other => panic!("unknown receipt mutation {other}"),
    }
    event.content = content.to_string();
}

fn case_pair(value: &Value) -> (&str, &str) {
    let value = value.as_array().unwrap();
    (value[0].as_str().unwrap(), value[1].as_str().unwrap())
}

fn replace_tag(event: &mut Event, name: &str, values: Vec<&str>) {
    let tag = event
        .tags
        .iter_mut()
        .find(|tag| tag.name() == Some(name))
        .unwrap();
    tag.0 = values.into_iter().map(str::to_owned).collect();
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/mint-profile-v1.json"
    ))
    .unwrap()
}
