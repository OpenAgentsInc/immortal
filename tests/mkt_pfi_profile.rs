use std::collections::BTreeSet;

use immortal::domain::{
    Event, MKT_PFI_PROFILE_ID, MKT_PFI_PROFILE_VERSION, MKT_PFI_QUALIFICATION_POLICY_KIND,
    MktProfileSupport, Tag, validate_mkt_pfi_evidence_reference,
    validate_mkt_private_with_profiles, validate_mkt_public_event,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn mkt_pfi_fixture_manifest_is_complete_and_explicitly_scoped() {
    let fixture = fixture();
    assert_eq!(fixture["source"]["profile"], MKT_PFI_PROFILE_ID);
    assert_eq!(fixture["source"]["version"], MKT_PFI_PROFILE_VERSION);
    assert_eq!(
        fixture["source"]["qualification_policy_kind"],
        MKT_PFI_QUALIFICATION_POLICY_KIND
    );
    assert_eq!(fixture["client_only_requirements"]["relay_enforced"], false);

    let cases = fixture["upstream_fixture_manifest"].as_array().unwrap();
    let unique = cases
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 41);
    assert_eq!(unique.len(), cases.len());
    for required in [
        "pfi-v1/positive-qualification-policy.json",
        "pfi-v1/negative-credential-before-quote.json",
        "pfi-v1/privacy-public-policy-pii.json",
        "pfi-v1/gap-provider-status-sequence.json",
        "pfi-v1/fork-provider-status-sequence.json",
        "pfi-v1/recovery-relay-and-api-down-complete.json",
        "pfi-v1/recovery-late-chargeback.json",
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
fn mkt_pfi_qualification_policy_is_closed_digest_bound_and_public_safe() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["qualification_policy"]);
    assert_eq!(base.kind, MKT_PFI_QUALIFICATION_POLICY_KIND);
    assert_eq!(validate_mkt_public_event(&base), Ok(()));

    for (mutation, expected_code) in fixture["relay_observable"]["public_policy_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_policy(&mut event, mutation);
        let error = validate_mkt_public_event(&event).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_pfi_offering_binds_assets_market_policy_limits_risk_and_rails() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["offering"]);
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
fn mkt_pfi_private_observable_subset_is_commitment_only_and_bounded() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["private_record"]);
    assert!(validate_mkt_private_with_profiles(&base, &[pfi_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["private_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_private(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[pfi_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }

    let content = serde_json::from_str::<Value>(&base.content).unwrap();
    let evidence = &content["mkt_pfi"]["evidence_refs"][0];
    assert_eq!(validate_mkt_pfi_evidence_reference(evidence), Ok(()));
}

#[test]
fn mkt_pfi_public_receipt_is_redacted_and_non_bearer() {
    let fixture = fixture();
    let mut receipt = Event {
        id: "0".repeat(64),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 1,
        kind: 39_603,
        tags: vec![
            Tag::new(vec!["d".into(), "receipt-pfi".into()]),
            Tag::new(vec!["profile".into(), "mkt-pfi".into(), "1".into()]),
            Tag::new(vec!["outcome".into(), "completed".into()]),
            Tag::new(vec!["x".into(), "a".repeat(64)]),
            Tag::new(vec!["role".into(), "provider".into()]),
        ],
        content: "{}".into(),
        sig: "0".repeat(128),
    };
    assert_eq!(validate_mkt_public_event(&receipt), Ok(()));

    for (mutation, expected_code) in fixture["relay_observable"]["public_receipt_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        mutate_receipt(&mut receipt, mutation);
        let error = validate_mkt_public_event(&receipt).unwrap_err();
        assert!(
            error.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
        receipt = Event {
            tags: vec![
                Tag::new(vec!["d".into(), "receipt-pfi".into()]),
                Tag::new(vec!["profile".into(), "mkt-pfi".into(), "1".into()]),
                Tag::new(vec!["outcome".into(), "completed".into()]),
                Tag::new(vec!["x".into(), "a".repeat(64)]),
                Tag::new(vec!["role".into(), "provider".into()]),
            ],
            content: "{}".into(),
            ..receipt
        };
    }
}

fn pfi_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_PFI_PROFILE_ID,
        version: MKT_PFI_PROFILE_VERSION,
        critical_members: &["mkt_pfi"],
        understood_members: &["mkt_pfi"],
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

fn mutate_policy(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-pfi", "2"]);
        return;
    }
    if mutation == "digest_mismatch" {
        replace_tag(event, "x", vec!["x", &"0".repeat(64)]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "unknown_member" => content["free_form"] = Value::String("fixture".into()),
        "public_pii_member" => content["full_name"] = Value::String("fixture-subject".into()),
        "public_pii_camel" => content["fullName"] = Value::String("fixture-subject".into()),
        "bearer_url" => {
            content["retention"]["deletion_request_url"] = Value::String(
                "https://provider.example.invalid/privacy?access_token=fixture".into(),
            )
        }
        "credential_stage" => {
            content["requirements"][0]["presentation_stage"] = Value::String("pre_quote".into())
        }
        other => panic!("unknown policy mutation {other}"),
    }
    event.content = content.to_string();
    replace_tag(event, "x", vec!["x", &sha256_hex(event.content.as_bytes())]);
}

fn mutate_offering(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "ticker_asset" => content["pfi"]["fiat_asset"]["asset_id"] = Value::String("USD".into()),
        "market_mismatch" => content["pfi"]["market_id"] = Value::String("0".repeat(64)),
        "json_number_amount" => content["pfi"]["on_ramp"]["min"] = Value::from(1000),
        "disabled_side_min_nonzero" => content["pfi"]["on_ramp"]["max"] = Value::String("0".into()),
        "fee_over_10000" => content["pfi"]["fee_bps"] = Value::String("10001".into()),
        "policy_event_mismatch" => {
            content["pfi"]["qualification_policy_event_id"] = Value::String("0".repeat(64))
        }
        "unknown_member" => content["pfi"]["display_name"] = Value::String("fixture".into()),
        "public_pii_member" => content["pfi"]["account_number"] = Value::String("fixture".into()),
        "bearer_url" => {
            content["pfi"]["crypto_asset"]["unit_registry_ref"] =
                Value::String("https://registry.example.invalid/assets?token=fixture".into())
        }
        other => panic!("unknown Offering mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_private(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "presentation_bytes" => {
            content["mkt_pfi"]["presentation_bytes"] = Value::String("fixture".into())
        }
        "camel_presentation_bytes" => {
            content["mkt_pfi"]["credentialPresentationBytes"] = Value::String("fixture".into())
        }
        "bearer_reference" => {
            content["mkt_pfi"]["evidence_refs"][0]["external_operation_ref"] =
                Value::String("https://evidence.example.invalid/get?token=fixture".into())
        }
        "nwc_value" => content["mkt_pfi"]["opaque_ref"] = Value::String("nwc:fixture".into()),
        "unknown_risk" => {
            content["mkt_pfi"]["risk_classification"] = Value::String("trusted".into())
        }
        "unknown_evidence" => {
            content["mkt_pfi"]["evidence_refs"][0]["evidence_class"] =
                Value::String("provider_database".into())
        }
        "unknown_commitment_member" => {
            content["mkt_pfi"]["credential_commitments"][0]["subject"] =
                Value::String("fixture".into())
        }
        "unknown_dispute_member" => {
            content["mkt_pfi"]["dispute"]["narrative_ref"] = Value::String("fixture".into())
        }
        "unknown_recourse_member" => {
            content["mkt_pfi"]["recourse"]["score"] = Value::String("fixture".into())
        }
        other => panic!("unknown private mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_receipt(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-pfi", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "market" => content["market"] = Value::String("0".repeat(64)),
        "credential_fact" => content["qualification_decision"] = Value::String("accepted".into()),
        "bearer_reference" => {
            content["public_safe_evidence_reference"] =
                Value::String("https://evidence.example.invalid/get?token=fixture".into())
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipmkt/pfi-profile-v1.json")).unwrap()
}
