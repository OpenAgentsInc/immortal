use std::collections::BTreeSet;

use immortal_core::domain::{
    Event, MKT_LSP_PROFILE_ID, MKT_LSP_PROFILE_VERSION, MKT_LSP_SERVICE_CONTRACT_KIND,
    MktProfileSupport, Tag, validate_mkt_lsp_source_reference, validate_mkt_private_with_profiles,
    validate_mkt_public_event,
};
use serde_json::Value;

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn mkt_lsp_fixture_manifest_is_complete_and_explicitly_scoped() {
    let fixture = fixture();
    assert_eq!(fixture["source"]["profile"], MKT_LSP_PROFILE_ID);
    assert_eq!(fixture["source"]["version"], MKT_LSP_PROFILE_VERSION);
    assert_eq!(
        fixture["source"]["service_contract_kind"],
        MKT_LSP_SERVICE_CONTRACT_KIND
    );
    assert_eq!(fixture["client_only_requirements"]["relay_enforced"], false);

    let cases = fixture["upstream_fixture_manifest"].as_array().unwrap();
    let unique = cases
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 30);
    assert_eq!(unique.len(), cases.len());
    for required in [
        "lsp-positive-lsps1-channel-purchase",
        "lsp-positive-lsps2-jit",
        "lsp-positive-service-contract",
        "lsp-positive-unilateral-close",
        "lsp-negative-client-trusts-lsp",
        "lsp-negative-prepaid-no-refund",
        "lsp-negative-custody-material",
        "lsp-replay-contract-conflict",
        "lsp-recovery-keyless-exit-executor",
        "lsp-loss-chain-reorg",
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
fn mkt_lsp_offering_binds_node_market_sides_terms_and_privacy() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["relay_observable"]["offering"], FIXTURE_PUBKEY);
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
fn mkt_lsp_service_contract_grammar_is_causal_digest_and_signer_bound() {
    let fixture = fixture();
    let firm = event_from_fixture(
        &fixture["relay_observable"]["service_contract"],
        FIXTURE_PUBKEY,
    );
    assert_eq!(firm.kind, MKT_LSP_SERVICE_CONTRACT_KIND);
    assert!(validate_mkt_private_with_profiles(&firm, &[lsp_support()]).is_ok());
    let indicative = event_from_fixture(
        &fixture["relay_observable"]["indicative_contract"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&indicative, &[lsp_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["contract_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = firm.clone();
        mutate_contract(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[lsp_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
    for (mutation, expected_code) in fixture["relay_observable"]["indicative_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = indicative.clone();
        mutate_contract(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[lsp_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_lsp_source_reference_preserves_lsps_authority_without_upgrade() {
    let fixture = fixture();
    let base = event_from_fixture(
        &fixture["relay_observable"]["quote_with_source"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&base, &[lsp_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["source_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_source(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[lsp_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }

    let content = serde_json::from_str::<Value>(&base.content).unwrap();
    assert_eq!(
        validate_mkt_lsp_source_reference(&content["source"]),
        Ok(())
    );
}

#[test]
fn mkt_lsp_status_states_are_the_exact_admitted_set() {
    let fixture = fixture();
    let base = event_from_fixture(
        &fixture["relay_observable"]["status_extension"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&base, &[lsp_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["status_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        match mutation {
            "base_state_not_admitted" => {
                replace_tag(&mut event, "state", vec!["state", "executing"]);
            }
            "unknown_state" => {
                replace_tag(&mut event, "state", vec!["state", "channel-open"]);
            }
            "custody_class_mismatch" => {
                let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
                content["custody_class"] = Value::String("a3-mint".into());
                event.content = content.to_string();
            }
            other => panic!("unknown status mutation {other}"),
        }
        let error = validate_mkt_private_with_profiles(&event, &[lsp_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_lsp_public_receipt_is_redacted_and_outcome_only() {
    let fixture = fixture();
    let mut receipt = Event {
        id: "0".repeat(64),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 1,
        kind: 39_603,
        tags: receipt_tags(),
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
            tags: receipt_tags(),
            content: "{}".into(),
            ..receipt
        };
    }
}

fn receipt_tags() -> Vec<Tag> {
    vec![
        Tag::new(vec!["d".into(), "receipt-lsp".into()]),
        Tag::new(vec!["profile".into(), "mkt-lsp".into(), "1".into()]),
        Tag::new(vec!["outcome".into(), "completed".into()]),
        Tag::new(vec!["x".into(), "a".repeat(64)]),
        Tag::new(vec!["role".into(), "provider".into()]),
    ]
}

fn lsp_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_LSP_PROFILE_ID,
        version: MKT_LSP_PROFILE_VERSION,
        critical_members: &["contract", "contract_sha256", "signer_role", "source"],
        understood_members: &["contract", "contract_sha256", "signer_role", "source"],
    }
}

fn event_from_fixture(value: &Value, pubkey: &str) -> Event {
    Event {
        id: "0".repeat(64),
        pubkey: pubkey.to_owned(),
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
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-lsp", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "node_id_invalid" => content["lsp_node_id"] = Value::String("abcdef".into()),
        "network_label" => content["network_id"] = Value::String("mainnet".into()),
        "ticker_asset" => content["market"]["quote_asset_id"] = Value::String("BTC".into()),
        "unknown_market_member" => {
            content["market"]["display_ticker"] = Value::String("BTCCAP".into())
        }
        "json_number_amount" => content["sides"]["channel-purchase"]["min"] = Value::from(50_000),
        "disabled_side_min_nonzero" => {
            content["sides"]["jit-inbound"] = serde_json::json!({ "min": "5", "max": "0" })
        }
        "inverted_range" => {
            content["sides"]["channel-purchase"] =
                serde_json::json!({ "min": "100000000", "max": "50000" })
        }
        "missing_side" => {
            content["sides"]
                .as_object_mut()
                .unwrap()
                .remove("jit-inbound");
        }
        "lsps_unbounded" => content["lsps"] = Value::String("lsps1".into()),
        "channel_types_shape" => content["channel_types"] = serde_json::json!([]),
        "zero_conf_policy_unknown" => content["zero_conf_policy"] = Value::String("always".into()),
        "lease_bounds_shape" => content["lease_bounds"] = serde_json::json!({}),
        "lease_bound_not_decimal" => content["lease_bounds"]["min_blocks"] = Value::from(4_320),
        "payment_method_unknown" => content["payment_methods"] = serde_json::json!(["fiat-wire"]),
        "custody_class_unknown" => content["custody_class"] = Value::String("a3-mint".into()),
        "reservation_class_unknown" => {
            content["reservation_proof_classes"] = serde_json::json!(["lsp-promise"])
        }
        "public_invoice_member" => content["invoice"] = Value::String("lnbcfixture".into()),
        "public_scid_member" => content["scid"] = Value::String("871840x20x1".into()),
        "public_macaroon_member" => content["macaroon"] = Value::String("fixture".into()),
        "public_invoice_value" => {
            content["fee_policy_note"] = Value::String("lnbc10u1pfixturefixturefixture".into())
        }
        other => panic!("unknown Offering mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_contract(event: &mut Event, mutation: &str) {
    match mutation {
        "wrong_profile" => {
            replace_tag(event, "profile", vec!["profile", "mkt-swp", "1"]);
            return;
        }
        "wrong_version" => {
            replace_tag(event, "profile", vec!["profile", "mkt-lsp", "2"]);
            return;
        }
        "alt_mismatch" => {
            replace_tag(event, "alt", vec!["alt", "MKT-LSP contract"]);
            return;
        }
        "role_unknown" => {
            replace_tag(event, "role", vec!["role", "arbiter"]);
            return;
        }
        "two_counterparties" => {
            event.tags.push(Tag::new(vec![
                "p".into(),
                "3".repeat(64),
                String::new(),
                "requester".into(),
            ]));
            return;
        }
        "same_role_counterparty" => {
            let role = single_tag_value(event, "role");
            let tag = event
                .tags
                .iter_mut()
                .find(|tag| tag.name() == Some("p"))
                .unwrap();
            let pubkey = tag.as_slice()[1].clone();
            tag.0 = vec!["p".into(), pubkey, String::new(), role];
            return;
        }
        "self_counterparty" => {
            let tag = event
                .tags
                .iter_mut()
                .find(|tag| tag.name() == Some("p"))
                .unwrap();
            let marker = tag.as_slice()[3].clone();
            tag.0 = vec!["p".into(), event.pubkey.clone(), String::new(), marker];
            return;
        }
        "expiration_tag" => {
            event
                .tags
                .push(Tag::new(vec!["expiration".into(), "1785862800".into()]));
            return;
        }
        "duplicate_quote_ref" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "9".repeat(64),
                String::new(),
                "quote".into(),
            ]));
            return;
        }
        "missing_order_ref" => {
            event
                .tags
                .retain(|tag| tag.as_slice().get(3).map(String::as_str) != Some("order"));
            return;
        }
        "unknown_event_reference" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "9".repeat(64),
                String::new(),
                "evidence".into(),
            ]));
            return;
        }
        "firm_with_status_tag" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "abababababababababababababababababababababababababababababababab".into(),
                String::new(),
                "status".into(),
            ]));
            return;
        }
        "null_with_status_tag" => {}
        _ => {}
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "unknown_content_member" => content["note"] = Value::String("fixture".into()),
        "unknown_contract_member" => content["contract"]["promise"] = Value::String("jit".into()),
        "service_shape" => content["contract"]["service"] = Value::String("LSPS1 Channel".into()),
        "signer_role_mismatch" => {
            let flipped = if content["signer_role"] == "provider" {
                "requester"
            } else {
                "provider"
            };
            content["signer_role"] = Value::String(flipped.into());
        }
        "digest_tag_mismatch" => content["contract_sha256"] = Value::String("9".repeat(64)),
        "digest_invalid" => {
            content["contract"]["lsps_request_sha256"] = Value::String("not-hex".into())
        }
        "quote_id_mismatch" => {
            content["contract"]["quote_event_id"] = Value::String("9".repeat(64))
        }
        "accepted_status_shape" => content["contract"]["accepted_status_event_id"] = Value::from(5),
        "status_id_mismatch" => {
            content["contract"]["accepted_status_event_id"] = Value::String("9".repeat(64))
        }
        "null_with_status_tag" => content["contract"]["accepted_status_event_id"] = Value::Null,
        "custody_material" => content["macaroon"] = Value::String("fixture".into()),
        other => panic!("unknown Service Contract mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_source(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "source_not_object" => content["source"] = Value::String("lsps1".into()),
        "protocol_unknown" => content["source"]["protocol"] = Value::String("lnd-rest".into()),
        "mapping_version_unknown" => {
            content["source"]["mapping_version"] = Value::String("mkt-lsp-v2".into())
        }
        "request_digest_invalid" => {
            content["source"]["request_sha256"] = Value::String("order-77".into())
        }
        "unknown_source_member" => {
            content["source"]["upgraded_signature"] = Value::String("fixture".into())
        }
        "method_shape" => content["source"]["method"] = Value::from(12),
        other => panic!("unknown source mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_receipt(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-lsp", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "invoice_member" => content["invoice"] = Value::String("lnbcfixture".into()),
        "payment_hash_member" => content["payment_hash"] = Value::String("a".repeat(64)),
        "scid_member" => content["scid"] = Value::String("871840x20x1".into()),
        "coupon_member" => content["coupon"] = Value::String("fixture".into()),
        "invoice_value" => {
            content["settlement_note"] = Value::String("lnbc10u1pfixturefixturefixture".into())
        }
        other => panic!("unknown receipt mutation {other}"),
    }
    event.content = content.to_string();
}

fn case_pair(value: &Value) -> (&str, &str) {
    let value = value.as_array().unwrap();
    (value[0].as_str().unwrap(), value[1].as_str().unwrap())
}

fn single_tag_value(event: &Event, name: &str) -> String {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == Some(name))
        .unwrap()
        .as_slice()[1]
        .clone()
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
        "../../../tests/fixtures/nipmkt/lsp-profile-v1.json"
    ))
    .unwrap()
}
