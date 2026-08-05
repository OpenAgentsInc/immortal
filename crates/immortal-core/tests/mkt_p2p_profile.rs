use std::collections::BTreeSet;

use immortal_core::domain::{
    Event, MKT_P2P_PROFILE_ID, MKT_P2P_PROFILE_VERSION, MKT_P2P_RESOLUTION_KIND, MktProfileSupport,
    Tag, validate_mkt_p2p_resolution_evidence, validate_mkt_p2p_source_reference,
    validate_mkt_private_with_profiles, validate_mkt_public_event,
};
use serde_json::Value;

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn mkt_p2p_fixture_manifest_is_complete_and_explicitly_scoped() {
    let fixture = fixture();
    assert_eq!(fixture["source"]["profile"], MKT_P2P_PROFILE_ID);
    assert_eq!(fixture["source"]["version"], MKT_P2P_PROFILE_VERSION);
    assert_eq!(
        fixture["source"]["resolution_kind"],
        MKT_P2P_RESOLUTION_KIND
    );
    assert_eq!(fixture["client_only_requirements"]["relay_enforced"], false);

    let cases = fixture["upstream_fixture_manifest"].as_array().unwrap();
    let unique = cases
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 26);
    assert_eq!(unique.len(), cases.len());
    for required in [
        "p2p-positive-fixed-complete",
        "p2p-positive-nip69-reference",
        "p2p-positive-per-trade-keys",
        "p2p-negative-nip69-silent-upgrade",
        "p2p-negative-no-independent-exit",
        "p2p-replay-resolution-conflict",
        "p2p-fork-resolution",
        "p2p-recovery-coordinator-gone-after-fiat",
        "p2p-loss-external-chargeback",
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
fn mkt_p2p_offering_binds_market_sides_bridge_custody_and_privacy() {
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
fn mkt_p2p_resolution_grammar_is_role_previous_and_policy_bound() {
    let fixture = fixture();
    let initial = event_from_fixture(&fixture["relay_observable"]["resolution"], FIXTURE_PUBKEY);
    assert_eq!(initial.kind, MKT_P2P_RESOLUTION_KIND);
    assert!(validate_mkt_private_with_profiles(&initial, &[p2p_support()]).is_ok());
    let appeal = event_from_fixture(&fixture["relay_observable"]["appeal"], FIXTURE_PUBKEY);
    assert!(validate_mkt_private_with_profiles(&appeal, &[p2p_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["resolution_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = initial.clone();
        mutate_resolution(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[p2p_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
    for (mutation, expected_code) in fixture["relay_observable"]["appeal_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = appeal.clone();
        mutate_resolution(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[p2p_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }

    let content = serde_json::from_str::<Value>(&initial.content).unwrap();
    let evidence = &content["resolution"]["evidence"][0];
    assert_eq!(validate_mkt_p2p_resolution_evidence(evidence), Ok(()));
}

#[test]
fn mkt_p2p_source_reference_preserves_nip69_authority_without_upgrade() {
    let fixture = fixture();
    let base = event_from_fixture(
        &fixture["relay_observable"]["rfq_with_source"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&base, &[p2p_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["source_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        mutate_source(&mut event, mutation);
        let error = validate_mkt_private_with_profiles(&event, &[p2p_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }

    let content = serde_json::from_str::<Value>(&base.content).unwrap();
    assert_eq!(
        validate_mkt_p2p_source_reference(&content["source"]),
        Ok(())
    );
}

#[test]
fn mkt_p2p_status_states_are_the_exact_admitted_set() {
    let fixture = fixture();
    let base = event_from_fixture(
        &fixture["relay_observable"]["status_extension"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&base, &[p2p_support()]).is_ok());

    for (mutation, expected_code) in fixture["relay_observable"]["status_errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(case_pair)
    {
        let mut event = base.clone();
        let state = match mutation {
            "base_state_not_admitted" => "executing",
            "unknown_state" => "fiat-received",
            other => panic!("unknown status mutation {other}"),
        };
        replace_tag(&mut event, "state", vec!["state", state]);
        let error = validate_mkt_private_with_profiles(&event, &[p2p_support()]).unwrap_err();
        assert!(
            error.detail.starts_with(expected_code),
            "{mutation}: expected {expected_code}, got {error}"
        );
    }
}

#[test]
fn mkt_p2p_per_trade_keys_require_no_identity_linkage() {
    let fixture = fixture();
    let keys = &fixture["relay_observable"]["per_trade_keys"];
    let first = event_from_fixture(
        &fixture["relay_observable"]["rfq_with_source"],
        FIXTURE_PUBKEY,
    );
    assert!(validate_mkt_private_with_profiles(&first, &[p2p_support()]).is_ok());

    // A second session under a fresh trade key validates with no member
    // linking it to the first key or to a long-lived identity.
    let mut second = event_from_fixture(
        &fixture["relay_observable"]["rfq_with_source"],
        keys["second_pubkey"].as_str().unwrap(),
    );
    let session = keys["second_session"].as_str().unwrap();
    replace_tag(
        &mut second,
        "d",
        vec!["d", keys["second_d"].as_str().unwrap()],
    );
    replace_tag(&mut second, "session", vec!["session", session]);
    let mut content = serde_json::from_str::<Value>(&second.content).unwrap();
    content["session_id"] = Value::String(session.to_owned());
    second.content = content.to_string();
    assert!(validate_mkt_private_with_profiles(&second, &[p2p_support()]).is_ok());

    // The public surface refuses trade-key linkage members outright.
    let offering = event_from_fixture(&fixture["relay_observable"]["offering"], FIXTURE_PUBKEY);
    let mut linked = offering.clone();
    let mut content = serde_json::from_str::<Value>(&linked.content).unwrap();
    content["identity_link"] = Value::String(FIXTURE_PUBKEY.into());
    linked.content = content.to_string();
    let error = validate_mkt_public_event(&linked).unwrap_err();
    assert!(error.starts_with("mkt_p2p_private_data_public"), "{error}");
}

#[test]
fn mkt_p2p_public_receipt_is_redacted_and_outcome_only() {
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
        Tag::new(vec!["d".into(), "receipt-p2p".into()]),
        Tag::new(vec!["profile".into(), "mkt-p2p".into(), "1".into()]),
        Tag::new(vec!["outcome".into(), "completed".into()]),
        Tag::new(vec!["x".into(), "a".repeat(64)]),
        Tag::new(vec!["role".into(), "provider".into()]),
    ]
}

fn p2p_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_P2P_PROFILE_ID,
        version: MKT_P2P_PROFILE_VERSION,
        critical_members: &["resolution", "loss", "source"],
        understood_members: &["resolution", "loss", "source"],
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
        replace_tag(event, "profile", vec!["profile", "mkt-p2p", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "ticker_asset" => content["market"]["quote_asset_id"] = Value::String("USD".into()),
        "unknown_market_member" => {
            content["market"]["display_ticker"] = Value::String("BTCUSD".into())
        }
        "json_number_amount" => content["sides"]["sell"]["min"] = Value::from(10_000),
        "disabled_side_min_nonzero" => {
            content["sides"]["buy"] = serde_json::json!({ "min": "5", "max": "0" })
        }
        "inverted_range" => {
            content["sides"]["sell"] = serde_json::json!({ "min": "1000000", "max": "10000" })
        }
        "amount_mode_unknown" => content["amount_mode"] = Value::String("market".into()),
        "nip69_unbounded" => content["nip69"] = Value::String("38383".into()),
        "custody_class_unknown" => {
            content["custody_class"] = Value::String("mostro-native-hold".into())
        }
        "bond_policy_shape" => content["bond_policy"] = Value::from(200),
        "dispute_digest_invalid" => {
            content["dispute_policy_digest"] = Value::String("not-a-digest".into())
        }
        "public_pii_member" => content["phone_number"] = Value::String("fixture".into()),
        "public_invoice_member" => content["invoice"] = Value::String("lnbcfixture".into()),
        other => panic!("unknown Offering mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_resolution(event: &mut Event, mutation: &str) {
    match mutation {
        "wrong_profile" => {
            replace_tag(event, "profile", vec!["profile", "mkt-swp", "1"]);
            return;
        }
        "wrong_version" => {
            replace_tag(event, "profile", vec!["profile", "mkt-p2p", "2"]);
            return;
        }
        "alt_mismatch" => {
            replace_tag(event, "alt", vec!["alt", "MKT-P2P decision"]);
            return;
        }
        "role_unknown" => {
            replace_tag(event, "role", vec!["role", "mediator"]);
            return;
        }
        "two_order_refs" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "9".repeat(64),
                String::new(),
                "order".into(),
            ]));
            return;
        }
        "unmarked_recipient" => {
            event.tags.push(Tag::new(vec!["p".into(), "6".repeat(64)]));
            return;
        }
        "missing_coordinator" => {
            event
                .tags
                .retain(|tag| tag.as_slice().get(3).map(String::as_str) != Some("coordinator"));
            return;
        }
        "author_role_missing" => {
            event.tags.retain(|tag| {
                tag.name() != Some("p")
                    || tag.as_slice().get(1).map(String::as_str) != Some(FIXTURE_PUBKEY)
            });
            return;
        }
        "initial_with_previous_tag" => {
            event.tags.push(Tag::new(vec![
                "e".into(),
                "abababababababababababababababababababababababababababababababab".into(),
                String::new(),
                "previous".into(),
            ]));
            return;
        }
        "appeal_role_solver" => {
            replace_tag(event, "role", vec!["role", "solver"]);
            let tag = event
                .tags
                .iter_mut()
                .find(|tag| {
                    tag.name() == Some("p")
                        && tag.as_slice().get(1).map(String::as_str) == Some(FIXTURE_PUBKEY)
                })
                .unwrap();
            tag.0 = vec![
                "p".into(),
                FIXTURE_PUBKEY.into(),
                String::new(),
                "solver".into(),
            ];
            return;
        }
        _ => {}
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "unknown_content_member" => content["note"] = Value::String("fixture".into()),
        "unknown_resolution_member" => {
            content["resolution"]["settlement_txid"] = Value::String("0".repeat(64))
        }
        "decision_unknown" => {
            content["resolution"]["decision"] = Value::String("split-funds".into())
        }
        "scope_unknown" => content["resolution"]["scope"] = Value::String("reputation".into()),
        "policy_digest_invalid" => {
            content["resolution"]["policy_sha256"] = Value::String("policy".into())
        }
        "evidence_provenance" => {
            content["resolution"]["evidence"] = serde_json::json!([{
                "ref": "d".repeat(64),
                "sha256": "e".repeat(64),
                "provenance": "guaranteed"
            }])
        }
        "evidence_bearer_ref" => {
            content["resolution"]["evidence"] = serde_json::json!([{
                "ref": "https://evidence.example.invalid/get?token=fixture",
                "sha256": "e".repeat(64),
                "provenance": "verified"
            }])
        }
        "appeal_previous_mismatch" => {
            content["resolution"]["previous_resolution_event_id"] = Value::String("9".repeat(64))
        }
        other => panic!("unknown Resolution mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_source(event: &mut Event, mutation: &str) {
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "source_not_object" => content["source"] = Value::String("nip-69".into()),
        "protocol_unknown" => content["source"]["protocol"] = Value::String("robosats".into()),
        "mapping_version_unknown" => {
            content["source"]["mapping_version"] = Value::String("mkt-p2p-v2".into())
        }
        "event_id_invalid" => content["source"]["event_id"] = Value::String("nevent1".into()),
        "unknown_source_member" => {
            content["source"]["upgraded_signature"] = Value::String("fixture".into())
        }
        "dropped_fields_shape" => {
            content["source"]["dropped_fields"] = Value::String("premium".into())
        }
        other => panic!("unknown source mutation {other}"),
    }
    event.content = content.to_string();
}

fn mutate_receipt(event: &mut Event, mutation: &str) {
    if mutation == "wrong_version" {
        replace_tag(event, "profile", vec!["profile", "mkt-p2p", "2"]);
        return;
    }
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    match mutation {
        "session_member" => content["session_id"] = Value::String("9".repeat(64)),
        "amount_member" => content["amount"] = Value::String("10000".into()),
        "invoice_member" => content["invoice"] = Value::String("lnbcfixture".into()),
        "trade_key_linkage" => content["identity_link"] = Value::String("1".repeat(64)),
        "dispute_evidence" => content["evidence"] = serde_json::json!(["fixture"]),
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
        "../../../tests/fixtures/nipmkt/p2p-profile-v1.json"
    ))
    .unwrap()
}
