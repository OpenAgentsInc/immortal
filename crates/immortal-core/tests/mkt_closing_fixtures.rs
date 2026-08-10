use std::collections::BTreeSet;

use immortal_core::domain::{
    Event, EventClass, MktImmutableDecision, MktProfileSupport, MktValidationCode, Tag,
    decide_mkt_immutable_admission, is_mkt_private_kind, validate_mkt_private_base,
    validate_mkt_private_with_profiles,
};
use serde_json::Value;

const MKT_BASE_COMMIT: &str = "b839dd43bad7915a35639b562d4d7ebf7d51c3f6";
// The boundary corpus pins the OpenAgents revision whose MKT.md kind
// allocation table it reproduces (v0.3: SWP 39610, P2P 39620, PFI 39630).
const MKT_ALLOCATION_COMMIT: &str = "006b35b1f428a2e2a18931ff1546e5a09a8f8961";

#[test]
fn nipmkt_relay_closing_corpus_pins_every_observable_boundary() {
    let fixture = relay_fixture();
    assert_eq!(fixture["source"]["commit"], MKT_ALLOCATION_COMMIT);

    let base = event_from_fixture(&fixture["private_base"]);
    assert!(validate_mkt_private_base(&base).is_ok());
    for case in fixture["validation_cases"].as_array().unwrap() {
        let mut event = base.clone();
        match case["id"].as_str().unwrap() {
            "malformed-missing-alt" => event
                .tags
                .retain(|tag| tag.0.first().map(String::as_str) != Some("alt")),
            "duplicate-json-member" => {
                event.content = case["input"]["content"].as_str().unwrap().to_owned();
            }
            "unsupported-profile" => {
                replace_profile(&mut event, "unknown", 1);
                let error =
                    validate_mkt_private_with_profiles(&event, &[profile_support()]).unwrap_err();
                assert_eq!(error.code, MktValidationCode::UnsupportedProfile);
                continue;
            }
            "unsupported-profile-version" => {
                replace_profile(&mut event, "conformance", 2);
                let error =
                    validate_mkt_private_with_profiles(&event, &[profile_support()]).unwrap_err();
                assert_eq!(error.code, MktValidationCode::UnsupportedProfileVersion);
                continue;
            }
            id => panic!("unknown closing validation case {id}"),
        }
        let error = validate_mkt_private_base(&event).unwrap_err();
        assert_eq!(
            error.code.as_str(),
            case["expected"]["code"].as_str().unwrap()
        );
    }

    let immutable = &fixture["immutable_changed_bytes"];
    let stored = &immutable["stored"];
    assert_eq!(
        decide_mkt_immutable_admission(
            Some((
                stored["id"].as_str().unwrap(),
                stored["sig"].as_str().unwrap()
            )),
            immutable["replay"]["id"].as_str().unwrap(),
            immutable["replay"]["sig"].as_str().unwrap(),
        ),
        MktImmutableDecision::Replay
    );
    assert_eq!(
        decide_mkt_immutable_admission(
            Some((
                stored["id"].as_str().unwrap(),
                stored["sig"].as_str().unwrap()
            )),
            immutable["changed"]["id"].as_str().unwrap(),
            immutable["changed"]["sig"].as_str().unwrap(),
        ),
        MktImmutableDecision::Conflict
    );

    assert_eq!(
        fixture["bare_private"]["kinds"],
        serde_json::json!([
            39604, 39605, 39606, 39607, 39608, 39609, 39610, 39611, 39612, 39640
        ])
    );
    assert_eq!(
        fixture["rewrapped_same_inner"]["expected"]["relay"],
        "store_both_distinct_outer_events"
    );
    assert_eq!(
        fixture["rewrapped_same_inner"]["expected"]["logical_records"],
        1
    );
    assert!(
        fixture["expiration_at_now"]
            .as_array()
            .unwrap()
            .iter()
            .any(|case| { case["id"] == "inner-order" && case["scope"] == "client_only" })
    );

    for range in fixture["classification"].as_array().unwrap() {
        let first = u16::try_from(range["first"].as_u64().unwrap()).unwrap();
        let last = u16::try_from(range["last"].as_u64().unwrap()).unwrap();
        for kind in first..=last {
            assert_eq!(EventClass::from_kind(kind), EventClass::Addressable);
            assert_eq!(
                is_mkt_private_kind(kind),
                (39_604..=39_612).contains(&kind)
                    || kind == 39_620
                    || kind == 39_640
                    || kind == 39_650
            );
        }
    }
    assert_eq!(
        fixture["classification"][3]["allocation"],
        "private_mkt_swp_hardening"
    );
}

#[test]
fn nipmkt_receipt_fixture_pins_the_versioned_event_only_contract() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/receipt-v1.json"
    ))
    .expect("receipt fixture");
    assert_eq!(fixture["wire_envelope"], "openagents.mkt.v2");
    assert_eq!(fixture["protocol_revision"], 2);
    assert_eq!(fixture["receipt_schema"], "openagents.mkt.receipt.v1");
    assert_eq!(fixture["receipt_version"], 1);
    assert_eq!(fixture["kind"], 39_613);
    assert_eq!(fixture["maximum_legs"], 8);
    assert_eq!(fixture["maximum_fees"], 16);
    assert_eq!(fixture["cases"].as_array().expect("cases").len(), 20);
}

#[test]
fn nipmkt_client_only_manifest_is_structured_and_explicitly_not_relay_enforced() {
    let fixture = client_fixture();
    assert_eq!(fixture["source"]["commit"], MKT_BASE_COMMIT);
    assert_eq!(fixture["enforcement"], "client_only_not_relay_enforced");

    let required = BTreeSet::from([
        "double-reservation",
        "evidence-mismatch",
        "expired-order",
        "quote-supersession",
        "recovery-loss",
        "rewrapped-inner-deduplication",
        "settlement-overclaim",
        "status-sequence-fork",
        "status-sequence-gap",
        "unauthorized-cancel",
        "unauthorized-close",
        "unauthorized-status",
        "wrapper-inner-kind-mismatch",
        "wrapper-inner-recipient-mismatch",
        "wrapper-inner-signer-mismatch",
    ]);
    let cases = fixture["cases"].as_array().unwrap();
    let actual = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, required);
    assert_eq!(actual.len(), cases.len(), "client case IDs must be unique");
    for case in cases {
        assert_eq!(case["scope"], "client", "{}", case["id"]);
        assert_eq!(case["relay_enforced"], false, "{}", case["id"]);
        assert!(case["inputs"].is_object(), "{}", case["id"]);
        assert!(case["expected"].is_object(), "{}", case["id"]);
        assert!(case["expected"]["decision"].is_string(), "{}", case["id"]);
    }

    let gap = find_case(cases, "status-sequence-gap");
    assert_eq!(gap["expected"]["missing_sequences"], serde_json::json!([1]));
    let fork = find_case(cases, "status-sequence-fork");
    assert_eq!(fork["expected"]["advance_state"], false);
    let settlement = find_case(cases, "settlement-overclaim");
    assert_eq!(settlement["expected"]["settled"], false);
    let recovery = find_case(cases, "recovery-loss");
    assert_eq!(recovery["expected"]["synthesize_history"], false);
    let rewrapped = find_case(cases, "rewrapped-inner-deduplication");
    assert_eq!(rewrapped["expected"]["logical_records"], 1);
    assert_eq!(rewrapped["expected"]["repeat_external_effect"], false);

    let raw = include_bytes!("../../../tests/fixtures/nipmkt/client-only-cases.json");
    let decoded: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        decoded, fixture,
        "the exported corpus uses the committed raw bytes"
    );
}

fn find_case<'a>(cases: &'a [Value], id: &str) -> &'a Value {
    cases.iter().find(|case| case["id"] == id).unwrap()
}

fn relay_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/relay-closing.json"
    ))
    .unwrap()
}

fn client_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/client-only-cases.json"
    ))
    .unwrap()
}

fn event_from_fixture(value: &Value) -> Event {
    Event {
        id: "0".repeat(64),
        pubkey: "1".repeat(64),
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
        content: value["content"].as_str().unwrap().to_owned(),
        sig: "2".repeat(128),
    }
}

fn profile_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: "conformance",
        version: 1,
        critical_members: &["terms"],
        understood_members: &["terms"],
    }
}

fn replace_profile(event: &mut Event, profile_id: &str, version: u64) {
    let profile = event
        .tags
        .iter_mut()
        .find(|tag| tag.0.first().map(String::as_str) == Some("profile"))
        .unwrap();
    profile.0[1] = profile_id.to_owned();
    profile.0[2] = version.to_string();
    let mut content = serde_json::from_str::<Value>(&event.content).unwrap();
    content["profile"] = Value::String(profile_id.to_owned());
    content["profile_version"] = Value::from(version);
    event.content = content.to_string();
}
