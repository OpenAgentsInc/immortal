use immortal_core::domain::{
    Event, MKT_HARDENING_ACK_DEADLINE_MAX_SECONDS, MKT_HARDENING_NONCE_FUTURE_SECONDS,
    MKT_HARDENING_NONCE_PAST_SECONDS, MKT_HARDENING_NONCE_RETENTION_SECONDS,
    MKT_HARDENING_OUTCOME_DEADLINE_MAX_SECONDS, MKT_HARDENING_PROTOCOL_REVISION,
    MKT_HARDENING_SCHEMA, MKT_ORDER_KIND, MKT_SWP_INTENT_ACK_KIND, MKT_SWP_PROFILE_ID,
    MKT_SWP_PROFILE_VERSION, MKT_SWP_REDRIVE_KIND, MktHardeningErrorCode, MktHardeningRecordKind,
    MktProfileSupport, Tag, is_mkt_private_kind, validate_mkt_hardening_event,
    validate_mkt_private_base, validate_mkt_private_with_profiles,
};
use serde_json::{Value, json};

const REQUESTER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROVIDER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const RESPONSE: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const SESSION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn hardening_fixture_pins_the_versioned_wire_contract() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/hardening-v2.json"
    ))
    .expect("hardening fixture");
    assert_eq!(fixture["wire_schema"], MKT_HARDENING_SCHEMA);
    assert_eq!(
        fixture["protocol_revision"],
        MKT_HARDENING_PROTOCOL_REVISION
    );
    assert_eq!(fixture["kinds"]["order"], MKT_ORDER_KIND);
    assert_eq!(fixture["kinds"]["acknowledgment"], MKT_SWP_INTENT_ACK_KIND);
    assert_eq!(fixture["kinds"]["redrive"], MKT_SWP_REDRIVE_KIND);
    assert_eq!(
        fixture["nonce_window"]["past_seconds"],
        MKT_HARDENING_NONCE_PAST_SECONDS
    );
    assert_eq!(
        fixture["nonce_window"]["future_seconds"],
        MKT_HARDENING_NONCE_FUTURE_SECONDS
    );
    assert_eq!(
        fixture["nonce_window"]["retention_seconds"],
        MKT_HARDENING_NONCE_RETENTION_SECONDS
    );
    assert_eq!(
        fixture["deadlines"]["ack_maximum_seconds"],
        MKT_HARDENING_ACK_DEADLINE_MAX_SECONDS
    );
    assert_eq!(
        fixture["deadlines"]["outcome_maximum_seconds"],
        MKT_HARDENING_OUTCOME_DEADLINE_MAX_SECONDS
    );
    let cases = fixture["cases"].as_array().expect("case list");
    assert_eq!(cases.len(), 10);
}

#[test]
fn order_ack_and_redrive_are_typed_private_revision_two_records() {
    let order = order();
    let order_envelope = validate(&order);
    let order_record = validate_mkt_hardening_event(&order, &order_envelope, Some(1_000))
        .expect("valid effectful Order");
    assert_eq!(order_record.kind, MktHardeningRecordKind::EffectfulIntent);
    assert_eq!(order_record.response_pubkey, RESPONSE);

    let ack = acknowledgment(&order.id);
    let ack_envelope = validate(&ack);
    let ack_record =
        validate_mkt_hardening_event(&ack, &ack_envelope, None).expect("valid acknowledgment");
    assert_eq!(ack_record.kind, MktHardeningRecordKind::Acknowledgment);
    assert_eq!(
        ack_record.intent_event_id.as_deref(),
        Some(order.id.as_str())
    );

    let redrive = redrive(&order.id, &ack.id);
    let redrive_envelope = validate(&redrive);
    let redrive_record = validate_mkt_hardening_event(&redrive, &redrive_envelope, Some(1_010))
        .expect("valid re-drive");
    assert_eq!(redrive_record.kind, MktHardeningRecordKind::RedriveIntent);
    assert_eq!(
        redrive_record.order_event_id.as_deref(),
        Some(order.id.as_str())
    );

    assert!(is_mkt_private_kind(MKT_SWP_INTENT_ACK_KIND));
    assert!(is_mkt_private_kind(MKT_SWP_REDRIVE_KIND));
}

#[test]
fn revision_two_fails_closed_on_schema_nonce_and_response_drift() {
    let mut old_schema_ack = acknowledgment(&"5".repeat(64));
    let mut content: Value = serde_json::from_str(&old_schema_ack.content).expect("ack content");
    content["schema"] = Value::String("openagents.mkt.v1".to_owned());
    content
        .as_object_mut()
        .expect("object")
        .remove("protocol_rev");
    old_schema_ack.content = serde_json::to_string(&content).expect("serialize");
    assert!(validate_mkt_private_base(&old_schema_ack).is_err());

    let stale = order();
    let stale_envelope = validate(&stale);
    let stale_error = validate_mkt_hardening_event(&stale, &stale_envelope, Some(1_301))
        .expect_err("stale nonce must fail");
    assert_eq!(stale_error.code, MktHardeningErrorCode::NonceWindow);

    let future_error = validate_mkt_hardening_event(&stale, &stale_envelope, Some(939))
        .expect_err("future nonce must fail");
    assert_eq!(future_error.code, MktHardeningErrorCode::NonceWindow);

    let mut wrong_response = order();
    replace_tag(&mut wrong_response, "response", &"6".repeat(64));
    let envelope = validate_mkt_private_base(&wrong_response).expect("base v2 envelope");
    let error = validate_mkt_hardening_event(&wrong_response, &envelope, Some(1_000))
        .expect_err("tag/body response mismatch must fail");
    assert_eq!(error.code, MktHardeningErrorCode::InvalidIntent);
}

fn validate(event: &Event) -> immortal_core::domain::MktPrivateEnvelope {
    let support = MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    };
    validate_mkt_private_with_profiles(event, &[support]).expect("valid hardening record")
}

fn order() -> Event {
    event(
        REQUESTER,
        MKT_ORDER_KIND,
        vec![
            pair("d", &"a".repeat(64)),
            pair("session", SESSION),
            profile(),
            counterparty(PROVIDER, "provider"),
            pair("alt", "MKT-SWP Order"),
            reference(&"3".repeat(64), "quote"),
            pair("intent", "effectful"),
            pair("nonce", &"c".repeat(64)),
            pair("nonce_at", "1000"),
            pair("response", RESPONSE),
        ],
        json!({
            "schema": MKT_HARDENING_SCHEMA,
            "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
            "profile": MKT_SWP_PROFILE_ID,
            "profile_version": MKT_SWP_PROFILE_VERSION,
            "session_id": SESSION,
            "intent": {
                "idempotency_key": "a".repeat(64),
                "nonce": "c".repeat(64),
                "nonce_at": 1000,
                "response_pubkey": RESPONSE,
                "ack_deadline_seconds": 30,
                "outcome_deadline_seconds": 300
            },
            "mkt_swp": {}
        }),
    )
}

fn acknowledgment(intent_id: &str) -> Event {
    event(
        PROVIDER,
        MKT_SWP_INTENT_ACK_KIND,
        vec![
            pair("d", &"d".repeat(64)),
            pair("session", SESSION),
            profile(),
            counterparty(REQUESTER, "requester"),
            pair("alt", "MKT-SWP Intent Acknowledgment"),
            reference(intent_id, "intent"),
            pair("ack", "accepted"),
            pair("response", RESPONSE),
            pair("expiration", "1300"),
        ],
        json!({
            "schema": MKT_HARDENING_SCHEMA,
            "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
            "profile": MKT_SWP_PROFILE_ID,
            "profile_version": MKT_SWP_PROFILE_VERSION,
            "session_id": SESSION,
            "ack": {
                "intent_event_id": intent_id,
                "idempotency_key": "a".repeat(64),
                "disposition": "accepted",
                "accepted_at": 1000,
                "error_code": Value::Null
            }
        }),
    )
}

fn redrive(order_id: &str, ack_id: &str) -> Event {
    event(
        REQUESTER,
        MKT_SWP_REDRIVE_KIND,
        vec![
            pair("d", &"e".repeat(64)),
            pair("session", SESSION),
            profile(),
            counterparty(PROVIDER, "provider"),
            pair("alt", "MKT-SWP Re-drive Intent"),
            pair("intent", "redrive"),
            pair("nonce", &"f".repeat(64)),
            pair("nonce_at", "1010"),
            pair("response", RESPONSE),
            reference(order_id, "order"),
            reference(ack_id, "ack"),
        ],
        json!({
            "schema": MKT_HARDENING_SCHEMA,
            "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
            "profile": MKT_SWP_PROFILE_ID,
            "profile_version": MKT_SWP_PROFILE_VERSION,
            "session_id": SESSION,
            "intent": {
                "idempotency_key": "e".repeat(64),
                "nonce": "f".repeat(64),
                "nonce_at": 1010,
                "response_pubkey": RESPONSE,
                "ack_deadline_seconds": 30,
                "outcome_deadline_seconds": 300,
                "order_event_id": order_id,
                "ack_event_id": ack_id,
                "last_known_event_id": Value::Null
            }
        }),
    )
}

fn event(pubkey: &str, kind: u16, tags: Vec<Tag>, content: Value) -> Event {
    let mut event = Event {
        id: String::new(),
        pubkey: pubkey.to_owned(),
        created_at: 1_000,
        kind,
        tags,
        content: serde_json::to_string(&content).expect("serialize content"),
        sig: "0".repeat(128),
    };
    event.id = event.computed_id().expect("event id");
    event
}

fn pair(name: &str, value: &str) -> Tag {
    Tag::new(vec![name.to_owned(), value.to_owned()])
}

fn profile() -> Tag {
    Tag::new(vec![
        "profile".to_owned(),
        MKT_SWP_PROFILE_ID.to_owned(),
        MKT_SWP_PROFILE_VERSION.to_string(),
    ])
}

fn counterparty(pubkey: &str, role: &str) -> Tag {
    Tag::new(vec![
        "p".to_owned(),
        pubkey.to_owned(),
        String::new(),
        role.to_owned(),
    ])
}

fn reference(event_id: &str, marker: &str) -> Tag {
    Tag::new(vec![
        "e".to_owned(),
        event_id.to_owned(),
        String::new(),
        marker.to_owned(),
    ])
}

fn replace_tag(event: &mut Event, name: &str, value: &str) {
    event.tags.retain(|tag| tag.name() != Some(name));
    event.tags.push(pair(name, value));
}
