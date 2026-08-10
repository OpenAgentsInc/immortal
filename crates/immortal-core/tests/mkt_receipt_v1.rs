use immortal_core::domain::{
    Event, MKT_CLOSE_KIND, MKT_HARDENING_PROTOCOL_REVISION, MKT_HARDENING_SCHEMA,
    MKT_KEY_ROTATION_SCHEMA, MKT_NETWORK_VERSION, MKT_ORDER_KIND, MKT_QUOTE_KIND,
    MKT_RECEIPT_SCHEMA, MKT_RECEIPT_VERSION, MKT_STATUS_KIND, MKT_SWP_INTENT_ACK_KIND,
    MKT_SWP_KEY_ROTATION_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
    MKT_SWP_SETTLEMENT_RECEIPT_KIND, MktKeyRotation, MktProfileSupport, MktReceiptChainErrorCode,
    MktReceiptFee, MktReceiptLeg, MktSettlementReceipt, Tag, canonical_mkt_key_rotation_content,
    canonical_mkt_receipt_content, mkt_key_rotation_id, mkt_receipt_id,
    validate_mkt_private_with_profiles, validate_mkt_receipt_event, verify_mkt_key_rotation_chain,
    verify_mkt_receipt_chain, verify_mkt_receipt_chain_parts,
    verify_mkt_receipt_chain_with_provider_keys,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn canonical_provider_receipt_verifies_from_events_alone() {
    let chain = chain(None);
    let receipt = verify_mkt_receipt_chain(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &chain.quote,
        &chain.outcome,
        None,
    )
    .expect("event-only receipt chain");
    assert_eq!(receipt.legs.len(), 2);
    assert_eq!(receipt.fees.len(), 1);
    assert_eq!(receipt.outcome, "completed");
    assert_eq!(receipt.receipt_id, mkt_receipt_id(&receipt).unwrap());
}

#[test]
fn optional_requester_confirmation_is_typed_and_missing_is_incomplete() {
    let base = chain(None);
    let confirmation = status(1, &base.intent.id);
    let chain = chain(Some(&confirmation));
    verify_mkt_receipt_chain(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &chain.quote,
        &chain.outcome,
        Some(&confirmation),
    )
    .expect("requester confirmation");
    let error = verify_mkt_receipt_chain(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &chain.quote,
        &chain.outcome,
        None,
    )
    .expect_err("missing referenced confirmation");
    assert_eq!(error.code, MktReceiptChainErrorCode::Incomplete);

    let error = verify_mkt_receipt_chain_parts(
        &base.receipt,
        Some(&base.intent),
        Some(&base.acknowledgment),
        None,
        Some(&base.outcome),
        None,
    )
    .expect_err("missing required Quote");
    assert_eq!(error.code, MktReceiptChainErrorCode::Incomplete);
}

#[test]
fn receipt_refuses_noncanonical_digest_fields_bounds_and_custody() {
    let chain = chain(None);
    let mut noncanonical = chain.receipt.clone();
    noncanonical.content = format!(" {}", noncanonical.content);
    resign(&mut noncanonical, 2);
    let envelope = receipt_envelope(&noncanonical);
    assert!(
        validate_mkt_receipt_event(&noncanonical, &envelope)
            .unwrap_err()
            .contains("mkt_receipt_noncanonical")
    );

    for mutate in [
        "digest",
        "amount",
        "duplicate-leg",
        "failure-code",
        "custody",
    ] {
        let mut event = chain.receipt.clone();
        let mut content: Value = serde_json::from_str(&event.content).unwrap();
        match mutate {
            "digest" => content["receipt"]["receipt_id"] = Value::String("f".repeat(64)),
            "amount" => content["receipt"]["legs"][0]["gross_amount"] = Value::String("01".into()),
            "duplicate-leg" => {
                let duplicate = content["receipt"]["legs"][0].clone();
                content["receipt"]["legs"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "failure-code" => {
                content["receipt"]["failure_code"] = Value::String("rail-failed".into())
            }
            "custody" => {
                content["receipt"]["legs"][0]
                    .as_object_mut()
                    .unwrap()
                    .insert("preimage".into(), Value::String("secret".into()));
            }
            _ => unreachable!(),
        }
        event.content = canonical_value(&content);
        resign(&mut event, 2);
        let result = validate_mkt_private_with_profiles(&event, &[support()]);
        assert!(result.is_err(), "mutation {mutate} was admitted");
    }
}

#[test]
fn receipt_chain_refuses_wrong_provider_and_broken_causality() {
    let chain = chain(None);
    let mut wrong_quote = chain.quote.clone();
    resign(&mut wrong_quote, 3);
    let error = verify_mkt_receipt_chain(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &wrong_quote,
        &chain.outcome,
        None,
    )
    .expect_err("wrong provider quote");
    assert_eq!(error.code, MktReceiptChainErrorCode::Invalid);

    let mut broken_outcome = chain.outcome.clone();
    replace_reference(&mut broken_outcome, "order", &"f".repeat(64));
    resign(&mut broken_outcome, 2);
    let error = verify_mkt_receipt_chain(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &chain.quote,
        &broken_outcome,
        None,
    )
    .expect_err("broken Close causality");
    assert_eq!(error.code, MktReceiptChainErrorCode::Invalid);
}

#[test]
fn receipt_chain_honors_provider_rotation_mid_session() {
    let mut chain = chain(None);
    let rotation = key_rotation(2, 3, 1_050, 1_095);
    let provider_keys = verify_mkt_key_rotation_chain(&pubkey(2), &[rotation]).unwrap();
    resign(&mut chain.receipt, 3);

    verify_mkt_receipt_chain_with_provider_keys(
        &chain.receipt,
        &chain.intent,
        &chain.acknowledgment,
        &chain.quote,
        &chain.outcome,
        None,
        &provider_keys,
    )
    .expect("provider rotation across receipt chain");
    assert!(
        verify_mkt_receipt_chain(
            &chain.receipt,
            &chain.intent,
            &chain.acknowledgment,
            &chain.quote,
            &chain.outcome,
            None,
        )
        .is_err(),
        "the legacy same-key verifier remains intentionally strict"
    );
}

struct Chain {
    quote: Event,
    intent: Event,
    acknowledgment: Event,
    outcome: Event,
    receipt: Event,
}

fn chain(client_confirmation: Option<&Event>) -> Chain {
    let requester = pubkey(1);
    let provider = pubkey(2);
    let quote = quote(&requester);
    let intent = intent(&requester, &provider, &quote.id);
    let acknowledgment = acknowledgment(&requester, &intent.id);
    let outcome = close(&requester, &intent.id);
    let mut claim = MktSettlementReceipt {
        schema: MKT_RECEIPT_SCHEMA.to_owned(),
        version: MKT_RECEIPT_VERSION,
        receipt_id: String::new(),
        intent_event_id: intent.id.clone(),
        acknowledgment_event_id: acknowledgment.id.clone(),
        quote_event_id: quote.id.clone(),
        outcome_event_id: outcome.id.clone(),
        client_confirmation_event_id: client_confirmation.map(|event| event.id.clone()),
        outcome: "completed".to_owned(),
        failure_code: None,
        started_at: 1_000,
        finished_at: 1_090,
        legs: vec![
            MktReceiptLeg {
                leg_id: "source".to_owned(),
                asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:chain".to_owned(),
                rail: "bitcoin".to_owned(),
                direction: "provider-receives".to_owned(),
                gross_amount: "100000".to_owned(),
                net_amount: "100000".to_owned(),
            },
            MktReceiptLeg {
                leg_id: "destination".to_owned(),
                asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:lightning".to_owned(),
                rail: "lightning".to_owned(),
                direction: "provider-sends".to_owned(),
                gross_amount: "99000".to_owned(),
                net_amount: "99000".to_owned(),
            },
        ],
        fees: vec![MktReceiptFee {
            fee_id: "provider-fee".to_owned(),
            asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:chain".to_owned(),
            rail: "bitcoin".to_owned(),
            amount: "1000".to_owned(),
            payer_role: "requester".to_owned(),
            recipient_role: "provider".to_owned(),
        }],
    };
    claim.receipt_id = mkt_receipt_id(&claim).unwrap();
    let receipt = receipt(&requester, &claim);
    Chain {
        quote,
        intent,
        acknowledgment,
        outcome,
        receipt,
    }
}

fn quote(requester: &str) -> Event {
    signed(
        2,
        990,
        MKT_QUOTE_KIND,
        common_tags("1", requester, "requester", "MKT-SWP Quote"),
        v1_content(),
    )
}

fn intent(requester: &str, provider: &str, quote_id: &str) -> Event {
    let mut tags = common_tags("2", provider, "provider", "MKT-SWP Order");
    tags.extend([
        reference(quote_id, "quote"),
        pair("intent", "effectful"),
        pair("nonce", &"c".repeat(64)),
        pair("nonce_at", "1000"),
        pair("response", requester),
    ]);
    signed(
        1,
        1_000,
        MKT_ORDER_KIND,
        tags,
        json!({
            "schema": MKT_HARDENING_SCHEMA,
            "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
            "profile": MKT_SWP_PROFILE_ID,
            "profile_version": MKT_SWP_PROFILE_VERSION,
            "session_id": SESSION,
            "intent": {
                "idempotency_key": "2".repeat(64),
                "nonce": "c".repeat(64),
                "nonce_at": 1000,
                "response_pubkey": requester,
                "ack_deadline_seconds": 30,
                "outcome_deadline_seconds": 300
            },
            "mkt_swp": {}
        }),
    )
}

fn acknowledgment(requester: &str, intent_id: &str) -> Event {
    let mut tags = common_tags("3", requester, "requester", "MKT-SWP Intent Acknowledgment");
    tags.extend([
        reference(intent_id, "intent"),
        pair("ack", "accepted"),
        pair("response", requester),
        pair("expiration", "2000"),
    ]);
    signed(
        2,
        1_001,
        MKT_SWP_INTENT_ACK_KIND,
        tags,
        json!({
            "schema": MKT_HARDENING_SCHEMA,
            "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
            "profile": MKT_SWP_PROFILE_ID,
            "profile_version": MKT_SWP_PROFILE_VERSION,
            "session_id": SESSION,
            "ack": {
                "intent_event_id": intent_id,
                "idempotency_key": "2".repeat(64),
                "disposition": "accepted",
                "accepted_at": 1001,
                "error_code": null
            }
        }),
    )
}

fn close(requester: &str, intent_id: &str) -> Event {
    let mut tags = common_tags("4", requester, "requester", "MKT-SWP Close");
    tags.extend([
        reference(intent_id, "order"),
        pair("outcome", "completed"),
        pair("terminal_at", "1090"),
    ]);
    signed(2, 1_090, MKT_CLOSE_KIND, tags, v1_content())
}

fn status(secret: u8, intent_id: &str) -> Event {
    let mut tags = common_tags("5", &pubkey(2), "provider", "MKT-SWP Status");
    tags.extend([
        reference(intent_id, "order"),
        pair("seq", "0"),
        pair("state", "completed"),
    ]);
    signed(secret, 1_091, MKT_STATUS_KIND, tags, v1_content())
}

fn receipt(requester: &str, claim: &MktSettlementReceipt) -> Event {
    let mut tags = common_tags(
        &claim.receipt_id,
        requester,
        "requester",
        "MKT-SWP Settlement Receipt",
    );
    tags.extend([
        reference(&claim.intent_event_id, "intent"),
        reference(&claim.acknowledgment_event_id, "ack"),
        reference(&claim.quote_event_id, "quote"),
        reference(&claim.outcome_event_id, "outcome"),
    ]);
    if let Some(id) = claim.client_confirmation_event_id.as_deref() {
        tags.push(reference(id, "client-confirmation"));
    }
    tags.extend([
        pair("outcome", &claim.outcome),
        pair("receipt", &MKT_RECEIPT_VERSION.to_string()),
    ]);
    signed(
        2,
        1_100,
        MKT_SWP_SETTLEMENT_RECEIPT_KIND,
        tags,
        Value::String(canonical_mkt_receipt_content(SESSION, claim).unwrap()),
    )
}

fn key_rotation(old_secret: u8, new_secret: u8, created_at: u64, effective_at: u64) -> Event {
    let provider_id = pubkey(old_secret);
    let mut claim = MktKeyRotation {
        schema: MKT_KEY_ROTATION_SCHEMA.to_owned(),
        version: MKT_NETWORK_VERSION,
        rotation_id: String::new(),
        provider_id: provider_id.clone(),
        generation: 1,
        previous_rotation_event_id: None,
        old_pubkey: provider_id.clone(),
        new_pubkey: pubkey(new_secret),
        effective_at,
    };
    claim.rotation_id = mkt_key_rotation_id(&claim).unwrap();
    signed(
        old_secret,
        created_at,
        MKT_SWP_KEY_ROTATION_KIND,
        vec![
            pair("d", &claim.rotation_id),
            pair("provider", &provider_id),
            pair("generation", "1"),
            pair("effective_at", &effective_at.to_string()),
            pair("alt", "MKT Provider Key Rotation"),
            Tag::new(vec![
                "p".to_owned(),
                claim.new_pubkey.clone(),
                String::new(),
                "successor".to_owned(),
            ]),
        ],
        Value::String(canonical_mkt_key_rotation_content(&claim).unwrap()),
    )
}

fn signed(secret_byte: u8, created_at: u64, kind: u16, tags: Vec<Tag>, content: Value) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let content = match content {
        Value::String(content) => content,
        content => serde_json::to_string(&content).unwrap(),
    };
    let mut event = Event {
        id: String::new(),
        pubkey: keypair.x_only_public_key().0.to_string(),
        created_at,
        kind,
        tags,
        content,
        sig: String::new(),
    };
    resign_with_keypair(&mut event, &keypair);
    event
}

fn resign(event: &mut Event, secret_byte: u8) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    event.pubkey = keypair.x_only_public_key().0.to_string();
    resign_with_keypair(event, &keypair);
}

fn resign_with_keypair(event: &mut Event, keypair: &Keypair) {
    event.id = event.computed_id().unwrap();
    event.sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&event.computed_id_bytes().unwrap(), keypair)
        .to_string();
}

fn common_tags(digit: &str, counterparty: &str, role: &str, alt: &str) -> Vec<Tag> {
    vec![
        pair(
            "d",
            &if digit.len() == 64 {
                digit.to_owned()
            } else {
                digit.repeat(64)
            },
        ),
        pair("session", SESSION),
        Tag::new(vec![
            "profile".into(),
            MKT_SWP_PROFILE_ID.into(),
            "1".into(),
        ]),
        Tag::new(vec![
            "p".into(),
            counterparty.into(),
            String::new(),
            role.into(),
        ]),
        pair("alt", alt),
    ]
}

fn v1_content() -> Value {
    json!({
        "schema": "openagents.mkt.v1",
        "profile": MKT_SWP_PROFILE_ID,
        "profile_version": MKT_SWP_PROFILE_VERSION,
        "session_id": SESSION,
        "mkt_swp": {}
    })
}

fn receipt_envelope(event: &Event) -> immortal_core::domain::MktPrivateEnvelope {
    let content: Value = serde_json::from_str(&event.content).unwrap();
    immortal_core::domain::MktPrivateEnvelope {
        schema: MKT_HARDENING_SCHEMA.to_owned(),
        protocol_revision: MKT_HARDENING_PROTOCOL_REVISION,
        profile_id: MKT_SWP_PROFILE_ID.to_owned(),
        profile_version: MKT_SWP_PROFILE_VERSION,
        session_id: SESSION.to_owned(),
        body: content.as_object().unwrap().clone(),
    }
}

fn support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }
}

fn pair(name: &str, value: &str) -> Tag {
    Tag::new(vec![name.to_owned(), value.to_owned()])
}

fn reference(event_id: &str, marker: &str) -> Tag {
    Tag::new(vec![
        "e".into(),
        event_id.into(),
        String::new(),
        marker.into(),
    ])
}

fn replace_reference(event: &mut Event, marker: &str, event_id: &str) {
    for tag in &mut event.tags {
        if tag.as_slice().get(3).map(String::as_str) == Some(marker) {
            tag.0[1] = event_id.to_owned();
        }
    }
}

fn pubkey(secret_byte: u8) -> String {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0
        .to_string()
}

fn canonical_value(value: &Value) -> String {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => output.push_str(&serde_json::to_string(value).unwrap()),
            Value::Array(values) => {
                output.push('[');
                for (index, child) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(child, output);
                }
                output.push(']');
            }
            Value::Object(object) => {
                output.push('{');
                let mut names = object.keys().collect::<Vec<_>>();
                names.sort();
                for (index, name) in names.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(name).unwrap());
                    output.push(':');
                    write(&object[name], output);
                }
                output.push('}');
            }
        }
    }
    let mut output = String::new();
    write(value, &mut output);
    output
}
