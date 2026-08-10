use immortal_core::domain::{
    Event, MKT_CLOSE_KIND, MKT_HARDENING_PROTOCOL_REVISION, MKT_HARDENING_SCHEMA, MKT_ORDER_KIND,
    MKT_QUOTE_KIND, MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
    MKT_SWP_REDRIVE_KIND, MktReceiptFee, MktReceiptLeg, Tag,
};
use immortal_provider::{
    EffectAttemptClaim, IntentAckSigningRequest, IntentAdmission, ProviderHardeningErrorCode,
    ProviderIntentJournal, ReceiptEmission, SettlementReceiptClaim,
    SettlementReceiptEmissionRequest, SettlementReceiptSigningRequest,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::json;

const SESSION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RESPONSE: &str = "4444444444444444444444444444444444444444444444444444444444444444";

#[test]
fn provider_acknowledges_once_replays_exactly_and_redrives_read_only() {
    let provider = signer(2);
    let requester = signer(1);
    let mut journal =
        ProviderIntentJournal::new(provider.pubkey.clone(), SESSION).expect("provider journal");
    let order = signed_order(&requester, &provider.pubkey, "a", "c", 1_000);

    let mut signs = 0;
    let mut persists = 0;
    let admission = journal
        .admit_with_ack(
            order.clone(),
            1_000,
            |request| {
                signs += 1;
                Ok(provider.sign_request(request))
            },
            |_| {
                persists += 1;
                Ok(())
            },
        )
        .expect("accepted Order");
    let acknowledgment = match admission {
        IntentAdmission::New { acknowledgment } => acknowledgment,
        IntentAdmission::Replay { .. } => panic!("first admission cannot be replay"),
    };
    assert_eq!(signs, 1);
    assert_eq!(persists, 1);
    assert_eq!(acknowledgment.pubkey, provider.pubkey);
    assert_eq!(tag_value(&acknowledgment, "response"), RESPONSE);
    assert_eq!(tag_value(&acknowledgment, "ack"), "accepted");

    let replay = journal
        .admit_with_ack(
            order.clone(),
            1_001,
            |_| panic!("exact replay must not sign again"),
            |_| panic!("exact replay must not mutate durable state"),
        )
        .expect("exact replay");
    match replay {
        IntentAdmission::Replay {
            acknowledgment: replayed,
            outcomes,
            receipts,
        } => {
            assert_eq!(replayed, acknowledgment);
            assert!(outcomes.is_empty());
            assert!(receipts.is_empty());
        }
        IntentAdmission::New { .. } => panic!("exact bytes must replay"),
    }

    let changed_key_bytes = signed_order(&requester, &provider.pubkey, "a", "d", 1_000);
    let conflict = journal
        .admit_with_ack(
            changed_key_bytes,
            1_000,
            |_| panic!("idempotency conflict must not sign"),
            |_| panic!("idempotency conflict must not persist"),
        )
        .expect_err("changed bytes under one key must fail");
    assert_eq!(
        conflict.code,
        ProviderHardeningErrorCode::IdempotencyConflict
    );

    let reused_nonce = signed_order(&requester, &provider.pubkey, "e", "c", 1_000);
    let replay_error = journal
        .admit_with_ack(
            reused_nonce,
            1_000,
            |_| panic!("nonce replay must not sign"),
            |_| panic!("nonce replay must not persist"),
        )
        .expect_err("nonce reuse on another intent must fail");
    assert_eq!(replay_error.code, ProviderHardeningErrorCode::Replay);

    let stale = signed_order(&requester, &provider.pubkey, "f", "1", 1_000);
    let stale_error = journal
        .admit_with_ack(
            stale,
            1_301,
            |_| panic!("stale nonce must not sign"),
            |_| panic!("stale nonce must not persist"),
        )
        .expect_err("stale nonce must fail");
    assert_eq!(stale_error.code, ProviderHardeningErrorCode::NonceWindow);

    let mut claim_persists = 0;
    assert_eq!(
        journal
            .claim_effect_attempt(&order.id, |_| {
                claim_persists += 1;
                Ok(())
            })
            .expect("first effect claim"),
        EffectAttemptClaim::Claimed
    );
    assert_eq!(
        journal
            .claim_effect_attempt(&order.id, |_| {
                claim_persists += 1;
                Ok(())
            })
            .expect("replayed effect claim"),
        EffectAttemptClaim::AlreadyClaimed
    );
    assert_eq!(claim_persists, 1, "effect attempt mutates exactly once");

    let outcome = signed_outcome(&provider, &requester.pubkey, &order.id);
    assert!(
        journal
            .record_outcome(&order.id, outcome.clone(), |_| Ok(()))
            .expect("record outcome")
    );
    assert!(
        !journal
            .record_outcome(&order.id, outcome.clone(), |_| {
                panic!("outcome replay must not persist")
            })
            .expect("outcome replay")
    );

    let redrive = signed_redrive(
        &requester,
        &provider.pubkey,
        &order.id,
        &acknowledgment.id,
        &outcome.id,
    );
    journal
        .admit_with_ack(
            redrive.clone(),
            1_010,
            |request| Ok(provider.sign_request(request)),
            |_| Ok(()),
        )
        .expect("admit re-drive");
    let restatement = journal.restate(&redrive.id).expect("durable restatement");
    assert_eq!(restatement.original_acknowledgment, acknowledgment);
    assert_eq!(restatement.outcomes, vec![outcome]);
    let redrive_effect = journal
        .claim_effect_attempt(&redrive.id, |_| {
            panic!("re-drive cannot persist an effect attempt")
        })
        .expect_err("re-drive is read-only");
    assert_eq!(
        redrive_effect.code,
        ProviderHardeningErrorCode::InvalidIntent
    );

    let snapshot = journal.snapshot_bytes().expect("journal snapshot");
    let mut restored = ProviderIntentJournal::restore(&snapshot).expect("restore journal");
    assert_eq!(
        restored
            .claim_effect_attempt(&order.id, |_| {
                panic!("restart cannot reclaim the effect attempt")
            })
            .expect("restored effect claim"),
        EffectAttemptClaim::AlreadyClaimed
    );
    assert_eq!(
        restored.restate(&redrive.id).expect("restored redrive"),
        restatement
    );
}

#[test]
fn failed_persistence_rolls_back_ack_admission() {
    let provider = signer(2);
    let requester = signer(1);
    let mut journal =
        ProviderIntentJournal::new(provider.pubkey.clone(), SESSION).expect("provider journal");
    let order = signed_order(&requester, &provider.pubkey, "a", "c", 1_000);
    let failure = journal
        .admit_with_ack(
            order.clone(),
            1_000,
            |request| Ok(provider.sign_request(request)),
            |_| Err("disk unavailable".to_owned()),
        )
        .expect_err("unpersisted acknowledgment cannot accept");
    assert_eq!(failure.code, ProviderHardeningErrorCode::Persistence);

    assert!(matches!(
        journal
            .admit_with_ack(
                order,
                1_000,
                |request| Ok(provider.sign_request(request)),
                |_| Ok(())
            )
            .expect("fresh admission after rollback"),
        IntentAdmission::New { .. }
    ));
}

#[test]
fn terminal_receipt_is_persisted_once_replayed_and_redriven_exactly() {
    let provider = signer(2);
    let requester = signer(1);
    let quote = signed_quote(&provider, &requester.pubkey);
    let order = signed_order_for_quote(&requester, &provider.pubkey, &quote.id);
    let mut journal =
        ProviderIntentJournal::new(provider.pubkey.clone(), SESSION).expect("provider journal");
    let acknowledgment = match journal
        .admit_with_ack(
            order.clone(),
            1_000,
            |request| Ok(provider.sign_request(request)),
            |_| Ok(()),
        )
        .expect("admit Order")
    {
        IntentAdmission::New { acknowledgment } => acknowledgment,
        IntentAdmission::Replay { .. } => panic!("new Order replayed"),
    };
    let close = signed_close(&provider, &requester.pubkey, &order.id);
    journal
        .record_outcome(&order.id, close.clone(), |_| Ok(()))
        .expect("record Close");

    let claim = receipt_claim();
    let mut signs = 0;
    let mut persists = 0;
    let receipt = match journal
        .emit_receipt_with_sign(
            SettlementReceiptEmissionRequest {
                order_event_id: order.id.clone(),
                outcome_event_id: close.id.clone(),
                quote: quote.clone(),
                client_confirmation: None,
                claim: claim.clone(),
                created_at: 1_101,
            },
            |request| {
                signs += 1;
                Ok(provider.sign_receipt_request(request))
            },
            |_| {
                persists += 1;
                Ok(())
            },
        )
        .expect("emit terminal receipt")
    {
        ReceiptEmission::New { receipt } => receipt,
        ReceiptEmission::Replay { .. } => panic!("first receipt replayed"),
    };
    assert_eq!(signs, 1);
    assert_eq!(persists, 1);

    assert_eq!(
        journal
            .emit_receipt_with_sign(
                SettlementReceiptEmissionRequest {
                    order_event_id: order.id.clone(),
                    outcome_event_id: close.id.clone(),
                    quote: quote.clone(),
                    client_confirmation: None,
                    claim: claim.clone(),
                    created_at: 1_200,
                },
                |_| panic!("exact receipt replay must not sign"),
                |_| panic!("exact receipt replay must not persist"),
            )
            .expect("exact receipt replay"),
        ReceiptEmission::Replay {
            receipt: receipt.clone()
        }
    );

    let mut changed = claim;
    changed.legs[0].gross_amount = "100001".to_owned();
    let conflict = journal
        .emit_receipt_with_sign(
            SettlementReceiptEmissionRequest {
                order_event_id: order.id.clone(),
                outcome_event_id: close.id.clone(),
                quote: quote.clone(),
                client_confirmation: None,
                claim: changed,
                created_at: 1_201,
            },
            |_| panic!("conflicting receipt must not sign"),
            |_| panic!("conflicting receipt must not persist"),
        )
        .expect_err("changed terminal claim must conflict");
    assert_eq!(
        conflict.code,
        ProviderHardeningErrorCode::IdempotencyConflict
    );

    match journal
        .admit_with_ack(
            order.clone(),
            1_200,
            |_| panic!("Order replay must not sign"),
            |_| panic!("Order replay must not persist"),
        )
        .expect("Order replay")
    {
        IntentAdmission::Replay { receipts, .. } => assert_eq!(receipts, vec![receipt.clone()]),
        IntentAdmission::New { .. } => panic!("existing Order was new"),
    }

    let redrive = signed_redrive(
        &requester,
        &provider.pubkey,
        &order.id,
        &acknowledgment.id,
        &close.id,
    );
    journal
        .admit_with_ack(
            redrive.clone(),
            1_010,
            |request| Ok(provider.sign_request(request)),
            |_| Ok(()),
        )
        .expect("admit Re-drive");
    assert_eq!(
        journal.restate(&redrive.id).unwrap().receipts,
        vec![receipt]
    );

    let snapshot = journal.snapshot_bytes().unwrap();
    let restored = ProviderIntentJournal::restore(&snapshot).expect("restore receipt journal");
    assert_eq!(
        restored.restate(&redrive.id).unwrap().receipts,
        journal.restate(&redrive.id).unwrap().receipts
    );
}

#[derive(Clone)]
struct Signer {
    secret_byte: u8,
    pubkey: String,
}

impl Signer {
    fn sign_request(&self, request: &IntentAckSigningRequest) -> Event {
        sign(
            self.secret_byte,
            Event {
                id: request.expected_event_id.clone(),
                pubkey: request.pubkey.clone(),
                created_at: request.created_at,
                kind: request.kind,
                tags: request.tags.clone(),
                content: request.content.clone(),
                sig: String::new(),
            },
        )
    }

    fn sign_receipt_request(&self, request: &SettlementReceiptSigningRequest) -> Event {
        sign(
            self.secret_byte,
            Event {
                id: request.expected_event_id.clone(),
                pubkey: request.pubkey.clone(),
                created_at: request.created_at,
                kind: request.kind,
                tags: request.tags.clone(),
                content: request.content.clone(),
                sig: String::new(),
            },
        )
    }
}

fn signer(secret_byte: u8) -> Signer {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).expect("secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    Signer {
        secret_byte,
        pubkey: keypair.x_only_public_key().0.to_string(),
    }
}

fn signed_order(
    requester: &Signer,
    provider_pubkey: &str,
    idempotency_byte: &str,
    nonce_byte: &str,
    nonce_at: u64,
) -> Event {
    let idempotency_key = idempotency_byte.repeat(64);
    let nonce = nonce_byte.repeat(64);
    sign(
        requester.secret_byte,
        Event {
            id: String::new(),
            pubkey: requester.pubkey.clone(),
            created_at: nonce_at,
            kind: MKT_ORDER_KIND,
            tags: vec![
                pair("d", &idempotency_key),
                pair("session", SESSION),
                profile(),
                counterparty(provider_pubkey, "provider"),
                pair("alt", "MKT-SWP Order"),
                reference(&"3".repeat(64), "quote"),
                pair("intent", "effectful"),
                pair("nonce", &nonce),
                pair("nonce_at", &nonce_at.to_string()),
                pair("response", RESPONSE),
            ],
            content: json!({
                "schema": MKT_HARDENING_SCHEMA,
                "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
                "profile": MKT_SWP_PROFILE_ID,
                "profile_version": MKT_SWP_PROFILE_VERSION,
                "session_id": SESSION,
                "intent": {
                    "idempotency_key": idempotency_key,
                    "nonce": nonce,
                    "nonce_at": nonce_at,
                    "response_pubkey": RESPONSE,
                    "ack_deadline_seconds": 30,
                    "outcome_deadline_seconds": 300
                },
                "mkt_swp": {}
            })
            .to_string(),
            sig: String::new(),
        },
    )
}

fn signed_order_for_quote(requester: &Signer, provider_pubkey: &str, quote_id: &str) -> Event {
    let mut order = signed_order(requester, provider_pubkey, "a", "c", 1_000);
    for tag in &mut order.tags {
        if tag.as_slice().get(3).map(String::as_str) == Some("quote") {
            tag.0[1] = quote_id.to_owned();
        }
    }
    sign(requester.secret_byte, order)
}

fn signed_quote(provider: &Signer, requester_pubkey: &str) -> Event {
    sign(
        provider.secret_byte,
        Event {
            id: String::new(),
            pubkey: provider.pubkey.clone(),
            created_at: 990,
            kind: MKT_QUOTE_KIND,
            tags: vec![
                pair("d", &"6".repeat(64)),
                pair("session", SESSION),
                profile(),
                counterparty(requester_pubkey, "requester"),
                pair("alt", "MKT-SWP Quote"),
            ],
            content: v1_content(),
            sig: String::new(),
        },
    )
}

fn signed_redrive(
    requester: &Signer,
    provider_pubkey: &str,
    order_id: &str,
    ack_id: &str,
    last_known: &str,
) -> Event {
    sign(
        requester.secret_byte,
        Event {
            id: String::new(),
            pubkey: requester.pubkey.clone(),
            created_at: 1_010,
            kind: MKT_SWP_REDRIVE_KIND,
            tags: vec![
                pair("d", &"e".repeat(64)),
                pair("session", SESSION),
                profile(),
                counterparty(provider_pubkey, "provider"),
                pair("alt", "MKT-SWP Re-drive Intent"),
                pair("intent", "redrive"),
                pair("nonce", &"f".repeat(64)),
                pair("nonce_at", "1010"),
                pair("response", RESPONSE),
                reference(order_id, "order"),
                reference(ack_id, "ack"),
                reference(last_known, "status"),
            ],
            content: json!({
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
                    "last_known_event_id": last_known
                }
            })
            .to_string(),
            sig: String::new(),
        },
    )
}

fn signed_outcome(provider: &Signer, requester_pubkey: &str, order_id: &str) -> Event {
    sign(
        provider.secret_byte,
        Event {
            id: String::new(),
            pubkey: provider.pubkey.clone(),
            created_at: 1_005,
            kind: MKT_STATUS_KIND,
            tags: vec![
                pair("d", &"7".repeat(64)),
                pair("session", SESSION),
                profile(),
                counterparty(requester_pubkey, "requester"),
                pair("alt", "MKT-SWP Status"),
                reference(order_id, "order"),
                pair("seq", "0"),
                pair("state", "accepted"),
            ],
            content: json!({
                "schema": "openagents.mkt.v1",
                "profile": MKT_SWP_PROFILE_ID,
                "profile_version": MKT_SWP_PROFILE_VERSION,
                "session_id": SESSION,
                "mkt_swp": {}
            })
            .to_string(),
            sig: String::new(),
        },
    )
}

fn signed_close(provider: &Signer, requester_pubkey: &str, order_id: &str) -> Event {
    sign(
        provider.secret_byte,
        Event {
            id: String::new(),
            pubkey: provider.pubkey.clone(),
            created_at: 1_100,
            kind: MKT_CLOSE_KIND,
            tags: vec![
                pair("d", &"8".repeat(64)),
                pair("session", SESSION),
                profile(),
                counterparty(requester_pubkey, "requester"),
                pair("alt", "MKT-SWP Close"),
                reference(order_id, "order"),
                pair("outcome", "completed"),
                pair("terminal_at", "1100"),
            ],
            content: v1_content(),
            sig: String::new(),
        },
    )
}

fn receipt_claim() -> SettlementReceiptClaim {
    SettlementReceiptClaim {
        failure_code: None,
        started_at: 1_000,
        finished_at: 1_100,
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
    }
}

fn v1_content() -> String {
    json!({
        "schema": "openagents.mkt.v1",
        "profile": MKT_SWP_PROFILE_ID,
        "profile_version": MKT_SWP_PROFILE_VERSION,
        "session_id": SESSION,
        "mkt_swp": {}
    })
    .to_string()
}

fn sign(secret_byte: u8, mut event: Event) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).expect("secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    event.pubkey = keypair.x_only_public_key().0.to_string();
    event.id = event.computed_id().expect("event id");
    let id = event.computed_id_bytes().expect("event id bytes");
    event.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
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

fn tag_value<'a>(event: &'a Event, name: &str) -> &'a str {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == Some(name))
        .and_then(Tag::value)
        .expect("tag value")
}
