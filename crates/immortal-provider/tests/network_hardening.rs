use immortal_core::domain::{
    Event, MKT_HARDENING_PROTOCOL_REVISION, MKT_HARDENING_SCHEMA, MKT_ORDER_KIND, MKT_STATUS_KIND,
    MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_REDRIVE_KIND, Tag,
};
use immortal_provider::{
    EffectAttemptClaim, IntentAckSigningRequest, IntentAdmission, ProviderHardeningErrorCode,
    ProviderIntentJournal,
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
        } => {
            assert_eq!(replayed, acknowledgment);
            assert!(outcomes.is_empty());
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
