use immortal_client::{
    domain::{Event, MKT_NETWORK_VERSION, MKT_RELAY_SET_SCHEMA, MktEventIdAdmission, MktRelaySet},
    market_network::{MktRelayConnectionState, MktRelaySetClient},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::json;

#[test]
fn one_relay_down_keeps_read_and_publication_thresholds_green() {
    let mut client = MktRelaySetClient::new(relay_set()).unwrap();
    let event = signed_event();
    let subscription = client
        .subscription_frames("mkt", &[json!({"kinds":[39614,39615]})])
        .unwrap();
    let publication = client.publication_frames(&event).unwrap();
    assert_eq!(subscription.len(), 2);
    assert_eq!(subscription[0].frame, subscription[1].frame);
    assert_eq!(publication.len(), 2);
    assert_eq!(publication[0].frame, publication[1].frame);

    client.mark_unavailable("wss://a.example").unwrap();
    assert!(client.is_degraded());
    assert!(client.mark_read_ready("wss://b.example").unwrap());
    assert_eq!(
        client.relay_state("wss://a.example"),
        Some(MktRelayConnectionState::Unavailable)
    );
    assert!(
        client
            .record_publication_ack("wss://b.example", &event.id, true)
            .unwrap()
    );
}

#[test]
fn events_from_multiple_relays_are_delivered_once_by_id() {
    let mut client = MktRelaySetClient::new(relay_set()).unwrap();
    let event = signed_event();
    assert_eq!(
        client.observe_event("wss://a.example", &event).unwrap(),
        MktEventIdAdmission::New
    );
    assert_eq!(
        client.observe_event("wss://b.example", &event).unwrap(),
        MktEventIdAdmission::Duplicate
    );
    assert!(
        client
            .observe_event("wss://outside.example", &event)
            .is_err()
    );
}

fn relay_set() -> MktRelaySet {
    MktRelaySet {
        schema: MKT_RELAY_SET_SCHEMA.to_owned(),
        version: MKT_NETWORK_VERSION,
        relay_set_id: "a".repeat(64),
        provider_id: "b".repeat(64),
        generation: 1,
        previous_relay_set_event_id: None,
        effective_at: 1,
        relays: vec!["wss://a.example".to_owned(), "wss://b.example".to_owned()],
        publish_minimum: 1,
        read_minimum: 1,
    }
}

fn signed_event() -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([7; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let mut event = Event {
        id: String::new(),
        pubkey: keypair.x_only_public_key().0.to_string(),
        created_at: 1,
        kind: 39_614,
        tags: Vec::new(),
        content: "{}".to_owned(),
        sig: String::new(),
    };
    event.id = event.computed_id().unwrap();
    event.sig = secp
        .sign_schnorr_no_aux_rand(&event.computed_id_bytes().unwrap(), &keypair)
        .to_string();
    event
}
