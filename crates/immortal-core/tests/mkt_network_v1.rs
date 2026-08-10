use immortal_core::domain::{
    Event, MKT_KEY_ROTATION_SCHEMA, MKT_NETWORK_VERSION, MKT_RELAY_SET_SCHEMA,
    MKT_SWP_KEY_ROTATION_KIND, MKT_SWP_RELAY_SET_KIND, MktEventIdAdmission, MktEventIdDeduplicator,
    MktKeyRotation, MktNetworkChainErrorCode, MktRelaySet, Tag, canonical_mkt_key_rotation_content,
    canonical_mkt_relay_set_content, mkt_key_rotation_id, mkt_relay_set_id,
    validate_mkt_public_event, validate_mkt_relay_origin, verify_mkt_key_rotation_chain,
    verify_mkt_relay_set_chain,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};

#[test]
fn canonical_rotation_selects_the_only_valid_key_at_the_boundary() {
    let provider = pubkey(1);
    let successor = pubkey(2);
    let rotation = rotation(1, 2, 100, 200, None);
    assert_eq!(validate_mkt_public_event(&rotation), Ok(()));

    let chain = verify_mkt_key_rotation_chain(&provider, &[rotation]).expect("rotation chain");
    assert_eq!(chain.provider_id(), provider);
    assert_eq!(chain.active_pubkey_at(199), provider);
    assert_eq!(chain.active_pubkey_at(200), successor);

    let old_event = signed(1, 199, 39_605, Vec::new(), "{}".to_owned());
    chain
        .validate_provider_event(&old_event)
        .expect("old key before boundary");
    let stale_old = signed(1, 200, 39_605, Vec::new(), "{}".to_owned());
    assert_eq!(
        chain
            .validate_provider_event(&stale_old)
            .expect_err("old key at boundary")
            .code,
        MktNetworkChainErrorCode::Invalid
    );
    let new_event = signed(2, 200, 39_605, Vec::new(), "{}".to_owned());
    chain
        .validate_provider_event(&new_event)
        .expect("new key at boundary");
}

#[test]
fn relay_set_chain_selects_effective_generation_across_rotation() {
    let provider = pubkey(1);
    let rotation = rotation(1, 2, 100, 200, None);
    let keys = verify_mkt_key_rotation_chain(&provider, &[rotation]).unwrap();
    let first = relay_set(
        1,
        1,
        110,
        120,
        None,
        &["wss://a.example", "wss://b.example"],
    );
    let second = relay_set(
        2,
        2,
        210,
        220,
        Some(&first.id),
        &["wss://b.example", "wss://c.example"],
    );
    assert_eq!(validate_mkt_public_event(&first), Ok(()));
    assert_eq!(validate_mkt_public_event(&second), Ok(()));

    let chain = verify_mkt_relay_set_chain(&provider, &[second, first], &keys).unwrap();
    assert_eq!(chain.effective_at(119), None);
    assert_eq!(chain.effective_at(120).unwrap().generation, 1);
    assert_eq!(chain.effective_at(219).unwrap().generation, 1);
    assert_eq!(chain.effective_at(220).unwrap().generation, 2);
}

#[test]
fn missing_generations_and_competing_successors_are_typed() {
    let provider = pubkey(1);
    let first = rotation(1, 2, 100, 200, None);
    let missing_first = rotation(2, 3, 210, 300, Some(&first.id));
    assert_eq!(
        verify_mkt_key_rotation_chain(&provider, &[missing_first])
            .expect_err("missing generation")
            .code,
        MktNetworkChainErrorCode::Incomplete
    );

    let fork_a = relay_set(
        1,
        1,
        100,
        120,
        None,
        &["wss://a.example", "wss://b.example"],
    );
    let fork_b = relay_set(
        1,
        1,
        101,
        121,
        None,
        &["wss://a.example", "wss://c.example"],
    );
    let keys = verify_mkt_key_rotation_chain(&provider, &[]).unwrap();
    assert_eq!(
        verify_mkt_relay_set_chain(&provider, &[fork_a, fork_b], &keys)
            .expect_err("relay-set fork")
            .code,
        MktNetworkChainErrorCode::Ambiguous
    );
}

#[test]
fn event_id_merge_deduplicates_exact_bytes_and_rejects_conflicting_signatures() {
    let event = signed(1, 100, 39_605, Vec::new(), "{}".to_owned());
    let mut merge = MktEventIdDeduplicator::default();
    assert_eq!(merge.observe(&event).unwrap(), MktEventIdAdmission::New);
    assert_eq!(
        merge.observe(&event).unwrap(),
        MktEventIdAdmission::Duplicate
    );
    assert_eq!(merge.len(), 1);

    let mut alternate = event.clone();
    let keypair = keypair(1);
    alternate.sig = Secp256k1::new()
        .sign_schnorr_with_aux_rand(&alternate.computed_id_bytes().unwrap(), &keypair, &[9; 32])
        .to_string();
    alternate
        .validate_crypto()
        .expect("alternate valid signature");
    assert_ne!(alternate.sig, event.sig);
    assert_eq!(
        merge
            .observe(&alternate)
            .expect_err("same ID changed signed bytes")
            .code,
        MktNetworkChainErrorCode::Invalid
    );
}

#[test]
fn relay_origins_and_thresholds_fail_closed() {
    for invalid in [
        "ws://relay.example",
        "wss://Relay.example",
        "wss://127.0.0.1",
        "wss://relay.example/",
        "wss://user@relay.example",
    ] {
        assert!(validate_mkt_relay_origin(invalid).is_err(), "{invalid}");
    }
    assert_eq!(validate_mkt_relay_origin("wss://relay.example:443"), Ok(()));

    let mut event = relay_set(
        1,
        1,
        100,
        120,
        None,
        &["wss://a.example", "wss://b.example"],
    );
    let content = event
        .content
        .replace("\"publish_minimum\":1", "\"publish_minimum\":3");
    event.content = content;
    resign(&mut event, 1);
    assert!(validate_mkt_public_event(&event).is_err());
}

fn rotation(
    old_secret: u8,
    new_secret: u8,
    created_at: u64,
    effective_at: u64,
    previous: Option<&str>,
) -> Event {
    let generation = if previous.is_some() { 2 } else { 1 };
    let provider_id = pubkey(1);
    let mut claim = MktKeyRotation {
        schema: MKT_KEY_ROTATION_SCHEMA.to_owned(),
        version: MKT_NETWORK_VERSION,
        rotation_id: String::new(),
        provider_id: provider_id.clone(),
        generation,
        previous_rotation_event_id: previous.map(str::to_owned),
        old_pubkey: pubkey(old_secret),
        new_pubkey: pubkey(new_secret),
        effective_at,
    };
    claim.rotation_id = mkt_key_rotation_id(&claim).unwrap();
    let mut tags = vec![
        pair("d", &claim.rotation_id),
        pair("provider", &provider_id),
        pair("generation", &generation.to_string()),
        pair("effective_at", &effective_at.to_string()),
        pair("alt", "MKT Provider Key Rotation"),
        Tag::new(vec![
            "p".to_owned(),
            claim.new_pubkey.clone(),
            String::new(),
            "successor".to_owned(),
        ]),
    ];
    if let Some(previous) = previous {
        tags.push(reference(previous, "previous-rotation"));
    }
    signed(
        old_secret,
        created_at,
        MKT_SWP_KEY_ROTATION_KIND,
        tags,
        canonical_mkt_key_rotation_content(&claim).unwrap(),
    )
}

fn relay_set(
    signer_secret: u8,
    generation: u64,
    created_at: u64,
    effective_at: u64,
    previous: Option<&str>,
    relays: &[&str],
) -> Event {
    let provider_id = pubkey(1);
    let mut claim = MktRelaySet {
        schema: MKT_RELAY_SET_SCHEMA.to_owned(),
        version: MKT_NETWORK_VERSION,
        relay_set_id: String::new(),
        provider_id: provider_id.clone(),
        generation,
        previous_relay_set_event_id: previous.map(str::to_owned),
        effective_at,
        relays: relays.iter().map(|relay| (*relay).to_owned()).collect(),
        publish_minimum: 1,
        read_minimum: 1,
    };
    claim.relay_set_id = mkt_relay_set_id(&claim).unwrap();
    let mut tags = vec![
        pair("d", &claim.relay_set_id),
        pair("provider", &provider_id),
        pair("generation", &generation.to_string()),
        pair("effective_at", &effective_at.to_string()),
        pair("alt", "MKT Provider Relay Set"),
    ];
    if let Some(previous) = previous {
        tags.push(reference(previous, "previous-relay-set"));
    }
    signed(
        signer_secret,
        created_at,
        MKT_SWP_RELAY_SET_KIND,
        tags,
        canonical_mkt_relay_set_content(&claim).unwrap(),
    )
}

fn signed(secret: u8, created_at: u64, kind: u16, tags: Vec<Tag>, content: String) -> Event {
    let keypair = keypair(secret);
    let mut event = Event {
        id: String::new(),
        pubkey: keypair.x_only_public_key().0.to_string(),
        created_at,
        kind,
        tags,
        content,
        sig: String::new(),
    };
    sign_with_keypair(&mut event, &keypair);
    event
}

fn resign(event: &mut Event, secret: u8) {
    let keypair = keypair(secret);
    event.pubkey = keypair.x_only_public_key().0.to_string();
    sign_with_keypair(event, &keypair);
}

fn sign_with_keypair(event: &mut Event, keypair: &Keypair) {
    event.id = event.computed_id().unwrap();
    event.sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&event.computed_id_bytes().unwrap(), keypair)
        .to_string();
}

fn keypair(secret: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret; 32]).unwrap();
    Keypair::from_secret_key(&secp, &secret)
}

fn pubkey(secret: u8) -> String {
    keypair(secret).x_only_public_key().0.to_string()
}

fn pair(name: &str, value: &str) -> Tag {
    Tag::new(vec![name.to_owned(), value.to_owned()])
}

fn reference(event_id: &str, marker: &str) -> Tag {
    Tag::new(vec![
        "e".to_owned(),
        event_id.to_owned(),
        String::new(),
        marker.to_owned(),
    ])
}
