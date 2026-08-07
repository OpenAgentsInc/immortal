use immortal::{
    domain::{MKT_QUOTE_KIND, MKT_STATUS_KIND, RelaySigner, Tag},
    market::{MarketSigner, WrapMaterial, wrap_mkt_record},
    mkt_swp_coordination::{
        MKT_SWP_COORDINATION_EXTENSION, MKT_SWP_MAX_FORKS_PER_SEQUENCE,
        MKT_SWP_STATUS_QUERY_ROW_LIMIT, MktSwpCoordinationClaim, coordination_conformance_sha256,
        parse_coordination_wrap, status_view_from_rows,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn fixture_pins_activation_bounds_and_noncustodial_laws() {
    let fixture = fixture();
    assert_eq!(
        fixture["activation"]["extension"],
        MKT_SWP_COORDINATION_EXTENSION
    );
    assert_eq!(fixture["activation"]["default"], "disabled");
    assert_eq!(
        fixture["bounds"]["forks_per_sequence"],
        u64::try_from(MKT_SWP_MAX_FORKS_PER_SEQUENCE).unwrap()
    );
    assert_eq!(
        fixture["bounds"]["status_query_rows"],
        u64::try_from(MKT_SWP_STATUS_QUERY_ROW_LIMIT).unwrap()
    );
    assert_eq!(
        fixture["reservation_proof_strength"]["covenant_reserve"],
        100
    );
    assert!(fixture["anti_patterns"]["balances"].as_bool() == Some(false));
    assert!(fixture["anti_patterns"]["on_relay_output_orderbook"].as_bool() == Some(false));
    let digest = coordination_conformance_sha256();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[test]
fn handler_unwraps_and_parses_provider_signed_covenant_reservation() {
    let provider = MarketSigner::from_secret_bytes([1; 32]).unwrap();
    let requester = MarketSigner::from_secret_bytes([2; 32]).unwrap();
    let handler = RelaySigner::from_secret_hex(&hex(&[9; 32])).unwrap();
    let session = "11".repeat(32);
    let quote = provider.sign(
        100,
        MKT_QUOTE_KIND,
        vec![
            Tag::new(vec!["d".into(), "22".repeat(32)]),
            Tag::new(vec!["session".into(), session.clone()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester.pubkey().into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Quote".into()]),
            Tag::new(vec![
                "e".into(),
                "33".repeat(32),
                String::new(),
                "rfq".into(),
            ]),
            Tag::new(vec!["expiration".into(), "500".into()]),
            Tag::new(vec!["quote".into(), "firm".into()]),
            Tag::new(vec!["reservation".into(), "hard".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session,
            "mkt_swp": {
                "reservation_terms": {
                    "reservation_id": "44".repeat(32),
                    "capacity_bucket_id": "btc-chain",
                    "reserved_asset_id": "swp:1:bip122:000000000019d6689c085ae165831e93:btc:chain",
                    "reserved_amount": "50",
                    "handler_committed_capacity": "100",
                    "reservation_expires_at": 450,
                    "profile_timeout_at": 475,
                    "allocation_sequence": "7",
                    "proof_class": "covenant_reserve",
                    "proof_ref": "bitcoin:reserve-unit-7",
                    "capacity_commitment_sha256": "55".repeat(32),
                    "covenant": {
                        "funding_ref": "66".repeat(32) + ":0",
                        "program_sha256": "77".repeat(32),
                        "eligible_fill_sha256": "88".repeat(32),
                        "minimum_output": "50",
                        "fee_rule_sha256": "99".repeat(32),
                        "expires_at": 500,
                        "verifier_view_sha256": "aa".repeat(32)
                    }
                }
            }
        })
        .to_string(),
    );
    let wrapped = wrap_mkt_record(
        &serde_json::to_vec(&quote).unwrap(),
        &provider,
        handler.pubkey(),
        WrapMaterial {
            seal_created_at: 98,
            wrap_created_at: 99,
            rumor_identifier: [2; 32],
            seal_nonce: [3; 32],
            wrap_nonce: [4; 32],
            wrap_secret: [5; 32],
        },
    )
    .unwrap();
    let parsed = parse_coordination_wrap(&wrapped.event, &handler)
        .unwrap()
        .unwrap();
    let MktSwpCoordinationClaim::Reservation(claim) = parsed.claim else {
        panic!("Quote did not produce a reservation claim");
    };
    assert_eq!(claim.provider_pubkey, provider.pubkey());
    assert_eq!(claim.reservation_class, "hard");
    assert_eq!(claim.proof_class.as_deref(), Some("covenant_reserve"));
    assert_eq!(claim.proof_strength, 100);
    assert_eq!(claim.reserved_amount, 50);
    assert_eq!(claim.handler_committed_capacity, 100);
    assert_eq!(claim.expires_at, Some(450));
    assert_ne!(
        claim.proof_ref_sha256.as_deref(),
        Some("bitcoin:reserve-unit-7")
    );
    assert!(claim.reserve_unit_sha256.is_some());
    assert_ne!(claim.reserve_unit_sha256, claim.proof_ref_sha256);
}

#[test]
fn firm_quote_cannot_disable_reservation() {
    let provider = MarketSigner::from_secret_bytes([31; 32]).unwrap();
    let requester = MarketSigner::from_secret_bytes([32; 32]).unwrap();
    let handler = RelaySigner::from_secret_hex(&hex(&[33; 32])).unwrap();
    let session = "a1".repeat(32);
    let quote = provider.sign(
        400,
        MKT_QUOTE_KIND,
        vec![
            Tag::new(vec!["d".into(), "a2".repeat(32)]),
            Tag::new(vec!["session".into(), session.clone()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester.pubkey().into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Quote".into()]),
            Tag::new(vec![
                "e".into(),
                "a3".repeat(32),
                String::new(),
                "rfq".into(),
            ]),
            Tag::new(vec!["expiration".into(), "500".into()]),
            Tag::new(vec!["quote".into(), "firm".into()]),
            Tag::new(vec!["reservation".into(), "none".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session,
            "mkt_swp": {}
        })
        .to_string(),
    );
    let wrapped = wrap_mkt_record(
        &serde_json::to_vec(&quote).unwrap(),
        &provider,
        handler.pubkey(),
        WrapMaterial {
            seal_created_at: 398,
            wrap_created_at: 399,
            rumor_identifier: [33; 32],
            seal_nonce: [34; 32],
            wrap_nonce: [35; 32],
            wrap_secret: [36; 32],
        },
    )
    .unwrap();
    let error = parse_coordination_wrap(&wrapped.event, &handler).unwrap_err();
    assert!(error.contains("firm MKT-SWP Quote"));
}

#[test]
fn public_transaction_hook_checks_bytes_without_retaining_them() {
    let provider = MarketSigner::from_secret_bytes([11; 32]).unwrap();
    let requester = MarketSigner::from_secret_bytes([12; 32]).unwrap();
    let handler = RelaySigner::from_secret_hex(&hex(&[13; 32])).unwrap();
    let verification: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-verification.json"
    ))
    .unwrap();
    let raw = verification["transaction"]["raw"].as_str().unwrap();
    let raw_bytes = decode_hex(raw);
    let session = "ab".repeat(32);
    let status = provider.sign(
        200,
        MKT_STATUS_KIND,
        vec![
            Tag::new(vec!["d".into(), "bc".repeat(32)]),
            Tag::new(vec!["session".into(), session.clone()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester.pubkey().into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Status".into()]),
            Tag::new(vec![
                "e".into(),
                "cd".repeat(32),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["seq".into(), "0".into()]),
            Tag::new(vec!["state".into(), "funding_observed".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session,
            "mkt_swp": {
                "swp_state": "funding_observed",
                "public_evidence": [{
                    "class": "bitcoin_transaction",
                    "rung": "measured",
                    "rail": "bitcoin",
                    "reference": verification["transaction"]["txid"],
                    "artifact_sha256": hex(&Sha256::digest(&raw_bytes)),
                    "producer_pubkey": provider.pubkey(),
                    "verifier_pubkey": null,
                    "verifier_policy": null,
                    "observed_at": 200,
                    "view": "submitted raw transaction; no chain-finality claim",
                    "raw_transaction": raw
                }]
            }
        })
        .to_string(),
    );
    let wrapped = wrap_mkt_record(
        &serde_json::to_vec(&status).unwrap(),
        &provider,
        handler.pubkey(),
        WrapMaterial {
            seal_created_at: 198,
            wrap_created_at: 199,
            rumor_identifier: [13; 32],
            seal_nonce: [14; 32],
            wrap_nonce: [15; 32],
            wrap_secret: [16; 32],
        },
    )
    .unwrap();
    let parsed = parse_coordination_wrap(&wrapped.event, &handler)
        .unwrap()
        .unwrap();
    assert_eq!(parsed.public_evidence.len(), 1);
    let evidence = &parsed.public_evidence[0];
    assert_eq!(evidence.rail_reference, verification["transaction"]["txid"]);
    assert!(!evidence.view_sha256.contains("submitted"));
    let debug = format!("{parsed:?}");
    assert!(
        !debug.contains(raw),
        "raw transaction must be dropped before storage"
    );
}

#[test]
fn custody_material_is_rejected_before_the_storage_boundary() {
    let provider = MarketSigner::from_secret_bytes([21; 32]).unwrap();
    let requester = MarketSigner::from_secret_bytes([22; 32]).unwrap();
    let handler = RelaySigner::from_secret_hex(&hex(&[23; 32])).unwrap();
    let session = "de".repeat(32);
    let status = provider.sign(
        300,
        MKT_STATUS_KIND,
        vec![
            Tag::new(vec!["d".into(), "df".repeat(32)]),
            Tag::new(vec!["session".into(), session.clone()]),
            Tag::new(vec!["profile".into(), "mkt-swp".into(), "1".into()]),
            Tag::new(vec![
                "p".into(),
                requester.pubkey().into(),
                String::new(),
                "requester".into(),
            ]),
            Tag::new(vec!["alt".into(), "MKT-SWP Status".into()]),
            Tag::new(vec![
                "e".into(),
                "e0".repeat(32),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["seq".into(), "0".into()]),
            Tag::new(vec!["state".into(), "funding_observed".into()]),
        ],
        json!({
            "schema": "openagents.mkt.v1",
            "profile": "mkt-swp",
            "profile_version": 1,
            "session_id": session,
            "mkt_swp": {
                "swp_state": "funding_observed",
                "preimage": "e1".repeat(32)
            }
        })
        .to_string(),
    );
    let wrapped = wrap_mkt_record(
        &serde_json::to_vec(&status).unwrap(),
        &provider,
        handler.pubkey(),
        WrapMaterial {
            seal_created_at: 298,
            wrap_created_at: 299,
            rumor_identifier: [23; 32],
            seal_nonce: [24; 32],
            wrap_nonce: [25; 32],
            wrap_secret: [26; 32],
        },
    )
    .unwrap();
    assert!(parse_coordination_wrap(&wrapped.event, &handler).is_err());
}

#[test]
fn status_projection_is_dense_and_retains_all_bounded_forks() {
    let view = status_view_from_rows(vec![
        (0, "a".repeat(64)),
        (2, "b".repeat(64)),
        (2, "c".repeat(64)),
    ])
    .unwrap();
    assert_eq!(view.gaps, vec![1]);
    assert_eq!(view.forks[&2].len(), 2);
    assert_eq!(view.sequences.len(), 2);
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-coordination-v1.json"
    ))
    .unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid fixture hex"),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
