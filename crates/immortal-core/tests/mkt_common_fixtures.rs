use immortal_core::domain::{
    Event, MKT_ENVELOPE_SCHEMA, MKT_EXECUTABLE_PROFILES, MKT_IDENTIFIER_MAX_BYTES,
    MKT_IDENTIFIER_PATTERN, MKT_MAX_COUNTERPARTIES, MKT_MAX_HINTS, MKT_MAX_PRIVATE_EVENT_BYTES,
    MKT_MAX_PROFILES, MKT_MAX_REFERENCES, MKT_MAX_TAGS, MKT_PROVIDER_PROFILE_KIND,
    MktProfileSupport, MktValidationCode, Tag, validate_mkt_private_base, validate_mkt_private_raw,
    validate_mkt_private_with_profiles, validate_mkt_public_event,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::Value;

#[test]
fn nipmkt_common_grammar_fixture_corpus() {
    let fixture = fixture();
    assert!(fixture["scope"]["relay"].is_array());
    assert!(fixture["scope"]["client"].is_array());
    assert!(fixture["scope"]["future_handler"].is_array());
    assert_eq!(MKT_ENVELOPE_SCHEMA, "openagents.mkt.v1");
    assert_eq!(MKT_IDENTIFIER_PATTERN, "[a-z0-9][a-z0-9._-]*");
    assert_eq!(MKT_IDENTIFIER_MAX_BYTES, 64);
    assert_eq!(
        MKT_MAX_PRIVATE_EVENT_BYTES,
        fixture["limits"]["serialized_private_bytes"]
    );
    assert_eq!(MKT_MAX_TAGS, fixture["limits"]["tags"]);
    assert_eq!(MKT_MAX_COUNTERPARTIES, fixture["limits"]["p_tags"]);
    assert_eq!(MKT_MAX_REFERENCES, fixture["limits"]["references"]);
    assert_eq!(MKT_MAX_PROFILES, fixture["limits"]["profiles"]);
    assert_eq!(MKT_MAX_HINTS, fixture["limits"]["hints"]);
    let base = event_from_fixture(&fixture["base"]);
    for kind in 39_604..=39_609 {
        let mut event = base.clone();
        event.kind = kind;
        assert!(validate_mkt_private_base(&event).is_ok());
    }
    let mut swap_contract_with_generic_profile = base.clone();
    swap_contract_with_generic_profile.kind = 39_610;
    assert_eq!(
        validate_mkt_private_base(&swap_contract_with_generic_profile)
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfile
    );

    for case in fixture["invalid"].as_array().unwrap() {
        let mut event = base.clone();
        apply_mutation(&mut event, case);
        let error = validate_mkt_private_base(&event).unwrap_err();
        assert_eq!(
            error.code.as_str(),
            case["expected_code"].as_str().unwrap(),
            "wrong code for {}: {error}",
            case["name"].as_str().unwrap(),
        );
    }

    let mut extended = base;
    extended.tags.push(Tag::new(vec![
        "p".into(),
        "unrelated".into(),
        "wss://hint.example".into(),
        "observer".into(),
        "extension".into(),
    ]));
    extended.tags.push(Tag::new(vec![
        "a".into(),
        "30000:unvalidated:subject".into(),
        String::new(),
        "subject".into(),
    ]));
    assert!(validate_mkt_private_base(&extended).is_ok());
}

#[test]
fn nipmkt_profile_aware_validation_is_explicit_and_fail_closed() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["base"]);
    let profile = &fixture["synthetic_profile"];
    let critical = strings(profile["critical_members"].as_array().unwrap());
    let understood = strings(profile["understood_members"].as_array().unwrap());
    let critical = critical.iter().map(String::as_str).collect::<Vec<_>>();
    let understood = understood.iter().map(String::as_str).collect::<Vec<_>>();
    let support = MktProfileSupport {
        profile_id: profile["id"].as_str().unwrap(),
        version: profile["version"].as_u64().unwrap(),
        critical_members: &critical,
        understood_members: &understood,
    };

    assert!(MKT_EXECUTABLE_PROFILES.is_empty());

    assert_eq!(
        validate_mkt_private_with_profiles(&base, &[])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfile
    );
    assert_eq!(
        validate_mkt_private_with_profiles(&base, &[support])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedCriticalMember
    );

    let understood_all = ["terms", "future"];
    let complete_support = MktProfileSupport {
        understood_members: &understood_all,
        ..support
    };
    assert!(validate_mkt_private_with_profiles(&base, &[complete_support]).is_ok());

    let mut unknown_id = base.clone();
    replace_tag(&mut unknown_id, vec!["profile", "unknown", "1"]);
    unknown_id.content = unknown_id.content.replace("conformance", "unknown");
    assert!(validate_mkt_private_base(&unknown_id).is_ok());
    assert_eq!(
        validate_mkt_private_with_profiles(&unknown_id, &[complete_support])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfile
    );

    let mut unknown_version = base;
    replace_tag(&mut unknown_version, vec!["profile", "conformance", "2"]);
    unknown_version.content = unknown_version
        .content
        .replace("\"profile_version\":1", "\"profile_version\":2");
    assert!(validate_mkt_private_base(&unknown_version).is_ok());
    assert_eq!(
        validate_mkt_private_with_profiles(&unknown_version, &[complete_support])
            .unwrap_err()
            .code,
        MktValidationCode::UnsupportedProfileVersion
    );
}

#[test]
fn nipmkt_identifier_hex_and_version_boundaries() {
    let fixture = fixture();
    let base = event_from_fixture(&fixture["base"]);

    for profile_id in ["a".to_owned(), "a".repeat(64)] {
        let mut event = base.clone();
        set_profile(&mut event, &profile_id, "1", Value::from(1));
        assert!(validate_mkt_private_base(&event).is_ok());
    }
    for profile_id in [
        String::new(),
        "a".repeat(65),
        ".bad".to_owned(),
        "é".to_owned(),
    ] {
        let mut event = base.clone();
        set_profile(&mut event, &profile_id, "1", Value::from(1));
        assert!(validate_mkt_private_base(&event).is_err());
    }

    for name in ["d", "session"] {
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let mut event = base.clone();
            replace_tag(&mut event, vec![name, &invalid]);
            assert!(
                validate_mkt_private_base(&event).is_err(),
                "{name} {invalid}"
            );
        }
    }

    let mut maximum_version = base.clone();
    set_profile(
        &mut maximum_version,
        "conformance",
        &u64::MAX.to_string(),
        Value::from(u64::MAX),
    );
    assert!(validate_mkt_private_base(&maximum_version).is_ok());
    for tag_version in ["0", "01", "-1", "18446744073709551616"] {
        let mut event = base.clone();
        set_profile(&mut event, "conformance", tag_version, Value::from(1));
        assert!(validate_mkt_private_base(&event).is_err());
    }
    for body_version in [
        Value::from(0),
        Value::from(-1),
        Value::from(1.5),
        Value::from("1"),
    ] {
        let mut event = base.clone();
        set_profile(&mut event, "conformance", "1", body_version);
        assert!(validate_mkt_private_base(&event).is_err());
    }
}

#[test]
fn nipmkt_raw_signed_record_bound_is_exact_and_crypto_checked() {
    let fixture = fixture();
    let maximum_bytes = usize::try_from(
        fixture["limits"]["serialized_private_bytes"]
            .as_u64()
            .unwrap(),
    )
    .unwrap();
    let mut event = event_from_fixture(&fixture["base"]);
    let prefix = event.content.trim_end_matches('}').to_owned() + ",\"padding\":\"";
    let suffix = "\"}";
    event.content = format!("{prefix}{suffix}");
    sign(&mut event, 7);
    let fixed_bytes = serde_json::to_vec(&event).unwrap().len();
    event.content = format!(
        "{prefix}{}{suffix}",
        "x".repeat(maximum_bytes - fixed_bytes)
    );
    sign(&mut event, 7);
    let raw = serde_json::to_vec(&event).unwrap();
    assert_eq!(raw.len(), maximum_bytes);
    let support = complete_profile_support();
    let validated = validate_mkt_private_raw(&raw, &[support]).unwrap();
    assert_eq!(validated.raw_signed_event(), raw);

    let mut oversized_raw = raw.clone();
    oversized_raw.push(b' ');
    assert_eq!(oversized_raw.len(), maximum_bytes + 1);
    assert!(validate_mkt_private_base(&event).is_ok());
    assert_eq!(
        validate_mkt_private_raw(&oversized_raw, &[support])
            .unwrap_err()
            .code,
        MktValidationCode::EventTooLarge
    );

    let mut bad_signature = serde_json::to_vec(&event).unwrap();
    let signature_position = bad_signature
        .windows(128)
        .position(|window| window == event.sig.as_bytes())
        .unwrap();
    bad_signature[signature_position] = if bad_signature[signature_position] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert_eq!(
        validate_mkt_private_raw(&bad_signature, &[support])
            .unwrap_err()
            .code,
        MktValidationCode::InvalidEventSignature
    );

    let compact =
        String::from_utf8(serde_json::to_vec(&event_from_signed_fixture()).unwrap()).unwrap();
    let duplicate_outer = compact.replacen("\"kind\":39604", "\"kind\":39604,\"kind\":39604", 1);
    assert_eq!(
        validate_mkt_private_raw(duplicate_outer.as_bytes(), &[support])
            .unwrap_err()
            .code,
        MktValidationCode::DuplicateJsonMember
    );

    event.content = fixture["base"]["content"].as_str().unwrap().to_owned();
    sign(&mut event, 7);
    let raw = serde_json::to_vec(&event).unwrap();
    let unknown_outer = String::from_utf8(raw)
        .unwrap()
        .replacen("{", "{\"extension\":true,", 1);
    assert_eq!(
        validate_mkt_private_raw(unknown_outer.as_bytes(), &[support])
            .unwrap_err()
            .code,
        MktValidationCode::InvalidEventShape
    );
}

fn complete_profile_support() -> MktProfileSupport<'static> {
    MktProfileSupport {
        profile_id: "conformance",
        version: 1,
        critical_members: &["terms", "future"],
        understood_members: &["terms", "future"],
    }
}

#[test]
fn nipmkt_collection_and_serialized_bounds_are_inclusive() {
    let fixture = fixture();
    let limits = &fixture["limits"];
    let base = event_from_fixture(&fixture["base"]);

    assert_private_tag_cap(&base, "p", limits["p_tags"].as_u64().unwrap(), || {
        vec![
            "p".into(),
            "d".repeat(64),
            String::new(),
            "requester".into(),
        ]
    });
    assert_private_tag_cap(&base, "e", limits["references"].as_u64().unwrap(), || {
        vec!["e".into(), "e".repeat(64), String::new(), "evidence".into()]
    });
    assert_private_tag_cap(&base, "relay", limits["hints"].as_u64().unwrap(), || {
        vec!["relay".into(), "wss://relay.example".into()]
    });

    let mut combined_hints = base.clone();
    for index in 0..3 {
        combined_hints.tags.push(Tag::new(vec![
            "relay".into(),
            format!("wss://relay-{index}.example"),
        ]));
    }
    combined_hints.tags.push(Tag::new(vec![
        "p".into(),
        "unrelated".into(),
        "wss://p-hint.example".into(),
    ]));
    combined_hints.tags.push(Tag::new(vec![
        "e".into(),
        "e".repeat(64),
        "wss://e-hint.example".into(),
        "evidence".into(),
    ]));
    combined_hints.tags.push(Tag::new(vec![
        "a".into(),
        "30000:any:subject".into(),
        "wss://a-hint.example".into(),
        "subject".into(),
    ]));
    combined_hints.tags.push(Tag::new(vec![
        "p".into(),
        "unrelated".into(),
        "wss://second-p-hint.example".into(),
    ]));
    combined_hints.tags.push(Tag::new(vec![
        "relay".into(),
        "wss://eighth.example".into(),
    ]));
    assert!(validate_mkt_private_base(&combined_hints).is_ok());
    combined_hints
        .tags
        .push(Tag::new(vec!["relay".into(), "wss://ninth.example".into()]));
    assert!(validate_mkt_private_base(&combined_hints).is_err());

    let maximum_tags = usize::try_from(limits["tags"].as_u64().unwrap()).unwrap();
    let mut at_tag_cap = base.clone();
    while at_tag_cap.tags.len() < maximum_tags {
        at_tag_cap.tags.push(Tag::new(vec!["t".into(), "x".into()]));
    }
    assert!(validate_mkt_private_base(&at_tag_cap).is_ok());
    at_tag_cap.tags.push(Tag::new(vec!["t".into(), "x".into()]));
    assert!(validate_mkt_private_base(&at_tag_cap).is_err());

    let maximum_bytes =
        usize::try_from(limits["serialized_private_bytes"].as_u64().unwrap()).unwrap();
    let mut at_size_cap = base.clone();
    let prefix = at_size_cap.content.trim_end_matches('}').to_owned() + ",\"padding\":\"";
    let suffix = "\"}";
    let fixed_event_bytes = {
        at_size_cap.content = format!("{prefix}{suffix}");
        serde_json::to_vec(&at_size_cap).unwrap().len()
    };
    at_size_cap.content = format!(
        "{prefix}{}{suffix}",
        "x".repeat(maximum_bytes - fixed_event_bytes)
    );
    assert_eq!(
        serde_json::to_vec(&at_size_cap).unwrap().len(),
        maximum_bytes
    );
    assert!(validate_mkt_private_base(&at_size_cap).is_ok());
    at_size_cap
        .content
        .insert(at_size_cap.content.len() - 2, 'x');
    assert!(validate_mkt_private_base(&at_size_cap).is_err());
}

#[test]
fn nipmkt_public_collections_use_the_common_caps() {
    let fixture = fixture();
    let limits = &fixture["limits"];
    let mut provider = Event {
        id: "0".repeat(64),
        pubkey: "1".repeat(64),
        created_at: 0,
        kind: MKT_PROVIDER_PROFILE_KIND,
        tags: vec![
            Tag::new(vec!["d".into(), "provider".into()]),
            Tag::new(vec!["status".into(), "active".into()]),
            Tag::new(vec!["published_at".into(), "0".into()]),
        ],
        content: "{}".into(),
        sig: "0".repeat(128),
    };
    provider.tags.push(Tag::new(vec![
        "profile".into(),
        "conformance".into(),
        "1".into(),
    ]));
    let mut non_object = provider.clone();
    non_object.content = "[]".into();
    assert!(validate_mkt_public_event(&non_object).is_err());
    let mut duplicate = provider.clone();
    duplicate.content = "{\"nested\":{\"x\":1,\"x\":2}}".into();
    assert!(validate_mkt_public_event(&duplicate).is_err());
    let mut oversized_malformed = provider.clone();
    oversized_malformed.content = "not-json".repeat(2_049);
    assert!(
        validate_mkt_public_event(&oversized_malformed)
            .unwrap_err()
            .contains("content exceeds 16384 bytes")
    );

    for (name, maximum) in [
        ("p", limits["p_tags"].as_u64().unwrap()),
        ("e", limits["references"].as_u64().unwrap()),
        ("relay", limits["hints"].as_u64().unwrap()),
    ] {
        let mut bounded = provider.clone();
        for _ in 0..maximum {
            bounded
                .tags
                .push(Tag::new(vec![name.into(), "value".into()]));
        }
        assert!(
            validate_mkt_public_event(&bounded).is_ok(),
            "public {name} cap"
        );
        bounded
            .tags
            .push(Tag::new(vec![name.into(), "value".into()]));
        assert!(
            validate_mkt_public_event(&bounded).is_err(),
            "public {name} overflow"
        );
    }

    let maximum_tags = usize::try_from(limits["tags"].as_u64().unwrap()).unwrap();
    let mut bounded_tags = provider.clone();
    while bounded_tags.tags.len() < maximum_tags {
        bounded_tags
            .tags
            .push(Tag::new(vec!["t".into(), "x".into()]));
    }
    assert!(validate_mkt_public_event(&bounded_tags).is_ok());
    bounded_tags
        .tags
        .push(Tag::new(vec!["t".into(), "x".into()]));
    assert!(validate_mkt_public_event(&bounded_tags).is_err());

    let maximum_profiles = limits["profiles"].as_u64().unwrap();
    for version in 2..=maximum_profiles {
        provider.tags.push(Tag::new(vec![
            "profile".into(),
            "conformance".into(),
            version.to_string(),
        ]));
    }
    assert!(validate_mkt_public_event(&provider).is_ok());
    provider.tags.push(Tag::new(vec![
        "profile".into(),
        "conformance".into(),
        (maximum_profiles + 1).to_string(),
    ]));
    assert!(validate_mkt_public_event(&provider).is_err());
}

fn assert_private_tag_cap(
    base: &Event,
    name: &str,
    maximum: u64,
    make_tag: impl Fn() -> Vec<String>,
) {
    let mut event = base.clone();
    let existing = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .count();
    for _ in existing..usize::try_from(maximum).unwrap() {
        event.tags.push(Tag::new(make_tag()));
    }
    assert!(validate_mkt_private_base(&event).is_ok(), "{name} cap");
    event.tags.push(Tag::new(make_tag()));
    assert!(
        validate_mkt_private_base(&event).is_err(),
        "{name} overflow"
    );
}

fn event_from_fixture(value: &Value) -> Event {
    Event {
        id: "0".repeat(64),
        pubkey: "1".repeat(64),
        created_at: 0,
        kind: u16::try_from(value["kind"].as_u64().unwrap()).unwrap(),
        tags: value["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| Tag::new(strings(tag.as_array().unwrap())))
            .collect(),
        content: value["content"].as_str().unwrap().to_owned(),
        sig: "0".repeat(128),
    }
}

fn event_from_signed_fixture() -> Event {
    let fixture = fixture();
    let mut event = event_from_fixture(&fixture["base"]);
    sign(&mut event, 7);
    event
}

fn sign(event: &mut Event, secret_byte: u8) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    event.pubkey = keypair.x_only_public_key().0.to_string();
    event.id = event.computed_id().unwrap();
    let id = event.computed_id_bytes().unwrap();
    event.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
}

fn apply_mutation(event: &mut Event, case: &Value) {
    if let Some(name) = case["remove"].as_str() {
        event.tags.retain(|tag| tag.name() != Some(name));
    }
    if let Some(tag) = case["set_tag"].as_array() {
        replace_tag(
            event,
            tag.iter().map(|value| value.as_str().unwrap()).collect(),
        );
    }
    if let Some(tag) = case["add"].as_array() {
        event.tags.push(Tag::new(strings(tag)));
    }
    if let Some(content) = case["content"].as_str() {
        event.content = content.to_owned();
    }
}

fn replace_tag(event: &mut Event, values: Vec<&str>) {
    let name = values[0];
    event
        .tags
        .iter_mut()
        .find(|tag| tag.name() == Some(name))
        .unwrap()
        .0 = values.into_iter().map(str::to_owned).collect();
}

fn set_profile(event: &mut Event, profile_id: &str, tag_version: &str, body_version: Value) {
    replace_tag(event, vec!["profile", profile_id, tag_version]);
    let mut body: Value = serde_json::from_str(&event.content).unwrap();
    body["profile"] = Value::from(profile_id);
    body["profile_version"] = body_version;
    event.content = serde_json::to_string(&body).unwrap();
}

fn strings(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/common-grammar.json"
    ))
    .unwrap()
}
