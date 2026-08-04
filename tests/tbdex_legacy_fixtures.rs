use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use immortal::tbdex::{
    TBDEX_MAPPING_VERSION, TBDEX_SOURCE_PROTOCOL, TBDEX_SOURCE_REVISION, TbdexLegacyTranslation,
    TbdexPrivateDataStatus, TbdexRefusalCode, TbdexTranslationErrorCode, tbdex_vocabulary,
    translate_tbdex_message, validate_tbdex_rfq_private_data,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn tbdex_schema_and_vector_harvest_is_complete_and_attributed() {
    let fixture = fixture();
    assert_eq!(fixture["attribution"]["license"], "Apache-2.0");
    assert_eq!(
        fixture["attribution"]["commit"],
        "7546a079bb860e7ede8125739b7970810a2df314"
    );
    assert!(
        fixture["attribution"]["notice"]
            .as_str()
            .is_some_and(|notice| notice.contains("adapted"))
    );

    let schemas = fixture["schema_harvest"]
        .as_array()
        .expect("schema harvest must be an array");
    assert_eq!(schemas.len(), 9);
    let mut schema_kinds = BTreeSet::new();
    for schema in schemas {
        let kind = schema["kind"].as_str().expect("schema kind must be text");
        assert!(schema_kinds.insert(kind));
        assert_lower_hex_digest(&schema["sha256"]);
        let vocabulary = tbdex_vocabulary(kind).expect("harvested kind must be supported");
        assert_eq!(
            serde_json::to_value(&vocabulary.required_data_fields)
                .expect("required fields must serialize"),
            schema["required"]
        );
        assert_eq!(
            serde_json::to_value(&vocabulary.optional_data_fields)
                .expect("optional fields must serialize"),
            schema["optional"]
        );
        assert_eq!(
            vocabulary
                .target_kind
                .map(Value::from)
                .unwrap_or(Value::Null),
            schema["target_kind"]
        );
    }

    let vectors = fixture["parse_vector_harvest"]
        .as_array()
        .expect("vector harvest must be an array");
    assert_eq!(vectors.len(), 10);
    let mut paths = BTreeSet::new();
    let mut path_kinds = BTreeMap::new();
    let mut by_kind = BTreeMap::<&str, usize>::new();
    for vector in vectors {
        let kind = vector["kind"].as_str().expect("vector kind must be text");
        let path = vector["path"].as_str().expect("vector path must be text");
        assert!(paths.insert(path));
        assert_eq!(path_kinds.insert(path, kind), None);
        assert!(schema_kinds.contains(kind));
        assert_lower_hex_digest(&vector["sha256"]);
        *by_kind.entry(kind).or_default() += 1;
    }
    assert_eq!(by_kind.get("rfq"), Some(&2));
    assert!(schema_kinds.iter().all(|kind| by_kind.contains_key(kind)));

    let translated_paths = fixture["translated_cases"]
        .as_array()
        .expect("translated cases must be an array")
        .iter()
        .map(|case| {
            case["source_vector"]
                .as_str()
                .expect("translated case must name its source vector")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(translated_paths, paths);
    for case in fixture["translated_cases"]
        .as_array()
        .expect("translated cases must be an array")
    {
        let path = case["source_vector"]
            .as_str()
            .expect("translated case must name its source vector");
        assert_eq!(
            case["input"]["metadata"]["kind"].as_str(),
            path_kinds.get(path).copied()
        );
    }
}

#[test]
fn tbdex_pinned_upstream_bytes_replay_one_for_one() {
    let fixture = fixture();
    for schema in fixture["schema_harvest"]
        .as_array()
        .expect("schema harvest must be an array")
    {
        let bytes = vendored_bytes("schemas", schema["path"].as_str().expect("schema path"));
        assert_eq!(sha256_hex(&bytes), schema["sha256"]);
        serde_json::from_slice::<Value>(&bytes).expect("pinned schema must remain JSON");
    }

    let mut replayed = BTreeSet::new();
    for vector in fixture["parse_vector_harvest"]
        .as_array()
        .expect("vector harvest must be an array")
    {
        let source_path = vector["path"].as_str().expect("vector path");
        let bytes = vendored_bytes("vectors", source_path);
        assert_eq!(sha256_hex(&bytes), vector["sha256"]);
        let pinned: Value =
            serde_json::from_slice(&bytes).expect("pinned vector must remain exact JSON");
        let raw_input = pinned["input"]
            .as_str()
            .expect("pinned vector input must be a JSON string");
        let parsed: Value =
            serde_json::from_str(raw_input).expect("pinned input must parse as JSON");
        assert_eq!(parsed, pinned["output"]);

        let translation =
            translate_tbdex_message(raw_input.as_bytes()).expect("pinned input must translate");
        assert!(!translation.executable);
        assert_eq!(translation.source_digest, sha256_hex(raw_input.as_bytes()));
        assert_eq!(translation.source_kind, vector["kind"]);
        assert!(replayed.insert(source_path));

        match Path::new(source_path)
            .file_name()
            .and_then(|name| name.to_str())
        {
            Some("parse-rfq.json") => assert_eq!(
                validate_tbdex_rfq_private_data(raw_input.as_bytes())
                    .expect("attached upstream RFQ must verify"),
                TbdexPrivateDataStatus::Verified {
                    commitments: vec![
                        "claims".to_owned(),
                        "payin.paymentDetails".to_owned(),
                        "payout.paymentDetails".to_owned(),
                    ]
                }
            ),
            Some("parse-rfq-omit-private-data.json") => assert_eq!(
                validate_tbdex_rfq_private_data(raw_input.as_bytes())
                    .expect("detached upstream RFQ must validate"),
                TbdexPrivateDataStatus::Detached
            ),
            _ => {}
        }
    }
    assert_eq!(replayed.len(), 10);
}

#[test]
fn tbdex_translation_is_deterministic_loss_accounted_and_non_executable() {
    let fixture = fixture();
    for case in fixture["translated_cases"]
        .as_array()
        .expect("translated cases must be an array")
    {
        let raw = serde_json::to_vec(&case["input"]).expect("case input must serialize");
        let translation = translate_tbdex_message(&raw).expect("case must translate to an audit");
        assert_eq!(
            translation,
            translate_tbdex_message(&raw).expect("same input must translate deterministically")
        );
        assert_eq!(translation.source_protocol, TBDEX_SOURCE_PROTOCOL);
        assert_eq!(translation.source_revision, TBDEX_SOURCE_REVISION);
        assert_eq!(translation.mapping_version, TBDEX_MAPPING_VERSION);
        assert!(!translation.executable);
        assert_lower_hex(&translation.source_digest, 64);
        assert_eq!(
            translation
                .target_kind
                .map(Value::from)
                .unwrap_or(Value::Null),
            case["target_kind"]
        );
        assert!(translation.refusals.iter().any(|refusal| {
            refusal.code == TbdexRefusalCode::UnrepresentableAuthority
                && refusal.detail.contains("DID/JOSE")
        }));
        assert_eq!(
            translation
                .refusals
                .iter()
                .any(|refusal| refusal.code == TbdexRefusalCode::UnrepresentableState),
            case["state_refusal"]
                .as_bool()
                .expect("state_refusal must be boolean")
        );
        assert_eq!(
            translation
                .field_mappings
                .iter()
                .map(|mapping| mapping.source.as_str())
                .collect::<Vec<_>>(),
            case["mapped_sources"]
                .as_array()
                .expect("mapped_sources must be an array")
                .iter()
                .map(|value| value.as_str().expect("mapped source must be text"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            translation.defaulted_fields,
            case["defaulted_fields"]
                .as_array()
                .expect("defaulted_fields must be an array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("defaulted field must be text")
                        .to_owned()
                })
                .collect::<Vec<_>>()
        );
        assert!(
            translation
                .dropped_fields
                .iter()
                .any(|field| field.contains("signature"))
        );
        let required_ambiguous = case["required_ambiguous"]
            .as_str()
            .expect("required_ambiguous must be text");
        assert!(
            translation
                .ambiguous_fields
                .iter()
                .any(|field| field.contains(required_ambiguous))
        );

        match case["source_vector"]
            .as_str()
            .expect("case must name its source vector")
        {
            "hosted/test-vectors/protocol/vectors/parse-rfq.json" => {
                assert_eq!(
                    validate_tbdex_rfq_private_data(&raw)
                        .expect("attached RFQ commitment must verify"),
                    TbdexPrivateDataStatus::Verified {
                        commitments: vec!["payin.paymentDetails".to_owned()]
                    }
                );
            }
            "hosted/test-vectors/protocol/vectors/parse-rfq-omit-private-data.json" => {
                assert_eq!(
                    validate_tbdex_rfq_private_data(&raw)
                        .expect("detached RFQ commitment must remain valid"),
                    TbdexPrivateDataStatus::Detached
                );
            }
            _ => {}
        }

        let encoded = serde_json::to_vec(&translation).expect("translation must serialize");
        let decoded: TbdexLegacyTranslation =
            serde_json::from_slice(&encoded).expect("translation must deserialize");
        assert_eq!(decoded, translation);
    }
}

#[test]
fn tbdex_cancel_and_order_instructions_keep_the_nip_mkt_boundary() {
    let fixture = fixture();
    let cases = fixture["translated_cases"]
        .as_array()
        .expect("translated cases must be an array");
    let cancel = case(cases, "cancel-request-only");
    let cancel_raw = serde_json::to_vec(&cancel["input"]).expect("cancel must serialize");
    let cancel = translate_tbdex_message(&cancel_raw).expect("cancel audit must translate");
    assert!(
        cancel
            .defaulted_fields
            .iter()
            .any(|field| field == "action=request (a legacy Cancel has no immediate effect)")
    );
    assert!(
        !cancel
            .refusals
            .iter()
            .any(|refusal| { refusal.code == TbdexRefusalCode::UnrepresentableState })
    );

    let instructions = case(cases, "order-instructions-off-relay");
    let instructions_raw =
        serde_json::to_vec(&instructions["input"]).expect("instructions must serialize");
    let instructions =
        translate_tbdex_message(&instructions_raw).expect("instructions audit must translate");
    assert!(
        instructions
            .dropped_fields
            .iter()
            .filter(|field| field.contains("direct protected channel only"))
            .count()
            == 2
    );
    assert!(
        instructions
            .ambiguous_fields
            .iter()
            .any(|field| { field.contains("digest, expiry, and direct-channel correlation") })
    );
    assert!(instructions.refusals.iter().any(|refusal| {
        refusal.code == TbdexRefusalCode::UnrepresentableState
            && refusal.detail.contains("Status sequence")
    }));
}

#[test]
fn tbdex_private_data_commitments_verify_without_persisting_cleartext() {
    let fixture = fixture();
    let positive = &fixture["privacy_commitment"]["positive"];
    let raw = serde_json::to_vec(positive).expect("positive privacy case must serialize");
    assert_eq!(
        validate_tbdex_rfq_private_data(&raw).expect("commitments must verify"),
        TbdexPrivateDataStatus::Verified {
            commitments: vec![
                "claims".to_owned(),
                "payin.paymentDetails".to_owned(),
                "payout.paymentDetails".to_owned(),
            ]
        }
    );

    let mut detached = positive.clone();
    detached
        .as_object_mut()
        .expect("privacy fixture must be an object")
        .remove("privateData");
    let detached_raw = serde_json::to_vec(&detached).expect("detached case must serialize");
    assert_eq!(
        validate_tbdex_rfq_private_data(&detached_raw)
            .expect("detached commitments remain a valid disclosure shape"),
        TbdexPrivateDataStatus::Detached
    );

    let negative = &fixture["privacy_commitment"]["negative"];
    let negative_raw = serde_json::to_vec(negative).expect("negative privacy case must serialize");
    let error = validate_tbdex_rfq_private_data(&negative_raw)
        .expect_err("changed private-data commitment must fail closed");
    assert_eq!(error.code, TbdexTranslationErrorCode::PrivateDataMismatch);
    assert!(error.detail.contains("claims"));

    let mut numeric = positive.clone();
    numeric["privateData"]["payin"]["paymentDetails"] = Value::from(1);
    let numeric_raw = serde_json::to_vec(&numeric).expect("numeric privacy case must serialize");
    let error = validate_tbdex_rfq_private_data(&numeric_raw)
        .expect_err("private JSON number must fail until full JCS number support exists");
    assert_eq!(
        error.code.as_str(),
        fixture["privacy_commitment"]["numeric_private_data_policy"]
            .as_str()
            .expect("numeric policy must be text")
    );
}

#[test]
fn tbdex_parser_rejects_duplicate_unsupported_and_invented_fields() {
    let fixture = fixture();
    let duplicate = fixture["fail_closed"]["duplicate_member"]
        .as_str()
        .expect("duplicate fixture must be text");
    assert_eq!(
        translate_tbdex_message(duplicate.as_bytes())
            .expect_err("duplicate JSON member must fail")
            .code,
        TbdexTranslationErrorCode::DuplicateJsonMember
    );

    let unsupported = serde_json::to_vec(&fixture["fail_closed"]["unsupported_protocol"])
        .expect("unsupported fixture must serialize");
    assert_eq!(
        translate_tbdex_message(&unsupported)
            .expect_err("unsupported source revision must fail")
            .code,
        TbdexTranslationErrorCode::UnsupportedProtocol
    );

    let invented = serde_json::to_vec(&fixture["fail_closed"]["unknown_data_field"])
        .expect("invented field fixture must serialize");
    assert_eq!(
        translate_tbdex_message(&invented)
            .expect_err("invented authority field must fail")
            .code,
        TbdexTranslationErrorCode::InvalidShape
    );
}

#[test]
fn tbdex_nested_shapes_and_private_data_fail_closed() {
    let mut malformed_detached = exact_output("parse-rfq-omit-private-data.json");
    malformed_detached["data"]["payin"] = Value::String("invented".to_owned());
    assert_invalid_private_data(malformed_detached);

    let mut invented_private = exact_output("parse-rfq.json");
    invented_private["privateData"]["invented"] = Value::Bool(true);
    assert_invalid_private_data(invented_private);

    let mut empty_private = exact_output("parse-rfq-omit-private-data.json");
    empty_private["data"]
        .as_object_mut()
        .expect("RFQ data must be an object")
        .remove("claimsHash");
    empty_private["data"]["payin"]
        .as_object_mut()
        .expect("RFQ payin must be an object")
        .remove("paymentDetailsHash");
    empty_private["data"]["payout"]
        .as_object_mut()
        .expect("RFQ payout must be an object")
        .remove("paymentDetailsHash");
    empty_private["privateData"] = serde_json::json!({"salt": "fixture"});
    assert_invalid_private_data(empty_private);

    let mut invented_nested = exact_output("parse-rfq-omit-private-data.json");
    invented_nested["data"]["payin"]["authority"] = Value::String("invented".to_owned());
    assert_invalid_translation(invented_nested);

    let mut numeric_quote = exact_output("parse-quote.json");
    numeric_quote["data"]["payin"]["fee"] = Value::from(1);
    assert_invalid_translation(numeric_quote);

    let mut unknown_status = exact_output("parse-orderstatus.json");
    unknown_status["data"]["status"] = Value::String("SETTLED".to_owned());
    assert_invalid_translation(unknown_status);

    let mut invented_method = exact_output("parse-offering.json");
    invented_method["data"]["payin"]["methods"][0]["authority"] =
        Value::String("invented".to_owned());
    assert_invalid_translation(invented_method);
}

#[test]
fn tbdex_optional_metadata_is_loss_accounted() {
    let offering = exact_output("parse-offering.json");
    let raw = serde_json::to_vec(&offering).expect("offering must serialize");
    let offering = translate_tbdex_message(&raw).expect("offering must translate");
    assert!(
        offering
            .dropped_fields
            .iter()
            .any(|field| field.starts_with("metadata.updatedAt "))
    );

    let order = exact_output("parse-order.json");
    let raw = serde_json::to_vec(&order).expect("order must serialize");
    let order = translate_tbdex_message(&raw).expect("order must translate");
    assert!(
        order
            .ambiguous_fields
            .iter()
            .any(|field| field.starts_with("metadata.externalId "))
    );
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipmkt/tbdex-legacy.json"))
        .expect("tbDEX legacy fixture must parse")
}

fn vendored_bytes(section: &str, source_path: &str) -> Vec<u8> {
    let file_name = Path::new(source_path)
        .file_name()
        .expect("pinned source path must have a file name");
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nipmkt/tbdex-upstream")
            .join(section)
            .join(file_name),
    )
    .expect("pinned upstream bytes must be committed")
}

fn exact_output(file_name: &str) -> Value {
    let bytes = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nipmkt/tbdex-upstream/vectors")
            .join(file_name),
    )
    .expect("pinned upstream vector must be committed");
    serde_json::from_slice::<Value>(&bytes).expect("pinned vector must parse")["output"].clone()
}

fn assert_invalid_translation(value: Value) {
    let raw = serde_json::to_vec(&value).expect("negative case must serialize");
    assert_eq!(
        translate_tbdex_message(&raw)
            .expect_err("malformed nested source must fail closed")
            .code,
        TbdexTranslationErrorCode::InvalidShape
    );
}

fn assert_invalid_private_data(value: Value) {
    let raw = serde_json::to_vec(&value).expect("negative case must serialize");
    assert_eq!(
        validate_tbdex_rfq_private_data(&raw)
            .expect_err("malformed private source must fail closed")
            .code,
        TbdexTranslationErrorCode::InvalidShape
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn case<'a>(cases: &'a [Value], id: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| case["id"] == id)
        .expect("named translated case must exist")
}

fn assert_lower_hex_digest(value: &Value) {
    assert_lower_hex(value.as_str().expect("digest must be text"), 64);
}

fn assert_lower_hex(value: &str, length: usize) {
    assert_eq!(value.len(), length);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}
