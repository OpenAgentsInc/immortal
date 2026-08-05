use immortal_core::domain::{Event, EventClass, Tag, validate_openagents_work_event};
use serde_json::Value;

const FIXTURE_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn nipwk_work_record_fixture_corpus() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipwk/work-records.json"
    ))
    .unwrap();
    let valid = fixture["valid"].as_array().unwrap();

    for case in valid {
        let event = event_from_case(case);
        assert!(
            validate_openagents_work_event(&event).is_ok(),
            "valid kind {} was rejected: {:?}",
            event.kind,
            validate_openagents_work_event(&event)
        );
    }

    for case in fixture["invalid"].as_array().unwrap() {
        let kind = case["kind"].as_u64().unwrap();
        let base = valid
            .iter()
            .find(|valid_case| valid_case["kind"].as_u64() == Some(kind))
            .unwrap();
        let mut event = event_from_case(base);
        apply_mutation(&mut event, case);
        assert!(
            validate_openagents_work_event(&event).is_err(),
            "invalid fixture was accepted: {}",
            case["name"].as_str().unwrap()
        );
    }
}

#[test]
fn nipwk_kinds_keep_nip01_addressable_classification() {
    for kind in [32_170_u16, 32_171, 32_172, 32_173, 32_200] {
        let event = Event {
            id: "00".repeat(32),
            pubkey: FIXTURE_PUBKEY.to_owned(),
            created_at: 0,
            kind,
            tags: vec![Tag::new(vec!["d".into(), "work-head".into()])],
            content: String::new(),
            sig: "00".repeat(64),
        };
        assert_eq!(EventClass::from_kind(kind), EventClass::Addressable);
        assert_eq!(event.distinct_parameter(), Some("work-head"));
        assert!(event.replacement_address().is_some());
    }
}

#[test]
fn nipwk_validation_ignores_other_kinds() {
    let event = Event {
        id: "00".repeat(32),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 0,
        kind: 1,
        tags: Vec::new(),
        content: "hello".to_owned(),
        sig: "00".repeat(64),
    };
    assert!(validate_openagents_work_event(&event).is_ok());
}

fn event_from_case(case: &Value) -> Event {
    Event {
        id: "00".repeat(32),
        pubkey: FIXTURE_PUBKEY.to_owned(),
        created_at: 0,
        kind: u16::try_from(case["kind"].as_u64().unwrap()).unwrap(),
        tags: case["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| Tag::new(strings(tag.as_array().unwrap())))
            .collect(),
        content: "{}".to_owned(),
        sig: "00".repeat(64),
    }
}

fn apply_mutation(event: &mut Event, case: &Value) {
    if let Some(name) = case["remove"].as_str() {
        event.tags.retain(|tag| tag.name() != Some(name));
    }
    if let Some(pair) = case["set"].as_array() {
        apply_set(event, pair);
    }
    if let Some(pairs) = case["sets"].as_array() {
        for pair in pairs {
            apply_set(event, pair.as_array().unwrap());
        }
    }
    if let Some(set_tag) = case["set_tag"].as_array() {
        let name = set_tag[0].as_str().unwrap();
        let tag = event
            .tags
            .iter_mut()
            .find(|tag| tag.name() == Some(name))
            .unwrap();
        tag.0 = strings(set_tag);
    }
    if let Some(add) = case["add"].as_array() {
        event.tags.push(Tag::new(strings(add)));
    }
    if let Some(content) = case["content"].as_str() {
        event.content = content.to_owned();
    }
    if let Some(bytes) = case["content_bytes"].as_u64() {
        event.content = "x".repeat(usize::try_from(bytes).unwrap());
    }
}

fn apply_set(event: &mut Event, pair: &[Value]) {
    let name = pair[0].as_str().unwrap();
    let tag = event
        .tags
        .iter_mut()
        .find(|tag| tag.name() == Some(name))
        .unwrap();
    tag.0[1] = pair[1].as_str().unwrap().to_owned();
}

fn strings(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}
