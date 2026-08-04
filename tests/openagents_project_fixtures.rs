//! Fixture-backed Operation Diamond Hands Phase 0 protocol/client coverage.

use immortal::client::{ConnectionState, ProjectActivityKind, ProjectClient, ProjectClientConfig};
use immortal::domain::{
    Event, OPENAGENTS_ORGANIZATION_KIND, OPENAGENTS_PROJECT_KIND, OPENAGENTS_PROJECT_STATUS_KIND,
    OPENAGENTS_PROJECT_UPDATE_KIND, OpenAgentsProjectEvent, Tag, validate_openagents_project_event,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ORGANIZATION_REF: &str = "org-openagents";
const PROJECT_REF: &str = "operation-diamond-hands";
const SUBSCRIPTION_ID: &str = "dh-project-v1";

#[test]
fn nipotpg_fixture_validates_the_four_phase_zero_records() {
    let fixture = fixture();
    assert_eq!(fixture["adopted_kinds"]["organization"], 32_100);
    assert_eq!(fixture["adopted_kinds"]["project"], 32_222);
    assert_eq!(fixture["adopted_kinds"]["project_status"], 32_223);
    assert_eq!(fixture["adopted_kinds"]["project_update"], 32_226);

    let authority = pubkey(3);
    let records = records(3, 4, 100, 1);
    assert!(matches!(
        validate_openagents_project_event(&records.organization, &authority),
        Ok(OpenAgentsProjectEvent::Organization(_))
    ));
    assert!(matches!(
        validate_openagents_project_event(&records.project, &authority),
        Ok(OpenAgentsProjectEvent::Project(_))
    ));
    assert!(matches!(
        validate_openagents_project_event(&records.status, &authority),
        Ok(OpenAgentsProjectEvent::ProjectStatus(_))
    ));
    assert!(matches!(
        validate_openagents_project_event(&records.update, &authority),
        Ok(OpenAgentsProjectEvent::ProjectUpdate(_))
    ));
}

#[test]
fn nipotpg_fixture_rejects_every_pinned_invalid_case() {
    let fixture = fixture();
    let cases = fixture["invalid_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    let authority = pubkey(3);

    for case in cases {
        let name = case.as_str().unwrap();
        let mut bundle = records(3, 4, 100, 1);
        let candidate = match name {
            "wrong-authority" => records(5, 4, 100, 1).project,
            "duplicate-required-tag" => {
                bundle
                    .project
                    .tags
                    .push(Tag::new(vec!["name".into(), "Duplicate".into()]));
                resign(&mut bundle.project, 3);
                bundle.project
            }
            "wrong-status-kind" => {
                replace_two_element_tag(
                    &mut bundle.project,
                    "status",
                    &format!("32224:{}:status-started", pubkey(3)),
                );
                resign(&mut bundle.project, 3);
                bundle.project
            }
            "noncanonical-revision" => {
                replace_two_element_tag(&mut bundle.organization, "revision", "01");
                resign(&mut bundle.organization, 3);
                bundle.organization
            }
            "unknown-status-category" => {
                replace_two_element_tag(&mut bundle.status, "category", "almost_done");
                resign(&mut bundle.status, 3);
                bundle.status
            }
            "unknown-update-health" => {
                replace_two_element_tag(&mut bundle.update, "health", "green");
                resign(&mut bundle.update, 3);
                bundle.update
            }
            "mismatched-update-subject" => {
                let subject = format!("32222:{}:another-project", pubkey(3));
                replace_marked_tag(&mut bundle.update, "a", "subject", &subject);
                resign(&mut bundle.update, 3);
                bundle.update
            }
            "mismatched-content-digest" => {
                bundle.update.content.push_str(" tampered");
                resign(&mut bundle.update, 3);
                bundle.update
            }
            _ => panic!("unknown fixture case: {name}"),
        };
        assert!(
            validate_openagents_project_event(&candidate, &authority).is_err(),
            "case should be rejected: {name}"
        );
    }
}

#[test]
fn project_client_builds_a_bounded_direct_relay_subscription() {
    let client = ProjectClient::new(config()).unwrap();
    let request: Value = serde_json::from_str(&client.subscription_request()).unwrap();
    let frame = request.as_array().unwrap();
    assert_eq!(frame[0], "REQ");
    assert_eq!(frame[1], SUBSCRIPTION_ID);
    assert_eq!(frame.len(), 6);
    assert_eq!(frame[2]["kinds"], json!([OPENAGENTS_ORGANIZATION_KIND]));
    assert_eq!(frame[3]["kinds"], json!([OPENAGENTS_PROJECT_KIND]));
    assert_eq!(frame[4]["kinds"], json!([OPENAGENTS_PROJECT_STATUS_KIND]));
    assert_eq!(frame[5]["#a"], json!([project_address()]));
    assert_eq!(frame[5]["limit"], 8);
}

#[test]
fn project_client_commits_only_at_eose_then_folds_live_events() {
    let mut client = ProjectClient::new(config()).unwrap();
    let bundle = records(3, 4, 100, 1);
    client.opened(100);
    for event in [
        &bundle.organization,
        &bundle.project,
        &bundle.status,
        &bundle.update,
    ] {
        assert!(!client.ingest_text(&event_frame(event), 101).unwrap());
    }
    assert_eq!(client.state(), ConnectionState::Snapshotting);
    assert!(client.snapshot().is_none());

    assert!(
        client
            .ingest_text(&json!(["EOSE", SUBSCRIPTION_ID]).to_string(), 102)
            .unwrap()
    );
    let snapshot = client.snapshot().unwrap();
    assert_eq!(snapshot.organization.as_ref().unwrap().name, "OpenAgents");
    assert_eq!(
        snapshot.project.as_ref().unwrap().name,
        "Operation Diamond Hands"
    );
    assert_eq!(snapshot.status.as_ref().unwrap().category, "started");
    assert_eq!(snapshot.latest_update.as_ref().unwrap().revision, 1);
    assert_eq!(snapshot.recent_activity.len(), 1);
    assert_eq!(client.state(), ConnectionState::Live);

    let second = records(3, 4, 110, 2).update;
    assert!(client.ingest_text(&event_frame(&second), 111).unwrap());
    assert_eq!(
        client
            .snapshot()
            .unwrap()
            .latest_update
            .as_ref()
            .unwrap()
            .revision,
        2
    );
    assert!(!client.ingest_text(&event_frame(&second), 112).unwrap());
    assert_eq!(client.snapshot().unwrap().recent_activity.len(), 2);
}

#[test]
fn project_client_retains_unknown_activity_but_fails_closed_on_bad_events() {
    let mut client = ProjectClient::new(config()).unwrap();
    client.opened(100);
    let unknown = signed_event(
        7,
        100,
        7_777,
        vec![Tag::new(vec!["a".into(), project_address()])],
        "future project activity",
    );
    assert!(!client.ingest_text(&event_frame(&unknown), 101).unwrap());

    let mut invalid = records(3, 4, 100, 1).project;
    invalid.content = "signature no longer matches".into();
    assert!(!client.ingest_text(&event_frame(&invalid), 101).unwrap());
    assert_eq!(client.diagnostics().len(), 1);
    assert!(client.snapshot().is_none());

    client
        .ingest_text(&json!(["EOSE", SUBSCRIPTION_ID]).to_string(), 102)
        .unwrap();
    let activity = &client.snapshot().unwrap().recent_activity;
    assert_eq!(activity.len(), 1);
    assert!(matches!(
        activity[0].kind,
        ProjectActivityKind::Unknown { kind: 7_777 }
    ));

    let before = client.snapshot().cloned();
    assert!(client.ingest_text("not-json", 103).is_err());
    assert_eq!(client.snapshot(), before.as_ref());
}

#[test]
fn project_client_reconnects_without_mixing_partial_snapshots() {
    let mut client = ProjectClient::new(config()).unwrap();
    let records = records(3, 4, 100, 1);
    client.opened(100);
    client
        .ingest_text(&event_frame(&records.project), 101)
        .unwrap();
    client
        .ingest_text(&json!(["EOSE", SUBSCRIPTION_ID]).to_string(), 102)
        .unwrap();
    assert!(client.snapshot().unwrap().project.is_some());

    client.disconnected();
    assert_eq!(client.state(), ConnectionState::Reconnecting);
    assert!(client.snapshot().unwrap().project.is_some());
    client.begin_connect();
    client.opened(110);
    client
        .ingest_text(&event_frame(&records.organization), 111)
        .unwrap();
    assert!(client.snapshot().unwrap().project.is_some());
    client
        .ingest_text(&json!(["EOSE", SUBSCRIPTION_ID]).to_string(), 112)
        .unwrap();
    assert!(client.snapshot().unwrap().organization.is_some());
    assert!(client.snapshot().unwrap().project.is_none());
    assert!(client.mark_stale(200, 30));
    assert_eq!(client.state(), ConnectionState::Stale);
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipotpg/project-read.json")).unwrap()
}

struct Records {
    organization: Event,
    project: Event,
    status: Event,
    update: Event,
}

fn records(authority_secret: u8, author_secret: u8, created_at: u64, revision: u64) -> Records {
    let authority = pubkey(authority_secret);
    let status_address = format!("32223:{authority}:status-started");
    let project_address = format!("32222:{authority}:{PROJECT_REF}");
    let body = format!("Phase {revision} is moving with relay-native proof.");
    let digest = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Records {
        organization: signed_event(
            authority_secret,
            created_at,
            OPENAGENTS_ORGANIZATION_KIND,
            vec![
                Tag::new(vec!["d".into(), ORGANIZATION_REF.into()]),
                Tag::new(vec!["name".into(), "OpenAgents".into()]),
                Tag::new(vec![
                    "p".into(),
                    authority.clone(),
                    "".into(),
                    "authority".into(),
                ]),
                Tag::new(vec!["p".into(), pubkey(1), "".into(), "founder".into()]),
                Tag::new(vec!["relay".into(), "wss://relay.openagents.com".into()]),
                Tag::new(vec!["revision".into(), revision.to_string()]),
                Tag::new(vec!["published_at".into(), created_at.to_string()]),
            ],
            "",
        ),
        project: signed_event(
            authority_secret,
            created_at,
            OPENAGENTS_PROJECT_KIND,
            vec![
                Tag::new(vec!["d".into(), PROJECT_REF.into()]),
                Tag::new(vec!["org".into(), ORGANIZATION_REF.into()]),
                Tag::new(vec!["name".into(), "Operation Diamond Hands".into()]),
                Tag::new(vec!["status".into(), status_address]),
                Tag::new(vec!["p".into(), pubkey(1), "".into(), "owner".into()]),
                Tag::new(vec!["progress".into(), format!("{revision}/4")]),
                Tag::new(vec!["revision".into(), revision.to_string()]),
                Tag::new(vec!["published_at".into(), created_at.to_string()]),
            ],
            "",
        ),
        status: signed_event(
            authority_secret,
            created_at,
            OPENAGENTS_PROJECT_STATUS_KIND,
            vec![
                Tag::new(vec!["d".into(), "status-started".into()]),
                Tag::new(vec!["org".into(), ORGANIZATION_REF.into()]),
                Tag::new(vec!["name".into(), "In progress".into()]),
                Tag::new(vec!["category".into(), "started".into()]),
                Tag::new(vec!["position".into(), "20".into()]),
                Tag::new(vec!["revision".into(), revision.to_string()]),
            ],
            "",
        ),
        update: signed_event(
            authority_secret,
            created_at,
            OPENAGENTS_PROJECT_UPDATE_KIND,
            vec![
                Tag::new(vec!["d".into(), format!("{PROJECT_REF}:upd:{revision}")]),
                Tag::new(vec!["org".into(), ORGANIZATION_REF.into()]),
                Tag::new(vec![
                    "a".into(),
                    project_address,
                    "".into(),
                    "subject".into(),
                ]),
                Tag::new(vec![
                    "p".into(),
                    pubkey(author_secret),
                    "".into(),
                    "author".into(),
                ]),
                Tag::new(vec!["health".into(), "on_track".into()]),
                Tag::new(vec!["published_at".into(), created_at.to_string()]),
                Tag::new(vec!["x".into(), digest]),
            ],
            &body,
        ),
    }
}

fn config() -> ProjectClientConfig {
    ProjectClientConfig {
        relay_url: "wss://relay.openagents.com".into(),
        pinned_authority: pubkey(3),
        organization_ref: ORGANIZATION_REF.into(),
        project_ref: PROJECT_REF.into(),
        subscription_id: SUBSCRIPTION_ID.into(),
        max_events: 32,
        max_activity: 8,
    }
}

fn project_address() -> String {
    format!("32222:{}:{PROJECT_REF}", pubkey(3))
}

fn event_frame(event: &Event) -> String {
    json!(["EVENT", SUBSCRIPTION_ID, event]).to_string()
}

fn replace_two_element_tag(event: &mut Event, name: &str, value: &str) {
    let tag = event
        .tags
        .iter_mut()
        .find(|tag| tag.name() == Some(name))
        .unwrap();
    tag.0 = vec![name.into(), value.into()];
}

fn replace_marked_tag(event: &mut Event, name: &str, marker: &str, value: &str) {
    let tag = event
        .tags
        .iter_mut()
        .find(|tag| {
            tag.name() == Some(name) && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .unwrap();
    tag.0[1] = value.into();
}

fn signed_event(
    secret_byte: u8,
    created_at: u64,
    kind: u16,
    tags: Vec<Tag>,
    content: &str,
) -> Event {
    let mut event = Event {
        id: "0".repeat(64),
        pubkey: pubkey(secret_byte),
        created_at,
        kind,
        tags,
        content: content.to_owned(),
        sig: "0".repeat(128),
    };
    resign(&mut event, secret_byte);
    event
}

fn resign(event: &mut Event, secret_byte: u8) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let digest = event.computed_id_bytes().unwrap();
    event.id = event.computed_id().unwrap();
    event.sig = secp.sign_schnorr_no_aux_rand(&digest, &keypair).to_string();
}

fn pubkey(secret_byte: u8) -> String {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0
        .to_string()
}
