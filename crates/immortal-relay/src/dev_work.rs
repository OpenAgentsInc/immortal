//! Dev work-item seeder for NIP-WK / NIP-PI (immortal#33).
//!
//! Builds authority-signed Work Records (kind 32170), Issue Projections
//! (kind 32200), and minimal Work Event chains (kind 32171, `created`)
//! from the checked-in public-safe snapshot of the OpenAgentsInc/omega
//! open-issue planning graph in `scripts/dev-work-items.json`. Payloads
//! carry only titles, states, labels, and issue URLs — never issue bodies.
//!
//! The signing key is a throwaway dev authority per the dev-seed key
//! conventions: `IMMORTAL_DEV_WORK_AUTHORITY_SECRET` selects the pinned
//! dev authority recorded in `scripts/dev-work-authority.md`; without it a
//! fresh ephemeral keypair is generated. Relay acceptance is transport
//! evidence only, and this dev key confers no organizational authority.

use serde::Serialize;
use serde_json::Value;

use crate::{
    dev_market::{
        RelayClient, close_socket, connect, publish, random_hex_32, read_json, send_json, tag,
        unix_now,
    },
    domain::{Event, RelaySigner, Tag, validate_openagents_work_event},
};

const WORK_ITEMS_SNAPSHOT: &str = include_str!("../../../scripts/dev-work-items.json");
const SNAPSHOT_SCHEMA: &str = "openagents.immortal.dev-work-items.v1";
const ORGANIZATION_REF: &str = "org-openagents";
const TEAM_REF: &str = "team-omega";
const WORK_DOMAIN: &str = "development";
const MAX_WORK_ITEMS: usize = 256;
const MAX_TITLE_BYTES: usize = 256;

#[derive(Debug, Serialize)]
pub struct DevWorkTrace {
    pub contract_version: u64,
    pub mode: &'static str,
    pub relay_url: Option<String>,
    pub authority_pubkey: String,
    pub authority_source: &'static str,
    pub work_items: usize,
    pub published: usize,
    pub queries: Vec<DevWorkQuery>,
    pub events: Vec<Event>,
    pub settlement_claim: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DevWorkQuery {
    pub filter: Value,
    pub matched: usize,
}

struct WorkItem {
    number: u64,
    title: String,
    state: String,
    labels: Vec<String>,
    url: String,
}

pub fn seed(
    relay_url: Option<&str>,
    authority_secret: Option<&str>,
) -> Result<DevWorkTrace, String> {
    let (signer, authority_source) = match authority_secret {
        Some(secret) => (
            RelaySigner::from_secret_hex(secret)
                .map_err(|error| format!("invalid dev work authority secret: {error}"))?,
            "IMMORTAL_DEV_WORK_AUTHORITY_SECRET",
        ),
        None => (
            RelaySigner::from_secret_hex(&random_hex_32()?)
                .map_err(|error| format!("could not derive an ephemeral authority: {error}"))?,
            "ephemeral",
        ),
    };
    let items = load_work_items()?;
    let now = unix_now()?;
    let mut events = Vec::with_capacity(items.len() * 3);
    for item in &items {
        events.push(work_record(&signer, item, now)?);
        events.push(issue_projection(&signer, item, now)?);
        events.push(work_created_event(&signer, item, now)?);
    }
    for event in &events {
        validate_openagents_work_event(event)
            .map_err(|error| format!("seed event kind {} is invalid: {error}", event.kind))?;
    }

    let Some(relay_url) = relay_url else {
        return Ok(trace(
            "emit",
            None,
            &signer,
            authority_source,
            &items,
            0,
            Vec::new(),
            events,
        ));
    };

    let mut client = connect(relay_url)?;
    let mut published = 0_usize;
    for event in &events {
        publish(&mut client, event)?;
        published += 1;
    }
    let projection_filter = serde_json::json!({
        "kinds": [32_200],
        "authors": [signer.pubkey()],
    });
    let first_work_ref = format!("omega-{}", items.first().map_or(0, |item| item.number));
    let work_event_filter = serde_json::json!({
        "kinds": [32_171],
        "#work": [first_work_ref],
    });
    let queries = vec![
        run_query(&mut client, "dev-work-projections", projection_filter)?,
        run_query(&mut client, "dev-work-events", work_event_filter)?,
    ];
    close_socket(&mut client.websocket);
    Ok(trace(
        "published",
        Some(relay_url.to_owned()),
        &signer,
        authority_source,
        &items,
        published,
        queries,
        events,
    ))
}

#[allow(clippy::too_many_arguments)]
fn trace(
    mode: &'static str,
    relay_url: Option<String>,
    signer: &RelaySigner,
    authority_source: &'static str,
    items: &[WorkItem],
    published: usize,
    queries: Vec<DevWorkQuery>,
    events: Vec<Event>,
) -> DevWorkTrace {
    DevWorkTrace {
        contract_version: 1,
        mode,
        relay_url,
        authority_pubkey: signer.pubkey().to_owned(),
        authority_source,
        work_items: items.len(),
        published,
        queries,
        events,
        settlement_claim: "structure_only; relay acceptance proves transport, not organizational authority or completion",
    }
}

fn load_work_items() -> Result<Vec<WorkItem>, String> {
    let snapshot: Value = serde_json::from_str(WORK_ITEMS_SNAPSHOT)
        .map_err(|error| format!("invalid dev work-items snapshot: {error}"))?;
    if snapshot.get("schema").and_then(Value::as_str) != Some(SNAPSHOT_SCHEMA) {
        return Err(format!(
            "dev work-items snapshot schema must be {SNAPSHOT_SCHEMA}"
        ));
    }
    let issues = snapshot
        .get("issues")
        .and_then(Value::as_array)
        .ok_or_else(|| "dev work-items snapshot requires an issues array".to_owned())?;
    if issues.is_empty() || issues.len() > MAX_WORK_ITEMS {
        return Err(format!(
            "dev work-items snapshot must contain between 1 and {MAX_WORK_ITEMS} issues"
        ));
    }
    issues
        .iter()
        .map(|issue| {
            let number = issue
                .get("number")
                .and_then(Value::as_u64)
                .ok_or_else(|| "issue requires a number".to_owned())?;
            let title = issue
                .get("title")
                .and_then(Value::as_str)
                .map(bounded_title)
                .ok_or_else(|| format!("issue {number} requires a title"))?;
            let state = match issue.get("state").and_then(Value::as_str) {
                Some("OPEN") => "active".to_owned(),
                Some("CLOSED") => "done".to_owned(),
                other => {
                    return Err(format!(
                        "issue {number} has an unmapped state {other:?}; extend the WK baseline mapping"
                    ));
                }
            };
            let labels = issue
                .get("labels")
                .and_then(Value::as_array)
                .map(|labels| {
                    labels
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let url = issue
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("issue {number} requires a url"))?
                .to_owned();
            Ok(WorkItem {
                number,
                title,
                state,
                labels,
                url,
            })
        })
        .collect()
}

fn work_record(signer: &RelaySigner, item: &WorkItem, now: u64) -> Result<Event, String> {
    let work_ref = work_ref(item);
    let mut tags = vec![
        tag(&["d", &work_ref]),
        tag(&["org", ORGANIZATION_REF]),
        tag(&["domain", WORK_DOMAIN]),
        tag(&["state", &item.state]),
        tag(&["revision", "1"]),
        tag(&["title", &item.title]),
        Tag::new(vec![
            "p".into(),
            signer.pubkey().into(),
            String::new(),
            "owner".into(),
        ]),
        tag(&["published_at", &now.to_string()]),
        tag(&["r", &item.url]),
    ];
    push_labels(&mut tags, item);
    Ok(signer.sign(now, 32_170, tags, String::new()))
}

fn issue_projection(signer: &RelaySigner, item: &WorkItem, now: u64) -> Result<Event, String> {
    let work_ref = work_ref(item);
    let identifier = format!("OMEGA-{}", item.number);
    let mut tags = vec![
        tag(&["d", &work_ref]),
        tag(&["org", ORGANIZATION_REF]),
        tag(&["team", TEAM_REF]),
        tag(&["identifier", &identifier]),
        tag(&["title", &item.title]),
        tag(&["state", &item.state]),
        tag(&["revision", "1"]),
        tag(&["published_at", &now.to_string()]),
        tag(&["r", &item.url]),
    ];
    push_labels(&mut tags, item);
    Ok(signer.sign(now, 32_200, tags, String::new()))
}

fn work_created_event(signer: &RelaySigner, item: &WorkItem, now: u64) -> Result<Event, String> {
    let work_ref = work_ref(item);
    let tags = vec![
        tag(&["d", &format!("{work_ref}:evt:1")]),
        tag(&["work", &work_ref]),
        tag(&["seq", "1"]),
        tag(&["event", "created"]),
        Tag::new(vec![
            "p".into(),
            signer.pubkey().into(),
            String::new(),
            "actor".into(),
        ]),
        tag(&["occurred_at", &now.to_string()]),
        tag(&["admitted_at", &now.to_string()]),
        tag(&["revision", "1"]),
    ];
    Ok(signer.sign(now, 32_171, tags, String::new()))
}

fn work_ref(item: &WorkItem) -> String {
    format!("omega-{}", item.number)
}

fn push_labels(tags: &mut Vec<Tag>, item: &WorkItem) {
    for label in &item.labels {
        tags.push(tag(&["t", label]));
    }
}

fn bounded_title(title: &str) -> String {
    let mut cleaned = title
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    while cleaned.len() > MAX_TITLE_BYTES {
        let mut boundary = cleaned.len() - 1;
        while !cleaned.is_char_boundary(boundary) {
            boundary -= 1;
        }
        cleaned.truncate(boundary);
    }
    if cleaned.is_empty() {
        cleaned.push_str("untitled");
    }
    cleaned
}

fn run_query(
    client: &mut RelayClient,
    subscription: &str,
    filter: Value,
) -> Result<DevWorkQuery, String> {
    send_json(
        &mut client.websocket,
        serde_json::json!(["REQ", subscription, filter]),
    )?;
    let mut matched = 0_usize;
    loop {
        let message = read_json(&mut client.websocket)?;
        let frame = message
            .as_array()
            .ok_or_else(|| format!("relay frame is not an array: {message}"))?;
        match frame.first().and_then(Value::as_str) {
            Some("EVENT") if frame.get(1).and_then(Value::as_str) == Some(subscription) => {
                matched += 1;
            }
            Some("EOSE") if frame.get(1).and_then(Value::as_str) == Some(subscription) => {
                send_json(
                    &mut client.websocket,
                    serde_json::json!(["CLOSE", subscription]),
                )?;
                return Ok(DevWorkQuery { filter, matched });
            }
            Some("CLOSED") => {
                return Err(format!("relay closed verification query: {message}"));
            }
            _ => {}
        }
    }
}
