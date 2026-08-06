use std::io::{Read, Write as _};

use immortal::contract::contract_json;
use immortal::domain::{
    Event, OPENAGENTS_ORGANIZATION_KIND, OPENAGENTS_PROJECT_KIND, OPENAGENTS_PROJECT_STATUS_KIND,
    OPENAGENTS_PROJECT_UPDATE_KIND, RelaySigner, Tag, validate_openagents_project_event,
};
use immortal::gateway::GatewayError;
use immortal::{bulk_import::import_jsonl, store::Store};
use serde::Deserialize;

const MAX_INPUT_BYTES: u64 = 64 * 1024;
const MAX_EVENTS: usize = 32;

pub fn print_contract() -> Result<(), GatewayError> {
    let bytes = contract_json().map_err(GatewayError::Internal)?;
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}

pub async fn import_signed_events() -> Result<(), GatewayError> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        GatewayError::Config("import-jsonl requires DATABASE_URL in the environment".to_owned())
    })?;
    if database_url.trim().is_empty() {
        return Err(GatewayError::Config(
            "import-jsonl requires a non-empty DATABASE_URL".to_owned(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            GatewayError::Internal(format!("system clock is before Unix time: {error}"))
        })?
        .as_secs();
    let mut store = Store::connect(&database_url).await?;
    let report = import_jsonl(
        std::io::BufReader::new(std::io::stdin().lock()),
        &mut store,
        now,
    )
    .await
    .map_err(|error| GatewayError::Config(error.to_string()))?;
    serde_json::to_writer(std::io::stdout().lock(), &report).map_err(|error| {
        GatewayError::Internal(format!("could not serialize import report: {error}"))
    })?;
    std::io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

pub fn dev_market_seed() -> Result<(), GatewayError> {
    let relay_url = std::env::var("IMMORTAL_DEV_RELAY_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:18080".to_owned());
    let trace = immortal::dev_market::seed(&relay_url).map_err(GatewayError::Config)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &trace).map_err(|error| {
        GatewayError::Internal(format!("could not serialize smoke trace: {error}"))
    })?;
    std::io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

pub fn dev_work_seed() -> Result<(), GatewayError> {
    let emit_only = std::env::var("IMMORTAL_DEV_WORK_EMIT").as_deref() == Ok("1");
    let relay_url = std::env::var("IMMORTAL_DEV_RELAY_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:18080".to_owned());
    let authority_secret = std::env::var("IMMORTAL_DEV_WORK_AUTHORITY_SECRET").ok();
    let trace = immortal::dev_work::seed(
        (!emit_only).then_some(relay_url.as_str()),
        authority_secret.as_deref(),
    )
    .map_err(GatewayError::Config)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &trace).map_err(|error| {
        GatewayError::Internal(format!("could not serialize work seed trace: {error}"))
    })?;
    std::io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedEvent {
    created_at: u64,
    kind: u16,
    tags: Vec<Tag>,
    content: String,
}

pub fn sign_openagents_project_events() -> Result<(), GatewayError> {
    let secret = std::env::var("IMMORTAL_RELAY_SECRET_KEY").map_err(|_| {
        GatewayError::Config(
            "sign-openagents-project-events requires IMMORTAL_RELAY_SECRET_KEY in the environment"
                .to_owned(),
        )
    })?;
    let signer = RelaySigner::from_secret_hex(&secret)
        .map_err(|error| GatewayError::Config(error.to_string()))?;
    let events = read_unsigned_events(std::io::stdin().lock())?;
    let signed = sign_and_validate(events, &signer)?;
    serde_json::to_writer(std::io::stdout().lock(), &signed).map_err(|error| {
        GatewayError::Internal(format!("could not serialize signed events: {error}"))
    })?;
    std::io::stdout().lock().write_all(b"\n")?;
    Ok(())
}

fn read_unsigned_events(reader: impl Read) -> Result<Vec<UnsignedEvent>, GatewayError> {
    let mut bytes = Vec::new();
    reader.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(GatewayError::Config(
            "OpenAgents project event input exceeds 65536 bytes".to_owned(),
        ));
    }
    let events = serde_json::from_slice::<Vec<UnsignedEvent>>(&bytes)
        .map_err(|error| GatewayError::Config(format!("invalid unsigned event JSON: {error}")))?;
    if events.is_empty() || events.len() > MAX_EVENTS {
        return Err(GatewayError::Config(
            "OpenAgents project event input must contain between 1 and 32 events".to_owned(),
        ));
    }
    Ok(events)
}

fn sign_and_validate(
    events: Vec<UnsignedEvent>,
    signer: &RelaySigner,
) -> Result<Vec<Event>, GatewayError> {
    events
        .into_iter()
        .map(|event| {
            if !matches!(
                event.kind,
                OPENAGENTS_ORGANIZATION_KIND
                    | OPENAGENTS_PROJECT_KIND
                    | OPENAGENTS_PROJECT_STATUS_KIND
                    | OPENAGENTS_PROJECT_UPDATE_KIND
            ) {
                return Err(GatewayError::Config(format!(
                    "kind {} is outside the OpenAgents project signing command",
                    event.kind
                )));
            }
            let event = signer.sign(event.created_at, event.kind, event.tags, event.content);
            validate_openagents_project_event(&event, signer.pubkey()).map_err(|error| {
                GatewayError::Config(format!(
                    "signed OpenAgents project event is invalid: {error}"
                ))
            })?;
            Ok(event)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const TEST_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn signs_only_valid_project_records() {
        let signer = RelaySigner::from_secret_hex(TEST_SECRET).expect("test secret is valid");
        let event = UnsignedEvent {
            created_at: 1_785_824_400,
            kind: OPENAGENTS_PROJECT_STATUS_KIND,
            tags: vec![
                tag(&["d", "status-started"]),
                tag(&["org", "org-openagents"]),
                tag(&["name", "Active hardening"]),
                tag(&["category", "started"]),
                tag(&["position", "10"]),
                tag(&["revision", "1"]),
            ],
            content: String::new(),
        };

        let signed = sign_and_validate(vec![event], &signer).expect("valid event signs");
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].pubkey, TEST_PUBKEY);
        signed[0].validate_crypto().expect("signature verifies");
    }

    #[test]
    fn rejects_kinds_outside_the_project_contract() {
        let signer = RelaySigner::from_secret_hex(TEST_SECRET).expect("test secret is valid");
        let error = sign_and_validate(
            vec![UnsignedEvent {
                created_at: 1_785_824_400,
                kind: 1,
                tags: Vec::new(),
                content: "not admitted".to_owned(),
            }],
            &signer,
        )
        .expect_err("kind 1 must be refused");
        assert!(error.to_string().contains("outside"));
    }

    fn tag(values: &[&str]) -> Tag {
        Tag::new(values.iter().map(|value| (*value).to_owned()).collect())
    }
}
