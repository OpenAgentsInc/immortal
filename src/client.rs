//! Transport-neutral Nostr client state for browser and native consumers.
//!
//! The embedding application owns the WebSocket. This module owns the wire
//! subscription, signature checks, EOSE boundary, deterministic projection,
//! reconnect semantics, and bounded memory used by Operation Diamond Hands.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::domain::{
    Event, OPENAGENTS_ORGANIZATION_KIND, OPENAGENTS_PROJECT_KIND, OPENAGENTS_PROJECT_STATUS_KIND,
    OPENAGENTS_PROJECT_UPDATE_KIND, OpenAgentsOrganization, OpenAgentsProject,
    OpenAgentsProjectEvent, OpenAgentsProjectStatus, OpenAgentsProjectUpdate, references_project,
    validate_openagents_project_event,
};

const MAX_WIRE_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSTICS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectClientConfig {
    pub relay_url: String,
    pub pinned_authority: String,
    pub organization_ref: String,
    pub project_ref: String,
    pub subscription_id: String,
    pub max_events: usize,
    pub max_activity: usize,
}

impl ProjectClientConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.relay_url.starts_with("wss://") || self.relay_url.len() > 2_048 {
            return Err("relay URL must be a bounded wss URL".to_owned());
        }
        validate_lower_hex(&self.pinned_authority, 64, "pinned authority")?;
        validate_ref(&self.organization_ref, "organization ref")?;
        validate_ref(&self.project_ref, "project ref")?;
        if self.subscription_id.is_empty()
            || self.subscription_id.len() > 64
            || self.subscription_id.chars().any(char::is_control)
        {
            return Err("subscription ID must be bounded display text".to_owned());
        }
        if !(1..=1_024).contains(&self.max_events) {
            return Err("max_events must be between 1 and 1024".to_owned());
        }
        if self.max_activity == 0 || self.max_activity > self.max_events {
            return Err("max_activity must be positive and no larger than max_events".to_owned());
        }
        Ok(())
    }

    pub fn project_address(&self) -> String {
        format!(
            "{}:{}:{}",
            OPENAGENTS_PROJECT_KIND, self.pinned_authority, self.project_ref
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Snapshotting,
    Live,
    Reconnecting,
    Stale,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectActivityKind {
    ProjectUpdate(Box<OpenAgentsProjectUpdate>),
    Unknown { kind: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectActivity {
    pub event: Event,
    pub kind: ProjectActivityKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSnapshot {
    pub organization: Option<OpenAgentsOrganization>,
    pub project: Option<OpenAgentsProject>,
    pub status: Option<OpenAgentsProjectStatus>,
    pub latest_update: Option<OpenAgentsProjectUpdate>,
    pub recent_activity: Vec<ProjectActivity>,
    pub eose_at: u64,
    pub last_event_at: Option<u64>,
}

#[derive(Debug, Clone)]
struct AcceptedEvent {
    event: Event,
    parsed: Option<OpenAgentsProjectEvent>,
}

#[derive(Debug, Clone)]
pub struct ProjectClient {
    config: ProjectClientConfig,
    state: ConnectionState,
    pending: Vec<AcceptedEvent>,
    committed: Vec<AcceptedEvent>,
    snapshot: Option<ProjectSnapshot>,
    diagnostics: Vec<String>,
    last_frame_at: Option<u64>,
}

impl ProjectClient {
    pub fn new(config: ProjectClientConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            state: ConnectionState::Connecting,
            pending: Vec::new(),
            committed: Vec::new(),
            snapshot: None,
            diagnostics: Vec::new(),
            last_frame_at: None,
        })
    }

    pub fn config(&self) -> &ProjectClientConfig {
        &self.config
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn snapshot(&self) -> Option<&ProjectSnapshot> {
        self.snapshot.as_ref()
    }

    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    /// Return the exact NIP-01 REQ frame for the embedding WebSocket.
    pub fn subscription_request(&self) -> String {
        json!([
            "REQ",
            self.config.subscription_id,
            {
                "authors": [self.config.pinned_authority],
                "kinds": [OPENAGENTS_ORGANIZATION_KIND],
                "#d": [self.config.organization_ref],
                "limit": 8
            },
            {
                "authors": [self.config.pinned_authority],
                "kinds": [OPENAGENTS_PROJECT_KIND],
                "#d": [self.config.project_ref],
                "limit": 8
            },
            {
                "authors": [self.config.pinned_authority],
                "kinds": [OPENAGENTS_PROJECT_STATUS_KIND],
                "limit": 64
            },
            {
                "#a": [self.config.project_address()],
                "limit": self.config.max_activity
            }
        ])
        .to_string()
    }

    /// Start a connection attempt while retaining the last completed truth.
    pub fn begin_connect(&mut self) {
        self.pending.clear();
        self.state = if self.snapshot.is_some() {
            ConnectionState::Reconnecting
        } else {
            ConnectionState::Connecting
        };
    }

    /// Mark the WebSocket open. No received event is canonical until EOSE.
    pub fn opened(&mut self, now: u64) {
        self.pending.clear();
        self.last_frame_at = Some(now);
        self.state = ConnectionState::Snapshotting;
    }

    pub fn disconnected(&mut self) {
        self.pending.clear();
        self.state = if self.snapshot.is_some() {
            ConnectionState::Reconnecting
        } else {
            ConnectionState::Unavailable
        };
    }

    pub fn mark_stale(&mut self, now: u64, after_seconds: u64) -> bool {
        if self.state == ConnectionState::Live
            && self
                .last_frame_at
                .is_some_and(|last| now.saturating_sub(last) > after_seconds)
        {
            self.state = ConnectionState::Stale;
            true
        } else {
            false
        }
    }

    /// Ingest one relay text frame. Returns true when visible state changed.
    /// Invalid events never enter pending or committed truth.
    pub fn ingest_text(&mut self, text: &str, now: u64) -> Result<bool, String> {
        if text.len() > MAX_WIRE_MESSAGE_BYTES {
            return Err("relay message exceeds 262144 bytes".to_owned());
        }
        let value: Value = serde_json::from_str(text)
            .map_err(|error| format!("relay message is not JSON: {error}"))?;
        let frame = value
            .as_array()
            .ok_or_else(|| "relay message must be a JSON array".to_owned())?;
        let command = frame
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| "relay message has no string command".to_owned())?;
        self.last_frame_at = Some(now);

        match command {
            "EVENT" => self.ingest_event_frame(frame, now),
            "EOSE" => self.ingest_eose(frame, now),
            "CLOSED" => self.ingest_closed(frame),
            "NOTICE" => {
                if let Some(message) = frame.get(1).and_then(Value::as_str) {
                    self.push_diagnostic(format!("relay NOTICE: {message}"));
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn ingest_event_frame(&mut self, frame: &[Value], now: u64) -> Result<bool, String> {
        if frame.len() != 3 {
            return Err("EVENT frame must have three elements".to_owned());
        }
        if frame[1].as_str() != Some(self.config.subscription_id.as_str()) {
            return Ok(false);
        }
        let event: Event = serde_json::from_value(frame[2].clone())
            .map_err(|error| format!("EVENT payload has invalid shape: {error}"))?;
        let accepted = match self.accept_event(event) {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(false),
            Err(error) => {
                self.push_diagnostic(error);
                return Ok(false);
            }
        };

        if matches!(self.state, ConnectionState::Live | ConnectionState::Stale) {
            if insert_bounded(&mut self.committed, accepted, self.config.max_events) {
                self.snapshot = Some(build_snapshot(
                    &self.config,
                    &self.committed,
                    self.snapshot
                        .as_ref()
                        .map_or(now, |snapshot| snapshot.eose_at),
                ));
                self.state = ConnectionState::Live;
                return Ok(true);
            }
        } else {
            insert_bounded(&mut self.pending, accepted, self.config.max_events);
        }
        Ok(false)
    }

    fn ingest_eose(&mut self, frame: &[Value], now: u64) -> Result<bool, String> {
        if frame.len() != 2 {
            return Err("EOSE frame must have two elements".to_owned());
        }
        if frame[1].as_str() != Some(self.config.subscription_id.as_str()) {
            return Ok(false);
        }
        self.committed = std::mem::take(&mut self.pending);
        self.snapshot = Some(build_snapshot(&self.config, &self.committed, now));
        self.state = ConnectionState::Live;
        Ok(true)
    }

    fn ingest_closed(&mut self, frame: &[Value]) -> Result<bool, String> {
        if frame.len() != 3 {
            return Err("CLOSED frame must have three elements".to_owned());
        }
        if frame[1].as_str() != Some(self.config.subscription_id.as_str()) {
            return Ok(false);
        }
        let reason = frame[2]
            .as_str()
            .ok_or_else(|| "CLOSED reason must be a string".to_owned())?;
        self.push_diagnostic(format!("relay CLOSED: {reason}"));
        self.pending.clear();
        self.state = ConnectionState::Unavailable;
        Ok(true)
    }

    fn accept_event(&self, event: Event) -> Result<Option<AcceptedEvent>, String> {
        event
            .validate_structure()
            .map_err(|error| format!("event {} has invalid structure: {error}", event.id))?;
        event.validate_crypto().map_err(|error| {
            format!(
                "event {} failed cryptographic verification: {error}",
                event.id
            )
        })?;

        let known = matches!(
            event.kind,
            OPENAGENTS_ORGANIZATION_KIND
                | OPENAGENTS_PROJECT_KIND
                | OPENAGENTS_PROJECT_STATUS_KIND
                | OPENAGENTS_PROJECT_UPDATE_KIND
        );
        if !known {
            return Ok(
                references_project(&event, &self.config.project_address()).then_some(
                    AcceptedEvent {
                        event,
                        parsed: None,
                    },
                ),
            );
        }

        let parsed = validate_openagents_project_event(&event, &self.config.pinned_authority)
            .map_err(|error| format!("event {} violates OT/PG: {error}", event.id))?;
        let relevant = match &parsed {
            OpenAgentsProjectEvent::Organization(organization) => {
                organization.address.distinct == self.config.organization_ref
            }
            OpenAgentsProjectEvent::Project(project) => {
                project.address.distinct == self.config.project_ref
                    && project.organization_ref == self.config.organization_ref
            }
            OpenAgentsProjectEvent::ProjectStatus(status) => {
                status.organization_ref == self.config.organization_ref
            }
            OpenAgentsProjectEvent::ProjectUpdate(update) => {
                update.organization_ref == self.config.organization_ref
                    && update.subject_address.distinct == self.config.project_ref
            }
        };
        Ok(relevant.then_some(AcceptedEvent {
            event,
            parsed: Some(parsed),
        }))
    }

    fn push_diagnostic(&mut self, message: String) {
        if self.diagnostics.len() == MAX_DIAGNOSTICS {
            self.diagnostics.remove(0);
        }
        self.diagnostics.push(message);
    }
}

fn insert_bounded(events: &mut Vec<AcceptedEvent>, event: AcceptedEvent, limit: usize) -> bool {
    if events
        .iter()
        .any(|current| current.event.id == event.event.id)
    {
        return false;
    }
    events.push(event);
    events.sort_by(|left, right| newest_first(&left.event, &right.event));
    events.truncate(limit);
    true
}

fn build_snapshot(
    config: &ProjectClientConfig,
    events: &[AcceptedEvent],
    eose_at: u64,
) -> ProjectSnapshot {
    let organization = select_latest(events, |parsed| match parsed {
        OpenAgentsProjectEvent::Organization(value)
            if value.address.distinct == config.organization_ref =>
        {
            Some(value.clone())
        }
        _ => None,
    });
    let project = select_latest(events, |parsed| match parsed {
        OpenAgentsProjectEvent::Project(value) if value.address.distinct == config.project_ref => {
            Some(value.clone())
        }
        _ => None,
    });
    let status = project.as_ref().and_then(|project| {
        select_latest(events, |parsed| match parsed {
            OpenAgentsProjectEvent::ProjectStatus(value)
                if value.address == project.status_address =>
            {
                Some(value.clone())
            }
            _ => None,
        })
    });

    let mut updates = events
        .iter()
        .filter_map(|accepted| match &accepted.parsed {
            Some(OpenAgentsProjectEvent::ProjectUpdate(update))
                if update.subject_address.distinct == config.project_ref =>
            {
                Some((accepted, update.clone()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    updates.sort_by(|(left_event, left), (right_event, right)| {
        right
            .published_at
            .cmp(&left.published_at)
            .then_with(|| right.revision.cmp(&left.revision))
            .then_with(|| newest_first(&left_event.event, &right_event.event))
    });
    let latest_update = updates.first().map(|(_, update)| update.clone());

    let project_address = config.project_address();
    let mut recent_activity = events
        .iter()
        .filter_map(|accepted| {
            if !references_project(&accepted.event, &project_address) {
                return None;
            }
            let kind = match &accepted.parsed {
                Some(OpenAgentsProjectEvent::ProjectUpdate(update)) => {
                    ProjectActivityKind::ProjectUpdate(Box::new(update.clone()))
                }
                Some(_) => return None,
                None => ProjectActivityKind::Unknown {
                    kind: accepted.event.kind,
                },
            };
            Some(ProjectActivity {
                event: accepted.event.clone(),
                kind,
            })
        })
        .collect::<Vec<_>>();
    recent_activity.sort_by(|left, right| newest_first(&left.event, &right.event));
    recent_activity.truncate(config.max_activity);

    ProjectSnapshot {
        organization,
        project,
        status,
        latest_update,
        recent_activity,
        eose_at,
        last_event_at: events
            .iter()
            .map(|accepted| accepted.event.created_at)
            .max(),
    }
}

fn select_latest<T>(
    events: &[AcceptedEvent],
    mut project: impl FnMut(&OpenAgentsProjectEvent) -> Option<T>,
) -> Option<T> {
    events
        .iter()
        .filter_map(|accepted| {
            accepted
                .parsed
                .as_ref()
                .and_then(&mut project)
                .map(|value| (&accepted.event, value))
        })
        .min_by(|(left, _), (right, _)| newest_first(left, right))
        .map(|(_, value)| value)
}

fn newest_first(left: &Event, right: &Event) -> Ordering {
    right
        .created_at
        .cmp(&left.created_at)
        .then_with(|| left.id.cmp(&right.id))
}

fn validate_ref(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!("{field} must be a bounded non-whitespace ref"));
    }
    Ok(())
}

fn validate_lower_hex(value: &str, length: usize, field: &str) -> Result<(), String> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be {length} lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

/// Return the event IDs currently represented by a completed snapshot.
pub fn snapshot_event_ids(snapshot: &ProjectSnapshot) -> BTreeSet<String> {
    snapshot
        .recent_activity
        .iter()
        .map(|activity| activity.event.id.clone())
        .collect()
}
