//! NIP-WK Work and NIP-PI Issue Projection structural validation.
//!
//! The pinned drafts are `nips/openagents/WK.md` (kinds 32170-32173) and
//! `nips/openagents/PI.md` (kind 32200). The relay validates structure
//! only: required tags, `d` address grammars, canonical decimals, and
//! bounded open vocabularies. Whether a record is signed by the declared
//! Organization authority key is a client/consumer rule (NIP-OT), never a
//! relay admission decision. Unknown tags and unknown-but-well-formed
//! vocabulary values are preserved, not rejected.

use super::openagents::{
    optional_value, parse_address, parse_decimal, required_decimal, required_marked_value,
    required_positive_decimal, required_value, validate_pubkey, validate_ref,
};
use super::{Event, Tag};

pub const OPENAGENTS_WORK_RECORD_KIND: u16 = 32_170;
pub const OPENAGENTS_WORK_EVENT_KIND: u16 = 32_171;
pub const OPENAGENTS_WORK_OBJECTIVE_KIND: u16 = 32_172;
pub const OPENAGENTS_OUTCOME_RECORD_KIND: u16 = 32_173;
pub const OPENAGENTS_ISSUE_PROJECTION_KIND: u16 = 32_200;

pub const WORK_MAX_TAGS: usize = 64;
pub const WORK_MAX_CONTENT_BYTES: usize = 16 * 1024;
pub const WORK_MAX_TITLE_BYTES: usize = 256;
pub const WORK_VOCAB_MAX_BYTES: usize = 64;

/// Baseline Work State vocabulary (WK 1.3). Open: deployments may declare
/// more values; any bounded label passes structural validation.
pub const WORK_BASELINE_STATES: &[&str] = &[
    "draft",
    "planned",
    "active",
    "blocked",
    "in_review",
    "done",
    "canceled",
    "superseded",
    "archived",
];

/// Baseline Work Domain vocabulary (WK 1.1). Open extension.
pub const WORK_BASELINE_DOMAINS: &[&str] = &[
    "general",
    "development",
    "ci",
    "deployment",
    "operations",
    "incident",
    "research",
    "security",
    "design_review",
    "service_delivery",
    "data",
];

/// Recommended Work Event kind vocabulary (WK 2.3). Open extension: an
/// unknown event kind is preserved and displayed as unknown.
pub const WORK_BASELINE_EVENT_KINDS: &[&str] = &[
    "created",
    "objective_revised",
    "classified",
    "related",
    "assigned",
    "delegated",
    "delegation_revoked",
    "state_changed",
    "blocked",
    "unblocked",
    "session_started",
    "session_ended",
    "activity_recorded",
    "evidence_attached",
    "verification_recorded",
    "disposition_recorded",
    "closed",
    "reopened",
    "superseded",
    "archived",
];

/// Recommended Outcome Record states (WK 4). Open extension.
pub const WORK_OUTCOME_STATES: &[&str] = &["open", "synthesizing", "terminal"];

/// Issue Projection priorities (PI 1.2). This list is closed in the draft.
pub const ISSUE_PRIORITIES: &[&str] = &["urgent", "high", "medium", "low", "none"];

pub const fn is_openagents_work_kind(kind: u16) -> bool {
    matches!(
        kind,
        OPENAGENTS_WORK_RECORD_KIND
            | OPENAGENTS_WORK_EVENT_KIND
            | OPENAGENTS_WORK_OBJECTIVE_KIND
            | OPENAGENTS_OUTCOME_RECORD_KIND
            | OPENAGENTS_ISSUE_PROJECTION_KIND
    )
}

/// Structural validation for NIP-WK/NIP-PI kinds. Returns `Ok(())` for
/// every other kind so it can sit on the shared public admission path.
pub fn validate_openagents_work_event(event: &Event) -> Result<(), String> {
    if !is_openagents_work_kind(event.kind) {
        return Ok(());
    }
    if event.tags.len() > WORK_MAX_TAGS {
        return Err(format!("work event exceeds {WORK_MAX_TAGS} tags"));
    }
    if event.content.len() > WORK_MAX_CONTENT_BYTES {
        return Err(format!(
            "work event content exceeds {WORK_MAX_CONTENT_BYTES} bytes"
        ));
    }
    validate_reference_tags(event)?;
    match event.kind {
        OPENAGENTS_WORK_RECORD_KIND => validate_work_record(event),
        OPENAGENTS_WORK_EVENT_KIND => validate_work_event_record(event),
        OPENAGENTS_WORK_OBJECTIVE_KIND => validate_work_objective(event),
        OPENAGENTS_OUTCOME_RECORD_KIND => validate_outcome_record(event),
        OPENAGENTS_ISSUE_PROJECTION_KIND => validate_issue_projection(event),
        _ => Ok(()),
    }
}

fn validate_work_record(event: &Event) -> Result<(), String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "Work Record work_ref")?;
    validate_ref(
        required_value(event, "org")?,
        "Work Record organization ref",
    )?;
    validate_vocab_label(required_value(event, "domain")?, "Work Record domain")?;
    validate_vocab_label(required_value(event, "state")?, "Work Record state")?;
    required_positive_decimal(event, "revision")?;
    validate_pubkey(
        required_marked_value(event, "p", "owner")?,
        "Work Record owner",
    )?;
    required_decimal(event, "published_at")?;
    if let Some(title) = optional_value(event, "title")? {
        validate_title(title, "Work Record title")?;
    }
    if let Some(class) = optional_value(event, "class")? {
        validate_ref(class, "Work Record class ref")?;
    }
    Ok(())
}

fn validate_work_event_record(event: &Event) -> Result<(), String> {
    let distinct = required_value(event, "d")?;
    let (work_ref, distinct_seq) = parse_suffixed_ref(distinct, ":evt:", "Work Event")?;
    if distinct_seq == 0 {
        return Err("Work Event seq must be positive".to_owned());
    }
    if required_value(event, "work")? != work_ref {
        return Err("Work Event work tag does not match its d work_ref".to_owned());
    }
    let seq = required_positive_decimal(event, "seq")?;
    if seq != distinct_seq {
        return Err("Work Event seq tag does not match its d sequence".to_owned());
    }
    validate_vocab_label(required_value(event, "event")?, "Work Event kind")?;
    validate_pubkey(
        required_marked_value(event, "p", "actor")?,
        "Work Event actor",
    )?;
    required_decimal(event, "occurred_at")?;
    required_decimal(event, "admitted_at")?;
    if let Some(revision) = optional_value(event, "revision")? {
        if parse_decimal(revision, u64::MAX, "Work Event revision")? == 0 {
            return Err("Work Event revision must be positive".to_owned());
        }
    }
    if let Some(reason) = optional_value(event, "reason")? {
        validate_ref(reason, "Work Event reason code")?;
    }
    Ok(())
}

fn validate_work_objective(event: &Event) -> Result<(), String> {
    let distinct = required_value(event, "d")?;
    let (work_ref, distinct_revision) = parse_suffixed_ref(distinct, ":obj:", "Work Objective")?;
    if distinct_revision == 0 {
        return Err("Work Objective revision must be positive".to_owned());
    }
    if required_value(event, "work")? != work_ref {
        return Err("Work Objective work tag does not match its d work_ref".to_owned());
    }
    if required_positive_decimal(event, "revision")? != distinct_revision {
        return Err("Work Objective revision tag does not match its d revision".to_owned());
    }
    let digest = required_value(event, "x")?;
    validate_hex_digest(digest, "Work Objective digest")?;
    required_decimal(event, "published_at")?;
    Ok(())
}

fn validate_outcome_record(event: &Event) -> Result<(), String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "Outcome Record work_ref")?;
    if let Some(work_ref) = optional_value(event, "work")? {
        if work_ref != distinct {
            return Err("Outcome Record work tag does not match its d work_ref".to_owned());
        }
    }
    if let Some(state) = optional_value(event, "state")? {
        validate_vocab_label(state, "Outcome Record state")?;
    }
    if let Some(revision) = optional_value(event, "revision")? {
        if parse_decimal(revision, u64::MAX, "Outcome Record revision")? == 0 {
            return Err("Outcome Record revision must be positive".to_owned());
        }
    }
    Ok(())
}

fn validate_issue_projection(event: &Event) -> Result<(), String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "Issue Projection work_ref")?;
    validate_ref(
        required_value(event, "org")?,
        "Issue Projection organization ref",
    )?;
    validate_ref(required_value(event, "team")?, "Issue Projection team ref")?;
    validate_issue_identifier(
        required_value(event, "identifier")?,
        "Issue Projection identifier",
    )?;
    match optional_value(event, "title")? {
        Some(title) => validate_title(title, "Issue Projection title")?,
        None if event.content.is_empty() => {
            return Err(
                "Issue Projection requires a title tag or non-empty (encrypted) content".to_owned(),
            );
        }
        None => {}
    }
    validate_ref(
        required_value(event, "state")?,
        "Issue Projection state ref",
    )?;
    required_positive_decimal(event, "revision")?;
    required_decimal(event, "published_at")?;
    if let Some(priority) = optional_value(event, "priority")? {
        if !ISSUE_PRIORITIES.contains(&priority) {
            return Err("Issue Projection priority is unknown".to_owned());
        }
    }
    if let Some(estimate) = optional_value(event, "estimate")? {
        parse_decimal(estimate, u64::MAX, "Issue Projection estimate")?;
    }
    if let Some(due) = optional_value(event, "due")? {
        parse_decimal(due, u64::MAX, "Issue Projection due")?;
    }
    if let Some(archived_at) = optional_value(event, "archived_at")? {
        parse_decimal(archived_at, u64::MAX, "Issue Projection archived_at")?;
    }
    if let Some(sla) = optional_value(event, "sla")? {
        validate_ref(sla, "Issue Projection SLA ref")?;
    }
    for alias in event.tag_values("identifier_alias") {
        validate_issue_identifier(alias, "Issue Projection identifier alias")?;
    }
    for label in event.tag_values("label") {
        validate_ref(label, "Issue Projection label ref")?;
    }
    Ok(())
}

/// Structural checks shared by every NIP-WK/NIP-PI kind: `p` values are
/// pubkeys, `e` values are event ids, `a` values parse as addressable
/// coordinates, `x` values are SHA-256 digests. Markers and relay hints
/// stay free-form, and unknown tag names are preserved untouched.
fn validate_reference_tags(event: &Event) -> Result<(), String> {
    for tag in &event.tags {
        match tag.name() {
            Some("p") => {
                validate_pubkey(tag_value(tag, "p")?, "work p tag")?;
            }
            Some("e") => {
                validate_hex_digest(tag_value(tag, "e")?, "work e tag")?;
            }
            Some("a") => {
                parse_address(tag_value(tag, "a")?)?;
            }
            Some("x") => {
                validate_hex_digest(tag_value(tag, "x")?, "work x tag")?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn tag_value<'a>(tag: &'a Tag, name: &str) -> Result<&'a str, String> {
    tag.value()
        .ok_or_else(|| format!("work {name} tag requires a value"))
}

fn parse_suffixed_ref<'a>(
    distinct: &'a str,
    separator: &str,
    record: &str,
) -> Result<(&'a str, u64), String> {
    let (work_ref, number) = distinct
        .rsplit_once(separator)
        .ok_or_else(|| format!("{record} d tag must be <work_ref>{separator}<n>"))?;
    validate_ref(work_ref, "work_ref")?;
    let number = parse_decimal(number, u64::MAX, "work d sequence")?;
    Ok((work_ref, number))
}

/// Bounded open-vocabulary label: baseline values pass, and so does any
/// deployment-declared value with the same shape. Rejecting only malformed
/// labels keeps the vocabularies open per the drafts.
fn validate_vocab_label(value: &str, field: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let starts_lower_alnum = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    if !starts_lower_alnum
        || value.len() > WORK_VOCAB_MAX_BYTES
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
    {
        return Err(format!(
            "{field} must be a bounded lowercase vocabulary label"
        ));
    }
    Ok(())
}

/// `<TEAM-KEY>-<number>` per PI 1.4, e.g. `CORE-142`.
fn validate_issue_identifier(value: &str, field: &str) -> Result<(), String> {
    let invalid = || format!("{field} must be <TEAM-KEY>-<number>");
    if value.len() > WORK_VOCAB_MAX_BYTES {
        return Err(invalid());
    }
    let (key, number) = value.rsplit_once('-').ok_or_else(invalid)?;
    let key_bytes = key.as_bytes();
    if !key_bytes.first().is_some_and(u8::is_ascii_uppercase)
        || !key_bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    if parse_decimal(number, u64::MAX, field).is_err() {
        return Err(invalid());
    }
    Ok(())
}

fn validate_title(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > WORK_MAX_TITLE_BYTES || value.chars().any(char::is_control)
    {
        return Err(format!("{field} must be bounded display text"));
    }
    Ok(())
}

fn validate_hex_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}
