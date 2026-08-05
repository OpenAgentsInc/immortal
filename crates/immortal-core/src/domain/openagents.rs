use sha2::{Digest, Sha256};

use super::hex::encode_lower_hex;
use super::{Event, Tag};

pub const OPENAGENTS_ORGANIZATION_KIND: u16 = 32_100;
pub const OPENAGENTS_PROJECT_KIND: u16 = 32_222;
pub const OPENAGENTS_PROJECT_STATUS_KIND: u16 = 32_223;
pub const OPENAGENTS_PROJECT_UPDATE_KIND: u16 = 32_226;

const MAX_REF_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 160;
const MAX_UPDATE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrAddress {
    pub kind: u16,
    pub pubkey: String,
    pub distinct: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAgentsOrganization {
    pub address: NostrAddress,
    pub name: String,
    pub authority_pubkey: String,
    pub founder_pubkeys: Vec<String>,
    pub relay_urls: Vec<String>,
    pub revision: u64,
    pub published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAgentsProject {
    pub address: NostrAddress,
    pub organization_ref: String,
    pub name: String,
    pub status_address: NostrAddress,
    pub owner_pubkeys: Vec<String>,
    pub lead_pubkeys: Vec<String>,
    pub team_refs: Vec<String>,
    pub linked_addresses: Vec<(String, String)>,
    pub progress: Option<(u64, u64)>,
    pub starts_at: Option<u64>,
    pub target_at: Option<u64>,
    pub revision: u64,
    pub published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAgentsProjectStatus {
    pub address: NostrAddress,
    pub organization_ref: String,
    pub name: String,
    pub category: String,
    pub position: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAgentsProjectUpdate {
    pub address: NostrAddress,
    pub organization_ref: String,
    pub subject_address: NostrAddress,
    pub author_pubkey: String,
    pub health: String,
    pub body: String,
    pub revision: u64,
    pub published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenAgentsProjectEvent {
    Organization(OpenAgentsOrganization),
    Project(OpenAgentsProject),
    ProjectStatus(OpenAgentsProjectStatus),
    ProjectUpdate(OpenAgentsProjectUpdate),
}

pub fn parse_address(value: &str) -> Result<NostrAddress, String> {
    let mut parts = value.splitn(3, ':');
    let kind = parts
        .next()
        .ok_or_else(|| "address is missing kind".to_owned())?;
    let pubkey = parts
        .next()
        .ok_or_else(|| "address is missing pubkey".to_owned())?;
    let distinct = parts
        .next()
        .ok_or_else(|| "address is missing distinct parameter".to_owned())?;
    let kind = parse_decimal(kind, u64::from(u16::MAX), "address kind")?;
    let kind = u16::try_from(kind).map_err(|_| "address kind is out of range".to_owned())?;
    validate_pubkey(pubkey, "address pubkey")?;
    validate_ref(distinct, "address distinct parameter")?;
    Ok(NostrAddress {
        kind,
        pubkey: pubkey.to_owned(),
        distinct: distinct.to_owned(),
    })
}

pub fn validate_openagents_project_event(
    event: &Event,
    pinned_authority: &str,
) -> Result<OpenAgentsProjectEvent, String> {
    event
        .validate_structure()
        .map_err(|error| format!("invalid OpenAgents event: {error}"))?;
    event
        .validate_crypto()
        .map_err(|error| format!("invalid OpenAgents event: {error}"))?;
    validate_pubkey(pinned_authority, "pinned authority")?;
    if event.pubkey != pinned_authority {
        return Err("OpenAgents project event signer is not the pinned authority".to_owned());
    }

    match event.kind {
        OPENAGENTS_ORGANIZATION_KIND => {
            validate_organization(event).map(OpenAgentsProjectEvent::Organization)
        }
        OPENAGENTS_PROJECT_KIND => validate_project(event).map(OpenAgentsProjectEvent::Project),
        OPENAGENTS_PROJECT_STATUS_KIND => {
            validate_project_status(event).map(OpenAgentsProjectEvent::ProjectStatus)
        }
        OPENAGENTS_PROJECT_UPDATE_KIND => {
            validate_project_update(event).map(OpenAgentsProjectEvent::ProjectUpdate)
        }
        _ => Err("event kind is outside the Operation Diamond Hands read contract".to_owned()),
    }
}

pub fn references_project(event: &Event, project_address: &str) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.name() == Some("a") && tag.value() == Some(project_address))
}

fn validate_organization(event: &Event) -> Result<OpenAgentsOrganization, String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "organization ref")?;
    let name = required_value(event, "name")?;
    validate_name(name, "organization name")?;
    let authority = required_marked_value(event, "p", "authority")?;
    validate_pubkey(authority, "organization authority")?;
    if authority != event.pubkey {
        return Err("initial Organization authority tag must match its signer".to_owned());
    }
    let revision = required_positive_decimal(event, "revision")?;
    let published_at = required_decimal(event, "published_at")?;
    let founder_pubkeys = marked_values(event, "p", "founder")
        .map(|value| {
            validate_pubkey(value, "organization founder")?;
            Ok(value.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let relay_urls = event
        .tag_values("relay")
        .map(|value| {
            if !value.starts_with("wss://") || value.len() > 2_048 {
                return Err("Organization relay must be a bounded wss URL".to_owned());
            }
            Ok(value.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(OpenAgentsOrganization {
        address: address_for(event, distinct),
        name: name.to_owned(),
        authority_pubkey: authority.to_owned(),
        founder_pubkeys,
        relay_urls,
        revision,
        published_at,
    })
}

fn validate_project(event: &Event) -> Result<OpenAgentsProject, String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "project ref")?;
    let organization_ref = required_value(event, "org")?;
    validate_ref(organization_ref, "project organization ref")?;
    let name = required_value(event, "name")?;
    validate_name(name, "project name")?;
    let status_address = parse_address(required_value(event, "status")?)?;
    if status_address.kind != OPENAGENTS_PROJECT_STATUS_KIND
        || status_address.pubkey != event.pubkey
    {
        return Err("Project status must name a Project Status from the same authority".to_owned());
    }
    let revision = required_positive_decimal(event, "revision")?;
    let published_at = required_decimal(event, "published_at")?;
    let owner_pubkeys = marked_pubkeys(event, "owner")?;
    let lead_pubkeys = marked_pubkeys(event, "lead")?;
    let team_refs = event
        .tag_values("team")
        .map(|value| {
            validate_ref(value, "project team ref")?;
            Ok(value.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let linked_addresses = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("a"))
        .map(|tag| {
            if tag.as_slice().len() < 4 {
                return Err("Project address refs require a marker".to_owned());
            }
            parse_address(&tag.as_slice()[1])?;
            Ok((tag.as_slice()[3].clone(), tag.as_slice()[1].clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let progress = optional_value(event, "progress")?
        .map(parse_progress)
        .transpose()?;
    let starts_at = optional_decimal(event, "start")?;
    let target_at = optional_decimal(event, "target")?;
    if starts_at
        .zip(target_at)
        .is_some_and(|(start, target)| start > target)
    {
        return Err("Project start must not be later than target".to_owned());
    }

    Ok(OpenAgentsProject {
        address: address_for(event, distinct),
        organization_ref: organization_ref.to_owned(),
        name: name.to_owned(),
        status_address,
        owner_pubkeys,
        lead_pubkeys,
        team_refs,
        linked_addresses,
        progress,
        starts_at,
        target_at,
        revision,
        published_at,
    })
}

fn validate_project_status(event: &Event) -> Result<OpenAgentsProjectStatus, String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "project status ref")?;
    let organization_ref = required_value(event, "org")?;
    validate_ref(organization_ref, "project status organization ref")?;
    let name = required_value(event, "name")?;
    validate_name(name, "project status name")?;
    let category = required_value(event, "category")?;
    if !matches!(
        category,
        "backlog" | "planned" | "started" | "paused" | "completed" | "canceled"
    ) {
        return Err("Project Status category is unknown".to_owned());
    }
    let position = required_decimal(event, "position")?;
    let revision = required_positive_decimal(event, "revision")?;

    Ok(OpenAgentsProjectStatus {
        address: address_for(event, distinct),
        organization_ref: organization_ref.to_owned(),
        name: name.to_owned(),
        category: category.to_owned(),
        position,
        revision,
    })
}

fn validate_project_update(event: &Event) -> Result<OpenAgentsProjectUpdate, String> {
    let distinct = required_value(event, "d")?;
    validate_ref(distinct, "project update ref")?;
    let (subject_ref, revision) = parse_update_ref(distinct)?;
    let organization_ref = required_value(event, "org")?;
    validate_ref(organization_ref, "project update organization ref")?;
    let subject_address = parse_address(required_marked_value(event, "a", "subject")?)?;
    if subject_address.kind != OPENAGENTS_PROJECT_KIND
        || subject_address.pubkey != event.pubkey
        || subject_address.distinct != subject_ref
    {
        return Err("Project Update subject does not match its address".to_owned());
    }
    let author_pubkey = required_marked_value(event, "p", "author")?;
    validate_pubkey(author_pubkey, "project update author")?;
    let health = required_value(event, "health")?;
    if !matches!(health, "on_track" | "at_risk" | "off_track") {
        return Err("Project Update health is unknown".to_owned());
    }
    let published_at = required_decimal(event, "published_at")?;
    if event.content.len() > MAX_UPDATE_BYTES {
        return Err("Project Update content exceeds 16384 bytes".to_owned());
    }
    if let Some(digest) = optional_value(event, "x")? {
        validate_lower_hex(digest, 64, "Project Update digest")?;
        let expected = encode_lower_hex(&Sha256::digest(event.content.as_bytes()));
        if digest != expected {
            return Err("Project Update content digest does not match".to_owned());
        }
    }

    Ok(OpenAgentsProjectUpdate {
        address: address_for(event, distinct),
        organization_ref: organization_ref.to_owned(),
        subject_address,
        author_pubkey: author_pubkey.to_owned(),
        health: health.to_owned(),
        body: event.content.clone(),
        revision,
        published_at,
    })
}

fn address_for(event: &Event, distinct: &str) -> NostrAddress {
    NostrAddress {
        kind: event.kind,
        pubkey: event.pubkey.clone(),
        distinct: distinct.to_owned(),
    }
}

pub(super) fn required_value<'a>(event: &'a Event, name: &str) -> Result<&'a str, String> {
    let mut tags = event.tags.iter().filter(|tag| tag.name() == Some(name));
    let tag = tags
        .next()
        .ok_or_else(|| format!("event requires one {name} tag"))?;
    if tags.next().is_some() || tag.as_slice().len() != 2 {
        return Err(format!("event requires exactly one two-element {name} tag"));
    }
    tag.value()
        .ok_or_else(|| format!("event {name} tag requires a value"))
}

pub(super) fn optional_value<'a>(event: &'a Event, name: &str) -> Result<Option<&'a str>, String> {
    let tags = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<&Tag>>();
    match tags.as_slice() {
        [] => Ok(None),
        [tag] if tag.as_slice().len() == 2 => Ok(tag.value()),
        _ => Err(format!("event permits at most one two-element {name} tag")),
    }
}

pub(super) fn required_marked_value<'a>(
    event: &'a Event,
    name: &'a str,
    marker: &'a str,
) -> Result<&'a str, String> {
    let values = marked_values(event, name, marker).collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(*value),
        _ => Err(format!(
            "event requires exactly one {name} tag marked {marker}"
        )),
    }
}

pub(super) fn marked_values<'a>(
    event: &'a Event,
    name: &'a str,
    marker: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    event.tags.iter().filter_map(move |tag| {
        let values = tag.as_slice();
        (tag.name() == Some(name) && values.len() >= 4 && values[3] == marker)
            .then(|| values[1].as_str())
    })
}

fn marked_pubkeys(event: &Event, marker: &str) -> Result<Vec<String>, String> {
    marked_values(event, "p", marker)
        .map(|value| {
            validate_pubkey(value, "Project principal")?;
            Ok(value.to_owned())
        })
        .collect()
}

pub(super) fn required_decimal(event: &Event, name: &str) -> Result<u64, String> {
    parse_decimal(required_value(event, name)?, u64::MAX, name)
}

pub(super) fn required_positive_decimal(event: &Event, name: &str) -> Result<u64, String> {
    let value = required_decimal(event, name)?;
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(value)
}

pub(super) fn optional_decimal(event: &Event, name: &str) -> Result<Option<u64>, String> {
    optional_value(event, name)?
        .map(|value| parse_decimal(value, u64::MAX, name))
        .transpose()
}

pub(super) fn parse_decimal(value: &str, max: u64, field: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{field} must be canonical unsigned decimal"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{field} is out of range"))?;
    if value > max {
        return Err(format!("{field} is out of range"));
    }
    Ok(value)
}

fn parse_progress(value: &str) -> Result<(u64, u64), String> {
    let (done, total) = value
        .split_once('/')
        .ok_or_else(|| "Project progress must be done/total".to_owned())?;
    let done = parse_decimal(done, u64::MAX, "Project progress done")?;
    let total = parse_decimal(total, u64::MAX, "Project progress total")?;
    if done > total {
        return Err("Project progress done exceeds total".to_owned());
    }
    Ok((done, total))
}

fn parse_update_ref(value: &str) -> Result<(&str, u64), String> {
    let (subject_ref, revision) = value
        .rsplit_once(":upd:")
        .ok_or_else(|| "Project Update d tag must end in :upd:<n>".to_owned())?;
    validate_ref(subject_ref, "Project Update subject ref")?;
    let revision = parse_decimal(revision, u64::MAX, "Project Update revision")?;
    if revision == 0 {
        return Err("Project Update revision must be positive".to_owned());
    }
    Ok((subject_ref, revision))
}

pub(super) fn validate_ref(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_REF_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!("{field} must be a bounded non-whitespace ref"));
    }
    Ok(())
}

pub(super) fn validate_name(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(format!("{field} must be bounded display text"));
    }
    Ok(())
}

pub(super) fn validate_pubkey(value: &str, field: &str) -> Result<(), String> {
    validate_lower_hex(value, 64, field)
}

pub(super) fn validate_lower_hex(value: &str, length: usize, field: &str) -> Result<(), String> {
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
