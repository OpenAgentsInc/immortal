use super::hex::decode_lower_hex;
use super::{Event, Tag};

pub const MKT_PROVIDER_PROFILE_KIND: u16 = 39_600;
pub const MKT_OFFERING_KIND: u16 = 39_601;
pub const MKT_PROFILE_DESCRIPTOR_KIND: u16 = 39_602;
pub const MKT_PUBLIC_RECEIPT_KIND: u16 = 39_603;

const MAX_DISCOVERY_CONTENT_BYTES: usize = 16 * 1024;
const MAX_RECEIPT_CONTENT_BYTES: usize = 4 * 1024;

pub fn validate_mkt_public_event(event: &Event) -> Result<(), String> {
    match event.kind {
        MKT_PROVIDER_PROFILE_KIND => validate_provider_profile(event),
        MKT_OFFERING_KIND => validate_offering(event),
        MKT_PROFILE_DESCRIPTOR_KIND => validate_profile_descriptor(event),
        MKT_PUBLIC_RECEIPT_KIND => validate_public_receipt(event),
        _ => Ok(()),
    }
}

fn validate_provider_profile(event: &Event) -> Result<(), String> {
    validate_content_bound(event, MAX_DISCOVERY_CONTENT_BYTES, "provider profile")?;
    validate_identifier(single_value(event, "d", "provider profile")?, "provider id")?;
    require_enum(
        single_value(event, "status", "provider profile")?,
        &["active", "paused", "retired"],
        "provider profile status",
    )?;
    canonical_decimal(
        single_value(event, "published_at", "provider profile")?,
        false,
        "provider profile published_at",
    )?;
    let profiles = profile_tags(event, "provider profile")?;
    if profiles.is_empty() {
        return Err("provider profile requires at least one profile tag".to_owned());
    }
    for (index, profile) in profiles.iter().enumerate() {
        if profiles[..index].contains(profile) {
            return Err("provider profile has a duplicate profile and version".to_owned());
        }
    }
    Ok(())
}

fn validate_offering(event: &Event) -> Result<(), String> {
    validate_content_bound(event, MAX_DISCOVERY_CONTENT_BYTES, "offering")?;
    validate_identifier(single_value(event, "d", "offering")?, "offering id")?;
    require_enum(
        single_value(event, "status", "offering")?,
        &["active", "paused", "exhausted", "retired"],
        "offering status",
    )?;
    canonical_decimal(
        single_value(event, "published_at", "offering")?,
        false,
        "offering published_at",
    )?;
    let profiles = profile_tags(event, "offering")?;
    if profiles.len() != 1 {
        return Err("offering requires exactly one profile tag".to_owned());
    }
    validate_provider_address(single_value(event, "provider", "offering")?, &event.pubkey)
}

fn validate_profile_descriptor(event: &Event) -> Result<(), String> {
    validate_content_bound(event, MAX_DISCOVERY_CONTENT_BYTES, "profile descriptor")?;
    validate_identifier(
        single_value(event, "d", "profile descriptor")?,
        "profile id",
    )?;
    canonical_decimal(
        single_value(event, "version", "profile descriptor")?,
        true,
        "profile descriptor version",
    )?;
    let digest = single_value(event, "x", "profile descriptor")?;
    decode_lower_hex::<32>(digest, "profile descriptor digest")
        .map_err(|_| "profile descriptor x must be a lowercase SHA-256 digest".to_owned())?;
    validate_retrieval_url(single_value(event, "r", "profile descriptor")?)?;
    require_enum(
        single_value(event, "status", "profile descriptor")?,
        &["draft", "active", "deprecated", "withdrawn"],
        "profile descriptor status",
    )
}

fn validate_public_receipt(event: &Event) -> Result<(), String> {
    validate_content_bound(event, MAX_RECEIPT_CONTENT_BYTES, "public market receipt")?;
    if single_value(event, "d", "public market receipt")?.is_empty() {
        return Err("public market receipt d must not be empty".to_owned());
    }
    let profiles = profile_tags(event, "public market receipt")?;
    if profiles.len() != 1 {
        return Err("public market receipt requires exactly one profile tag".to_owned());
    }
    require_enum(
        single_value(event, "outcome", "public market receipt")?,
        &[
            "completed",
            "cancelled",
            "expired",
            "failed",
            "refunded",
            "disputed",
            "unresolved",
        ],
        "public market receipt outcome",
    )?;
    let close_id = single_value(event, "x", "public market receipt")?;
    decode_lower_hex::<32>(close_id, "private Close event id").map_err(|_| {
        "public market receipt x must be a 64-character lowercase Close event id".to_owned()
    })?;
    validate_identifier(
        single_value(event, "role", "public market receipt")?,
        "public market receipt role",
    )
}

fn validate_content_bound(event: &Event, maximum: usize, subject: &str) -> Result<(), String> {
    if event.content.len() > maximum {
        return Err(format!("{subject} content exceeds {maximum} bytes"));
    }
    Ok(())
}

fn single_value<'a>(event: &'a Event, name: &str, subject: &str) -> Result<&'a str, String> {
    let tags = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<&Tag>>();
    if tags.len() != 1 || tags[0].as_slice().len() != 2 {
        return Err(format!(
            "{subject} requires exactly one two-element {name} tag"
        ));
    }
    tags[0]
        .value()
        .ok_or_else(|| format!("{subject} {name} tag requires a value"))
}

fn profile_tags<'a>(event: &'a Event, subject: &str) -> Result<Vec<(&'a str, u64)>, String> {
    event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("profile"))
        .map(|tag| {
            let values = tag.as_slice();
            if values.len() != 3 {
                return Err(format!(
                    "{subject} profile tags must contain an id and version"
                ));
            }
            validate_identifier(&values[1], "profile id")?;
            let version = canonical_decimal(&values[2], true, "profile version")?;
            Ok((values[1].as_str(), version))
        })
        .collect()
}

fn validate_identifier(value: &str, subject: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!(
            "{subject} must match [a-z0-9][a-z0-9._-]* within 64 bytes"
        ));
    }
    Ok(())
}

fn canonical_decimal(value: &str, positive: bool, subject: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(format!("{subject} must be a canonical decimal"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{subject} is out of range"))?;
    if positive && value == 0 {
        return Err(format!("{subject} must be positive"));
    }
    Ok(value)
}

fn require_enum(value: &str, allowed: &[&str], subject: &str) -> Result<(), String> {
    allowed
        .contains(&value)
        .then_some(())
        .ok_or_else(|| format!("{subject} is unknown"))
}

fn validate_provider_address(value: &str, event_pubkey: &str) -> Result<(), String> {
    let mut parts = value.split(':');
    let kind = parts.next();
    let pubkey = parts.next();
    let distinct = parts.next();
    if kind != Some("39600") || pubkey != Some(event_pubkey) || parts.next().is_some() {
        return Err(
            "offering provider must be a kind 39600 address from the offering signer".to_owned(),
        );
    }
    validate_identifier(distinct.unwrap_or_default(), "provider id")
}

fn validate_retrieval_url(value: &str) -> Result<(), String> {
    let authority_and_path = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    if value.len() > 2_048
        || authority_and_path.is_none_or(str::is_empty)
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("profile descriptor r must be a bounded http(s) URL".to_owned());
    }
    Ok(())
}
