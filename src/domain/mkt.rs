use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

use super::hex::decode_lower_hex;
use super::{Event, Tag};

pub const MKT_PROVIDER_PROFILE_KIND: u16 = 39_600;
pub const MKT_OFFERING_KIND: u16 = 39_601;
pub const MKT_PROFILE_DESCRIPTOR_KIND: u16 = 39_602;
pub const MKT_PUBLIC_RECEIPT_KIND: u16 = 39_603;
pub const MKT_RFQ_KIND: u16 = 39_604;
pub const MKT_QUOTE_KIND: u16 = 39_605;
pub const MKT_ORDER_KIND: u16 = 39_606;
pub const MKT_STATUS_KIND: u16 = 39_607;
pub const MKT_CANCEL_KIND: u16 = 39_608;
pub const MKT_CLOSE_KIND: u16 = 39_609;
pub const MKT_EXECUTABLE_PROFILES: &[(&str, u64)] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MktImmutableDecision {
    StoreFirst,
    Replay,
    Conflict,
}

pub const MKT_MAX_DISCOVERY_CONTENT_BYTES: usize = 16 * 1024;
pub const MKT_MAX_RECEIPT_CONTENT_BYTES: usize = 4 * 1024;
pub const MKT_MAX_PRIVATE_EVENT_BYTES: usize = 32 * 1024;
pub const MKT_MAX_TAGS: usize = 64;
pub const MKT_MAX_COUNTERPARTIES: usize = 8;
pub const MKT_MAX_REFERENCES: usize = 32;
pub const MKT_MAX_PROFILES: usize = 16;
pub const MKT_MAX_HINTS: usize = 8;
pub const MKT_IDENTIFIER_MAX_BYTES: usize = 64;
pub const MKT_IDENTIFIER_PATTERN: &str = "[a-z0-9][a-z0-9._-]*";
pub const MKT_ENVELOPE_SCHEMA: &str = "openagents.mkt.v1";
pub const MKT_PROVIDER_STATUSES: &[&str] = &["active", "paused", "retired"];
pub const MKT_OFFERING_STATUSES: &[&str] = &["active", "paused", "exhausted", "retired"];
pub const MKT_DESCRIPTOR_STATUSES: &[&str] = &["draft", "active", "deprecated", "withdrawn"];
pub const MKT_QUOTE_CLASSES: &[&str] = &["indicative", "firm"];
pub const MKT_RESERVATION_CLASSES: &[&str] = &["none", "soft", "hard"];
pub const MKT_STATUS_STATES: &[&str] = &[
    "accepted",
    "rejected",
    "awaiting_input",
    "funding_required",
    "funding_observed",
    "executing",
    "settlement_pending",
    "completed",
    "refund_pending",
    "refunded",
    "disputed",
    "failed",
];
pub const MKT_CANCEL_ACTIONS: &[&str] = &["request", "accepted", "rejected", "effective"];
pub const MKT_OUTCOMES: &[&str] = &[
    "completed",
    "rejected",
    "cancelled",
    "expired",
    "failed",
    "refunded",
    "disputed",
    "unresolved",
];
pub const MKT_PUBLIC_RECEIPT_OUTCOMES: &[&str] = &[
    "completed",
    "cancelled",
    "expired",
    "failed",
    "refunded",
    "disputed",
    "unresolved",
];

#[derive(Debug, Clone, PartialEq)]
pub struct MktPrivateEnvelope {
    pub profile_id: String,
    pub profile_version: u64,
    pub session_id: String,
    pub body: Map<String, Value>,
}

#[derive(Debug, Clone, Copy)]
pub struct MktProfileSupport<'a> {
    pub profile_id: &'a str,
    pub version: u64,
    pub critical_members: &'a [&'a str],
    pub understood_members: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MktValidationCode {
    EventTooLarge,
    InvalidJson,
    DuplicateJsonMember,
    InvalidEventShape,
    InvalidEventStructure,
    InvalidEventSignature,
    InvalidKind,
    CollectionLimit,
    TagGrammar,
    InvalidIdentifier,
    InvalidReference,
    EnvelopeMismatch,
    UnsupportedProfile,
    UnsupportedProfileVersion,
    UnsupportedCriticalMember,
}

impl MktValidationCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventTooLarge => "event_too_large",
            Self::InvalidJson => "invalid_json",
            Self::DuplicateJsonMember => "duplicate_json_member",
            Self::InvalidEventShape => "invalid_event_shape",
            Self::InvalidEventStructure => "invalid_event_structure",
            Self::InvalidEventSignature => "invalid_event_signature",
            Self::InvalidKind => "invalid_kind",
            Self::CollectionLimit => "collection_limit",
            Self::TagGrammar => "tag_grammar",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidReference => "invalid_reference",
            Self::EnvelopeMismatch => "envelope_mismatch",
            Self::UnsupportedProfile => "unsupported_profile",
            Self::UnsupportedProfileVersion => "unsupported_profile_version",
            Self::UnsupportedCriticalMember => "unsupported_critical_member",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktValidationError {
    pub code: MktValidationCode,
    pub detail: String,
}

impl fmt::Display for MktValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for MktValidationError {}

#[derive(Debug, Clone, PartialEq)]
pub struct MktValidatedPrivateRecord {
    pub raw_signed_event: Vec<u8>,
    pub event: Event,
    pub envelope: MktPrivateEnvelope,
}

pub fn validate_mkt_public_event(event: &Event) -> Result<(), String> {
    if (MKT_PROVIDER_PROFILE_KIND..=MKT_PUBLIC_RECEIPT_KIND).contains(&event.kind) {
        validate_collection_bounds(event)?;
        let maximum = if event.kind == MKT_PUBLIC_RECEIPT_KIND {
            MKT_MAX_RECEIPT_CONTENT_BYTES
        } else {
            MKT_MAX_DISCOVERY_CONTENT_BYTES
        };
        validate_content_bound(event, maximum, "public MKT")?;
        let content = parse_unique_json(&event.content, "public MKT content")?;
        if !content.is_object() {
            return Err("public MKT content must be a JSON object".to_owned());
        }
    }
    match event.kind {
        MKT_PROVIDER_PROFILE_KIND => validate_provider_profile(event),
        MKT_OFFERING_KIND => validate_offering(event),
        MKT_PROFILE_DESCRIPTOR_KIND => validate_profile_descriptor(event),
        MKT_PUBLIC_RECEIPT_KIND => validate_public_receipt(event),
        _ => Ok(()),
    }
}

pub fn validate_mkt_private_base(event: &Event) -> Result<MktPrivateEnvelope, MktValidationError> {
    validate_mkt_private_syntax(event).map_err(classify_syntax_error)
}

fn validate_mkt_private_syntax(event: &Event) -> Result<MktPrivateEnvelope, String> {
    if !is_mkt_private_kind(event.kind) {
        return Err("event kind is outside the private NIP-MKT range".to_owned());
    }
    validate_collection_bounds(event)?;
    let serialized_bytes = serde_json::to_vec(event)
        .map_err(|error| format!("private MKT event serialization failed: {error}"))?
        .len();
    if serialized_bytes > MKT_MAX_PRIVATE_EVENT_BYTES {
        return Err(format!(
            "private MKT event exceeds {MKT_MAX_PRIVATE_EVENT_BYTES} serialized bytes"
        ));
    }

    let distinct = single_value(event, "d", "private MKT event")?;
    lower_hex_32(distinct, "private MKT d")?;
    let session = single_value(event, "session", "private MKT event")?;
    lower_hex_32(session, "private MKT session")?;
    let profiles = profile_tags(event, "private MKT event")?;
    let [(profile_id, profile_version)] = profiles.as_slice() else {
        return Err("private MKT event requires exactly one profile tag".to_owned());
    };
    let alt = single_value(event, "alt", "private MKT event")?;
    if alt.is_empty() || alt.len() > 128 || alt.chars().any(char::is_control) {
        return Err("private MKT alt must be a nonempty bounded description".to_owned());
    }
    validate_counterparties(event)?;
    validate_references(event)?;

    let value = parse_unique_json(&event.content, "private MKT content")?;
    let Value::Object(body) = value else {
        return Err("private MKT content must be a JSON object".to_owned());
    };
    require_json_string(&body, "schema", MKT_ENVELOPE_SCHEMA)?;
    require_json_string(&body, "profile", profile_id)?;
    require_json_u64(&body, "profile_version", *profile_version)?;
    require_json_string(&body, "session_id", session)?;

    Ok(MktPrivateEnvelope {
        profile_id: (*profile_id).to_owned(),
        profile_version: *profile_version,
        session_id: session.to_owned(),
        body,
    })
}

pub fn validate_mkt_private_with_profiles(
    event: &Event,
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<MktPrivateEnvelope, MktValidationError> {
    let envelope = validate_mkt_private_base(event)?;
    let profile_matches = supported_profiles
        .iter()
        .filter(|support| support.profile_id == envelope.profile_id)
        .collect::<Vec<_>>();
    if profile_matches.is_empty() {
        return Err(validation_error(
            MktValidationCode::UnsupportedProfile,
            "private MKT profile is unsupported",
        ));
    }
    let support = profile_matches
        .into_iter()
        .find(|support| support.version == envelope.profile_version)
        .ok_or_else(|| {
            validation_error(
                MktValidationCode::UnsupportedProfileVersion,
                "private MKT profile version is unsupported",
            )
        })?;
    for member in support.critical_members {
        if envelope.body.contains_key(*member) && !support.understood_members.contains(member) {
            return Err(validation_error(
                MktValidationCode::UnsupportedCriticalMember,
                format!("private MKT critical member {member:?} is unsupported"),
            ));
        }
    }
    Ok(envelope)
}

pub fn validate_mkt_private_raw(
    raw_event: &[u8],
    supported_profiles: &[MktProfileSupport<'_>],
) -> Result<MktValidatedPrivateRecord, MktValidationError> {
    if raw_event.len() > MKT_MAX_PRIVATE_EVENT_BYTES {
        return Err(validation_error(
            MktValidationCode::EventTooLarge,
            format!("private MKT signed record exceeds {MKT_MAX_PRIVATE_EVENT_BYTES} raw bytes"),
        ));
    }
    let raw_text = std::str::from_utf8(raw_event).map_err(|_| {
        validation_error(
            MktValidationCode::InvalidJson,
            "private MKT signed record is not UTF-8",
        )
    })?;
    let value =
        parse_unique_json(raw_text, "private MKT signed record").map_err(classify_syntax_error)?;
    let Value::Object(fields) = &value else {
        return Err(validation_error(
            MktValidationCode::InvalidEventShape,
            "private MKT signed record must be an event object",
        ));
    };
    const EVENT_FIELDS: [&str; 7] = [
        "id",
        "pubkey",
        "created_at",
        "kind",
        "tags",
        "content",
        "sig",
    ];
    if let Some(name) = fields
        .keys()
        .find(|name| !EVENT_FIELDS.contains(&name.as_str()))
    {
        return Err(validation_error(
            MktValidationCode::InvalidEventShape,
            format!("private MKT signed record has unknown event member {name:?}"),
        ));
    }
    let event: Event = serde_json::from_value(value).map_err(|error| {
        validation_error(
            MktValidationCode::InvalidEventShape,
            format!("private MKT signed record has invalid event shape: {error}"),
        )
    })?;
    event.validate_structure().map_err(|error| {
        validation_error(
            MktValidationCode::InvalidEventStructure,
            format!("private MKT signed record structure is invalid: {error}"),
        )
    })?;
    event.validate_crypto().map_err(|error| {
        validation_error(
            MktValidationCode::InvalidEventSignature,
            format!("private MKT signed record signature is invalid: {error}"),
        )
    })?;
    let envelope = validate_mkt_private_with_profiles(&event, supported_profiles)?;
    Ok(MktValidatedPrivateRecord {
        raw_signed_event: raw_event.to_vec(),
        event,
        envelope,
    })
}

fn validation_error(code: MktValidationCode, detail: impl Into<String>) -> MktValidationError {
    MktValidationError {
        code,
        detail: detail.into(),
    }
}

fn classify_syntax_error(detail: String) -> MktValidationError {
    let code = if detail.contains("exceeds 32768") || detail.contains("serialization failed") {
        MktValidationCode::EventTooLarge
    } else if detail.contains("duplicate JSON member") {
        MktValidationCode::DuplicateJsonMember
    } else if detail.contains("invalid JSON") || detail.contains("trailing data") {
        MktValidationCode::InvalidJson
    } else if detail.contains("outside the private NIP-MKT range") {
        MktValidationCode::InvalidKind
    } else if detail.contains("exceeds") {
        MktValidationCode::CollectionLimit
    } else if detail.contains("reference")
        || detail.contains("offering")
        || detail.contains("private MKT e tag")
    {
        MktValidationCode::InvalidReference
    } else if detail.contains("64 lowercase hexadecimal")
        || detail.contains("identifier")
        || detail.contains("profile id")
    {
        MktValidationCode::InvalidIdentifier
    } else if detail.contains("content") {
        MktValidationCode::EnvelopeMismatch
    } else {
        MktValidationCode::TagGrammar
    };
    validation_error(code, detail)
}

pub const fn is_mkt_private_kind(kind: u16) -> bool {
    matches!(
        kind,
        MKT_RFQ_KIND
            | MKT_QUOTE_KIND
            | MKT_ORDER_KIND
            | MKT_STATUS_KIND
            | MKT_CANCEL_KIND
            | MKT_CLOSE_KIND
    )
}

pub fn decide_mkt_immutable_admission(
    stored_signed_event: Option<(&str, &str)>,
    candidate_event_id: &str,
    candidate_signature: &str,
) -> MktImmutableDecision {
    match stored_signed_event {
        None => MktImmutableDecision::StoreFirst,
        Some((stored_event_id, stored_signature))
            if stored_event_id == candidate_event_id && stored_signature == candidate_signature =>
        {
            MktImmutableDecision::Replay
        }
        Some((_, _)) => MktImmutableDecision::Conflict,
    }
}

fn validate_provider_profile(event: &Event) -> Result<(), String> {
    validate_content_bound(event, MKT_MAX_DISCOVERY_CONTENT_BYTES, "provider profile")?;
    validate_identifier(single_value(event, "d", "provider profile")?, "provider id")?;
    require_enum(
        single_value(event, "status", "provider profile")?,
        MKT_PROVIDER_STATUSES,
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
    validate_content_bound(event, MKT_MAX_DISCOVERY_CONTENT_BYTES, "offering")?;
    validate_identifier(single_value(event, "d", "offering")?, "offering id")?;
    require_enum(
        single_value(event, "status", "offering")?,
        MKT_OFFERING_STATUSES,
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
    validate_content_bound(event, MKT_MAX_DISCOVERY_CONTENT_BYTES, "profile descriptor")?;
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
        MKT_DESCRIPTOR_STATUSES,
        "profile descriptor status",
    )
}

fn validate_public_receipt(event: &Event) -> Result<(), String> {
    validate_content_bound(
        event,
        MKT_MAX_RECEIPT_CONTENT_BYTES,
        "public market receipt",
    )?;
    if single_value(event, "d", "public market receipt")?.is_empty() {
        return Err("public market receipt d must not be empty".to_owned());
    }
    let profiles = profile_tags(event, "public market receipt")?;
    if profiles.len() != 1 {
        return Err("public market receipt requires exactly one profile tag".to_owned());
    }
    require_enum(
        single_value(event, "outcome", "public market receipt")?,
        MKT_PUBLIC_RECEIPT_OUTCOMES,
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

fn validate_collection_bounds(event: &Event) -> Result<(), String> {
    if event.tags.len() > MKT_MAX_TAGS {
        return Err(format!("NIP-MKT event exceeds {MKT_MAX_TAGS} tags"));
    }
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .count();
    if counterparties > MKT_MAX_COUNTERPARTIES {
        return Err(format!(
            "NIP-MKT event exceeds {MKT_MAX_COUNTERPARTIES} p tags"
        ));
    }
    let references = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("e"))
        .count();
    if references > MKT_MAX_REFERENCES {
        return Err(format!(
            "NIP-MKT event exceeds {MKT_MAX_REFERENCES} causal or evidence references"
        ));
    }
    let profiles = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("profile"))
        .count();
    if profiles > MKT_MAX_PROFILES {
        return Err(format!(
            "NIP-MKT event exceeds {MKT_MAX_PROFILES} profile tags"
        ));
    }
    let hints = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("relay")
                || (matches!(tag.name(), Some("p" | "e" | "a"))
                    && tag.as_slice().get(2).is_some_and(|hint| !hint.is_empty()))
        })
        .count();
    if hints > MKT_MAX_HINTS {
        return Err(format!(
            "NIP-MKT event exceeds {MKT_MAX_HINTS} relay or endpoint hints"
        ));
    }
    Ok(())
}

fn validate_counterparties(event: &Event) -> Result<(), String> {
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .collect::<Vec<_>>();
    let mut role_marked = 0;
    for tag in counterparties {
        let values = tag.as_slice();
        if values
            .get(3)
            .is_some_and(|role| matches!(role.as_str(), "requester" | "provider"))
        {
            let pubkey = values.get(1).map(String::as_str).unwrap_or_default();
            lower_hex_32(pubkey, "private MKT counterparty")?;
            role_marked += 1;
        }
    }
    if role_marked == 0 {
        return Err("private MKT event requires a requester/provider role-marked p tag".to_owned());
    }
    Ok(())
}

fn validate_references(event: &Event) -> Result<(), String> {
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        let values = tag.as_slice();
        if values.len() < 4
            || !matches!(
                values[3].as_str(),
                "rfq"
                    | "quote"
                    | "order"
                    | "previous"
                    | "status"
                    | "cancel"
                    | "close"
                    | "evidence"
                    | "settlement"
            )
        {
            return Err("private MKT e tag has an unknown or missing marker".to_owned());
        }
        lower_hex_32(&values[1], "private MKT event reference")?;
    }
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("a")) {
        let values = tag.as_slice();
        if values.get(3).is_some_and(|marker| marker == "offering") {
            let address = values.get(1).map(String::as_str).unwrap_or_default();
            validate_offering_address(address)?;
        }
    }
    Ok(())
}

fn validate_offering_address(value: &str) -> Result<(), String> {
    let mut parts = value.split(':');
    if parts.next() != Some("39601") {
        return Err("private MKT offering reference has the wrong kind".to_owned());
    }
    let pubkey = parts.next().unwrap_or_default();
    let offering_id = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err("private MKT offering reference is malformed".to_owned());
    }
    lower_hex_32(pubkey, "private MKT offering pubkey")?;
    validate_identifier(offering_id, "offering id")
}

fn lower_hex_32(value: &str, subject: &str) -> Result<(), String> {
    decode_lower_hex::<32>(value, "NIP-MKT hexadecimal value")
        .map(|_| ())
        .map_err(|_| format!("{subject} must be 64 lowercase hexadecimal characters"))
}

fn require_json_string(
    body: &Map<String, Value>,
    name: &str,
    expected: &str,
) -> Result<(), String> {
    match body.get(name) {
        Some(Value::String(value)) if value == expected => Ok(()),
        Some(Value::String(_)) => Err(format!(
            "private MKT content {name} does not agree with its tag or schema"
        )),
        _ => Err(format!("private MKT content requires string member {name}")),
    }
}

fn require_json_u64(body: &Map<String, Value>, name: &str, expected: u64) -> Result<(), String> {
    match body.get(name).and_then(Value::as_u64) {
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(format!(
            "private MKT content {name} does not agree with its profile tag"
        )),
        None => Err(format!(
            "private MKT content requires unsigned integer member {name}"
        )),
    }
}

fn parse_unique_json(content: &str, subject: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(content);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{subject} is invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{subject} has trailing data: {error}"))?;
    Ok(value.0)
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut names = BTreeSet::new();
        while let Some(name) = object.next_key::<String>()? {
            if !names.insert(name.clone()) {
                return Err(A::Error::custom(format!("duplicate JSON member {name:?}")));
            }
            let value = object.next_value::<UniqueJsonValue>()?;
            values.insert(name, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
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
        || bytes.len() > MKT_IDENTIFIER_MAX_BYTES
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!(
            "{subject} must match {MKT_IDENTIFIER_PATTERN} within {MKT_IDENTIFIER_MAX_BYTES} bytes"
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
