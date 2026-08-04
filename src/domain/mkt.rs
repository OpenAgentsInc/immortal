use std::{collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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
pub const MKT_SWP_SWAP_CONTRACT_KIND: u16 = 39_610;
pub const MKT_SWP_PROFILE_ID: &str = "mkt-swp";
pub const MKT_SWP_PROFILE_VERSION: u64 = 1;
pub const MKT_PFI_QUALIFICATION_POLICY_KIND: u16 = 39_630;
pub const MKT_PFI_PROFILE_ID: &str = "mkt-pfi";
pub const MKT_PFI_PROFILE_VERSION: u64 = 1;
pub const MKT_EXECUTABLE_PROFILES: &[(&str, u64)] = &[];
pub const MKT_RELAY_PROFILES: &[(&str, u64)] = &[
    (MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION),
    (MKT_PFI_PROFILE_ID, MKT_PFI_PROFILE_VERSION),
];

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
    if (MKT_PROVIDER_PROFILE_KIND..=MKT_PUBLIC_RECEIPT_KIND).contains(&event.kind)
        || event.kind == MKT_PFI_QUALIFICATION_POLICY_KIND
    {
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
        MKT_PFI_QUALIFICATION_POLICY_KIND => validate_mkt_pfi_qualification_policy(event),
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
    if event.kind == MKT_SWP_SWAP_CONTRACT_KIND {
        if *profile_id != MKT_SWP_PROFILE_ID {
            return Err(swp_error(
                "swp_unsupported_profile",
                "kind 39610 requires profile mkt-swp",
            ));
        }
        if *profile_version != MKT_SWP_PROFILE_VERSION {
            return Err(swp_error(
                "swp_unsupported_version",
                "kind 39610 requires MKT-SWP version 1",
            ));
        }
    }
    let alt = single_value(event, "alt", "private MKT event")?;
    if alt.is_empty() || alt.len() > 128 || alt.chars().any(char::is_control) {
        return Err("private MKT alt must be a nonempty bounded description".to_owned());
    }
    validate_counterparties(event)?;
    validate_references(event, profile_id, *profile_version)?;

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
    if envelope.profile_id == MKT_SWP_PROFILE_ID
        && envelope.profile_version == MKT_SWP_PROFILE_VERSION
    {
        validate_mkt_swp_visible_private(event, &envelope)
            .map_err(|detail| validation_error(MktValidationCode::TagGrammar, detail))?;
    }
    if envelope.profile_id == MKT_PFI_PROFILE_ID
        && envelope.profile_version == MKT_PFI_PROFILE_VERSION
    {
        validate_mkt_pfi_visible_private(&envelope)
            .map_err(|detail| validation_error(MktValidationCode::TagGrammar, detail))?;
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
    let code = if detail.starts_with("swp_unsupported_profile") {
        MktValidationCode::UnsupportedProfile
    } else if detail.starts_with("swp_unsupported_version") {
        MktValidationCode::UnsupportedProfileVersion
    } else if detail.contains("exceeds 32768") || detail.contains("serialization failed") {
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
            | MKT_SWP_SWAP_CONTRACT_KIND
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
    validate_provider_address(single_value(event, "provider", "offering")?, &event.pubkey)?;
    if profiles[0].0 == MKT_SWP_PROFILE_ID {
        if profiles[0].1 != MKT_SWP_PROFILE_VERSION {
            return Err(swp_error(
                "swp_unsupported_version",
                "only MKT-SWP profile version 1 is relay-observable",
            ));
        }
        validate_mkt_swp_offering(event)?;
    } else if profiles[0].0 == MKT_PFI_PROFILE_ID {
        if profiles[0].1 != MKT_PFI_PROFILE_VERSION {
            return Err(pfi_error(
                "pfi_unsupported_version",
                "only MKT-PFI profile version 1 is relay-observable",
            ));
        }
        validate_mkt_pfi_offering(event)?;
    }
    Ok(())
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
    )?;
    if profiles[0].0 == MKT_SWP_PROFILE_ID {
        if profiles[0].1 != MKT_SWP_PROFILE_VERSION {
            return Err(swp_error(
                "swp_unsupported_version",
                "only MKT-SWP profile version 1 is relay-observable",
            ));
        }
        let content = parse_unique_json(&event.content, "MKT-SWP public receipt content")?;
        reject_swp_secret_material(&content)?;
        reject_swp_public_offering_material(&content)?;
        reject_swp_public_receipt_material(&content)?;
    } else if profiles[0].0 == MKT_PFI_PROFILE_ID {
        if profiles[0].1 != MKT_PFI_PROFILE_VERSION {
            return Err(pfi_error(
                "pfi_unsupported_version",
                "only MKT-PFI profile version 1 is relay-observable",
            ));
        }
        let content = parse_unique_json(&event.content, "MKT-PFI public receipt content")?;
        reject_pfi_forbidden_material(&content)?;
        validate_mkt_pfi_public_receipt_content(&content)?;
    }
    Ok(())
}

fn validate_mkt_pfi_qualification_policy(event: &Event) -> Result<(), String> {
    let profiles = profile_tags(event, "MKT-PFI qualification policy")?;
    let [(profile_id, profile_version)] = profiles.as_slice() else {
        return Err(pfi_error(
            "pfi_unsupported_version",
            "qualification policy requires exactly one profile tag",
        ));
    };
    if *profile_id != MKT_PFI_PROFILE_ID || *profile_version != MKT_PFI_PROFILE_VERSION {
        return Err(pfi_error(
            "pfi_unsupported_version",
            "kind 39630 requires profile mkt-pfi version 1",
        ));
    }
    let policy_id = single_value(event, "d", "MKT-PFI qualification policy")?;
    pfi_identifier(policy_id, "qualification policy id", 128)?;
    require_enum(
        single_value(event, "status", "MKT-PFI qualification policy")?,
        MKT_PROVIDER_STATUSES,
        "MKT-PFI qualification policy status",
    )
    .map_err(|detail| pfi_error("pfi_policy_unknown_member", detail))?;
    let version = canonical_decimal(
        single_value(event, "version", "MKT-PFI qualification policy")?,
        true,
        "MKT-PFI qualification policy version",
    )
    .map_err(|detail| pfi_error("pfi_policy_unknown_member", detail))?;
    canonical_decimal(
        single_value(event, "published_at", "MKT-PFI qualification policy")?,
        false,
        "MKT-PFI qualification policy published_at",
    )
    .map_err(|detail| pfi_error("pfi_policy_unknown_member", detail))?;
    if single_value(event, "alt", "MKT-PFI qualification policy")? != "MKT-PFI qualification policy"
    {
        return Err(pfi_error(
            "pfi_policy_unknown_member",
            "qualification policy alt tag is not the fixed profile label",
        ));
    }
    let tagged_digest = single_value(event, "x", "MKT-PFI qualification policy")?;
    pfi_hex_with_code(
        tagged_digest,
        "qualification policy content digest",
        "pfi_policy_digest_mismatch",
    )?;
    if tagged_digest != sha256_hex(event.content.as_bytes()) {
        return Err(pfi_error(
            "pfi_policy_digest_mismatch",
            "qualification policy x does not hash the exact content bytes",
        ));
    }

    let content = parse_unique_json(&event.content, "MKT-PFI qualification policy content")?;
    reject_pfi_forbidden_material(&content)?;
    let body = pfi_object(
        &content,
        "qualification policy",
        "pfi_policy_unknown_member",
    )?;
    pfi_closed(
        body,
        &[
            "schema",
            "profile",
            "profile_version",
            "qualification_policy_id",
            "policy_version",
            "jurisdictions",
            "requirements",
            "retention",
        ],
        "qualification policy",
        "pfi_policy_unknown_member",
    )?;
    pfi_exact_string(
        body,
        "schema",
        MKT_ENVELOPE_SCHEMA,
        "pfi_policy_unknown_member",
    )?;
    pfi_exact_string(
        body,
        "profile",
        MKT_PFI_PROFILE_ID,
        "pfi_policy_unknown_member",
    )?;
    if body.get("profile_version").and_then(Value::as_u64) != Some(MKT_PFI_PROFILE_VERSION) {
        return Err(pfi_error(
            "pfi_unsupported_version",
            "qualification policy content requires profile_version 1",
        ));
    }
    if pfi_required_string(body, "qualification_policy_id", "pfi_policy_unknown_member")?
        != policy_id
    {
        return Err(pfi_error(
            "pfi_policy_missing",
            "qualification policy d and content identifier differ",
        ));
    }
    let content_version =
        pfi_decimal_member(body, "policy_version", true, "pfi_policy_unknown_member")?;
    if content_version != version {
        return Err(pfi_error(
            "pfi_policy_missing",
            "qualification policy version tag and content differ",
        ));
    }
    validate_pfi_jurisdictions(body.get("jurisdictions"), "qualification policy")?;

    let requirements = body
        .get("requirements")
        .and_then(Value::as_array)
        .filter(|requirements| requirements.len() <= 16)
        .ok_or_else(|| {
            pfi_error(
                "pfi_policy_unknown_member",
                "qualification policy requires at most 16 requirements",
            )
        })?;
    let mut requirement_ids = BTreeSet::new();
    for requirement in requirements {
        let requirement = pfi_object(
            requirement,
            "qualification requirement",
            "pfi_policy_unknown_member",
        )?;
        pfi_closed(
            requirement,
            &[
                "requirement_id",
                "credential_schema_id",
                "accepted_issuer_ids",
                "claim_types",
                "presentation_format",
                "presentation_stage",
                "maximum_credential_age_seconds",
            ],
            "qualification requirement",
            "pfi_policy_unknown_member",
        )?;
        let requirement_id =
            pfi_required_string(requirement, "requirement_id", "pfi_policy_unknown_member")?;
        pfi_identifier(requirement_id, "qualification requirement id", 128)?;
        if !requirement_ids.insert(requirement_id) {
            return Err(pfi_error(
                "pfi_policy_unknown_member",
                "qualification requirement ids must be unique",
            ));
        }
        pfi_public_url(
            pfi_required_string(
                requirement,
                "credential_schema_id",
                "pfi_policy_unknown_member",
            )?,
            "credential schema",
        )?;
        let issuers = pfi_string_array(
            requirement.get("accepted_issuer_ids"),
            1,
            16,
            "accepted issuer ids",
            "pfi_policy_unknown_member",
        )?;
        for issuer in issuers {
            pfi_bounded_ascii(
                issuer,
                "accepted issuer id",
                512,
                "pfi_policy_unknown_member",
            )?;
        }
        let claims = pfi_string_array(
            requirement.get("claim_types"),
            1,
            32,
            "claim types",
            "pfi_policy_unknown_member",
        )?;
        for claim in claims {
            pfi_identifier(claim, "claim type", 128)?;
        }
        pfi_bounded_ascii(
            pfi_required_string(
                requirement,
                "presentation_format",
                "pfi_policy_unknown_member",
            )?,
            "presentation format",
            128,
            "pfi_policy_unknown_member",
        )?;
        pfi_exact_string(
            requirement,
            "presentation_stage",
            "post_quote_pre_acceptance",
            "pfi_policy_unknown_member",
        )?;
        pfi_decimal_member(
            requirement,
            "maximum_credential_age_seconds",
            false,
            "pfi_policy_unknown_member",
        )?;
    }

    let retention = pfi_object(
        body.get("retention")
            .ok_or_else(|| pfi_error("pfi_policy_unknown_member", "retention is required"))?,
        "retention",
        "pfi_policy_unknown_member",
    )?;
    pfi_closed(
        retention,
        &[
            "policy_url",
            "policy_sha256",
            "maximum_seconds",
            "deletion_request_url",
        ],
        "retention",
        "pfi_policy_unknown_member",
    )?;
    for member in ["policy_url", "deletion_request_url"] {
        pfi_public_url(
            pfi_required_string(retention, member, "pfi_policy_unknown_member")?,
            member,
        )?;
    }
    pfi_hex(
        pfi_required_string(retention, "policy_sha256", "pfi_policy_unknown_member")?,
        "retention policy digest",
    )?;
    pfi_decimal_member(
        retention,
        "maximum_seconds",
        false,
        "pfi_policy_unknown_member",
    )?;
    Ok(())
}

fn validate_mkt_pfi_offering(event: &Event) -> Result<(), String> {
    let content = parse_unique_json(&event.content, "MKT-PFI Offering content")?;
    reject_pfi_forbidden_material(&content)?;
    let body = pfi_object(&content, "MKT-PFI Offering", "pfi_policy_unknown_member")?;
    pfi_closed(
        body,
        &["schema", "profile", "profile_version", "pfi"],
        "MKT-PFI Offering",
        "pfi_policy_unknown_member",
    )?;
    pfi_exact_string(
        body,
        "schema",
        MKT_ENVELOPE_SCHEMA,
        "pfi_policy_unknown_member",
    )?;
    pfi_exact_string(
        body,
        "profile",
        MKT_PFI_PROFILE_ID,
        "pfi_policy_unknown_member",
    )?;
    if body.get("profile_version").and_then(Value::as_u64) != Some(MKT_PFI_PROFILE_VERSION) {
        return Err(pfi_error(
            "pfi_unsupported_version",
            "MKT-PFI Offering content requires profile_version 1",
        ));
    }
    let pfi = pfi_object(
        body.get("pfi")
            .ok_or_else(|| pfi_error("pfi_policy_unknown_member", "pfi object is required"))?,
        "MKT-PFI Offering pfi",
        "pfi_policy_unknown_member",
    )?;
    pfi_closed(
        pfi,
        &[
            "market_id",
            "fiat_asset",
            "crypto_asset",
            "on_ramp",
            "off_ramp",
            "fee_bps",
            "qualification_policy_event_id",
            "qualification_policy_sha256",
            "credential_burden",
            "rail_ids",
            "risk_classes",
            "jurisdictions",
            "custody_dimensions",
        ],
        "MKT-PFI Offering pfi",
        "pfi_policy_unknown_member",
    )?;

    let fiat_asset = validate_pfi_asset(
        pfi.get("fiat_asset")
            .ok_or_else(|| pfi_error("pfi_invalid_asset_id", "fiat_asset is required"))?,
        true,
    )?;
    let crypto_asset = validate_pfi_asset(
        pfi.get("crypto_asset")
            .ok_or_else(|| pfi_error("pfi_invalid_asset_id", "crypto_asset is required"))?,
        false,
    )?;
    let expected_market = pfi_market_id(fiat_asset, crypto_asset);
    let market_id = pfi_required_string(pfi, "market_id", "pfi_market_id_mismatch")?;
    pfi_hex_with_code(market_id, "MKT-PFI market id", "pfi_market_id_mismatch")?;
    if market_id != expected_market {
        return Err(pfi_error(
            "pfi_market_id_mismatch",
            "market_id does not commit to the ordered asset pair",
        ));
    }
    if single_value(event, "market", "MKT-PFI Offering")? != market_id {
        return Err(pfi_error(
            "pfi_market_id_mismatch",
            "Offering market tag and content differ",
        ));
    }

    let on_ramp = validate_pfi_side(
        pfi.get("on_ramp")
            .ok_or_else(|| pfi_error("pfi_side_disabled", "on_ramp is required"))?,
        fiat_asset,
        crypto_asset,
        "on_ramp",
    )?;
    let off_ramp = validate_pfi_side(
        pfi.get("off_ramp")
            .ok_or_else(|| pfi_error("pfi_side_disabled", "off_ramp is required"))?,
        crypto_asset,
        fiat_asset,
        "off_ramp",
    )?;
    if !on_ramp && !off_ramp {
        return Err(pfi_error(
            "pfi_side_disabled",
            "Offering must enable at least one direction",
        ));
    }
    let direction_tags = pfi_two_element_tags(event, "direction", 1, 2)?;
    let expected_directions = [("on_ramp", on_ramp), ("off_ramp", off_ramp)]
        .into_iter()
        .filter_map(|(direction, enabled)| enabled.then_some(direction))
        .collect::<BTreeSet<_>>();
    if direction_tags.iter().copied().collect::<BTreeSet<_>>() != expected_directions
        || direction_tags.len() != expected_directions.len()
    {
        return Err(pfi_error(
            "pfi_side_disabled",
            "direction tags must name exactly the enabled sides",
        ));
    }

    let fee_bps = pfi_decimal_member(pfi, "fee_bps", false, "pfi_invalid_fee_promise")?;
    if fee_bps > 10_000 {
        return Err(pfi_error(
            "pfi_invalid_fee_promise",
            "fee_bps exceeds 10000",
        ));
    }
    let policy_event_id =
        pfi_required_string(pfi, "qualification_policy_event_id", "pfi_policy_missing")?;
    pfi_hex_with_code(
        policy_event_id,
        "qualification policy event id",
        "pfi_policy_missing",
    )?;
    pfi_hex_with_code(
        pfi_required_string(pfi, "qualification_policy_sha256", "pfi_policy_missing")?,
        "qualification policy digest",
        "pfi_policy_missing",
    )?;
    validate_pfi_policy_tags(event, policy_event_id)?;

    require_enum(
        pfi_required_string(pfi, "credential_burden", "pfi_policy_unknown_member")?,
        &["none", "basic", "enhanced", "institutional"],
        "MKT-PFI credential burden",
    )
    .map_err(|detail| pfi_error("pfi_policy_unknown_member", detail))?;
    let rails = pfi_string_array(
        pfi.get("rail_ids"),
        1,
        16,
        "rail ids",
        "pfi_policy_unknown_member",
    )?;
    for rail in &rails {
        pfi_identifier(rail, "rail id", MKT_IDENTIFIER_MAX_BYTES)?;
    }
    let rail_tags = pfi_two_element_tags(event, "rail", 1, 16)?;
    pfi_equal_unique_sets(&rails, &rail_tags, "rail tags and content")?;

    let risks = pfi_string_array(
        pfi.get("risk_classes"),
        1,
        5,
        "risk classes",
        "pfi_risk_classification_missing",
    )?;
    for risk in &risks {
        validate_pfi_risk_class(risk)?;
    }
    let risk_tags = pfi_two_element_tags(event, "risk", 1, 5)?;
    pfi_equal_unique_sets(&risks, &risk_tags, "risk tags and content")?;
    validate_pfi_jurisdictions(pfi.get("jurisdictions"), "MKT-PFI Offering")?;
    validate_pfi_custody_dimensions(pfi.get("custody_dimensions").ok_or_else(|| {
        pfi_error(
            "pfi_policy_unknown_member",
            "custody_dimensions is required",
        )
    })?)?;
    Ok(())
}

fn validate_mkt_pfi_visible_private(envelope: &MktPrivateEnvelope) -> Result<(), String> {
    let value = Value::Object(envelope.body.clone());
    reject_pfi_forbidden_material(&value)?;
    let profile = envelope
        .body
        .get("mkt_pfi")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            pfi_error(
                "pfi_policy_unknown_member",
                "private profile record requires an mkt_pfi object",
            )
        })?;
    validate_pfi_observable_members(&Value::Object(profile.clone()))
}

fn validate_pfi_observable_members(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                match name.as_str() {
                    "risk_classification" => {
                        validate_pfi_risk_class(child.as_str().ok_or_else(|| {
                            pfi_error(
                                "pfi_risk_classification_missing",
                                "risk_classification must be a string",
                            )
                        })?)?
                    }
                    "credential_commitments" => {
                        let commitments = child
                            .as_array()
                            .filter(|values| (1..=16).contains(&values.len()))
                            .ok_or_else(|| {
                                pfi_error(
                                    "pfi_credential_binding_mismatch",
                                    "credential_commitments requires 1-16 entries",
                                )
                            })?;
                        for commitment in commitments {
                            validate_pfi_credential_commitment(commitment)?;
                        }
                    }
                    "evidence_refs" => {
                        let references = child
                            .as_array()
                            .filter(|values| values.len() <= MKT_MAX_REFERENCES)
                            .ok_or_else(|| {
                                pfi_error(
                                    "pfi_settlement_evidence_invalid",
                                    "evidence_refs exceeds the relay bound",
                                )
                            })?;
                        for reference in references {
                            validate_mkt_pfi_evidence_reference(reference)?;
                        }
                    }
                    "dispute" => validate_pfi_dispute(child)?,
                    "recourse" => validate_pfi_recourse(child)?,
                    _ => validate_pfi_observable_members(child)?,
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_pfi_observable_members(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_mkt_pfi_evidence_reference(value: &Value) -> Result<(), String> {
    let evidence = pfi_object(
        value,
        "MKT-PFI evidence reference",
        "pfi_settlement_evidence_invalid",
    )?;
    pfi_closed(
        evidence,
        &[
            "evidence_class",
            "evidence_sha256",
            "authority_id",
            "authority_key",
            "verifier_id",
            "observed_at",
            "provenance",
            "reversibility_until",
            "external_operation_ref",
        ],
        "MKT-PFI evidence reference",
        "pfi_settlement_evidence_invalid",
    )?;
    require_enum(
        pfi_required_string(
            evidence,
            "evidence_class",
            "pfi_settlement_evidence_invalid",
        )?,
        &[
            "rail_receipt",
            "institution_confirmation",
            "beneficiary_attestation",
            "escrow_funding",
            "escrow_release",
            "ledger_finality",
            "reversibility_window_elapsed",
            "refund_confirmation",
            "chargeback_confirmation",
            "guarantee_reserve",
            "guarantee_payout",
            "dispute_disposition",
        ],
        "MKT-PFI evidence class",
    )
    .map_err(|detail| pfi_error("pfi_settlement_evidence_invalid", detail))?;
    pfi_hex_with_code(
        pfi_required_string(
            evidence,
            "evidence_sha256",
            "pfi_settlement_evidence_invalid",
        )?,
        "MKT-PFI evidence digest",
        "pfi_settlement_evidence_invalid",
    )?;
    pfi_bounded_ascii(
        pfi_required_string(evidence, "authority_id", "pfi_settlement_evidence_invalid")?,
        "MKT-PFI evidence authority",
        512,
        "pfi_settlement_evidence_invalid",
    )?;
    pfi_hex_with_code(
        pfi_required_string(evidence, "authority_key", "pfi_settlement_evidence_invalid")?,
        "MKT-PFI evidence authority key",
        "pfi_settlement_evidence_invalid",
    )?;
    pfi_bounded_ascii(
        pfi_required_string(evidence, "verifier_id", "pfi_settlement_evidence_invalid")?,
        "MKT-PFI evidence verifier",
        128,
        "pfi_settlement_evidence_invalid",
    )?;
    for member in ["observed_at", "reversibility_until"] {
        pfi_decimal_member(evidence, member, false, "pfi_settlement_evidence_invalid")?;
    }
    require_enum(
        pfi_required_string(evidence, "provenance", "pfi_settlement_evidence_invalid")?,
        &[
            "pledged", "reserved", "observed", "verified", "paid", "settled",
        ],
        "MKT-PFI evidence provenance",
    )
    .map_err(|detail| pfi_error("pfi_settlement_evidence_invalid", detail))?;
    pfi_non_bearer_reference(
        pfi_required_string(
            evidence,
            "external_operation_ref",
            "pfi_settlement_evidence_invalid",
        )?,
        "external operation reference",
    )
}

fn validate_pfi_credential_commitment(value: &Value) -> Result<(), String> {
    let commitment = pfi_object(
        value,
        "credential commitment",
        "pfi_credential_binding_mismatch",
    )?;
    pfi_closed(
        commitment,
        &[
            "presentation_id",
            "presentation_sha256",
            "policy_event_id",
            "requirement_ids",
            "audience_pubkey",
            "purpose",
            "challenge",
            "expires_at",
            "transport",
            "channel_ref",
        ],
        "credential commitment",
        "pfi_credential_binding_mismatch",
    )?;
    for member in [
        "presentation_id",
        "presentation_sha256",
        "policy_event_id",
        "audience_pubkey",
        "challenge",
        "channel_ref",
    ] {
        pfi_hex_with_code(
            pfi_required_string(commitment, member, "pfi_credential_binding_mismatch")?,
            member,
            "pfi_credential_binding_mismatch",
        )?;
    }
    let requirements = pfi_string_array(
        commitment.get("requirement_ids"),
        1,
        16,
        "credential requirement ids",
        "pfi_credential_binding_mismatch",
    )?;
    for requirement in requirements {
        pfi_identifier(requirement, "credential requirement id", 128)?;
    }
    pfi_exact_string(
        commitment,
        "purpose",
        "mkt-pfi-order-qualification",
        "pfi_credential_binding_mismatch",
    )?;
    pfi_decimal_member(
        commitment,
        "expires_at",
        false,
        "pfi_credential_binding_mismatch",
    )?;
    pfi_exact_string(
        commitment,
        "transport",
        "direct-encrypted",
        "pfi_credential_binding_mismatch",
    )
}

fn validate_pfi_dispute(value: &Value) -> Result<(), String> {
    let dispute = pfi_object(value, "dispute", "pfi_policy_unknown_member")?;
    pfi_closed(
        dispute,
        &[
            "dispute_ref",
            "reason_code",
            "evidence_digests",
            "authority_refs",
            "opening_deadline",
            "response_deadline",
            "adjudication_deadline",
            "appeal_deadline",
        ],
        "dispute",
        "pfi_policy_unknown_member",
    )?;
    pfi_non_bearer_reference(
        pfi_required_string(dispute, "dispute_ref", "pfi_policy_unknown_member")?,
        "dispute reference",
    )?;
    pfi_identifier(
        pfi_required_string(dispute, "reason_code", "pfi_policy_unknown_member")?,
        "dispute reason code",
        128,
    )?;
    for digest in pfi_string_array(
        dispute.get("evidence_digests"),
        0,
        MKT_MAX_REFERENCES,
        "dispute evidence digests",
        "pfi_policy_unknown_member",
    )? {
        pfi_hex(digest, "dispute evidence digest")?;
    }
    for authority in pfi_string_array(
        dispute.get("authority_refs"),
        1,
        16,
        "dispute authority refs",
        "pfi_policy_unknown_member",
    )? {
        pfi_bounded_ascii(
            authority,
            "dispute authority ref",
            512,
            "pfi_policy_unknown_member",
        )?;
    }
    for member in [
        "opening_deadline",
        "response_deadline",
        "adjudication_deadline",
        "appeal_deadline",
    ] {
        if dispute.contains_key(member) {
            pfi_decimal_member(dispute, member, false, "pfi_policy_unknown_member")?;
        }
    }
    Ok(())
}

fn validate_pfi_recourse(value: &Value) -> Result<(), String> {
    if value.as_str() == Some("none") {
        return Ok(());
    }
    let recourse = pfi_object(value, "recourse", "pfi_policy_unknown_member")?;
    pfi_closed(
        recourse,
        &[
            "remedy",
            "authority_id",
            "terms_url",
            "terms_sha256",
            "deadline",
        ],
        "recourse",
        "pfi_policy_unknown_member",
    )?;
    require_enum(
        pfi_required_string(recourse, "remedy", "pfi_policy_unknown_member")?,
        &[
            "refund",
            "reperformance",
            "escrow_release",
            "guarantee_claim",
            "arbitration",
            "legal_claim",
        ],
        "MKT-PFI recourse remedy",
    )
    .map_err(|detail| pfi_error("pfi_policy_unknown_member", detail))?;
    pfi_bounded_ascii(
        pfi_required_string(recourse, "authority_id", "pfi_policy_unknown_member")?,
        "recourse authority",
        512,
        "pfi_policy_unknown_member",
    )?;
    pfi_public_url(
        pfi_required_string(recourse, "terms_url", "pfi_policy_unknown_member")?,
        "recourse terms",
    )?;
    pfi_hex(
        pfi_required_string(recourse, "terms_sha256", "pfi_policy_unknown_member")?,
        "recourse terms digest",
    )?;
    pfi_decimal_member(recourse, "deadline", false, "pfi_policy_unknown_member")?;
    Ok(())
}

fn validate_mkt_pfi_public_receipt_content(value: &Value) -> Result<(), String> {
    let receipt = pfi_object(value, "MKT-PFI public receipt", "pfi_public_pii_forbidden")?;
    pfi_closed(
        receipt,
        &["public_safe_evidence_reference"],
        "MKT-PFI public receipt",
        "pfi_public_pii_forbidden",
    )?;
    if let Some(reference) = receipt.get("public_safe_evidence_reference") {
        pfi_non_bearer_reference(
            reference.as_str().ok_or_else(|| {
                pfi_error(
                    "pfi_public_pii_forbidden",
                    "public-safe evidence reference must be a string",
                )
            })?,
            "public-safe evidence reference",
        )?;
    }
    Ok(())
}

fn validate_pfi_asset(value: &Value, fiat: bool) -> Result<&str, String> {
    let asset = pfi_object(value, "MKT-PFI asset", "pfi_invalid_asset_id")?;
    pfi_closed(
        asset,
        &[
            "asset_id",
            "atomic_unit_exponent",
            "unit_registry_ref",
            "unit_registry_digest",
        ],
        "MKT-PFI asset",
        "pfi_policy_unknown_member",
    )?;
    let asset_id = pfi_required_string(asset, "asset_id", "pfi_invalid_asset_id")?;
    if fiat {
        let code = asset_id.strip_prefix("iso4217:").unwrap_or_default();
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(pfi_error(
                "pfi_invalid_asset_id",
                "fiat asset id must be iso4217 followed by three uppercase letters",
            ));
        }
    } else {
        validate_pfi_caip19_asset_id(asset_id)?;
    }
    let exponent =
        pfi_decimal_member(asset, "atomic_unit_exponent", false, "pfi_invalid_asset_id")?;
    if exponent > 18 {
        return Err(pfi_error(
            "pfi_invalid_asset_id",
            "asset atomic_unit_exponent exceeds 18",
        ));
    }
    pfi_public_url(
        pfi_required_string(asset, "unit_registry_ref", "pfi_invalid_asset_id")?,
        "asset unit registry",
    )?;
    pfi_hex(
        pfi_required_string(asset, "unit_registry_digest", "pfi_invalid_asset_id")?,
        "asset unit registry digest",
    )?;
    Ok(asset_id)
}

fn validate_pfi_caip19_asset_id(value: &str) -> Result<(), String> {
    let value = value.strip_prefix("caip19:").ok_or_else(|| {
        pfi_error(
            "pfi_invalid_asset_id",
            "cryptographic asset id must use the caip19 prefix",
        )
    })?;
    let (chain, asset) = value.split_once('/').ok_or_else(|| {
        pfi_error(
            "pfi_invalid_asset_id",
            "CAIP-19 asset id requires chain and asset references",
        )
    })?;
    if asset.contains('/') {
        return Err(pfi_error(
            "pfi_invalid_asset_id",
            "CAIP-19 asset id has extra separators",
        ));
    }
    for (subject, component) in [("chain", chain), ("asset", asset)] {
        let (namespace, reference) = component.split_once(':').ok_or_else(|| {
            pfi_error(
                "pfi_invalid_asset_id",
                format!("CAIP-19 {subject} component is malformed"),
            )
        })?;
        if !(3..=8).contains(&namespace.len())
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || reference.is_empty()
            || reference.len() > 128
            || !reference.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'%')
            })
        {
            return Err(pfi_error(
                "pfi_invalid_asset_id",
                format!("CAIP-19 {subject} component is noncanonical"),
            ));
        }
    }
    Ok(())
}

fn validate_pfi_side(
    value: &Value,
    expected_pay_asset: &str,
    expected_receive_asset: &str,
    direction: &str,
) -> Result<bool, String> {
    let side = pfi_object(value, direction, "pfi_noncanonical_amount")?;
    pfi_closed(
        side,
        &["pay_asset_id", "receive_asset_id", "min", "max"],
        direction,
        "pfi_policy_unknown_member",
    )?;
    if pfi_required_string(side, "pay_asset_id", "pfi_invalid_asset_id")? != expected_pay_asset
        || pfi_required_string(side, "receive_asset_id", "pfi_invalid_asset_id")?
            != expected_receive_asset
    {
        return Err(pfi_error(
            "pfi_invalid_asset_id",
            format!("{direction} asset order is invalid"),
        ));
    }
    let minimum = pfi_decimal_member(side, "min", false, "pfi_noncanonical_amount")?;
    let maximum = pfi_decimal_member(side, "max", false, "pfi_noncanonical_amount")?;
    if maximum == 0 {
        if minimum != 0 {
            return Err(pfi_error(
                "pfi_side_disabled",
                format!("disabled {direction} requires min=0 and max=0"),
            ));
        }
        return Ok(false);
    }
    if minimum == 0 || minimum > maximum {
        return Err(pfi_error(
            "pfi_amount_out_of_range",
            format!("enabled {direction} requires 0 < min <= max"),
        ));
    }
    Ok(true)
}

fn validate_pfi_policy_tags(event: &Event, expected_event_id: &str) -> Result<(), String> {
    let addresses = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("a"))
        .collect::<Vec<_>>();
    if addresses.len() != 1
        || addresses[0].as_slice().len() != 4
        || addresses[0].as_slice().get(3).map(String::as_str) != Some("qualification-policy")
    {
        return Err(pfi_error(
            "pfi_policy_missing",
            "Offering requires one qualification-policy address reference",
        ));
    }
    let address = addresses[0]
        .as_slice()
        .get(1)
        .map(String::as_str)
        .unwrap_or_default();
    let mut parts = address.split(':');
    if parts.next() != Some("39630")
        || parts.next() != Some(event.pubkey.as_str())
        || pfi_identifier(
            parts.next().unwrap_or_default(),
            "qualification policy id",
            128,
        )
        .is_err()
        || parts.next().is_some()
    {
        return Err(pfi_error(
            "pfi_policy_missing",
            "Offering qualification-policy address is invalid",
        ));
    }
    let events = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("e"))
        .collect::<Vec<_>>();
    if events.len() != 1
        || events[0].as_slice().len() != 4
        || events[0].as_slice().get(1).map(String::as_str) != Some(expected_event_id)
        || events[0].as_slice().get(3).map(String::as_str) != Some("qualification-policy")
    {
        return Err(pfi_error(
            "pfi_policy_missing",
            "Offering requires the exact qualification-policy event reference",
        ));
    }
    Ok(())
}

fn validate_pfi_jurisdictions(value: Option<&Value>, subject: &str) -> Result<(), String> {
    let jurisdictions =
        pfi_string_array(value, 1, 32, "jurisdictions", "pfi_policy_unknown_member")?;
    for jurisdiction in jurisdictions {
        if jurisdiction.len() != 2 || !jurisdiction.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(pfi_error(
                "pfi_policy_unknown_member",
                format!("{subject} jurisdiction must be ISO 3166-1 alpha-2"),
            ));
        }
    }
    Ok(())
}

fn validate_pfi_custody_dimensions(value: &Value) -> Result<(), String> {
    let custody = pfi_object(value, "custody dimensions", "pfi_policy_unknown_member")?;
    pfi_closed(
        custody,
        &[
            "funds_control",
            "execution_control",
            "settlement_authority",
            "reversibility",
            "recourse",
            "credential_exposure",
        ],
        "custody dimensions",
        "pfi_policy_unknown_member",
    )?;
    for (member, expected) in [
        ("funds_control", "disclosed_in_quote"),
        ("execution_control", "provider_and_external_rails"),
        ("settlement_authority", "external_rails"),
        ("reversibility", "rail_specific"),
        ("recourse", "disclosed_in_quote"),
        ("credential_exposure", "post_quote_direct_encrypted"),
    ] {
        pfi_exact_string(custody, member, expected, "pfi_policy_unknown_member")?;
    }
    Ok(())
}

fn validate_pfi_risk_class(value: &str) -> Result<(), String> {
    require_enum(
        value,
        &[
            "atomic",
            "escrowed",
            "reserved",
            "guaranteed",
            "best-effort",
        ],
        "MKT-PFI risk classification",
    )
    .map_err(|detail| pfi_error("pfi_risk_classification_missing", detail))
}

fn reject_pfi_forbidden_material(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name
                    .bytes()
                    .filter(|byte| byte.is_ascii_alphanumeric())
                    .map(|byte| byte.to_ascii_lowercase() as char)
                    .collect::<String>();
                if matches!(
                    normalized.as_str(),
                    "name"
                        | "fullname"
                        | "dateofbirth"
                        | "dob"
                        | "address"
                        | "email"
                        | "phone"
                        | "phonenumber"
                        | "governmentidentifier"
                        | "governmentid"
                        | "credentialidentifier"
                        | "subjectdid"
                        | "account"
                        | "accountnumber"
                        | "bankaccount"
                        | "iban"
                        | "routingnumber"
                        | "sortcode"
                        | "walletaddress"
                        | "credential"
                        | "credentials"
                        | "credentialbytes"
                        | "credentialpresentation"
                        | "credentialpresentationbytes"
                        | "presentation"
                        | "presentationbytes"
                        | "presentationjwt"
                        | "verifiablepresentation"
                        | "vp"
                        | "vc"
                        | "sdjwt"
                        | "bankinstruction"
                        | "bankinstructions"
                        | "paymentinstruction"
                        | "paymentinstructions"
                        | "settlementendpoint"
                        | "disputenarrative"
                        | "userdecision"
                        | "qualificationdecision"
                        | "seed"
                        | "privatekey"
                        | "claimprivatekey"
                        | "refundprivatekey"
                        | "preimage"
                        | "macaroon"
                ) {
                    return Err(pfi_error(
                        "pfi_public_pii_forbidden",
                        format!("market record contains forbidden member {name:?}"),
                    ));
                }
                if matches!(
                    normalized.as_str(),
                    "accesstoken"
                        | "bearertoken"
                        | "cookie"
                        | "authorization"
                        | "authorizationheader"
                        | "retrievalsecret"
                        | "password"
                        | "capability"
                        | "credentialurl"
                        | "evidenceurl"
                ) {
                    return Err(pfi_error(
                        "pfi_bearer_reference_forbidden",
                        format!("market record contains bearer member {name:?}"),
                    ));
                }
                reject_pfi_forbidden_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_pfi_forbidden_material(child)?;
            }
        }
        Value::String(value) if pfi_value_is_bearer_shaped(value) => {
            return Err(pfi_error(
                "pfi_bearer_reference_forbidden",
                "market record contains a bearer-shaped value",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn pfi_value_is_bearer_shaped(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    if lowercase.starts_with("bearer ") {
        return true;
    }
    if lowercase.starts_with("nwc:")
        || lowercase.starts_with("xprv")
        || lowercase.starts_with("tprv")
    {
        return true;
    }
    let Some(rest) = lowercase.strip_prefix("https://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if rest[..authority_end].contains('@') || lowercase.contains('#') {
        return true;
    }
    lowercase
        .split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or_default())
        .is_some_and(|query| {
            query.split('&').any(|pair| {
                let name = pair.split('=').next().unwrap_or_default();
                name.contains("token")
                    || name.contains("secret")
                    || name.contains("auth")
                    || name.contains("cookie")
                    || name.contains("capability")
                    || name.ends_with("key")
            })
        })
}

fn pfi_public_url(value: &str, subject: &str) -> Result<(), String> {
    let rest = value.strip_prefix("https://").ok_or_else(|| {
        pfi_error(
            "pfi_bearer_reference_forbidden",
            format!("{subject} URL must use HTTPS"),
        )
    })?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if value.len() > 512
        || rest.is_empty()
        || rest[..authority_end].is_empty()
        || pfi_value_is_bearer_shaped(value)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(pfi_error(
            "pfi_bearer_reference_forbidden",
            format!("{subject} URL is unbounded or bearer-shaped"),
        ));
    }
    Ok(())
}

fn pfi_non_bearer_reference(value: &str, subject: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || value.contains("://")
        || pfi_value_is_bearer_shaped(value)
    {
        return Err(pfi_error(
            "pfi_bearer_reference_forbidden",
            format!("{subject} is unbounded or bearer-shaped"),
        ));
    }
    Ok(())
}

fn pfi_market_id(fiat_asset: &str, crypto_asset: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mkt-pfi-v1\0");
    hasher.update(fiat_asset.as_bytes());
    hasher.update(b"\0");
    hasher.update(crypto_asset.as_bytes());
    digest_hex(hasher.finalize().as_slice())
}

fn sha256_hex(value: &[u8]) -> String {
    digest_hex(Sha256::digest(value).as_slice())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(pfi_hex_digit(byte >> 4));
        output.push(pfi_hex_digit(byte & 0x0f));
    }
    output
}

fn pfi_hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + nibble - 10),
        _ => '?',
    }
}

fn pfi_two_element_tags<'a>(
    event: &'a Event,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<&'a str>, String> {
    let tags = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<_>>();
    if !(minimum..=maximum).contains(&tags.len())
        || tags.iter().any(|tag| tag.as_slice().len() != 2)
    {
        return Err(pfi_error(
            "pfi_policy_unknown_member",
            format!("MKT-PFI Offering requires {minimum}-{maximum} two-element {name} tags"),
        ));
    }
    Ok(tags.iter().filter_map(|tag| tag.value()).collect())
}

fn pfi_equal_unique_sets(left: &[&str], right: &[&str], subject: &str) -> Result<(), String> {
    let left_set = left.iter().copied().collect::<BTreeSet<_>>();
    let right_set = right.iter().copied().collect::<BTreeSet<_>>();
    if left_set != right_set || left_set.len() != left.len() || right_set.len() != right.len() {
        return Err(pfi_error(
            "pfi_policy_unknown_member",
            format!("{subject} must be equal and duplicate-free"),
        ));
    }
    Ok(())
}

fn pfi_closed(
    object: &Map<String, Value>,
    allowed: &[&str],
    subject: &str,
    code: &str,
) -> Result<(), String> {
    if let Some(member) = object
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        return Err(pfi_error(
            code,
            format!("{subject} contains unknown member {member:?}"),
        ));
    }
    Ok(())
}

fn pfi_object<'a>(
    value: &'a Value,
    subject: &str,
    code: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| pfi_error(code, format!("{subject} must be an object")))
}

fn pfi_required_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    code: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| pfi_error(code, format!("{name} must be a string")))
}

fn pfi_exact_string(
    object: &Map<String, Value>,
    name: &str,
    expected: &str,
    code: &str,
) -> Result<(), String> {
    if pfi_required_string(object, name, code)? != expected {
        return Err(pfi_error(code, format!("{name} is unsupported")));
    }
    Ok(())
}

fn pfi_decimal_member(
    object: &Map<String, Value>,
    name: &str,
    positive: bool,
    code: &str,
) -> Result<u64, String> {
    canonical_decimal(pfi_required_string(object, name, code)?, positive, name)
        .map_err(|detail| pfi_error(code, detail))
}

fn pfi_string_array<'a>(
    value: Option<&'a Value>,
    minimum: usize,
    maximum: usize,
    subject: &str,
    code: &str,
) -> Result<Vec<&'a str>, String> {
    let values = value
        .and_then(Value::as_array)
        .filter(|values| (minimum..=maximum).contains(&values.len()))
        .ok_or_else(|| {
            pfi_error(
                code,
                format!("{subject} must contain {minimum}-{maximum} strings"),
            )
        })?;
    let strings = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| pfi_error(code, format!("{subject} values must be strings")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if strings.iter().copied().collect::<BTreeSet<_>>().len() != strings.len() {
        return Err(pfi_error(code, format!("{subject} must be duplicate-free")));
    }
    Ok(strings)
}

fn pfi_identifier(value: &str, subject: &str, maximum: usize) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(pfi_error(
            "pfi_policy_unknown_member",
            format!("{subject} is not a bounded identifier"),
        ));
    }
    Ok(())
}

fn pfi_bounded_ascii(value: &str, subject: &str, maximum: usize, code: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(pfi_error(
            code,
            format!("{subject} is invalid or unbounded"),
        ));
    }
    Ok(())
}

fn pfi_hex(value: &str, subject: &str) -> Result<(), String> {
    pfi_hex_with_code(value, subject, "pfi_policy_unknown_member")
}

fn pfi_hex_with_code(value: &str, subject: &str, code: &str) -> Result<(), String> {
    lower_hex_32(value, subject).map_err(|detail| pfi_error(code, detail))
}

fn pfi_error(code: &str, detail: impl fmt::Display) -> String {
    format!("{code}: {detail}")
}

fn validate_mkt_swp_offering(event: &Event) -> Result<(), String> {
    let content = parse_unique_json(&event.content, "MKT-SWP Offering content")?;
    reject_swp_secret_material(&content)?;
    reject_swp_public_offering_material(&content)?;
    let body = content
        .as_object()
        .and_then(|body| body.get("mkt_swp"))
        .and_then(Value::as_object)
        .ok_or_else(|| swp_error("swp_terms_mismatch", "Offering requires an mkt_swp object"))?;

    let swap_types = swp_string_array(body, "swap_types", 1, 3)?;
    for swap_type in &swap_types {
        if !matches!(*swap_type, "submarine" | "reverse" | "chain") {
            return Err(swp_error("swp_invalid_pair", "unknown swap type"));
        }
    }

    let networks = swp_string_array(body, "networks", 1, 8)?;
    for network in &networks {
        validate_swp_network_id(network)?;
    }

    let script_modes = swp_string_array(body, "script_modes", 1, 8)?;
    if script_modes
        .iter()
        .any(|mode| *mode != "taproot-musig2-script-exit")
    {
        return Err(swp_error(
            "swp_unsupported_version",
            "MKT-SWP v1 supports only taproot-musig2-script-exit",
        ));
    }

    let reservation_classes = swp_string_array(body, "reservation_proof_classes", 1, 8)?;
    for proof_class in reservation_classes {
        if !matches!(
            proof_class,
            "provider_signed"
                | "handler_accounted"
                | "utxo_control"
                | "lightning_liquidity"
                | "funded_htlc"
                | "covenant_reserve"
                | "third_party_guarantee"
        ) {
            return Err(swp_error(
                "swp_reservation_proof_invalid",
                "unknown reservation proof class",
            ));
        }
    }

    let availability = body
        .get("availability")
        .and_then(Value::as_str)
        .ok_or_else(|| swp_error("swp_terms_mismatch", "Offering requires availability"))?;
    if !matches!(availability, "available" | "limited" | "unavailable") {
        return Err(swp_error("swp_terms_mismatch", "unknown availability"));
    }
    match body.get("evm_extension") {
        Some(Value::String(value)) if value == "unsupported" => {}
        _ => {
            return Err(swp_error(
                "swp_unsupported_extension",
                "MKT-SWP v1 requires evm_extension=unsupported",
            ));
        }
    }

    let sides = body
        .get("sides")
        .and_then(Value::as_array)
        .filter(|sides| (1..=16).contains(&sides.len()))
        .ok_or_else(|| swp_error("swp_invalid_pair", "Offering requires 1-16 sides"))?;
    let mut pairs = BTreeSet::new();
    for side in sides {
        let side = side
            .as_object()
            .ok_or_else(|| swp_error("swp_invalid_pair", "Offering side must be an object"))?;
        let input = swp_required_string(side, "input_asset_id", "swp_invalid_asset_id")?;
        let output = swp_required_string(side, "output_asset_id", "swp_invalid_asset_id")?;
        let (input_network, input_rail) = validate_swp_asset_id(input)?;
        let (output_network, output_rail) = validate_swp_asset_id(output)?;
        if !networks.contains(&input_network) || !networks.contains(&output_network) {
            return Err(swp_error(
                "swp_invalid_pair",
                "Offering side uses an unadvertised network",
            ));
        }
        let required_swap_type = match (input_rail, output_rail) {
            ("chain", "lightning") if input_network == output_network => "submarine",
            ("lightning", "chain") if input_network == output_network => "reverse",
            ("chain", "chain") if input_network != output_network => "chain",
            _ => {
                return Err(swp_error(
                    "swp_invalid_pair",
                    "Offering side has an unsupported ordered rail pair",
                ));
            }
        };
        if !swap_types.contains(&required_swap_type) {
            return Err(swp_error(
                "swp_invalid_pair",
                "Offering side swap type is not advertised",
            ));
        }
        if !pairs.insert((input, output)) {
            return Err(swp_error("swp_invalid_pair", "duplicate Offering side"));
        }
        let minimum = swp_decimal_member(side, "min", "swp_invalid_amount")?;
        let maximum = swp_decimal_member(side, "max", "swp_invalid_amount")?;
        if maximum == 0 {
            if minimum != 0 {
                return Err(swp_error(
                    "swp_side_disabled",
                    "a disabled side requires min=0 and max=0",
                ));
            }
        } else if minimum == 0 || minimum > maximum {
            return Err(swp_error(
                "swp_invalid_amount",
                "an enabled side requires 0 < min <= max",
            ));
        }
        let fee = swp_decimal_member(side, "fee_bps", "swp_invalid_fee")?;
        if fee > 10_000 {
            return Err(swp_error("swp_invalid_fee", "fee_bps exceeds 10000"));
        }
    }

    let policies = body
        .get("confirmation_policies")
        .and_then(Value::as_array)
        .filter(|policies| (1..=8).contains(&policies.len()))
        .ok_or_else(|| {
            swp_error(
                "swp_terms_mismatch",
                "Offering requires 1-8 confirmation policies",
            )
        })?;
    let mut policy_ids = BTreeSet::new();
    for policy in policies {
        let policy = policy.as_object().ok_or_else(|| {
            swp_error(
                "swp_terms_mismatch",
                "confirmation policy must be an object",
            )
        })?;
        let policy_id = swp_required_string(policy, "policy_id", "swp_terms_mismatch")?;
        validate_identifier(policy_id, "MKT-SWP confirmation policy id")
            .map_err(|detail| swp_error("swp_terms_mismatch", detail))?;
        if !policy_ids.insert(policy_id) {
            return Err(swp_error(
                "swp_terms_mismatch",
                "duplicate confirmation policy",
            ));
        }
        swp_decimal_member(policy, "minimum_confirmations", "swp_terms_mismatch")?;
        swp_decimal_member(policy, "reorg_safety_blocks", "swp_terms_mismatch")?;
        swp_policy_enum(policy, "zero_confirmation", &["forbidden", "allowed"])?;
        swp_policy_enum(policy, "rbf", &["reject", "track"])?;
        swp_policy_enum(policy, "replacement", &["reject", "track"])?;
    }
    Ok(())
}

fn validate_mkt_swp_visible_private(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    reject_swp_secret_material(&Value::Object(envelope.body.clone()))?;
    let profile = envelope
        .body
        .get("mkt_swp")
        .and_then(Value::as_object)
        .ok_or_else(|| swp_error("swp_terms_mismatch", "record requires an mkt_swp object"))?;
    validate_swp_evidence_members(&Value::Object(profile.clone()))?;
    if event.kind != MKT_SWP_SWAP_CONTRACT_KIND {
        return Ok(());
    }

    if event
        .tags
        .iter()
        .any(|tag| tag.name() == Some("expiration"))
    {
        return Err(swp_error(
            "swp_contract_terms_mismatch",
            "Swap Contract must not expire",
        ));
    }
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .count();
    if counterparties != 1 {
        return Err(swp_error(
            "swp_contract_signer_invalid",
            "Swap Contract requires exactly one counterparty",
        ));
    }
    let role = single_value(event, "role", "MKT-SWP Swap Contract")?;
    if !matches!(role, "requester" | "provider") {
        return Err(swp_error(
            "swp_contract_signer_invalid",
            "Swap Contract role is invalid",
        ));
    }
    let counterparty = event
        .tags
        .iter()
        .find(|tag| tag.name() == Some("p"))
        .map(Tag::as_slice)
        .ok_or_else(|| {
            swp_error(
                "swp_contract_signer_invalid",
                "Swap Contract counterparty is missing",
            )
        })?;
    let counterparty_pubkey = counterparty.get(1).map(String::as_str).unwrap_or_default();
    let counterparty_role = counterparty.get(3).map(String::as_str).unwrap_or_default();
    let expected_counterparty_role = if role == "requester" {
        "provider"
    } else {
        "requester"
    };
    if counterparty_pubkey == event.pubkey || counterparty_role != expected_counterparty_role {
        return Err(swp_error(
            "swp_contract_signer_invalid",
            "Swap Contract requires a distinct counterparty with the complementary role",
        ));
    }
    let signer_role = profile
        .get("signer_role")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            swp_error(
                "swp_contract_signer_invalid",
                "Swap Contract requires signer_role",
            )
        })?;
    if signer_role != role {
        return Err(swp_error(
            "swp_contract_signer_invalid",
            "Swap Contract tag and content roles differ",
        ));
    }
    let digest = single_value(event, "x", "MKT-SWP Swap Contract")?;
    lower_hex_32(digest, "MKT-SWP contract digest")?;
    let content_digest = profile
        .get("contract_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            swp_error(
                "swp_contract_digest_mismatch",
                "Swap Contract requires contract_sha256",
            )
        })?;
    if digest != content_digest
        || decode_lower_hex::<32>(content_digest, "contract digest").is_err()
    {
        return Err(swp_error(
            "swp_contract_digest_mismatch",
            "Swap Contract x and content digest differ",
        ));
    }
    let contract = profile
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            swp_error(
                "swp_contract_terms_mismatch",
                "Swap Contract requires a contract object",
            )
        })?;
    if !matches!(contract.get("evm_leg"), None | Some(Value::Null)) {
        return Err(swp_error(
            "swp_unsupported_extension",
            "MKT-SWP v1 contract evm_leg must be absent or null",
        ));
    }
    let mut order = 0;
    let mut quote = 0;
    let mut status = 0;
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        match tag.as_slice().get(3).map(String::as_str) {
            Some("order") => order += 1,
            Some("quote") => quote += 1,
            Some("status") => status += 1,
            _ => {
                return Err(swp_error(
                    "swp_contract_terms_mismatch",
                    "Swap Contract has an unsupported event reference",
                ));
            }
        }
    }
    if order != 1 || quote != 1 || status > 1 {
        return Err(swp_error(
            "swp_contract_terms_mismatch",
            "Swap Contract requires one Order, one Quote, and at most one accepted Status",
        ));
    }
    Ok(())
}

pub fn validate_mkt_swp_evidence_reference(value: &Value) -> Result<(), String> {
    let evidence = value
        .as_object()
        .ok_or_else(|| swp_error("swp_evidence_mismatch", "evidence must be an object"))?;
    let class = swp_required_string(evidence, "class", "swp_evidence_mismatch")?;
    if !matches!(
        class,
        "invoice"
            | "lightning_htlc"
            | "lightning_payment"
            | "bitcoin_transaction"
            | "bitcoin_output"
            | "bitcoin_spend"
            | "reservation"
            | "covenant_reserve"
            | "claim"
            | "refund"
            | "reorg"
            | "replacement"
    ) {
        return Err(swp_error("swp_evidence_mismatch", "unknown evidence class"));
    }
    let rung = swp_required_string(evidence, "rung", "swp_evidence_mismatch")?;
    if !matches!(
        rung,
        "pledged" | "reserved" | "measured" | "verified" | "paid" | "settled"
    ) {
        return Err(swp_error(
            "swp_settlement_overclaim",
            "unknown evidence rung",
        ));
    }
    let rail = swp_required_string(evidence, "rail", "swp_evidence_mismatch")?;
    validate_identifier(rail, "MKT-SWP evidence rail")
        .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?;
    let reference = swp_required_string(evidence, "reference", "swp_evidence_mismatch")?;
    if reference.is_empty()
        || reference.len() > 512
        || reference.chars().any(char::is_control)
        || reference.contains("://") && (reference.contains('@') || reference.contains('?'))
    {
        return Err(swp_error(
            "swp_privacy_violation",
            "evidence reference is empty, unbounded, or bearer-shaped",
        ));
    }
    validate_swp_evidence_rail_reference(class, rail, reference)?;
    for member in ["artifact_sha256", "producer_pubkey"] {
        lower_hex_32(
            swp_required_string(evidence, member, "swp_evidence_mismatch")?,
            "MKT-SWP evidence digest or key",
        )
        .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?;
    }
    match evidence.get("verifier_pubkey") {
        Some(Value::Null) => {}
        Some(Value::String(value)) => lower_hex_32(value, "MKT-SWP verifier pubkey")
            .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?,
        _ => {
            return Err(swp_error(
                "swp_evidence_mismatch",
                "verifier_pubkey must be a pubkey or null",
            ));
        }
    }
    match evidence.get("verifier_policy") {
        Some(Value::Null) => {}
        Some(Value::String(value)) => validate_identifier(value, "MKT-SWP verifier policy")
            .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?,
        _ => {
            return Err(swp_error(
                "swp_evidence_mismatch",
                "verifier_policy must be an identifier or null",
            ));
        }
    }
    if evidence
        .get("observed_at")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(swp_error(
            "swp_evidence_mismatch",
            "observed_at must be an unsigned integer",
        ));
    }
    let view = swp_required_string(evidence, "view", "swp_evidence_mismatch")?;
    if view.is_empty() || view.len() > 512 || view.chars().any(char::is_control) {
        return Err(swp_error(
            "swp_evidence_mismatch",
            "evidence view is invalid",
        ));
    }
    Ok(())
}

fn validate_swp_evidence_rail_reference(
    class: &str,
    rail: &str,
    reference: &str,
) -> Result<(), String> {
    let expected_rail = match class {
        "invoice" | "lightning_htlc" | "lightning_payment" => Some("lightning"),
        "bitcoin_transaction"
        | "bitcoin_output"
        | "bitcoin_spend"
        | "covenant_reserve"
        | "claim"
        | "refund"
        | "reorg"
        | "replacement" => Some("bitcoin"),
        "reservation" => None,
        _ => None,
    };
    if expected_rail.is_some_and(|expected| rail != expected) {
        return Err(swp_error(
            "swp_evidence_mismatch",
            "evidence class and rail are incompatible",
        ));
    }
    match class {
        "invoice"
        | "lightning_htlc"
        | "lightning_payment"
        | "bitcoin_transaction"
        | "claim"
        | "refund" => lower_hex_32(reference, "MKT-SWP evidence reference")
            .map_err(|detail| swp_error("swp_evidence_mismatch", detail)),
        "bitcoin_output" | "bitcoin_spend" => {
            let (transaction_id, output_index) = reference.split_once(':').ok_or_else(|| {
                swp_error(
                    "swp_evidence_mismatch",
                    "Bitcoin output evidence requires txid:vout",
                )
            })?;
            if output_index.contains(':') {
                return Err(swp_error(
                    "swp_evidence_mismatch",
                    "Bitcoin output evidence requires one vout",
                ));
            }
            lower_hex_32(transaction_id, "MKT-SWP evidence transaction id")
                .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?;
            let output_index = canonical_decimal(output_index, false, "evidence vout")
                .map_err(|detail| swp_error("swp_evidence_mismatch", detail))?;
            if output_index > u64::from(u32::MAX) {
                return Err(swp_error(
                    "swp_evidence_mismatch",
                    "Bitcoin evidence vout exceeds u32",
                ));
            }
            Ok(())
        }
        "reservation" | "covenant_reserve" | "reorg" | "replacement" => Ok(()),
        _ => Err(swp_error("swp_evidence_mismatch", "unknown evidence class")),
    }
}

fn validate_swp_evidence_members(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                if name == "evidence_refs" {
                    let references = child.as_array().ok_or_else(|| {
                        swp_error("swp_evidence_mismatch", "evidence_refs must be an array")
                    })?;
                    if references.len() > MKT_MAX_REFERENCES {
                        return Err(swp_error(
                            "swp_evidence_mismatch",
                            "too many evidence references",
                        ));
                    }
                    for reference in references {
                        validate_mkt_swp_evidence_reference(reference)?;
                    }
                } else {
                    validate_swp_evidence_members(child)?;
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_swp_evidence_members(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_swp_secret_material(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "seed"
                        | "private_key"
                        | "claim_private_key"
                        | "refund_private_key"
                        | "preimage"
                        | "macaroon"
                        | "nwc"
                        | "nwc_string"
                        | "musig_secret_nonce"
                        | "signing_nonce"
                ) {
                    return Err(swp_error(
                        "swp_secret_material_forbidden",
                        format!("forbidden custody member {name:?}"),
                    ));
                }
                reject_swp_secret_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_swp_secret_material(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_swp_public_offering_material(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "live_inventory"
                        | "inventory"
                        | "utxo"
                        | "utxos"
                        | "channel_balance"
                        | "channel_balances"
                        | "invoice"
                        | "invoices"
                        | "address"
                        | "addresses"
                        | "script"
                        | "scripts"
                        | "payment_hash"
                        | "payment_hashes"
                        | "reserve_witness"
                        | "reserve_witnesses"
                ) {
                    return Err(swp_error(
                        "swp_privacy_violation",
                        format!("public Offering contains private member {name:?}"),
                    ));
                }
                reject_swp_public_offering_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_swp_public_offering_material(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_swp_public_receipt_material(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "session_id"
                        | "counterparty"
                        | "counterparties"
                        | "amount"
                        | "input_amount"
                        | "output_amount"
                        | "asset_pair"
                        | "input_asset_id"
                        | "output_asset_id"
                        | "route"
                        | "transaction_id"
                        | "txid"
                        | "timing_ladder"
                        | "evidence"
                        | "evidence_refs"
                ) {
                    return Err(swp_error(
                        "swp_privacy_violation",
                        format!("public receipt contains private member {name:?}"),
                    ));
                }
                reject_swp_public_receipt_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_swp_public_receipt_material(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn swp_string_array<'a>(
    body: &'a Map<String, Value>,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<&'a str>, String> {
    let values = body
        .get(name)
        .and_then(Value::as_array)
        .filter(|values| (minimum..=maximum).contains(&values.len()))
        .ok_or_else(|| {
            swp_error(
                "swp_terms_mismatch",
                format!("{name} must contain {minimum}-{maximum} values"),
            )
        })?;
    let values = values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                swp_error(
                    "swp_terms_mismatch",
                    format!("{name} values must be strings"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let unique = values.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(swp_error(
            "swp_terms_mismatch",
            format!("{name} must be duplicate-free"),
        ));
    }
    Ok(values)
}

fn swp_required_string<'a>(
    body: &'a Map<String, Value>,
    name: &str,
    code: &str,
) -> Result<&'a str, String> {
    body.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| swp_error(code, format!("{name} must be a string")))
}

fn swp_decimal_member(body: &Map<String, Value>, name: &str, code: &str) -> Result<u64, String> {
    let value = swp_required_string(body, name, code)?;
    canonical_decimal(value, false, name).map_err(|detail| swp_error(code, detail))
}

fn swp_policy_enum(
    policy: &Map<String, Value>,
    name: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let value = swp_required_string(policy, name, "swp_terms_mismatch")?;
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(swp_error(
            "swp_terms_mismatch",
            format!("unknown confirmation policy {name}"),
        ))
    }
}

fn validate_swp_network_id(value: &str) -> Result<(), String> {
    let Some(reference) = value.strip_prefix("bip122:") else {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "network ID must use bip122",
        ));
    };
    if reference.len() != 32
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "network ID has an invalid BIP-122 reference",
        ));
    }
    Ok(())
}

fn validate_swp_asset_id(value: &str) -> Result<(&str, &str), String> {
    let Some(value) = value.strip_prefix("swp:1:") else {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "asset ID has the wrong profile",
        ));
    };
    let Some((network, rail)) = value.rsplit_once(":btc:") else {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "asset ID has the wrong shape",
        ));
    };
    validate_swp_network_id(network)?;
    if !matches!(rail, "chain" | "lightning") {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "asset ID has an unknown rail",
        ));
    }
    Ok((network, rail))
}

fn swp_error(code: &str, detail: impl fmt::Display) -> String {
    format!("{code}: {detail}")
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

fn validate_references(
    event: &Event,
    profile_id: &str,
    profile_version: u64,
) -> Result<(), String> {
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        let values = tag.as_slice();
        let marker = values.get(3).map(String::as_str).unwrap_or_default();
        let common_marker = matches!(
            marker,
            "rfq"
                | "quote"
                | "order"
                | "previous"
                | "status"
                | "cancel"
                | "close"
                | "evidence"
                | "settlement"
        );
        let swp_contract_marker = marker == "contract"
            && profile_id == MKT_SWP_PROFILE_ID
            && profile_version == MKT_SWP_PROFILE_VERSION;
        let swp_cancel_marker = matches!(marker, "cancel-request" | "cancel-accept")
            && profile_id == MKT_SWP_PROFILE_ID
            && profile_version == MKT_SWP_PROFILE_VERSION;
        if values.len() < 4 || !(common_marker || swp_contract_marker || swp_cancel_marker) {
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
