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
pub const MKT_SWP_SWAP_CONTRACT_KIND: u16 = 39_610;
pub const MKT_SWP_PROFILE_ID: &str = "mkt-swp";
pub const MKT_SWP_PROFILE_VERSION: u64 = 1;
pub const MKT_EXECUTABLE_PROFILES: &[(&str, u64)] = &[];
pub const MKT_RELAY_PROFILES: &[(&str, u64)] = &[(MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION)];

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
    }
    Ok(())
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
        if values.len() < 4 || !(common_marker || swp_contract_marker) {
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
