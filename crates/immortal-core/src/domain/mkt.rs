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
pub const MKT_MINT_ROUTE_CONTRACT_KIND: u16 = 39_640;
pub const MKT_MINT_PROFILE_ID: &str = "mkt-mint";
pub const MKT_MINT_PROFILE_VERSION: u64 = 1;
// MKT-P2P v1 (nips/openagents/MKT-P2P.md) relay-observable adoption.
pub const MKT_P2P_RESOLUTION_KIND: u16 = 39_620;
pub const MKT_P2P_PROFILE_ID: &str = "mkt-p2p";
pub const MKT_P2P_PROFILE_VERSION: u64 = 1;
pub const MKT_P2P_CUSTODY_CLASS: &str = "a1-coordinated-hold";
pub const MKT_P2P_RESOLUTION_ALT: &str = "MKT-P2P resolution";
pub const MKT_P2P_SOURCE_PROTOCOL: &str = "nip-69-mostro";
pub const MKT_P2P_SOURCE_MAPPING_VERSION: &str = "mkt-p2p-v1";
pub const MKT_P2P_AMOUNT_MODES: &[&str] = &["fixed", "range", "both"];
pub const MKT_P2P_RECIPIENT_ROLES: &[&str] =
    &["maker", "taker", "coordinator", "solver", "appeal-arbiter"];
pub const MKT_P2P_RESOLUTION_ROLES: &[&str] = &["solver", "appeal-arbiter"];
pub const MKT_P2P_RESOLUTION_DECISIONS: &[&str] = &[
    "release-to-buyer",
    "refund-to-seller",
    "cooperative-cancel",
    "slash-maker-bond",
    "slash-taker-bond",
    "dismissed",
    "unresolved",
];
pub const MKT_P2P_RESOLUTION_SCOPES: &[&str] = &["principal", "bond", "both"];
pub const MKT_P2P_EVIDENCE_PROVENANCE: &[&str] = &[
    "pledged", "observed", "verified", "paid", "refunded", "settled",
];
pub const MKT_P2P_STATUS_BASE_STATES: &[&str] =
    &["accepted", "settlement_pending", "completed", "disputed"];
pub const MKT_P2P_STATUS_EXTENSION_STATES: &[&str] = &[
    "bond-required",
    "bond-locked",
    "seller-funding-required",
    "seller-funding-locked",
    "fiat-payment-pending",
    "fiat-sent",
    "release-pending",
    "solver-pending",
    "solver-taken",
    "appeal-pending",
];
// MKT-LSP v1 (nips/openagents/MKT-LSP.md) relay-observable adoption.
pub const MKT_LSP_SERVICE_CONTRACT_KIND: u16 = 39_650;
pub const MKT_LSP_PROFILE_ID: &str = "mkt-lsp";
pub const MKT_LSP_PROFILE_VERSION: u64 = 1;
pub const MKT_LSP_CUSTODY_CLASS: &str = "a1-coordinated-hold";
pub const MKT_LSP_SERVICE_CONTRACT_ALT: &str = "MKT-LSP service contract";
pub const MKT_LSP_SOURCE_MAPPING_VERSION: &str = "mkt-lsp-v1";
pub const MKT_LSP_SOURCE_PROTOCOLS: &[&str] = &["lsps0", "lsps1", "lsps2"];
pub const MKT_LSP_SIDES: &[&str] = &["channel-purchase", "jit-inbound"];
pub const MKT_LSP_PAYMENT_METHODS: &[&str] = &["bolt11", "bolt12", "onchain"];
pub const MKT_LSP_ZERO_CONF_POLICIES: &[&str] = &["unsupported", "client-policy"];
pub const MKT_LSP_RESERVATION_PROOF_CLASSES: &[&str] = &[
    "provider-signed",
    "channel-slot",
    "funding-input-commitment",
    "funding-output-observed",
    "covenant-reserve",
];
pub const MKT_LSP_HARD_RESERVATION_PROOF_CLASSES: &[&str] = &[
    "funding-input-commitment",
    "funding-output-observed",
    "covenant-reserve",
];
pub const MKT_LSP_STATUS_BASE_STATES: &[&str] = &["accepted", "completed", "refunded", "failed"];
pub const MKT_LSP_STATUS_EXTENSION_STATES: &[&str] = &[
    "reservation-held",
    "fee-parameters-pinned",
    "jit-route-issued",
    "service-contract-pending",
    "service-contract-bound",
    "payment-required",
    "payment-observed",
    "incoming-htlc-observed",
    "funding-pending",
    "funding-output-observed",
    "channel-ready",
    "jit-forward-committed",
    "jit-payment-settled",
    "usable",
];
pub const MKT_EXECUTABLE_PROFILES: &[(&str, u64)] = &[];
pub const MKT_RELAY_PROFILES: &[(&str, u64)] = &[
    (MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION),
    (MKT_PFI_PROFILE_ID, MKT_PFI_PROFILE_VERSION),
    (MKT_MINT_PROFILE_ID, MKT_MINT_PROFILE_VERSION),
    (MKT_P2P_PROFILE_ID, MKT_P2P_PROFILE_VERSION),
    (MKT_LSP_PROFILE_ID, MKT_LSP_PROFILE_VERSION),
];
pub const MKT_MINT_RAILS: &[&str] = &["cashu", "fedimint"];
pub const MKT_MINT_CUSTODY_CLASSES: &[(&str, &str)] =
    &[("cashu", "a3-mint"), ("fedimint", "a2-federation")];
pub const MKT_MINT_OPERATIONS_CASHU: &[&str] = &["mint", "melt"];
pub const MKT_MINT_OPERATIONS_FEDIMINT: &[&str] = &["withdraw-lightning", "withdraw-onchain"];
pub const MKT_MINT_CREDENTIAL_BURDENS: &[&str] = &[
    "none",
    "access-token",
    "membership-proof",
    "external-policy",
];
pub const MKT_MINT_GATEWAY_POLICIES: &[&str] =
    &["fixed", "requester-selectable", "federation-selected"];
pub const MKT_MINT_EVIDENCE_PROVENANCE: &[&str] = &[
    "pledged", "observed", "verified", "paid", "issued", "refunded", "settled",
];
pub const MKT_MINT_STATUS_EXTENSIONS: &[&str] = &[
    "quote-issued",
    "route-contract-pending",
    "route-contract-bound",
    "issuance-pending",
    "proofs-issued",
    "wallet-verified",
    "payment-required",
    "payment-observed",
    "proofs-submitted-to-mint",
    "melt-paid",
    "change-verified",
    "federation-contract-pending",
    "federation-contract-accepted",
    "gateway-pending",
    "external-settlement-pending",
    "withdrawal-verified",
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
    raw_signed_event: Vec<u8>,
    event: Event,
    envelope: MktPrivateEnvelope,
}

impl MktValidatedPrivateRecord {
    pub fn raw_signed_event(&self) -> &[u8] {
        &self.raw_signed_event
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn envelope(&self) -> &MktPrivateEnvelope {
        &self.envelope
    }
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
    if event.kind == MKT_P2P_RESOLUTION_KIND {
        if *profile_id != MKT_P2P_PROFILE_ID {
            return Err(p2p_error(
                "mkt_p2p_invalid_resolution",
                "kind 39620 requires profile mkt-p2p",
            ));
        }
        if *profile_version != MKT_P2P_PROFILE_VERSION {
            return Err(p2p_error(
                "mkt_p2p_unsupported_version",
                "kind 39620 requires MKT-P2P version 1",
            ));
        }
    }
    if event.kind == MKT_MINT_ROUTE_CONTRACT_KIND {
        if *profile_id != MKT_MINT_PROFILE_ID {
            return Err(mint_error(
                "mkt_mint_unsupported_profile",
                "kind 39640 requires profile mkt-mint",
            ));
        }
        if *profile_version != MKT_MINT_PROFILE_VERSION {
            return Err(mint_error(
                "mkt_mint_unsupported_version",
                "kind 39640 requires MKT-MINT version 1",
            ));
        }
    }
    if event.kind == MKT_LSP_SERVICE_CONTRACT_KIND {
        if *profile_id != MKT_LSP_PROFILE_ID {
            return Err(lsp_error(
                "mkt_lsp_unsupported_version",
                "kind 39650 requires profile mkt-lsp",
            ));
        }
        if *profile_version != MKT_LSP_PROFILE_VERSION {
            return Err(lsp_error(
                "mkt_lsp_unsupported_version",
                "kind 39650 requires MKT-LSP version 1",
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
    if envelope.profile_id == MKT_MINT_PROFILE_ID
        && envelope.profile_version == MKT_MINT_PROFILE_VERSION
    {
        validate_mkt_mint_visible_private(event, &envelope)
            .map_err(|detail| validation_error(MktValidationCode::TagGrammar, detail))?;
    }
    if envelope.profile_id == MKT_P2P_PROFILE_ID
        && envelope.profile_version == MKT_P2P_PROFILE_VERSION
    {
        validate_mkt_p2p_visible_private(event, &envelope)
            .map_err(|detail| validation_error(MktValidationCode::TagGrammar, detail))?;
    }
    if envelope.profile_id == MKT_LSP_PROFILE_ID
        && envelope.profile_version == MKT_LSP_PROFILE_VERSION
    {
        validate_mkt_lsp_visible_private(event, &envelope)
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
    let code = if detail.starts_with("swp_unsupported_profile")
        || detail.starts_with("mkt_mint_unsupported_profile")
        || detail.contains("kind 39620 requires profile mkt-p2p")
        || detail.contains("kind 39650 requires profile mkt-lsp")
    {
        MktValidationCode::UnsupportedProfile
    } else if detail.starts_with("swp_unsupported_version")
        || detail.starts_with("mkt_mint_unsupported_version")
        || detail.starts_with("mkt_p2p_unsupported_version")
        || detail.contains("kind 39650 requires MKT-LSP version 1")
    {
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
            | MKT_P2P_RESOLUTION_KIND
            | MKT_MINT_ROUTE_CONTRACT_KIND
            | MKT_LSP_SERVICE_CONTRACT_KIND
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
    } else if profiles[0].0 == MKT_MINT_PROFILE_ID {
        if profiles[0].1 != MKT_MINT_PROFILE_VERSION {
            return Err(mint_error(
                "mkt_mint_unsupported_version",
                "only MKT-MINT profile version 1 is relay-observable",
            ));
        }
        validate_mkt_mint_offering(event)?;
    } else if profiles[0].0 == MKT_P2P_PROFILE_ID {
        if profiles[0].1 != MKT_P2P_PROFILE_VERSION {
            return Err(p2p_error(
                "mkt_p2p_unsupported_version",
                "only MKT-P2P profile version 1 is relay-observable",
            ));
        }
        validate_mkt_p2p_offering(event)?;
    } else if profiles[0].0 == MKT_LSP_PROFILE_ID {
        if profiles[0].1 != MKT_LSP_PROFILE_VERSION {
            return Err(lsp_error(
                "mkt_lsp_unsupported_version",
                "only MKT-LSP profile version 1 is relay-observable",
            ));
        }
        validate_mkt_lsp_offering(event)?;
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
    } else if profiles[0].0 == MKT_MINT_PROFILE_ID {
        if profiles[0].1 != MKT_MINT_PROFILE_VERSION {
            return Err(mint_error(
                "mkt_mint_unsupported_version",
                "only MKT-MINT profile version 1 is relay-observable",
            ));
        }
        let content = parse_unique_json(&event.content, "MKT-MINT public receipt content")?;
        reject_mint_public_material(&content)?;
    } else if profiles[0].0 == MKT_P2P_PROFILE_ID {
        if profiles[0].1 != MKT_P2P_PROFILE_VERSION {
            return Err(p2p_error(
                "mkt_p2p_unsupported_version",
                "only MKT-P2P profile version 1 is relay-observable",
            ));
        }
        let content = parse_unique_json(&event.content, "MKT-P2P public receipt content")?;
        reject_p2p_public_private_material(&content)?;
        reject_p2p_public_receipt_material(&content)?;
    } else if profiles[0].0 == MKT_LSP_PROFILE_ID {
        if profiles[0].1 != MKT_LSP_PROFILE_VERSION {
            return Err(lsp_error(
                "mkt_lsp_unsupported_version",
                "only MKT-LSP profile version 1 is relay-observable",
            ));
        }
        let content = parse_unique_json(&event.content, "MKT-LSP public receipt content")?;
        reject_lsp_public_material(&content)?;
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

// ---------------------------------------------------------------------------
// MKT-MINT v1 relay-observable validation (nips/openagents/MKT-MINT.md).
// Official NIP-87 stays the discovery authority, the Cashu NUTs and Fedimint
// protocols stay the rail authority, and the relay validates only shapes,
// cross-reference grammar, custody disclosure, and forbidden material.
// ---------------------------------------------------------------------------

fn validate_mkt_mint_offering(event: &Event) -> Result<(), String> {
    let content = parse_unique_json(&event.content, "MKT-MINT Offering content")?;
    reject_mint_public_material(&content)?;
    let body = pfi_object(&content, "MKT-MINT Offering", "mkt_mint_invalid_market")?;
    pfi_closed(
        body,
        &["schema", "profile", "profile_version", "mkt_mint"],
        "MKT-MINT Offering",
        "mkt_mint_invalid_market",
    )?;
    pfi_exact_string(
        body,
        "schema",
        MKT_ENVELOPE_SCHEMA,
        "mkt_mint_invalid_market",
    )?;
    pfi_exact_string(
        body,
        "profile",
        MKT_MINT_PROFILE_ID,
        "mkt_mint_invalid_market",
    )?;
    if body.get("profile_version").and_then(Value::as_u64) != Some(MKT_MINT_PROFILE_VERSION) {
        return Err(mint_error(
            "mkt_mint_unsupported_version",
            "MKT-MINT Offering content requires profile_version 1",
        ));
    }
    let mint = pfi_object(
        body.get("mkt_mint")
            .ok_or_else(|| mint_error("mkt_mint_invalid_market", "mkt_mint object is required"))?,
        "MKT-MINT Offering mkt_mint",
        "mkt_mint_invalid_market",
    )?;
    pfi_closed(
        mint,
        &[
            "nip87_ref",
            "rail",
            "market",
            "sides",
            "operations",
            "protocol_revisions",
            "custody_class",
            "credential_burden",
            "gateway_policy",
        ],
        "MKT-MINT Offering mkt_mint",
        "mkt_mint_invalid_market",
    )?;
    let rail = pfi_required_string(mint, "rail", "mkt_mint_invalid_market")?;
    if !MKT_MINT_RAILS.contains(&rail) {
        return Err(mint_error(
            "mkt_mint_invalid_market",
            "rail must be cashu or fedimint",
        ));
    }
    validate_mint_nip87_reference(mint.get("nip87_ref"), rail)?;
    validate_mint_market(mint.get("market"))?;
    let operations = validate_mint_operations(mint.get("operations"), rail)?;
    validate_mint_sides(mint.get("sides"), rail, &operations)?;
    validate_mint_protocol_revisions(mint.get("protocol_revisions"))?;
    validate_mint_custody_class_value(
        pfi_required_string(
            mint,
            "custody_class",
            "mkt_mint_custody_disclosure_mismatch",
        )?,
        Some(rail),
    )?;
    require_enum(
        pfi_required_string(mint, "credential_burden", "mkt_mint_invalid_market")?,
        MKT_MINT_CREDENTIAL_BURDENS,
        "MKT-MINT credential burden",
    )
    .map_err(|detail| mint_error("mkt_mint_invalid_market", detail))?;
    require_enum(
        pfi_required_string(mint, "gateway_policy", "mkt_mint_invalid_market")?,
        MKT_MINT_GATEWAY_POLICIES,
        "MKT-MINT gateway policy",
    )
    .map_err(|detail| mint_error("mkt_mint_invalid_market", detail))?;
    Ok(())
}

fn validate_mint_nip87_reference(value: Option<&Value>, rail: &str) -> Result<(), String> {
    let reference = pfi_object(
        value.ok_or_else(|| {
            mint_error(
                "mkt_mint_invalid_nip87_reference",
                "nip87_ref is required; NIP-87 owns mint and federation discovery",
            )
        })?,
        "MKT-MINT nip87_ref",
        "mkt_mint_invalid_nip87_reference",
    )?;
    pfi_closed(
        reference,
        &["kind", "address", "event_id", "relays"],
        "MKT-MINT nip87_ref",
        "mkt_mint_invalid_nip87_reference",
    )?;
    let expected_kind = if rail == "cashu" { "38172" } else { "38173" };
    let kind = pfi_required_string(reference, "kind", "mkt_mint_invalid_nip87_reference")?;
    if kind == "38000" {
        return Err(mint_error(
            "mkt_mint_invalid_nip87_reference",
            "a kind-38000 recommendation is a user claim and cannot replace the announcement",
        ));
    }
    if kind != expected_kind {
        return Err(mint_error(
            "mkt_mint_invalid_nip87_reference",
            format!("a {rail} route requires the exact kind-{expected_kind} announcement"),
        ));
    }
    let address = pfi_required_string(reference, "address", "mkt_mint_invalid_nip87_reference")?;
    let mut parts = address.split(':');
    let address_kind = parts.next().unwrap_or_default();
    let address_pubkey = parts.next().unwrap_or_default();
    let address_identifier = parts.next().unwrap_or_default();
    if address_kind != expected_kind
        || lower_hex_32(address_pubkey, "NIP-87 announcement pubkey").is_err()
        || address_identifier.is_empty()
        || address_identifier.len() > 128
        || !address_identifier.is_ascii()
        || address_identifier
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || parts.next().is_some()
    {
        return Err(mint_error(
            "mkt_mint_invalid_nip87_reference",
            "nip87_ref address must be the exact kind:pubkey:identifier announcement address",
        ));
    }
    pfi_hex_with_code(
        pfi_required_string(reference, "event_id", "mkt_mint_invalid_nip87_reference")?,
        "NIP-87 announcement event id",
        "mkt_mint_invalid_nip87_reference",
    )?;
    let relays = reference
        .get("relays")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= MKT_MAX_HINTS)
        .ok_or_else(|| {
            mint_error(
                "mkt_mint_invalid_nip87_reference",
                "nip87_ref relays must be a bounded array of relay hints",
            )
        })?;
    for relay in relays {
        let relay = relay.as_str().unwrap_or_default();
        if !relay.starts_with("wss://")
            || relay.len() > 512
            || !relay.is_ascii()
            || relay
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(mint_error(
                "mkt_mint_invalid_nip87_reference",
                "nip87_ref relay hints must be bounded wss URLs",
            ));
        }
    }
    Ok(())
}

fn validate_mint_market(value: Option<&Value>) -> Result<(), String> {
    let market = pfi_object(
        value.ok_or_else(|| mint_error("mkt_mint_invalid_market", "market is required"))?,
        "MKT-MINT market",
        "mkt_mint_invalid_market",
    )?;
    pfi_closed(
        market,
        &["base_asset_id", "quote_asset_id"],
        "MKT-MINT market",
        "mkt_mint_invalid_market",
    )?;
    let base = pfi_required_string(market, "base_asset_id", "mkt_mint_invalid_market")?;
    let quote = pfi_required_string(market, "quote_asset_id", "mkt_mint_invalid_market")?;
    for asset in [base, quote] {
        validate_mint_asset_id(asset)?;
    }
    if base == quote {
        return Err(mint_error(
            "mkt_mint_invalid_market",
            "market requires two distinct asset identifiers",
        ));
    }
    Ok(())
}

fn validate_mint_asset_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(mint_error(
            "mkt_mint_invalid_market",
            "asset identifier is empty, unbounded, or noncanonical",
        ));
    }
    if !value.contains(':') {
        return Err(mint_error(
            "mkt_mint_invalid_market",
            "display units such as sat, USD, or EUR are labels and are insufficient identifiers",
        ));
    }
    Ok(())
}

fn validate_mint_operations<'a>(
    value: Option<&'a Value>,
    rail: &str,
) -> Result<Vec<&'a str>, String> {
    let allowed = if rail == "cashu" {
        MKT_MINT_OPERATIONS_CASHU
    } else {
        MKT_MINT_OPERATIONS_FEDIMINT
    };
    let operations = pfi_string_array(value, 1, 4, "operations", "mkt_mint_invalid_market")?;
    for operation in &operations {
        if !allowed.contains(operation) {
            return Err(mint_error(
                "mkt_mint_invalid_market",
                format!("operation {operation:?} is not admitted for a {rail} route"),
            ));
        }
    }
    Ok(operations)
}

fn validate_mint_sides(
    value: Option<&Value>,
    rail: &str,
    operations: &[&str],
) -> Result<(), String> {
    let sides = pfi_object(
        value.ok_or_else(|| {
            mint_error(
                "mkt_mint_invalid_market",
                "sides is required; omission is invalid",
            )
        })?,
        "MKT-MINT sides",
        "mkt_mint_invalid_market",
    )?;
    let names: &[&str] = if rail == "cashu" {
        &["mint", "melt"]
    } else {
        &["deposit", "withdrawal"]
    };
    pfi_closed(sides, names, "MKT-MINT sides", "mkt_mint_invalid_market")?;
    let mut enabled = Vec::new();
    for name in names {
        enabled.push(validate_mint_side(sides.get(*name), name)?);
    }
    if rail == "cashu" {
        for (index, name) in names.iter().enumerate() {
            if enabled[index] != operations.contains(name) {
                return Err(mint_error(
                    "mkt_mint_side_disabled",
                    format!("{name} side and the declared operations must agree"),
                ));
            }
        }
    } else {
        if enabled[0] {
            return Err(mint_error(
                "mkt_mint_side_disabled",
                "version-1 Fedimint deposit must be present with min 0 and max 0",
            ));
        }
        if !enabled[1] {
            return Err(mint_error(
                "mkt_mint_side_disabled",
                "a Fedimint route requires an enabled withdrawal side",
            ));
        }
    }
    if !enabled.iter().any(|side| *side) {
        return Err(mint_error(
            "mkt_mint_side_disabled",
            "Offering must enable at least one side",
        ));
    }
    Ok(())
}

fn validate_mint_side(value: Option<&Value>, name: &str) -> Result<bool, String> {
    let side = pfi_object(
        value.ok_or_else(|| {
            mint_error(
                "mkt_mint_invalid_market",
                format!("{name} side is required; omission is invalid"),
            )
        })?,
        name,
        "mkt_mint_invalid_market",
    )?;
    pfi_closed(side, &["min", "max"], name, "mkt_mint_invalid_market")?;
    let minimum = pfi_decimal_member(side, "min", false, "mkt_mint_invalid_market")?;
    let maximum = pfi_decimal_member(side, "max", false, "mkt_mint_invalid_market")?;
    if maximum == 0 {
        if minimum != 0 {
            return Err(mint_error(
                "mkt_mint_side_disabled",
                format!("disabled {name} requires min 0 and max 0"),
            ));
        }
        return Ok(false);
    }
    if minimum == 0 || minimum > maximum {
        return Err(mint_error(
            "mkt_mint_invalid_market",
            format!("enabled {name} requires 0 < min <= max"),
        ));
    }
    Ok(true)
}

fn validate_mint_protocol_revisions(value: Option<&Value>) -> Result<(), String> {
    let revisions = pfi_string_array(
        value,
        1,
        16,
        "protocol_revisions",
        "mkt_mint_protocol_mismatch",
    )?;
    for revision in revisions {
        mint_identifier(
            revision,
            "protocol revision",
            64,
            "mkt_mint_protocol_mismatch",
        )?;
    }
    Ok(())
}

fn validate_mint_custody_class_value(value: &str, rail: Option<&str>) -> Result<(), String> {
    if !MKT_MINT_CUSTODY_CLASSES
        .iter()
        .any(|(_, class)| *class == value)
    {
        return Err(mint_error(
            "mkt_mint_custody_disclosure_mismatch",
            "custody_class must be a3-mint or a2-federation; a mint or federation route \
             cannot present itself as noncustodial",
        ));
    }
    if let Some(rail) = rail {
        let expected = MKT_MINT_CUSTODY_CLASSES
            .iter()
            .find(|(class_rail, _)| *class_rail == rail)
            .map(|(_, class)| *class)
            .unwrap_or_default();
        if value != expected {
            return Err(mint_error(
                "mkt_mint_custody_disclosure_mismatch",
                format!("a {rail} route must disclose custody_class {expected}"),
            ));
        }
    }
    Ok(())
}

fn validate_mkt_mint_visible_private(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    let body = Value::Object(envelope.body.clone());
    reject_mint_custody_material(&body)?;
    validate_mint_observable_members(&body, None)?;
    if event.kind == MKT_MINT_ROUTE_CONTRACT_KIND {
        validate_mint_route_contract(event, envelope)?;
    }
    Ok(())
}

fn validate_mint_observable_members(value: &Value, rail: Option<&str>) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            let object_rail = object
                .get("rail")
                .and_then(Value::as_str)
                .filter(|rail| MKT_MINT_RAILS.contains(rail))
                .or(rail);
            if let Some(declared) = object.get("rail").and_then(Value::as_str) {
                if !MKT_MINT_RAILS.contains(&declared) {
                    return Err(mint_error(
                        "mkt_mint_invalid_market",
                        "rail must be cashu or fedimint",
                    ));
                }
            }
            for (name, child) in object {
                match name.as_str() {
                    "custody_class" => validate_mint_custody_class_value(
                        child.as_str().ok_or_else(|| {
                            mint_error(
                                "mkt_mint_custody_disclosure_mismatch",
                                "custody_class must be a string",
                            )
                        })?,
                        object_rail,
                    )?,
                    "evidence_refs" => {
                        let references = child
                            .as_array()
                            .filter(|values| values.len() <= MKT_MAX_REFERENCES)
                            .ok_or_else(|| {
                                mint_error(
                                    "mkt_mint_evidence_mismatch",
                                    "evidence_refs exceeds the relay bound",
                                )
                            })?;
                        for reference in references {
                            validate_mkt_mint_evidence_reference(reference)?;
                        }
                    }
                    _ => validate_mint_observable_members(child, object_rail)?,
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_mint_observable_members(child, rail)?;
            }
        }
        _ => {}
    }
    Ok(())
}

const MKT_MINT_CONTRACT_DIGEST_MEMBERS: &[&str] = &[
    "native_request_sha256",
    "native_quote_id_sha256",
    "native_quote_sha256",
    "terms_sha256",
    "custody_sha256",
    "verifier_policy_sha256",
    "external_effect_ids_sha256",
    "recovery_package_sha256",
];

fn validate_mint_route_contract(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    if event
        .tags
        .iter()
        .any(|tag| tag.name() == Some("expiration"))
    {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            "Route Contract has no NIP-40 expiration",
        ));
    }
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .collect::<Vec<_>>();
    let [counterparty] = counterparties.as_slice() else {
        return Err(mint_error(
            "mkt_mint_invalid_contract_signer",
            "Route Contract requires exactly one counterparty",
        ));
    };
    let role = single_value(event, "role", "MKT-MINT Route Contract")?;
    if !matches!(role, "requester" | "provider") {
        return Err(mint_error(
            "mkt_mint_invalid_contract_signer",
            "Route Contract role is invalid",
        ));
    }
    let counterparty = counterparty.as_slice();
    let counterparty_pubkey = counterparty.get(1).map(String::as_str).unwrap_or_default();
    let counterparty_role = counterparty.get(3).map(String::as_str).unwrap_or_default();
    let expected_counterparty_role = if role == "requester" {
        "provider"
    } else {
        "requester"
    };
    if counterparty_pubkey == event.pubkey || counterparty_role != expected_counterparty_role {
        return Err(mint_error(
            "mkt_mint_invalid_contract_signer",
            "Route Contract requires a distinct counterparty with the complementary role",
        ));
    }
    let rail = single_value(event, "rail", "MKT-MINT Route Contract")?;
    if !MKT_MINT_RAILS.contains(&rail) {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            "Route Contract rail must be cashu or fedimint",
        ));
    }
    let alt = single_value(event, "alt", "MKT-MINT Route Contract")?;
    if alt != "MKT-MINT route contract" {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            "Route Contract alt text is fixed",
        ));
    }
    let digest = single_value(event, "x", "MKT-MINT Route Contract")?;
    lower_hex_32(digest, "MKT-MINT contract digest")?;

    let mut quote_id = None;
    let mut order_id = None;
    let mut status_id = None;
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        let values = tag.as_slice();
        let id = values.get(1).map(String::as_str).unwrap_or_default();
        let slot = match values.get(3).map(String::as_str) {
            Some("quote") => &mut quote_id,
            Some("order") => &mut order_id,
            Some("status") => &mut status_id,
            _ => {
                return Err(mint_error(
                    "mkt_mint_route_contract_mismatch",
                    "Route Contract has an unsupported event reference",
                ));
            }
        };
        if slot.replace(id).is_some() {
            return Err(mint_error(
                "mkt_mint_route_contract_mismatch",
                "Route Contract has a duplicate causal reference",
            ));
        }
    }
    let (Some(quote_id), Some(order_id)) = (quote_id, order_id) else {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            "Route Contract requires one Quote and one Order reference",
        ));
    };

    let profile = envelope
        .body
        .get("mkt_mint")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            mint_error(
                "mkt_mint_route_contract_mismatch",
                "Route Contract requires an mkt_mint object",
            )
        })?;
    pfi_closed(
        profile,
        &["contract", "contract_sha256", "signer_role"],
        "MKT-MINT Route Contract content",
        "mkt_mint_route_contract_mismatch",
    )?;
    let signer_role =
        pfi_required_string(profile, "signer_role", "mkt_mint_invalid_contract_signer")?;
    if signer_role != role {
        return Err(mint_error(
            "mkt_mint_invalid_contract_signer",
            "Route Contract tag and content roles differ",
        ));
    }
    let content_digest = pfi_required_string(
        profile,
        "contract_sha256",
        "mkt_mint_route_contract_mismatch",
    )?;
    if content_digest != digest {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            "Route Contract x tag and contract_sha256 differ",
        ));
    }
    let contract = pfi_object(
        profile.get("contract").ok_or_else(|| {
            mint_error(
                "mkt_mint_route_contract_mismatch",
                "Route Contract requires a contract object",
            )
        })?,
        "MKT-MINT contract",
        "mkt_mint_route_contract_mismatch",
    )?;
    pfi_closed(
        contract,
        &[
            "quote_event_id",
            "order_event_id",
            "accepted_status_event_id",
            "operation",
            "native_request_sha256",
            "native_quote_id_sha256",
            "native_quote_sha256",
            "terms_sha256",
            "custody_sha256",
            "verifier_policy_sha256",
            "external_effect_ids_sha256",
            "recovery_package_sha256",
        ],
        "MKT-MINT contract",
        "mkt_mint_route_contract_mismatch",
    )?;
    let operation = pfi_required_string(contract, "operation", "mkt_mint_route_contract_mismatch")?;
    let allowed_operations = if rail == "cashu" {
        MKT_MINT_OPERATIONS_CASHU
    } else {
        MKT_MINT_OPERATIONS_FEDIMINT
    };
    if !allowed_operations.contains(&operation) {
        return Err(mint_error(
            "mkt_mint_route_contract_mismatch",
            format!("operation {operation:?} is not admitted for a {rail} route"),
        ));
    }
    for member in MKT_MINT_CONTRACT_DIGEST_MEMBERS {
        pfi_hex_with_code(
            pfi_required_string(contract, member, "mkt_mint_route_contract_mismatch")?,
            member,
            "mkt_mint_route_contract_mismatch",
        )?;
    }
    for (member, expected) in [("quote_event_id", quote_id), ("order_event_id", order_id)] {
        let value = pfi_required_string(contract, member, "mkt_mint_route_contract_mismatch")?;
        pfi_hex_with_code(value, member, "mkt_mint_route_contract_mismatch")?;
        if value != expected {
            return Err(mint_error(
                "mkt_mint_route_contract_mismatch",
                format!("{member} must equal the causal tag"),
            ));
        }
    }
    match contract.get("accepted_status_event_id") {
        Some(Value::Null) => {
            if status_id.is_some() {
                return Err(mint_error(
                    "mkt_mint_route_contract_mismatch",
                    "a firm-Quote contract forbids the status reference",
                ));
            }
        }
        Some(Value::String(value)) => {
            pfi_hex_with_code(
                value,
                "accepted_status_event_id",
                "mkt_mint_route_contract_mismatch",
            )?;
            if status_id != Some(value.as_str()) {
                return Err(mint_error(
                    "mkt_mint_route_contract_mismatch",
                    "accepted_status_event_id must equal the status causal tag",
                ));
            }
        }
        _ => {
            return Err(mint_error(
                "mkt_mint_route_contract_mismatch",
                "accepted_status_event_id must be the accepted Status id or null",
            ));
        }
    }
    Ok(())
}

pub fn validate_mkt_mint_evidence_reference(value: &Value) -> Result<(), String> {
    let evidence = pfi_object(
        value,
        "MKT-MINT evidence reference",
        "mkt_mint_evidence_mismatch",
    )?;
    pfi_closed(
        evidence,
        &[
            "receipt_type",
            "artifact_sha256",
            "issuer",
            "provenance",
            "observed_at",
            "verifier_policy",
        ],
        "MKT-MINT evidence reference",
        "mkt_mint_evidence_mismatch",
    )?;
    let receipt_type = pfi_required_string(evidence, "receipt_type", "mkt_mint_evidence_mismatch")?;
    mint_identifier(
        receipt_type,
        "MKT-MINT receipt type",
        64,
        "mkt_mint_evidence_mismatch",
    )?;
    pfi_hex_with_code(
        pfi_required_string(evidence, "artifact_sha256", "mkt_mint_evidence_mismatch")?,
        "MKT-MINT evidence digest",
        "mkt_mint_evidence_mismatch",
    )?;
    let issuer = pfi_required_string(evidence, "issuer", "mkt_mint_evidence_mismatch")?;
    pfi_bounded_ascii(
        issuer,
        "MKT-MINT evidence issuer",
        512,
        "mkt_mint_evidence_mismatch",
    )?;
    if mint_value_is_custody_shaped(issuer) || pfi_value_is_bearer_shaped(issuer) {
        return Err(mint_error(
            "mkt_mint_bearer_material_forbidden",
            "evidence issuer is bearer-shaped",
        ));
    }
    let provenance = pfi_required_string(evidence, "provenance", "mkt_mint_evidence_mismatch")?;
    if !MKT_MINT_EVIDENCE_PROVENANCE.contains(&provenance) {
        return Err(mint_error(
            "mkt_mint_settlement_overclaim",
            "unknown provenance label; labels are never inferred upward",
        ));
    }
    pfi_decimal_member(evidence, "observed_at", false, "mkt_mint_evidence_mismatch")?;
    match evidence.get("verifier_policy") {
        Some(Value::Null) => {}
        Some(Value::String(value)) => mint_identifier(
            value,
            "MKT-MINT verifier policy",
            128,
            "mkt_mint_evidence_mismatch",
        )?,
        _ => {
            return Err(mint_error(
                "mkt_mint_evidence_mismatch",
                "verifier_policy must be an identifier or null",
            ));
        }
    }
    if receipt_type.contains("quote")
        && matches!(provenance, "paid" | "issued" | "refunded" | "settled")
    {
        return Err(mint_error(
            "mkt_mint_settlement_overclaim",
            "a quote does not prove payment, issuance, redemption, or finality",
        ));
    }
    if (receipt_type.contains("invoice") || receipt_type.contains("payment"))
        && provenance == "issued"
    {
        return Err(mint_error(
            "mkt_mint_settlement_overclaim",
            "payment evidence cannot prove proof issuance",
        ));
    }
    Ok(())
}

fn reject_mint_custody_material(value: &Value) -> Result<(), String> {
    mint_material_sweep(value, false)
}

fn reject_mint_public_material(value: &Value) -> Result<(), String> {
    mint_material_sweep(value, true)
}

fn mint_material_sweep(value: &Value, public: bool) -> Result<(), String> {
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
                    "proof"
                        | "proofs"
                        | "ecashproof"
                        | "ecashproofs"
                        | "cashutoken"
                        | "cashutokens"
                        | "note"
                        | "notes"
                        | "ecashnote"
                        | "ecashnotes"
                        | "blindedmessage"
                        | "blindedmessages"
                        | "blindingfactor"
                        | "blindingfactors"
                        | "secret"
                        | "secrets"
                        | "preimage"
                        | "macaroon"
                        | "seed"
                        | "walletseed"
                        | "mnemonic"
                        | "privatekey"
                        | "spendkey"
                        | "spendkeys"
                        | "claimprivatekey"
                        | "refundprivatekey"
                        | "recoverysecret"
                        | "recoverysecrets"
                        | "accesstoken"
                        | "bearertoken"
                        | "authorization"
                        | "password"
                        | "nwc"
                        | "nwcstring"
                        | "nwcuri"
                ) {
                    return Err(mint_error(
                        "mkt_mint_bearer_material_forbidden",
                        format!("market record contains custody member {name:?}"),
                    ));
                }
                if public {
                    if matches!(
                        normalized.as_str(),
                        "minturl"
                            | "mintendpoint"
                            | "federationinvite"
                            | "federationinvitecode"
                            | "federationinvitation"
                            | "invitecode"
                            | "nutlist"
                            | "modulelist"
                            | "operatorclaim"
                    ) {
                        return Err(mint_error(
                            "mkt_mint_discovery_duplication",
                            format!(
                                "public record copies NIP-87 discovery authority member {name:?}"
                            ),
                        ));
                    }
                    if matches!(
                        normalized.as_str(),
                        "invoice"
                            | "invoices"
                            | "bolt11"
                            | "paymentrequest"
                            | "mintquote"
                            | "meltquote"
                            | "nativequote"
                            | "withdrawaladdress"
                            | "account"
                            | "accountnumber"
                            | "accountidentifier"
                            | "membershippresentation"
                            | "invitationcode"
                            | "recoverypackage"
                    ) {
                        return Err(mint_error(
                            "mkt_mint_bearer_material_forbidden",
                            format!("public record contains forbidden member {name:?}"),
                        ));
                    }
                }
                mint_material_sweep(child, public)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                mint_material_sweep(child, public)?;
            }
        }
        Value::String(value) => {
            if mint_value_is_custody_shaped(value) {
                return Err(mint_error(
                    "mkt_mint_bearer_material_forbidden",
                    "market record contains a bearer ecash value",
                ));
            }
            if public && mint_value_is_public_forbidden(value) {
                return Err(mint_error(
                    "mkt_mint_bearer_material_forbidden",
                    "public record contains an invoice, invitation, or bearer value",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn mint_value_is_custody_shaped(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("cashua") || lowercase.starts_with("cashub")
}

fn mint_value_is_public_forbidden(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    if lowercase.starts_with("fed1") {
        return true;
    }
    if lowercase.len() >= 20
        && ["lnbc", "lntb", "lntbs", "lnbcrt"]
            .iter()
            .any(|prefix| lowercase.starts_with(prefix))
        && lowercase.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return true;
    }
    pfi_value_is_bearer_shaped(value)
}

fn mint_identifier(value: &str, subject: &str, maximum: usize, code: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(mint_error(
            code,
            format!("{subject} is not a bounded identifier"),
        ));
    }
    Ok(())
}

fn mint_error(code: &str, detail: impl fmt::Display) -> String {
    format!("{code}: {detail}")
}

// MKT-P2P v1 relay-observable validation (nips/openagents/MKT-P2P.md).
// The relay validates only the visible grammar: public Offering and
// receipt shapes, the wrapped kind-39620 Resolution record, admitted
// Status states, and the NIP-69/Mostro source-reference mapping. Escrow,
// bond, dispute, payment, and settlement authority stay external.

fn validate_mkt_p2p_offering(event: &Event) -> Result<(), String> {
    let content = parse_unique_json(&event.content, "MKT-P2P Offering content")?;
    reject_p2p_public_private_material(&content)?;
    let body = content
        .as_object()
        .ok_or_else(|| "MKT-P2P Offering content must be a JSON object".to_owned())?;

    let market = p2p_object(
        body.get("market"),
        "MKT-P2P Offering market",
        "mkt_p2p_invalid_market",
    )?;
    p2p_closed(
        market,
        &["base_asset_id", "quote_asset_id"],
        "MKT-P2P Offering market",
        "mkt_p2p_invalid_market",
    )?;
    for member in ["base_asset_id", "quote_asset_id"] {
        validate_p2p_registry_asset_id(p2p_required_string(
            market,
            member,
            "mkt_p2p_invalid_market",
        )?)?;
    }

    let sides = p2p_object(
        body.get("sides"),
        "MKT-P2P Offering sides",
        "mkt_p2p_invalid_market",
    )?;
    p2p_closed(
        sides,
        &["buy", "sell"],
        "MKT-P2P Offering sides",
        "mkt_p2p_invalid_market",
    )?;
    for side_name in ["buy", "sell"] {
        let side = p2p_object(
            sides.get(side_name),
            "MKT-P2P Offering side",
            "mkt_p2p_invalid_market",
        )?;
        p2p_closed(
            side,
            &["min", "max"],
            "MKT-P2P Offering side",
            "mkt_p2p_invalid_market",
        )?;
        let minimum = canonical_decimal(
            p2p_required_string(side, "min", "mkt_p2p_invalid_market")?,
            false,
            "MKT-P2P side min",
        )
        .map_err(|detail| p2p_error("mkt_p2p_invalid_market", detail))?;
        let maximum = canonical_decimal(
            p2p_required_string(side, "max", "mkt_p2p_invalid_market")?,
            false,
            "MKT-P2P side max",
        )
        .map_err(|detail| p2p_error("mkt_p2p_invalid_market", detail))?;
        if maximum == 0 {
            if minimum != 0 {
                return Err(p2p_error(
                    "mkt_p2p_side_disabled",
                    format!("disabled {side_name} side requires min=0 and max=0"),
                ));
            }
        } else if minimum == 0 || minimum > maximum {
            return Err(p2p_error(
                "mkt_p2p_invalid_market",
                format!("enabled {side_name} side requires 0 < min <= max"),
            ));
        }
    }

    let methods = body
        .get("payment_method_ids")
        .and_then(Value::as_array)
        .filter(|values| (1..=16).contains(&values.len()))
        .ok_or_else(|| "MKT-P2P Offering requires 1-16 payment_method_ids".to_owned())?;
    let mut method_ids = BTreeSet::new();
    for method in methods {
        let method = method
            .as_str()
            .ok_or_else(|| "MKT-P2P payment method ids must be strings".to_owned())?;
        validate_identifier(method, "MKT-P2P payment method id")?;
        if !method_ids.insert(method) {
            return Err("MKT-P2P payment method ids must be duplicate-free".to_owned());
        }
    }

    require_enum(
        p2p_required_string(body, "amount_mode", "mkt_p2p_invalid_market")?,
        MKT_P2P_AMOUNT_MODES,
        "MKT-P2P amount_mode",
    )
    .map_err(|detail| p2p_error("mkt_p2p_invalid_market", detail))?;

    validate_p2p_nip69_declaration(body.get("nip69"))?;

    if p2p_required_string(body, "custody_class", "mkt_p2p_unsupported_version")?
        != MKT_P2P_CUSTODY_CLASS
    {
        return Err(p2p_error(
            "mkt_p2p_unsupported_version",
            "MKT-P2P v1 supports only custody class a1-coordinated-hold",
        ));
    }

    let bond_policy = p2p_required_string(body, "bond_policy", "mkt_p2p_bond_mismatch")?;
    if bond_policy != "none" {
        p2p_bounded_ascii(
            bond_policy,
            "bond policy summary",
            512,
            "mkt_p2p_bond_mismatch",
        )?;
    }

    p2p_hex(
        p2p_required_string(body, "dispute_policy_digest", "mkt_p2p_invalid_resolution")?,
        "dispute policy digest",
        "mkt_p2p_invalid_resolution",
    )?;
    Ok(())
}

fn validate_p2p_registry_asset_id(value: &str) -> Result<(), String> {
    let Some((namespace, reference)) = value.split_once(':') else {
        return Err(p2p_error(
            "mkt_p2p_invalid_market",
            "asset id must be a collision-resistant registry identifier, not a ticker",
        ));
    };
    if !(2..=16).contains(&namespace.len())
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || reference.is_empty()
        || reference.len() > 128
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(p2p_error(
            "mkt_p2p_invalid_market",
            "asset id registry namespace or reference is noncanonical",
        ));
    }
    Ok(())
}

fn validate_p2p_nip69_declaration(value: Option<&Value>) -> Result<(), String> {
    let nip69 = p2p_object(value, "Offering nip69", "mkt_p2p_invalid_nip69_reference")?;
    if nip69.is_empty() || nip69.len() > 8 {
        return Err(p2p_error(
            "mkt_p2p_invalid_nip69_reference",
            "nip69 declaration requires 1-8 bounded members",
        ));
    }
    for (name, child) in nip69 {
        p2p_bounded_ascii(
            name,
            "nip69 member name",
            64,
            "mkt_p2p_invalid_nip69_reference",
        )?;
        match child {
            Value::String(child) => p2p_bounded_ascii(
                child,
                "nip69 member value",
                128,
                "mkt_p2p_invalid_nip69_reference",
            )?,
            Value::Array(children) if children.len() <= 16 => {
                for child in children {
                    p2p_bounded_ascii(
                        child.as_str().ok_or_else(|| {
                            p2p_error(
                                "mkt_p2p_invalid_nip69_reference",
                                "nip69 list values must be strings",
                            )
                        })?,
                        "nip69 list value",
                        128,
                        "mkt_p2p_invalid_nip69_reference",
                    )?;
                }
            }
            _ => {
                return Err(p2p_error(
                    "mkt_p2p_invalid_nip69_reference",
                    "nip69 members must be bounded strings or string lists",
                ));
            }
        }
    }
    Ok(())
}

fn validate_mkt_p2p_visible_private(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    validate_p2p_source_members(&Value::Object(envelope.body.clone()))?;
    if event.kind == MKT_STATUS_KIND {
        for tag in event.tags.iter().filter(|tag| tag.name() == Some("state")) {
            let state = tag.value().unwrap_or_default();
            if !MKT_P2P_STATUS_BASE_STATES.contains(&state)
                && !MKT_P2P_STATUS_EXTENSION_STATES.contains(&state)
            {
                return Err(p2p_error(
                    "mkt_p2p_invalid_transition",
                    "Status state is not admitted by MKT-P2P version 1",
                ));
            }
        }
    }
    if event.kind == MKT_P2P_RESOLUTION_KIND {
        validate_mkt_p2p_resolution(event, envelope)?;
    }
    Ok(())
}

fn validate_p2p_source_members(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                if name == "source" {
                    validate_mkt_p2p_source_reference(child)?;
                } else {
                    validate_p2p_source_members(child)?;
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_p2p_source_members(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_mkt_p2p_source_reference(value: &Value) -> Result<(), String> {
    let source = p2p_object(
        Some(value),
        "MKT-P2P source reference",
        "mkt_p2p_invalid_nip69_reference",
    )?;
    p2p_closed(
        source,
        &[
            "protocol",
            "revision",
            "event_id",
            "source_sha256",
            "mapping_version",
            "dropped_fields",
            "defaulted_fields",
            "ambiguous_fields",
        ],
        "MKT-P2P source reference",
        "mkt_p2p_invalid_nip69_reference",
    )?;
    if p2p_required_string(source, "protocol", "mkt_p2p_invalid_nip69_reference")?
        != MKT_P2P_SOURCE_PROTOCOL
    {
        return Err(p2p_error(
            "mkt_p2p_unrepresentable_source",
            "MKT-P2P v1 bridges only nip-69-mostro sources",
        ));
    }
    p2p_bounded_ascii(
        p2p_required_string(source, "revision", "mkt_p2p_invalid_nip69_reference")?,
        "source revision",
        128,
        "mkt_p2p_invalid_nip69_reference",
    )?;
    for member in ["event_id", "source_sha256"] {
        p2p_hex(
            p2p_required_string(source, member, "mkt_p2p_invalid_nip69_reference")?,
            member,
            "mkt_p2p_invalid_nip69_reference",
        )?;
    }
    if p2p_required_string(source, "mapping_version", "mkt_p2p_invalid_nip69_reference")?
        != MKT_P2P_SOURCE_MAPPING_VERSION
    {
        return Err(p2p_error(
            "mkt_p2p_invalid_nip69_reference",
            "source mapping_version must be mkt-p2p-v1",
        ));
    }
    for member in ["dropped_fields", "defaulted_fields", "ambiguous_fields"] {
        let fields = source
            .get(member)
            .and_then(Value::as_array)
            .filter(|values| values.len() <= 32)
            .ok_or_else(|| {
                p2p_error(
                    "mkt_p2p_invalid_nip69_reference",
                    format!("source {member} must be a bounded array"),
                )
            })?;
        for field in fields {
            p2p_bounded_ascii(
                field.as_str().ok_or_else(|| {
                    p2p_error(
                        "mkt_p2p_invalid_nip69_reference",
                        format!("source {member} entries must be strings"),
                    )
                })?,
                "source loss-accounting field",
                128,
                "mkt_p2p_invalid_nip69_reference",
            )?;
        }
    }
    Ok(())
}

fn validate_mkt_p2p_resolution(event: &Event, envelope: &MktPrivateEnvelope) -> Result<(), String> {
    if single_value(event, "alt", "MKT-P2P Resolution")? != MKT_P2P_RESOLUTION_ALT {
        return Err(p2p_error(
            "mkt_p2p_invalid_resolution",
            "Resolution alt tag is not the fixed profile label",
        ));
    }
    let role = single_value(event, "role", "MKT-P2P Resolution")?;
    if !MKT_P2P_RESOLUTION_ROLES.contains(&role) {
        return Err(p2p_error(
            "mkt_p2p_invalid_resolution",
            "Resolution role must be solver or appeal-arbiter",
        ));
    }

    let mut order = 0;
    let mut previous_tag = None;
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        match tag.as_slice().get(3).map(String::as_str) {
            Some("order") => order += 1,
            Some("previous") => {
                if previous_tag
                    .replace(
                        tag.as_slice()
                            .get(1)
                            .map(String::as_str)
                            .unwrap_or_default(),
                    )
                    .is_some()
                {
                    return Err(p2p_error(
                        "mkt_p2p_invalid_resolution",
                        "Resolution permits exactly one previous reference",
                    ));
                }
            }
            Some("evidence") => {}
            _ => {
                return Err(p2p_error(
                    "mkt_p2p_invalid_resolution",
                    "Resolution has an unsupported event reference",
                ));
            }
        }
    }
    if order != 1 {
        return Err(p2p_error(
            "mkt_p2p_invalid_resolution",
            "Resolution requires exactly one order reference",
        ));
    }

    let mut maker = 0;
    let mut taker = 0;
    let mut coordinator = 0;
    let mut author_role_marked = false;
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("p")) {
        let values = tag.as_slice();
        let tag_role = values.get(3).map(String::as_str).unwrap_or_default();
        if !MKT_P2P_RECIPIENT_ROLES.contains(&tag_role) {
            return Err(p2p_error(
                "mkt_p2p_invalid_resolution",
                "every Resolution p tag must carry a profile recipient role",
            ));
        }
        let pubkey = values.get(1).map(String::as_str).unwrap_or_default();
        lower_hex_32(pubkey, "Resolution recipient")
            .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
        match tag_role {
            "maker" => maker += 1,
            "taker" => taker += 1,
            "coordinator" => coordinator += 1,
            _ => {}
        }
        if pubkey == event.pubkey && tag_role == role {
            author_role_marked = true;
        }
    }
    if maker != 1 || taker != 1 || coordinator != 1 {
        return Err(p2p_error(
            "mkt_p2p_invalid_resolution",
            "Resolution requires one maker, one taker, and one coordinator recipient",
        ));
    }
    if !author_role_marked {
        return Err(p2p_error(
            "mkt_p2p_invalid_resolution",
            "Resolution author requires a matching role-marked p tag",
        ));
    }

    p2p_closed(
        &envelope.body,
        &[
            "schema",
            "profile",
            "profile_version",
            "session_id",
            "resolution",
            "loss",
        ],
        "Resolution content",
        "mkt_p2p_invalid_resolution",
    )?;
    let resolution = p2p_object(
        envelope.body.get("resolution"),
        "Resolution decision",
        "mkt_p2p_invalid_resolution",
    )?;
    p2p_closed(
        resolution,
        &[
            "previous_resolution_event_id",
            "decision",
            "scope",
            "reason",
            "effective_after",
            "appeal_deadline",
            "policy_sha256",
            "evidence",
        ],
        "Resolution decision",
        "mkt_p2p_invalid_resolution",
    )?;
    require_enum(
        p2p_required_string(resolution, "decision", "mkt_p2p_invalid_resolution")?,
        MKT_P2P_RESOLUTION_DECISIONS,
        "MKT-P2P decision",
    )
    .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
    require_enum(
        p2p_required_string(resolution, "scope", "mkt_p2p_invalid_resolution")?,
        MKT_P2P_RESOLUTION_SCOPES,
        "MKT-P2P decision scope",
    )
    .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
    validate_identifier(
        p2p_required_string(resolution, "reason", "mkt_p2p_invalid_resolution")?,
        "MKT-P2P decision reason",
    )
    .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
    for member in ["effective_after", "appeal_deadline"] {
        if resolution.contains_key(member) {
            canonical_decimal(
                p2p_required_string(resolution, member, "mkt_p2p_invalid_resolution")?,
                false,
                member,
            )
            .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
        }
    }
    p2p_hex(
        p2p_required_string(resolution, "policy_sha256", "mkt_p2p_invalid_resolution")?,
        "Resolution policy digest",
        "mkt_p2p_invalid_resolution",
    )?;

    match resolution.get("previous_resolution_event_id") {
        Some(Value::Null) => {
            if previous_tag.is_some() || role != "solver" {
                return Err(p2p_error(
                    "mkt_p2p_invalid_resolution",
                    "an initial decision permits no previous reference and requires the solver role",
                ));
            }
        }
        Some(Value::String(previous_id)) => {
            p2p_hex(
                previous_id,
                "previous Resolution event id",
                "mkt_p2p_invalid_resolution",
            )?;
            if previous_tag != Some(previous_id.as_str()) || role != "appeal-arbiter" {
                return Err(p2p_error(
                    "mkt_p2p_invalid_resolution",
                    "an appeal requires the appeal-arbiter role and the exact previous reference",
                ));
            }
        }
        _ => {
            return Err(p2p_error(
                "mkt_p2p_invalid_resolution",
                "previous_resolution_event_id must be null or an exact event id",
            ));
        }
    }

    let evidence = resolution
        .get("evidence")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= MKT_MAX_REFERENCES)
        .ok_or_else(|| {
            p2p_error(
                "mkt_p2p_evidence_mismatch",
                "Resolution evidence must be a bounded array",
            )
        })?;
    for reference in evidence {
        validate_mkt_p2p_resolution_evidence(reference)?;
    }

    if let Some(loss) = envelope.body.get("loss") {
        let entries = loss
            .as_array()
            .filter(|values| values.len() <= 32)
            .ok_or_else(|| {
                p2p_error(
                    "mkt_p2p_invalid_resolution",
                    "Resolution loss must be a bounded array",
                )
            })?;
        for entry in entries {
            validate_identifier(
                entry.as_str().ok_or_else(|| {
                    p2p_error(
                        "mkt_p2p_invalid_resolution",
                        "Resolution loss entries must be strings",
                    )
                })?,
                "MKT-P2P loss state",
            )
            .map_err(|detail| p2p_error("mkt_p2p_invalid_resolution", detail))?;
        }
    }
    Ok(())
}

pub fn validate_mkt_p2p_resolution_evidence(value: &Value) -> Result<(), String> {
    let evidence = p2p_object(
        Some(value),
        "Resolution evidence reference",
        "mkt_p2p_evidence_mismatch",
    )?;
    p2p_closed(
        evidence,
        &["ref", "sha256", "provenance"],
        "Resolution evidence reference",
        "mkt_p2p_evidence_mismatch",
    )?;
    let reference = p2p_required_string(evidence, "ref", "mkt_p2p_evidence_mismatch")?;
    if reference.is_empty()
        || reference.len() > 512
        || reference.chars().any(char::is_control)
        || reference.contains("://") && (reference.contains('@') || reference.contains('?'))
    {
        return Err(p2p_error(
            "mkt_p2p_evidence_mismatch",
            "evidence ref is empty, unbounded, or bearer-shaped",
        ));
    }
    p2p_hex(
        p2p_required_string(evidence, "sha256", "mkt_p2p_evidence_mismatch")?,
        "evidence digest",
        "mkt_p2p_evidence_mismatch",
    )?;
    require_enum(
        p2p_required_string(evidence, "provenance", "mkt_p2p_evidence_mismatch")?,
        MKT_P2P_EVIDENCE_PROVENANCE,
        "MKT-P2P evidence provenance",
    )
    .map_err(|detail| p2p_error("mkt_p2p_evidence_mismatch", detail))
}

fn reject_p2p_public_private_material(value: &Value) -> Result<(), String> {
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
                        | "phone"
                        | "phonenumber"
                        | "physicaladdress"
                        | "streetaddress"
                        | "address"
                        | "location"
                        | "geohash"
                        | "bankaccount"
                        | "account"
                        | "accountnumber"
                        | "iban"
                        | "routingnumber"
                        | "sortcode"
                        | "mobilemoney"
                        | "mobilemoneyaccount"
                        | "paymentreference"
                        | "paymentref"
                        | "paymentinstruction"
                        | "paymentinstructions"
                        | "invoice"
                        | "invoices"
                        | "bolt11"
                        | "paymenthash"
                        | "preimage"
                        | "credential"
                        | "credentials"
                        | "credentialpresentation"
                        | "presentation"
                        | "presentationbytes"
                        | "tradekeylink"
                        | "tradekeylinkage"
                        | "identitylink"
                        | "linkedidentity"
                        | "ipaddress"
                        | "clientip"
                        | "privaterelayurl"
                        | "disputeevidence"
                        | "disputenarrative"
                        | "seed"
                        | "privatekey"
                        | "claimprivatekey"
                        | "refundprivatekey"
                        | "macaroon"
                ) {
                    return Err(p2p_error(
                        "mkt_p2p_private_data_public",
                        format!("public MKT-P2P record contains forbidden member {name:?}"),
                    ));
                }
                reject_p2p_public_private_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_p2p_public_private_material(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_p2p_public_receipt_material(value: &Value) -> Result<(), String> {
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
                    "sessionid"
                        | "counterparty"
                        | "counterparties"
                        | "maker"
                        | "taker"
                        | "amount"
                        | "baseamount"
                        | "quoteamount"
                        | "minamount"
                        | "maxamount"
                        | "price"
                        | "fee"
                        | "feebps"
                        | "route"
                        | "transactionid"
                        | "txid"
                        | "bond"
                        | "bonds"
                        | "bondstatus"
                        | "dispute"
                        | "resolution"
                        | "evidence"
                        | "evidencerefs"
                        | "source"
                        | "timingladder"
                ) {
                    return Err(p2p_error(
                        "mkt_p2p_private_data_public",
                        format!("public MKT-P2P receipt contains private member {name:?}"),
                    ));
                }
                reject_p2p_public_receipt_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_p2p_public_receipt_material(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn p2p_object<'a>(
    value: Option<&'a Value>,
    subject: &str,
    code: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| p2p_error(code, format!("{subject} must be an object")))
}

fn p2p_closed(
    object: &Map<String, Value>,
    allowed: &[&str],
    subject: &str,
    code: &str,
) -> Result<(), String> {
    if let Some(member) = object
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        return Err(p2p_error(
            code,
            format!("{subject} contains unknown member {member:?}"),
        ));
    }
    Ok(())
}

fn p2p_required_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    code: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| p2p_error(code, format!("{name} must be a string")))
}

fn p2p_bounded_ascii(value: &str, subject: &str, maximum: usize, code: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(p2p_error(
            code,
            format!("{subject} is invalid or unbounded"),
        ));
    }
    Ok(())
}

fn p2p_hex(value: &str, subject: &str, code: &str) -> Result<(), String> {
    lower_hex_32(value, subject).map_err(|detail| p2p_error(code, detail))
}

fn p2p_error(code: &str, detail: impl fmt::Display) -> String {
    format!("{code}: {detail}")
}

// MKT-LSP v1 relay-observable validation (nips/openagents/MKT-LSP.md).
// The relay validates only the visible grammar: public Offering and
// receipt shapes, the wrapped kind-39650 LSP Service Contract, admitted
// Status states, and the LSPS0/1/2 source-reference mapping. Channel
// opening, JIT execution, LSP node operations, fee-negotiation
// settlement, reservation proof evaluation, and recovery stay client or
// external-rail authority: the relay coordinates, it does not operate
// channels.

fn validate_mkt_lsp_offering(event: &Event) -> Result<(), String> {
    let content = parse_unique_json(&event.content, "MKT-LSP Offering content")?;
    reject_lsp_public_material(&content)?;
    let body = content
        .as_object()
        .ok_or_else(|| "MKT-LSP Offering content must be a JSON object".to_owned())?;

    validate_lsp_node_id(lsp_required_string(
        body,
        "lsp_node_id",
        "mkt_lsp_invalid_node",
    )?)?;
    validate_lsp_registry_id(
        lsp_required_string(body, "network_id", "mkt_lsp_invalid_market")?,
        "network id",
    )?;
    validate_lsp_bounded_declaration(
        body.get("lsps"),
        "Offering lsps declaration",
        "mkt_lsp_lsps_mismatch",
    )?;

    let market = lsp_object(
        body.get("market"),
        "MKT-LSP Offering market",
        "mkt_lsp_invalid_market",
    )?;
    lsp_closed(
        market,
        &["base_asset_id", "quote_asset_id"],
        "MKT-LSP Offering market",
        "mkt_lsp_invalid_market",
    )?;
    for member in ["base_asset_id", "quote_asset_id"] {
        validate_lsp_registry_id(
            lsp_required_string(market, member, "mkt_lsp_invalid_market")?,
            "asset id",
        )?;
    }

    let sides = lsp_object(
        body.get("sides"),
        "MKT-LSP Offering sides",
        "mkt_lsp_invalid_market",
    )?;
    lsp_closed(
        sides,
        MKT_LSP_SIDES,
        "MKT-LSP Offering sides",
        "mkt_lsp_invalid_market",
    )?;
    for side_name in MKT_LSP_SIDES {
        let side = lsp_object(
            sides.get(*side_name),
            "MKT-LSP Offering side",
            "mkt_lsp_invalid_market",
        )?;
        lsp_closed(
            side,
            &["min", "max"],
            "MKT-LSP Offering side",
            "mkt_lsp_invalid_market",
        )?;
        let minimum = canonical_decimal(
            lsp_required_string(side, "min", "mkt_lsp_invalid_market")?,
            false,
            "MKT-LSP side min",
        )
        .map_err(|detail| lsp_error("mkt_lsp_invalid_market", detail))?;
        let maximum = canonical_decimal(
            lsp_required_string(side, "max", "mkt_lsp_invalid_market")?,
            false,
            "MKT-LSP side max",
        )
        .map_err(|detail| lsp_error("mkt_lsp_invalid_market", detail))?;
        if maximum == 0 {
            if minimum != 0 {
                return Err(lsp_error(
                    "mkt_lsp_side_disabled",
                    format!("disabled {side_name} side requires min=0 and max=0"),
                ));
            }
        } else if minimum == 0 || minimum > maximum {
            return Err(lsp_error(
                "mkt_lsp_invalid_market",
                format!("enabled {side_name} side requires 0 < min <= max"),
            ));
        }
    }

    let channel_types = body
        .get("channel_types")
        .and_then(Value::as_array)
        .filter(|values| (1..=16).contains(&values.len()))
        .ok_or_else(|| "MKT-LSP Offering requires 1-16 channel_types".to_owned())?;
    let mut channel_type_ids = BTreeSet::new();
    for channel_type in channel_types {
        let channel_type = channel_type
            .as_str()
            .ok_or_else(|| "MKT-LSP channel types must be strings".to_owned())?;
        validate_identifier(channel_type, "MKT-LSP channel type")?;
        if !channel_type_ids.insert(channel_type) {
            return Err("MKT-LSP channel types must be duplicate-free".to_owned());
        }
    }

    match body.get("zero_conf_policy") {
        Some(Value::String(policy)) => {
            require_enum(
                policy,
                MKT_LSP_ZERO_CONF_POLICIES,
                "MKT-LSP zero_conf_policy",
            )?;
        }
        Some(policy @ Value::Object(_)) => validate_lsp_bounded_declaration(
            Some(policy),
            "Offering zero_conf_policy constraints",
            "mkt_lsp_invalid_market",
        )?,
        _ => {
            return Err(
                "MKT-LSP zero_conf_policy must be unsupported, client-policy, or exact provider constraints"
                    .to_owned(),
            );
        }
    }

    let lease_bounds = lsp_object(
        body.get("lease_bounds"),
        "MKT-LSP Offering lease_bounds",
        "mkt_lsp_invalid_market",
    )?;
    if lease_bounds.is_empty() || lease_bounds.len() > 4 {
        return Err("MKT-LSP lease_bounds requires 1-4 block-duration members".to_owned());
    }
    for (name, bound) in lease_bounds {
        lsp_bounded_ascii(
            name,
            "lease bound member name",
            64,
            "mkt_lsp_invalid_market",
        )?;
        canonical_decimal(
            bound
                .as_str()
                .ok_or_else(|| "MKT-LSP lease bounds must be decimal strings".to_owned())?,
            false,
            "MKT-LSP lease bound",
        )?;
    }

    let methods = body
        .get("payment_methods")
        .and_then(Value::as_array)
        .filter(|values| (1..=MKT_LSP_PAYMENT_METHODS.len()).contains(&values.len()))
        .ok_or_else(|| "MKT-LSP Offering requires 1-3 payment_methods".to_owned())?;
    let mut method_ids = BTreeSet::new();
    for method in methods {
        let method = method
            .as_str()
            .ok_or_else(|| "MKT-LSP payment methods must be strings".to_owned())?;
        require_enum(method, MKT_LSP_PAYMENT_METHODS, "MKT-LSP payment method")?;
        if !method_ids.insert(method) {
            return Err("MKT-LSP payment methods must be duplicate-free".to_owned());
        }
    }

    if lsp_required_string(body, "custody_class", "mkt_lsp_unsupported_version")?
        != MKT_LSP_CUSTODY_CLASS
    {
        return Err(lsp_error(
            "mkt_lsp_unsupported_version",
            "MKT-LSP v1 supports only custody class a1-coordinated-hold",
        ));
    }

    let proof_classes = body
        .get("reservation_proof_classes")
        .and_then(Value::as_array)
        .filter(|values| (1..=MKT_LSP_RESERVATION_PROOF_CLASSES.len()).contains(&values.len()))
        .ok_or_else(|| {
            lsp_error(
                "mkt_lsp_reservation_mismatch",
                "Offering requires 1-5 reservation_proof_classes",
            )
        })?;
    let mut seen_classes = BTreeSet::new();
    for class in proof_classes {
        let class = class.as_str().ok_or_else(|| {
            lsp_error(
                "mkt_lsp_reservation_mismatch",
                "reservation proof classes must be strings",
            )
        })?;
        if !MKT_LSP_RESERVATION_PROOF_CLASSES.contains(&class) {
            return Err(lsp_error(
                "mkt_lsp_reservation_mismatch",
                format!("reservation proof class {class:?} is not admitted"),
            ));
        }
        if !seen_classes.insert(class) {
            return Err(lsp_error(
                "mkt_lsp_reservation_mismatch",
                "reservation proof classes must be duplicate-free",
            ));
        }
    }
    Ok(())
}

fn validate_lsp_node_id(value: &str) -> Result<(), String> {
    if value.len() != 66
        || !(value.starts_with("02") || value.starts_with("03"))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(lsp_error(
            "mkt_lsp_invalid_node",
            "lsp_node_id must be an exact compressed secp256k1 node public key",
        ));
    }
    Ok(())
}

fn validate_lsp_registry_id(value: &str, subject: &str) -> Result<(), String> {
    let Some((namespace, reference)) = value.split_once(':') else {
        return Err(lsp_error(
            "mkt_lsp_invalid_market",
            format!("{subject} must be a collision-resistant registry identifier, not a label"),
        ));
    };
    if !(2..=16).contains(&namespace.len())
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || reference.is_empty()
        || reference.len() > 128
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(lsp_error(
            "mkt_lsp_invalid_market",
            format!("{subject} registry namespace or reference is noncanonical"),
        ));
    }
    Ok(())
}

fn validate_lsp_bounded_declaration(
    value: Option<&Value>,
    subject: &str,
    code: &str,
) -> Result<(), String> {
    let declaration = lsp_object(value, subject, code)?;
    if declaration.is_empty() || declaration.len() > 8 {
        return Err(lsp_error(
            code,
            format!("{subject} requires 1-8 bounded members"),
        ));
    }
    for (name, child) in declaration {
        lsp_bounded_ascii(name, subject, 64, code)?;
        match child {
            Value::String(child) => lsp_bounded_ascii(child, subject, 128, code)?,
            Value::Array(children) if children.len() <= 16 => {
                for child in children {
                    lsp_bounded_ascii(
                        child.as_str().ok_or_else(|| {
                            lsp_error(code, format!("{subject} list values must be strings"))
                        })?,
                        subject,
                        128,
                        code,
                    )?;
                }
            }
            _ => {
                return Err(lsp_error(
                    code,
                    format!("{subject} members must be bounded strings or string lists"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_mkt_lsp_visible_private(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    let body = Value::Object(envelope.body.clone());
    reject_lsp_custody_material(&body)?;
    validate_lsp_visible_members(&body)?;
    if event.kind == MKT_STATUS_KIND {
        for tag in event.tags.iter().filter(|tag| tag.name() == Some("state")) {
            let state = tag.value().unwrap_or_default();
            if !MKT_LSP_STATUS_BASE_STATES.contains(&state)
                && !MKT_LSP_STATUS_EXTENSION_STATES.contains(&state)
            {
                return Err(lsp_error(
                    "mkt_lsp_invalid_transition",
                    "Status state is not admitted by MKT-LSP version 1",
                ));
            }
        }
    }
    if event.kind == MKT_LSP_SERVICE_CONTRACT_KIND {
        validate_mkt_lsp_service_contract(event, envelope)?;
    }
    Ok(())
}

fn validate_lsp_visible_members(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                match name.as_str() {
                    "source" => validate_mkt_lsp_source_reference(child)?,
                    "custody_class" => {
                        if child.as_str() != Some(MKT_LSP_CUSTODY_CLASS) {
                            return Err(lsp_error(
                                "mkt_lsp_unsupported_version",
                                "MKT-LSP v1 supports only custody class a1-coordinated-hold",
                            ));
                        }
                    }
                    _ => validate_lsp_visible_members(child)?,
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_lsp_visible_members(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_mkt_lsp_source_reference(value: &Value) -> Result<(), String> {
    let source = lsp_object(
        Some(value),
        "MKT-LSP source reference",
        "mkt_lsp_lsps_mismatch",
    )?;
    lsp_closed(
        source,
        &[
            "protocol",
            "revision",
            "method",
            "request_sha256",
            "response_sha256",
            "external_id_sha256",
            "mapping_version",
        ],
        "MKT-LSP source reference",
        "mkt_lsp_lsps_mismatch",
    )?;
    let protocol = lsp_required_string(source, "protocol", "mkt_lsp_lsps_mismatch")?;
    if !MKT_LSP_SOURCE_PROTOCOLS.contains(&protocol) {
        return Err(lsp_error(
            "mkt_lsp_lsps_mismatch",
            "MKT-LSP v1 bridges only lsps0, lsps1, and lsps2 sources",
        ));
    }
    for member in ["revision", "method"] {
        lsp_bounded_ascii(
            lsp_required_string(source, member, "mkt_lsp_lsps_mismatch")?,
            member,
            128,
            "mkt_lsp_lsps_mismatch",
        )?;
    }
    for member in ["request_sha256", "response_sha256", "external_id_sha256"] {
        lsp_hex(
            lsp_required_string(source, member, "mkt_lsp_lsps_mismatch")?,
            member,
            "mkt_lsp_lsps_mismatch",
        )?;
    }
    if lsp_required_string(source, "mapping_version", "mkt_lsp_lsps_mismatch")?
        != MKT_LSP_SOURCE_MAPPING_VERSION
    {
        return Err(lsp_error(
            "mkt_lsp_lsps_mismatch",
            "source mapping_version must be mkt-lsp-v1",
        ));
    }
    Ok(())
}

const MKT_LSP_CONTRACT_DIGEST_MEMBERS: &[&str] = &[
    "lsps_request_sha256",
    "lsps_response_sha256",
    "external_effect_ids_sha256",
    "reservation_sha256",
    "funding_constraints_sha256",
    "verifier_policy_sha256",
    "recovery_package_sha256",
];

fn validate_mkt_lsp_service_contract(
    event: &Event,
    envelope: &MktPrivateEnvelope,
) -> Result<(), String> {
    if event
        .tags
        .iter()
        .any(|tag| tag.name() == Some("expiration"))
    {
        return Err(lsp_error(
            "mkt_lsp_service_contract_mismatch",
            "Service Contract has no NIP-40 expiration",
        ));
    }
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .collect::<Vec<_>>();
    let [counterparty] = counterparties.as_slice() else {
        return Err(lsp_error(
            "mkt_lsp_invalid_contract_signer",
            "Service Contract requires exactly one counterparty",
        ));
    };
    let role = single_value(event, "role", "MKT-LSP Service Contract")?;
    if !matches!(role, "requester" | "provider") {
        return Err(lsp_error(
            "mkt_lsp_invalid_contract_signer",
            "Service Contract role is invalid",
        ));
    }
    let counterparty = counterparty.as_slice();
    let counterparty_pubkey = counterparty.get(1).map(String::as_str).unwrap_or_default();
    let counterparty_role = counterparty.get(3).map(String::as_str).unwrap_or_default();
    let expected_counterparty_role = if role == "requester" {
        "provider"
    } else {
        "requester"
    };
    if counterparty_pubkey == event.pubkey || counterparty_role != expected_counterparty_role {
        return Err(lsp_error(
            "mkt_lsp_invalid_contract_signer",
            "Service Contract requires a distinct counterparty with the complementary role",
        ));
    }
    let alt = single_value(event, "alt", "MKT-LSP Service Contract")?;
    if alt != MKT_LSP_SERVICE_CONTRACT_ALT {
        return Err(lsp_error(
            "mkt_lsp_service_contract_mismatch",
            "Service Contract alt text is fixed",
        ));
    }
    let digest = single_value(event, "x", "MKT-LSP Service Contract")?;
    lower_hex_32(digest, "MKT-LSP contract digest")?;

    let mut quote_id = None;
    let mut order_id = None;
    let mut status_id = None;
    for tag in event.tags.iter().filter(|tag| tag.name() == Some("e")) {
        let values = tag.as_slice();
        let id = values.get(1).map(String::as_str).unwrap_or_default();
        let slot = match values.get(3).map(String::as_str) {
            Some("quote") => &mut quote_id,
            Some("order") => &mut order_id,
            Some("status") => &mut status_id,
            _ => {
                return Err(lsp_error(
                    "mkt_lsp_service_contract_mismatch",
                    "Service Contract has an unsupported event reference",
                ));
            }
        };
        if slot.replace(id).is_some() {
            return Err(lsp_error(
                "mkt_lsp_service_contract_mismatch",
                "Service Contract has a duplicate causal reference",
            ));
        }
    }
    let (Some(quote_id), Some(order_id)) = (quote_id, order_id) else {
        return Err(lsp_error(
            "mkt_lsp_service_contract_mismatch",
            "Service Contract requires one Quote and one Order reference",
        ));
    };

    lsp_closed(
        &envelope.body,
        &[
            "schema",
            "profile",
            "profile_version",
            "session_id",
            "contract",
            "contract_sha256",
            "signer_role",
        ],
        "Service Contract content",
        "mkt_lsp_service_contract_mismatch",
    )?;
    let signer_role = lsp_required_string(
        &envelope.body,
        "signer_role",
        "mkt_lsp_invalid_contract_signer",
    )?;
    if signer_role != role {
        return Err(lsp_error(
            "mkt_lsp_invalid_contract_signer",
            "Service Contract tag and content roles differ",
        ));
    }
    let content_digest = lsp_required_string(
        &envelope.body,
        "contract_sha256",
        "mkt_lsp_service_contract_mismatch",
    )?;
    if content_digest != digest {
        return Err(lsp_error(
            "mkt_lsp_service_contract_mismatch",
            "Service Contract x tag and contract_sha256 differ",
        ));
    }
    let contract = lsp_object(
        envelope.body.get("contract"),
        "MKT-LSP contract",
        "mkt_lsp_service_contract_mismatch",
    )?;
    lsp_closed(
        contract,
        &[
            "quote_event_id",
            "order_event_id",
            "accepted_status_event_id",
            "service",
            "lsps_request_sha256",
            "lsps_response_sha256",
            "external_effect_ids_sha256",
            "reservation_sha256",
            "funding_constraints_sha256",
            "verifier_policy_sha256",
            "recovery_package_sha256",
        ],
        "MKT-LSP contract",
        "mkt_lsp_service_contract_mismatch",
    )?;
    validate_identifier(
        lsp_required_string(contract, "service", "mkt_lsp_service_contract_mismatch")?,
        "MKT-LSP contract service",
    )
    .map_err(|detail| lsp_error("mkt_lsp_service_contract_mismatch", detail))?;
    for member in MKT_LSP_CONTRACT_DIGEST_MEMBERS {
        lsp_hex(
            lsp_required_string(contract, member, "mkt_lsp_service_contract_mismatch")?,
            member,
            "mkt_lsp_service_contract_mismatch",
        )?;
    }
    for (member, expected) in [("quote_event_id", quote_id), ("order_event_id", order_id)] {
        let value = lsp_required_string(contract, member, "mkt_lsp_service_contract_mismatch")?;
        lsp_hex(value, member, "mkt_lsp_service_contract_mismatch")?;
        if value != expected {
            return Err(lsp_error(
                "mkt_lsp_service_contract_mismatch",
                format!("{member} must equal the causal tag"),
            ));
        }
    }
    match contract.get("accepted_status_event_id") {
        Some(Value::Null) => {
            if status_id.is_some() {
                return Err(lsp_error(
                    "mkt_lsp_service_contract_mismatch",
                    "a firm-Quote contract forbids the status reference",
                ));
            }
        }
        Some(Value::String(value)) => {
            lsp_hex(
                value,
                "accepted_status_event_id",
                "mkt_lsp_service_contract_mismatch",
            )?;
            if status_id != Some(value.as_str()) {
                return Err(lsp_error(
                    "mkt_lsp_service_contract_mismatch",
                    "accepted_status_event_id must equal the status causal tag",
                ));
            }
        }
        _ => {
            return Err(lsp_error(
                "mkt_lsp_service_contract_mismatch",
                "accepted_status_event_id must be the accepted Status id or null",
            ));
        }
    }
    Ok(())
}

fn reject_lsp_custody_material(value: &Value) -> Result<(), String> {
    lsp_material_sweep(value, false)
}

fn reject_lsp_public_material(value: &Value) -> Result<(), String> {
    lsp_material_sweep(value, true)
}

fn lsp_material_sweep(value: &Value, public: bool) -> Result<(), String> {
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
                    "seed"
                        | "walletseed"
                        | "mnemonic"
                        | "nwc"
                        | "nwcstring"
                        | "nwcuri"
                        | "macaroon"
                        | "nodemacaroon"
                        | "channelbackup"
                        | "channelbackupsecret"
                        | "commitmentsecret"
                        | "commitmentsecrets"
                        | "spendkey"
                        | "spendkeys"
                        | "preimage"
                        | "preimages"
                        | "claimprivatekey"
                        | "refundprivatekey"
                        | "privatekey"
                        | "signingnonce"
                        | "signingnonces"
                        | "exitpackage"
                        | "rawexitpackage"
                        | "coupon"
                        | "coupons"
                        | "couponcode"
                        | "accesstoken"
                        | "bearertoken"
                        | "authorization"
                        | "password"
                ) {
                    return Err(lsp_error(
                        "mkt_lsp_custody_material_forbidden",
                        format!("market record contains custody member {name:?}"),
                    ));
                }
                if public
                    && matches!(
                        normalized.as_str(),
                        "invoice"
                            | "invoices"
                            | "bolt11"
                            | "bolt12offer"
                            | "paymentrequest"
                            | "paymenthash"
                            | "paymenthashes"
                            | "scid"
                            | "scids"
                            | "routehint"
                            | "routehints"
                            | "channelid"
                            | "channelids"
                            | "fundingtxid"
                            | "fundingoutpoint"
                            | "fundingplan"
                            | "transactionplan"
                            | "address"
                            | "onchainaddress"
                            | "refundaddress"
                            | "privateendpoint"
                            | "privaterelayurl"
                    )
                {
                    return Err(lsp_error(
                        "mkt_lsp_custody_material_forbidden",
                        format!("public record contains private member {name:?}"),
                    ));
                }
                lsp_material_sweep(child, public)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                lsp_material_sweep(child, public)?;
            }
        }
        Value::String(value) => {
            if public && lsp_value_is_invoice_shaped(value) {
                return Err(lsp_error(
                    "mkt_lsp_custody_material_forbidden",
                    "public record contains a Lightning invoice value",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn lsp_value_is_invoice_shaped(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.len() >= 20
        && ["lnbc", "lntb", "lntbs", "lnbcrt"]
            .iter()
            .any(|prefix| lowercase.starts_with(prefix))
        && lowercase.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn lsp_object<'a>(
    value: Option<&'a Value>,
    subject: &str,
    code: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| lsp_error(code, format!("{subject} must be an object")))
}

fn lsp_closed(
    object: &Map<String, Value>,
    allowed: &[&str],
    subject: &str,
    code: &str,
) -> Result<(), String> {
    if let Some(member) = object
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        return Err(lsp_error(
            code,
            format!("{subject} contains unknown member {member:?}"),
        ));
    }
    Ok(())
}

fn lsp_required_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    code: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| lsp_error(code, format!("{name} must be a string")))
}

fn lsp_bounded_ascii(value: &str, subject: &str, maximum: usize, code: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(lsp_error(
            code,
            format!("{subject} is invalid or unbounded"),
        ));
    }
    Ok(())
}

fn lsp_hex(value: &str, subject: &str, code: &str) -> Result<(), String> {
    lower_hex_32(value, subject).map_err(|detail| lsp_error(code, detail))
}

fn lsp_error(code: &str, detail: impl fmt::Display) -> String {
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
            ("liquid", "lightning") => "submarine",
            ("lightning", "liquid") => "reverse",
            ("chain", "liquid") | ("liquid", "chain") => "chain",
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
            | "liquid_transaction"
            | "liquid_output"
            | "liquid_spend"
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
        "liquid_transaction" | "liquid_output" | "liquid_spend" => Some("liquid"),
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
        | "liquid_transaction"
        | "claim"
        | "refund" => lower_hex_32(reference, "MKT-SWP evidence reference")
            .map_err(|detail| swp_error("swp_evidence_mismatch", detail)),
        "bitcoin_output" | "bitcoin_spend" | "liquid_output" | "liquid_spend" => {
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
                        | "blinding_key"
                        | "blindingkey"
                        | "value_blinder"
                        | "valueblinder"
                        | "asset_blinder"
                        | "assetblinder"
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
    if let Some((network, rail)) = value.rsplit_once(":btc:") {
        validate_swp_network_id(network)?;
        if !matches!(rail, "chain" | "lightning") {
            return Err(swp_error(
                "swp_invalid_asset_id",
                "asset ID has an unknown rail",
            ));
        }
        return Ok((network, rail));
    }
    let Some((network, liquid)) = value.split_once(":elements:") else {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "asset ID has the wrong shape",
        ));
    };
    let Some(asset) = liquid.strip_suffix(":liquid") else {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "Elements asset ID has an unknown rail",
        ));
    };
    validate_swp_network_id(network)?;
    if asset.len() != 64
        || !asset
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(swp_error(
            "swp_invalid_asset_id",
            "Elements asset ID is not lowercase 32-byte hex",
        ));
    }
    Ok((network, "liquid"))
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
    // MKT-P2P extends the private recipient-role vocabulary for its
    // Resolution kind; every other private kind keeps the base roles.
    let p2p_resolution = event.kind == MKT_P2P_RESOLUTION_KIND;
    let counterparties = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some("p"))
        .collect::<Vec<_>>();
    let mut role_marked = 0;
    for tag in counterparties {
        let values = tag.as_slice();
        let role_matches = values.get(3).is_some_and(|role| {
            if p2p_resolution {
                MKT_P2P_RECIPIENT_ROLES.contains(&role.as_str())
            } else {
                matches!(role.as_str(), "requester" | "provider")
            }
        });
        if role_matches {
            let pubkey = values.get(1).map(String::as_str).unwrap_or_default();
            lower_hex_32(pubkey, "private MKT counterparty")?;
            role_marked += 1;
        }
    }
    if role_marked == 0 {
        if p2p_resolution {
            return Err(p2p_error(
                "mkt_p2p_invalid_resolution",
                "Resolution requires role-marked p tags",
            ));
        }
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

pub fn parse_unique_json(content: &str, subject: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(content);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{subject} is invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{subject} has trailing data: {error}"))?;
    Ok(value.0)
}

pub fn parse_json_without_duplicate_members(content: &str, subject: &str) -> Result<Value, String> {
    parse_unique_json(content, subject)
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
