use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::domain::{
    MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_OFFERING_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND,
    MKT_RFQ_KIND, MKT_STATUS_KIND,
};

pub const TBDEX_SOURCE_PROTOCOL: &str = "tbdex";
pub const TBDEX_SOURCE_REVISION: &str = "protocol-1.0@7546a079bb860e7ede8125739b7970810a2df314";
pub const TBDEX_MAPPING_VERSION: &str = "immortal.tbdex-to-nip-mkt.v1";
pub const TBDEX_MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TbdexVocabulary {
    pub source_kind: String,
    pub target_kind: Option<u16>,
    pub required_data_fields: Vec<String>,
    pub optional_data_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TbdexFieldMapping {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TbdexRefusalCode {
    UnrepresentableAuthority,
    UnrepresentableState,
}

impl TbdexRefusalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnrepresentableAuthority => "tbdex_unrepresentable_authority",
            Self::UnrepresentableState => "tbdex_unrepresentable_state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TbdexRefusal {
    pub code: TbdexRefusalCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TbdexLegacyTranslation {
    pub source_protocol: String,
    pub source_revision: String,
    pub mapping_version: String,
    pub source_digest: String,
    pub source_kind: String,
    pub source_id: String,
    pub source_exchange_id: Option<String>,
    pub target_kind: Option<u16>,
    pub executable: bool,
    pub field_mappings: Vec<TbdexFieldMapping>,
    pub dropped_fields: Vec<String>,
    pub defaulted_fields: Vec<String>,
    pub ambiguous_fields: Vec<String>,
    pub refusals: Vec<TbdexRefusal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TbdexTranslationErrorCode {
    MessageTooLarge,
    InvalidJson,
    DuplicateJsonMember,
    InvalidShape,
    UnsupportedProtocol,
    UnsupportedKind,
    PrivateDataMismatch,
    UnsupportedCanonicalValue,
}

impl TbdexTranslationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MessageTooLarge => "tbdex_message_too_large",
            Self::InvalidJson => "tbdex_invalid_json",
            Self::DuplicateJsonMember => "tbdex_duplicate_json_member",
            Self::InvalidShape => "tbdex_invalid_shape",
            Self::UnsupportedProtocol => "tbdex_unsupported_protocol",
            Self::UnsupportedKind => "tbdex_unsupported_kind",
            Self::PrivateDataMismatch => "tbdex_private_data_mismatch",
            Self::UnsupportedCanonicalValue => "tbdex_unsupported_canonical_value",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbdexTranslationError {
    pub code: TbdexTranslationErrorCode,
    pub detail: String,
}

impl fmt::Display for TbdexTranslationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for TbdexTranslationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TbdexPrivateDataStatus {
    Detached,
    Verified { commitments: Vec<String> },
}

pub fn tbdex_vocabulary(source_kind: &str) -> Option<TbdexVocabulary> {
    let (target_kind, required, optional): (Option<u16>, &[&str], &[&str]) = match source_kind {
        "balance" => (None, &["currencyCode", "available"], &[]),
        "cancel" => (Some(MKT_CANCEL_KIND), &[], &["reason"]),
        "close" => (Some(MKT_CLOSE_KIND), &[], &["reason", "success"]),
        "offering" => (
            Some(MKT_OFFERING_KIND),
            &[
                "description",
                "payin",
                "payout",
                "payoutUnitsPerPayinUnit",
                "cancellation",
            ],
            &["requiredClaims"],
        ),
        "order" => (Some(MKT_ORDER_KIND), &[], &[]),
        "orderinstructions" => (Some(MKT_STATUS_KIND), &["payin", "payout"], &[]),
        "orderstatus" => (Some(MKT_STATUS_KIND), &["status"], &["details"]),
        "quote" => (
            Some(MKT_QUOTE_KIND),
            &["expiresAt", "payoutUnitsPerPayinUnit", "payin", "payout"],
            &[],
        ),
        "rfq" => (
            Some(MKT_RFQ_KIND),
            &["offeringId", "payin", "payout"],
            &["claimsHash"],
        ),
        _ => return None,
    };
    Some(TbdexVocabulary {
        source_kind: source_kind.to_owned(),
        target_kind,
        required_data_fields: strings(required),
        optional_data_fields: strings(optional),
    })
}

pub fn translate_tbdex_message(
    raw_source: &[u8],
) -> Result<TbdexLegacyTranslation, TbdexTranslationError> {
    if raw_source.len() > TBDEX_MAX_MESSAGE_BYTES {
        return Err(error(
            TbdexTranslationErrorCode::MessageTooLarge,
            format!("tbDEX source exceeds {TBDEX_MAX_MESSAGE_BYTES} bytes"),
        ));
    }
    let source_text = std::str::from_utf8(raw_source).map_err(|_| {
        error(
            TbdexTranslationErrorCode::InvalidJson,
            "tbDEX source is not UTF-8",
        )
    })?;
    let source = parse_unique_json(source_text)?;
    let source_object = source.as_object().ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX source must be an object",
        )
    })?;
    require_known_fields(
        source_object,
        &["metadata", "data", "signature", "privateData"],
        "tbDEX source",
    )?;
    let metadata = required_object(source_object, "metadata")?;
    require_known_fields(
        metadata,
        &[
            "from",
            "to",
            "kind",
            "id",
            "exchangeId",
            "externalId",
            "createdAt",
            "updatedAt",
            "protocol",
        ],
        "tbDEX metadata",
    )?;
    let data = required_object(source_object, "data")?;
    let source_kind = required_nonempty_string(metadata, "kind", "tbDEX metadata")?;
    let source_id = required_nonempty_string(metadata, "id", "tbDEX metadata")?;
    let protocol = required_nonempty_string(metadata, "protocol", "tbDEX metadata")?;
    if protocol != "1.0" {
        return Err(error(
            TbdexTranslationErrorCode::UnsupportedProtocol,
            format!("tbDEX protocol {protocol:?} is unsupported"),
        ));
    }
    let vocabulary = tbdex_vocabulary(source_kind).ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::UnsupportedKind,
            format!("tbDEX kind {source_kind:?} is unsupported"),
        )
    })?;
    validate_tbdex_shape(source_object, metadata, data, source_kind)?;
    if source_kind == "rfq" {
        verify_rfq_private_data(source_object, data)?;
    }
    let source_from = required_nonempty_string(metadata, "from", "tbDEX metadata")?;
    let source_to = optional_string(metadata, "to", "tbDEX metadata")?;
    let source_signature = required_nonempty_string(source_object, "signature", "tbDEX source")?;

    let mut mapping = mapping_for(source_kind, data);
    if metadata.contains_key("to") {
        mapping
            .dropped_fields
            .push("metadata.to (DID authority)".to_owned());
    }
    if metadata.contains_key("updatedAt") {
        mapping
            .dropped_fields
            .push("metadata.updatedAt (not trusted Nostr event time)".to_owned());
    }
    if metadata.contains_key("externalId") {
        mapping
            .ambiguous_fields
            .push("metadata.externalId -> profile external-effect idempotency binding".to_owned());
    }
    if metadata.contains_key("exchangeId") {
        mapping
            .ambiguous_fields
            .push("metadata.exchangeId -> random NIP-MKT session".to_owned());
    }
    let mut refusals = vec![TbdexRefusal {
        code: TbdexRefusalCode::UnrepresentableAuthority,
        detail: authority_refusal(source_from, source_to, source_signature),
    }];
    if let Some(detail) = mapping.state_refusal {
        refusals.push(TbdexRefusal {
            code: TbdexRefusalCode::UnrepresentableState,
            detail,
        });
    }

    Ok(TbdexLegacyTranslation {
        source_protocol: TBDEX_SOURCE_PROTOCOL.to_owned(),
        source_revision: TBDEX_SOURCE_REVISION.to_owned(),
        mapping_version: TBDEX_MAPPING_VERSION.to_owned(),
        source_digest: lower_hex(&Sha256::digest(raw_source)),
        source_kind: source_kind.to_owned(),
        source_id: source_id.to_owned(),
        source_exchange_id: metadata
            .get("exchangeId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        target_kind: vocabulary.target_kind,
        executable: false,
        field_mappings: mapping.field_mappings,
        dropped_fields: mapping.dropped_fields,
        defaulted_fields: mapping.defaulted_fields,
        ambiguous_fields: mapping.ambiguous_fields,
        refusals,
    })
}

pub fn validate_tbdex_rfq_private_data(
    raw_source: &[u8],
) -> Result<TbdexPrivateDataStatus, TbdexTranslationError> {
    if raw_source.len() > TBDEX_MAX_MESSAGE_BYTES {
        return Err(error(
            TbdexTranslationErrorCode::MessageTooLarge,
            format!("tbDEX source exceeds {TBDEX_MAX_MESSAGE_BYTES} bytes"),
        ));
    }
    let source_text = std::str::from_utf8(raw_source).map_err(|_| {
        error(
            TbdexTranslationErrorCode::InvalidJson,
            "tbDEX source is not UTF-8",
        )
    })?;
    let source = parse_unique_json(source_text)?;
    let source_object = source.as_object().ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX source must be an object",
        )
    })?;
    let metadata = required_object(source_object, "metadata")?;
    let data = required_object(source_object, "data")?;
    let source_kind = required_nonempty_string(metadata, "kind", "tbDEX metadata")?;
    validate_tbdex_shape(source_object, metadata, data, source_kind)?;
    if required_nonempty_string(metadata, "protocol", "tbDEX metadata")? != "1.0" {
        return Err(error(
            TbdexTranslationErrorCode::UnsupportedProtocol,
            "tbDEX RFQ private data requires protocol 1.0",
        ));
    }
    if source_kind != "rfq" {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX privateData is defined only for RFQ",
        ));
    }
    verify_rfq_private_data(source_object, data)
}

struct Mapping {
    field_mappings: Vec<TbdexFieldMapping>,
    dropped_fields: Vec<String>,
    defaulted_fields: Vec<String>,
    ambiguous_fields: Vec<String>,
    state_refusal: Option<String>,
}

fn mapping_for(source_kind: &str, data: &Map<String, Value>) -> Mapping {
    let mut mapping = Mapping {
        field_mappings: Vec::new(),
        dropped_fields: strings(&[
            "signature (JOSE cannot become a NIP-01 signature)",
            "metadata.from (DID authority)",
            "metadata.createdAt (not trusted Nostr created_at)",
        ]),
        defaulted_fields: Vec::new(),
        ambiguous_fields: strings(&["metadata.id -> immutable NIP-MKT d"]),
        state_refusal: None,
    };
    match source_kind {
        "balance" => {
            mapping.ambiguous_fields.extend(strings(&[
                "data.currencyCode -> profile asset ID",
                "data.available -> independently proved capacity",
            ]));
            mapping.state_refusal = Some(
                "a tbDEX custodial Balance has no NIP-MKT base record and cannot prove available liquidity"
                    .to_owned(),
            );
        }
        "offering" => {
            add_mapping(&mut mapping, "data.description", "Offering.content.summary");
            add_mapping(
                &mut mapping,
                "data.cancellation",
                "profile cancellation policy",
            );
            mapping.ambiguous_fields.extend(strings(&[
                "data.payin/data.payout currencyCode labels -> collision-resistant profile asset IDs",
                "data.payoutUnitsPerPayinUnit -> quoted price with units and pinned feed",
                "data.requiredClaims -> MKT-PFI qualification policy event",
                "data.payin/data.payout payment method schemas -> private/off-relay collection policy",
            ]));
        }
        "rfq" => {
            add_mapping(&mut mapping, "data.offeringId", "RFQ offering reference");
            add_mapping(&mut mapping, "data.payin.amount", "profile amount");
            add_mapping(
                &mut mapping,
                "data.*Hash",
                "privacy commitment in profile content",
            );
            mapping
                .dropped_fields
                .push("privateData cleartext (off-relay presentation only)".to_owned());
            mapping.ambiguous_fields.extend(strings(&[
                "data.offeringId -> exact Nostr address",
                "data.payin/data.payout kind -> profile rail and asset IDs",
                "data.claimsHash -> MKT-PFI policy and presentation commitments",
            ]));
        }
        "quote" => {
            add_mapping(&mut mapping, "data.expiresAt", "Quote expiration");
            add_mapping(&mut mapping, "data.payin/payout", "profile quote terms");
            mapping.defaulted_fields.extend(strings(&[
                "quote=indicative (projection only)",
                "reservation=none (projection only)",
            ]));
            mapping.ambiguous_fields.extend(strings(&[
                "exchangeId -> exact RFQ event ID",
                "data.payoutUnitsPerPayinUnit -> quoted price with units and pinned feed",
                "data.payin/data.payout currencyCode labels -> collision-resistant profile asset IDs",
                "data.payin/data.payout subtotal/fee/total -> atomic-unit amounts and fee allocation",
                "custody, reversibility, recourse, and settlement evidence",
            ]));
        }
        "order" => {
            mapping
                .ambiguous_fields
                .push("exchangeId -> exact accepted Quote event ID".to_owned());
        }
        "orderinstructions" => {
            mapping.defaulted_fields.push(
                "state=funding_required (projection only; no execution authority)".to_owned(),
            );
            mapping.dropped_fields.extend(strings(&[
                "data.payin.link and instruction (direct protected channel only)",
                "data.payout.link and instruction (direct protected channel only)",
            ]));
            mapping.ambiguous_fields.extend(strings(&[
                "exchangeId -> exact Order event ID",
                "missing per-author Status seq and previous reference",
                "instruction bytes -> digest, expiry, and direct-channel correlation",
            ]));
            mapping.state_refusal = Some(
                "OrderInstructions lacks the exact Order reference, Status sequence, instruction digest, and profile execution authority required by NIP-MKT"
                    .to_owned(),
            );
        }
        "orderstatus" => {
            if let Some(status) = data.get("status").and_then(Value::as_str) {
                let candidate = candidate_status(status);
                add_mapping(
                    &mut mapping,
                    "data.status",
                    &format!("Status.state candidate {candidate}"),
                );
            }
            mapping.dropped_fields.push(
                "data.details (unbounded human claim; retain only in authorized local audit)"
                    .to_owned(),
            );
            mapping.ambiguous_fields.extend(strings(&[
                "exchangeId -> exact Order event ID",
                "missing per-author Status seq and previous reference",
                "rail evidence rung and settlement authority",
            ]));
            mapping.state_refusal = Some(
                "tbDEX OrderStatus has no sequence chain or profile evidence, so payment/refund states cannot advance NIP-MKT state"
                    .to_owned(),
            );
        }
        "close" => {
            add_mapping(
                &mut mapping,
                "data.reason",
                "Close loss/reconciliation detail",
            );
            let candidate = match data.get("success").and_then(Value::as_bool) {
                Some(true) => "completed",
                Some(false) | None => "unresolved",
            };
            mapping
                .defaulted_fields
                .push(format!("outcome={candidate} (projection only)"));
            mapping.ambiguous_fields.extend(strings(&[
                "exchangeId -> exact Order event ID",
                "terminal_at, evidence inventory, recovery, and loss accounting",
                "success=false -> rejected/cancelled/expired/failed/disputed/unresolved",
            ]));
            mapping.state_refusal = Some(
                "tbDEX Close success/reason cannot establish a NIP-MKT terminal outcome or settlement"
                    .to_owned(),
            );
        }
        "cancel" => {
            add_mapping(&mut mapping, "data.reason", "Cancel.reason");
            mapping
                .defaulted_fields
                .push("action=request (a legacy Cancel has no immediate effect)".to_owned());
            mapping.ambiguous_fields.push(
                "exchangeId -> exact Order event ID; pre-Order legacy cancellation has no base target"
                    .to_owned(),
            );
        }
        _ => {}
    }
    mapping
}

fn candidate_status(status: &str) -> &'static str {
    match status {
        "PAYIN_PENDING" => "funding_required",
        "PAYIN_INITIATED" => "executing",
        "PAYIN_SETTLED" | "PAYOUT_PENDING" | "PAYOUT_INITIATED" | "PAYOUT_SETTLED" => {
            "settlement_pending"
        }
        "REFUND_PENDING" | "REFUND_INITIATED" | "REFUND_SETTLED" | "REFUND_FAILED" => {
            "refund_pending"
        }
        "PAYIN_FAILED" | "PAYIN_EXPIRED" | "PAYOUT_FAILED" => "failed",
        _ => "unsupported",
    }
}

fn authority_refusal(source_from: &str, source_to: Option<&str>, signature: &str) -> String {
    let did_fields = source_from.starts_with("did:")
        || source_to.is_some_and(|counterparty| counterparty.starts_with("did:"));
    if did_fields || signature.contains('.') {
        "tbDEX DID/JOSE authority cannot be emulated or upgraded to Nostr signer authority"
            .to_owned()
    } else {
        "the source signature scheme is not a verified NIP-01 signer authority".to_owned()
    }
}

fn validate_tbdex_shape(
    source: &Map<String, Value>,
    metadata: &Map<String, Value>,
    data: &Map<String, Value>,
    source_kind: &str,
) -> Result<(), TbdexTranslationError> {
    require_known_fields(
        source,
        &["metadata", "data", "signature", "privateData"],
        "tbDEX source",
    )?;
    required_nonempty_string(source, "signature", "tbDEX source")?;
    validate_metadata(metadata, source_kind)?;
    validate_data_shape(data, source_kind)?;
    match source.get("privateData") {
        Some(private_data) if source_kind == "rfq" => {
            validate_private_data_shape(private_data.as_object().ok_or_else(|| {
                error(
                    TbdexTranslationErrorCode::InvalidShape,
                    "tbDEX privateData must be an object",
                )
            })?)?;
        }
        Some(_) => {
            return Err(error(
                TbdexTranslationErrorCode::InvalidShape,
                "tbDEX privateData is permitted only on RFQ",
            ));
        }
        None => {}
    }
    Ok(())
}

fn validate_metadata(
    metadata: &Map<String, Value>,
    source_kind: &str,
) -> Result<(), TbdexTranslationError> {
    let is_resource = matches!(source_kind, "balance" | "offering");
    let known = if is_resource {
        &["from", "kind", "id", "createdAt", "updatedAt", "protocol"][..]
    } else {
        &[
            "from",
            "to",
            "kind",
            "id",
            "exchangeId",
            "externalId",
            "createdAt",
            "protocol",
        ][..]
    };
    require_known_fields(metadata, known, "tbDEX metadata")?;
    let from = required_nonempty_string(metadata, "from", "tbDEX metadata")?;
    if !from.starts_with("did:") {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX metadata.from must be a DID",
        ));
    }
    required_nonempty_string(metadata, "kind", "tbDEX metadata")?;
    required_nonempty_string(metadata, "id", "tbDEX metadata")?;
    required_nonempty_string(metadata, "createdAt", "tbDEX metadata")?;
    required_nonempty_string(metadata, "protocol", "tbDEX metadata")?;
    optional_string(metadata, "updatedAt", "tbDEX metadata")?;
    if !is_resource {
        let to = required_nonempty_string(metadata, "to", "tbDEX metadata")?;
        if !to.starts_with("did:") {
            return Err(error(
                TbdexTranslationErrorCode::InvalidShape,
                "tbDEX metadata.to must be a DID",
            ));
        }
        required_nonempty_string(metadata, "exchangeId", "tbDEX metadata")?;
        optional_string(metadata, "externalId", "tbDEX metadata")?;
        if metadata.contains_key("externalId") && source_kind != "order" {
            return Err(error(
                TbdexTranslationErrorCode::InvalidShape,
                "tbDEX metadata.externalId is permitted only on Order",
            ));
        }
    }
    Ok(())
}

fn validate_data_shape(
    data: &Map<String, Value>,
    source_kind: &str,
) -> Result<(), TbdexTranslationError> {
    match source_kind {
        "balance" => {
            require_known_fields(data, &["currencyCode", "available"], "tbDEX balance data")?;
            required_nonempty_string(data, "currencyCode", "tbDEX balance data")?;
            required_decimal(data, "available", "tbDEX balance data")?;
        }
        "cancel" => {
            require_known_fields(data, &["reason"], "tbDEX cancel data")?;
            optional_string(data, "reason", "tbDEX cancel data")?;
        }
        "close" => {
            require_known_fields(data, &["reason", "success"], "tbDEX close data")?;
            optional_string(data, "reason", "tbDEX close data")?;
            optional_bool(data, "success", "tbDEX close data")?;
        }
        "offering" => validate_offering_data(data)?,
        "order" => require_known_fields(data, &[], "tbDEX order data")?,
        "orderinstructions" => {
            require_known_fields(data, &["payin", "payout"], "tbDEX OrderInstructions data")?;
            validate_payment_instruction(
                required_object(data, "payin")?,
                "tbDEX OrderInstructions payin",
            )?;
            validate_payment_instruction(
                required_object(data, "payout")?,
                "tbDEX OrderInstructions payout",
            )?;
        }
        "orderstatus" => {
            require_known_fields(data, &["status", "details"], "tbDEX OrderStatus data")?;
            let status = required_nonempty_string(data, "status", "tbDEX OrderStatus data")?;
            if !matches!(
                status,
                "PAYIN_PENDING"
                    | "PAYIN_INITIATED"
                    | "PAYIN_SETTLED"
                    | "PAYIN_FAILED"
                    | "PAYIN_EXPIRED"
                    | "PAYOUT_PENDING"
                    | "PAYOUT_INITIATED"
                    | "PAYOUT_SETTLED"
                    | "PAYOUT_FAILED"
                    | "REFUND_PENDING"
                    | "REFUND_INITIATED"
                    | "REFUND_SETTLED"
                    | "REFUND_FAILED"
            ) {
                return Err(error(
                    TbdexTranslationErrorCode::InvalidShape,
                    format!("tbDEX OrderStatus status {status:?} is unsupported"),
                ));
            }
            optional_string(data, "details", "tbDEX OrderStatus data")?;
        }
        "quote" => {
            require_known_fields(
                data,
                &["expiresAt", "payoutUnitsPerPayinUnit", "payin", "payout"],
                "tbDEX Quote data",
            )?;
            required_nonempty_string(data, "expiresAt", "tbDEX Quote data")?;
            required_decimal(data, "payoutUnitsPerPayinUnit", "tbDEX Quote data")?;
            validate_quote_details(required_object(data, "payin")?, "tbDEX Quote payin")?;
            validate_quote_details(required_object(data, "payout")?, "tbDEX Quote payout")?;
        }
        "rfq" => {
            require_known_fields(
                data,
                &["offeringId", "claimsHash", "payin", "payout"],
                "tbDEX RFQ data",
            )?;
            required_nonempty_string(data, "offeringId", "tbDEX RFQ data")?;
            optional_string(data, "claimsHash", "tbDEX RFQ data")?;
            let payin = required_object(data, "payin")?;
            require_known_fields(
                payin,
                &["amount", "kind", "paymentDetailsHash"],
                "tbDEX RFQ payin",
            )?;
            required_decimal(payin, "amount", "tbDEX RFQ payin")?;
            required_nonempty_string(payin, "kind", "tbDEX RFQ payin")?;
            optional_string(payin, "paymentDetailsHash", "tbDEX RFQ payin")?;
            let payout = required_object(data, "payout")?;
            require_known_fields(payout, &["kind", "paymentDetailsHash"], "tbDEX RFQ payout")?;
            required_nonempty_string(payout, "kind", "tbDEX RFQ payout")?;
            optional_string(payout, "paymentDetailsHash", "tbDEX RFQ payout")?;
        }
        _ => {
            return Err(error(
                TbdexTranslationErrorCode::UnsupportedKind,
                format!("tbDEX kind {source_kind:?} is unsupported"),
            ));
        }
    }
    Ok(())
}

fn validate_offering_data(data: &Map<String, Value>) -> Result<(), TbdexTranslationError> {
    require_known_fields(
        data,
        &[
            "description",
            "payin",
            "payout",
            "payoutUnitsPerPayinUnit",
            "requiredClaims",
            "cancellation",
        ],
        "tbDEX Offering data",
    )?;
    required_nonempty_string(data, "description", "tbDEX Offering data")?;
    required_decimal(data, "payoutUnitsPerPayinUnit", "tbDEX Offering data")?;
    let payin = required_object(data, "payin")?;
    validate_offering_side(payin, false, "tbDEX Offering payin")?;
    let payout = required_object(data, "payout")?;
    validate_offering_side(payout, true, "tbDEX Offering payout")?;
    optional_object(data, "requiredClaims", "tbDEX Offering data")?;
    let cancellation = required_object(data, "cancellation")?;
    require_known_fields(
        cancellation,
        &["enabled", "termsUrl", "terms"],
        "tbDEX Offering cancellation",
    )?;
    required_bool(cancellation, "enabled", "tbDEX Offering cancellation")?;
    optional_string(cancellation, "termsUrl", "tbDEX Offering cancellation")?;
    optional_string(cancellation, "terms", "tbDEX Offering cancellation")?;
    Ok(())
}

fn validate_offering_side(
    side: &Map<String, Value>,
    payout: bool,
    subject: &str,
) -> Result<(), TbdexTranslationError> {
    require_known_fields(side, &["currencyCode", "min", "max", "methods"], subject)?;
    required_nonempty_string(side, "currencyCode", subject)?;
    optional_decimal(side, "min", subject)?;
    optional_decimal(side, "max", subject)?;
    let methods = side
        .get("methods")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            error(
                TbdexTranslationErrorCode::InvalidShape,
                format!("{subject} requires array \"methods\""),
            )
        })?;
    for method in methods {
        let method = method.as_object().ok_or_else(|| {
            error(
                TbdexTranslationErrorCode::InvalidShape,
                format!("{subject} methods must be objects"),
            )
        })?;
        require_known_fields(
            method,
            &[
                "kind",
                "name",
                "description",
                "group",
                "requiredPaymentDetails",
                "min",
                "max",
                "fee",
                "estimatedSettlementTime",
            ],
            "tbDEX Offering payment method",
        )?;
        required_nonempty_string(method, "kind", "tbDEX Offering payment method")?;
        optional_string(method, "name", "tbDEX Offering payment method")?;
        optional_string(method, "description", "tbDEX Offering payment method")?;
        optional_string(method, "group", "tbDEX Offering payment method")?;
        optional_object(
            method,
            "requiredPaymentDetails",
            "tbDEX Offering payment method",
        )?;
        optional_decimal(method, "min", "tbDEX Offering payment method")?;
        optional_decimal(method, "max", "tbDEX Offering payment method")?;
        optional_decimal(method, "fee", "tbDEX Offering payment method")?;
        optional_nonnegative_number(
            method,
            "estimatedSettlementTime",
            "tbDEX Offering payment method",
        )?;
        if payout && !method.contains_key("estimatedSettlementTime") {
            return Err(error(
                TbdexTranslationErrorCode::InvalidShape,
                "tbDEX Offering payout method requires estimatedSettlementTime",
            ));
        }
    }
    Ok(())
}

fn validate_payment_instruction(
    instruction: &Map<String, Value>,
    subject: &str,
) -> Result<(), TbdexTranslationError> {
    require_known_fields(instruction, &["link", "instruction"], subject)?;
    optional_string(instruction, "link", subject)?;
    optional_string(instruction, "instruction", subject)?;
    Ok(())
}

fn validate_quote_details(
    details: &Map<String, Value>,
    subject: &str,
) -> Result<(), TbdexTranslationError> {
    require_known_fields(
        details,
        &["currencyCode", "subtotal", "fee", "total"],
        subject,
    )?;
    required_nonempty_string(details, "currencyCode", subject)?;
    required_decimal(details, "subtotal", subject)?;
    optional_decimal(details, "fee", subject)?;
    required_decimal(details, "total", subject)?;
    Ok(())
}

fn validate_private_data_shape(
    private_data: &Map<String, Value>,
) -> Result<(), TbdexTranslationError> {
    require_known_fields(
        private_data,
        &["salt", "claims", "payin", "payout"],
        "tbDEX privateData",
    )?;
    required_nonempty_string(private_data, "salt", "tbDEX privateData")?;
    if let Some(claims) = private_data.get("claims") {
        if !claims.is_array() {
            return Err(error(
                TbdexTranslationErrorCode::InvalidShape,
                "tbDEX privateData claims must be an array",
            ));
        }
    }
    for side_name in ["payin", "payout"] {
        let Some(side) = optional_object(private_data, side_name, "tbDEX privateData")? else {
            continue;
        };
        require_known_fields(side, &["paymentDetails"], "tbDEX privateData side")?;
        required_object(side, "paymentDetails")?;
    }
    Ok(())
}

fn verify_rfq_private_data(
    source: &Map<String, Value>,
    data: &Map<String, Value>,
) -> Result<TbdexPrivateDataStatus, TbdexTranslationError> {
    let Some(private_data) = source.get("privateData") else {
        return Ok(TbdexPrivateDataStatus::Detached);
    };
    let private_data = private_data.as_object().ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX privateData must be an object",
        )
    })?;
    let salt = required_nonempty_string(private_data, "salt", "tbDEX privateData")?;
    if salt.len() > 256 || salt.chars().any(char::is_control) {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX privateData salt must be bounded text",
        ));
    }

    let mut commitments = Vec::new();
    verify_commitment(
        data.get("claimsHash"),
        private_data.get("claims"),
        salt,
        "claims",
        &mut commitments,
    )?;
    verify_commitment(
        nested(data, &["payin", "paymentDetailsHash"]),
        nested(private_data, &["payin", "paymentDetails"]),
        salt,
        "payin.paymentDetails",
        &mut commitments,
    )?;
    verify_commitment(
        nested(data, &["payout", "paymentDetailsHash"]),
        nested(private_data, &["payout", "paymentDetails"]),
        salt,
        "payout.paymentDetails",
        &mut commitments,
    )?;
    if commitments.is_empty() {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            "tbDEX attached privateData must verify at least one commitment",
        ));
    }
    Ok(TbdexPrivateDataStatus::Verified { commitments })
}

fn verify_commitment(
    expected: Option<&Value>,
    private: Option<&Value>,
    salt: &str,
    field: &str,
    verified: &mut Vec<String>,
) -> Result<(), TbdexTranslationError> {
    match (expected, private) {
        (None, None) => Ok(()),
        (Some(expected), Some(private)) => {
            let expected = expected.as_str().ok_or_else(|| {
                error(
                    TbdexTranslationErrorCode::InvalidShape,
                    format!("tbDEX {field} commitment must be a string"),
                )
            })?;
            let actual = private_data_digest(salt, private)?;
            if actual != expected {
                return Err(error(
                    TbdexTranslationErrorCode::PrivateDataMismatch,
                    format!("tbDEX privateData commitment mismatch for {field}"),
                ));
            }
            verified.push(field.to_owned());
            Ok(())
        }
        _ => Err(error(
            TbdexTranslationErrorCode::PrivateDataMismatch,
            format!("tbDEX {field} commitment and private value must be present together"),
        )),
    }
}

fn private_data_digest(salt: &str, value: &Value) -> Result<String, TbdexTranslationError> {
    let mut canonical = String::from("[");
    canonical_json(&Value::String(salt.to_owned()), &mut canonical)?;
    canonical.push(',');
    canonical_json(value, &mut canonical)?;
    canonical.push(']');
    Ok(base64url_no_pad(&Sha256::digest(canonical.as_bytes())))
}

fn canonical_json(value: &Value, output: &mut String) -> Result<(), TbdexTranslationError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(|json_error| {
                error(
                    TbdexTranslationErrorCode::InvalidJson,
                    format!("failed to encode tbDEX private value: {json_error}"),
                )
            })?)
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut names = values.keys().collect::<Vec<_>>();
            names.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, name) in names.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                canonical_json(&Value::String(name.clone()), output)?;
                output.push(':');
                let value = values.get(name).ok_or_else(|| {
                    error(
                        TbdexTranslationErrorCode::InvalidJson,
                        "tbDEX privateData object changed during canonicalization",
                    )
                })?;
                canonical_json(value, output)?;
            }
            output.push('}');
        }
        Value::Number(_) => {
            return Err(error(
                TbdexTranslationErrorCode::UnsupportedCanonicalValue,
                "numeric privateData requires a complete RFC 8785 number encoder",
            ));
        }
    }
    Ok(())
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut chunk_bytes = chunk.iter().copied();
        let Some(first) = chunk_bytes.next() else {
            continue;
        };
        let second = chunk_bytes.next().unwrap_or(0);
        let third = chunk_bytes.next().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)],
            ));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    output
}

fn parse_unique_json(source: &str) -> Result<Value, TbdexTranslationError> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = UniqueJsonValue::deserialize(&mut deserializer).map_err(|json_error| {
        let detail = json_error.to_string();
        let code = if detail.contains("duplicate JSON member") {
            TbdexTranslationErrorCode::DuplicateJsonMember
        } else {
            TbdexTranslationErrorCode::InvalidJson
        };
        error(code, format!("tbDEX source JSON is invalid: {detail}"))
    })?;
    deserializer.end().map_err(|json_error| {
        error(
            TbdexTranslationErrorCode::InvalidJson,
            format!("tbDEX source has trailing JSON: {json_error}"),
        )
    })?;
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
        formatter.write_str("a JSON value with unique object members")
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
            .ok_or_else(|| E::custom("JSON number is not finite"))
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
        while let Some(name) = object.next_key::<String>()? {
            if values.contains_key(&name) {
                return Err(A::Error::custom(format!("duplicate JSON member {name:?}")));
            }
            let value = object.next_value::<UniqueJsonValue>()?;
            values.insert(name, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Map<String, Value>, TbdexTranslationError> {
    object.get(name).and_then(Value::as_object).ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("tbDEX source requires object {name:?}"),
        )
    })
}

fn required_nonempty_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<&'a str, TbdexTranslationError> {
    let value = object.get(name).and_then(Value::as_str).ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} requires string {name:?}"),
        )
    })?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} {name:?} must be non-empty bounded text"),
        ));
    }
    Ok(value)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<Option<&'a str>, TbdexTranslationError> {
    let Some(value) = object.get(name) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} {name:?} must be a string"),
        )
    })?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} {name:?} must be non-empty bounded text"),
        ));
    }
    Ok(Some(value))
}

fn required_bool(
    object: &Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<bool, TbdexTranslationError> {
    object.get(name).and_then(Value::as_bool).ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} requires boolean {name:?}"),
        )
    })
}

fn optional_bool(
    object: &Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<Option<bool>, TbdexTranslationError> {
    object
        .get(name)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                error(
                    TbdexTranslationErrorCode::InvalidShape,
                    format!("{subject} {name:?} must be a boolean"),
                )
            })
        })
        .transpose()
}

fn required_decimal<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<&'a str, TbdexTranslationError> {
    let value = required_nonempty_string(object, name, subject)?;
    validate_decimal(value, name, subject)?;
    Ok(value)
}

fn optional_decimal<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<Option<&'a str>, TbdexTranslationError> {
    let Some(value) = optional_string(object, name, subject)? else {
        return Ok(None);
    };
    validate_decimal(value, name, subject)?;
    Ok(Some(value))
}

fn validate_decimal(value: &str, name: &str, subject: &str) -> Result<(), TbdexTranslationError> {
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    let valid = !integer.is_empty()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.is_none_or(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        && parts.next().is_none();
    if !valid {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} {name:?} must be a decimal string"),
        ));
    }
    Ok(())
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<Option<&'a Map<String, Value>>, TbdexTranslationError> {
    object
        .get(name)
        .map(|value| {
            value.as_object().ok_or_else(|| {
                error(
                    TbdexTranslationErrorCode::InvalidShape,
                    format!("{subject} {name:?} must be an object"),
                )
            })
        })
        .transpose()
}

fn optional_nonnegative_number(
    object: &Map<String, Value>,
    name: &str,
    subject: &str,
) -> Result<Option<f64>, TbdexTranslationError> {
    let Some(value) = object.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0);
    value.map(Some).ok_or_else(|| {
        error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} {name:?} must be a non-negative number"),
        )
    })
}

fn require_known_fields(
    object: &Map<String, Value>,
    known: &[&str],
    subject: &str,
) -> Result<(), TbdexTranslationError> {
    if let Some(unknown) = object.keys().find(|name| !known.contains(&name.as_str())) {
        return Err(error(
            TbdexTranslationErrorCode::InvalidShape,
            format!("{subject} contains unknown field {unknown:?}"),
        ));
    }
    Ok(())
}

fn nested<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    let (first, rest) = names.split_first()?;
    let mut value = object.get(*first)?;
    for name in rest {
        value = value.as_object()?.get(*name)?;
    }
    Some(value)
}

fn add_mapping(mapping: &mut Mapping, source: &str, target: &str) {
    mapping.field_mappings.push(TbdexFieldMapping {
        source: source.to_owned(),
        target: target.to_owned(),
    });
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn error(code: TbdexTranslationErrorCode, detail: impl Into<String>) -> TbdexTranslationError {
    TbdexTranslationError {
        code,
        detail: detail.into(),
    }
}
