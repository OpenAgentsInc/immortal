//! Transport-neutral MKT-SWP requester execution and recovery.
//!
//! The embedding wallet owns transport, signing, secrets, chain access, and
//! broadcast. This module validates signed protocol records and public rail
//! inputs, then exposes bounded requests to those external capabilities.

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ENVELOPE_SCHEMA, MKT_ORDER_KIND,
        MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
        MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport, Tag, validate_mkt_private_raw,
        validate_mkt_swp_evidence_reference,
    },
    mkt_swp_verify::{
        BitcoinNetwork, Musig2Tweak, ScriptInstruction, Timelock, Transaction, TransactionOutput,
        check_cltv, check_csv, musig2_aggregate_key, musig2_aggregate_partial_signatures,
        musig2_tweaked_aggregate_key, parse_bolt11, parse_swap_script, sha256, tagged_hash,
        tapleaf_hash, taproot_key_spend_sighash, validate_timelock_ladder, verify_control_block,
        verify_musig2_partial_signature_with_tweaks, verify_musig2_signature, verify_preimage,
    },
};

const SNAPSHOT_SCHEMA: &str = "openagents.mkt-swp.client-snapshot.v2";
const EXIT_SCHEMA: &str = "openagents.mkt-swp.exit.v1";
const MAX_SIGNED_RECORDS: usize = 512;
const MAX_STATUS_SEQUENCE: u64 = 511;
const MAX_EXIT_PACKAGES: usize = 16;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXTERNAL_EFFECTS: usize = 64;
const MAX_WIRE_EVENT_BYTES: usize = 512 * 1024;
const COOPERATIVE_SIGNING_SCHEMA: &str = "openagents.mkt-swp.cooperative-signing.v1";
const COOPERATIVE_COMMITMENT_FIELD: u8 = 1 << 0;
const COOPERATIVE_PUBLIC_NONCE_FIELD: u8 = 1 << 1;
const COOPERATIVE_PUBLIC_NONCES_FIELD: u8 = 1 << 2;
const COOPERATIVE_PARTIAL_FIELD: u8 = 1 << 3;
const COOPERATIVE_PARTIALS_FIELD: u8 = 1 << 4;
const COOPERATIVE_FINAL_FIELD: u8 = 1 << 5;
const COOPERATIVE_ABORT_FIELDS: u8 = 1 << 6;
pub const REQUESTER_SESSION_VIEW_SCHEMA: &str = "openagents.mkt-swp.requester-session-view.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapClientError {
    pub code: &'static str,
    pub detail: String,
}

impl SwapClientError {
    pub(crate) fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for SwapClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SwapClientError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapType {
    Submarine,
    Reverse,
    Chain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Requester,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotePolicy<'a> {
    pub quote_class: &'a str,
    pub reservation: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterEffectBinding {
    pub role: String,
    pub leg_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterExitPackageCommitment {
    pub participant_role: String,
    pub leg_id: String,
    pub path: String,
    pub package_mode: String,
    pub package_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterContractLocalInputs {
    pub effect_bindings: Vec<RequesterEffectBinding>,
    pub exit_package_commitments: Vec<RequesterExitPackageCommitment>,
}

pub struct RequesterOrderInput<'a> {
    pub rfq: &'a Event,
    pub quote: &'a Event,
    pub created_at: u64,
    pub observed_at: u64,
    pub distinct: &'a str,
    pub selection: Option<Map<String, Value>>,
}

pub struct RequesterContractSigningInput<'a> {
    pub rfq: &'a Event,
    pub quote: &'a Event,
    pub order: &'a Event,
    pub order_observed_at: u64,
    pub created_at: u64,
    pub distinct: &'a str,
    pub contract: Value,
}

impl RequesterContractLocalInputs {
    pub fn for_swap_type(swap_type: SwapType) -> Self {
        let topology = requester_topology(swap_type);
        Self {
            effect_bindings: std::iter::once(RequesterEffectBinding {
                role: topology.funding_effect_role.to_owned(),
                leg_id: topology.funding_leg_id.to_owned(),
            })
            .chain(topology.exits.iter().map(|exit| RequesterEffectBinding {
                role: if exit.path == "claim" {
                    "chain_claim".to_owned()
                } else {
                    "chain_refund".to_owned()
                },
                leg_id: exit.leg_id.to_owned(),
            }))
            .collect(),
            exit_package_commitments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryProvenance {
    LocallySigned,
    Direct,
    GiftWrap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecordDelivery {
    event_id: String,
    raw_signed_event: Vec<u8>,
    raw_wrap_event: Option<Vec<u8>>,
    wrap_event_id: Option<String>,
    sender_pubkey: String,
    observed_at: u64,
    provenance: DeliveryProvenance,
}

impl SignedRecordDelivery {
    pub fn from_locally_signed(
        raw_signed_event: Vec<u8>,
        observed_at: u64,
    ) -> Result<Self, SwapClientError> {
        Self::from_unwrapped(
            raw_signed_event,
            observed_at,
            DeliveryProvenance::LocallySigned,
        )
    }

    pub fn from_direct(
        raw_signed_event: Vec<u8>,
        observed_at: u64,
    ) -> Result<Self, SwapClientError> {
        Self::from_unwrapped(raw_signed_event, observed_at, DeliveryProvenance::Direct)
    }

    fn from_unwrapped(
        raw_signed_event: Vec<u8>,
        observed_at: u64,
        provenance: DeliveryProvenance,
    ) -> Result<Self, SwapClientError> {
        let event = validate_mkt_private_raw(&raw_signed_event, &swp_profile_support())
            .map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("signed-record delivery bytes violate MKT-SWP: {error}"),
                )
            })?
            .event()
            .clone();
        let evidence = Self {
            event_id: event.id.clone(),
            raw_signed_event,
            raw_wrap_event: None,
            wrap_event_id: None,
            sender_pubkey: event.pubkey.clone(),
            observed_at,
            provenance,
        };
        evidence.validate(&event)?;
        Ok(evidence)
    }

    pub fn from_delivered(
        delivered: &crate::market::DeliveredMktRecord,
        observed_at: u64,
    ) -> Result<Self, SwapClientError> {
        let raw_wrap_event = delivered.raw_wrap_event().ok_or_else(|| {
            SwapClientError::new(
                "swp_unresolved_loss",
                "gift-wrap delivery did not originate from exact outer bytes",
            )
        })?;
        let record = delivered.record();
        let evidence = Self {
            event_id: record.event().id.clone(),
            raw_signed_event: record.raw_signed_event().to_vec(),
            raw_wrap_event: Some(raw_wrap_event.to_vec()),
            wrap_event_id: Some(delivered.wrap_event_id().to_owned()),
            sender_pubkey: delivered.sender().to_owned(),
            observed_at,
            provenance: DeliveryProvenance::GiftWrap,
        };
        evidence.validate(record.event())?;
        Ok(evidence)
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn raw_signed_event(&self) -> &[u8] {
        &self.raw_signed_event
    }

    pub fn raw_wrap_event(&self) -> Option<&[u8]> {
        self.raw_wrap_event.as_deref()
    }

    pub fn provenance(&self) -> DeliveryProvenance {
        self.provenance
    }

    pub fn validate(&self, event: &Event) -> Result<(), SwapClientError> {
        if self.raw_signed_event.is_empty() || self.raw_signed_event.len() > MAX_WIRE_EVENT_BYTES {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "signed-record delivery bytes are empty or exceed their bound",
            ));
        }
        let decoded = validate_mkt_private_raw(&self.raw_signed_event, &swp_profile_support())
            .map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("signed-record delivery bytes violate MKT-SWP: {error}"),
                )
            })?
            .event()
            .clone();
        if &decoded != event || self.event_id != event.id {
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "signed-record delivery bytes do not match the projected event",
            ));
        }
        if self.sender_pubkey != event.pubkey {
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "signed-record delivery sender does not match the signed event",
            ));
        }
        match (
            self.provenance,
            self.wrap_event_id.as_deref(),
            self.raw_wrap_event.as_deref(),
        ) {
            (DeliveryProvenance::GiftWrap, Some(wrap_event_id), Some(raw_wrap_event)) => {
                require_lower_hex_32(wrap_event_id, "gift-wrap event ID")?;
                if raw_wrap_event.is_empty() || raw_wrap_event.len() > MAX_WIRE_EVENT_BYTES {
                    return Err(SwapClientError::new(
                        "swp_unresolved_loss",
                        "gift-wrap delivery bytes are empty or exceed their bound",
                    ));
                }
                let wrap: Event = serde_json::from_slice(raw_wrap_event).map_err(|error| {
                    SwapClientError::new(
                        "swp_unresolved_loss",
                        format!("gift-wrap delivery bytes are invalid JSON: {error}"),
                    )
                })?;
                wrap.validate_structure()
                    .and_then(|()| wrap.validate_crypto())
                    .map_err(|error| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            format!("gift-wrap delivery is invalid: {error}"),
                        )
                    })?;
                if wrap.kind != 1_059 || wrap.id != wrap_event_id {
                    return Err(SwapClientError::new(
                        "swp_idempotency_conflict",
                        "gift-wrap delivery bytes do not match the verified wrap event",
                    ));
                }
            }
            (DeliveryProvenance::GiftWrap, _, _) => {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "gift-wrap delivery evidence is incomplete",
                ));
            }
            (DeliveryProvenance::Direct | DeliveryProvenance::LocallySigned, None, None) => {}
            (DeliveryProvenance::Direct | DeliveryProvenance::LocallySigned, _, _) => {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "non-wrapped delivery evidence carries gift-wrap bytes",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterFeeView {
    pub fee_bps: String,
    pub provider_fee: String,
    pub miner_fee_budget: String,
    pub lightning_routing_fee_budget: String,
    pub maximum_total_fee: String,
    pub fee_payer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterPriceFeedView {
    pub url: String,
    pub value_pointer: String,
    pub observed_value: String,
    pub response_sha256: String,
    pub observed_at: u64,
    pub max_age_seconds: u64,
}

impl RequesterPriceFeedView {
    pub fn from_pinned_terms(value: &Value) -> Result<Option<Self>, SwapClientError> {
        if value.is_null() {
            return Ok(None);
        }
        let feed = object(value, "Quote price feed")?;
        if feed.len() != 6 {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "price-feed pin has unknown or missing members",
            ));
        }
        let url = require_string(feed, "url", None, "swp_contract_terms_mismatch")?;
        let value_pointer =
            require_string(feed, "value_pointer", None, "swp_contract_terms_mismatch")?;
        let observed_value =
            require_string(feed, "observed_value", None, "swp_contract_terms_mismatch")?;
        let response_sha256 =
            require_string(feed, "response_sha256", None, "swp_contract_terms_mismatch")?;
        validate_price_feed_url(url)?;
        validate_json_pointer(value_pointer)?;
        canonical_decimal_string(observed_value, "price-feed observed value")?;
        require_lower_hex_32(response_sha256, "price-feed response digest")?;
        let observed_at = feed
            .get("observed_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "price-feed observation time is invalid",
                )
            })?;
        let max_age_seconds = feed
            .get("max_age_seconds")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "price-feed maximum age is invalid",
                )
            })?;
        Ok(Some(Self {
            url: url.to_owned(),
            value_pointer: value_pointer.to_owned(),
            observed_value: observed_value.to_owned(),
            response_sha256: response_sha256.to_owned(),
            observed_at,
            max_age_seconds,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterQuoteView {
    pub rfq_id: String,
    pub quote_id: String,
    pub provider_pubkey: String,
    pub quote_class: String,
    pub reservation_class: String,
    pub swap_type: SwapType,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub input_amount: String,
    pub output_amount: String,
    pub amount_equation: String,
    pub rounding: String,
    pub clock_skew_seconds: String,
    pub expires_at: u64,
    pub effective_acceptance_deadline: u64,
    pub fees: RequesterFeeView,
    pub price_feed: Option<RequesterPriceFeedView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequesterTimelineKind {
    Rfq,
    Quote,
    Order,
    Contract,
    Status,
    Cancel,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterTimelineEntry {
    pub event_id: String,
    pub author: ParticipantRole,
    pub kind: RequesterTimelineKind,
    pub created_at: u64,
    pub sequence: Option<u64>,
    pub state: Option<String>,
    pub causal_event_ids: Vec<String>,
    pub conflict: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequesterVerificationState {
    QuoteVerified,
    OrderVerified,
    AwaitingProviderContract,
    ContractTermsVerified,
    TerminalVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequesterTerminalState {
    Open,
    Completed,
    Refunded,
    Cancelled,
    Rejected,
    Expired,
    Failed,
    Disputed,
    Unresolved,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterTerminalView {
    pub claimed_state: RequesterTerminalState,
    pub canonical_close_id: Option<String>,
    pub close_event_ids: Vec<String>,
    pub principal_unresolved: Option<String>,
    pub loss_accounting_complete: bool,
    pub local_effects_verified: bool,
    pub watch_terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterVerificationView {
    pub state: RequesterVerificationState,
    pub local_verification_required: bool,
    pub funding_authorized: bool,
    pub status_gaps: Vec<String>,
    pub status_forks: Vec<String>,
    pub invalid_status_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequesterSessionView {
    pub schema: String,
    pub session_id: String,
    pub quote: RequesterQuoteView,
    pub timeline: Vec<RequesterTimelineEntry>,
    pub verification: RequesterVerificationView,
    pub terminal: RequesterTerminalView,
    pub deliveries: Vec<SignedRecordDelivery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancellation<'a> {
    pub action: &'a str,
    pub reason: &'a str,
    pub request_id: Option<&'a str>,
    pub accepted_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseOutcome<'a> {
    pub outcome: &'a str,
    pub terminal_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusState<'a> {
    pub sequence: u64,
    pub previous: Option<&'a str>,
    pub base_state: &'a str,
    pub swp_state: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativePrevout {
    pub amount: String,
    pub script_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeTweak {
    pub value: String,
    pub xonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeSigningContext {
    pub schema: String,
    pub order_id: String,
    pub swap_contract_sha256: String,
    pub effect_id: String,
    pub leg_id: String,
    pub unsigned_transaction: String,
    pub transaction_sha256: String,
    pub input_index: u32,
    pub prevouts: Vec<CooperativePrevout>,
    pub signature_hash: String,
    pub sighash_type: String,
    pub participant_keys: Vec<String>,
    pub tweaks: Vec<CooperativeTweak>,
    pub aggregate_key: String,
    pub exit_package_sha256: String,
    pub latest_safe_height: String,
}

impl CooperativeSigningContext {
    pub fn validate(&self) -> Result<(), SwapClientError> {
        if self.schema != COOPERATIVE_SIGNING_SCHEMA {
            return Err(musig_error("cooperative signing schema is unsupported"));
        }
        require_lower_hex_32(&self.order_id, "cooperative signing Order ID")?;
        require_lower_hex_32(
            &self.swap_contract_sha256,
            "cooperative signing Swap Contract digest",
        )?;
        require_lower_hex_32(&self.effect_id, "cooperative signing effect ID")?;
        require_lower_hex_32(
            &self.exit_package_sha256,
            "cooperative signing exit package digest",
        )?;
        if !matches!(self.leg_id.as_str(), "source" | "destination") {
            return Err(musig_error("cooperative signing leg is unsupported"));
        }
        if self.effect_id != effect_id(&self.order_id, "cooperative_sign", &self.leg_id)? {
            return Err(musig_error(
                "cooperative signing effect ID does not bind the Order and leg",
            ));
        }
        if self.sighash_type != "DEFAULT" {
            return Err(musig_error(
                "cooperative signing requires Taproot SIGHASH_DEFAULT",
            ));
        }
        let latest_safe_height = canonical_amount(&self.latest_safe_height)
            .map_err(|_| musig_error("cooperative signing latest safe height is not canonical"))?;
        if latest_safe_height == 0 || u32::try_from(latest_safe_height).is_err() {
            return Err(musig_error(
                "cooperative signing latest safe height is outside bounds",
            ));
        }
        require_lower_hex_32(&self.transaction_sha256, "cooperative transaction digest")?;
        require_lower_hex_32(&self.signature_hash, "cooperative signature hash")?;
        require_lower_hex_32(&self.aggregate_key, "cooperative aggregate key")?;
        let raw = decode_hex(
            &self.unsigned_transaction,
            "cooperative unsigned transaction",
        )?;
        if lower_hex(&sha256(&raw)) != self.transaction_sha256 {
            return Err(musig_error("cooperative transaction digest mismatch"));
        }
        let transaction = Transaction::parse(&raw)
            .map_err(|error| musig_error(format!("cooperative transaction is invalid: {error}")))?;
        if transaction.serialize(false).map_err(core_musig_error)? != raw
            || transaction
                .inputs
                .iter()
                .any(|input| !input.witness.is_empty())
        {
            return Err(musig_error(
                "cooperative signing transaction must be canonical and unsigned",
            ));
        }
        if usize::try_from(self.input_index).ok().is_none_or(|index| {
            index >= transaction.inputs.len() || self.prevouts.len() != transaction.inputs.len()
        }) {
            return Err(musig_error(
                "cooperative signing prevouts do not cover the selected input",
            ));
        }
        let prevouts = self
            .prevouts
            .iter()
            .map(|prevout| {
                Ok(TransactionOutput {
                    value_sat: canonical_amount(&prevout.amount)?,
                    script_pubkey: decode_hex(
                        &prevout.script_pubkey,
                        "cooperative prevout scriptPubKey",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, SwapClientError>>()?;
        let keys = cooperative_public_keys(&self.participant_keys)?;
        let tweaks = cooperative_tweaks(&self.tweaks)?;
        let aggregate = musig2_tweaked_aggregate_key(&keys, &tweaks).map_err(core_musig_error)?;
        if lower_hex(&aggregate.serialize()) != self.aggregate_key {
            return Err(musig_error("cooperative aggregate key mismatch"));
        }
        let selected = prevouts
            .get(usize::try_from(self.input_index).map_err(|_| {
                musig_error("cooperative signing input index exceeds platform bounds")
            })?)
            .ok_or_else(|| musig_error("cooperative signing input is missing"))?;
        let mut expected_script_pubkey = vec![0x51, 0x20];
        expected_script_pubkey.extend_from_slice(&aggregate.serialize());
        if selected.script_pubkey != expected_script_pubkey {
            return Err(musig_error(
                "cooperative prevout does not pay the tweaked aggregate key",
            ));
        }
        let signature_hash = taproot_key_spend_sighash(
            &transaction,
            &prevouts,
            usize::try_from(self.input_index)
                .map_err(|_| musig_error("cooperative signing input index"))?,
        )
        .map_err(core_musig_error)?;
        if lower_hex(&signature_hash) != self.signature_hash {
            return Err(musig_error("cooperative signature hash mismatch"));
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, SwapClientError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|error| {
            musig_error(format!("could not serialize cooperative context: {error}"))
        })?;
        Ok(lower_hex(&sha256(&canonical_json(&value)?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeSigningAction {
    NonceCommitment,
    PublicNonce,
    PartialSignature,
    FinalSignature,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeSigningMessage {
    pub context: CooperativeSigningContext,
    pub context_sha256: String,
    pub participant_index: u8,
    pub action: CooperativeSigningAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_nonces: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_signatures: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
}

impl CooperativeSigningMessage {
    pub fn nonce_commitment(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        nonce_commitment: [u8; 32],
    ) -> Result<Self, SwapClientError> {
        Self::new(
            context,
            role,
            CooperativeSigningAction::NonceCommitment,
            Some(lower_hex(&nonce_commitment)),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    pub fn public_nonce(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        public_nonce: [u8; 66],
    ) -> Result<Self, SwapClientError> {
        Self::new(
            context,
            role,
            CooperativeSigningAction::PublicNonce,
            Some(lower_hex(&sha256(&public_nonce))),
            Some(lower_hex(&public_nonce)),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    pub fn partial_signature(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        public_nonces: [[u8; 66]; 2],
        partial_signature: [u8; 32],
    ) -> Result<Self, SwapClientError> {
        Self::new(
            context,
            role,
            CooperativeSigningAction::PartialSignature,
            None,
            None,
            Some(public_nonces.iter().map(|nonce| lower_hex(nonce)).collect()),
            Some(lower_hex(&partial_signature)),
            None,
            None,
            None,
            None,
        )
    }

    pub fn final_signature(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        public_nonces: [[u8; 66]; 2],
        partial_signatures: [[u8; 32]; 2],
    ) -> Result<Self, SwapClientError> {
        let keys = cooperative_public_keys(&context.participant_keys)?;
        let tweaks = cooperative_tweaks(&context.tweaks)?;
        let signature_hash =
            fixed_hex::<32>(&context.signature_hash, "cooperative signature hash")?;
        let signature = musig2_aggregate_partial_signatures(
            &keys,
            &public_nonces,
            &tweaks,
            &signature_hash,
            &partial_signatures,
        )
        .map_err(core_musig_error)?;
        Self::new(
            context,
            role,
            CooperativeSigningAction::FinalSignature,
            None,
            None,
            Some(public_nonces.iter().map(|nonce| lower_hex(nonce)).collect()),
            None,
            Some(
                partial_signatures
                    .iter()
                    .map(|partial| lower_hex(partial))
                    .collect(),
            ),
            Some(lower_hex(&signature)),
            None,
            None,
        )
    }

    pub fn aborted(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        reason: &str,
    ) -> Result<Self, SwapClientError> {
        Self::new(
            context,
            role,
            CooperativeSigningAction::Aborted,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(reason.to_owned()),
            Some("script_path".to_owned()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        context: CooperativeSigningContext,
        role: ParticipantRole,
        action: CooperativeSigningAction,
        nonce_commitment: Option<String>,
        public_nonce: Option<String>,
        public_nonces: Option<Vec<String>>,
        partial_signature: Option<String>,
        partial_signatures: Option<Vec<String>>,
        final_signature: Option<String>,
        abort_reason: Option<String>,
        fallback: Option<String>,
    ) -> Result<Self, SwapClientError> {
        let context_sha256 = context.sha256()?;
        let participant_index = match role {
            ParticipantRole::Requester => 0,
            ParticipantRole::Provider => 1,
        };
        let message = Self {
            context,
            context_sha256,
            participant_index,
            action,
            nonce_commitment,
            public_nonce,
            public_nonces,
            partial_signature,
            partial_signatures,
            final_signature,
            abort_reason,
            fallback,
        };
        message.validate(role)?;
        Ok(message)
    }

    pub fn validate(&self, role: ParticipantRole) -> Result<(), SwapClientError> {
        self.context.validate()?;
        if self.context.sha256()? != self.context_sha256 {
            return Err(musig_error("cooperative signing context digest mismatch"));
        }
        let expected_index = match role {
            ParticipantRole::Requester => 0,
            ParticipantRole::Provider => 1,
        };
        if self.participant_index != expected_index {
            return Err(musig_error(
                "cooperative contribution signer does not match participant key order",
            ));
        }
        let keys = cooperative_public_keys(&self.context.participant_keys)?;
        let tweaks = cooperative_tweaks(&self.context.tweaks)?;
        let message = fixed_hex::<32>(&self.context.signature_hash, "cooperative signature hash")?;
        match self.action {
            CooperativeSigningAction::NonceCommitment => {
                self.require_only(COOPERATIVE_COMMITMENT_FIELD)?;
                require_lower_hex_32(
                    self.nonce_commitment
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative nonce commitment is missing"))?,
                    "cooperative nonce commitment",
                )?;
            }
            CooperativeSigningAction::PublicNonce => {
                self.require_only(COOPERATIVE_COMMITMENT_FIELD | COOPERATIVE_PUBLIC_NONCE_FIELD)?;
                let commitment = fixed_hex::<32>(
                    self.nonce_commitment
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative nonce commitment is missing"))?,
                    "cooperative nonce commitment",
                )?;
                let public_nonce = fixed_hex::<66>(
                    self.public_nonce
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative public nonce is missing"))?,
                    "cooperative public nonce",
                )?;
                if sha256(&public_nonce) != commitment {
                    return Err(musig_error(
                        "cooperative public nonce does not open its commitment",
                    ));
                }
                parse_public_nonce(&public_nonce)?;
            }
            CooperativeSigningAction::PartialSignature => {
                self.require_only(COOPERATIVE_PUBLIC_NONCES_FIELD | COOPERATIVE_PARTIAL_FIELD)?;
                let nonces = cooperative_public_nonces(
                    self.public_nonces
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative public nonce set is missing"))?,
                )?;
                let partial = fixed_hex::<32>(
                    self.partial_signature
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative partial signature is missing"))?,
                    "cooperative partial signature",
                )?;
                verify_musig2_partial_signature_with_tweaks(
                    &keys,
                    &nonces,
                    &tweaks,
                    usize::from(self.participant_index),
                    &message,
                    &partial,
                )
                .map_err(core_musig_error)?;
            }
            CooperativeSigningAction::FinalSignature => {
                self.require_only(
                    COOPERATIVE_PUBLIC_NONCES_FIELD
                        | COOPERATIVE_PARTIALS_FIELD
                        | COOPERATIVE_FINAL_FIELD,
                )?;
                let nonces = cooperative_public_nonces(
                    self.public_nonces
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative public nonce set is missing"))?,
                )?;
                let partials = cooperative_partial_signatures(
                    self.partial_signatures.as_deref().ok_or_else(|| {
                        musig_error("cooperative partial signature set is missing")
                    })?,
                )?;
                let expected = musig2_aggregate_partial_signatures(
                    &keys, &nonces, &tweaks, &message, &partials,
                )
                .map_err(core_musig_error)?;
                let supplied = fixed_hex::<64>(
                    self.final_signature
                        .as_deref()
                        .ok_or_else(|| musig_error("cooperative final signature is missing"))?,
                    "cooperative final signature",
                )?;
                if supplied != expected {
                    return Err(musig_error("cooperative final signature mismatch"));
                }
            }
            CooperativeSigningAction::Aborted => {
                self.require_only(COOPERATIVE_ABORT_FIELDS)?;
                if !matches!(
                    self.abort_reason.as_deref(),
                    Some(
                        "timeout"
                            | "counterparty_unavailable"
                            | "transcript_invalid"
                            | "wallet_refused"
                    )
                ) || self.fallback.as_deref() != Some("script_path")
                {
                    return Err(musig_error(
                        "cooperative abort must select a bounded reason and script-path fallback",
                    ));
                }
            }
        }
        Ok(())
    }

    fn require_only(&self, expected: u8) -> Result<(), SwapClientError> {
        let mut actual = 0_u8;
        actual |= u8::from(self.nonce_commitment.is_some()) * COOPERATIVE_COMMITMENT_FIELD;
        actual |= u8::from(self.public_nonce.is_some()) * COOPERATIVE_PUBLIC_NONCE_FIELD;
        actual |= u8::from(self.public_nonces.is_some()) * COOPERATIVE_PUBLIC_NONCES_FIELD;
        actual |= u8::from(self.partial_signature.is_some()) * COOPERATIVE_PARTIAL_FIELD;
        actual |= u8::from(self.partial_signatures.is_some()) * COOPERATIVE_PARTIALS_FIELD;
        actual |= u8::from(self.final_signature.is_some()) * COOPERATIVE_FINAL_FIELD;
        if self.abort_reason.is_some() != self.fallback.is_some() {
            return Err(musig_error(
                "cooperative abort reason and fallback must appear together",
            ));
        }
        actual |= u8::from(self.abort_reason.is_some()) * COOPERATIVE_ABORT_FIELDS;
        if actual != expected {
            return Err(musig_error(
                "cooperative signing action has an invalid field shape",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapContractReferences<'a> {
    pub order_id: &'a str,
    pub quote_id: &'a str,
    pub accepted_status_id: Option<&'a str>,
}

impl ParticipantRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Provider => "provider",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Requester => Self::Provider,
            Self::Provider => Self::Requester,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapClientConfig {
    pub session_id: String,
    pub requester_pubkey: String,
    pub provider_pubkey: String,
    pub offering_address: String,
}

impl SwapClientConfig {
    pub fn validate(&self) -> Result<(), SwapClientError> {
        require_lower_hex_32(&self.session_id, "session ID")?;
        require_lower_hex_32(&self.requester_pubkey, "requester pubkey")?;
        require_lower_hex_32(&self.provider_pubkey, "provider pubkey")?;
        if self.requester_pubkey == self.provider_pubkey {
            return Err(SwapClientError::new(
                "swp_contract_signer_invalid",
                "requester and provider must use distinct keys",
            ));
        }
        let mut address = self.offering_address.split(':');
        if address.next() != Some("39601")
            || address.next() != Some(self.provider_pubkey.as_str())
            || address.next().is_none_or(str::is_empty)
            || address.next().is_some()
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Offering address does not belong to the provider",
            ));
        }
        Ok(())
    }

    fn pubkey_for(&self, role: ParticipantRole) -> &str {
        match role {
            ParticipantRole::Requester => &self.requester_pubkey,
            ParticipantRole::Provider => &self.provider_pubkey,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MktSigningRequest {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
    pub expected_event_id: String,
}

impl MktSigningRequest {
    fn new(
        pubkey: String,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        content: Value,
    ) -> Result<Self, SwapClientError> {
        reject_custody_material(&content)?;
        let content = serde_json::to_string(&content).map_err(|error| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("could not serialize signing content: {error}"),
            )
        })?;
        let unsigned = Event {
            id: String::new(),
            pubkey: pubkey.clone(),
            created_at,
            kind,
            tags: tags.clone(),
            content: content.clone(),
            sig: String::new(),
        };
        let expected_event_id = unsigned.computed_id().map_err(|error| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("could not compute signing request ID: {error}"),
            )
        })?;
        Ok(Self {
            pubkey,
            created_at,
            kind,
            tags,
            content,
            expected_event_id,
        })
    }

    pub fn verify_signed(&self, event: Event) -> Result<Event, SwapClientError> {
        if event.pubkey != self.pubkey
            || event.created_at != self.created_at
            || event.kind != self.kind
            || event.tags != self.tags
            || event.content != self.content
            || event.id != self.expected_event_id
        {
            return Err(SwapClientError::new(
                "swp_external_signature_mismatch",
                "external signer changed the requested event bytes",
            ));
        }
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .map_err(|error| {
                SwapClientError::new(
                    "swp_external_signature_invalid",
                    format!("external signer returned an invalid event: {error}"),
                )
            })?;
        let raw = serde_json::to_vec(&event).map_err(|error| {
            SwapClientError::new(
                "swp_external_signature_invalid",
                format!("could not serialize signed event: {error}"),
            )
        })?;
        validate_mkt_private_raw(&raw, &swp_profile_support()).map_err(|error| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("signed event violates MKT-SWP: {error}"),
            )
        })?;
        Ok(event)
    }
}

#[derive(Debug, Clone)]
pub struct SwapRecordFactory {
    config: SwapClientConfig,
}

#[derive(Clone, Copy)]
enum QuoteMode {
    Indicative,
    Soft,
}

impl QuoteMode {
    fn tags(self) -> (&'static str, &'static str) {
        match self {
            Self::Indicative => ("indicative", "none"),
            Self::Soft => ("firm", "soft"),
        }
    }
}

impl SwapRecordFactory {
    pub fn new(config: SwapClientConfig) -> Result<Self, SwapClientError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &SwapClientConfig {
        &self.config
    }

    pub fn rfq(
        &self,
        created_at: u64,
        distinct: &str,
        expiration: u64,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let mut tags = self.common_tags(ParticipantRole::Requester, distinct, "MKT-SWP RFQ")?;
        tags.push(Tag::new(vec![
            "a".into(),
            self.config.offering_address.clone(),
            String::new(),
            "offering".into(),
        ]));
        tags.push(Tag::new(vec!["expiration".into(), expiration.to_string()]));
        self.request(
            ParticipantRole::Requester,
            created_at,
            MKT_RFQ_KIND,
            tags,
            mkt_swp,
        )
    }

    pub fn indicative_quote(
        &self,
        created_at: u64,
        distinct: &str,
        rfq_id: &str,
        expiration: u64,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        self.quote_with_policy(
            created_at,
            distinct,
            rfq_id,
            expiration,
            QuoteMode::Indicative,
            mkt_swp,
        )
    }

    pub fn soft_quote(
        &self,
        created_at: u64,
        distinct: &str,
        rfq_id: &str,
        expiration: u64,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        self.quote_with_policy(
            created_at,
            distinct,
            rfq_id,
            expiration,
            QuoteMode::Soft,
            mkt_swp,
        )
    }

    pub fn quote(
        &self,
        created_at: u64,
        distinct: &str,
        rfq_id: &str,
        expiration: u64,
        policy: QuotePolicy<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let mode = match (policy.quote_class, policy.reservation) {
            ("indicative", "none") => QuoteMode::Indicative,
            ("firm", "soft") => QuoteMode::Soft,
            ("firm", "hard") => {
                return Err(SwapClientError::new(
                    "swp_reservation_unconfirmed",
                    "hard Quote construction requires the provider reserve gate",
                ));
            }
            _ => {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "unknown Quote class or reservation",
                ));
            }
        };
        self.quote_with_policy(created_at, distinct, rfq_id, expiration, mode, mkt_swp)
    }

    fn quote_with_policy(
        &self,
        created_at: u64,
        distinct: &str,
        rfq_id: &str,
        expiration: u64,
        policy: QuoteMode,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(rfq_id, "RFQ event ID")?;
        let (quote_class, reservation) = policy.tags();
        let mut tags = self.common_tags(ParticipantRole::Provider, distinct, "MKT-SWP Quote")?;
        tags.extend([
            Tag::new(vec!["e".into(), rfq_id.into(), String::new(), "rfq".into()]),
            Tag::new(vec!["expiration".into(), expiration.to_string()]),
            Tag::new(vec!["quote".into(), quote_class.into()]),
            Tag::new(vec!["reservation".into(), reservation.into()]),
        ]);
        self.request(
            ParticipantRole::Provider,
            created_at,
            MKT_QUOTE_KIND,
            tags,
            mkt_swp,
        )
    }

    pub fn order(
        &self,
        created_at: u64,
        distinct: &str,
        quote_id: &str,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(quote_id, "Quote event ID")?;
        let mut tags = self.common_tags(ParticipantRole::Requester, distinct, "MKT-SWP Order")?;
        tags.push(Tag::new(vec![
            "e".into(),
            quote_id.into(),
            String::new(),
            "quote".into(),
        ]));
        self.request(
            ParticipantRole::Requester,
            created_at,
            MKT_ORDER_KIND,
            tags,
            mkt_swp,
        )
    }

    pub fn requester_order(
        &self,
        input: RequesterOrderInput<'_>,
    ) -> Result<MktSigningRequest, SwapClientError> {
        validate_firm_quote(input.quote)?;
        let quote_profile = validate_requester_quote(&self.config, input.rfq, input.quote)?;
        validate_quote_observation(&quote_profile, input.quote, input.observed_at)?;
        reject_unsupported_executable_quote(&quote_profile)?;
        let mut order_profile = Map::from_iter([(
            "accepted_quote_id".to_owned(),
            Value::String(input.quote.id.clone()),
        )]);
        if let Some(selection) = input.selection {
            order_profile.insert("selection".to_owned(), Value::Object(selection));
        }
        validate_order_selection(&quote_profile, &order_profile)?;
        self.order(
            input.created_at,
            input.distinct,
            &input.quote.id,
            Value::Object(order_profile),
        )
    }

    pub fn requester_contract(
        &self,
        input: RequesterContractSigningInput<'_>,
    ) -> Result<MktSigningRequest, SwapClientError> {
        validate_firm_quote(input.quote)?;
        let quote_profile = validate_requester_quote(&self.config, input.rfq, input.quote)?;
        validate_composed_order(
            &self.config,
            input.quote,
            input.order,
            input.order_observed_at,
            &quote_profile,
        )?;
        reject_custody_material(&input.contract)?;
        let request = self.swap_contract(
            ParticipantRole::Requester,
            input.created_at,
            input.distinct,
            SwapContractReferences {
                order_id: &input.order.id,
                quote_id: &input.quote.id,
                accepted_status_id: None,
            },
            input.contract.clone(),
        )?;
        let requester_contract = unsigned_event(&request);
        let records = vec![
            input.rfq.clone(),
            input.quote.clone(),
            input.order.clone(),
            requester_contract,
        ];
        validate_provider_contract_candidate(&self.config, &records, &input.contract)?;
        Ok(request)
    }

    pub fn requester_contract_draft(
        &self,
        rfq: &Event,
        quote: &Event,
        order: &Event,
        order_observed_at: u64,
        local_inputs: RequesterContractLocalInputs,
    ) -> Result<Value, SwapClientError> {
        validate_firm_quote(quote)?;
        let quote_profile = validate_requester_quote(&self.config, rfq, quote)?;
        validate_composed_order(
            &self.config,
            quote,
            order,
            order_observed_at,
            &quote_profile,
        )?;
        compose_requester_contract(
            &self.config,
            rfq,
            quote,
            order,
            &quote_profile,
            local_inputs,
        )
    }

    pub fn status(
        &self,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        order_id: &str,
        status: StatusState<'_>,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(order_id, "Order event ID")?;
        if status.sequence > MAX_STATUS_SEQUENCE {
            return Err(SwapClientError::new(
                "swp_status_gap",
                "Status sequence exceeds the bounded session history",
            ));
        }
        if status.sequence == 0 && status.previous.is_some()
            || status.sequence > 0 && status.previous.is_none()
        {
            return Err(SwapClientError::new(
                "swp_status_gap",
                "Status previous reference does not match its sequence",
            ));
        }
        let expected_base = base_state_for(status.swp_state).ok_or_else(|| {
            SwapClientError::new("swp_status_transition_invalid", "unknown MKT-SWP state")
        })?;
        if status.base_state != expected_base || !state_allowed_for_role(role, status.swp_state) {
            return Err(SwapClientError::new(
                "swp_status_signer_invalid",
                "Status signer or base state does not match the MKT-SWP state",
            ));
        }
        let mut tags = self.common_tags(role, distinct, "MKT-SWP Status")?;
        tags.extend([
            Tag::new(vec![
                "e".into(),
                order_id.into(),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["seq".into(), status.sequence.to_string()]),
            Tag::new(vec!["state".into(), status.base_state.into()]),
        ]);
        if let Some(previous) = status.previous {
            require_lower_hex_32(previous, "previous Status ID")?;
            tags.push(Tag::new(vec![
                "e".into(),
                previous.into(),
                String::new(),
                "previous".into(),
            ]));
        }
        let mut mkt_swp = extra;
        mkt_swp.insert("swp_state".into(), Value::String(status.swp_state.into()));
        self.request(
            role,
            created_at,
            MKT_STATUS_KIND,
            tags,
            Value::Object(mkt_swp),
        )
    }

    pub fn cooperative_status(
        &self,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        order_id: &str,
        status: StatusState<'_>,
        message: CooperativeSigningMessage,
    ) -> Result<MktSigningRequest, SwapClientError> {
        if status.swp_state != "cooperative_signing_pending" {
            return Err(musig_error(
                "cooperative signing requires the cooperative signing Status state",
            ));
        }
        message.validate(role)?;
        let value = serde_json::to_value(message).map_err(|error| {
            musig_error(format!("could not serialize cooperative message: {error}"))
        })?;
        self.status(
            role,
            created_at,
            distinct,
            order_id,
            status,
            Map::from_iter([("cooperative_signing".to_owned(), value)]),
        )
    }

    pub fn cancel(
        &self,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        order_id: &str,
        cancellation: Cancellation<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(order_id, "Order event ID")?;
        if !matches!(
            cancellation.action,
            "request" | "accepted" | "rejected" | "effective"
        ) {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "unknown cancellation action",
            ));
        }
        let mut tags = self.common_tags(role, distinct, "MKT-SWP Cancel")?;
        tags.extend([
            Tag::new(vec![
                "e".into(),
                order_id.into(),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["action".into(), cancellation.action.into()]),
            Tag::new(vec!["reason".into(), cancellation.reason.into()]),
        ]);
        let reference_shape_valid = match cancellation.action {
            "request" => cancellation.request_id.is_none() && cancellation.accepted_id.is_none(),
            "accepted" | "rejected" => {
                cancellation.request_id.is_some() && cancellation.accepted_id.is_none()
            }
            "effective" => cancellation.request_id.is_some() && cancellation.accepted_id.is_some(),
            _ => false,
        };
        if !reference_shape_valid {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "cancellation action has the wrong consent reference shape",
            ));
        }
        if let Some(request_id) = cancellation.request_id {
            require_lower_hex_32(request_id, "Cancel request ID")?;
            tags.push(Tag::new(vec![
                "e".into(),
                request_id.into(),
                String::new(),
                "cancel-request".into(),
            ]));
        }
        if let Some(accepted_id) = cancellation.accepted_id {
            require_lower_hex_32(accepted_id, "accepted Cancel ID")?;
            tags.push(Tag::new(vec![
                "e".into(),
                accepted_id.into(),
                String::new(),
                "cancel-accept".into(),
            ]));
        }
        self.request(role, created_at, MKT_CANCEL_KIND, tags, mkt_swp)
    }

    pub fn close(
        &self,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        order_id: &str,
        close: CloseOutcome<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(order_id, "Order event ID")?;
        if !matches!(
            close.outcome,
            "completed"
                | "rejected"
                | "cancelled"
                | "expired"
                | "failed"
                | "refunded"
                | "disputed"
                | "unresolved"
        ) {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "unknown Close outcome",
            ));
        }
        let mut tags = self.common_tags(role, distinct, "MKT-SWP Close")?;
        tags.extend([
            Tag::new(vec![
                "e".into(),
                order_id.into(),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec!["outcome".into(), close.outcome.into()]),
            Tag::new(vec!["terminal_at".into(), close.terminal_at.to_string()]),
        ]);
        self.request(role, created_at, MKT_CLOSE_KIND, tags, mkt_swp)
    }

    pub fn swap_contract(
        &self,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        references: SwapContractReferences<'_>,
        contract: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(references.order_id, "Order event ID")?;
        require_lower_hex_32(references.quote_id, "Quote event ID")?;
        reject_custody_material(&contract)?;
        let digest = lower_hex(&Sha256::digest(canonical_json(&contract)?));
        let mut tags = self.common_tags(role, distinct, "MKT-SWP swap contract")?;
        tags.extend([
            Tag::new(vec![
                "e".into(),
                references.order_id.into(),
                String::new(),
                "order".into(),
            ]),
            Tag::new(vec![
                "e".into(),
                references.quote_id.into(),
                String::new(),
                "quote".into(),
            ]),
            Tag::new(vec!["x".into(), digest.clone()]),
            Tag::new(vec!["role".into(), role.as_str().into()]),
        ]);
        if let Some(status_id) = references.accepted_status_id {
            require_lower_hex_32(status_id, "accepted Status ID")?;
            tags.push(Tag::new(vec![
                "e".into(),
                status_id.into(),
                String::new(),
                "status".into(),
            ]));
        }
        self.request(
            role,
            created_at,
            MKT_SWP_SWAP_CONTRACT_KIND,
            tags,
            json!({
                "contract": contract,
                "contract_sha256": digest,
                "signer_role": role.as_str()
            }),
        )
    }

    fn request(
        &self,
        role: ParticipantRole,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        MktSigningRequest::new(
            self.config.pubkey_for(role).to_owned(),
            created_at,
            kind,
            tags,
            json!({
                "schema": MKT_ENVELOPE_SCHEMA,
                "profile": MKT_SWP_PROFILE_ID,
                "profile_version": MKT_SWP_PROFILE_VERSION,
                "session_id": self.config.session_id,
                "mkt_swp": mkt_swp
            }),
        )
    }

    fn common_tags(
        &self,
        author: ParticipantRole,
        distinct: &str,
        alt: &str,
    ) -> Result<Vec<Tag>, SwapClientError> {
        require_lower_hex_32(distinct, "record idempotency key")?;
        let recipient = author.other();
        Ok(vec![
            Tag::new(vec!["d".into(), distinct.into()]),
            Tag::new(vec!["session".into(), self.config.session_id.clone()]),
            Tag::new(vec![
                "profile".into(),
                MKT_SWP_PROFILE_ID.into(),
                "1".into(),
            ]),
            Tag::new(vec![
                "p".into(),
                self.config.pubkey_for(recipient).into(),
                String::new(),
                recipient.as_str().into(),
            ]),
            Tag::new(vec!["alt".into(), alt.into()]),
        ])
    }
}

impl RequesterSessionView {
    pub fn from_signed_records(
        config: &SwapClientConfig,
        records: &[Event],
        deliveries: Vec<SignedRecordDelivery>,
    ) -> Result<Self, SwapClientError> {
        Self::from_signed_records_internal(config, records, deliveries, None)
    }

    pub fn from_restored_snapshot(
        snapshot: &[u8],
        deliveries: Vec<SignedRecordDelivery>,
    ) -> Result<Self, SwapClientError> {
        SwapSession::<AwaitingVerification>::restore(snapshot)?.requester_session_view(deliveries)
    }

    fn from_signed_records_internal(
        config: &SwapClientConfig,
        records: &[Event],
        deliveries: Vec<SignedRecordDelivery>,
        external_effects: Option<&BTreeMap<String, ExternalEffectResult>>,
    ) -> Result<Self, SwapClientError> {
        config.validate()?;
        if records.len() < 2 || records.len() > MAX_SIGNED_RECORDS {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "requester session view requires a bounded RFQ and Quote history",
            ));
        }
        let mut event_ids = BTreeSet::new();
        for event in records {
            validate_composer_record(config, event)?;
            if !event_ids.insert(event.id.clone()) {
                return Err(SwapClientError::new(
                    "swp_idempotency_conflict",
                    "requester session view contains duplicate event IDs",
                ));
            }
        }
        let rfq = exactly_one(records, MKT_RFQ_KIND, "swp_unresolved_loss")?;
        let quote = exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
        let quote_profile = validate_requester_quote(config, rfq, quote)?;
        let quote_view = requester_quote_view(rfq, quote, &quote_profile)?;

        let mut delivery_ids = BTreeSet::new();
        for delivery in &deliveries {
            let event = records
                .iter()
                .find(|event| event.id == delivery.event_id)
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_unresolved_loss",
                        "delivery evidence refers to an event outside the session",
                    )
                })?;
            delivery.validate(event)?;
            if !delivery_ids.insert(delivery.event_id.clone()) {
                return Err(SwapClientError::new(
                    "swp_idempotency_conflict",
                    "session view has duplicate delivery evidence",
                ));
            }
        }
        if delivery_ids != event_ids {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "requester session view requires exactly one validated delivery receipt per record",
            ));
        }

        let orders = records
            .iter()
            .filter(|event| event.kind == MKT_ORDER_KIND)
            .collect::<Vec<_>>();
        if orders.len() > 1 {
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "requester session has conflicting Order records",
            ));
        }
        let order = orders.first().copied();
        if let Some(order) = order {
            validate_firm_quote(quote)?;
            let order_observed_at = deliveries
                .iter()
                .find(|delivery| delivery.event_id == order.id)
                .map(SignedRecordDelivery::observed_at)
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_unresolved_loss",
                        "Order has no trusted local observation time",
                    )
                })?;
            validate_composed_order(config, quote, order, order_observed_at, &quote_profile)?;
        }
        let status = StatusProjection::from_records(config, records)?;
        let requester_contracts = records
            .iter()
            .filter(|event| {
                event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == config.requester_pubkey
            })
            .collect::<Vec<_>>();
        let provider_contracts = records
            .iter()
            .filter(|event| {
                event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == config.provider_pubkey
            })
            .collect::<Vec<_>>();
        if requester_contracts.len() > 1 || provider_contracts.len() > 1 {
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "requester session has conflicting participant Contract records",
            ));
        }
        let requester_contract = requester_contracts.first().copied();
        let provider_contract = provider_contracts.first().copied();
        let mut state = match (order, requester_contract, provider_contract) {
            (None, None, None) => RequesterVerificationState::QuoteVerified,
            (Some(_), None, None) => RequesterVerificationState::OrderVerified,
            (Some(_), Some(_), None) => RequesterVerificationState::AwaitingProviderContract,
            (Some(_), Some(_), Some(_)) => {
                let bound = BoundSession::from_records(config, records)?;
                bound.verify_contract_terms()?;
                bound.verify_requester_topology()?;
                RequesterVerificationState::ContractTermsVerified
            }
            _ => {
                return Err(SwapClientError::new(
                    "swp_contract_missing",
                    "requester session has an invalid Order or Contract prefix",
                ));
            }
        };
        if let Some(external_effects) = external_effects {
            validate_lifecycle(config, records, external_effects)?;
        }
        let terminal = requester_terminal_view(records, external_effects)?;
        if terminal.watch_terminal {
            if !matches!(state, RequesterVerificationState::ContractTermsVerified) {
                return Err(SwapClientError::new(
                    "swp_contract_missing",
                    "terminal Close has no fully verified participant Contract pair",
                ));
            }
            state = RequesterVerificationState::TerminalVerified;
        }
        let conflicting_timeline_ids = requester_timeline_conflicts(records, &terminal)?;
        let mut timeline = records
            .iter()
            .map(|event| requester_timeline_entry(config, event, &conflicting_timeline_ids))
            .collect::<Result<Vec<_>, _>>()?;
        sort_requester_timeline(&mut timeline)?;
        Ok(Self {
            schema: REQUESTER_SESSION_VIEW_SCHEMA.to_owned(),
            session_id: config.session_id.clone(),
            quote: quote_view,
            timeline,
            verification: RequesterVerificationView {
                state,
                local_verification_required: true,
                funding_authorized: false,
                status_gaps: status.gaps.keys().cloned().collect(),
                status_forks: status.forks.keys().cloned().collect(),
                invalid_status_claims: status.invalid_claims.keys().cloned().collect(),
            },
            terminal,
            deliveries,
        })
    }
}

/// Narrow cross-crate bridge used by `immortal-provider` to share the
/// requester's fail-closed MKT-SWP validation without duplicating it.
#[doc(hidden)]
pub mod provider_support {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::{Map, Value};

    use super::{
        CooperativeSigningContext, CooperativeSigningMessage, Event, ExitPackage,
        MAX_SIGNED_RECORDS, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND,
        MKT_SWP_SWAP_CONTRACT_KIND, ParticipantRole, StatusProjection, SwapClientConfig,
        SwapClientError,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ValidatedSession {
        pub contract: Value,
        pub order_id: String,
        pub requester_contract_id: String,
        pub provider_contract_id: String,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ValidatedPrecontractSession {
        pub quote_terms: Value,
        pub order_id: String,
    }

    pub fn error(code: &'static str, detail: impl Into<String>) -> SwapClientError {
        SwapClientError::new(code, detail)
    }

    pub fn canonical_json(value: &Value) -> Result<Vec<u8>, SwapClientError> {
        super::canonical_json(value)
    }

    pub fn reject_custody_material(value: &Value) -> Result<(), SwapClientError> {
        super::reject_custody_material(value)
    }

    pub fn require_lower_hex_32(value: &str, label: &str) -> Result<(), SwapClientError> {
        super::require_lower_hex_32(value, label)
    }

    pub fn status_projection(
        config: &SwapClientConfig,
        records: &[Event],
    ) -> Result<StatusProjection, SwapClientError> {
        StatusProjection::from_records(config, records)
    }

    pub fn validate_bound_session(
        config: &SwapClientConfig,
        records: &[Event],
    ) -> Result<ValidatedSession, SwapClientError> {
        config.validate()?;
        let bound = super::BoundSession::from_records(config, records)?;
        bound.verify_contract_terms()?;
        bound.verify_requester_topology()?;
        Ok(ValidatedSession {
            contract: bound.contract,
            order_id: bound.order.id.clone(),
            requester_contract_id: bound.requester_contract.id.clone(),
            provider_contract_id: bound.provider_contract.id.clone(),
        })
    }

    pub fn validate_precontract_session(
        config: &SwapClientConfig,
        records: &[Event],
    ) -> Result<ValidatedPrecontractSession, SwapClientError> {
        config.validate()?;
        let rfq = super::exactly_one(records, MKT_RFQ_KIND, "swp_contract_terms_mismatch")?;
        let quote = super::exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
        let order = super::exactly_one(records, MKT_ORDER_KIND, "swp_contract_terms_mismatch")?;
        if rfq.pubkey != config.requester_pubkey
            || quote.pubkey != config.provider_pubkey
            || order.pubkey != config.requester_pubkey
        {
            return Err(SwapClientError::new(
                "swp_contract_signer_invalid",
                "RFQ, Quote, or Order author is not the configured participant",
            ));
        }
        for event in [rfq, quote, order] {
            let raw = serde_json::to_vec(event).map_err(|error| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    format!("could not serialize signed precontract record: {error}"),
                )
            })?;
            let validated = super::validate_mkt_private_raw(&raw, &super::swp_profile_support())
                .map_err(|error| {
                    SwapClientError::new(
                        "swp_contract_terms_mismatch",
                        format!("signed precontract record failed validation: {error}"),
                    )
                })?;
            if validated.envelope.session_id != config.session_id {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "signed precontract record belongs to another session",
                ));
            }
        }
        let offering_references = rfq
            .tags
            .iter()
            .filter(|tag| {
                tag.name() == Some("a")
                    && tag.as_slice().get(3).map(String::as_str) == Some("offering")
            })
            .collect::<Vec<_>>();
        if !matches!(offering_references.as_slice(), [reference] if reference.value() == Some(config.offering_address.as_str()))
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "RFQ does not bind the configured Offering address",
            ));
        }
        super::require_marked_reference(quote, "rfq", &rfq.id)?;
        super::require_marked_reference(order, "quote", &quote.id)?;
        let quote_content = super::parse_content(quote)?;
        let quote_profile = super::object(
            quote_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Quote",
        )?;
        let reservation_class = super::tag_value(quote, "reservation")?;
        super::validate_provider_quote_profile(quote_profile, reservation_class)?;
        let quote_expiration = super::tag_value(quote, "expiration")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_quote_expired", "Quote expiration is invalid")
            })?;
        super::validate_quote_against_rfq(
            rfq,
            quote_profile,
            super::tag_value(quote, "quote")?,
            quote.created_at,
            quote_expiration,
        )?;
        let order_content = super::parse_content(order)?;
        let order_profile = super::object(
            order_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Order",
        )?;
        if order_profile
            .get("accepted_quote_id")
            .and_then(Value::as_str)
            != Some(quote.id.as_str())
        {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order body does not accept the referenced Quote",
            ));
        }
        super::validate_order_acceptance_deadline(
            quote_profile,
            quote_expiration,
            order.created_at,
        )?;
        super::validate_order_selection(quote_profile, order_profile)?;
        let quote_terms = quote_profile.get("terms").cloned().ok_or_else(|| {
            SwapClientError::new("swp_contract_terms_mismatch", "MKT-SWP Quote has no terms")
        })?;
        super::object(&quote_terms, "MKT-SWP Quote terms")?;
        Ok(ValidatedPrecontractSession {
            quote_terms,
            order_id: order.id.clone(),
        })
    }

    pub fn session_config(records: &[Event]) -> Result<SwapClientConfig, SwapClientError> {
        let rfq = super::exactly_one(records, MKT_RFQ_KIND, "swp_contract_terms_mismatch")?;
        let quote = super::exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
        let offering = rfq
            .tags
            .iter()
            .filter(|tag| {
                tag.name() == Some("a")
                    && tag.as_slice().get(3).map(String::as_str) == Some("offering")
            })
            .collect::<Vec<_>>();
        let offering_address = match offering.as_slice() {
            [tag] => tag
                .value()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_contract_terms_mismatch",
                        "RFQ offering address is empty",
                    )
                })?,
            _ => {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "RFQ requires exactly one marked Offering address",
                ));
            }
        };
        let config = SwapClientConfig {
            session_id: super::tag_value(rfq, "session")?.to_owned(),
            requester_pubkey: rfq.pubkey.clone(),
            provider_pubkey: quote.pubkey.clone(),
            offering_address: offering_address.to_owned(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate_status_history(
        config: &SwapClientConfig,
        records: &[Event],
        contract: &Value,
    ) -> Result<StatusProjection, SwapClientError> {
        config.validate()?;
        if records.is_empty() || records.len() > MAX_SIGNED_RECORDS {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "signed record history is empty or exceeds its bound",
            ));
        }
        let mut event_ids = BTreeSet::new();
        for event in records {
            let raw = serde_json::to_vec(event).map_err(|error| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    format!("could not serialize signed record: {error}"),
                )
            })?;
            let validated = super::validate_mkt_private_raw(&raw, &super::swp_profile_support())
                .map_err(|error| {
                    SwapClientError::new(
                        "swp_status_transition_invalid",
                        format!("signed record failed MKT-SWP validation: {error}"),
                    )
                })?;
            if validated.envelope.session_id != config.session_id {
                return Err(SwapClientError::new(
                    "swp_status_transition_invalid",
                    "signed record belongs to another session",
                ));
            }
            super::role_for_author(config, &event.pubkey)?;
            if !event_ids.insert(event.id.clone()) {
                return Err(SwapClientError::new(
                    "swp_status_fork",
                    "signed record history repeats an event ID",
                ));
            }
        }
        let order = super::exactly_one(records, MKT_ORDER_KIND, "swp_status_transition_invalid")?;
        for status in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
            super::require_marked_reference(status, "order", &order.id)?;
        }
        let projection = StatusProjection::from_records(config, records)?;
        projection.require_contiguous()?;
        validate_facade_predecessors(config, records)?;
        validate_facade_evidence(config, records, contract)?;
        Ok(projection)
    }

    pub fn validate_status_prefix(
        config: &SwapClientConfig,
        records: &[Event],
        contract: &Value,
        terminal_status_id: &str,
    ) -> Result<StatusProjection, SwapClientError> {
        let terminal = records
            .iter()
            .filter(|event| event.kind == MKT_STATUS_KIND && event.id == terminal_status_id)
            .collect::<Vec<_>>();
        let [terminal] = terminal.as_slice() else {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status prefix requires one exact terminal Status",
            ));
        };
        let mut prefix = records
            .iter()
            .filter(|event| {
                matches!(
                    event.kind,
                    MKT_RFQ_KIND | MKT_QUOTE_KIND | MKT_ORDER_KIND | MKT_SWP_SWAP_CONTRACT_KIND
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut chain = Vec::new();
        let mut visited = BTreeSet::new();
        let mut current = *terminal;
        loop {
            if !visited.insert(current.id.clone()) {
                return Err(SwapClientError::new(
                    "swp_status_fork",
                    "Status prefix contains a predecessor cycle",
                ));
            }
            chain.push(current.clone());
            let sequence = super::tag_value(current, "seq")?
                .parse::<u64>()
                .map_err(|_| SwapClientError::new("swp_status_gap", "Status seq is invalid"))?;
            if sequence == 0 {
                break;
            }
            let previous_id = super::marked_reference(current, "previous")?;
            let previous = records
                .iter()
                .filter(|event| {
                    event.kind == MKT_STATUS_KIND
                        && event.id == previous_id
                        && event.pubkey == current.pubkey
                })
                .collect::<Vec<_>>();
            let [previous] = previous.as_slice() else {
                return Err(SwapClientError::new(
                    "swp_status_gap",
                    "Status prefix predecessor is absent or has another signer",
                ));
            };
            current = *previous;
        }
        prefix.extend(chain.into_iter().rev());
        validate_status_history(config, &prefix, contract)
    }

    fn validate_facade_predecessors(
        config: &SwapClientConfig,
        records: &[Event],
    ) -> Result<(), SwapClientError> {
        let swap_type = super::quote_swap_type(records)?;
        let mut streams = BTreeMap::<&str, BTreeMap<u64, &Event>>::new();
        let mut settlement_started = false;
        let mut cancelled_or_expired = false;
        for event in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
            let sequence = super::tag_value(event, "seq")?
                .parse::<u64>()
                .map_err(|_| SwapClientError::new("swp_status_gap", "Status seq is invalid"))?;
            let state = super::status_state(event)?;
            settlement_started |= facade_settlement_started(&state);
            cancelled_or_expired |= matches!(state.as_str(), "cancelled" | "expired");
            streams
                .entry(event.pubkey.as_str())
                .or_default()
                .insert(sequence, event);
        }
        if settlement_started && cancelled_or_expired {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status cannot cancel or expire after settlement starts",
            ));
        }
        for (author, stream) in streams {
            let role = super::role_for_author(config, author)?;
            let initial = stream.get(&0).ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_gap",
                    "Status signer stream does not begin at seq 0",
                )
            })?;
            let initial_state = super::status_state(initial)?;
            if !facade_initial_state_allowed(swap_type, role, &initial_state) {
                return Err(SwapClientError::new(
                    "swp_status_transition_invalid",
                    "Status signer stream begins outside its role flow",
                ));
            }
            for (sequence, current) in stream.range(1..) {
                let previous = sequence
                    .checked_sub(1)
                    .and_then(|value| stream.get(&value))
                    .ok_or_else(|| {
                        SwapClientError::new(
                            "swp_status_gap",
                            "Status predecessor sequence is absent",
                        )
                    })?;
                let previous_state = super::status_state(previous)?;
                let current_state = super::status_state(current)?;
                if !facade_predecessor_allowed(swap_type, role, &previous_state, &current_state) {
                    return Err(SwapClientError::new(
                        "swp_status_transition_invalid",
                        "Status predecessor is outside the signer-local flow graph",
                    ));
                }
            }
        }
        Ok(())
    }

    fn facade_initial_state_allowed(
        swap_type: super::SwapType,
        role: ParticipantRole,
        state: &str,
    ) -> bool {
        super::state_allowed_for_swap(role, state, swap_type)
            && !matches!(state, "completed" | "refunded")
    }

    fn facade_predecessor_allowed(
        swap_type: super::SwapType,
        role: ParticipantRole,
        previous: &str,
        current: &str,
    ) -> bool {
        if previous == "cooperative_signing_pending" && current == previous {
            return true;
        }
        if matches!(
            current,
            "cancelled" | "expired" | "disputed" | "failed" | "unresolved"
        ) {
            if matches!(current, "cancelled" | "expired") && facade_settlement_started(previous) {
                return false;
            }
            return !matches!(previous, "completed" | "refunded");
        }
        if current == "completed" {
            return match swap_type {
                super::SwapType::Submarine => previous == "provider_claimed",
                super::SwapType::Reverse => previous == "lightning_paid",
                super::SwapType::Chain => matches!(
                    previous,
                    "provider_source_claimed" | "requester_destination_claimed"
                ),
            };
        }
        if current == "refunded" {
            return match swap_type {
                super::SwapType::Submarine => previous == "refund_pending",
                super::SwapType::Reverse => previous == "invoice_cancelled",
                super::SwapType::Chain => matches!(
                    previous,
                    "requester_source_refunded" | "provider_destination_refunded"
                ),
            };
        }
        if matches!(
            (previous, current),
            ("lightning_paid", "provider_claim_pending")
                | ("lightning_paid", "cooperative_signing_pending")
                | ("cooperative_signing_pending", "provider_claim_pending")
                | ("funding_final", "lightning_settlement_pending")
                | ("funding_final", "cooperative_signing_pending")
                | (
                    "cooperative_signing_pending",
                    "lightning_settlement_pending"
                )
                | ("requester_lock_verified", "requester_claim_pending")
                | ("requester_lock_verified", "cooperative_signing_pending")
                | ("cooperative_signing_pending", "requester_claim_pending")
                | ("funding_final", "provider_refund_prepared")
                | ("provider_refund_prepared", "provider_refund_pending")
                | ("provider_refund_pending", "provider_refunded")
                | ("provider_refunded", "invoice_cancel_pending")
                | ("invoice_cancel_pending", "invoice_cancelled")
                | ("requester_funding_broadcast", "refund_prepared")
                | ("refund_prepared", "refund_pending")
        ) {
            return true;
        }
        let flow: &[&str] = match (swap_type, role) {
            (super::SwapType::Submarine, ParticipantRole::Requester) => &[
                "requester_verification_passed",
                "funding_required",
                "requester_funding_broadcast",
                "refund_prepared",
                "refund_pending",
            ],
            (super::SwapType::Submarine, ParticipantRole::Provider) => &[
                "accepted",
                "lock_terms_ready",
                "funding_observed",
                "funding_final",
                "lightning_payment_pending",
                "lightning_paid",
                "cooperative_signing_pending",
                "provider_claim_pending",
                "provider_claimed",
            ],
            (super::SwapType::Reverse, ParticipantRole::Requester) => &[
                "requester_invoice_verified",
                "lightning_payment_pending",
                "requester_lock_verified",
                "cooperative_signing_pending",
                "requester_claim_pending",
                "requester_claimed",
            ],
            (super::SwapType::Reverse, ParticipantRole::Provider) => &[
                "accepted",
                "hold_invoice_ready",
                "lightning_htlcs_held",
                "provider_lock_terms_ready",
                "provider_funding_broadcast",
                "funding_observed",
                "funding_final",
                "cooperative_signing_pending",
                "lightning_settlement_pending",
                "lightning_paid",
                "provider_refund_prepared",
                "provider_refund_pending",
                "provider_refunded",
                "invoice_cancel_pending",
                "invoice_cancelled",
            ],
            _ => {
                return super::transition_rank(swap_type, previous)
                    .zip(super::transition_rank(swap_type, current))
                    .is_some_and(|(left, right)| right > left);
            }
        };
        flow.iter()
            .position(|state| *state == previous)
            .zip(flow.iter().position(|state| *state == current))
            .is_some_and(|(left, right)| right > left)
    }

    fn validate_facade_evidence(
        config: &SwapClientConfig,
        records: &[Event],
        contract: &Value,
    ) -> Result<(), SwapClientError> {
        let contract = super::object(contract, "Swap Contract")?;
        let swap_type = super::quote_swap_type(records)?;
        let contract_minimum = contract
            .get("evidence_requirements")
            .and_then(Value::as_object)
            .and_then(|requirements| requirements.get("minimum_rung"))
            .and_then(Value::as_str)
            .and_then(evidence_rung)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "Swap Contract evidence requirement is invalid",
                )
            })?;
        for event in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
            super::role_for_author(config, &event.pubkey)?;
            let content = super::parse_content(event)?;
            let profile = super::object(
                content.get("mkt_swp").unwrap_or(&Value::Null),
                "MKT-SWP Status",
            )?;
            let state = profile
                .get("swp_state")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SwapClientError::new("swp_status_transition_invalid", "Status has no swp_state")
                })?;
            let required = match state {
                "funding_observed" | "source_funding_observed" | "destination_funding_observed" => {
                    Some(2)
                }
                "funding_final" | "source_funding_final" | "destination_funding_final" => {
                    Some(contract_minimum.max(3))
                }
                "provider_claim_pending"
                | "provider_source_claim_pending"
                | "requester_destination_claim_pending"
                | "requester_source_refund_pending"
                | "provider_refund_pending"
                | "provider_destination_refund_pending"
                | "refund_pending" => Some(2),
                "provider_claimed"
                | "provider_source_claimed"
                | "requester_destination_claimed"
                | "lightning_paid"
                | "lightning_settlement_pending"
                | "refunded"
                | "invoice_cancelled"
                | "requester_source_refunded"
                | "provider_refunded"
                | "provider_destination_refunded" => Some(contract_minimum.max(5)),
                _ => None,
            };
            let Some(required) = required else { continue };
            let evidence = profile.get("evidence").ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "observational provider Status has no evidence",
                )
            })?;
            super::validate_mkt_swp_evidence_reference(evidence).map_err(|error| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    format!("provider Status evidence is invalid: {error}"),
                )
            })?;
            let rung = evidence
                .get("rung")
                .and_then(Value::as_str)
                .and_then(evidence_rung)
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_status_transition_invalid",
                        "provider Status evidence rung is invalid",
                    )
                })?;
            if rung < required {
                return Err(SwapClientError::new(
                    "swp_status_transition_invalid",
                    "provider Status evidence is below the required rung",
                ));
            }
            validate_facade_evidence_binding(swap_type, event, state, evidence, contract)?;
        }
        Ok(())
    }

    fn facade_settlement_started(state: &str) -> bool {
        matches!(
            state,
            "funding_observed"
                | "funding_final"
                | "source_funding_observed"
                | "source_funding_final"
                | "destination_funding_observed"
                | "destination_funding_final"
                | "provider_claim_pending"
                | "provider_claimed"
                | "requester_claim_pending"
                | "requester_claimed"
                | "provider_source_claim_pending"
                | "provider_source_claimed"
                | "requester_destination_claim_pending"
                | "requester_destination_claimed"
                | "lightning_settlement_pending"
                | "lightning_paid"
                | "refund_pending"
                | "refunded"
                | "requester_source_refund_pending"
                | "requester_source_refunded"
                | "provider_refund_pending"
                | "provider_refunded"
                | "provider_destination_refund_pending"
                | "provider_destination_refunded"
                | "invoice_cancel_pending"
                | "invoice_cancelled"
                | "completed"
        )
    }

    fn validate_facade_evidence_binding(
        swap_type: super::SwapType,
        event: &Event,
        state: &str,
        evidence: &Value,
        contract: &Map<String, Value>,
    ) -> Result<(), SwapClientError> {
        let evidence = super::object(evidence, "Status evidence")?;
        let (leg_id, class, reference_mode) =
            facade_evidence_target(swap_type, state).ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "observational Status has no contract evidence mapping",
                )
            })?;
        let legs = contract
            .get("legs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "Swap Contract has no evidence legs",
                )
            })?;
        let matching_legs = legs
            .iter()
            .filter(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
            .collect::<Vec<_>>();
        let [leg] = matching_legs.as_slice() else {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status evidence does not identify one Contract leg",
            ));
        };
        let rail = leg.get("rail").and_then(Value::as_str).ok_or_else(|| {
            SwapClientError::new(
                "swp_status_transition_invalid",
                "Contract evidence leg has no rail",
            )
        })?;
        let verifier_policy = leg
            .get("verifier_policy")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "Contract evidence leg has no verifier policy",
                )
            })?;
        let verifier = super::verifier_for_leg(contract, leg_id).map_err(|_| {
            SwapClientError::new(
                "swp_status_transition_invalid",
                "Status evidence has no exact Contract verifier",
            )
        })?;
        if evidence.get("class").and_then(Value::as_str) != Some(class)
            || evidence.get("rail").and_then(Value::as_str) != Some(rail)
            || evidence.get("verifier_policy").and_then(Value::as_str) != Some(verifier_policy)
            || evidence.get("producer_pubkey").and_then(Value::as_str)
                != Some(event.pubkey.as_str())
            || !super::evidence_verifier_is_authorized(evidence, verifier)
        {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status evidence policy or authority differs from the Contract",
            ));
        }
        let reference = evidence
            .get("reference")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_status_transition_invalid",
                    "Status evidence has no reference",
                )
            })?;
        let expected_reference = match reference_mode {
            FacadeEvidenceReference::FundingOutpoint => {
                let raw = super::decode_hex(
                    super::require_string(
                        verifier,
                        "funding_transaction",
                        None,
                        "swp_status_transition_invalid",
                    )?,
                    "Status funding transaction",
                )?;
                let transaction = super::Transaction::parse(&raw).map_err(|error| {
                    SwapClientError::new(
                        "swp_status_transition_invalid",
                        format!("Status funding transaction is invalid: {error}"),
                    )
                })?;
                let output_index = super::required_u32(verifier, "output_index")?;
                format!(
                    "{}:{output_index}",
                    super::lower_hex(&transaction.txid().map_err(|error| {
                        SwapClientError::new(
                            "swp_status_transition_invalid",
                            format!("could not derive Status funding txid: {error}"),
                        )
                    })?)
                )
            }
            FacadeEvidenceReference::PaymentHash => super::require_string(
                contract,
                "payment_hash",
                None,
                "swp_status_transition_invalid",
            )?
            .to_owned(),
            FacadeEvidenceReference::StatusTransaction => super::require_string(
                super::object(
                    super::parse_content(event)?
                        .get("mkt_swp")
                        .unwrap_or(&Value::Null),
                    "MKT-SWP Status",
                )?,
                "transaction_id",
                None,
                "swp_status_transition_invalid",
            )?
            .to_owned(),
        };
        if reference != expected_reference {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status evidence reference differs from the Contract-bound artifact",
            ));
        }
        if class == "bitcoin_output"
            && evidence.get("artifact_sha256").and_then(Value::as_str)
                != verifier
                    .get("funding_transaction_sha256")
                    .and_then(Value::as_str)
        {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Status funding artifact differs from the Contract",
            ));
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FacadeEvidenceReference {
        FundingOutpoint,
        PaymentHash,
        StatusTransaction,
    }

    fn facade_evidence_target(
        swap_type: super::SwapType,
        state: &str,
    ) -> Option<(&'static str, &'static str, FacadeEvidenceReference)> {
        use FacadeEvidenceReference::{FundingOutpoint, PaymentHash, StatusTransaction};
        match (swap_type, state) {
            (super::SwapType::Submarine, "funding_observed" | "funding_final") => {
                Some(("source", "bitcoin_output", FundingOutpoint))
            }
            (super::SwapType::Reverse, "funding_observed" | "funding_final") => {
                Some(("destination", "bitcoin_output", FundingOutpoint))
            }
            (_, "source_funding_observed" | "source_funding_final") => {
                Some(("source", "bitcoin_output", FundingOutpoint))
            }
            (_, "destination_funding_observed" | "destination_funding_final") => {
                Some(("destination", "bitcoin_output", FundingOutpoint))
            }
            (super::SwapType::Submarine, "provider_claim_pending") => {
                Some(("source", "claim", StatusTransaction))
            }
            (super::SwapType::Submarine, "provider_claimed") => {
                Some(("source", "bitcoin_spend", FundingOutpoint))
            }
            (super::SwapType::Submarine, "refund_pending" | "refunded") => {
                Some(("source", "refund", StatusTransaction))
            }
            (super::SwapType::Reverse, "requester_claim_pending") => {
                Some(("destination", "claim", StatusTransaction))
            }
            (super::SwapType::Reverse, "requester_claimed" | "lightning_settlement_pending") => {
                Some(("destination", "bitcoin_spend", FundingOutpoint))
            }
            (super::SwapType::Reverse, "provider_refund_pending" | "provider_refunded") => {
                Some(("destination", "refund", StatusTransaction))
            }
            (super::SwapType::Reverse, "refunded") => {
                Some(("destination", "refund", StatusTransaction))
            }
            (super::SwapType::Reverse, "lightning_paid")
            | (super::SwapType::Submarine, "lightning_paid") => {
                Some(("lightning", "lightning_payment", PaymentHash))
            }
            (super::SwapType::Reverse, "invoice_cancelled") => {
                Some(("lightning", "invoice", PaymentHash))
            }
            (super::SwapType::Chain, "provider_source_claim_pending") => {
                Some(("source", "claim", StatusTransaction))
            }
            (super::SwapType::Chain, "provider_source_claimed") => {
                Some(("source", "bitcoin_spend", FundingOutpoint))
            }
            (super::SwapType::Chain, "requester_destination_claim_pending") => {
                Some(("destination", "claim", StatusTransaction))
            }
            (super::SwapType::Chain, "requester_destination_claimed") => {
                Some(("destination", "bitcoin_spend", FundingOutpoint))
            }
            (
                super::SwapType::Chain,
                "requester_source_refund_pending" | "requester_source_refunded",
            ) => Some(("source", "refund", StatusTransaction)),
            (
                super::SwapType::Chain,
                "provider_destination_refund_pending" | "provider_destination_refunded",
            ) => Some(("destination", "refund", StatusTransaction)),
            _ => None,
        }
    }

    fn evidence_rung(value: &str) -> Option<u8> {
        [
            "pledged", "reserved", "measured", "verified", "paid", "settled",
        ]
        .iter()
        .position(|candidate| *candidate == value)
        .and_then(|index| u8::try_from(index).ok())
    }

    pub fn require_contiguous_status(projection: &StatusProjection) -> Result<(), SwapClientError> {
        projection.require_contiguous()
    }

    pub fn require_signer_status_contiguous(
        projection: &StatusProjection,
        signer: &str,
    ) -> Result<(), SwapClientError> {
        projection.require_signer_contiguous(signer)
    }

    pub fn validate_no_spend_loss_accounting(
        loss: &Map<String, Value>,
        reservation_released: u64,
    ) -> Result<(), SwapClientError> {
        super::validate_no_spend_loss_accounting(loss, reservation_released)
    }

    pub fn validate_quote_profile(
        profile: &Value,
        reservation_class: &str,
    ) -> Result<(), SwapClientError> {
        let profile = super::object(profile, "MKT-SWP Quote profile")?;
        super::validate_provider_quote_profile(profile, reservation_class)
    }

    pub fn validate_quote_against_rfq(
        rfq: &Event,
        profile: &Value,
        quote_class: &str,
        created_at: u64,
        expiration: u64,
    ) -> Result<(), SwapClientError> {
        let profile = super::object(profile, "MKT-SWP Quote profile")?;
        super::validate_quote_against_rfq(rfq, profile, quote_class, created_at, expiration)
    }

    pub fn validate_order_selection(
        quote_profile: &Map<String, Value>,
        order_profile: &Map<String, Value>,
    ) -> Result<(), SwapClientError> {
        super::validate_order_selection(quote_profile, order_profile)
    }

    pub fn validate_order_acceptance_deadline(
        quote_profile: &Map<String, Value>,
        quote_expiration: u64,
        order_created_at: u64,
    ) -> Result<(), SwapClientError> {
        super::validate_order_acceptance_deadline(quote_profile, quote_expiration, order_created_at)
    }

    pub fn validate_contract_candidate(
        config: &SwapClientConfig,
        records: &[Event],
        contract: &Value,
    ) -> Result<(), SwapClientError> {
        super::validate_provider_contract_candidate(config, records, contract)
    }

    pub fn cooperative_signing_message(
        event: &Event,
        role: ParticipantRole,
    ) -> Result<Option<CooperativeSigningMessage>, SwapClientError> {
        super::cooperative_signing_message(event, role)
    }

    pub fn effect_id(
        order_id: &str,
        effect_role: &str,
        leg_id: &str,
    ) -> Result<String, SwapClientError> {
        super::effect_id(order_id, effect_role, leg_id)
    }

    pub fn validate_provider_cooperative_context(
        config: &SwapClientConfig,
        records: &[Event],
        context: &CooperativeSigningContext,
        package: &ExitPackage,
    ) -> Result<(), SwapClientError> {
        super::validate_cooperative_context_binding(
            config,
            records,
            context,
            package,
            Some(ParticipantRole::Provider),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPackage {
    document: Value,
}

impl ExitPackage {
    pub fn parse(document: Value) -> Result<Self, SwapClientError> {
        reject_custody_material(&document)?;
        let root = object(&document, "exit package")?;
        require_string(
            root,
            "schema",
            Some(EXIT_SCHEMA),
            "swp_exit_package_unusable",
        )?;
        require_string(
            root,
            "profile",
            Some(MKT_SWP_PROFILE_ID),
            "swp_exit_package_unusable",
        )?;
        if root.get("profile_version").and_then(Value::as_u64) != Some(MKT_SWP_PROFILE_VERSION) {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "exit package profile version is unsupported",
            ));
        }
        for name in ["order_id", "contract_sha256", "effect_id"] {
            require_lower_hex_32(
                require_string(root, name, None, "swp_exit_package_unusable")?,
                name,
            )?;
        }
        let contract_ids = root
            .get("swap_contract_ids")
            .and_then(Value::as_array)
            .filter(|ids| ids.len() == 2)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_exit_package_unusable",
                    "exit package requires both Swap Contract IDs",
                )
            })?;
        for id in contract_ids {
            require_lower_hex_32(
                id.as_str().ok_or_else(|| {
                    SwapClientError::new(
                        "swp_exit_package_unusable",
                        "Swap Contract ID must be a string",
                    )
                })?,
                "Swap Contract ID",
            )?;
        }
        require_role(root, "participant_role")?;
        let funding = object(root.get("funding").unwrap_or(&Value::Null), "exit funding")?;
        canonical_amount(require_string(
            funding,
            "amount",
            None,
            "swp_exit_package_unusable",
        )?)?;
        require_lower_hex_32(
            require_string(
                funding,
                "transaction_template_sha256",
                None,
                "swp_exit_package_unusable",
            )?,
            "funding transaction template digest",
        )?;
        require_lower_hex_32(
            require_string(
                funding,
                "confirmation_policy_sha256",
                None,
                "swp_exit_package_unusable",
            )?,
            "confirmation policy digest",
        )?;
        require_lower_hex(
            require_string(funding, "script_pubkey", None, "swp_exit_package_unusable")?,
            "funding scriptPubKey",
        )?;
        match funding.get("transaction_id") {
            Some(Value::String(transaction_id)) => {
                require_lower_hex_32(transaction_id, "funding transaction ID")?;
            }
            Some(Value::Null) => {}
            _ => {
                return Err(SwapClientError::new(
                    "swp_exit_package_unusable",
                    "funding transaction ID must be a lowercase txid or null",
                ));
            }
        }
        if let Some(Value::String(transaction_template)) = funding.get("transaction_template") {
            decode_hex(transaction_template, "funding transaction template")?;
        } else if !matches!(
            funding.get("transaction_template"),
            None | Some(Value::Null)
        ) {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "funding transaction template must be raw transaction hex or null",
            ));
        }
        let exit = object(root.get("exit").unwrap_or(&Value::Null), "exit transaction")?;
        let mode = require_string(exit, "mode", None, "swp_exit_package_unusable")?;
        if !matches!(mode, "presigned" | "wallet_sign" | "external_signer") {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "exit package has an unknown signing mode",
            ));
        }
        let path = require_string(exit, "path", None, "swp_exit_package_unusable")?;
        if !matches!(path, "claim" | "refund") {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "exit package path must be claim or refund",
            ));
        }
        require_lower_hex_32(
            require_string(
                exit,
                "transaction_template_sha256",
                None,
                "swp_exit_package_unusable",
            )?,
            "exit transaction template digest",
        )?;
        require_lower_hex(
            require_string(
                exit,
                "destination_script_pubkey",
                None,
                "swp_exit_package_unusable",
            )?,
            "exit destination scriptPubKey",
        )?;
        let verification = object(
            root.get("verification").unwrap_or(&Value::Null),
            "exit verification",
        )?;
        require_lower_hex(
            require_string(
                verification,
                "taproot_script",
                None,
                "swp_exit_package_unusable",
            )?,
            "exit Taproot script",
        )?;
        require_lower_hex(
            require_string(
                verification,
                "taproot_control_block",
                None,
                "swp_exit_package_unusable",
            )?,
            "exit Taproot control block",
        )?;
        require_string(
            exit,
            "sighash_type",
            Some("DEFAULT"),
            "swp_exit_package_unusable",
        )?;
        match mode {
            "presigned" => {
                let signed = require_string(
                    exit,
                    "signed_transaction",
                    None,
                    "swp_exit_package_unusable",
                )?;
                let signed = decode_hex(signed, "pre-signed exit transaction")?;
                Transaction::parse(&signed).map_err(|error| {
                    SwapClientError::new(
                        "swp_exit_package_unusable",
                        format!("pre-signed exit transaction is invalid: {error}"),
                    )
                })?;
                if !matches!(exit.get("signer_ref"), None | Some(Value::Null)) {
                    return Err(SwapClientError::new(
                        "swp_exit_package_unusable",
                        "pre-signed exit must not depend on a signer reference",
                    ));
                }
            }
            "wallet_sign" | "external_signer" => {
                if !matches!(exit.get("signed_transaction"), None | Some(Value::Null)) {
                    return Err(SwapClientError::new(
                        "swp_exit_package_unusable",
                        "externally signed exit must not persist signed bytes prematurely",
                    ));
                }
                let signer_ref =
                    require_string(exit, "signer_ref", None, "swp_exit_package_unusable")?;
                if signer_ref.is_empty()
                    || signer_ref.len() > 256
                    || signer_ref.chars().any(char::is_control)
                {
                    return Err(SwapClientError::new(
                        "swp_exit_package_unusable",
                        "external signer reference is not bounded public metadata",
                    ));
                }
            }
            _ => {
                return Err(SwapClientError::new(
                    "swp_exit_package_unusable",
                    "exit package mode must be a supported broadcast mode",
                ));
            }
        }
        let is_presigned = mode == "presigned";
        let package = Self { document };
        validate_funding_template(&package, is_presigned)?;
        parse_exit_leaf(&package)?;
        if package.funding_transaction_id()?.is_some() {
            let unsigned = package.unsigned_transaction()?;
            let transaction = Transaction::parse(&unsigned).map_err(|error| {
                SwapClientError::new(
                    "swp_exit_package_unusable",
                    format!("assembled exit transaction is invalid: {error}"),
                )
            })?;
            validate_exit_leaf_template(&package, &transaction)?;
        }
        if is_presigned
            && matches!(
                parse_exit_leaf(&package)?.condition,
                ExitLeafCondition::Hashlock(_)
            )
        {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "hashlock claims cannot be pre-signed before the preimage is released",
            ));
        }
        if is_presigned {
            package.presigned_transaction()?.ok_or_else(|| {
                SwapClientError::new(
                    "swp_exit_package_unusable",
                    "pre-signed exit package has no complete transaction",
                )
            })?;
        }
        Ok(package)
    }

    pub fn document(&self) -> &Value {
        &self.document
    }

    pub fn commitment_sha256(&self) -> Result<String, SwapClientError> {
        let mut commitment = object(&self.document, "exit package")?.clone();
        commitment.remove("swap_contract_ids");
        commitment.remove("contract_sha256");
        Ok(lower_hex(&Sha256::digest(canonical_json(&Value::Object(
            commitment,
        ))?)))
    }

    pub fn effect_id(&self) -> Result<&str, SwapClientError> {
        require_string(
            object(&self.document, "exit package")?,
            "effect_id",
            None,
            "swp_exit_package_unusable",
        )
    }

    pub fn path(&self) -> Result<&str, SwapClientError> {
        let root = object(&self.document, "exit package")?;
        require_string(
            object(root.get("exit").unwrap_or(&Value::Null), "exit transaction")?,
            "path",
            None,
            "swp_exit_package_unusable",
        )
    }

    pub fn mode(&self) -> Result<&str, SwapClientError> {
        let root = object(&self.document, "exit package")?;
        require_string(
            object(root.get("exit").unwrap_or(&Value::Null), "exit transaction")?,
            "mode",
            None,
            "swp_exit_package_unusable",
        )
    }

    pub fn unsigned_transaction(&self) -> Result<Vec<u8>, SwapClientError> {
        let root = object(&self.document, "exit package")?;
        let funding = object(root.get("funding").unwrap_or(&Value::Null), "exit funding")?;
        let exit = object(root.get("exit").unwrap_or(&Value::Null), "exit transaction")?;
        let transaction_id = self.funding_transaction_id()?.ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "exit transaction cannot be assembled until the funding txid is known",
            )
        })?;
        let mut previous_txid = decode_hex_32(&transaction_id, "funding transaction ID")?;
        previous_txid.reverse();
        let previous_output = required_u32(funding, "output_index")?;
        let amount = canonical_amount(require_string(
            funding,
            "amount",
            None,
            "swp_exit_package_unusable",
        )?)?;
        let maximum_fee = canonical_amount(require_string(
            object(
                exit.get("fee_policy").unwrap_or(&Value::Null),
                "exit fee policy",
            )?,
            "maximum_fee",
            None,
            "swp_exit_package_unusable",
        )?)?;
        let output_value = amount.checked_sub(maximum_fee).ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "exit maximum fee consumes the funding amount",
            )
        })?;
        let transaction = Transaction::new(
            required_i32(exit, "transaction_version")?,
            vec![crate::mkt_swp_verify::TransactionInput {
                previous_txid,
                previous_output,
                script_sig: Vec::new(),
                sequence: required_u32(exit, "input_sequence")?,
                witness: Vec::new(),
            }],
            vec![crate::mkt_swp_verify::TransactionOutput {
                value_sat: output_value,
                script_pubkey: decode_hex(
                    require_string(
                        exit,
                        "destination_script_pubkey",
                        None,
                        "swp_exit_package_unusable",
                    )?,
                    "destination scriptPubKey",
                )?,
            }],
            required_u32(exit, "lock_time")?,
        );
        let bytes = transaction.serialize(false).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                format!("could not assemble exit transaction: {error}"),
            )
        })?;
        let digest = lower_hex(&sha256(&bytes));
        let expected = require_string(
            exit,
            "transaction_template_sha256",
            None,
            "swp_exit_package_unusable",
        )?;
        if digest != expected {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "assembled exit transaction does not match the package digest",
            ));
        }
        Ok(bytes)
    }

    fn funding_transaction_id(&self) -> Result<Option<String>, SwapClientError> {
        let root = object(&self.document, "exit package")?;
        let funding = object(root.get("funding").unwrap_or(&Value::Null), "exit funding")?;
        match funding.get("transaction_id") {
            Some(Value::String(transaction_id)) => Ok(Some(transaction_id.clone())),
            Some(Value::Null) => match funding.get("transaction_template") {
                Some(Value::String(transaction_template)) => {
                    let transaction = Transaction::parse(&decode_hex(
                        transaction_template,
                        "funding transaction template",
                    )?)
                    .map_err(|error| {
                        SwapClientError::new(
                            "swp_exit_package_unusable",
                            format!("funding transaction template is invalid: {error}"),
                        )
                    })?;
                    Ok(Some(lower_hex(&transaction.txid().map_err(|error| {
                        SwapClientError::new(
                            "swp_exit_package_unusable",
                            format!("could not derive funding transaction ID: {error}"),
                        )
                    })?)))
                }
                None | Some(Value::Null) => Ok(None),
                _ => Err(SwapClientError::new(
                    "swp_exit_package_unusable",
                    "funding transaction template has an invalid shape",
                )),
            },
            _ => Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "funding transaction ID has an invalid shape",
            )),
        }
    }

    fn presigned_transaction(&self) -> Result<Option<Vec<u8>>, SwapClientError> {
        if self.mode()? != "presigned" {
            return Ok(None);
        }
        let root = object(&self.document, "exit package")?;
        let exit = object(root.get("exit").unwrap_or(&Value::Null), "exit transaction")?;
        let bytes = decode_hex(
            require_string(
                exit,
                "signed_transaction",
                None,
                "swp_exit_package_unusable",
            )?,
            "pre-signed exit transaction",
        )?;
        validate_signed_transaction_matches(self, &self.unsigned_transaction()?, &bytes)?;
        Ok(Some(bytes))
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], SwapClientError> {
        let transaction = Transaction::parse(&self.unsigned_transaction()?).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                format!("assembled exit transaction is invalid: {error}"),
            )
        })?;
        taproot_exit_sighash(self, &transaction)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingVerificationInput {
    pub raw_transaction: String,
    pub output_index: u32,
    pub expected_amount: String,
    pub expected_script_pubkey: String,
    pub taproot_output_key: String,
    pub taproot_script: String,
    pub taproot_control_block: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceVerificationInput {
    pub invoice: String,
    pub expected_network: String,
    pub expected_amount_msat: String,
    pub observed_at: u64,
    pub required_minimum_final_cltv_delta: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningReadinessRequest {
    pub order_id: String,
    pub leg_id: String,
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub amount_msat: String,
    pub network: String,
    pub invoice_expires_at: u64,
    pub minimum_final_cltv_delta: u64,
    pub maximum_routing_fee: String,
    pub hold_invoice_required: bool,
    pub hold_expiry_height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightningReadinessState {
    Acceptable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLightningReadiness {
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub observed_at: u64,
    pub state: LightningReadinessState,
}

type LightningReadinessAdapter<'a> =
    dyn FnMut(&LightningReadinessRequest) -> Result<LocalLightningReadiness, String> + 'a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningProgressRequest {
    pub order_id: String,
    pub effect_id: String,
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub hold_invoice_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightningProgressState {
    PaymentPending,
    HtlcsHeld,
    Settled,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLightningProgress {
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub observed_at: u64,
    pub view_sha256: String,
    pub state: LightningProgressState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightningDispositionState {
    Cancelled,
    UnpaidFinal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLightningDisposition {
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub observed_at: u64,
    pub view_sha256: String,
    pub state: LightningDispositionState,
    pub principal_moved: bool,
    pub external_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningDispositionRequest {
    pub effect_id: String,
    pub session_id: String,
    pub order_id: String,
    pub funding_effect_id: String,
    pub leg_id: String,
    pub invoice_sha256: String,
    pub payment_hash: String,
    pub observed_at: u64,
    pub view_sha256: String,
    pub state: LightningDispositionState,
    pub principal_moved: bool,
    pub evidence_reference_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLightningDisposition {
    request: ExternalEffectRequest,
    result: ExternalEffectResult,
    evidence_reference: Value,
}

impl VerifiedLightningDisposition {
    pub fn evidence_reference(&self) -> &Value {
        &self.evidence_reference
    }

    pub fn request_document(&self) -> Result<Value, SwapClientError> {
        let ExternalEffectRequest::LightningDisposition(request) = &self.request else {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "verified Lightning disposition contains another request type",
            ));
        };
        serde_json::to_value(request).map_err(|error| {
            SwapClientError::new(
                "swp_external_effect_conflict",
                format!("could not serialize verified Lightning disposition: {error}"),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "swap_type", rename_all = "snake_case")]
pub enum TimeoutLadder {
    Submarine {
        current_height: u32,
        fund_last: u32,
        claim_last: u32,
        refund_first: u32,
        chain_finality_blocks: u32,
        broadcast_safety_blocks: u32,
        reorg_safety_blocks: u32,
        invoice_expiration_time: u64,
        claim_expected_time: u64,
    },
    Reverse {
        current_height: u32,
        lock_last: u32,
        user_claim_last: u32,
        provider_refund_first: u32,
        hold_expiry_height: u32,
        chain_finality_blocks: u32,
        broadcast_safety_blocks: u32,
        reorg_safety_blocks: u32,
        lightning_settlement_blocks: u32,
    },
    Chain {
        destination_final: bool,
        destination_refund_time: u64,
        source_refund_time: u64,
        provider_claim_margin: u64,
        both_network_reorg_margins: u64,
        both_network_broadcast_margins: u64,
    },
}

impl TimeoutLadder {
    pub fn validate(&self) -> Result<(), SwapClientError> {
        let unsafe_ladder = || {
            SwapClientError::new(
                "swp_timeout_ladder_unsafe",
                "quoted timeout ladder does not preserve unilateral recovery",
            )
        };
        match self {
            Self::Submarine {
                current_height,
                fund_last,
                claim_last,
                refund_first,
                chain_finality_blocks,
                broadcast_safety_blocks,
                reorg_safety_blocks,
                invoice_expiration_time,
                claim_expected_time,
            } => {
                validate_positive(&[
                    *chain_finality_blocks,
                    *broadcast_safety_blocks,
                    *reorg_safety_blocks,
                ])?;
                validate_timelock_ladder(&[
                    Timelock::BlockHeight(*fund_last),
                    Timelock::BlockHeight(*claim_last),
                    Timelock::BlockHeight(*refund_first),
                ])
                .map_err(|_| unsafe_ladder())?;
                let final_claim = fund_last
                    .checked_add(*chain_finality_blocks)
                    .ok_or_else(unsafe_ladder)?;
                let refund_margin = claim_last
                    .checked_add(*broadcast_safety_blocks)
                    .and_then(|height| height.checked_add(*reorg_safety_blocks))
                    .ok_or_else(unsafe_ladder)?;
                if current_height >= fund_last
                    || final_claim > *claim_last
                    || refund_margin >= *refund_first
                    || invoice_expiration_time <= claim_expected_time
                {
                    return Err(unsafe_ladder());
                }
            }
            Self::Reverse {
                current_height,
                lock_last,
                user_claim_last,
                provider_refund_first,
                hold_expiry_height,
                chain_finality_blocks,
                broadcast_safety_blocks,
                reorg_safety_blocks,
                lightning_settlement_blocks,
            } => {
                validate_positive(&[
                    *chain_finality_blocks,
                    *broadcast_safety_blocks,
                    *reorg_safety_blocks,
                    *lightning_settlement_blocks,
                ])?;
                validate_timelock_ladder(&[
                    Timelock::BlockHeight(*lock_last),
                    Timelock::BlockHeight(*user_claim_last),
                    Timelock::BlockHeight(*provider_refund_first),
                    Timelock::BlockHeight(*hold_expiry_height),
                ])
                .map_err(|_| unsafe_ladder())?;
                let final_claim = lock_last
                    .checked_add(*chain_finality_blocks)
                    .ok_or_else(unsafe_ladder)?;
                let refund_margin = user_claim_last
                    .checked_add(*broadcast_safety_blocks)
                    .and_then(|height| height.checked_add(*reorg_safety_blocks))
                    .ok_or_else(unsafe_ladder)?;
                let hold_margin = provider_refund_first
                    .checked_add(*broadcast_safety_blocks)
                    .and_then(|height| height.checked_add(*lightning_settlement_blocks))
                    .ok_or_else(unsafe_ladder)?;
                if current_height >= lock_last
                    || final_claim > *user_claim_last
                    || refund_margin >= *provider_refund_first
                    || hold_margin >= *hold_expiry_height
                {
                    return Err(unsafe_ladder());
                }
            }
            Self::Chain {
                destination_final,
                destination_refund_time,
                source_refund_time,
                provider_claim_margin,
                both_network_reorg_margins,
                both_network_broadcast_margins,
            } => {
                let safe_source_time = destination_refund_time
                    .checked_add(*provider_claim_margin)
                    .and_then(|time| time.checked_add(*both_network_reorg_margins))
                    .and_then(|time| time.checked_add(*both_network_broadcast_margins))
                    .ok_or_else(unsafe_ladder)?;
                if !destination_final || source_refund_time < &safe_source_time {
                    return Err(unsafe_ladder());
                }
            }
        }
        Ok(())
    }

    fn swap_type(&self) -> SwapType {
        match self {
            Self::Submarine { .. } => SwapType::Submarine,
            Self::Reverse { .. } => SwapType::Reverse,
            Self::Chain { .. } => SwapType::Chain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBeforeFundInput {
    pub observed_at: u64,
    pub payment_hash: String,
    pub funding: FundingVerificationInput,
    pub invoice: Option<InvoiceVerificationInput>,
    pub timeout_ladder: TimeoutLadder,
    pub minimum_confirmations: u32,
    pub replacement_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingAuthorizationRequest {
    pub session_id: String,
    pub order_id: String,
    pub quote_id: String,
    pub swap_type: SwapType,
    pub action: FundingAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FundingAction {
    BroadcastBitcoin {
        effect_id: String,
        leg_id: String,
        raw_transaction: String,
    },
    PayLightningInvoice {
        effect_id: String,
        leg_id: String,
        invoice: String,
        maximum_routing_fee: String,
        invoice_expires_at: u64,
        minimum_final_cltv_delta: u64,
        hold_invoice_required: bool,
        hold_expiry_height: u32,
    },
}

impl FundingAction {
    pub fn effect_id(&self) -> &str {
        match self {
            Self::BroadcastBitcoin { effect_id, .. }
            | Self::PayLightningInvoice { effect_id, .. } => effect_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinObservationRequest {
    pub leg_id: String,
    pub transaction_template_sha256: String,
    pub output_index: u32,
    pub amount: String,
    pub script_pubkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBitcoinObservation {
    pub raw_transaction: String,
    pub confirmations: u32,
    pub replacement_detected: bool,
    pub competing_spend_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBitcoinFunding {
    pub leg_id: String,
    pub transaction_id: String,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwaitingVerification;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingAuthorized {
    _private: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversePaymentObserved {
    _private: (),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalEffectRequest {
    Funding(FundingAuthorizationRequest),
    WalletSigning(WalletSigningRequest),
    EsploraBroadcast(EsploraBroadcastRequest),
    RailEvidence(RailEvidenceRequest),
    LightningDisposition(LightningDispositionRequest),
}

impl ExternalEffectRequest {
    pub fn effect_id(&self) -> &str {
        match self {
            Self::Funding(request) => request.action.effect_id(),
            Self::WalletSigning(request) => &request.effect_id,
            Self::EsploraBroadcast(request) => &request.effect_id,
            Self::RailEvidence(request) => &request.effect_id,
            Self::LightningDisposition(request) => &request.effect_id,
        }
    }

    pub fn sha256(&self) -> Result<String, SwapClientError> {
        let value = serde_json::to_value(self).map_err(|error| {
            SwapClientError::new(
                "swp_external_effect_conflict",
                format!("could not serialize external effect request: {error}"),
            )
        })?;
        Ok(lower_hex(&sha256(&canonical_json(&value)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RailEvidenceRequest {
    pub effect_id: String,
    pub session_id: String,
    pub order_id: String,
    pub leg_id: String,
    pub outcome: String,
    pub rail: String,
    pub evidence_class: String,
    pub source_reference: String,
    pub reference: String,
    pub artifact_sha256: String,
    pub rung: String,
    pub verifier_policy: String,
    pub verifier_authority_sha256: String,
    pub observed_at: u64,
    pub view_sha256: String,
    pub finality_state: String,
    pub evidence_reference_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailObservationRequest {
    pub session_id: String,
    pub order_id: String,
    pub leg_id: String,
    pub outcome: String,
    pub rail: String,
    pub evidence_class: String,
    pub reference: String,
    pub rung: String,
    pub verifier_policy: String,
    pub verifier_authority_sha256: String,
    pub finality_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRailEvidence {
    pub artifact_sha256: String,
    pub observed_at: u64,
    pub view: String,
    pub settlement_reference: String,
    pub verifier_pubkey: Option<String>,
    pub producer_pubkey: String,
    pub external_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRailEvidence {
    request: ExternalEffectRequest,
    result: ExternalEffectResult,
    evidence_reference: Value,
}

impl VerifiedRailEvidence {
    pub fn evidence_reference(&self) -> &Value {
        &self.evidence_reference
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalEffectResult {
    order_id: String,
    effect_id: String,
    request_sha256: String,
    external_identifier: String,
    result_sha256: String,
}

impl ExternalEffectResult {
    pub fn order_id(&self) -> &str {
        &self.order_id
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    pub fn external_identifier(&self) -> &str {
        &self.external_identifier
    }

    pub fn result_sha256(&self) -> &str {
        &self.result_sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedExternalEffectResult {
    order_id: String,
    effect_id: String,
    request_sha256: String,
    external_identifier: String,
    result_sha256: String,
}

impl From<&ExternalEffectResult> for PersistedExternalEffectResult {
    fn from(result: &ExternalEffectResult) -> Self {
        Self {
            order_id: result.order_id.clone(),
            effect_id: result.effect_id.clone(),
            request_sha256: result.request_sha256.clone(),
            external_identifier: result.external_identifier.clone(),
            result_sha256: result.result_sha256.clone(),
        }
    }
}

impl From<PersistedExternalEffectResult> for ExternalEffectResult {
    fn from(result: PersistedExternalEffectResult) -> Self {
        Self {
            order_id: result.order_id,
            effect_id: result.effect_id,
            request_sha256: result.request_sha256,
            external_identifier: result.external_identifier,
            result_sha256: result.result_sha256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SwapSession<State> {
    config: SwapClientConfig,
    signed_records: Vec<Event>,
    exit_packages: Vec<ExitPackage>,
    external_effects: BTreeMap<String, ExternalEffectResult>,
    external_effect_requests: BTreeMap<String, ExternalEffectRequest>,
    funding_request: Option<FundingAuthorizationRequest>,
    _state: PhantomData<State>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSwapSession {
    schema: String,
    config: SwapClientConfig,
    signed_records: Vec<Event>,
    exit_packages: Vec<ExitPackage>,
    external_effects: Vec<PersistedExternalEffectResult>,
    #[serde(default)]
    external_effect_requests: Vec<ExternalEffectRequest>,
    #[serde(default)]
    funding_request: Option<FundingAuthorizationRequest>,
}

impl SwapSession<AwaitingVerification> {
    pub fn from_signed_records(
        config: SwapClientConfig,
        signed_records: Vec<Event>,
        exit_packages: Vec<ExitPackage>,
    ) -> Result<Self, SwapClientError> {
        config.validate()?;
        validate_session_material(&config, &signed_records, &exit_packages)?;
        validate_lifecycle(&config, &signed_records, &BTreeMap::new())?;
        Ok(Self {
            config,
            signed_records,
            exit_packages,
            external_effects: BTreeMap::new(),
            external_effect_requests: BTreeMap::new(),
            funding_request: None,
            _state: PhantomData,
        })
    }

    pub fn validate_negotiated_terms(&self) -> Result<(), SwapClientError> {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        bound.verify_contract_terms()?;
        bound.verify_requester_topology()
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, SwapClientError> {
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "persisted swap snapshot is empty or exceeds its bound",
            ));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("persisted swap snapshot is invalid JSON: {error}"),
            )
        })?;
        reject_custody_material(&value)?;
        let persisted: PersistedSwapSession = serde_json::from_value(value).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("persisted swap snapshot has an invalid shape: {error}"),
            )
        })?;
        if persisted.schema != SNAPSHOT_SCHEMA {
            return Err(SwapClientError::new(
                "swp_unsupported_version",
                "persisted swap snapshot schema is unsupported",
            ));
        }
        validate_session_material(
            &persisted.config,
            &persisted.signed_records,
            &persisted.exit_packages,
        )?;
        if let Some(request) = &persisted.funding_request {
            validate_persisted_funding_request(
                &persisted.config,
                &persisted.signed_records,
                &persisted.exit_packages,
                request,
            )?;
        }
        if persisted.external_effects.len() > MAX_EXTERNAL_EFFECTS
            || persisted.external_effect_requests.len() > MAX_EXTERNAL_EFFECTS
        {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "persisted swap snapshot has too many external effects",
            ));
        }
        let mut external_effects = BTreeMap::new();
        for effect in persisted.external_effects {
            let effect = ExternalEffectResult::from(effect);
            validate_effect(&effect)?;
            validate_effect_row_binding(
                &persisted.config,
                &persisted.signed_records,
                &persisted.exit_packages,
                &effect,
            )?;
            if let Some(previous) =
                external_effects.insert(effect.effect_id.clone(), effect.clone())
            {
                if previous != effect {
                    return Err(SwapClientError::new(
                        "swp_external_effect_conflict",
                        "persisted effect ID has conflicting results",
                    ));
                }
            }
        }
        let mut external_effect_requests = BTreeMap::new();
        for request in persisted.external_effect_requests {
            let effect_id = request.effect_id().to_owned();
            if external_effect_requests
                .insert(effect_id.clone(), request)
                .is_some()
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted effect ID has multiple typed requests",
                ));
            }
        }
        if external_effect_requests.len() != external_effects.len() {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "persisted effect ledger lacks an exact typed request",
            ));
        }
        for (effect_id, effect) in &external_effects {
            let request = external_effect_requests.get(effect_id).ok_or_else(|| {
                SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted effect has no exact typed request",
                )
            })?;
            validate_effect_request_binding(
                &persisted.config,
                &persisted.signed_records,
                &persisted.exit_packages,
                request,
                effect,
            )?;
        }
        let bound = BoundSession::from_records(&persisted.config, &persisted.signed_records)?;
        let topology = requester_topology(bound.swap_type);
        let funding_effect_id = effect_id(
            &bound.order.id,
            topology.funding_effect_role,
            topology.funding_leg_id,
        )?;
        if let Some(effect) = external_effects.get(&funding_effect_id) {
            let request = persisted.funding_request.as_ref().ok_or_else(|| {
                SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted funding effect has no exact authorization request",
                )
            })?;
            validate_effect_request_binding(
                &persisted.config,
                &persisted.signed_records,
                &persisted.exit_packages,
                &ExternalEffectRequest::Funding(request.clone()),
                effect,
            )?;
        }
        validate_lifecycle(
            &persisted.config,
            &persisted.signed_records,
            &external_effects,
        )?;
        validate_post_funding_effects(
            persisted.funding_request.as_ref(),
            &external_effect_requests,
            &external_effects,
        )?;
        Ok(Self {
            config: persisted.config,
            signed_records: persisted.signed_records,
            exit_packages: persisted.exit_packages,
            external_effects,
            external_effect_requests,
            funding_request: persisted.funding_request,
            _state: PhantomData,
        })
    }

    pub fn resume_funding_authorized(
        self,
    ) -> Result<SwapSession<FundingAuthorized>, SwapClientError> {
        if self.funding_request.is_none() {
            return Err(SwapClientError::new(
                "swp_funding_not_authorized",
                "persisted session has no verified funding authorization",
            ));
        }
        Ok(SwapSession {
            config: self.config,
            signed_records: self.signed_records,
            exit_packages: self.exit_packages,
            external_effects: self.external_effects,
            external_effect_requests: self.external_effect_requests,
            funding_request: self.funding_request,
            _state: PhantomData,
        })
    }

    pub fn verify_before_fund<F>(
        self,
        input: VerifyBeforeFundInput,
        wallet_authorize: F,
    ) -> Result<SwapSession<FundingAuthorized>, SwapClientError>
    where
        F: FnMut(&FundingAuthorizationRequest) -> Result<(), String>,
    {
        self.verify_before_fund_inner(input, None, wallet_authorize)
    }

    pub fn verify_before_fund_with_lightning<Observe, Authorize>(
        self,
        input: VerifyBeforeFundInput,
        mut observe_lightning: Observe,
        wallet_authorize: Authorize,
    ) -> Result<SwapSession<FundingAuthorized>, SwapClientError>
    where
        Observe: FnMut(&LightningReadinessRequest) -> Result<LocalLightningReadiness, String>,
        Authorize: FnMut(&FundingAuthorizationRequest) -> Result<(), String>,
    {
        self.verify_before_fund_inner(input, Some(&mut observe_lightning), wallet_authorize)
    }

    fn verify_before_fund_inner<F>(
        self,
        input: VerifyBeforeFundInput,
        mut observe_lightning: Option<&mut LightningReadinessAdapter<'_>>,
        mut wallet_authorize: F,
    ) -> Result<SwapSession<FundingAuthorized>, SwapClientError>
    where
        F: FnMut(&FundingAuthorizationRequest) -> Result<(), String>,
    {
        if effective_cancellation(&self.signed_records)?.is_some() {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "funding cannot begin after cancellation becomes effective",
            ));
        }
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        bound.verify_contract_terms()?;
        bound.verify_local_expiration(input.observed_at)?;
        bound.verify_requester_topology()?;
        input.timeout_ladder.validate()?;
        if input.timeout_ladder.swap_type() != bound.swap_type {
            return Err(SwapClientError::new(
                "swp_timeout_ladder_unsafe",
                "timeout ladder belongs to a different swap type",
            ));
        }
        let contract_ladder = object(&bound.contract, "Swap Contract")?
            .get("timeout_ladder")
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_timeout_ladder_unsafe",
                    "Swap Contract has no timeout ladder",
                )
            })?;
        if serde_json::to_value(&input.timeout_ladder).map_err(|error| {
            SwapClientError::new(
                "swp_timeout_ladder_unsafe",
                format!("could not serialize timeout ladder: {error}"),
            )
        })? != *contract_ladder
        {
            return Err(SwapClientError::new(
                "swp_timeout_ladder_unsafe",
                "local timeout ladder differs from the Swap Contract",
            ));
        }
        require_lower_hex_32(&input.payment_hash, "verification payment hash")?;
        if input.payment_hash != bound.payment_hash {
            return Err(SwapClientError::new(
                "swp_payment_hash_mismatch",
                "local payment hash differs from the bound contract",
            ));
        }
        verify_funding_input(&input, &bound)?;
        verify_invoice_input(&input, &bound)?;
        verify_exit_packages(&self.exit_packages, &bound)?;
        let topology = requester_topology(bound.swap_type);
        let funding_effect_id = effect_id(
            &bound.order.id,
            topology.funding_effect_role,
            topology.funding_leg_id,
        )?;
        let action = match bound.swap_type {
            SwapType::Submarine | SwapType::Chain => FundingAction::BroadcastBitcoin {
                effect_id: funding_effect_id,
                leg_id: topology.funding_leg_id.to_owned(),
                raw_transaction: input.funding.raw_transaction.clone(),
            },
            SwapType::Reverse => {
                let readiness_request = lightning_readiness_request(&input, &bound)?;
                let observe = observe_lightning.as_mut().ok_or_else(|| {
                    SwapClientError::new(
                        "swp_funding_not_authorized",
                        "reverse funding requires a local Lightning readiness adapter",
                    )
                })?;
                let readiness = observe(&readiness_request).map_err(|error| {
                    SwapClientError::new(
                        "swp_funding_not_authorized",
                        format!("local Lightning adapter refused readiness: {error}"),
                    )
                })?;
                validate_lightning_readiness(&readiness_request, &readiness, input.observed_at)?;
                FundingAction::PayLightningInvoice {
                    effect_id: funding_effect_id,
                    leg_id: topology.funding_leg_id.to_owned(),
                    invoice: input
                        .invoice
                        .as_ref()
                        .ok_or_else(|| {
                            SwapClientError::new(
                                "swp_invoice_invalid",
                                "reverse funding requires the verified invoice",
                            )
                        })?
                        .invoice
                        .clone(),
                    maximum_routing_fee: readiness_request.maximum_routing_fee,
                    invoice_expires_at: readiness_request.invoice_expires_at,
                    minimum_final_cltv_delta: readiness_request.minimum_final_cltv_delta,
                    hold_invoice_required: readiness_request.hold_invoice_required,
                    hold_expiry_height: readiness_request.hold_expiry_height,
                }
            }
        };
        let request = FundingAuthorizationRequest {
            session_id: self.config.session_id.clone(),
            order_id: bound.order.id.clone(),
            quote_id: bound.quote.id.clone(),
            swap_type: bound.swap_type,
            action,
        };
        if let Some(previous) = self.external_effects.get(request.action.effect_id()) {
            validate_effect(previous)?;
            if previous.request_sha256
                != ExternalEffectRequest::Funding(request.clone()).sha256()?
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "recorded funding effect differs from the verified funding request",
                ));
            }
        } else {
            wallet_authorize(&request).map_err(|error| {
                SwapClientError::new(
                    "swp_funding_not_authorized",
                    format!("embedding wallet refused funding: {error}"),
                )
            })?;
        }
        Ok(SwapSession {
            config: self.config,
            signed_records: self.signed_records,
            exit_packages: self.exit_packages,
            external_effects: self.external_effects,
            external_effect_requests: self.external_effect_requests,
            funding_request: Some(request),
            _state: PhantomData::<FundingAuthorized>,
        })
    }
}

impl SwapSession<FundingAuthorized> {
    pub fn funding_request(&self) -> Result<&FundingAuthorizationRequest, SwapClientError> {
        self.funding_request.as_ref().ok_or_else(|| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                "funding request is unavailable until verification succeeds",
            )
        })
    }

    pub fn observe_reverse_payment_with<F>(
        self,
        mut observe: F,
    ) -> Result<SwapSession<ReversePaymentObserved>, SwapClientError>
    where
        F: FnMut(&LightningProgressRequest) -> Result<LocalLightningProgress, String>,
    {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        if bound.swap_type != SwapType::Reverse {
            return Err(SwapClientError::new(
                "swp_funding_not_authorized",
                "Lightning payment progression applies only to reverse swaps",
            ));
        }
        let funding = self.funding_request.as_ref().ok_or_else(|| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                "reverse payment progression has no funding request",
            )
        })?;
        let FundingAction::PayLightningInvoice {
            effect_id,
            invoice,
            hold_invoice_required,
            invoice_expires_at,
            ..
        } = &funding.action
        else {
            return Err(SwapClientError::new(
                "swp_funding_not_authorized",
                "reverse payment progression has no Lightning payment effect",
            ));
        };
        if !self.external_effects.contains_key(effect_id) {
            return Err(SwapClientError::new(
                "swp_funding_not_authorized",
                "reverse payment must be durably recorded before observing progression",
            ));
        }
        let request = LightningProgressRequest {
            order_id: funding.order_id.clone(),
            effect_id: effect_id.clone(),
            invoice_sha256: lower_hex(&sha256(invoice.as_bytes())),
            payment_hash: bound.payment_hash,
            hold_invoice_required: *hold_invoice_required,
        };
        let observation = observe(&request).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("local Lightning progression adapter failed: {error}"),
            )
        })?;
        require_lower_hex_32(
            &observation.view_sha256,
            "Lightning progression view digest",
        )?;
        if observation.invoice_sha256 != request.invoice_sha256
            || observation.payment_hash != request.payment_hash
            || observation.observed_at >= *invoice_expires_at
            || !matches!(
                observation.state,
                LightningProgressState::PaymentPending | LightningProgressState::HtlcsHeld
            )
        {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Lightning progression is terminal, contradictory, or belongs to another payment",
            ));
        }
        Ok(SwapSession {
            config: self.config,
            signed_records: self.signed_records,
            exit_packages: self.exit_packages,
            external_effects: self.external_effects,
            external_effect_requests: self.external_effect_requests,
            funding_request: self.funding_request,
            _state: PhantomData::<ReversePaymentObserved>,
        })
    }

    pub fn verify_reverse_no_fund_with<F>(
        &self,
        mut observe: F,
    ) -> Result<VerifiedLightningDisposition, SwapClientError>
    where
        F: FnMut(&LightningProgressRequest) -> Result<LocalLightningDisposition, String>,
    {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        if bound.swap_type != SwapType::Reverse {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "Lightning no-fund disposition applies only to reverse swaps",
            ));
        }
        let funding = self.funding_request.as_ref().ok_or_else(|| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                "Lightning no-fund disposition has no persisted funding authorization",
            )
        })?;
        let FundingAction::PayLightningInvoice {
            effect_id: funding_effect_id,
            leg_id,
            invoice,
            hold_invoice_required,
            ..
        } = &funding.action
        else {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "Lightning no-fund disposition has no bound invoice payment",
            ));
        };
        if !self.external_effects.contains_key(funding_effect_id) {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "Lightning payment initiation must be persisted before its disposition",
            ));
        }
        let observation_request = LightningProgressRequest {
            order_id: bound.order.id.clone(),
            effect_id: funding_effect_id.clone(),
            invoice_sha256: lower_hex(&sha256(invoice.as_bytes())),
            payment_hash: bound.payment_hash.clone(),
            hold_invoice_required: *hold_invoice_required,
        };
        let observation = observe(&observation_request).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("local Lightning disposition adapter failed: {error}"),
            )
        })?;
        require_lower_hex_32(&observation.view_sha256, "Lightning disposition view")?;
        if observation.invoice_sha256 != observation_request.invoice_sha256
            || observation.payment_hash != observation_request.payment_hash
            || observation.principal_moved
        {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Lightning disposition does not prove exact zero-principal finality",
            ));
        }
        let evidence_reference = json!({
            "invoice_sha256": observation.invoice_sha256,
            "payment_hash": observation.payment_hash,
            "observed_at": observation.observed_at,
            "view_sha256": observation.view_sha256,
            "state": observation.state,
            "principal_moved": observation.principal_moved,
        });
        let evidence_reference_sha256 = lower_hex(&sha256(&canonical_json(&evidence_reference)?));
        let effect_id = effect_id(&bound.order.id, "lightning_disposition", leg_id)?;
        let request = LightningDispositionRequest {
            effect_id: effect_id.clone(),
            session_id: self.config.session_id.clone(),
            order_id: bound.order.id.clone(),
            funding_effect_id: funding_effect_id.clone(),
            leg_id: leg_id.clone(),
            invoice_sha256: observation_request.invoice_sha256,
            payment_hash: observation_request.payment_hash,
            observed_at: observation.observed_at,
            view_sha256: observation.view_sha256,
            state: observation.state,
            principal_moved: observation.principal_moved,
            evidence_reference_sha256: evidence_reference_sha256.clone(),
        };
        let request = ExternalEffectRequest::LightningDisposition(request);
        let result = ExternalEffectResult {
            order_id: bound.order.id.clone(),
            effect_id,
            request_sha256: request.sha256()?,
            external_identifier: observation.external_identifier,
            result_sha256: evidence_reference_sha256,
        };
        validate_effect(&result)?;
        validate_effect_request_binding(
            &self.config,
            &self.signed_records,
            &self.exit_packages,
            &request,
            &result,
        )?;
        Ok(VerifiedLightningDisposition {
            request,
            result,
            evidence_reference,
        })
    }

    pub fn sign_exit_with<F>(
        &self,
        package_index: usize,
        wallet_sign: F,
    ) -> Result<ExitSigningOutcome, SwapClientError>
    where
        F: FnMut(&WalletSigningRequest) -> Result<Vec<u8>, String>,
    {
        if BoundSession::from_records(&self.config, &self.signed_records)?.swap_type
            == SwapType::Reverse
        {
            return Err(SwapClientError::new(
                "swp_funding_not_authorized",
                "reverse exit signing requires a post-payment Lightning observation",
            ));
        }
        self.sign_exit_inner(package_index, wallet_sign)
    }
}

impl SwapSession<ReversePaymentObserved> {
    pub fn sign_exit_with<F>(
        &self,
        package_index: usize,
        wallet_sign: F,
    ) -> Result<ExitSigningOutcome, SwapClientError>
    where
        F: FnMut(&WalletSigningRequest) -> Result<Vec<u8>, String>,
    {
        self.sign_exit_inner(package_index, wallet_sign)
    }
}

impl<State> SwapSession<State> {
    pub fn config(&self) -> &SwapClientConfig {
        &self.config
    }

    pub fn signed_records(&self) -> &[Event] {
        &self.signed_records
    }

    pub fn exit_packages(&self) -> &[ExitPackage] {
        &self.exit_packages
    }

    pub fn status_projection(&self) -> Result<StatusProjection, SwapClientError> {
        StatusProjection::from_records(&self.config, &self.signed_records)
    }

    fn requester_session_view(
        &self,
        deliveries: Vec<SignedRecordDelivery>,
    ) -> Result<RequesterSessionView, SwapClientError> {
        validate_session_material(&self.config, &self.signed_records, &self.exit_packages)?;
        validate_effect_ledger(
            &self.config,
            &self.signed_records,
            &self.exit_packages,
            self.funding_request.as_ref(),
            &self.external_effect_requests,
            &self.external_effects,
        )?;
        RequesterSessionView::from_signed_records_internal(
            &self.config,
            &self.signed_records,
            deliveries,
            Some(&self.external_effects),
        )
    }

    pub fn ingest_signed_record(&mut self, event: Event) -> Result<bool, SwapClientError> {
        if let Some(existing) = self
            .signed_records
            .iter()
            .find(|existing| existing.id == event.id)
        {
            if existing == &event {
                return Ok(false);
            }
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "one signed event ID maps to different record bytes",
            ));
        }
        let distinct = tag_value(&event, "d")?;
        if self.signed_records.iter().any(|existing| {
            existing.kind == event.kind
                && existing.pubkey == event.pubkey
                && tag_value(existing, "d").ok() == Some(distinct)
        }) {
            return Err(SwapClientError::new(
                "swp_idempotency_conflict",
                "immutable signed record address already has different content",
            ));
        }
        let mut candidate = self.signed_records.clone();
        candidate.push(event);
        validate_session_material(&self.config, &candidate, &self.exit_packages)?;
        validate_lifecycle(&self.config, &candidate, &self.external_effects)?;
        self.signed_records = candidate;
        Ok(true)
    }

    pub fn record_external_effect(
        &mut self,
        request: &ExternalEffectRequest,
        external_identifier: impl Into<String>,
        result_sha256: impl Into<String>,
    ) -> Result<&ExternalEffectResult, SwapClientError> {
        if matches!(
            request,
            ExternalEffectRequest::RailEvidence(_) | ExternalEffectRequest::LightningDisposition(_)
        ) {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "terminal evidence must be recorded through its typed verified recorder",
            ));
        }
        let order_id = BoundSession::from_records(&self.config, &self.signed_records)?
            .order
            .id
            .clone();
        let effect = ExternalEffectResult {
            order_id,
            effect_id: request.effect_id().to_owned(),
            request_sha256: request.sha256()?,
            external_identifier: external_identifier.into(),
            result_sha256: result_sha256.into(),
        };
        self.record_external_effect_result(request, effect)
    }

    pub fn record_verified_rail_evidence(
        &mut self,
        verified: VerifiedRailEvidence,
    ) -> Result<&ExternalEffectResult, SwapClientError> {
        self.record_external_effect_result(&verified.request, verified.result)
    }

    pub fn record_verified_lightning_disposition(
        &mut self,
        verified: VerifiedLightningDisposition,
    ) -> Result<&ExternalEffectResult, SwapClientError> {
        self.record_external_effect_result(&verified.request, verified.result)
    }

    fn record_external_effect_result(
        &mut self,
        request: &ExternalEffectRequest,
        effect: ExternalEffectResult,
    ) -> Result<&ExternalEffectResult, SwapClientError> {
        if effective_cancellation(&self.signed_records)?.is_some() {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "external effects cannot begin after cancellation becomes effective",
            ));
        }
        match request {
            ExternalEffectRequest::Funding(request)
                if self.funding_request.as_ref() != Some(request) =>
            {
                return Err(SwapClientError::new(
                    "swp_funding_not_authorized",
                    "funding effect does not match a verified persisted authorization",
                ));
            }
            ExternalEffectRequest::WalletSigning(_)
            | ExternalEffectRequest::EsploraBroadcast(_)
            | ExternalEffectRequest::RailEvidence(_)
            | ExternalEffectRequest::LightningDisposition(_)
                if self.funding_request.is_none() =>
            {
                return Err(SwapClientError::new(
                    "swp_funding_not_authorized",
                    "post-funding effect has no verified persisted authorization",
                ));
            }
            _ => {}
        }
        if matches!(
            request,
            ExternalEffectRequest::RailEvidence(_) | ExternalEffectRequest::LightningDisposition(_)
        ) {
            require_exact_funding_effect(
                self.funding_request.as_ref(),
                &self.external_effect_requests,
                &self.external_effects,
            )?;
        }
        validate_effect(&effect)?;
        validate_effect_request_binding(
            &self.config,
            &self.signed_records,
            &self.exit_packages,
            request,
            &effect,
        )?;
        if self.external_effects.contains_key(&effect.effect_id) {
            let previous = self
                .external_effects
                .get(&effect.effect_id)
                .ok_or_else(|| {
                    SwapClientError::new("swp_external_effect_conflict", "effect lookup failed")
                })?;
            if previous == &effect {
                return Ok(previous);
            }
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "one effect ID maps to different external operations",
            ));
        }
        if self.external_effects.len() >= MAX_EXTERNAL_EFFECTS {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "external effect bound exceeded",
            ));
        }
        let effect_id = effect.effect_id.clone();
        self.external_effect_requests
            .insert(effect_id.clone(), request.clone());
        self.external_effects.insert(effect_id.clone(), effect);
        self.external_effects.get(&effect_id).ok_or_else(|| {
            SwapClientError::new("swp_external_effect_conflict", "effect insertion failed")
        })
    }

    fn sign_exit_inner<F>(
        &self,
        package_index: usize,
        mut wallet_sign: F,
    ) -> Result<ExitSigningOutcome, SwapClientError>
    where
        F: FnMut(&WalletSigningRequest) -> Result<Vec<u8>, String>,
    {
        let package = self.exit_packages.get(package_index).ok_or_else(|| {
            SwapClientError::new("swp_exit_package_missing", "exit package index is missing")
        })?;
        if package.mode()? == "presigned" {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "pre-signed package does not need a wallet callback",
            ));
        }
        let request = wallet_signing_request(package)?;
        if let Some(previous) = self.external_effects.get(&request.effect_id) {
            if previous.request_sha256
                != ExternalEffectRequest::WalletSigning(request.clone()).sha256()?
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "recorded exit effect differs from the exact wallet-signing request",
                ));
            }
            return Ok(ExitSigningOutcome::AlreadyExecuted {
                effect_id: request.effect_id,
                external_identifier: previous.external_identifier.clone(),
            });
        }
        let unsigned = decode_hex(&request.unsigned_transaction, "unsigned exit transaction")?;
        let signed = wallet_sign(&request).map_err(|error| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                format!("embedding wallet refused exit signing: {error}"),
            )
        })?;
        validate_signed_transaction_matches(package, &unsigned, &signed)?;
        Ok(ExitSigningOutcome::Signed(SignedExitTransaction {
            effect_id: request.effect_id,
            path: request.path,
            transaction: lower_hex(&signed),
        }))
    }

    pub fn verify_terminal_rail_evidence_with<F>(
        &self,
        leg_id: &str,
        outcome: &str,
        mut observe: F,
    ) -> Result<VerifiedRailEvidence, SwapClientError>
    where
        F: FnMut(&RailObservationRequest) -> Result<LocalRailEvidence, String>,
    {
        require_exact_funding_effect(
            self.funding_request.as_ref(),
            &self.external_effect_requests,
            &self.external_effects,
        )?;
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        let observation_request = rail_observation_request(&bound, leg_id, outcome)?;
        let observation = observe(&observation_request).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("local rail evidence adapter failed: {error}"),
            )
        })?;
        require_lower_hex_32(
            &observation.artifact_sha256,
            "rail evidence artifact digest",
        )?;
        require_lower_hex_32(&observation.producer_pubkey, "rail evidence producer")?;
        if let Some(verifier_pubkey) = &observation.verifier_pubkey {
            require_lower_hex_32(verifier_pubkey, "rail evidence verifier")?;
        }
        if observation.view.is_empty()
            || observation.view.len() > 512
            || observation.external_identifier.is_empty()
            || observation.external_identifier.len() > 512
            || observation.settlement_reference.is_empty()
            || observation.settlement_reference.len() > 512
            || observation
                .view
                .chars()
                .chain(observation.external_identifier.chars())
                .chain(observation.settlement_reference.chars())
                .any(char::is_control)
        {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "local rail evidence view or identifier is unbounded",
            ));
        }
        if observation_request.evidence_class == "bitcoin_spend" {
            let verifier = verifier_for_leg(object(&bound.contract, "Swap Contract")?, leg_id)?;
            let funding_artifact = require_string(
                verifier,
                "funding_transaction_sha256",
                None,
                "swp_unresolved_loss",
            )?;
            if observation.artifact_sha256 == funding_artifact
                || observation.external_identifier == observation_request.reference
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "Bitcoin spend evidence reuses only the funding artifact identity",
                ));
            }
        }
        let view_sha256 = lower_hex(&sha256(observation.view.as_bytes()));
        let effect_id = effect_id(
            &bound.order.id,
            &format!("terminal_evidence_{outcome}"),
            leg_id,
        )?;
        let evidence_reference = json!({
            "class": observation_request.evidence_class,
            "rung": observation_request.rung,
            "rail": observation_request.rail,
            "reference": observation.settlement_reference,
            "artifact_sha256": observation.artifact_sha256,
            "producer_pubkey": observation.producer_pubkey,
            "verifier_pubkey": observation.verifier_pubkey,
            "verifier_policy": observation_request.verifier_policy,
            "observed_at": observation.observed_at,
            "view": observation.view,
        });
        validate_mkt_swp_evidence_reference(&evidence_reference).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("local rail evidence reference is invalid: {error}"),
            )
        })?;
        let verifier = verifier_for_leg(object(&bound.contract, "Swap Contract")?, leg_id)?;
        if !evidence_verifier_is_authorized(
            object(&evidence_reference, "rail evidence reference")?,
            verifier,
        ) {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "local rail evidence verifier is outside the frozen authority",
            ));
        }
        let result_sha256 = lower_hex(&sha256(&canonical_json(&evidence_reference)?));
        let request = RailEvidenceRequest {
            effect_id: effect_id.clone(),
            session_id: self.config.session_id.clone(),
            order_id: bound.order.id.clone(),
            leg_id: leg_id.to_owned(),
            outcome: outcome.to_owned(),
            rail: observation_request.rail.clone(),
            evidence_class: observation_request.evidence_class.clone(),
            source_reference: observation_request.reference.clone(),
            reference: observation.settlement_reference.clone(),
            artifact_sha256: observation.artifact_sha256.clone(),
            rung: observation_request.rung.clone(),
            verifier_policy: observation_request.verifier_policy.clone(),
            verifier_authority_sha256: observation_request.verifier_authority_sha256.clone(),
            observed_at: observation.observed_at,
            view_sha256,
            finality_state: observation_request.finality_state.clone(),
            evidence_reference_sha256: result_sha256.clone(),
        };
        validate_rail_evidence_request(&bound, &request)?;
        let effect_request = ExternalEffectRequest::RailEvidence(request);
        let result = ExternalEffectResult {
            order_id: bound.order.id.clone(),
            effect_id,
            request_sha256: effect_request.sha256()?,
            external_identifier: observation.external_identifier,
            result_sha256,
        };
        Ok(VerifiedRailEvidence {
            request: effect_request,
            result,
            evidence_reference,
        })
    }

    pub fn observe_bitcoin_funding_with<F>(
        &self,
        leg_id: &str,
        mut local_adapter: F,
    ) -> Result<VerifiedBitcoinFunding, SwapClientError>
    where
        F: FnMut(&BitcoinObservationRequest) -> Result<LocalBitcoinObservation, String>,
    {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        let contract = object(&bound.contract, "Swap Contract")?;
        let verifier = verifier_for_leg(contract, leg_id)?;
        let request = BitcoinObservationRequest {
            leg_id: leg_id.to_owned(),
            transaction_template_sha256: require_string(
                verifier,
                "funding_transaction_sha256",
                None,
                "swp_contract_terms_mismatch",
            )?
            .to_owned(),
            output_index: required_u32(verifier, "output_index")?,
            amount: require_string(verifier, "amount", None, "swp_contract_terms_mismatch")?
                .to_owned(),
            script_pubkey: require_string(
                verifier,
                "script_pubkey",
                None,
                "swp_contract_terms_mismatch",
            )?
            .to_owned(),
        };
        let observation = local_adapter(&request).map_err(|error| {
            SwapClientError::new(
                "swp_confirmation_insufficient",
                format!("local Bitcoin adapter refused observation: {error}"),
            )
        })?;
        verify_bitcoin_observation(verifier, &request, &observation)
    }

    pub fn persist(&self) -> Result<Vec<u8>, SwapClientError> {
        let persisted = PersistedSwapSession {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            config: self.config.clone(),
            signed_records: self.signed_records.clone(),
            exit_packages: self.exit_packages.clone(),
            external_effects: self
                .external_effects
                .values()
                .map(PersistedExternalEffectResult::from)
                .collect(),
            external_effect_requests: self.external_effect_requests.values().cloned().collect(),
            funding_request: self.funding_request.clone(),
        };
        let value = serde_json::to_value(&persisted).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("could not serialize swap snapshot: {error}"),
            )
        })?;
        reject_custody_material(&value)?;
        let mut bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("could not serialize swap snapshot: {error}"),
            )
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "swap snapshot exceeds its persisted bound",
            ));
        }
        Ok(bytes)
    }

    pub fn recovery_action_with<F>(&self, mut observe: F) -> Result<RecoveryAction, SwapClientError>
    where
        F: FnMut(&RecoveryObservationRequest) -> Result<LocalRecoveryObservation, String>,
    {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        bound.verify_contract_terms()?;
        bound.verify_requester_topology()?;
        verify_exit_packages(&self.exit_packages, &bound)?;
        let source_refund = exit_package(&self.exit_packages, "source", "refund");
        let source_refund_condition = source_refund
            .map(recovery_timeout_condition)
            .transpose()?
            .flatten();
        let rail_bindings = recovery_rail_bindings(&bound)?;
        let binding_sha256 = lower_hex(&sha256(&canonical_json(
            &serde_json::to_value(&rail_bindings).map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("could not serialize recovery rail bindings: {error}"),
                )
            })?,
        )?));
        let request = RecoveryObservationRequest {
            session_id: self.config.session_id.clone(),
            order_id: bound.order.id.clone(),
            swap_type: bound.swap_type,
            payment_hash: bound.payment_hash.clone(),
            rail_bindings,
            binding_sha256,
            source_refund_condition,
        };
        let observation = observe(&request).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("local recovery adapter refused observation: {error}"),
            )
        })?;
        if observation.session_id != request.session_id
            || observation.order_id != request.order_id
            || observation.binding_sha256 != request.binding_sha256
        {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "local recovery observation belongs to a different session or rail binding",
            ));
        }
        if observation.completed && (observation.record_loss || observation.rail_state_unknown) {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "recovery observation contradicts completion with loss or unknown rail state",
            ));
        }
        if recovery_observation_is_contradictory(bound.swap_type, &observation) {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "recovery observation contains contradictory rail states",
            ));
        }
        if observation.record_loss || observation.rail_state_unknown {
            return Ok(RecoveryAction::ExplicitLoss {
                code: "swp_unresolved_loss".to_owned(),
            });
        }
        if observation.completed {
            let projection = StatusProjection::from_records(&self.config, &self.signed_records)?;
            projection.require_contiguous()?;
            let has_terminal_status = projection.last_valid_status.values().any(|status_id| {
                self.signed_records
                    .iter()
                    .find(|event| event.id == *status_id)
                    .and_then(|event| status_state(event).ok())
                    .is_some_and(|state| state == "completed")
            });
            if !has_terminal_status {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "recovery completion lacks a contiguous locally validated terminal Status",
                ));
            }
            return Ok(RecoveryAction::Completed);
        }
        match bound.swap_type {
            SwapType::Submarine if observation.counterparty_available => {
                Ok(RecoveryAction::DirectCounterpartyCompletion)
            }
            SwapType::Submarine
                if observation.lightning_state != Some(LightningRecoveryState::UnpaidFinal) =>
            {
                Ok(RecoveryAction::WaitForCounterparty)
            }
            SwapType::Submarine => {
                refund_action(source_refund, &observation, &self.external_effects)
            }
            SwapType::Reverse
                if observation.chain_state == Some(ChainRecoveryState::DestinationClaimable) =>
            {
                claim_action(
                    exit_package(&self.exit_packages, "destination", "claim"),
                    &self.external_effects,
                )
            }
            SwapType::Reverse
                if observation.chain_state
                    == Some(ChainRecoveryState::DestinationRefundedFinal) =>
            {
                match observation.lightning_state {
                    Some(LightningRecoveryState::UnpaidFinal) => Ok(RecoveryAction::Cancelled),
                    Some(LightningRecoveryState::Pending) if observation.counterparty_available => {
                        Ok(RecoveryAction::WaitForCounterparty)
                    }
                    Some(LightningRecoveryState::Paid)
                    | Some(LightningRecoveryState::Pending)
                    | None => Ok(RecoveryAction::ExplicitLoss {
                        code: "swp_unresolved_loss".to_owned(),
                    }),
                }
            }
            SwapType::Reverse
                if observation.chain_state == Some(ChainRecoveryState::DestinationNotFunded)
                    && observation.lightning_state == Some(LightningRecoveryState::UnpaidFinal) =>
            {
                Ok(RecoveryAction::Cancelled)
            }
            SwapType::Reverse => Ok(RecoveryAction::WaitForCounterparty),
            SwapType::Chain if observation.counterparty_available => {
                Ok(RecoveryAction::DirectCounterpartyCompletion)
            }
            SwapType::Chain => match observation.chain_state {
                Some(ChainRecoveryState::DestinationClaimable) => claim_action(
                    exit_package(&self.exit_packages, "destination", "claim"),
                    &self.external_effects,
                ),
                Some(ChainRecoveryState::DestinationFundedUnclaimed) => {
                    Ok(RecoveryAction::WaitForDestinationRefund)
                }
                Some(
                    ChainRecoveryState::DestinationNotFunded
                    | ChainRecoveryState::DestinationRefundedFinal,
                ) => refund_action(source_refund, &observation, &self.external_effects),
                None => Ok(RecoveryAction::ExplicitLoss {
                    code: "swp_unresolved_loss".to_owned(),
                }),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSigningRequest {
    pub effect_id: String,
    pub path: String,
    pub unsigned_transaction: String,
    pub signature_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedExitTransaction {
    pub effect_id: String,
    pub path: String,
    pub transaction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitSigningOutcome {
    Signed(SignedExitTransaction),
    AlreadyExecuted {
        effect_id: String,
        external_identifier: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsploraBroadcastRequest {
    pub effect_id: String,
    pub method: String,
    pub url: String,
    pub content_type: String,
    pub body: String,
}

pub struct KeylessEsploraExecutor;

impl KeylessEsploraExecutor {
    pub fn request(
        package: &ExitPackage,
        esplora_url: &str,
    ) -> Result<EsploraBroadcastRequest, SwapClientError> {
        let transaction = package.presigned_transaction()?.ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "keyless executor requires a complete pre-signed transaction",
            )
        })?;
        let base = validate_esplora_url(esplora_url)?;
        Ok(EsploraBroadcastRequest {
            effect_id: package.effect_id()?.to_owned(),
            method: "POST".to_owned(),
            url: format!("{base}/tx"),
            content_type: "text/plain".to_owned(),
            body: lower_hex(&transaction),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservationRequest {
    pub session_id: String,
    pub order_id: String,
    pub swap_type: SwapType,
    pub payment_hash: String,
    pub rail_bindings: Vec<RecoveryRailBinding>,
    pub binding_sha256: String,
    pub source_refund_condition: Option<RecoveryTimeoutCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRailBinding {
    pub leg_id: String,
    pub rail: String,
    pub verifier_digest: String,
    pub funding_transaction_sha256: Option<String>,
    pub output_index: Option<u32>,
    pub amount: String,
    pub script_pubkey: Option<String>,
    pub confirmation_policy_sha256: Option<String>,
    pub invoice_sha256: Option<String>,
    pub claim_effect_id: Option<String>,
    pub refund_effect_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "condition", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryTimeoutCondition {
    Cltv { lock_height: u32 },
    Csv { delay_blocks: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecoveryObservation {
    pub session_id: String,
    pub order_id: String,
    pub binding_sha256: String,
    pub current_height: u32,
    pub source_funding_confirmation_height: Option<u32>,
    pub counterparty_available: bool,
    pub completed: bool,
    pub record_loss: bool,
    pub rail_state_unknown: bool,
    pub lightning_state: Option<LightningRecoveryState>,
    pub chain_state: Option<ChainRecoveryState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LightningRecoveryState {
    Pending,
    Paid,
    UnpaidFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRecoveryState {
    DestinationNotFunded,
    DestinationClaimable,
    DestinationFundedUnclaimed,
    DestinationRefundedFinal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    DirectCounterpartyCompletion,
    BroadcastPresigned {
        effect_id: String,
    },
    RequestWalletClaim {
        effect_id: String,
    },
    RequestWalletRefund {
        effect_id: String,
    },
    WaitForCounterparty,
    WaitForDestinationRefund,
    WaitForTimeout,
    Cancelled,
    Completed,
    AlreadyExecuted {
        effect_id: String,
        external_identifier: String,
    },
    ExplicitLoss {
        code: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProjection {
    pub streams: BTreeMap<String, BTreeMap<u64, Vec<String>>>,
    pub gaps: BTreeMap<String, Vec<u64>>,
    pub forks: BTreeMap<String, Vec<u64>>,
    pub close_records: Vec<String>,
    pub invalid_claims: BTreeMap<String, String>,
    pub last_valid_status: BTreeMap<String, String>,
}

impl StatusProjection {
    pub(crate) fn from_records(
        config: &SwapClientConfig,
        records: &[Event],
    ) -> Result<Self, SwapClientError> {
        let mut streams: BTreeMap<String, BTreeMap<u64, Vec<String>>> = BTreeMap::new();
        let mut status_events: BTreeMap<String, BTreeMap<u64, Vec<&Event>>> = BTreeMap::new();
        let mut cooperative_messages = Vec::new();
        let mut close_records = Vec::new();
        let mut invalid_claims = BTreeMap::new();
        let swap_type = quote_swap_type(records)?;
        for event in records {
            if event.kind == MKT_CLOSE_KIND {
                close_records.push(event.id.clone());
                continue;
            }
            if event.kind != MKT_STATUS_KIND {
                continue;
            }
            let sequence = tag_value(event, "seq")?
                .parse::<u64>()
                .map_err(|_| SwapClientError::new("swp_status_gap", "Status seq is invalid"))?;
            if sequence > MAX_STATUS_SEQUENCE {
                return Err(SwapClientError::new(
                    "swp_status_gap",
                    "Status seq exceeds the signed record bound",
                ));
            }
            let role = role_for_author(config, &event.pubkey)?;
            let content = parse_content(event)?;
            let swp_state = object(
                content.get("mkt_swp").unwrap_or(&Value::Null),
                "MKT-SWP Status",
            )?
            .get("swp_state")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new("swp_status_transition_invalid", "Status has no swp_state")
            })?;
            let declared_base_state = tag_value(event, "state")?;
            if base_state_for(swp_state) != Some(declared_base_state) {
                invalid_claims.insert(
                    event.id.clone(),
                    "swp_status_transition_invalid: base state tag does not match the MKT-SWP state"
                        .to_owned(),
                );
            }
            if !state_allowed_for_swap(role, swp_state, swap_type) {
                invalid_claims.insert(
                    event.id.clone(),
                    "swp_status_signer_invalid: state is unavailable to this signer or flow"
                        .to_owned(),
                );
            }
            if let Some(message) = cooperative_signing_message(event, role)? {
                if swp_state != "cooperative_signing_pending" {
                    return Err(musig_error(
                        "cooperative signing messages require the cooperative signing Status state",
                    ));
                }
                cooperative_messages.push((role, message));
            }
            streams
                .entry(event.pubkey.clone())
                .or_default()
                .entry(sequence)
                .or_default()
                .push(event.id.clone());
            status_events
                .entry(event.pubkey.clone())
                .or_default()
                .entry(sequence)
                .or_default()
                .push(event);
        }
        let mut gaps = BTreeMap::new();
        let mut forks = BTreeMap::new();
        for (author, stream) in &streams {
            let maximum = stream.keys().next_back().copied().unwrap_or_default();
            let missing = (0..=maximum)
                .filter(|sequence| !stream.contains_key(sequence))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                gaps.insert(author.clone(), missing);
            }
            let forked = stream
                .iter()
                .filter_map(|(sequence, ids)| (ids.len() > 1).then_some(*sequence))
                .collect::<Vec<_>>();
            if !forked.is_empty() {
                forks.insert(author.clone(), forked);
            }
        }
        for stream in status_events.values() {
            if stream.keys().next().copied() != Some(0) {
                continue;
            }
            if let Some(initial_events) = stream.get(&0) {
                for event in initial_events {
                    if event.tags.iter().any(|tag| {
                        tag.name() == Some("e")
                            && tag.as_slice().get(3).map(String::as_str) == Some("previous")
                    }) {
                        invalid_claims.insert(
                            event.id.clone(),
                            "swp_status_transition_invalid: seq 0 has a previous reference"
                                .to_owned(),
                        );
                    }
                }
            }
            for (sequence, events) in stream.range(1..) {
                let [event] = events.as_slice() else {
                    continue;
                };
                let Some(previous_sequence) = sequence.checked_sub(1) else {
                    continue;
                };
                let Some(previous_events) = stream.get(&previous_sequence) else {
                    continue;
                };
                let [previous_event] = previous_events.as_slice() else {
                    continue;
                };
                if require_marked_reference(event, "previous", &previous_event.id).is_err() {
                    invalid_claims.insert(
                        event.id.clone(),
                        "swp_status_transition_invalid: previous reference mismatch".to_owned(),
                    );
                    continue;
                }
                let previous_state = status_state(previous_event)?;
                let current_state = status_state(event)?;
                let cooperative_transition = cooperative_status_transition(
                    previous_event,
                    event,
                    config,
                    &previous_state,
                    &current_state,
                )?;
                if !cooperative_transition
                    && transition_rank(swap_type, &previous_state)
                        .zip(transition_rank(swap_type, &current_state))
                        .is_none_or(|(previous_rank, current_rank)| current_rank <= previous_rank)
                {
                    invalid_claims.insert(
                        event.id.clone(),
                        "swp_status_transition_invalid: claim regresses or leaves the flow"
                            .to_owned(),
                    );
                }
            }
        }
        validate_cooperative_signing_exchange(&cooperative_messages)?;
        let mut last_valid_status = BTreeMap::new();
        for (author, stream) in &status_events {
            let mut expected_sequence = 0_u64;
            let mut ancestry_valid = true;
            for (sequence, events) in stream {
                if *sequence != expected_sequence {
                    ancestry_valid = false;
                }
                expected_sequence = sequence.saturating_add(1);
                let [event] = events.as_slice() else {
                    ancestry_valid = false;
                    for event in events {
                        invalid_claims.entry(event.id.clone()).or_insert_with(|| {
                            "swp_status_transition_invalid: fork has ambiguous ancestry".to_owned()
                        });
                    }
                    continue;
                };
                if !ancestry_valid || invalid_claims.contains_key(&event.id) {
                    ancestry_valid = false;
                    invalid_claims.entry(event.id.clone()).or_insert_with(|| {
                        "swp_status_transition_invalid: claim descends from a gap, fork, or invalid claim"
                            .to_owned()
                    });
                    continue;
                }
                last_valid_status.insert(author.clone(), event.id.clone());
            }
        }
        Ok(Self {
            streams,
            gaps,
            forks,
            close_records,
            invalid_claims,
            last_valid_status,
        })
    }

    pub fn require_contiguous(&self) -> Result<(), SwapClientError> {
        if !self.forks.is_empty() {
            return Err(SwapClientError::new(
                "swp_status_fork",
                "one signer has conflicting Status records at one sequence",
            ));
        }
        if !self.gaps.is_empty() {
            return Err(SwapClientError::new(
                "swp_status_gap",
                "one signer has a missing Status sequence",
            ));
        }
        if !self.invalid_claims.is_empty() {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "one signer has an unauthorized or invalid Status claim",
            ));
        }
        Ok(())
    }

    pub(crate) fn require_signer_contiguous(&self, signer: &str) -> Result<(), SwapClientError> {
        if self.forks.contains_key(signer) {
            return Err(SwapClientError::new(
                "swp_status_fork",
                "Close signer has conflicting Status records at one sequence",
            ));
        }
        if self.gaps.contains_key(signer) {
            return Err(SwapClientError::new(
                "swp_status_gap",
                "Close signer has a missing Status sequence",
            ));
        }
        let signer_has_invalid_claim = self
            .streams
            .get(signer)
            .into_iter()
            .flat_map(BTreeMap::values)
            .flatten()
            .any(|event_id| self.invalid_claims.contains_key(event_id));
        if signer_has_invalid_claim {
            return Err(SwapClientError::new(
                "swp_status_transition_invalid",
                "Close signer has an unauthorized or invalid Status ancestor",
            ));
        }
        Ok(())
    }
}

struct BoundSession<'a> {
    session_id: String,
    rfq: &'a Event,
    quote: &'a Event,
    order: &'a Event,
    requester_contract: &'a Event,
    provider_contract: &'a Event,
    contract: Value,
    contract_sha256: String,
    swap_type: SwapType,
    payment_hash: String,
}

impl<'a> BoundSession<'a> {
    fn from_records(
        config: &SwapClientConfig,
        records: &'a [Event],
    ) -> Result<Self, SwapClientError> {
        let rfq = exactly_one(records, MKT_RFQ_KIND, "swp_unresolved_loss")?;
        let quote = exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
        let order = exactly_one(records, MKT_ORDER_KIND, "swp_contract_terms_mismatch")?;
        if rfq.pubkey != config.requester_pubkey
            || quote.pubkey != config.provider_pubkey
            || order.pubkey != config.requester_pubkey
        {
            return Err(SwapClientError::new(
                "swp_contract_signer_invalid",
                "RFQ, Quote, or Order author is not the configured participant",
            ));
        }
        let offering_references = rfq
            .tags
            .iter()
            .filter(|tag| {
                tag.name() == Some("a")
                    && tag.as_slice().get(3).map(String::as_str) == Some("offering")
            })
            .collect::<Vec<_>>();
        if !matches!(offering_references.as_slice(), [reference] if reference.value() == Some(config.offering_address.as_str()))
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "RFQ does not bind the configured Offering address",
            ));
        }
        require_marked_reference(quote, "rfq", &rfq.id)?;
        require_marked_reference(order, "quote", &quote.id)?;
        let quote_profile = validate_requester_quote(config, rfq, quote)?;
        reject_unsupported_executable_quote(&quote_profile)?;
        let contracts = records
            .iter()
            .filter(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
            .collect::<Vec<_>>();
        let requester_contract = contracts
            .iter()
            .copied()
            .find(|event| event.pubkey == config.requester_pubkey)
            .ok_or_else(|| {
                SwapClientError::new("swp_contract_missing", "requester Swap Contract is missing")
            })?;
        let provider_contract = contracts
            .iter()
            .copied()
            .find(|event| event.pubkey == config.provider_pubkey)
            .ok_or_else(|| {
                SwapClientError::new("swp_contract_missing", "provider Swap Contract is missing")
            })?;
        if contracts.len() != 2 {
            return Err(SwapClientError::new(
                "swp_contract_signer_invalid",
                "session requires exactly two participant Swap Contracts",
            ));
        }
        for contract_event in [requester_contract, provider_contract] {
            require_marked_reference(contract_event, "quote", &quote.id)?;
            require_marked_reference(contract_event, "order", &order.id)?;
        }
        let requester_content = parse_content(requester_contract)?;
        let provider_content = parse_content(provider_contract)?;
        let requester_profile = object(
            requester_content.get("mkt_swp").unwrap_or(&Value::Null),
            "requester Swap Contract",
        )?;
        let provider_profile = object(
            provider_content.get("mkt_swp").unwrap_or(&Value::Null),
            "provider Swap Contract",
        )?;
        if requester_profile.get("signer_role").and_then(Value::as_str) != Some("requester")
            || provider_profile.get("signer_role").and_then(Value::as_str) != Some("provider")
        {
            return Err(SwapClientError::new(
                "swp_contract_signer_invalid",
                "Swap Contract signer roles are not complementary",
            ));
        }
        let requester_contract_value = requester_profile.get("contract").ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "requester contract is missing",
            )
        })?;
        let provider_contract_value = provider_profile.get("contract").ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "provider contract is missing",
            )
        })?;
        if requester_contract_value != provider_contract_value {
            return Err(SwapClientError::new(
                "swp_contract_digest_mismatch",
                "participant Swap Contracts contain different terms",
            ));
        }
        let contract_sha256 = requester_profile
            .get("contract_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_digest_mismatch",
                    "requester contract digest is missing",
                )
            })?;
        if provider_profile
            .get("contract_sha256")
            .and_then(Value::as_str)
            != Some(contract_sha256)
            || lower_hex(&Sha256::digest(canonical_json(requester_contract_value)?))
                != contract_sha256
        {
            return Err(SwapClientError::new(
                "swp_contract_digest_mismatch",
                "participant or recomputed contract digest differs",
            ));
        }
        let contract = object(requester_contract_value, "Swap Contract")?;
        if contract.get("order_id").and_then(Value::as_str) != Some(order.id.as_str())
            || contract.get("quote_id").and_then(Value::as_str) != Some(quote.id.as_str())
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract does not bind the accepted Quote and Order",
            ));
        }
        let swap_type = match contract.get("swap_type").and_then(Value::as_str) {
            Some("submarine") => SwapType::Submarine,
            Some("reverse") => SwapType::Reverse,
            Some("chain") => SwapType::Chain,
            _ => {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "Swap Contract has an unsupported swap type",
                ));
            }
        };
        let payment_hash = contract
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_payment_hash_mismatch",
                    "Swap Contract has no payment hash",
                )
            })?;
        require_lower_hex_32(payment_hash, "Swap Contract payment hash")?;
        Ok(Self {
            session_id: config.session_id.clone(),
            rfq,
            quote,
            order,
            requester_contract,
            provider_contract,
            contract: requester_contract_value.clone(),
            contract_sha256: contract_sha256.to_owned(),
            swap_type,
            payment_hash: payment_hash.to_owned(),
        })
    }

    fn verify_contract_terms(&self) -> Result<(), SwapClientError> {
        let quote_content = parse_content(self.quote)?;
        let quote_profile = object(
            quote_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Quote",
        )?;
        let terms = object(
            quote_profile.get("terms").unwrap_or(&Value::Null),
            "MKT-SWP Quote terms",
        )?;
        validate_provider_quote_profile(quote_profile, tag_value(self.quote, "reservation")?)?;
        let contract = object(&self.contract, "Swap Contract")?;
        let quote_expiration = tag_value(self.quote, "expiration")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_quote_expired", "Quote expiration is invalid")
            })?;
        validate_quote_against_rfq(
            self.rfq,
            quote_profile,
            tag_value(self.quote, "quote")?,
            self.quote.created_at,
            quote_expiration,
        )?;
        for member in [
            "swap_type",
            "asset_pair",
            "payment_hash",
            "fee_bps",
            "miner_fee_budget",
            "lightning_routing_fee_budget",
            "amount_equation",
            "rounding",
            "script_mode",
            "musig2_execution",
            "desired_completion_time",
            "clock_skew_seconds",
            "timeout_ladder",
            "cancellation",
            "evidence_requirements",
            "recovery",
            "price_feed",
            "evm_leg",
        ] {
            if terms.get(member) != contract.get(member) {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    format!("Swap Contract member {member} differs from the Quote"),
                ));
            }
        }
        verify_quote_contract_execution_resolution(terms, contract)?;
        let order_content = parse_content(self.order)?;
        let order_profile = object(
            order_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Order",
        )?;
        if order_profile
            .get("accepted_quote_id")
            .and_then(Value::as_str)
            != Some(self.quote.id.as_str())
        {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order body does not accept the referenced Quote",
            ));
        }
        verify_order_selection(quote_profile, order_profile, contract)?;
        Ok(())
    }

    fn verify_requester_topology(&self) -> Result<(), SwapClientError> {
        verify_requester_topology(object(&self.contract, "Swap Contract")?, self.swap_type)
    }

    fn verify_local_expiration(&self, observed_at: u64) -> Result<(), SwapClientError> {
        let contract = object(&self.contract, "Swap Contract")?;
        let clock_skew = require_string(contract, "clock_skew_seconds", None, "swp_quote_expired")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_quote_expired", "clock-skew bound is invalid")
            })?;
        if clock_skew > 120 {
            return Err(SwapClientError::new(
                "swp_quote_expired",
                "clock-skew bound exceeds 120 seconds",
            ));
        }
        for record in [self.rfq, self.quote] {
            let expiration = tag_value(record, "expiration")?
                .parse::<u64>()
                .map_err(|_| {
                    SwapClientError::new("swp_quote_expired", "record expiration is invalid")
                })?;
            if observed_at > expiration.saturating_add(clock_skew) {
                return Err(SwapClientError::new(
                    "swp_quote_expired",
                    "local wallet time reports an expired RFQ or Quote",
                ));
            }
        }
        if object(
            contract
                .get("reservation_commitment")
                .unwrap_or(&Value::Null),
            "reservation commitment",
        )?
        .get("expires_at")
        .and_then(Value::as_u64)
        .is_some_and(|expiration| observed_at > expiration.saturating_add(clock_skew))
        {
            return Err(SwapClientError::new(
                "swp_quote_expired",
                "local wallet time reports an expired reservation",
            ));
        }
        self.verify_reservation(observed_at, clock_skew)?;
        Ok(())
    }

    fn verify_reservation(&self, observed_at: u64, clock_skew: u64) -> Result<(), SwapClientError> {
        let quote_class = tag_value(self.quote, "quote")?;
        let reservation_class = tag_value(self.quote, "reservation")?;
        if quote_class != "firm" || !matches!(reservation_class, "soft" | "hard") {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "funding requires a firm Quote with a soft or hard reservation",
            ));
        }
        let quote_content = parse_content(self.quote)?;
        let profile = object(
            quote_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Quote",
        )?;
        let terms = object(
            profile.get("reservation_terms").unwrap_or(&Value::Null),
            "reservation terms",
        )?;
        let reservation_id =
            require_string(terms, "reservation_id", None, "swp_contract_terms_mismatch")?;
        require_lower_hex_32(reservation_id, "reservation ID")?;
        let capacity_bucket_id = require_string(
            terms,
            "capacity_bucket_id",
            None,
            "swp_contract_terms_mismatch",
        )?;
        if capacity_bucket_id.is_empty()
            || capacity_bucket_id.len() > 64
            || !capacity_bucket_id
                .bytes()
                .enumerate()
                .all(|(index, byte)| match byte {
                    b'a'..=b'z' | b'0'..=b'9' => true,
                    b'.' | b'_' | b'-' => index > 0,
                    _ => false,
                })
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation capacity bucket is not a bounded profile identifier",
            ));
        }
        let reserved_asset_id = require_string(
            terms,
            "reserved_asset_id",
            None,
            "swp_contract_terms_mismatch",
        )?;
        let reserved_amount = canonical_amount(require_string(
            terms,
            "reserved_amount",
            None,
            "swp_contract_terms_mismatch",
        )?)?;
        let committed_capacity = canonical_amount(require_string(
            terms,
            "handler_committed_capacity",
            None,
            "swp_contract_terms_mismatch",
        )?)?;
        let allocation_sequence = canonical_amount(require_string(
            terms,
            "allocation_sequence",
            None,
            "swp_contract_terms_mismatch",
        )?)?;
        let proof_class =
            require_string(terms, "proof_class", None, "swp_contract_terms_mismatch")?;
        let strength = reservation_proof_strength(reservation_class, proof_class)?;
        let proof_ref = require_string(terms, "proof_ref", None, "swp_contract_terms_mismatch")?;
        if proof_ref.is_empty()
            || proof_ref.len() > 512
            || proof_ref.contains('@')
            || proof_ref.contains('?')
            || proof_ref.chars().any(char::is_control)
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation proof reference is unbounded or bearer-shaped",
            ));
        }
        let expiration = terms
            .get("reservation_expires_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "reservation expiration is invalid",
                )
            })?;
        let contract = object(&self.contract, "Swap Contract")?;
        let output_asset = contract
            .get("asset_pair")
            .and_then(Value::as_array)
            .and_then(|assets| assets.get(1))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "contract output asset is missing",
                )
            })?;
        if reserved_asset_id != output_asset
            || reserved_amount < contract_amount(contract, "output_amount")?
            || reserved_amount > committed_capacity
            || observed_at > expiration.saturating_add(clock_skew)
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation does not cover the Order asset, amount, or local verification time",
            ));
        }
        let capacity_commitment_sha256 = require_string(
            terms,
            "capacity_commitment_sha256",
            None,
            "swp_contract_terms_mismatch",
        )?;
        require_lower_hex_32(capacity_commitment_sha256, "capacity commitment digest")?;
        let profile_timeout_at = match terms.get("profile_timeout_at") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "reservation profile timeout is invalid",
                )
            })?),
        };
        if profile_timeout_at
            .is_some_and(|timeout| observed_at > timeout.saturating_add(clock_skew))
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation profile timeout does not cover local verification time",
            ));
        }
        let covenant_commitment = if proof_class == "covenant_reserve" {
            validate_covenant_reservation(terms, reserved_amount, expiration)?
        } else {
            if terms.get("covenant").is_some_and(|value| !value.is_null()) {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "non-covenant reservation carries covenant proof inputs",
                ));
            }
            Value::Null
        };
        let expected = json!({
            "session_id": self.session_id.as_str(),
            "rfq_id": self.rfq.id.as_str(),
            "quote_id": self.quote.id.as_str(),
            "reservation_id":reservation_id,
            "reservation_class":reservation_class,
            "capacity_bucket_id":capacity_bucket_id,
            "reserved_asset_id":reserved_asset_id,
            "reserved_amount":reserved_amount.to_string(),
            "handler_committed_capacity":committed_capacity.to_string(),
            "allocation_sequence":allocation_sequence.to_string(),
            "proof_class":proof_class,
            "proof_strength":strength,
            "proof_ref_sha256":lower_hex(&sha256(proof_ref.as_bytes())),
            "capacity_commitment_sha256":capacity_commitment_sha256,
            "reservation_expires_at":expiration,
            "profile_timeout_at":profile_timeout_at,
            "covenant_commitment":covenant_commitment
        });
        if contract.get("reservation_commitment") != Some(&expected) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract reservation commitment does not bind the Quote proof and scope",
            ));
        }
        Ok(())
    }

    fn contract_ids(&self) -> [&str; 2] {
        [&self.requester_contract.id, &self.provider_contract.id]
    }
}

fn verify_quote_contract_execution_resolution(
    quote: &Map<String, Value>,
    contract: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    if quote.get("legs") == contract.get("legs")
        && quote.get("verifier_inputs") == contract.get("verifier_inputs")
    {
        return Ok(());
    }
    let mismatch = |detail| SwapClientError::new("swp_contract_terms_mismatch", detail);
    if quote.get("swap_type").and_then(Value::as_str) != Some("submarine") {
        return Err(mismatch(
            "only a submarine requester-funded source leg may resolve funding after Order",
        ));
    }
    let quote_verifiers = quote
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| mismatch("Quote verifier inputs are invalid"))?;
    let contract_verifiers = contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| mismatch("Swap Contract verifier inputs are invalid"))?;
    let quote_legs = quote
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| mismatch("Quote legs are invalid"))?;
    let contract_legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| mismatch("Swap Contract legs are invalid"))?;
    if quote_verifiers.len() != contract_verifiers.len() || quote_legs.len() != contract_legs.len()
    {
        return Err(mismatch(
            "Swap Contract changes the Quote leg or verifier count",
        ));
    }
    let unique_index = |values: &[Value], label: &str| {
        let indexes = values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                (value.get("leg_id").and_then(Value::as_str) == Some("source")).then_some(index)
            })
            .collect::<Vec<_>>();
        let [index] = indexes.as_slice() else {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("{label} requires exactly one source leg binding"),
            ));
        };
        Ok(*index)
    };
    let quote_verifier_index = unique_index(quote_verifiers, "Quote verifier inputs")?;
    let contract_verifier_index =
        unique_index(contract_verifiers, "Swap Contract verifier inputs")?;
    let quote_leg_index = unique_index(quote_legs, "Quote legs")?;
    let contract_leg_index = unique_index(contract_legs, "Swap Contract legs")?;
    if quote_verifier_index != contract_verifier_index || quote_leg_index != contract_leg_index {
        return Err(mismatch(
            "Swap Contract reorders the requester-funded source binding",
        ));
    }
    let quote_verifier = object(
        &quote_verifiers[quote_verifier_index],
        "Quote source verifier",
    )?;
    let contract_verifier = object(
        &contract_verifiers[contract_verifier_index],
        "Swap Contract source verifier",
    )?;
    let quote_leg = object(&quote_legs[quote_leg_index], "Quote source leg")?;
    let contract_leg = object(
        &contract_legs[contract_leg_index],
        "Swap Contract source leg",
    )?;
    if quote_leg.get("rail").and_then(Value::as_str) != Some("bitcoin")
        || quote_leg.get("funding_role").and_then(Value::as_str) != Some("requester")
        || quote_leg.get("receiving_role").and_then(Value::as_str) != Some("provider")
        || quote_verifier
            .get("verifier_policy")
            .and_then(Value::as_str)
            != Some("mkt-swp-bitcoin-v1")
    {
        return Err(mismatch(
            "post-Order funding resolution belongs only to the submarine requester source lock",
        ));
    }
    const RESOLVED_MEMBERS: [&str; 3] = [
        "funding_transaction",
        "funding_transaction_sha256",
        "output_index",
    ];
    if RESOLVED_MEMBERS
        .iter()
        .any(|member| quote_verifier.contains_key(*member))
    {
        return Err(mismatch(
            "a Quote funding resolution must add fields that were previously absent",
        ));
    }
    let mut unresolved_contract_verifier = contract_verifier.clone();
    for member in RESOLVED_MEMBERS {
        if unresolved_contract_verifier.remove(member).is_none() {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("Swap Contract funding resolution omits {member}"),
            ));
        }
    }
    if &unresolved_contract_verifier != quote_verifier {
        return Err(mismatch(
            "Swap Contract changes source verifier bytes outside the funding resolution",
        ));
    }
    let mut normalized_verifiers = contract_verifiers.clone();
    normalized_verifiers[contract_verifier_index] = Value::Object(quote_verifier.clone());
    if &normalized_verifiers != quote_verifiers {
        return Err(mismatch(
            "Swap Contract changes a verifier outside the requester source resolution",
        ));
    }
    let mut normalized_legs = contract_legs.clone();
    let normalized_leg = normalized_legs
        .get_mut(contract_leg_index)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| mismatch("Swap Contract source leg is invalid"))?;
    normalized_leg.insert(
        "verifier_digest".to_owned(),
        quote_leg
            .get("verifier_digest")
            .cloned()
            .ok_or_else(|| mismatch("Quote source leg omits its verifier digest"))?,
    );
    if &normalized_legs != quote_legs {
        return Err(mismatch(
            "Swap Contract changes source leg bytes outside the resolved verifier digest",
        ));
    }
    let raw_transaction = require_string(
        contract_verifier,
        "funding_transaction",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let raw = decode_hex(raw_transaction, "resolved funding transaction")?;
    let declared_sha256 = require_string(
        contract_verifier,
        "funding_transaction_sha256",
        None,
        "swp_contract_terms_mismatch",
    )?;
    require_lower_hex_32(declared_sha256, "resolved funding transaction digest")?;
    if lower_hex(&sha256(&raw)) != declared_sha256 {
        return Err(mismatch(
            "resolved funding transaction digest does not match its exact bytes",
        ));
    }
    let transaction = Transaction::parse(&raw).map_err(|error| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("resolved funding transaction is invalid: {error}"),
        )
    })?;
    let output_index = required_u32(contract_verifier, "output_index")?;
    let output =
        transaction
            .outputs
            .get(usize::try_from(output_index).map_err(|_| {
                mismatch("resolved funding output index exceeds the local platform")
            })?)
            .ok_or_else(|| mismatch("resolved funding output index does not exist"))?;
    let quoted_amount = canonical_amount(require_string(
        quote_verifier,
        "amount",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let quoted_script = decode_hex(
        require_string(
            quote_verifier,
            "script_pubkey",
            None,
            "swp_contract_terms_mismatch",
        )?,
        "quoted source scriptPubKey",
    )?;
    if output.value_sat != quoted_amount || output.script_pubkey != quoted_script {
        return Err(mismatch(
            "resolved funding output does not pay the quoted source amount and scriptPubKey",
        ));
    }
    let verifier_digest = lower_hex(&sha256(&canonical_json(&Value::Object(
        contract_verifier.clone(),
    ))?));
    if contract_leg.get("verifier_digest").and_then(Value::as_str) != Some(verifier_digest.as_str())
    {
        return Err(mismatch(
            "resolved source leg does not bind the canonical verifier digest",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ExitTopology {
    leg_id: &'static str,
    path: &'static str,
    condition: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct RequesterTopology {
    funding_effect_role: &'static str,
    funding_leg_id: &'static str,
    bitcoin_verifier_leg_id: &'static str,
    invoice_verifier_leg_id: Option<&'static str>,
    legs: &'static [(&'static str, &'static str, &'static str, &'static str)],
    exits: &'static [ExitTopology],
}

const SUBMARINE_LEGS: &[(&str, &str, &str, &str)] = &[
    ("source", "bitcoin", "requester", "provider"),
    ("lightning", "lightning", "provider", "requester"),
];
const SUBMARINE_EXITS: &[ExitTopology] = &[ExitTopology {
    leg_id: "source",
    path: "refund",
    condition: "cltv",
}];
const REVERSE_LEGS: &[(&str, &str, &str, &str)] = &[
    ("lightning", "lightning", "requester", "provider"),
    ("destination", "bitcoin", "provider", "requester"),
];
const REVERSE_EXITS: &[ExitTopology] = &[ExitTopology {
    leg_id: "destination",
    path: "claim",
    condition: "hashlock",
}];
const CHAIN_LEGS: &[(&str, &str, &str, &str)] = &[
    ("source", "bitcoin", "requester", "provider"),
    ("destination", "bitcoin", "provider", "requester"),
];
const CHAIN_EXITS: &[ExitTopology] = &[
    ExitTopology {
        leg_id: "source",
        path: "refund",
        condition: "csv",
    },
    ExitTopology {
        leg_id: "destination",
        path: "claim",
        condition: "hashlock",
    },
];

fn requester_topology(swap_type: SwapType) -> RequesterTopology {
    match swap_type {
        SwapType::Submarine => RequesterTopology {
            funding_effect_role: "chain_fund",
            funding_leg_id: "source",
            bitcoin_verifier_leg_id: "source",
            invoice_verifier_leg_id: Some("lightning"),
            legs: SUBMARINE_LEGS,
            exits: SUBMARINE_EXITS,
        },
        SwapType::Reverse => RequesterTopology {
            funding_effect_role: "invoice_pay",
            funding_leg_id: "lightning",
            bitcoin_verifier_leg_id: "destination",
            invoice_verifier_leg_id: Some("lightning"),
            legs: REVERSE_LEGS,
            exits: REVERSE_EXITS,
        },
        SwapType::Chain => RequesterTopology {
            funding_effect_role: "chain_fund",
            funding_leg_id: "source",
            bitcoin_verifier_leg_id: "source",
            invoice_verifier_leg_id: None,
            legs: CHAIN_LEGS,
            exits: CHAIN_EXITS,
        },
    }
}

fn recovery_rail_bindings(
    bound: &BoundSession<'_>,
) -> Result<Vec<RecoveryRailBinding>, SwapClientError> {
    let contract = object(&bound.contract, "Swap Contract")?;
    let legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new("swp_unresolved_loss", "Swap Contract has no recovery legs")
        })?;
    let mut bindings = Vec::with_capacity(legs.len());
    for leg in legs {
        let leg = object(leg, "Swap Contract leg")?;
        let leg_id = require_string(leg, "leg_id", None, "swp_unresolved_loss")?;
        let rail = require_string(leg, "rail", None, "swp_unresolved_loss")?;
        let verifier = verifier_for_leg(contract, leg_id)?;
        let confirmation_policy_sha256 = leg
            .get("confirmation_policy")
            .map(canonical_json)
            .transpose()?
            .map(|policy| lower_hex(&sha256(&policy)));
        bindings.push(RecoveryRailBinding {
            leg_id: leg_id.to_owned(),
            rail: rail.to_owned(),
            verifier_digest: require_string(leg, "verifier_digest", None, "swp_unresolved_loss")?
                .to_owned(),
            funding_transaction_sha256: verifier
                .get("funding_transaction_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned),
            output_index: verifier
                .get("output_index")
                .and_then(Value::as_u64)
                .map(u32::try_from)
                .transpose()
                .map_err(|_| {
                    SwapClientError::new("swp_unresolved_loss", "recovery output index exceeds u32")
                })?,
            amount: require_string(leg, "amount", None, "swp_unresolved_loss")?.to_owned(),
            script_pubkey: leg
                .get("script_pubkey")
                .and_then(Value::as_str)
                .map(str::to_owned),
            confirmation_policy_sha256,
            invoice_sha256: verifier
                .get("invoice_sha256")
                .and_then(Value::as_str)
                .map(str::to_owned),
            claim_effect_id: (rail == "bitcoin")
                .then(|| effect_id(&bound.order.id, "chain_claim", leg_id))
                .transpose()?,
            refund_effect_id: (rail == "bitcoin")
                .then(|| effect_id(&bound.order.id, "chain_refund", leg_id))
                .transpose()?,
        });
    }
    Ok(bindings)
}

fn recovery_observation_is_contradictory(
    swap_type: SwapType,
    observation: &LocalRecoveryObservation,
) -> bool {
    match swap_type {
        SwapType::Reverse => matches!(
            (observation.lightning_state, observation.chain_state),
            (
                Some(LightningRecoveryState::Paid),
                Some(ChainRecoveryState::DestinationNotFunded)
            ) | (
                Some(LightningRecoveryState::UnpaidFinal),
                Some(
                    ChainRecoveryState::DestinationClaimable
                        | ChainRecoveryState::DestinationFundedUnclaimed
                )
            )
        ),
        SwapType::Submarine => matches!(
            (observation.lightning_state, observation.chain_state),
            (
                Some(LightningRecoveryState::Paid),
                Some(ChainRecoveryState::DestinationNotFunded)
            )
        ),
        SwapType::Chain => false,
    }
}

fn verify_requester_topology(
    contract: &Map<String, Value>,
    swap_type: SwapType,
) -> Result<(), SwapClientError> {
    let topology = requester_topology(swap_type);
    let legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new("swp_contract_terms_mismatch", "Swap Contract has no legs")
        })?;
    if legs.len() != topology.legs.len() {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Swap Contract has the wrong flow leg count",
        ));
    }
    let asset_pair = contract
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract requires an ordered asset pair",
            )
        })?;
    let payment_hash = require_string(
        contract,
        "payment_hash",
        None,
        "swp_contract_terms_mismatch",
    )?;
    for (index, (leg_id, rail, funding_role, receiving_role)) in topology.legs.iter().enumerate() {
        let matching = legs.iter().filter(|leg| {
            leg.get("leg_id").and_then(Value::as_str) == Some(*leg_id)
                && leg.get("rail").and_then(Value::as_str) == Some(*rail)
                && leg.get("funding_role").and_then(Value::as_str) == Some(*funding_role)
                && leg.get("receiving_role").and_then(Value::as_str) == Some(*receiving_role)
        });
        let matching = matching.collect::<Vec<_>>();
        let [leg] = matching.as_slice() else {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract flow signer or leg topology is invalid",
            ));
        };
        let verifier = verifier_for_leg(contract, leg_id)?;
        let expected_amount = if index == 0 {
            contract_amount(contract, "input_amount")?
        } else {
            contract_amount(contract, "output_amount")?
        };
        verify_leg_execution_fields(
            leg,
            verifier,
            &asset_pair[index],
            payment_hash,
            rail,
            expected_amount,
        )?;
    }
    let effect_bindings = contract
        .get("effect_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract has no effect bindings",
            )
        })?;
    let mut expected_effects = vec![(topology.funding_effect_role, topology.funding_leg_id)];
    expected_effects.extend(topology.exits.iter().map(|exit| {
        (
            if exit.path == "claim" {
                "chain_claim"
            } else {
                "chain_refund"
            },
            exit.leg_id,
        )
    }));
    for (role, leg_id) in expected_effects {
        if !effect_bindings.iter().any(|binding| {
            binding.get("role").and_then(Value::as_str) == Some(role)
                && binding.get("leg_id").and_then(Value::as_str) == Some(leg_id)
        }) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract omits a requester external-effect binding",
            ));
        }
    }
    let commitments = contract
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_missing",
                "Swap Contract has no exit commitments",
            )
        })?;
    let requester_commitments = commitments
        .iter()
        .filter(|commitment| {
            commitment.get("participant_role").and_then(Value::as_str) == Some("requester")
        })
        .collect::<Vec<_>>();
    if requester_commitments.len() != topology.exits.len()
        || topology.exits.iter().any(|exit| {
            !requester_commitments.iter().any(|commitment| {
                commitment.get("leg_id").and_then(Value::as_str) == Some(exit.leg_id)
                    && commitment.get("path").and_then(Value::as_str) == Some(exit.path)
            })
        })
    {
        return Err(SwapClientError::new(
            "swp_exit_package_missing",
            "Swap Contract requester exits do not match the selected flow",
        ));
    }
    Ok(())
}

fn verify_leg_execution_fields(
    leg: &Value,
    verifier: &Map<String, Value>,
    asset_id: &Value,
    payment_hash: &str,
    rail: &str,
    expected_amount: u64,
) -> Result<(), SwapClientError> {
    let leg = object(leg, "Swap Contract leg")?;
    let asset_id = asset_id.as_str().ok_or_else(|| {
        SwapClientError::new("swp_contract_terms_mismatch", "asset ID is not a string")
    })?;
    let network_id = asset_id
        .strip_prefix("swp:1:")
        .and_then(|asset_id| asset_id.split(":btc:").next())
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "asset ID does not carry a network namespace",
            )
        })?;
    let verifier_digest = lower_hex(&sha256(&canonical_json(&Value::Object(verifier.clone()))?));
    if leg.get("network_id").and_then(Value::as_str) != Some(network_id)
        || leg.get("asset_id").and_then(Value::as_str) != Some(asset_id)
        || leg.get("payment_hash").and_then(Value::as_str) != Some(payment_hash)
        || leg.get("verifier_digest").and_then(Value::as_str) != Some(verifier_digest.as_str())
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Swap Contract leg omits or changes its network, asset, hash, or verifier binding",
        ));
    }
    if rail == "lightning" {
        for member in [
            "invoice_sha256",
            "invoice_expiry_seconds",
            "invoice_minimum_final_cltv_delta",
        ] {
            if leg.get(member) != verifier.get(member) {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    format!("Lightning leg member {member} differs from its verifier"),
                ));
            }
        }
        let leg_amount = canonical_amount(require_string(
            leg,
            "amount",
            None,
            "swp_contract_terms_mismatch",
        )?)?;
        let invoice_amount_msat = canonical_amount(require_string(
            verifier,
            "invoice_amount_msat",
            None,
            "swp_contract_terms_mismatch",
        )?)?;
        if leg_amount != expected_amount
            || leg_amount.checked_mul(1_000) != Some(invoice_amount_msat)
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Lightning leg amount differs from its invoice commitment",
            ));
        }
        return Ok(());
    }
    if leg.get("amount") != verifier.get("amount")
        || canonical_amount(require_string(
            leg,
            "amount",
            None,
            "swp_contract_terms_mismatch",
        )?)? != expected_amount
        || leg.get("script_pubkey") != verifier.get("script_pubkey")
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Bitcoin leg amount or script differs from its verifier",
        ));
    }
    let confirmation = object(
        leg.get("confirmation_policy").unwrap_or(&Value::Null),
        "Bitcoin confirmation policy",
    )?;
    if confirmation.get("minimum_confirmations") != verifier.get("minimum_confirmations")
        || confirmation.get("replacement_policy") != verifier.get("replacement_policy")
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Bitcoin leg confirmation or replacement policy differs from its verifier",
        ));
    }
    let tree = verifier
        .get("taproot_tree")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Bitcoin leg verifier has no complete Taproot tree",
            )
        })?;
    for path in ["claim", "refund"] {
        let leaf = tree
            .iter()
            .find(|leaf| leaf.get("path").and_then(Value::as_str) == Some(path))
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    format!("Bitcoin leg has no {path} leaf"),
                )
            })?;
        if leg
            .get(&format!("{path}_public_key"))
            .and_then(Value::as_str)
            != leaf.get("signing_pubkey").and_then(Value::as_str)
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("Bitcoin leg {path} key differs from its executable leaf"),
            ));
        }
        if path == "refund"
            && (leg.get("refund_condition") != leaf.get("condition")
                || leg.get("refund_lock_value") != leaf.get("lock_value"))
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Bitcoin leg refund timelock differs from its executable leaf",
            ));
        }
    }
    Ok(())
}

fn validate_composer_record(
    config: &SwapClientConfig,
    event: &Event,
) -> Result<(), SwapClientError> {
    let raw = serde_json::to_vec(event).map_err(|error| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("could not serialize composer input: {error}"),
        )
    })?;
    let validated = validate_mkt_private_raw(&raw, &swp_profile_support()).map_err(|error| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("composer input violates MKT-SWP: {error}"),
        )
    })?;
    if validated.envelope().session_id != config.session_id {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "composer input belongs to another session",
        ));
    }
    role_for_author(config, &event.pubkey)?;
    Ok(())
}

fn validate_requester_quote(
    config: &SwapClientConfig,
    rfq: &Event,
    quote: &Event,
) -> Result<Map<String, Value>, SwapClientError> {
    config.validate()?;
    validate_composer_record(config, rfq)?;
    validate_composer_record(config, quote)?;
    if rfq.kind != MKT_RFQ_KIND
        || rfq.pubkey != config.requester_pubkey
        || quote.kind != MKT_QUOTE_KIND
        || quote.pubkey != config.provider_pubkey
    {
        return Err(SwapClientError::new(
            "swp_contract_signer_invalid",
            "requester composer requires its configured RFQ and provider Quote",
        ));
    }
    let offering_references = rfq
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("a") && tag.as_slice().get(3).map(String::as_str) == Some("offering")
        })
        .collect::<Vec<_>>();
    if !matches!(offering_references.as_slice(), [reference] if reference.value() == Some(config.offering_address.as_str()))
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "RFQ does not bind the configured Offering address",
        ));
    }
    require_marked_reference(quote, "rfq", &rfq.id)?;
    let content = parse_content(quote)?;
    let profile = object(
        content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP Quote",
    )?
    .clone();
    let reservation_class = tag_value(quote, "reservation")?;
    validate_provider_quote_profile(&profile, reservation_class)?;
    let expiration = tag_value(quote, "expiration")?
        .parse::<u64>()
        .map_err(|_| SwapClientError::new("swp_quote_expired", "Quote expiration is invalid"))?;
    validate_quote_against_rfq(
        rfq,
        &profile,
        tag_value(quote, "quote")?,
        quote.created_at,
        expiration,
    )?;
    Ok(profile)
}

fn validate_firm_quote(quote: &Event) -> Result<(), SwapClientError> {
    if tag_value(quote, "quote")? != "firm"
        || !matches!(tag_value(quote, "reservation")?, "soft" | "hard")
    {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "requester execution requires a firm Quote with a capacity reservation",
        ));
    }
    Ok(())
}

fn validate_quote_observation(
    quote_profile: &Map<String, Value>,
    quote: &Event,
    observed_at: u64,
) -> Result<(), SwapClientError> {
    let expiration = tag_value(quote, "expiration")?
        .parse::<u64>()
        .map_err(|_| SwapClientError::new("swp_quote_expired", "Quote expiration is invalid"))?;
    validate_order_acceptance_deadline(quote_profile, expiration, observed_at)
}

fn validate_composed_order(
    config: &SwapClientConfig,
    quote: &Event,
    order: &Event,
    order_observed_at: u64,
    quote_profile: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    reject_unsupported_executable_quote(quote_profile)?;
    validate_composer_record(config, order)?;
    if order.kind != MKT_ORDER_KIND || order.pubkey != config.requester_pubkey {
        return Err(SwapClientError::new(
            "swp_contract_signer_invalid",
            "requester composer requires its configured Order",
        ));
    }
    require_marked_reference(order, "quote", &quote.id)?;
    let content = parse_content(order)?;
    let profile = object(
        content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP Order",
    )?;
    if profile.get("accepted_quote_id").and_then(Value::as_str) != Some(quote.id.as_str()) {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Order body does not accept the referenced Quote",
        ));
    }
    validate_order_selection(quote_profile, profile)?;
    validate_quote_observation(quote_profile, quote, order_observed_at)
}

fn reject_unsupported_executable_quote(
    quote_profile: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    let terms = object(
        quote_profile.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    if !terms.get("price_feed").is_none_or(Value::is_null) {
        return Err(SwapClientError::new(
            "swp_price_feed_unsupported",
            "pinned-feed Quote execution is unavailable until its deterministic amount formula is specified",
        ));
    }
    Ok(())
}

fn compose_requester_contract(
    config: &SwapClientConfig,
    rfq: &Event,
    quote: &Event,
    order: &Event,
    quote_profile: &Map<String, Value>,
    local_inputs: RequesterContractLocalInputs,
) -> Result<Value, SwapClientError> {
    let local_contract = serde_json::to_value(local_inputs).map_err(|error| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("requester Contract inputs cannot be encoded: {error}"),
        )
    })?;
    reject_custody_material(&local_contract)?;
    let mut contract = object(&local_contract, "requester local Contract inputs")?.clone();
    let terms = object(
        quote_profile.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    for (name, value) in terms {
        contract.insert(name.clone(), value.clone());
    }
    let order_content = parse_content(order)?;
    let order_profile = object(
        order_content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP Order",
    )?;
    if let Some(selection) = order_profile.get("selection").and_then(Value::as_object) {
        for name in ["fee_payer", "confirmation_policy", "public_receipt_consent"] {
            if let Some(value) = selection.get(name) {
                contract.insert(name.to_owned(), value.clone());
            }
        }
        if let Some(input_amount) = selection.get("input_amount").and_then(Value::as_str) {
            let input_amount = canonical_amount(input_amount)?;
            let fee_bps = contract_amount(&contract, "fee_bps")?;
            let provider_fee = u64::try_from(
                u128::from(input_amount)
                    .checked_mul(u128::from(fee_bps))
                    .ok_or_else(|| {
                        SwapClientError::new(
                            "swp_order_selection_invalid",
                            "selected input fee calculation overflows",
                        )
                    })?
                    / 10_000,
            )
            .map_err(|_| {
                SwapClientError::new(
                    "swp_order_selection_invalid",
                    "selected input fee exceeds the v1 amount range",
                )
            })?;
            let miner_fee = contract_amount(&contract, "miner_fee_budget")?;
            let lightning_fee = contract_amount(&contract, "lightning_routing_fee_budget")?;
            let output_amount = input_amount
                .checked_sub(provider_fee)
                .and_then(|amount| amount.checked_sub(miner_fee))
                .and_then(|amount| amount.checked_sub(lightning_fee))
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_order_selection_invalid",
                        "selected input cannot satisfy the quoted amount equation",
                    )
                })?;
            let maximum_total_fee = provider_fee
                .checked_add(miner_fee)
                .and_then(|amount| amount.checked_add(lightning_fee))
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_order_selection_invalid",
                        "selected input fee total overflows",
                    )
                })?;
            contract.insert(
                "input_amount".to_owned(),
                Value::String(input_amount.to_string()),
            );
            contract.insert(
                "output_amount".to_owned(),
                Value::String(output_amount.to_string()),
            );
            contract.insert(
                "provider_fee".to_owned(),
                Value::String(provider_fee.to_string()),
            );
            contract.insert(
                "maximum_total_fee".to_owned(),
                Value::String(maximum_total_fee.to_string()),
            );
        }
        contract.insert(
            "order_selection".to_owned(),
            Value::Object(selection.clone()),
        );
    }
    contract.insert("order_id".to_owned(), Value::String(order.id.clone()));
    contract.insert("quote_id".to_owned(), Value::String(quote.id.clone()));

    let reservation_class = tag_value(quote, "reservation")?;
    let reservation = object(
        quote_profile
            .get("reservation_terms")
            .unwrap_or(&Value::Null),
        "Quote reservation terms",
    )?;
    let reservation_id = require_string(
        reservation,
        "reservation_id",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let capacity_bucket_id = require_string(
        reservation,
        "capacity_bucket_id",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let reserved_asset_id = require_string(
        reservation,
        "reserved_asset_id",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let reserved_amount = canonical_amount(require_string(
        reservation,
        "reserved_amount",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let committed_capacity = canonical_amount(require_string(
        reservation,
        "handler_committed_capacity",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let allocation_sequence = canonical_amount(require_string(
        reservation,
        "allocation_sequence",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let proof_class = require_string(
        reservation,
        "proof_class",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let proof_strength = reservation_proof_strength(reservation_class, proof_class)?;
    let proof_ref = require_string(
        reservation,
        "proof_ref",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let capacity_commitment_sha256 = require_string(
        reservation,
        "capacity_commitment_sha256",
        None,
        "swp_contract_terms_mismatch",
    )?;
    let reservation_expires_at = reservation
        .get("reservation_expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation expiration is invalid",
            )
        })?;
    let profile_timeout_at = match reservation.get("profile_timeout_at") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "reservation profile timeout is invalid",
            )
        })?),
    };
    let covenant_commitment = if proof_class == "covenant_reserve" {
        validate_covenant_reservation(reservation, reserved_amount, reservation_expires_at)?
    } else {
        Value::Null
    };
    contract.insert(
        "reservation_commitment".to_owned(),
        json!({
            "session_id":config.session_id,
            "rfq_id":rfq.id,
            "quote_id":quote.id,
            "reservation_id":reservation_id,
            "reservation_class":reservation_class,
            "capacity_bucket_id":capacity_bucket_id,
            "reserved_asset_id":reserved_asset_id,
            "reserved_amount":reserved_amount.to_string(),
            "handler_committed_capacity":committed_capacity.to_string(),
            "allocation_sequence":allocation_sequence.to_string(),
            "proof_class":proof_class,
            "proof_strength":proof_strength,
            "proof_ref_sha256":lower_hex(&sha256(proof_ref.as_bytes())),
            "capacity_commitment_sha256":capacity_commitment_sha256,
            "reservation_expires_at":reservation_expires_at,
            "profile_timeout_at":profile_timeout_at,
            "covenant_commitment":covenant_commitment
        }),
    );
    reject_custody_material(&Value::Object(contract.clone()))?;
    Ok(Value::Object(contract))
}

fn requester_quote_view(
    rfq: &Event,
    quote: &Event,
    profile: &Map<String, Value>,
) -> Result<RequesterQuoteView, SwapClientError> {
    let terms = object(
        profile.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    let assets = terms
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|assets| assets.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new("swp_contract_terms_mismatch", "Quote has no asset pair")
        })?;
    let expires_at = tag_value(quote, "expiration")?
        .parse::<u64>()
        .map_err(|_| SwapClientError::new("swp_quote_expired", "Quote expiration is invalid"))?;
    let effective_acceptance_deadline = effective_acceptance_deadline(profile, expires_at)?;
    let swap_type = match terms.get("swap_type").and_then(Value::as_str) {
        Some("submarine") => SwapType::Submarine,
        Some("reverse") => SwapType::Reverse,
        Some("chain") => SwapType::Chain,
        _ => {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote has an unsupported swap type",
            ));
        }
    };
    let string =
        |name| require_string(terms, name, None, "swp_contract_terms_mismatch").map(str::to_owned);
    let price_feed =
        RequesterPriceFeedView::from_pinned_terms(terms.get("price_feed").unwrap_or(&Value::Null))?;
    Ok(RequesterQuoteView {
        rfq_id: rfq.id.clone(),
        quote_id: quote.id.clone(),
        provider_pubkey: quote.pubkey.clone(),
        quote_class: tag_value(quote, "quote")?.to_owned(),
        reservation_class: tag_value(quote, "reservation")?.to_owned(),
        swap_type,
        input_asset_id: assets[0]
            .as_str()
            .ok_or_else(|| {
                SwapClientError::new("swp_contract_terms_mismatch", "input asset is invalid")
            })?
            .to_owned(),
        output_asset_id: assets[1]
            .as_str()
            .ok_or_else(|| {
                SwapClientError::new("swp_contract_terms_mismatch", "output asset is invalid")
            })?
            .to_owned(),
        input_amount: string("input_amount")?,
        output_amount: string("output_amount")?,
        amount_equation: string("amount_equation")?,
        rounding: string("rounding")?,
        clock_skew_seconds: string("clock_skew_seconds")?,
        expires_at,
        effective_acceptance_deadline,
        fees: RequesterFeeView {
            fee_bps: string("fee_bps")?,
            provider_fee: string("provider_fee")?,
            miner_fee_budget: string("miner_fee_budget")?,
            lightning_routing_fee_budget: string("lightning_routing_fee_budget")?,
            maximum_total_fee: string("maximum_total_fee")?,
            fee_payer: string("fee_payer")?,
        },
        price_feed,
    })
}

fn requester_timeline_entry(
    config: &SwapClientConfig,
    event: &Event,
    conflicts: &BTreeMap<String, String>,
) -> Result<RequesterTimelineEntry, SwapClientError> {
    let kind = match event.kind {
        MKT_RFQ_KIND => RequesterTimelineKind::Rfq,
        MKT_QUOTE_KIND => RequesterTimelineKind::Quote,
        MKT_ORDER_KIND => RequesterTimelineKind::Order,
        MKT_SWP_SWAP_CONTRACT_KIND => RequesterTimelineKind::Contract,
        MKT_STATUS_KIND => RequesterTimelineKind::Status,
        MKT_CANCEL_KIND => RequesterTimelineKind::Cancel,
        MKT_CLOSE_KIND => RequesterTimelineKind::Close,
        _ => {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "requester session contains an unsupported record kind",
            ));
        }
    };
    let sequence =
        if event.kind == MKT_STATUS_KIND {
            Some(tag_value(event, "seq")?.parse::<u64>().map_err(|_| {
                SwapClientError::new("swp_status_gap", "Status sequence is invalid")
            })?)
        } else {
            None
        };
    let state = if matches!(
        event.kind,
        MKT_STATUS_KIND | MKT_CANCEL_KIND | MKT_CLOSE_KIND
    ) {
        let profile = parse_content(event)?;
        let profile = object(
            profile.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP timeline record",
        )?;
        match event.kind {
            MKT_STATUS_KIND => profile.get("swp_state").and_then(Value::as_str),
            MKT_CANCEL_KIND => tag_value(event, "action").ok(),
            MKT_CLOSE_KIND => tag_value(event, "outcome").ok(),
            _ => None,
        }
        .map(str::to_owned)
    } else {
        None
    };
    let mut causal_event_ids = event
        .tags
        .iter()
        .filter_map(|tag| {
            (tag.name() == Some("e")
                && matches!(
                    tag.as_slice().get(3).map(String::as_str),
                    Some(
                        "rfq"
                            | "quote"
                            | "order"
                            | "previous"
                            | "status"
                            | "cancel-request"
                            | "cancel-accept"
                    )
                ))
            .then(|| tag.value().map(str::to_owned))
            .flatten()
        })
        .collect::<Vec<_>>();
    if event.kind == MKT_CLOSE_KIND {
        let content = parse_content(event)?;
        let profile = object(
            content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Close timeline record",
        )?;
        for name in ["status_id", "cancel_id"] {
            if let Some(event_id) = profile.get(name).and_then(Value::as_str) {
                causal_event_ids.push(event_id.to_owned());
            }
        }
    }
    causal_event_ids.sort();
    causal_event_ids.dedup();
    Ok(RequesterTimelineEntry {
        event_id: event.id.clone(),
        author: role_for_author(config, &event.pubkey)?,
        kind,
        created_at: event.created_at,
        sequence,
        state,
        causal_event_ids,
        conflict: conflicts.get(&event.id).cloned(),
    })
}

fn requester_terminal_view(
    records: &[Event],
    external_effects: Option<&BTreeMap<String, ExternalEffectResult>>,
) -> Result<RequesterTerminalView, SwapClientError> {
    let mut closes = records
        .iter()
        .filter(|event| event.kind == MKT_CLOSE_KIND)
        .collect::<Vec<_>>();
    closes.sort_by(|left, right| left.id.cmp(&right.id));
    if closes.is_empty() {
        return Ok(RequesterTerminalView {
            claimed_state: RequesterTerminalState::Open,
            canonical_close_id: None,
            close_event_ids: Vec::new(),
            principal_unresolved: None,
            loss_accounting_complete: false,
            local_effects_verified: false,
            watch_terminal: false,
        });
    }
    let mut claims = Vec::with_capacity(closes.len());
    for close in &closes {
        let outcome = tag_value(close, "outcome")?;
        let content = parse_content(close)?;
        let profile = object(
            content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Close",
        )?;
        let loss = object(
            profile.get("loss_accounting").unwrap_or(&Value::Null),
            "Close loss accounting",
        )?;
        claims.push((
            *close,
            outcome,
            canonical_json(&json!({
                "outcome":outcome,
                "terminal_at":tag_value(close, "terminal_at")?,
                "status_id":profile.get("status_id").cloned().unwrap_or(Value::Null),
                "cancel_id":profile.get("cancel_id").cloned().unwrap_or(Value::Null),
                "loss_accounting":loss
            }))?,
            profile.clone(),
            loss.clone(),
        ));
    }
    claims.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    let first_claim = &claims[0].2;
    if claims.iter().any(|claim| &claim.2 != first_claim) {
        return Ok(RequesterTerminalView {
            claimed_state: RequesterTerminalState::Conflicted,
            canonical_close_id: None,
            close_event_ids: closes.iter().map(|event| event.id.clone()).collect(),
            principal_unresolved: None,
            loss_accounting_complete: false,
            local_effects_verified: false,
            watch_terminal: false,
        });
    }
    let (close, outcome, _, _profile, loss) = &claims[0];
    let numeric_fields = [
        "input_committed",
        "input_recovered",
        "output_received",
        "provider_fee_paid",
        "miner_fee_paid",
        "lightning_routing_fee_paid",
        "guarantee_recovery_received",
        "principal_unresolved",
        "reservation_released",
    ];
    let unknown_empty = match loss.get("unknown_fields") {
        None => true,
        Some(Value::Array(fields)) => fields.is_empty(),
        Some(_) => false,
    };
    let loss_accounting_complete = unknown_empty
        && numeric_fields.iter().all(|field| {
            loss.get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| canonical_amount(value).is_ok())
        });
    let principal_unresolved = loss
        .get("principal_unresolved")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let claimed_state = match *outcome {
        "completed" => RequesterTerminalState::Completed,
        "refunded" => RequesterTerminalState::Refunded,
        "cancelled" => RequesterTerminalState::Cancelled,
        "rejected" => RequesterTerminalState::Rejected,
        "expired" => RequesterTerminalState::Expired,
        "failed" => RequesterTerminalState::Failed,
        "disputed" => RequesterTerminalState::Disputed,
        "unresolved" => RequesterTerminalState::Unresolved,
        _ => {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Close outcome is unsupported",
            ));
        }
    };
    let watch_terminal = if let Some(external_effects) = external_effects {
        let contract = records
            .iter()
            .find(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
            .map(parse_content)
            .transpose()?
            .and_then(|content| content.get("mkt_swp").cloned())
            .and_then(|profile| profile.get("contract").cloned())
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    "terminal claim has no accepted Swap Contract",
                )
            })?;
        let terminal_at = tag_value(close, "terminal_at")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_unresolved_loss", "Close terminal time is invalid")
            })?;
        validate_loss_accounting(
            loss,
            &contract,
            outcome,
            terminal_at,
            tag_value(close, "session")?,
            external_effects,
        )?;
        match claimed_state {
            RequesterTerminalState::Completed | RequesterTerminalState::Refunded => {
                !external_effects.is_empty()
            }
            RequesterTerminalState::Failed => false,
            RequesterTerminalState::Open
            | RequesterTerminalState::Cancelled
            | RequesterTerminalState::Rejected
            | RequesterTerminalState::Expired
            | RequesterTerminalState::Disputed
            | RequesterTerminalState::Unresolved
            | RequesterTerminalState::Conflicted => false,
        }
    } else {
        false
    };
    Ok(RequesterTerminalView {
        claimed_state,
        canonical_close_id: Some(close.id.clone()),
        close_event_ids: closes.iter().map(|event| event.id.clone()).collect(),
        principal_unresolved,
        loss_accounting_complete,
        local_effects_verified: watch_terminal,
        watch_terminal,
    })
}

fn requester_timeline_conflicts(
    records: &[Event],
    terminal: &RequesterTerminalView,
) -> Result<BTreeMap<String, String>, SwapClientError> {
    let mut conflicts = BTreeMap::new();
    if terminal.claimed_state == RequesterTerminalState::Conflicted {
        for event_id in &terminal.close_event_ids {
            conflicts.insert(event_id.clone(), "conflicting Close claim".to_owned());
        }
    }
    let mut responses: BTreeMap<String, Vec<(&Event, &str)>> = BTreeMap::new();
    for cancel in records.iter().filter(|event| event.kind == MKT_CANCEL_KIND) {
        let action = tag_value(cancel, "action")?;
        if matches!(action, "accepted" | "rejected") {
            let request_id = marked_reference(cancel, "cancel-request")?;
            responses
                .entry(request_id.to_owned())
                .or_default()
                .push((cancel, action));
        }
    }
    for response_set in responses.values() {
        let actions = response_set
            .iter()
            .map(|(_, action)| *action)
            .collect::<BTreeSet<_>>();
        if response_set.len() > 1 || actions.len() > 1 {
            for (event, _) in response_set {
                conflicts.insert(
                    event.id.clone(),
                    "conflicting cancellation response".to_owned(),
                );
            }
        }
    }
    Ok(conflicts)
}

fn timeline_sort_key(entry: &RequesterTimelineEntry) -> (u8, u8, u64, String) {
    let phase = match entry.kind {
        RequesterTimelineKind::Rfq => 0,
        RequesterTimelineKind::Quote => 1,
        RequesterTimelineKind::Order => 2,
        RequesterTimelineKind::Contract => 3,
        RequesterTimelineKind::Status => 4,
        RequesterTimelineKind::Cancel => 5,
        RequesterTimelineKind::Close => 6,
    };
    let author = match entry.author {
        ParticipantRole::Requester => 0,
        ParticipantRole::Provider => 1,
    };
    (
        phase,
        author,
        entry.sequence.unwrap_or_default(),
        entry.event_id.clone(),
    )
}

fn sort_requester_timeline(
    timeline: &mut Vec<RequesterTimelineEntry>,
) -> Result<(), SwapClientError> {
    let known_ids = timeline
        .iter()
        .map(|entry| entry.event_id.clone())
        .collect::<BTreeSet<_>>();
    let mut remaining = std::mem::take(timeline);
    let mut emitted = BTreeSet::new();
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry
                    .causal_event_ids
                    .iter()
                    .all(|event_id| !known_ids.contains(event_id) || emitted.contains(event_id))
            })
            .min_by_key(|(_, entry)| timeline_sort_key(entry))
            .map(|(index, _)| index)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_idempotency_conflict",
                    "requester timeline contains a causal reference cycle",
                )
            })?;
        let entry = remaining.remove(next);
        emitted.insert(entry.event_id.clone());
        timeline.push(entry);
    }
    Ok(())
}

fn unsigned_event(request: &MktSigningRequest) -> Event {
    Event {
        id: request.expected_event_id.clone(),
        pubkey: request.pubkey.clone(),
        created_at: request.created_at,
        kind: request.kind,
        tags: request.tags.clone(),
        content: request.content.clone(),
        sig: String::new(),
    }
}

fn validate_price_feed_url(url: &str) -> Result<(), SwapClientError> {
    if !url.starts_with("https://") || url.len() > 2_048 || url.contains('#') {
        return Err(SwapClientError::new(
            "swp_price_feed_invalid",
            "price-feed URL must be bounded HTTPS without a fragment",
        ));
    }
    let remainder = &url["https://".len()..];
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.chars().any(char::is_whitespace)
    {
        return Err(SwapClientError::new(
            "swp_price_feed_invalid",
            "price-feed URL has an empty host, userinfo, or whitespace",
        ));
    }
    Ok(())
}

fn validate_json_pointer(pointer: &str) -> Result<(), SwapClientError> {
    if pointer.len() > 512 || (!pointer.is_empty() && !pointer.starts_with('/')) {
        return Err(SwapClientError::new(
            "swp_price_feed_invalid",
            "price-feed value pointer is not an RFC 6901 pointer",
        ));
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return Err(SwapClientError::new(
                    "swp_price_feed_invalid",
                    "price-feed value pointer has an invalid escape",
                ));
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn canonical_decimal_string(value: &str, subject: &str) -> Result<(), SwapClientError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(SwapClientError::new(
            "swp_price_feed_invalid",
            format!("{subject} is not a canonical decimal string"),
        ));
    }
    Ok(())
}

fn effective_acceptance_deadline(
    quote: &Map<String, Value>,
    quote_expiration: u64,
) -> Result<u64, SwapClientError> {
    let mut deadline = quote_expiration;
    if let Some(reservation) = quote.get("reservation_terms") {
        let reservation = object(reservation, "Quote reservation terms")?;
        let expiration = reservation
            .get("reservation_expires_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_quote_expired",
                    "Quote reservation expiration is invalid",
                )
            })?;
        deadline = deadline.min(expiration);
        match reservation.get("profile_timeout_at") {
            None | Some(Value::Null) => {}
            Some(value) => {
                deadline = deadline.min(value.as_u64().ok_or_else(|| {
                    SwapClientError::new("swp_quote_expired", "Quote profile timeout is invalid")
                })?);
            }
        }
    }
    Ok(deadline)
}

fn validate_order_acceptance_deadline(
    quote: &Map<String, Value>,
    quote_expiration: u64,
    order_observed_at: u64,
) -> Result<(), SwapClientError> {
    let deadline = effective_acceptance_deadline(quote, quote_expiration)?;
    if order_observed_at > deadline {
        return Err(SwapClientError::new(
            "swp_quote_expired",
            "Order was locally observed after the Quote's effective acceptance deadline",
        ));
    }
    Ok(())
}

fn validate_order_selection(
    quote: &Map<String, Value>,
    order: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    if order
        .keys()
        .any(|name| !matches!(name.as_str(), "accepted_quote_id" | "selection"))
    {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Order restates or changes a non-selectable Quote field",
        ));
    }
    let selection = match order.get("selection") {
        None | Some(Value::Null) => None,
        Some(Value::Object(selection)) if selection.is_empty() => None,
        Some(Value::Object(selection)) => Some(selection),
        Some(_) => {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selection must be an object",
            ));
        }
    };
    let selectable = match quote.get("selectable") {
        None | Some(Value::Null) => None,
        Some(Value::Object(selectable))
            if selectable.keys().all(|name| {
                matches!(
                    name.as_str(),
                    "input_amount" | "fee_payer" | "confirmation_policy" | "public_receipt_consent"
                )
            }) =>
        {
            Some(selectable)
        }
        Some(_) => {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Quote selectable terms must be an object",
            ));
        }
    };
    let Some(selection) = selection else {
        return Ok(());
    };
    let selectable = selectable.ok_or_else(|| {
        SwapClientError::new(
            "swp_order_selection_invalid",
            "Quote permits no Order selection",
        )
    })?;
    for (name, selected) in selection {
        if !matches!(
            name.as_str(),
            "input_amount" | "fee_payer" | "confirmation_policy" | "public_receipt_consent"
        ) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selected a field outside the v1 allowlist",
            ));
        }
        let offered = selectable.get(name).ok_or_else(|| {
            SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selected a field not offered by the Quote",
            )
        })?;
        let valid = if name == "input_amount" {
            let selected = selected
                .as_str()
                .and_then(|value| canonical_amount(value).ok());
            let range = offered.as_object();
            match (selected, range) {
                (Some(selected), Some(range)) => {
                    let minimum = range
                        .get("minimum")
                        .and_then(Value::as_str)
                        .and_then(|value| canonical_amount(value).ok());
                    let maximum = range
                        .get("maximum")
                        .and_then(Value::as_str)
                        .and_then(|value| canonical_amount(value).ok());
                    matches!((minimum, maximum), (Some(minimum), Some(maximum)) if minimum <= selected && selected <= maximum)
                }
                _ => false,
            }
        } else {
            offered
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == selected))
        };
        if !valid {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selection is outside the Quote's finite choices",
            ));
        }
    }
    Ok(())
}

fn verify_order_selection(
    quote: &Map<String, Value>,
    order: &Map<String, Value>,
    contract: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    validate_order_selection(quote, order)?;
    let quote_terms = object(
        quote.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    if order
        .keys()
        .any(|name| !matches!(name.as_str(), "accepted_quote_id" | "selection"))
    {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Order restates or changes a non-selectable Quote field",
        ));
    }
    let selection = match order.get("selection") {
        None | Some(Value::Null) => None,
        Some(Value::Object(selection)) if selection.is_empty() => None,
        Some(Value::Object(selection)) => Some(selection),
        Some(_) => {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selection must be an object",
            ));
        }
    };
    let selectable = match quote.get("selectable") {
        None | Some(Value::Null) => None,
        Some(Value::Object(selectable))
            if selectable.keys().all(|name| {
                matches!(
                    name.as_str(),
                    "input_amount" | "fee_payer" | "confirmation_policy" | "public_receipt_consent"
                )
            }) =>
        {
            Some(selectable)
        }
        Some(_) => {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Quote selectable terms must be an object",
            ));
        }
    };
    for name in [
        "fee_bps",
        "miner_fee_budget",
        "lightning_routing_fee_budget",
        "amount_equation",
    ] {
        if quote_terms.get(name) != contract.get(name) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                format!("Swap Contract changed non-selectable amount member {name}"),
            ));
        }
    }
    let Some(selection) = selection else {
        if contract.get("order_selection").is_some_and(|value| {
            !value.is_null() && value.as_object().is_none_or(|object| !object.is_empty())
        }) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Swap Contract records a selection absent from the Order",
            ));
        }
        for name in [
            "input_amount",
            "output_amount",
            "provider_fee",
            "maximum_total_fee",
            "fee_payer",
            "confirmation_policy",
            "public_receipt_consent",
        ] {
            if quote_terms.get(name) != contract.get(name) {
                return Err(SwapClientError::new(
                    "swp_order_selection_invalid",
                    format!("Swap Contract changed unselected amount member {name}"),
                ));
            }
        }
        return verify_amount_equation(contract);
    };
    let selectable = selectable.ok_or_else(|| {
        SwapClientError::new(
            "swp_order_selection_invalid",
            "Quote permits no Order selection",
        )
    })?;
    for (name, selected) in selection {
        if !matches!(
            name.as_str(),
            "input_amount" | "fee_payer" | "confirmation_policy" | "public_receipt_consent"
        ) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selected a field outside the v1 allowlist",
            ));
        }
        let offered = selectable.get(name).ok_or_else(|| {
            SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selected a field not offered by the Quote",
            )
        })?;
        let valid = if name == "input_amount" {
            let selected = selected
                .as_str()
                .and_then(|value| canonical_amount(value).ok());
            let range = offered.as_object();
            match (selected, range) {
                (Some(selected), Some(range)) => {
                    let minimum = range
                        .get("minimum")
                        .and_then(Value::as_str)
                        .and_then(|value| canonical_amount(value).ok());
                    let maximum = range
                        .get("maximum")
                        .and_then(Value::as_str)
                        .and_then(|value| canonical_amount(value).ok());
                    matches!((minimum, maximum), (Some(minimum), Some(maximum)) if minimum <= selected && selected <= maximum)
                }
                _ => false,
            }
        } else {
            offered
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == selected))
        };
        if !valid {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Order selection is outside the Quote's finite choices",
            ));
        }
        if name != "input_amount" && contract.get(name) != Some(selected) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Swap Contract does not freeze the selected Quote option",
            ));
        }
    }
    if contract.get("order_selection") != Some(&Value::Object(selection.clone())) {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Swap Contract does not bind the exact Order selection",
        ));
    }
    for name in ["fee_payer", "confirmation_policy", "public_receipt_consent"] {
        let expected = selection.get(name).or_else(|| quote_terms.get(name));
        if contract.get(name) != expected {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                format!("Swap Contract does not bind selected or inherited {name}"),
            ));
        }
    }
    if let Some(selected_input) = selection.get("input_amount").and_then(Value::as_str) {
        if contract.get("input_amount").and_then(Value::as_str) != Some(selected_input) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Swap Contract does not bind the selected input amount",
            ));
        }
    } else {
        for name in ["provider_fee", "maximum_total_fee"] {
            if contract.get(name) != quote_terms.get(name) {
                return Err(SwapClientError::new(
                    "swp_order_selection_invalid",
                    format!("Swap Contract changed unselected amount member {name}"),
                ));
            }
        }
    }
    verify_amount_equation(contract)
}

fn verify_amount_equation(contract: &Map<String, Value>) -> Result<(), SwapClientError> {
    let input = contract_amount(contract, "input_amount")?;
    let output = contract_amount(contract, "output_amount")?;
    let fee_bps = contract_amount(contract, "fee_bps")?;
    let provider_fee = contract_amount(contract, "provider_fee")?;
    let miner_fee = contract_amount(contract, "miner_fee_budget")?;
    let lightning_fee = contract_amount(contract, "lightning_routing_fee_budget")?;
    let expected_provider_fee = u64::try_from(
        u128::from(input)
            .checked_mul(u128::from(fee_bps))
            .ok_or_else(|| {
                SwapClientError::new("swp_order_selection_invalid", "fee calculation overflows")
            })?
            / 10_000,
    )
    .map_err(|_| {
        SwapClientError::new(
            "swp_order_selection_invalid",
            "fee calculation exceeds the v1 amount range",
        )
    })?;
    let expected_output = input
        .checked_sub(provider_fee)
        .and_then(|amount| amount.checked_sub(miner_fee))
        .and_then(|amount| amount.checked_sub(lightning_fee))
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_order_selection_invalid",
                "input amount cannot satisfy the quoted amount equation",
            )
        })?;
    if fee_bps > 10_000
        || provider_fee != expected_provider_fee
        || output != expected_output
        || contract.get("rounding").and_then(Value::as_str) != Some("floor_output_sats")
        || !matches!(
            contract.get("amount_equation").and_then(Value::as_str),
            Some("input_minus_provider_and_quoted_fees" | "one_to_one_less_quoted_fees")
        )
    {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "frozen amounts, fee basis points, or rounding do not reproduce output",
        ));
    }
    Ok(())
}

fn validate_provider_quote_profile(
    profile: &Map<String, Value>,
    reservation_class: &str,
) -> Result<(), SwapClientError> {
    reject_custody_material(&Value::Object(profile.clone()))?;
    if let Some(critical) = profile.get("critical") {
        let critical = critical
            .as_array()
            .filter(|members| members.len() <= 32)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_unsupported_critical_member",
                    "Quote critical members must be a bounded array",
                )
            })?;
        let mut names = BTreeSet::new();
        for member in critical {
            let member = member.as_str().filter(|member| {
                !member.is_empty()
                    && member.len() <= 64
                    && member.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
            });
            let Some(member) = member else {
                return Err(SwapClientError::new(
                    "swp_unsupported_critical_member",
                    "Quote critical member name is invalid",
                ));
            };
            if !names.insert(member)
                || !matches!(member, "terms" | "reservation_terms" | "selectable")
            {
                return Err(SwapClientError::new(
                    "swp_unsupported_critical_member",
                    "Quote names an unsupported critical member",
                ));
            }
        }
    }
    let terms = object(
        profile.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    let swap_type = match terms.get("swap_type").and_then(Value::as_str) {
        Some("submarine") => SwapType::Submarine,
        Some("reverse") => SwapType::Reverse,
        Some("chain") => SwapType::Chain,
        _ => {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote has an unsupported swap type",
            ));
        }
    };
    for member in [
        "asset_pair",
        "payment_hash",
        "input_amount",
        "output_amount",
        "fee_bps",
        "provider_fee",
        "miner_fee_budget",
        "lightning_routing_fee_budget",
        "maximum_total_fee",
        "confirmation_policy",
        "script_mode",
        "desired_completion_time",
        "clock_skew_seconds",
        "amount_equation",
        "rounding",
        "fee_payer",
        "legs",
        "timeout_ladder",
        "verifier_inputs",
        "recovery",
        "reservation_commitment",
        "cancellation",
        "evidence_requirements",
        "price_feed",
        "evm_leg",
    ] {
        if !terms.contains_key(member) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("Quote terms omit {member}"),
            ));
        }
    }
    require_lower_hex_32(
        require_string(terms, "payment_hash", None, "swp_payment_hash_mismatch")?,
        "Quote payment hash",
    )?;
    verify_amount_equation(terms)?;
    if !terms
        .get("reservation_commitment")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
        || !matches!(
            terms.get("fee_payer").and_then(Value::as_str),
            Some("requester" | "provider")
        )
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote reservation placeholder or fee payer is invalid",
        ));
    }
    if canonical_amount(require_string(
        terms,
        "maximum_total_fee",
        None,
        "swp_contract_terms_mismatch",
    )?)? != contract_amount(terms, "provider_fee")?
        .checked_add(contract_amount(terms, "miner_fee_budget")?)
        .and_then(|fee| {
            fee.checked_add(contract_amount(terms, "lightning_routing_fee_budget").ok()?)
        })
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote maximum fee calculation overflows",
            )
        })?
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote maximum total fee differs from its fee components",
        ));
    }
    RequesterPriceFeedView::from_pinned_terms(terms.get("price_feed").unwrap_or(&Value::Null))?;
    if terms.get("script_mode").and_then(Value::as_str) != Some("taproot-musig2-script-exit")
        || terms
            .get("desired_completion_time")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0)
        || canonical_amount(require_string(
            terms,
            "clock_skew_seconds",
            None,
            "swp_contract_terms_mismatch",
        )?)? > 120
        || !terms.get("evm_leg").is_some_and(Value::is_null)
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote script, timing, price-feed, or EVM policy is invalid",
        ));
    }
    validate_quote_cooperative_policy(terms, swap_type)?;
    let confirmation = object(
        terms.get("confirmation_policy").unwrap_or(&Value::Null),
        "Quote confirmation policy",
    )?;
    for member in ["minimum_confirmations", "reorg_safety_blocks"] {
        canonical_amount(require_string(
            confirmation,
            member,
            None,
            "swp_contract_terms_mismatch",
        )?)?;
    }
    if !matches!(
        confirmation
            .get("zero_confirmation")
            .and_then(Value::as_str),
        Some("forbidden" | "allowed")
    ) || !matches!(
        confirmation.get("rbf").and_then(Value::as_str),
        Some("reject" | "track")
    ) || !matches!(
        confirmation.get("replacement").and_then(Value::as_str),
        Some("reject" | "track")
    ) {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote confirmation policy is invalid",
        ));
    }
    let timeout_ladder: TimeoutLadder =
        serde_json::from_value(terms.get("timeout_ladder").cloned().unwrap_or(Value::Null))
            .map_err(|error| {
                SwapClientError::new(
                    "swp_timeout_ladder_unsafe",
                    format!("Quote timeout ladder is invalid: {error}"),
                )
            })?;
    timeout_ladder.validate()?;
    if timeout_ladder.swap_type() != swap_type {
        return Err(SwapClientError::new(
            "swp_timeout_ladder_unsafe",
            "Quote timeout ladder belongs to another swap type",
        ));
    }
    validate_quote_recovery_policy(terms)?;
    validate_quote_cancellation_and_evidence(terms)?;
    validate_quote_selectable(profile)?;
    let topology = requester_topology(swap_type);
    let mut topology_terms = terms.clone();
    topology_terms.insert(
        "effect_bindings".into(),
        Value::Array(
            std::iter::once(json!({
                "role":topology.funding_effect_role,
                "leg_id":topology.funding_leg_id
            }))
            .chain(topology.exits.iter().map(|exit| {
                json!({
                    "role":if exit.path == "claim" { "chain_claim" } else { "chain_refund" },
                    "leg_id":exit.leg_id
                })
            }))
            .collect(),
        ),
    );
    topology_terms.insert(
        "exit_package_commitments".into(),
        Value::Array(
            topology
                .exits
                .iter()
                .map(|exit| {
                    json!({
                        "participant_role":"requester",
                        "leg_id":exit.leg_id,
                        "path":exit.path
                    })
                })
                .collect(),
        ),
    );
    verify_requester_topology(&topology_terms, swap_type)?;
    validate_quote_reservation(profile, terms, reservation_class)
}

fn validate_quote_cooperative_policy(
    terms: &Map<String, Value>,
    swap_type: SwapType,
) -> Result<(), SwapClientError> {
    let Some(declared) = terms.get("musig2_execution") else {
        return Ok(());
    };
    let enabled = declared.as_bool().ok_or_else(|| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote cooperative execution flag is not boolean",
        )
    })?;
    if enabled && swap_type != SwapType::Submarine {
        return Err(SwapClientError::new(
            "swp_unsupported_extension",
            "this Quote profile enables cooperative execution only for submarine swaps",
        ));
    }
    let bitcoin_leg = terms
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            let matching = legs
                .iter()
                .filter(|leg| leg.get("rail").and_then(Value::as_str) == Some("bitcoin"))
                .collect::<Vec<_>>();
            let [leg] = matching.as_slice() else {
                return None;
            };
            Some(*leg)
        })
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote cooperative profile requires one Bitcoin leg",
            )
        })?;
    let leg_id = bitcoin_leg
        .get("leg_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SwapClientError::new("swp_contract_terms_mismatch", "Quote Bitcoin leg has no ID")
        })?;
    let verifier = terms
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers
                .iter()
                .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote Bitcoin leg has no verifier",
            )
        })?;
    if verifier.get("musig2_execution").and_then(Value::as_bool) != Some(enabled)
        || verifier.get("sighash_policy").and_then(Value::as_str)
            != Some(if enabled {
                "default_key_path_with_script_fallback"
            } else {
                "default_script_path_only"
            })
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote cooperative and sighash policies disagree",
        ));
    }
    let effects = terms
        .get("effect_policy")
        .and_then(Value::as_object)
        .and_then(|policy| policy.get("effects"))
        .and_then(Value::as_array)
        .filter(|effects| effects.len() <= 32);
    if enabled && effects.is_none() {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "cooperative Quote has no bounded effect policy",
        ));
    }
    let cooperative_effects = effects
        .into_iter()
        .flatten()
        .filter(|effect| {
            effect.get("actor").and_then(Value::as_str) == Some("provider")
                && effect.get("effect_role").and_then(Value::as_str) == Some("cooperative_sign")
                && effect.get("leg_id").and_then(Value::as_str) == Some(leg_id)
        })
        .count();
    if cooperative_effects != usize::from(enabled) {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote cooperative effect policy disagrees with execution",
        ));
    }
    let extension_fields = [
        "provider_exit_destination_script_pubkey",
        "provider_exit_signer_ref",
        "provider_exit_policy",
    ];
    if !enabled {
        if extension_fields
            .iter()
            .any(|member| verifier.contains_key(*member))
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "script-only Quote carries inactive cooperative exit fields",
            ));
        }
        return Ok(());
    }
    let destination = decode_hex(
        require_string(
            verifier,
            "provider_exit_destination_script_pubkey",
            None,
            "swp_contract_terms_mismatch",
        )?,
        "provider cooperative exit destination",
    )?;
    if destination.len() != 34
        || destination.first() != Some(&0x51)
        || destination.get(1) != Some(&0x20)
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "provider cooperative exit destination is not native Taproot",
        ));
    }
    let signer_ref = require_string(
        verifier,
        "provider_exit_signer_ref",
        None,
        "swp_contract_terms_mismatch",
    )?;
    if signer_ref.is_empty() || signer_ref.len() > 256 || signer_ref.chars().any(char::is_control) {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "provider cooperative signer reference is invalid",
        ));
    }
    let policy = object(
        verifier.get("provider_exit_policy").unwrap_or(&Value::Null),
        "provider cooperative exit policy",
    )?;
    let earliest = canonical_amount(require_string(
        policy,
        "earliest_broadcast_height",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let latest = canonical_amount(require_string(
        policy,
        "latest_safe_broadcast_height",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let maximum_fee = canonical_amount(require_string(
        policy,
        "maximum_fee",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    if latest < earliest
        || maximum_fee == 0
        || policy.get("bump_mode").and_then(Value::as_str) != Some("cpfp")
        || policy
            .get("target_blocks")
            .and_then(Value::as_u64)
            .is_none_or(|blocks| blocks == 0 || blocks > 1_008)
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "provider cooperative exit policy is invalid",
        ));
    }
    let timeout_ladder = object(
        terms.get("timeout_ladder").unwrap_or(&Value::Null),
        "Quote timeout ladder",
    )?;
    let chain_tip_height = canonical_amount(require_string(
        verifier,
        "chain_tip_height",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    if earliest != chain_tip_height
        || maximum_fee != contract_amount(terms, "miner_fee_budget")?
        || timeout_ladder.get("claim_last").and_then(Value::as_u64) != Some(latest)
    {
        return Err(SwapClientError::new(
            "swp_timeout_ladder_unsafe",
            "provider cooperative exit policy differs from the Quote bounds",
        ));
    }
    Ok(())
}

fn validate_quote_against_rfq(
    rfq: &Event,
    profile: &Map<String, Value>,
    quote_class: &str,
    created_at: u64,
    expiration: u64,
) -> Result<(), SwapClientError> {
    let terms = object(
        profile.get("terms").unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    let rfq_content = parse_content(rfq)?;
    let rfq_profile = object(
        rfq_content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP RFQ",
    )?;
    let constraints = object(
        rfq_profile.get("constraints").unwrap_or(&Value::Null),
        "MKT-SWP RFQ constraints",
    )?;
    let rfq_expiration = tag_value(rfq, "expiration")?
        .parse::<u64>()
        .map_err(|_| SwapClientError::new("swp_quote_expired", "RFQ expiration is invalid"))?;
    if !matches!(quote_class, "indicative" | "firm")
        || created_at > expiration
        || expiration > rfq_expiration
    {
        return Err(SwapClientError::new(
            "swp_quote_expired",
            "Quote lifetime is invalid or exceeds its RFQ",
        ));
    }
    for member in ["swap_type", "asset_pair", "payment_hash"] {
        if constraints.get(member) != terms.get(member) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("Quote member {member} weakens the RFQ constraint"),
            ));
        }
    }
    let quoted_input = contract_amount(terms, "input_amount")?;
    let amount_allowed = match (
        constraints.get("input_amount"),
        constraints.get("input_amount_range"),
    ) {
        (Some(Value::String(amount)), None) => canonical_amount(amount)? == quoted_input,
        (None, Some(Value::Object(range))) => {
            let minimum = canonical_amount(require_string(
                range,
                "minimum",
                None,
                "swp_contract_terms_mismatch",
            )?)?;
            let maximum = canonical_amount(require_string(
                range,
                "maximum",
                None,
                "swp_contract_terms_mismatch",
            )?)?;
            minimum <= quoted_input && quoted_input <= maximum
        }
        _ => false,
    };
    let maximum_total_fee = canonical_amount(require_string(
        constraints,
        "maximum_total_fee",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let quoted_total_fee = contract_amount(terms, "maximum_total_fee")?;
    let requested_confirmation = object(
        constraints
            .get("confirmation_policy")
            .unwrap_or(&Value::Null),
        "RFQ confirmation policy",
    )?;
    let quoted_confirmation = object(
        terms.get("confirmation_policy").unwrap_or(&Value::Null),
        "Quote confirmation policy",
    )?;
    let requested_minimum = canonical_amount(require_string(
        requested_confirmation,
        "minimum_confirmations",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let quoted_minimum = canonical_amount(require_string(
        quoted_confirmation,
        "minimum_confirmations",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let requested_reorg = canonical_amount(require_string(
        requested_confirmation,
        "reorg_safety_blocks",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let quoted_reorg = canonical_amount(require_string(
        quoted_confirmation,
        "reorg_safety_blocks",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let script_modes = constraints
        .get("allowed_script_modes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "RFQ has no allowed script modes",
            )
        })?;
    let desired_completion = constraints
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "RFQ desired completion time is invalid",
            )
        })?;
    let expected_invoice = terms
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers.iter().find(|verifier| {
                verifier.get("leg_id").and_then(Value::as_str) == Some("lightning")
            })
        })
        .and_then(|verifier| verifier.get("invoice_sha256"));
    let invoice_matches = match constraints.get("swap_type").and_then(Value::as_str) {
        Some("submarine") => {
            expected_invoice.is_some() && constraints.get("invoice_sha256") == expected_invoice
        }
        Some("reverse") => {
            expected_invoice.is_some()
                && (matches!(constraints.get("invoice_sha256"), None | Some(Value::Null))
                    || constraints.get("invoice_sha256") == expected_invoice)
        }
        Some("chain") => match expected_invoice {
            Some(invoice) => constraints.get("invoice_sha256") == Some(invoice),
            None => matches!(constraints.get("invoice_sha256"), None | Some(Value::Null)),
        },
        _ => false,
    };
    let requester_public_keys = requester_public_keys_from_terms(terms)?;
    if !amount_allowed
        || quoted_total_fee > maximum_total_fee
        || quoted_minimum < requested_minimum
        || quoted_reorg < requested_reorg
        || ["zero_confirmation", "rbf", "replacement"]
            .iter()
            .any(|member| quoted_confirmation.get(*member) != requested_confirmation.get(*member))
        || !script_modes
            .iter()
            .any(|mode| mode == terms.get("script_mode").unwrap_or(&Value::Null))
        || terms
            .get("desired_completion_time")
            .and_then(Value::as_u64)
            .is_none_or(|completion| completion > desired_completion)
        || constraints
            .get("firm_quote_required")
            .and_then(Value::as_bool)
            == Some(true)
            && quote_class != "firm"
        || !invoice_matches
        || constraints.get("requester_public_keys") != Some(&requester_public_keys)
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote weakens an RFQ amount, fee, policy, script, timing, or commitment constraint",
        ));
    }
    let bitcoin_verifiers = terms
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote has no verifier inputs",
            )
        })?
        .iter()
        .filter(|verifier| {
            verifier.get("verifier_policy").and_then(Value::as_str) == Some("mkt-swp-bitcoin-v1")
        });
    for verifier in bitcoin_verifiers {
        if verifier.get("minimum_confirmations") != quoted_confirmation.get("minimum_confirmations")
            || verifier.get("replacement_policy") != quoted_confirmation.get("replacement")
            || verifier.get("zero_confirmation") != quoted_confirmation.get("zero_confirmation")
            || verifier.get("rbf_policy") != quoted_confirmation.get("rbf")
            || verifier.get("reorg_safety_blocks") != quoted_confirmation.get("reorg_safety_blocks")
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote weakens the RFQ confirmation or replacement policy",
            ));
        }
    }
    Ok(())
}

fn validate_quote_cancellation_and_evidence(
    terms: &Map<String, Value>,
) -> Result<(), SwapClientError> {
    let cancellation = object(
        terms.get("cancellation").unwrap_or(&Value::Null),
        "Quote cancellation policy",
    )?;
    let evidence = object(
        terms.get("evidence_requirements").unwrap_or(&Value::Null),
        "Quote evidence requirements",
    )?;
    if cancellation.len() != 1
        || cancellation
            .get("effective_before_external_effect")
            .and_then(Value::as_bool)
            != Some(true)
        || evidence.len() != 1
        || !matches!(
            evidence.get("minimum_rung").and_then(Value::as_str),
            Some("pledged" | "reserved" | "measured" | "verified" | "paid" | "settled")
        )
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote cancellation or evidence policy is invalid",
        ));
    }
    Ok(())
}

fn validate_quote_selectable(profile: &Map<String, Value>) -> Result<(), SwapClientError> {
    let Some(selectable) = profile.get("selectable") else {
        return Ok(());
    };
    let selectable = object(selectable, "Quote selectable terms")?;
    if selectable.keys().any(|member| {
        !matches!(
            member.as_str(),
            "input_amount" | "fee_payer" | "confirmation_policy" | "public_receipt_consent"
        )
    }) {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Quote contains an unsupported selectable member",
        ));
    }
    if let Some(range) = selectable.get("input_amount") {
        let range = object(range, "Quote selectable input amount")?;
        let minimum = canonical_amount(require_string(
            range,
            "minimum",
            None,
            "swp_order_selection_invalid",
        )?)?;
        let maximum = canonical_amount(require_string(
            range,
            "maximum",
            None,
            "swp_order_selection_invalid",
        )?)?;
        if range.len() != 2 || minimum > maximum {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "Quote selectable input range is invalid",
            ));
        }
    }
    for member in ["fee_payer", "confirmation_policy", "public_receipt_consent"] {
        if selectable.get(member).is_some_and(|choices| {
            choices
                .as_array()
                .is_none_or(|choices| choices.is_empty() || choices.len() > 16)
        }) {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                format!("Quote selectable {member} choices are invalid"),
            ));
        }
    }
    Ok(())
}

fn validate_quote_recovery_policy(terms: &Map<String, Value>) -> Result<(), SwapClientError> {
    let recovery = object(
        terms.get("recovery").unwrap_or(&Value::Null),
        "Quote recovery policy",
    )?;
    if recovery.get("channel").and_then(Value::as_str) != Some("direct_or_relay_agnostic") {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote recovery channel is unsupported",
        ));
    }
    let exit = object(
        recovery.get("exit_policy").unwrap_or(&Value::Null),
        "Quote exit policy",
    )?;
    let earliest = canonical_amount(require_string(
        exit,
        "earliest_broadcast_height",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let latest = canonical_amount(require_string(
        exit,
        "latest_safe_broadcast_height",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let maximum_fee = canonical_amount(require_string(
        exit,
        "maximum_fee",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    if earliest > latest
        || maximum_fee > contract_amount(terms, "miner_fee_budget")?
        || exit
            .get("target_blocks")
            .and_then(Value::as_u64)
            .is_none_or(|blocks| blocks == 0)
        || exit.get("bump_mode").and_then(Value::as_str) != Some("cpfp")
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote exit policy is invalid",
        ));
    }
    Ok(())
}

fn validate_quote_reservation(
    profile: &Map<String, Value>,
    terms: &Map<String, Value>,
    reservation_class: &str,
) -> Result<(), SwapClientError> {
    if reservation_class == "none" {
        if profile
            .get("reservation_terms")
            .is_some_and(|value| !value.is_null())
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "non-reserving Quote carries reservation terms",
            ));
        }
        return Ok(());
    }
    if !matches!(reservation_class, "soft" | "hard") {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote reservation class is invalid",
        ));
    }
    let reservation = object(
        profile.get("reservation_terms").unwrap_or(&Value::Null),
        "Quote reservation terms",
    )?;
    require_lower_hex_32(
        require_string(
            reservation,
            "reservation_id",
            None,
            "swp_contract_terms_mismatch",
        )?,
        "reservation ID",
    )?;
    let capacity_bucket = require_string(
        reservation,
        "capacity_bucket_id",
        None,
        "swp_contract_terms_mismatch",
    )?;
    if capacity_bucket.is_empty()
        || capacity_bucket.len() > 64
        || !capacity_bucket
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' => true,
                b'.' | b'_' | b'-' => index > 0,
                _ => false,
            })
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "reservation capacity bucket is invalid",
        ));
    }
    let assets = terms
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|assets| assets.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote has no ordered asset pair",
            )
        })?;
    let reserved_amount = canonical_amount(require_string(
        reservation,
        "reserved_amount",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let committed = canonical_amount(require_string(
        reservation,
        "handler_committed_capacity",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    canonical_amount(require_string(
        reservation,
        "allocation_sequence",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let proof_class = require_string(
        reservation,
        "proof_class",
        None,
        "swp_contract_terms_mismatch",
    )?;
    reservation_proof_strength(reservation_class, proof_class)?;
    require_lower_hex_32(
        require_string(
            reservation,
            "capacity_commitment_sha256",
            None,
            "swp_contract_terms_mismatch",
        )?,
        "capacity commitment digest",
    )?;
    let proof_ref = require_string(
        reservation,
        "proof_ref",
        None,
        "swp_contract_terms_mismatch",
    )?;
    if proof_ref.is_empty()
        || proof_ref.len() > 512
        || proof_ref.contains('@')
        || proof_ref.contains('?')
        || proof_ref.chars().any(char::is_control)
        || reservation
            .get("reservation_expires_at")
            .and_then(Value::as_u64)
            .is_none_or(|expiration| expiration == 0)
        || reservation.get("reserved_asset_id") != assets.get(1)
        || reserved_amount < contract_amount(terms, "output_amount")?
        || committed < reserved_amount
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "reservation does not cover the Quote output or expiry",
        ));
    }
    Ok(())
}

fn validate_provider_contract_candidate(
    config: &SwapClientConfig,
    records: &[Event],
    contract: &Value,
) -> Result<(), SwapClientError> {
    reject_custody_material(contract)?;
    let quote = exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
    let order = exactly_one(records, MKT_ORDER_KIND, "swp_contract_terms_mismatch")?;
    if records.iter().any(|record| {
        record.kind == MKT_SWP_SWAP_CONTRACT_KIND && record.pubkey == config.provider_pubkey
    }) {
        return Err(SwapClientError::new(
            "swp_idempotency_conflict",
            "provider Swap Contract already exists",
        ));
    }
    let request = SwapRecordFactory::new(config.clone())?.swap_contract(
        ParticipantRole::Provider,
        records
            .iter()
            .map(|record| record.created_at)
            .max()
            .unwrap_or_default()
            .saturating_add(1),
        &lower_hex(&sha256(
            format!("provider-contract-candidate:{}", config.session_id).as_bytes(),
        )),
        SwapContractReferences {
            order_id: &order.id,
            quote_id: &quote.id,
            accepted_status_id: None,
        },
        contract.clone(),
    )?;
    let mut candidate = records.to_vec();
    candidate.push(Event {
        id: request.expected_event_id,
        pubkey: request.pubkey,
        created_at: request.created_at,
        kind: request.kind,
        tags: request.tags,
        content: request.content,
        sig: "00".repeat(64),
    });
    let bound = BoundSession::from_records(config, &candidate)?;
    bound.verify_contract_terms()?;
    bound.verify_requester_topology()
}

fn contract_amount(contract: &Map<String, Value>, name: &str) -> Result<u64, SwapClientError> {
    contract
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_order_selection_invalid",
                format!("Swap Contract is missing {name}"),
            )
        })
        .and_then(canonical_amount)
}

fn reservation_proof_strength(
    reservation_class: &str,
    proof_class: &str,
) -> Result<u16, SwapClientError> {
    match (reservation_class, proof_class) {
        ("soft", "provider_signed") => Ok(10),
        ("soft" | "hard", "handler_accounted") => Ok(20),
        ("hard", "third_party_guarantee") => Ok(40),
        ("hard", "lightning_liquidity") => Ok(50),
        ("hard", "utxo_control") => Ok(60),
        ("hard", "funded_htlc") => Ok(80),
        ("hard", "covenant_reserve") => Ok(100),
        _ => Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "reservation class and proof class are incompatible",
        )),
    }
}

fn validate_covenant_reservation(
    terms: &Map<String, Value>,
    reserved_amount: u64,
    reservation_expires_at: u64,
) -> Result<Value, SwapClientError> {
    let covenant = object(
        terms.get("covenant").unwrap_or(&Value::Null),
        "covenant reserve",
    )?;
    let funding_ref = require_string(covenant, "funding_ref", None, "swp_contract_terms_mismatch")?;
    let (transaction_id, output_index) = funding_ref.split_once(':').ok_or_else(|| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            "covenant funding reference is not txid:vout",
        )
    })?;
    require_lower_hex_32(transaction_id, "covenant funding txid")?;
    output_index.parse::<u32>().map_err(|_| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            "covenant funding output index is invalid",
        )
    })?;
    for member in [
        "program_sha256",
        "eligible_fill_sha256",
        "fee_rule_sha256",
        "verifier_view_sha256",
    ] {
        require_lower_hex_32(
            require_string(covenant, member, None, "swp_contract_terms_mismatch")?,
            member,
        )?;
    }
    let minimum_output = canonical_amount(require_string(
        covenant,
        "minimum_output",
        None,
        "swp_contract_terms_mismatch",
    )?)?;
    let expires_at = covenant
        .get("expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "covenant expiration is invalid",
            )
        })?;
    if minimum_output < reserved_amount || expires_at < reservation_expires_at {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "covenant reserve does not cover the reservation amount or expiry",
        ));
    }
    Ok(json!({
        "reserve_unit_sha256":lower_hex(&sha256(funding_ref.as_bytes())),
        "program_sha256":covenant["program_sha256"],
        "eligible_fill_sha256":covenant["eligible_fill_sha256"],
        "fee_rule_sha256":covenant["fee_rule_sha256"],
        "verifier_view_sha256":covenant["verifier_view_sha256"],
        "minimum_output":minimum_output.to_string(),
        "expires_at":expires_at
    }))
}

fn requester_public_keys_from_terms(terms: &Map<String, Value>) -> Result<Value, SwapClientError> {
    let verifiers = terms
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Quote has no verifier inputs",
            )
        })?;
    let mut keys = Vec::new();
    for verifier in verifiers {
        let Some(tree) = verifier.get("taproot_tree").and_then(Value::as_array) else {
            continue;
        };
        let leg_id = verifier
            .get("leg_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "Quote verifier leg ID is missing",
                )
            })?;
        for leaf in tree.iter().filter(|leaf| {
            leaf.get("participant_role").and_then(Value::as_str) == Some("requester")
        }) {
            keys.push(json!({
                "leg_id":leg_id,
                "path":leaf.get("path").cloned().unwrap_or(Value::Null),
                "public_key":leaf.get("signing_pubkey").cloned().unwrap_or(Value::Null)
            }));
        }
    }
    keys.sort_by_key(Value::to_string);
    Ok(Value::Array(keys))
}

fn validate_session_material(
    config: &SwapClientConfig,
    records: &[Event],
    exit_packages: &[ExitPackage],
) -> Result<(), SwapClientError> {
    config.validate()?;
    if records.is_empty() || records.len() > MAX_SIGNED_RECORDS {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "signed record history is empty or exceeds its bound",
        ));
    }
    if exit_packages.len() > MAX_EXIT_PACKAGES {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "exit package count exceeds its bound",
        ));
    }
    let mut event_ids = BTreeSet::new();
    for event in records {
        let raw = serde_json::to_vec(event).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("could not serialize signed record: {error}"),
            )
        })?;
        let validated =
            validate_mkt_private_raw(&raw, &swp_profile_support()).map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("persisted signed record failed validation: {error}"),
                )
            })?;
        reject_custody_material(&parse_content(event)?)?;
        if validated.envelope().session_id != config.session_id {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "signed record belongs to a different session",
            ));
        }
        role_for_author(config, &event.pubkey)?;
        event_ids.insert(event.id.clone());
    }
    if event_ids.len() != records.len() {
        return Err(SwapClientError::new(
            "swp_idempotency_conflict",
            "signed record history contains duplicate event IDs",
        ));
    }
    let order = exactly_one(records, MKT_ORDER_KIND, "swp_contract_terms_mismatch")?;
    let rfq = exactly_one(records, MKT_RFQ_KIND, "swp_unresolved_loss")?;
    let quote = exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
    let quote_profile = validate_requester_quote(config, rfq, quote)?;
    reject_unsupported_executable_quote(&quote_profile)?;
    for event in records.iter().filter(|event| {
        matches!(
            event.kind,
            MKT_STATUS_KIND | MKT_CANCEL_KIND | MKT_CLOSE_KIND
        )
    }) {
        require_marked_reference(event, "order", &order.id)?;
    }
    for package in exit_packages {
        ExitPackage::parse(package.document.clone())?;
    }
    StatusProjection::from_records(config, records)?;
    validate_cooperative_context_bindings(config, records, exit_packages)?;
    Ok(())
}

fn validate_cooperative_context_bindings(
    config: &SwapClientConfig,
    records: &[Event],
    exit_packages: &[ExitPackage],
) -> Result<(), SwapClientError> {
    let mut contexts = BTreeMap::new();
    for event in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
        let role = role_for_author(config, &event.pubkey)?;
        if let Some(message) = cooperative_signing_message(event, role)? {
            contexts
                .entry(message.context_sha256.clone())
                .or_insert(message.context);
        }
    }
    if contexts.is_empty() {
        return Ok(());
    }
    for context in contexts.values() {
        let mut matching_package = None;
        for package in exit_packages {
            if package.commitment_sha256()? == context.exit_package_sha256 {
                matching_package = Some(package);
                break;
            }
        }
        let package = matching_package.ok_or_else(|| {
            musig_error("cooperative context has no exact local unilateral exit package")
        })?;
        validate_cooperative_context_binding(config, records, context, package, None)?;
    }
    Ok(())
}

fn validate_cooperative_context_binding(
    config: &SwapClientConfig,
    records: &[Event],
    context: &CooperativeSigningContext,
    package: &ExitPackage,
    expected_role: Option<ParticipantRole>,
) -> Result<(), SwapClientError> {
    context.validate()?;
    let bound = BoundSession::from_records(config, records)?;
    let contract = object(&bound.contract, "Swap Contract")?;
    if contract.get("musig2_execution").and_then(Value::as_bool) != Some(true) {
        return Err(musig_error(
            "bilateral Swap Contract does not enable cooperative execution",
        ));
    }
    let effect_bindings = contract
        .get("effect_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| musig_error("Swap Contract has no cooperative effect bindings"))?;
    if context.order_id != bound.order.id
        || context.swap_contract_sha256 != bound.contract_sha256
        || !effect_bindings.iter().any(|binding| {
            binding.get("role").and_then(Value::as_str) == Some("cooperative_sign")
                && binding.get("leg_id").and_then(Value::as_str) == Some(context.leg_id.as_str())
        })
    {
        return Err(musig_error(
            "cooperative context is not bound by the bilateral Swap Contract",
        ));
    }
    let verifier = verifier_for_leg(contract, &context.leg_id)?;
    let declared_keys = verifier
        .get("cooperative_pubkeys")
        .and_then(Value::as_array)
        .ok_or_else(|| musig_error("contract verifier has no cooperative keys"))?;
    let expected_keys = ["requester", "provider"]
        .iter()
        .map(|role| {
            declared_keys
                .iter()
                .find(|entry| entry.get("participant_role").and_then(Value::as_str) == Some(*role))
                .and_then(|entry| entry.get("public_key"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| musig_error("contract cooperative key order is incomplete"))
        })
        .collect::<Result<Vec<_>, SwapClientError>>()?;
    if context.participant_keys != expected_keys
        || verifier.get("taproot_output_key").and_then(Value::as_str)
            != Some(context.aggregate_key.as_str())
    {
        return Err(musig_error(
            "cooperative context keys differ from the contract verifier",
        ));
    }
    let keys = cooperative_public_keys(&context.participant_keys)?;
    let merkle_root = fixed_hex::<32>(
        verifier
            .get("taproot_merkle_root")
            .and_then(Value::as_str)
            .ok_or_else(|| musig_error("contract verifier has no Taproot merkle root"))?,
        "contract Taproot merkle root",
    )?;
    let expected_tweak = crate::mkt_swp_verify::musig2_taproot_tweak(&keys, merkle_root)
        .map_err(core_musig_error)?;
    if context.tweaks
        != vec![CooperativeTweak {
            value: lower_hex(&expected_tweak.value),
            xonly: expected_tweak.xonly,
        }]
    {
        return Err(musig_error(
            "cooperative context tweak differs from the committed Taproot tree",
        ));
    }
    let document = object(package.document(), "cooperative exit package")?;
    if package.commitment_sha256()? != context.exit_package_sha256
        || document.get("order_id").and_then(Value::as_str) != Some(bound.order.id.as_str())
        || document.get("contract_sha256").and_then(Value::as_str)
            != Some(bound.contract_sha256.as_str())
    {
        return Err(musig_error(
            "cooperative exit package does not bind the accepted session",
        ));
    }
    let contract_ids = bound.contract_ids();
    let package_contract_ids = document
        .get("swap_contract_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| musig_error("cooperative exit package has no Swap Contract IDs"))?;
    if !contract_ids.iter().all(|id| {
        package_contract_ids
            .iter()
            .any(|candidate| candidate.as_str() == Some(id))
    }) {
        return Err(musig_error(
            "cooperative exit package does not bind both Swap Contract records",
        ));
    }
    let role = require_string(
        document,
        "participant_role",
        None,
        "swp_musig_transcript_invalid",
    )?;
    if expected_role.is_some_and(|expected| role != expected.as_str()) {
        return Err(musig_error(
            "cooperative actor requires the provider unilateral exit package",
        ));
    }
    let leg = require_string(document, "leg_id", None, "swp_musig_transcript_invalid")?;
    let path = package.path()?;
    let mode = package.mode()?;
    let exit_effect_role = match path {
        "claim" => "chain_claim",
        "refund" => "chain_refund",
        _ => return Err(musig_error("cooperative exit path is unsupported")),
    };
    if package.effect_id()? != effect_id(&bound.order.id, exit_effect_role, leg)?
        || !effect_bindings.iter().any(|binding| {
            binding.get("role").and_then(Value::as_str) == Some(exit_effect_role)
                && binding.get("leg_id").and_then(Value::as_str) == Some(leg)
        })
    {
        return Err(musig_error(
            "cooperative exit package has no exact unilateral effect binding",
        ));
    }
    let package_digest = package.commitment_sha256()?;
    let committed = contract
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .is_some_and(|commitments| {
            commitments.iter().any(|commitment| {
                commitment.get("participant_role").and_then(Value::as_str) == Some(role)
                    && commitment.get("leg_id").and_then(Value::as_str) == Some(leg)
                    && commitment.get("path").and_then(Value::as_str) == Some(path)
                    && commitment.get("package_mode").and_then(Value::as_str) == Some(mode)
                    && commitment.get("package_sha256").and_then(Value::as_str)
                        == Some(package_digest.as_str())
            })
        });
    if !committed {
        return Err(musig_error(
            "cooperative exit package has no exact Swap Contract commitment",
        ));
    }
    validate_cooperative_package_binding(context, package)
}

fn validate_cooperative_package_binding(
    context: &CooperativeSigningContext,
    package: &ExitPackage,
) -> Result<(), SwapClientError> {
    let document = object(package.document(), "cooperative exit package")?;
    if document.get("leg_id").and_then(Value::as_str) != Some(context.leg_id.as_str()) {
        return Err(musig_error(
            "cooperative context and unilateral exit name different legs",
        ));
    }
    let funding = object(
        document.get("funding").unwrap_or(&Value::Null),
        "cooperative exit funding",
    )?;
    let exit = object(
        document.get("exit").unwrap_or(&Value::Null),
        "cooperative exit transaction",
    )?;
    if exit
        .get("transaction_template_sha256")
        .and_then(Value::as_str)
        != Some(context.transaction_sha256.as_str())
        || exit
            .get("latest_safe_broadcast_height")
            .and_then(Value::as_str)
            != Some(context.latest_safe_height.as_str())
    {
        return Err(musig_error(
            "cooperative transaction or deadline differs from the unilateral exit package",
        ));
    }
    let raw = decode_hex(
        &context.unsigned_transaction,
        "cooperative unsigned transaction",
    )?;
    let transaction = Transaction::parse(&raw).map_err(core_musig_error)?;
    let input =
        transaction
            .inputs
            .get(usize::try_from(context.input_index).map_err(|_| {
                musig_error("cooperative signing input index exceeds platform bounds")
            })?)
            .ok_or_else(|| musig_error("cooperative signing input is absent"))?;
    let mut transaction_id = input.previous_txid;
    transaction_id.reverse();
    let prevout = context
        .prevouts
        .get(usize::try_from(context.input_index).map_err(|_| {
            musig_error("cooperative signing prevout index exceeds platform bounds")
        })?)
        .ok_or_else(|| musig_error("cooperative signing prevout is absent"))?;
    if funding.get("transaction_id").and_then(Value::as_str)
        != Some(lower_hex(&transaction_id).as_str())
        || funding.get("output_index").and_then(Value::as_u64)
            != Some(u64::from(input.previous_output))
        || funding.get("amount").and_then(Value::as_str) != Some(prevout.amount.as_str())
        || funding.get("script_pubkey").and_then(Value::as_str)
            != Some(prevout.script_pubkey.as_str())
    {
        return Err(musig_error(
            "cooperative signing input differs from the committed funding outpoint",
        ));
    }
    Ok(())
}

fn effective_cancellation(records: &[Event]) -> Result<Option<&Event>, SwapClientError> {
    let effective = records
        .iter()
        .filter(|event| {
            event.kind == MKT_CANCEL_KIND && tag_value(event, "action").ok() == Some("effective")
        })
        .collect::<Vec<_>>();
    let effective = match effective.as_slice() {
        [] => return Ok(None),
        [effective] => *effective,
        _ => {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "session has multiple effective cancellation records",
            ));
        }
    };
    let request_id = marked_reference(effective, "cancel-request").map_err(|_| {
        SwapClientError::new(
            "swp_cancel_ineffective",
            "effective cancellation lacks its exact request reference",
        )
    })?;
    let accepted_id = marked_reference(effective, "cancel-accept").map_err(|_| {
        SwapClientError::new(
            "swp_cancel_ineffective",
            "effective cancellation lacks its exact accepted-consent reference",
        )
    })?;
    if request_id == accepted_id {
        return Err(SwapClientError::new(
            "swp_cancel_ineffective",
            "effective cancellation duplicates its consent references",
        ));
    }
    let accepted = records
        .iter()
        .find(|event| event.id == accepted_id && event.kind == MKT_CANCEL_KIND)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_cancel_ineffective",
                "effective cancellation does not reference accepted consent",
            )
        })?;
    if tag_value(accepted, "action")? != "accepted" {
        return Err(SwapClientError::new(
            "swp_cancel_ineffective",
            "effective cancellation reference is not accepted consent",
        ));
    }
    require_marked_reference(accepted, "cancel-request", request_id).map_err(|_| {
        SwapClientError::new(
            "swp_cancel_ineffective",
            "accepted cancellation does not bind the effective request",
        )
    })?;
    let request = records
        .iter()
        .find(|event| event.id == request_id && event.kind == MKT_CANCEL_KIND)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_cancel_ineffective",
                "accepted cancellation does not reference its request",
            )
        })?;
    if tag_value(request, "action")? != "request"
        || accepted.pubkey == request.pubkey
        || (effective.pubkey != request.pubkey && effective.pubkey != accepted.pubkey)
    {
        return Err(SwapClientError::new(
            "swp_cancel_ineffective",
            "effective cancellation lacks exact consent from the other participant",
        ));
    }
    Ok(Some(effective))
}

fn validate_lifecycle(
    config: &SwapClientConfig,
    records: &[Event],
    external_effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    for cancel in records.iter().filter(|event| event.kind == MKT_CANCEL_KIND) {
        role_for_author(config, &cancel.pubkey)?;
        match tag_value(cancel, "action")? {
            "request" => {
                if cancel.tags.iter().any(|tag| {
                    tag.name() == Some("e")
                        && matches!(
                            tag.as_slice().get(3).map(String::as_str),
                            Some("cancel-request" | "cancel-accept")
                        )
                }) {
                    return Err(SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancellation request must not reference a prior Cancel",
                    ));
                }
            }
            "accepted" | "rejected" => {
                let request_id = marked_reference(cancel, "cancel-request").map_err(|_| {
                    SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancellation response requires exactly one request reference",
                    )
                })?;
                if cancel.tags.iter().any(|tag| {
                    tag.name() == Some("e")
                        && tag.as_slice().get(3).map(String::as_str) == Some("cancel-accept")
                }) {
                    return Err(SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancellation response must not carry accepted-consent references",
                    ));
                }
                let request = records
                    .iter()
                    .find(|event| event.kind == MKT_CANCEL_KIND && event.id == request_id)
                    .ok_or_else(|| {
                        SwapClientError::new(
                            "swp_cancel_ineffective",
                            "cancellation response does not reference an existing request",
                        )
                    })?;
                if tag_value(request, "action")? != "request" || request.pubkey == cancel.pubkey {
                    return Err(SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancellation response is not consent from the other participant",
                    ));
                }
            }
            "effective" => {
                marked_reference(cancel, "cancel-request").map_err(|_| {
                    SwapClientError::new(
                        "swp_cancel_ineffective",
                        "effective cancellation requires one request reference",
                    )
                })?;
                marked_reference(cancel, "cancel-accept").map_err(|_| {
                    SwapClientError::new(
                        "swp_cancel_ineffective",
                        "effective cancellation requires one accepted-consent reference",
                    )
                })?;
            }
            _ => {
                return Err(SwapClientError::new(
                    "swp_cancel_ineffective",
                    "cancellation action is unsupported",
                ));
            }
        }
    }
    let effective = effective_cancellation(records)?;
    if let Some(effective) = effective {
        let reverse_no_fund =
            verified_lightning_disposition_for_event(config, records, external_effects, effective)?;
        if reverse_no_fund && !has_last_valid_invoice_cancelled(config, records)? {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "Lightning no-fund cancellation lacks a contiguous invoice_cancelled Status",
            ));
        }
        if has_irreversible_external_effect(config, records, external_effects, reverse_no_fund)?
            || signed_history_has_irreversible_effect(records, reverse_no_fund)?
        {
            return Err(SwapClientError::new(
                "swp_cancel_ineffective",
                "cancellation cannot become effective after an irreversible external effect",
            ));
        }
    }
    let lifecycle_contract = records
        .iter()
        .find(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .map(parse_content)
        .transpose()?
        .and_then(|content| content.get("mkt_swp").cloned())
        .and_then(|profile| profile.get("contract").cloned());
    let status_projection = StatusProjection::from_records(config, records)?;
    for close in records.iter().filter(|event| event.kind == MKT_CLOSE_KIND) {
        let outcome = tag_value(close, "outcome")?;
        let terminal_at = tag_value(close, "terminal_at")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_unresolved_loss", "Close terminal time is invalid")
            })?;
        let content = parse_content(close)?;
        let profile = object(
            content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Close",
        )?;
        let loss = object(
            profile.get("loss_accounting").unwrap_or(&Value::Null),
            "Close loss accounting",
        )?;
        let contract = lifecycle_contract.as_ref().ok_or_else(|| {
            SwapClientError::new(
                "swp_unresolved_loss",
                "Close cannot be evaluated without the accepted contract",
            )
        })?;
        let accounting = validate_loss_accounting(
            loss,
            contract,
            outcome,
            terminal_at,
            &config.session_id,
            external_effects,
        )?;
        match outcome {
            "completed" | "refunded" => {
                status_projection.require_signer_contiguous(&close.pubkey)?;
                let status_id = profile
                    .get("status_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            "Close does not bind its signer's terminal Status",
                        )
                    })?;
                let status = records
                    .iter()
                    .find(|event| {
                        event.kind == MKT_STATUS_KIND
                            && event.id == status_id
                            && event.pubkey == close.pubkey
                    })
                    .ok_or_else(|| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            "Close status reference is not a signer-local Status",
                        )
                    })?;
                if status_state(status)? != outcome
                    || status.created_at > terminal_at
                    || status_projection.last_valid_status.get(&close.pubkey) != Some(&status.id)
                    || status_projection.invalid_claims.contains_key(&status.id)
                {
                    return Err(SwapClientError::new(
                        "swp_unresolved_loss",
                        "Close outcome overclaims its signer's Status stream",
                    ));
                }
            }
            "cancelled" => {
                let effective = effective.ok_or_else(|| {
                    SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancelled Close has no mutually consented effective cancellation",
                    )
                })?;
                if profile.get("cancel_id").and_then(Value::as_str) != Some(effective.id.as_str()) {
                    return Err(SwapClientError::new(
                        "swp_cancel_ineffective",
                        "cancelled Close does not bind the effective cancellation",
                    ));
                }
            }
            "rejected" | "expired" => {
                let effects_disposed = if outcome == "expired" {
                    verified_lightning_disposition_for_event(
                        config,
                        records,
                        external_effects,
                        close,
                    )?
                } else {
                    false
                };
                if accounting.funded != 0
                    || has_irreversible_external_effect(
                        config,
                        records,
                        external_effects,
                        effects_disposed,
                    )?
                    || signed_history_has_irreversible_effect(records, effects_disposed)?
                {
                    return Err(SwapClientError::new(
                        "swp_unresolved_loss",
                        "rejected or expired Close cannot follow funding",
                    ));
                }
            }
            "failed" | "disputed" | "unresolved" => {
                let sufficient = match outcome {
                    "failed" => accounting.has_evidence,
                    "disputed" => accounting.has_evidence || accounting.unresolved > 0,
                    "unresolved" => accounting.unresolved > 0 || accounting.has_unknown,
                    _ => false,
                };
                if !sufficient {
                    return Err(SwapClientError::new(
                        "swp_unresolved_loss",
                        "terminal Close lacks the failure, dispute, or unknown-loss basis it claims",
                    ));
                }
            }
            _ => {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "Close outcome is unsupported",
                ));
            }
        }
    }
    Ok(())
}

fn verified_lightning_disposition_for_event(
    config: &SwapClientConfig,
    records: &[Event],
    external_effects: &BTreeMap<String, ExternalEffectResult>,
    event: &Event,
) -> Result<bool, SwapClientError> {
    let content = parse_content(event)?;
    let profile = object(
        content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP terminal record",
    )?;
    let Some(value) = profile.get("lightning_disposition") else {
        return Ok(false);
    };
    let request: LightningDispositionRequest =
        serde_json::from_value(value.clone()).map_err(|error| {
            SwapClientError::new(
                "swp_external_effect_conflict",
                format!("signed Lightning disposition has an invalid shape: {error}"),
            )
        })?;
    let bound = BoundSession::from_records(config, records)?;
    validate_lightning_disposition_request(&bound, config, &request)?;
    let typed_request = ExternalEffectRequest::LightningDisposition(request.clone());
    let effect = external_effects.get(&request.effect_id).ok_or_else(|| {
        SwapClientError::new(
            "swp_external_effect_conflict",
            "signed Lightning disposition has no persisted local effect",
        )
    })?;
    if effect.order_id != request.order_id
        || effect.effect_id != request.effect_id
        || effect.request_sha256 != typed_request.sha256()?
        || effect.result_sha256 != request.evidence_reference_sha256
        || request.principal_moved
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "signed Lightning disposition differs from its persisted local observation",
        ));
    }
    Ok(true)
}

fn has_last_valid_invoice_cancelled(
    config: &SwapClientConfig,
    records: &[Event],
) -> Result<bool, SwapClientError> {
    let projection = StatusProjection::from_records(config, records)?;
    projection.require_contiguous()?;
    Ok(projection.last_valid_status.values().any(|status_id| {
        records
            .iter()
            .find(|event| event.id == *status_id)
            .and_then(|event| status_state(event).ok())
            .is_some_and(|state| state == "invoice_cancelled")
    }))
}

fn has_irreversible_external_effect(
    config: &SwapClientConfig,
    records: &[Event],
    external_effects: &BTreeMap<String, ExternalEffectResult>,
    reverse_no_fund: bool,
) -> Result<bool, SwapClientError> {
    let bound = BoundSession::from_records(config, records)?;
    let topology = requester_topology(bound.swap_type);
    let funding_effect = effect_id(
        &bound.order.id,
        topology.funding_effect_role,
        topology.funding_leg_id,
    )?;
    let disposition_effect = (bound.swap_type == SwapType::Reverse)
        .then(|| {
            effect_id(
                &bound.order.id,
                "lightning_disposition",
                topology.funding_leg_id,
            )
        })
        .transpose()?;
    let contract = object(&bound.contract, "Swap Contract")?;
    let mut observation_effects = BTreeSet::new();
    for leg in contract
        .get("legs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(leg_id) = leg.get("leg_id").and_then(Value::as_str) {
            for outcome in ["completed", "refunded"] {
                observation_effects.insert(effect_id(
                    &bound.order.id,
                    &format!("terminal_evidence_{outcome}"),
                    leg_id,
                )?);
            }
        }
    }
    for effect_id in external_effects.keys() {
        if observation_effects.contains(effect_id) || disposition_effect.as_ref() == Some(effect_id)
        {
            continue;
        }
        if effect_id == &funding_effect && bound.swap_type == SwapType::Reverse && reverse_no_fund {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

fn signed_history_has_irreversible_effect(
    records: &[Event],
    reverse_no_fund: bool,
) -> Result<bool, SwapClientError> {
    for status in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
        let state = status_state(status)?;
        if state.ends_with("funding_broadcast")
            || state.ends_with("funding_observed")
            || state.ends_with("funding_final")
            || (!reverse_no_fund
                && (state.ends_with("payment_pending") || state.ends_with("htlcs_held")))
            || state.ends_with("paid")
            || state.ends_with("claim_pending")
            || state.ends_with("claimed")
            || state.ends_with("refund_pending")
            || state.ends_with("refunded")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

struct LossAccountingTotals {
    funded: u64,
    unresolved: u64,
    has_evidence: bool,
    has_unknown: bool,
}

fn validate_loss_accounting(
    loss: &Map<String, Value>,
    contract: &Value,
    outcome: &str,
    terminal_at: u64,
    session_id: &str,
    external_effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<LossAccountingTotals, SwapClientError> {
    let contract = object(contract, "Swap Contract")?;
    let assets = contract
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|assets| assets.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_unresolved_loss",
                "Close contract has no ordered asset pair",
            )
        })?;
    if loss.get("input_asset_id") != assets.first() || loss.get("output_asset_id") != assets.get(1)
    {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close loss accounting uses different assets than the accepted contract",
        ));
    }
    let numeric_fields = [
        "input_committed",
        "input_recovered",
        "output_received",
        "provider_fee_paid",
        "miner_fee_paid",
        "lightning_routing_fee_paid",
        "guarantee_recovery_received",
        "principal_unresolved",
        "reservation_released",
    ];
    let unknown_fields = match loss.get("unknown_fields") {
        None => BTreeSet::new(),
        Some(Value::Array(fields)) => fields
            .iter()
            .map(Value::as_str)
            .collect::<Option<BTreeSet<_>>>()
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    "Close unknown_fields must contain field names",
                )
            })?,
        Some(_) => {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Close unknown_fields must be an array",
            ));
        }
    };
    if unknown_fields
        .iter()
        .any(|field| !numeric_fields.contains(field))
        || unknown_fields.contains("input_committed")
        || (matches!(
            outcome,
            "completed" | "rejected" | "cancelled" | "expired" | "refunded"
        ) && !unknown_fields.is_empty())
    {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close has unsupported or outcome-incompatible unknown fields",
        ));
    }
    let allowed = BTreeSet::from([
        "input_asset_id",
        "output_asset_id",
        "input_committed",
        "input_recovered",
        "output_received",
        "provider_fee_paid",
        "miner_fee_paid",
        "lightning_routing_fee_paid",
        "guarantee_recovery_received",
        "principal_unresolved",
        "reservation_released",
        "evidence_refs",
        "unknown_fields",
    ]);
    if loss
        .keys()
        .map(String::as_str)
        .any(|field| !allowed.contains(field))
    {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close loss accounting has unknown members",
        ));
    }
    let amount = |field: &str| -> Result<Option<u64>, SwapClientError> {
        if unknown_fields.contains(field) {
            if loss.contains_key(field) {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "unknown Close amount must be omitted rather than encoded as zero",
                ));
            }
            Ok(None)
        } else {
            require_string(loss, field, None, "swp_unresolved_loss")
                .and_then(canonical_amount)
                .map(Some)
        }
    };
    let input_committed = amount("input_committed")?.unwrap_or_default();
    let input_recovered = amount("input_recovered")?.unwrap_or_default();
    let output_received = amount("output_received")?.unwrap_or_default();
    let provider_fee = amount("provider_fee_paid")?.unwrap_or_default();
    let miner_fee = amount("miner_fee_paid")?.unwrap_or_default();
    let lightning_fee = amount("lightning_routing_fee_paid")?.unwrap_or_default();
    let guarantee = amount("guarantee_recovery_received")?.unwrap_or_default();
    let unresolved = amount("principal_unresolved")?.unwrap_or_default();
    let reservation_released = amount("reservation_released")?.unwrap_or_default();
    let reserved_amount = contract
        .get("reservation_commitment")
        .and_then(Value::as_object)
        .and_then(|commitment| commitment.get("reserved_amount"))
        .and_then(Value::as_str)
        .map(canonical_amount)
        .transpose()?
        .unwrap_or_default();
    let maximum_input = contract_amount(contract, "input_amount")?;
    let expected_output = contract_amount(contract, "output_amount")?;
    let maximum_provider_fee = contract_amount(contract, "provider_fee")?;
    let maximum_miner_fee = contract_amount(contract, "miner_fee_budget")?;
    let maximum_lightning_fee = contract_amount(contract, "lightning_routing_fee_budget")?;
    let accounted_input = input_recovered
        .checked_add(guarantee)
        .and_then(|value| value.checked_add(provider_fee))
        .and_then(|value| value.checked_add(miner_fee))
        .and_then(|value| value.checked_add(lightning_fee))
        .and_then(|value| value.checked_add(unresolved));
    let failure_balance_valid =
        if matches!(outcome, "failed" | "disputed" | "unresolved") && input_committed > 0 {
            let known_accounted = accounted_input.unwrap_or(u64::MAX);
            let unknown_fee_capacity = [
                ("provider_fee_paid", maximum_provider_fee),
                ("miner_fee_paid", maximum_miner_fee),
                ("lightning_routing_fee_paid", maximum_lightning_fee),
            ]
            .into_iter()
            .filter_map(|(field, maximum)| unknown_fields.contains(field).then_some(maximum))
            .try_fold(0_u64, u64::checked_add);
            known_accounted == input_committed
                || (known_accounted < input_committed
                    && (unknown_fields.contains("principal_unresolved")
                        || unknown_fee_capacity
                            .and_then(|capacity| known_accounted.checked_add(capacity))
                            .is_some_and(|maximum_accounted| maximum_accounted >= input_committed)))
        } else {
            true
        };
    if input_committed > maximum_input
        || provider_fee > maximum_provider_fee
        || miner_fee > maximum_miner_fee
        || lightning_fee > maximum_lightning_fee
        || accounted_input.is_none_or(|accounted| accounted > input_committed)
        || (outcome == "completed"
            && (input_committed != maximum_input
                || output_received != expected_output
                || unresolved != 0))
        || (outcome == "refunded"
            && (input_recovered
                .checked_add(guarantee)
                .is_none_or(|recovered| recovered < input_committed.saturating_sub(provider_fee))
                || unresolved != 0
                || accounted_input != Some(input_committed)))
        || !failure_balance_valid
        || (matches!(outcome, "cancelled" | "rejected" | "expired")
            && (input_committed != 0
                || input_recovered != 0
                || output_received != 0
                || provider_fee != 0
                || miner_fee != 0
                || lightning_fee != 0
                || guarantee != 0
                || unresolved != 0
                || reservation_released != reserved_amount))
    {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close loss accounting does not balance for the claimed outcome",
        ));
    }
    validate_bound_close_evidence(
        loss,
        contract,
        outcome,
        terminal_at,
        session_id,
        external_effects,
    )?;
    Ok(LossAccountingTotals {
        funded: input_committed,
        unresolved,
        has_evidence: loss
            .get("evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(|evidence| !evidence.is_empty()),
        has_unknown: !unknown_fields.is_empty(),
    })
}

pub(crate) fn validate_no_spend_loss_accounting(
    loss: &Map<String, Value>,
    reservation_released: u64,
) -> Result<(), SwapClientError> {
    let allowed = BTreeSet::from([
        "input_asset_id",
        "output_asset_id",
        "input_committed",
        "input_recovered",
        "output_received",
        "provider_fee_paid",
        "miner_fee_paid",
        "lightning_routing_fee_paid",
        "guarantee_recovery_received",
        "principal_unresolved",
        "reservation_released",
        "evidence_refs",
        "unknown_fields",
    ]);
    if loss.keys().any(|field| !allowed.contains(field.as_str()))
        || loss.get("input_asset_id").and_then(Value::as_str).is_none()
        || loss
            .get("output_asset_id")
            .and_then(Value::as_str)
            .is_none()
        || [
            "input_committed",
            "input_recovered",
            "output_received",
            "provider_fee_paid",
            "miner_fee_paid",
            "lightning_routing_fee_paid",
            "guarantee_recovery_received",
            "principal_unresolved",
        ]
        .iter()
        .any(|field| loss.get(*field).and_then(Value::as_str) != Some("0"))
        || loss
            .get("reservation_released")
            .and_then(Value::as_str)
            .map(canonical_amount)
            .transpose()?
            != Some(reservation_released)
        || loss
            .get("evidence_refs")
            .and_then(Value::as_array)
            .is_none_or(|references| !references.is_empty())
        || loss
            .get("unknown_fields")
            .and_then(Value::as_array)
            .is_none_or(|fields| !fields.is_empty())
        || loss.len() != allowed.len()
    {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "no-spend Close requires exact balanced zero loss accounting",
        ));
    }
    Ok(())
}

fn validate_bound_close_evidence(
    loss: &Map<String, Value>,
    contract: &Map<String, Value>,
    outcome: &str,
    terminal_at: u64,
    session_id: &str,
    external_effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    let legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| SwapClientError::new("swp_unresolved_loss", "contract has no legs"))?;
    let evidence = loss
        .get("evidence_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new("swp_unresolved_loss", "Close evidence_refs is not an array")
        })?;
    if matches!(outcome, "completed" | "refunded") && evidence.len() != legs.len() {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close requires one bound evidence reference per contract leg",
        ));
    }
    if !matches!(outcome, "completed" | "refunded") {
        return validate_nonterminal_close_evidence(
            evidence,
            contract,
            terminal_at,
            external_effects,
        );
    }
    let order_id = require_string(contract, "order_id", None, "swp_unresolved_loss")?;
    let payment_hash = require_string(contract, "payment_hash", None, "swp_unresolved_loss")?;
    let mut unmatched = (0..evidence.len()).collect::<BTreeSet<_>>();
    for (leg_index, leg) in legs.iter().enumerate() {
        let leg_id = leg
            .get("leg_id")
            .and_then(Value::as_str)
            .ok_or_else(|| SwapClientError::new("swp_unresolved_loss", "leg ID is missing"))?;
        let rail = leg
            .get("rail")
            .and_then(Value::as_str)
            .ok_or_else(|| SwapClientError::new("swp_unresolved_loss", "leg rail is missing"))?;
        let verifier_policy = leg
            .get("verifier_policy")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SwapClientError::new("swp_unresolved_loss", "leg verifier policy is missing")
            })?;
        let verifier = verifier_for_leg(contract, leg_id)?;
        let verifier_authority = verifier.get("evidence_authority").ok_or_else(|| {
            SwapClientError::new("swp_unresolved_loss", "leg evidence authority is missing")
        })?;
        validate_evidence_authority(verifier_authority)?;
        let verifier_authority_sha256 = lower_hex(&sha256(&canonical_json(verifier_authority)?));
        let (evidence_class, source_reference, rung) =
            terminal_evidence_identity(contract, order_id, payment_hash, leg_id, rail, outcome)?;
        let effect_id = effect_id(order_id, &format!("terminal_evidence_{outcome}"), leg_id)?;
        let mut matches = Vec::new();
        for index in [leg_index] {
            if !unmatched.contains(&index) {
                continue;
            }
            let Some(evidence_value) = evidence.get(index) else {
                continue;
            };
            if validate_mkt_swp_evidence_reference(evidence_value).is_err() {
                continue;
            }
            let Some(reference_value) = evidence_value.as_object() else {
                continue;
            };
            if reference_value.get("class").and_then(Value::as_str) != Some(evidence_class.as_str())
                || reference_value.get("rail").and_then(Value::as_str) != Some(rail)
                || reference_value.get("rung").and_then(Value::as_str) != Some(rung.as_str())
                || reference_value
                    .get("verifier_policy")
                    .and_then(Value::as_str)
                    != Some(verifier_policy)
                || !evidence_verifier_is_authorized(reference_value, verifier)
            {
                continue;
            }
            let Some(observed_at) = reference_value.get("observed_at").and_then(Value::as_u64)
            else {
                continue;
            };
            if observed_at > terminal_at {
                continue;
            }
            let Some(artifact_sha256) = reference_value
                .get("artifact_sha256")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some(view) = reference_value.get("view").and_then(Value::as_str) else {
                continue;
            };
            let Some(reference) = reference_value.get("reference").and_then(Value::as_str) else {
                continue;
            };
            let request = RailEvidenceRequest {
                effect_id: effect_id.clone(),
                session_id: session_id.to_owned(),
                order_id: order_id.to_owned(),
                leg_id: leg_id.to_owned(),
                outcome: outcome.to_owned(),
                rail: rail.to_owned(),
                evidence_class: evidence_class.clone(),
                source_reference: source_reference.clone(),
                reference: reference.to_owned(),
                artifact_sha256: artifact_sha256.to_owned(),
                rung: rung.clone(),
                verifier_policy: verifier_policy.to_owned(),
                verifier_authority_sha256: verifier_authority_sha256.clone(),
                observed_at,
                view_sha256: lower_hex(&sha256(view.as_bytes())),
                finality_state: if outcome == "completed" {
                    "settled".to_owned()
                } else {
                    "refunded_final".to_owned()
                },
                evidence_reference_sha256: lower_hex(&sha256(&canonical_json(evidence_value)?)),
            };
            let typed_request = ExternalEffectRequest::RailEvidence(request);
            let Some(effect) = external_effects.get(&effect_id) else {
                continue;
            };
            let Ok(request_sha256) = typed_request.sha256() else {
                continue;
            };
            let Ok(result_bytes) = canonical_json(evidence_value) else {
                continue;
            };
            if effect.order_id == order_id
                && effect.request_sha256 == request_sha256
                && effect.result_sha256 == lower_hex(&sha256(&result_bytes))
            {
                matches.push(index);
            }
        }
        let [matched] = matches.as_slice() else {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Close lacks one persisted locally verified terminal rail observation",
            ));
        };
        unmatched.remove(matched);
    }
    if !unmatched.is_empty() {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "Close carries evidence unrelated to the accepted contract",
        ));
    }
    Ok(())
}

fn rail_observation_request(
    bound: &BoundSession<'_>,
    leg_id: &str,
    outcome: &str,
) -> Result<RailObservationRequest, SwapClientError> {
    if !matches!(outcome, "completed" | "refunded") {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "terminal rail evidence applies only to completed or refunded outcomes",
        ));
    }
    let contract = object(&bound.contract, "Swap Contract")?;
    let legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| SwapClientError::new("swp_unresolved_loss", "contract has no legs"))?;
    let matching = legs
        .iter()
        .filter(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        .collect::<Vec<_>>();
    let [leg] = matching.as_slice() else {
        return Err(SwapClientError::new(
            "swp_unresolved_loss",
            "terminal evidence leg is absent or duplicated",
        ));
    };
    let rail = leg
        .get("rail")
        .and_then(Value::as_str)
        .ok_or_else(|| SwapClientError::new("swp_unresolved_loss", "leg rail is missing"))?;
    let verifier_policy = leg
        .get("verifier_policy")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SwapClientError::new("swp_unresolved_loss", "leg verifier policy is missing")
        })?;
    let verifier = verifier_for_leg(contract, leg_id)?;
    let authority = verifier.get("evidence_authority").ok_or_else(|| {
        SwapClientError::new("swp_unresolved_loss", "leg evidence authority is missing")
    })?;
    validate_evidence_authority(authority)?;
    let verifier_authority_sha256 = lower_hex(&sha256(&canonical_json(authority)?));
    let (evidence_class, reference, rung) = match (rail, outcome) {
        ("bitcoin", "completed") => {
            let raw = decode_hex(
                require_string(verifier, "funding_transaction", None, "swp_unresolved_loss")?,
                "evidence funding transaction",
            )?;
            let transaction = Transaction::parse(&raw).map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("evidence funding transaction is invalid: {error}"),
                )
            })?;
            let output_index = required_u32(verifier, "output_index")?;
            (
                "bitcoin_spend".to_owned(),
                format!(
                    "{}:{output_index}",
                    lower_hex(&transaction.txid().map_err(|error| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            format!("could not derive evidence funding txid: {error}"),
                        )
                    })?)
                ),
                "settled".to_owned(),
            )
        }
        ("bitcoin", "refunded") => (
            "refund".to_owned(),
            effect_id(&bound.order.id, "chain_refund", leg_id)?,
            "settled".to_owned(),
        ),
        ("lightning", "completed") => (
            "lightning_payment".to_owned(),
            bound.payment_hash.clone(),
            "settled".to_owned(),
        ),
        ("lightning", "refunded") => (
            "invoice".to_owned(),
            bound.payment_hash.clone(),
            "verified".to_owned(),
        ),
        _ => {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "terminal evidence uses an unsupported rail",
            ));
        }
    };
    Ok(RailObservationRequest {
        session_id: bound.session_id.clone(),
        order_id: bound.order.id.clone(),
        leg_id: leg_id.to_owned(),
        outcome: outcome.to_owned(),
        rail: rail.to_owned(),
        evidence_class,
        reference,
        rung,
        verifier_policy: verifier_policy.to_owned(),
        verifier_authority_sha256,
        finality_state: if outcome == "completed" {
            "settled".to_owned()
        } else {
            "refunded_final".to_owned()
        },
    })
}

fn terminal_evidence_identity(
    contract: &Map<String, Value>,
    order_id: &str,
    payment_hash: &str,
    leg_id: &str,
    rail: &str,
    outcome: &str,
) -> Result<(String, String, String), SwapClientError> {
    match (rail, outcome) {
        ("bitcoin", "completed") => {
            let verifier = verifier_for_leg(contract, leg_id)?;
            let raw = decode_hex(
                require_string(verifier, "funding_transaction", None, "swp_unresolved_loss")?,
                "evidence funding transaction",
            )?;
            let transaction = Transaction::parse(&raw).map_err(|error| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    format!("evidence funding transaction is invalid: {error}"),
                )
            })?;
            let output_index = required_u32(verifier, "output_index")?;
            Ok((
                "bitcoin_spend".to_owned(),
                format!(
                    "{}:{output_index}",
                    lower_hex(&transaction.txid().map_err(|error| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            format!("could not derive evidence funding txid: {error}"),
                        )
                    })?)
                ),
                "settled".to_owned(),
            ))
        }
        ("bitcoin", "refunded") => Ok((
            "refund".to_owned(),
            effect_id(order_id, "chain_refund", leg_id)?,
            "settled".to_owned(),
        )),
        ("lightning", "completed") => Ok((
            "lightning_payment".to_owned(),
            payment_hash.to_owned(),
            "settled".to_owned(),
        )),
        ("lightning", "refunded") => Ok((
            "invoice".to_owned(),
            payment_hash.to_owned(),
            "verified".to_owned(),
        )),
        _ => Err(SwapClientError::new(
            "swp_unresolved_loss",
            "terminal evidence uses an unsupported rail or outcome",
        )),
    }
}

fn validate_rail_evidence_request(
    bound: &BoundSession<'_>,
    request: &RailEvidenceRequest,
) -> Result<(), SwapClientError> {
    let expected = rail_observation_request(bound, &request.leg_id, &request.outcome)?;
    let expected_effect_id = effect_id(
        &bound.order.id,
        &format!("terminal_evidence_{}", request.outcome),
        &request.leg_id,
    )?;
    require_lower_hex_32(&request.artifact_sha256, "terminal artifact digest")?;
    require_lower_hex_32(&request.view_sha256, "terminal view digest")?;
    require_lower_hex_32(
        &request.evidence_reference_sha256,
        "terminal evidence reference digest",
    )?;
    if request.reference.is_empty()
        || request.reference.len() > 512
        || request.reference.chars().any(char::is_control)
        || (request.rail == "bitcoin"
            && request.evidence_class != "bitcoin_spend"
            && request.reference == request.source_reference)
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "terminal rail evidence does not identify a distinct bounded settlement artifact",
        ));
    }
    if request.effect_id != expected_effect_id
        || request.session_id != expected.session_id
        || request.order_id != expected.order_id
        || request.rail != expected.rail
        || request.evidence_class != expected.evidence_class
        || request.source_reference != expected.reference
        || request.rung != expected.rung
        || request.verifier_policy != expected.verifier_policy
        || request.verifier_authority_sha256 != expected.verifier_authority_sha256
        || request.finality_state != expected.finality_state
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "terminal rail evidence request differs from the frozen contract and rail view",
        ));
    }
    Ok(())
}

fn validate_lightning_disposition_request(
    bound: &BoundSession<'_>,
    config: &SwapClientConfig,
    request: &LightningDispositionRequest,
) -> Result<(), SwapClientError> {
    if bound.swap_type != SwapType::Reverse {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "Lightning disposition belongs to a non-reverse swap",
        ));
    }
    let topology = requester_topology(bound.swap_type);
    let expected_funding_effect = effect_id(
        &bound.order.id,
        topology.funding_effect_role,
        topology.funding_leg_id,
    )?;
    let expected_effect = effect_id(
        &bound.order.id,
        "lightning_disposition",
        topology.funding_leg_id,
    )?;
    let verifier = verifier_for_leg(
        object(&bound.contract, "Swap Contract")?,
        topology.funding_leg_id,
    )?;
    for (value, label) in [
        (&request.invoice_sha256, "Lightning disposition invoice"),
        (&request.payment_hash, "Lightning disposition payment hash"),
        (&request.view_sha256, "Lightning disposition view"),
        (
            &request.evidence_reference_sha256,
            "Lightning disposition evidence",
        ),
    ] {
        require_lower_hex_32(value, label)?;
    }
    if request.effect_id != expected_effect
        || request.session_id != config.session_id
        || request.order_id != bound.order.id
        || request.funding_effect_id != expected_funding_effect
        || request.leg_id != topology.funding_leg_id
        || request.payment_hash != bound.payment_hash
        || verifier.get("invoice_sha256").and_then(Value::as_str)
            != Some(request.invoice_sha256.as_str())
        || request.principal_moved
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "Lightning disposition differs from the frozen reverse payment",
        ));
    }
    Ok(())
}

fn validate_nonterminal_close_evidence(
    evidence: &[Value],
    contract: &Map<String, Value>,
    terminal_at: u64,
    external_effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    for reference in evidence {
        validate_mkt_swp_evidence_reference(reference).map_err(|error| {
            SwapClientError::new(
                "swp_unresolved_loss",
                format!("Close evidence reference is invalid: {error}"),
            )
        })?;
        let reference = object(reference, "Close evidence reference")?;
        if reference.get("observed_at").and_then(Value::as_u64) > Some(terminal_at) {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Close evidence was observed after the terminal time",
            ));
        }
        let rail = reference.get("rail").and_then(Value::as_str);
        let policy = reference.get("verifier_policy").and_then(Value::as_str);
        let artifact_sha256 = reference.get("artifact_sha256").and_then(Value::as_str);
        let matching = contract
            .get("legs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|leg| {
                leg.get("rail").and_then(Value::as_str) == rail
                    && leg.get("verifier_policy").and_then(Value::as_str) == policy
            })
            .filter_map(|leg| {
                let leg_id = leg.get("leg_id")?.as_str()?;
                let verifier = verifier_for_leg(contract, leg_id).ok()?;
                let artifact_bound = ["funding_transaction_sha256", "invoice_sha256"]
                    .iter()
                    .any(|member| verifier.get(*member).and_then(Value::as_str) == artifact_sha256)
                    || external_effects
                        .values()
                        .any(|effect| Some(effect.result_sha256.as_str()) == artifact_sha256);
                (artifact_bound && evidence_verifier_is_authorized(reference, verifier))
                    .then_some(leg_id)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "Close evidence does not bind one exact contract artifact and verifier authority",
            ));
        }
    }
    Ok(())
}

fn evidence_verifier_is_authorized(
    evidence: &Map<String, Value>,
    verifier: &Map<String, Value>,
) -> bool {
    let Some(authority) = verifier
        .get("evidence_authority")
        .and_then(Value::as_object)
    else {
        return false;
    };
    match authority.get("mode").and_then(Value::as_str) {
        Some("local") => {
            authority
                .get("adapter_sha256")
                .and_then(Value::as_str)
                .is_some_and(|digest| {
                    require_lower_hex_32(digest, "local evidence adapter").is_ok()
                })
                && matches!(evidence.get("verifier_pubkey"), Some(Value::Null))
        }
        Some("external") => evidence
            .get("verifier_pubkey")
            .and_then(Value::as_str)
            .is_some_and(|pubkey| {
                authority
                    .get("pubkeys")
                    .and_then(Value::as_array)
                    .is_some_and(|pubkeys| {
                        pubkeys
                            .iter()
                            .any(|candidate| candidate.as_str() == Some(pubkey))
                    })
            }),
        _ => false,
    }
}

fn validate_evidence_authority(authority: &Value) -> Result<(), SwapClientError> {
    let authority = object(authority, "evidence authority")?;
    match authority.get("mode").and_then(Value::as_str) {
        Some("local") => {
            require_lower_hex_32(
                require_string(authority, "adapter_sha256", None, "swp_unresolved_loss")?,
                "local evidence adapter digest",
            )?;
            if !matches!(authority.get("pubkeys"), Some(Value::Array(pubkeys)) if pubkeys.is_empty())
            {
                return Err(SwapClientError::new(
                    "swp_unresolved_loss",
                    "local evidence authority must not delegate verifier keys",
                ));
            }
        }
        Some("external") => {
            let pubkeys = authority
                .get("pubkeys")
                .and_then(Value::as_array)
                .filter(|pubkeys| !pubkeys.is_empty())
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_unresolved_loss",
                        "external evidence authority requires verifier keys",
                    )
                })?;
            for pubkey in pubkeys {
                require_lower_hex_32(
                    pubkey.as_str().ok_or_else(|| {
                        SwapClientError::new(
                            "swp_unresolved_loss",
                            "external evidence verifier key is not a string",
                        )
                    })?,
                    "external evidence verifier key",
                )?;
            }
        }
        _ => {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "evidence authority mode is unsupported",
            ));
        }
    }
    Ok(())
}

fn verifier_for_leg<'a>(
    contract: &'a Map<String, Value>,
    leg_id: &str,
) -> Result<&'a Map<String, Value>, SwapClientError> {
    let verifiers = contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract has no verifier inputs",
            )
        })?;
    let matches = verifiers
        .iter()
        .filter(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        .collect::<Vec<_>>();
    let [verifier] = matches.as_slice() else {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Swap Contract requires exactly one verifier for the flow leg",
        ));
    };
    verifier.as_object().ok_or_else(|| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Swap Contract verifier input is not an object",
        )
    })
}

fn verify_bitcoin_observation(
    verifier: &Map<String, Value>,
    request: &BitcoinObservationRequest,
    observation: &LocalBitcoinObservation,
) -> Result<VerifiedBitcoinFunding, SwapClientError> {
    let raw = decode_hex(&observation.raw_transaction, "observed funding transaction")?;
    if lower_hex(&sha256(&raw)) != request.transaction_template_sha256 {
        return Err(SwapClientError::new(
            "swp_terms_mismatch",
            "local Bitcoin observation differs from the bound funding template",
        ));
    }
    let transaction = Transaction::parse(&raw).map_err(|error| {
        SwapClientError::new(
            "swp_script_invalid",
            format!("observed funding transaction is invalid: {error}"),
        )
    })?;
    let output = transaction
        .outputs
        .get(usize::try_from(request.output_index).map_err(|_| {
            SwapClientError::new(
                "swp_terms_mismatch",
                "observed output index is out of range",
            )
        })?)
        .ok_or_else(|| {
            SwapClientError::new("swp_terms_mismatch", "observed funding output is missing")
        })?;
    if output.value_sat != canonical_amount(&request.amount)?
        || output.script_pubkey != decode_hex(&request.script_pubkey, "observed scriptPubKey")?
    {
        return Err(SwapClientError::new(
            "swp_terms_mismatch",
            "observed funding amount or script differs from the bound template",
        ));
    }
    let minimum_confirmations = require_string(
        verifier,
        "minimum_confirmations",
        None,
        "swp_contract_terms_mismatch",
    )?
    .parse::<u32>()
    .map_err(|_| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            "bound confirmation threshold is invalid",
        )
    })?;
    if observation.confirmations < minimum_confirmations {
        return Err(SwapClientError::new(
            "swp_confirmation_insufficient",
            "local Bitcoin adapter reports insufficient confirmations",
        ));
    }
    let replacement_policy = require_string(
        verifier,
        "replacement_policy",
        None,
        "swp_contract_terms_mismatch",
    )?;
    if observation.replacement_detected && replacement_policy == "reject" {
        return Err(SwapClientError::new(
            "swp_rbf_policy_violation",
            "local Bitcoin adapter reports a forbidden replacement",
        ));
    }
    if observation.competing_spend_detected {
        return Err(SwapClientError::new(
            "swp_funding_reorged",
            "local Bitcoin adapter reports a competing spend",
        ));
    }
    Ok(VerifiedBitcoinFunding {
        leg_id: request.leg_id.clone(),
        transaction_id: lower_hex(&transaction.txid().map_err(|error| {
            SwapClientError::new(
                "swp_script_invalid",
                format!("could not derive funding transaction ID: {error}"),
            )
        })?),
        confirmations: observation.confirmations,
    })
}

fn verify_funding_input(
    input: &VerifyBeforeFundInput,
    bound: &BoundSession<'_>,
) -> Result<(), SwapClientError> {
    let raw = decode_hex(&input.funding.raw_transaction, "funding transaction")?;
    let transaction = Transaction::parse(&raw).map_err(|error| {
        SwapClientError::new(
            "swp_script_invalid",
            format!("funding transaction is invalid: {error}"),
        )
    })?;
    let output = transaction
        .outputs
        .get(usize::try_from(input.funding.output_index).map_err(|_| {
            SwapClientError::new("swp_terms_mismatch", "funding output index is out of range")
        })?)
        .ok_or_else(|| {
            SwapClientError::new("swp_terms_mismatch", "funding output does not exist")
        })?;
    let amount = canonical_amount(&input.funding.expected_amount)?;
    if output.value_sat != amount
        || output.script_pubkey
            != decode_hex(
                &input.funding.expected_script_pubkey,
                "expected scriptPubKey",
            )?
    {
        return Err(SwapClientError::new(
            "swp_terms_mismatch",
            "funding output amount or scriptPubKey differs from local terms",
        ));
    }
    let output_key = XOnlyPublicKey::from_byte_array(decode_hex_32(
        &input.funding.taproot_output_key,
        "Taproot output key",
    )?)
    .map_err(|_| SwapClientError::new("swp_script_invalid", "Taproot output key is invalid"))?;
    let script = decode_hex(&input.funding.taproot_script, "Taproot script")?;
    parse_swap_script(&script).map_err(|error| {
        SwapClientError::new(
            "swp_script_invalid",
            format!("swap script is invalid: {error}"),
        )
    })?;
    verify_control_block(
        &output_key,
        &script,
        &decode_hex(
            &input.funding.taproot_control_block,
            "Taproot control block",
        )?,
    )
    .map_err(|error| {
        SwapClientError::new(
            "swp_script_commitment_mismatch",
            format!("Taproot commitment is invalid: {error}"),
        )
    })?;
    let expected_script = [vec![0x51, 0x20], output_key.serialize().to_vec()].concat();
    if output.script_pubkey != expected_script {
        return Err(SwapClientError::new(
            "swp_script_commitment_mismatch",
            "funding output does not pay the re-derived Taproot key",
        ));
    }
    if input.minimum_confirmations == 0 {
        return Err(SwapClientError::new(
            "swp_confirmation_insufficient",
            "quoted confirmation threshold must be positive",
        ));
    }
    if !matches!(input.replacement_policy.as_str(), "reject" | "track") {
        return Err(SwapClientError::new(
            "swp_terms_mismatch",
            "replacement policy is unknown",
        ));
    }
    let contract = object(&bound.contract, "Swap Contract")?;
    let topology = requester_topology(bound.swap_type);
    let verifier = verifier_for_leg(contract, topology.bitcoin_verifier_leg_id)?;
    let checks = [
        ("funding_transaction_sha256", lower_hex(&sha256(&raw))),
        ("amount", input.funding.expected_amount.clone()),
        (
            "script_pubkey",
            input.funding.expected_script_pubkey.clone(),
        ),
        (
            "taproot_output_key",
            input.funding.taproot_output_key.clone(),
        ),
        ("taproot_script", input.funding.taproot_script.clone()),
        (
            "taproot_control_block",
            input.funding.taproot_control_block.clone(),
        ),
        (
            "minimum_confirmations",
            input.minimum_confirmations.to_string(),
        ),
        ("replacement_policy", input.replacement_policy.clone()),
    ];
    for (name, expected) in checks {
        if verifier.get(name).and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("local verifier input {name} differs from the Swap Contract"),
            ));
        }
    }
    if verifier.get("output_index").and_then(Value::as_u64)
        != Some(u64::from(input.funding.output_index))
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "funding output index differs from the Swap Contract",
        ));
    }
    Ok(())
}

fn verify_invoice_input(
    input: &VerifyBeforeFundInput,
    bound: &BoundSession<'_>,
) -> Result<(), SwapClientError> {
    if !matches!(bound.swap_type, SwapType::Submarine | SwapType::Reverse) {
        if input.invoice.is_some() {
            return Err(SwapClientError::new(
                "swp_invoice_invalid",
                "chain swap unexpectedly carries a Lightning invoice",
            ));
        }
        return Ok(());
    }
    let invoice_input = input.invoice.as_ref().ok_or_else(|| {
        SwapClientError::new("swp_invoice_invalid", "Lightning swap requires an invoice")
    })?;
    let invoice = parse_bolt11(&invoice_input.invoice).map_err(|error| {
        SwapClientError::new("swp_invoice_invalid", format!("BOLT11 is invalid: {error}"))
    })?;
    let amount_msat = invoice.amount_msat.ok_or_else(|| {
        SwapClientError::new("swp_invoice_invalid", "amountless invoice is invalid in v1")
    })?;
    if amount_msat != canonical_amount(&invoice_input.expected_amount_msat)?
        || lower_hex(&invoice.payment_hash) != bound.payment_hash
        || network_name(invoice.network) != invoice_input.expected_network
    {
        return Err(SwapClientError::new(
            "swp_invoice_invalid",
            "invoice network, amount, or payment hash differs from the Swap Contract",
        ));
    }
    let expires_at = invoice
        .timestamp
        .checked_add(invoice.expiry_seconds)
        .ok_or_else(|| SwapClientError::new("swp_invoice_invalid", "invoice expiry overflows"))?;
    if invoice_input.observed_at >= expires_at
        || invoice.minimum_final_cltv_delta < invoice_input.required_minimum_final_cltv_delta
    {
        return Err(SwapClientError::new(
            "swp_invoice_invalid",
            "invoice is expired or its final CLTV delta is below the quoted minimum",
        ));
    }
    let contract = object(&bound.contract, "Swap Contract")?;
    let invoice_leg = requester_topology(bound.swap_type)
        .invoice_verifier_leg_id
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                "selected flow has no invoice verifier leg",
            )
        })?;
    let verifier = verifier_for_leg(contract, invoice_leg)?;
    if verifier.get("invoice_sha256").and_then(Value::as_str)
        != Some(lower_hex(&sha256(invoice_input.invoice.as_bytes())).as_str())
        || verifier.get("invoice_amount_msat").and_then(Value::as_str)
            != Some(invoice_input.expected_amount_msat.as_str())
        || verifier.get("invoice_network").and_then(Value::as_str)
            != Some(invoice_input.expected_network.as_str())
        || verifier
            .get("invoice_expiry_seconds")
            .and_then(Value::as_str)
            != Some(invoice.expiry_seconds.to_string().as_str())
        || verifier
            .get("invoice_minimum_final_cltv_delta")
            .and_then(Value::as_str)
            != Some(
                invoice_input
                    .required_minimum_final_cltv_delta
                    .to_string()
                    .as_str(),
            )
    {
        return Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "invoice verifier input differs from the Swap Contract",
        ));
    }
    Ok(())
}

fn lightning_readiness_request(
    input: &VerifyBeforeFundInput,
    bound: &BoundSession<'_>,
) -> Result<LightningReadinessRequest, SwapClientError> {
    let invoice_input = input.invoice.as_ref().ok_or_else(|| {
        SwapClientError::new(
            "swp_invoice_invalid",
            "reverse swap has no Lightning invoice",
        )
    })?;
    let invoice = parse_bolt11(&invoice_input.invoice).map_err(|error| {
        SwapClientError::new("swp_invoice_invalid", format!("BOLT11 is invalid: {error}"))
    })?;
    let invoice_expires_at = invoice
        .timestamp
        .checked_add(invoice.expiry_seconds)
        .ok_or_else(|| SwapClientError::new("swp_invoice_invalid", "invoice expiry overflows"))?;
    let contract = object(&bound.contract, "Swap Contract")?;
    let maximum_routing_fee = require_string(
        contract,
        "lightning_routing_fee_budget",
        None,
        "swp_contract_terms_mismatch",
    )?
    .to_owned();
    canonical_amount(&maximum_routing_fee)?;
    let (hold_expiry_height, hold_invoice_required) = match &input.timeout_ladder {
        TimeoutLadder::Reverse {
            hold_expiry_height, ..
        } => (*hold_expiry_height, true),
        _ => {
            return Err(SwapClientError::new(
                "swp_timeout_ladder_unsafe",
                "Lightning readiness requires the reverse timeout ladder",
            ));
        }
    };
    let topology = requester_topology(bound.swap_type);
    Ok(LightningReadinessRequest {
        order_id: bound.order.id.clone(),
        leg_id: topology.funding_leg_id.to_owned(),
        invoice_sha256: lower_hex(&sha256(invoice_input.invoice.as_bytes())),
        payment_hash: bound.payment_hash.clone(),
        amount_msat: invoice_input.expected_amount_msat.clone(),
        network: invoice_input.expected_network.clone(),
        invoice_expires_at,
        minimum_final_cltv_delta: invoice_input.required_minimum_final_cltv_delta,
        maximum_routing_fee,
        hold_invoice_required,
        hold_expiry_height,
    })
}

fn validate_lightning_readiness(
    request: &LightningReadinessRequest,
    readiness: &LocalLightningReadiness,
    local_observed_at: u64,
) -> Result<(), SwapClientError> {
    if readiness.invoice_sha256 != request.invoice_sha256
        || readiness.payment_hash != request.payment_hash
        || readiness.observed_at < local_observed_at
        || readiness.observed_at >= request.invoice_expires_at
        || readiness.state != LightningReadinessState::Acceptable
    {
        return Err(SwapClientError::new(
            "swp_funding_not_authorized",
            "local Lightning readiness does not bind the verified invoice and timing",
        ));
    }
    Ok(())
}

fn verify_exit_packages(
    packages: &[ExitPackage],
    bound: &BoundSession<'_>,
) -> Result<(), SwapClientError> {
    if packages.is_empty() {
        return Err(SwapClientError::new(
            "swp_exit_package_missing",
            "no exit package was persisted before funding",
        ));
    }
    let contract = object(&bound.contract, "Swap Contract")?;
    let commitments = contract
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_missing",
                "Swap Contract has no exit package commitments",
            )
        })?;
    let effect_bindings = contract
        .get("effect_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "Swap Contract has no external-effect bindings",
            )
        })?;
    let contract_ids = bound.contract_ids();
    let mut matched_commitments = BTreeSet::new();
    for package in packages {
        let document = object(package.document(), "exit package")?;
        if document.get("order_id").and_then(Value::as_str) != Some(bound.order.id.as_str())
            || document.get("contract_sha256").and_then(Value::as_str)
                != Some(bound.contract_sha256.as_str())
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package does not bind the accepted session",
            ));
        }
        let ids = document
            .get("swap_contract_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_exit_package_mismatch",
                    "exit package has no Swap Contract IDs",
                )
            })?;
        if !contract_ids
            .iter()
            .all(|id| ids.iter().any(|value| value.as_str() == Some(id)))
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package does not bind both Swap Contract records",
            ));
        }
        let digest = package.commitment_sha256()?;
        let role = require_string(
            document,
            "participant_role",
            None,
            "swp_exit_package_mismatch",
        )?;
        let leg = require_string(document, "leg_id", None, "swp_exit_package_mismatch")?;
        let path = package.path()?;
        let mode = package.mode()?;
        let expected_exit = requester_topology(bound.swap_type)
            .exits
            .iter()
            .find(|exit| exit.leg_id == leg && exit.path == path)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_exit_package_mismatch",
                    "exit package is not part of the requester flow topology",
                )
            })?;
        let leaf = parse_exit_leaf(package)?;
        let condition = match leaf.condition {
            ExitLeafCondition::Hashlock(_) => "hashlock",
            ExitLeafCondition::Cltv(_) => "cltv",
            ExitLeafCondition::Csv(_) => "csv",
        };
        if condition != expected_exit.condition {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit leaf condition differs from the selected flow topology",
            ));
        }
        let verifier = verifier_for_leg(contract, leg)?;
        let contract_leg = contract
            .get("legs")
            .and_then(Value::as_array)
            .and_then(|legs| {
                legs.iter()
                    .find(|candidate| candidate.get("leg_id").and_then(Value::as_str) == Some(leg))
            })
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_exit_package_mismatch",
                    "exit package has no exact contract leg",
                )
            })?;
        if document.get("network_id") != contract_leg.get("network_id")
            || document.get("asset_id") != contract_leg.get("asset_id")
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package network or asset differs from its contract leg",
            ));
        }
        let funding = object(
            document.get("funding").unwrap_or(&Value::Null),
            "exit funding",
        )?;
        let verification = object(
            document.get("verification").unwrap_or(&Value::Null),
            "exit verification",
        )?;
        for (package_member, verifier_member) in [
            ("transaction_template_sha256", "funding_transaction_sha256"),
            ("amount", "amount"),
            ("script_pubkey", "script_pubkey"),
        ] {
            if funding.get(package_member) != verifier.get(verifier_member) {
                return Err(SwapClientError::new(
                    "swp_exit_package_mismatch",
                    format!("exit funding member {package_member} differs from its leg verifier"),
                ));
            }
        }
        if funding.get("output_index") != verifier.get("output_index") {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit funding output index differs from its leg verifier",
            ));
        }
        let confirmation_policy = contract_leg.get("confirmation_policy").ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "Bitcoin contract leg has no confirmation policy",
            )
        })?;
        let confirmation_policy_sha256 = lower_hex(&sha256(&canonical_json(confirmation_policy)?));
        if funding
            .get("confirmation_policy_sha256")
            .and_then(Value::as_str)
            != Some(confirmation_policy_sha256.as_str())
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit funding confirmation-policy digest differs from the contract leg",
            ));
        }
        verify_exit_broadcast_policy(document, contract, &leaf)?;
        for member in ["taproot_script", "taproot_control_block"] {
            if verification.get(member) != verifier.get(member) {
                return Err(SwapClientError::new(
                    "swp_exit_package_mismatch",
                    format!("exit verification member {member} differs from its leg verifier"),
                ));
            }
        }
        if verification.get("quote_id").and_then(Value::as_str) != Some(bound.quote.id.as_str()) {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit verification does not bind the accepted Quote",
            ));
        }
        let verifier_digest =
            lower_hex(&sha256(&canonical_json(&Value::Object(verifier.clone()))?));
        if verification.get("verifier_digest").and_then(Value::as_str)
            != Some(verifier_digest.as_str())
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit verifier digest does not bind the complete leg verifier",
            ));
        }
        let (script, control_block, swap_tree_sha256) =
            verify_declared_swap_tree(verification, verifier, &bound.payment_hash, path, &leaf)?;
        if verification.get("swap_tree_sha256").and_then(Value::as_str)
            != Some(swap_tree_sha256.as_str())
            || verifier.get("swap_tree_sha256").and_then(Value::as_str)
                != Some(swap_tree_sha256.as_str())
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit swap tree digest differs from the declared Taproot tree",
            ));
        }
        if verifier.get("exit_signing_pubkey").and_then(Value::as_str)
            != Some(lower_hex(&leaf.signing_key.serialize()).as_str())
            || verifier.get("exit_path").and_then(Value::as_str) != Some(path)
            || verifier.get("exit_condition").and_then(Value::as_str) != Some(condition)
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit leaf key, path, or condition differs from the Quote",
            ));
        }
        let lock_value = match leaf.condition {
            ExitLeafCondition::Hashlock(_) => Value::Null,
            ExitLeafCondition::Cltv(lock) | ExitLeafCondition::Csv(lock) => {
                Value::String(lock.to_string())
            }
        };
        if verifier.get("exit_lock_value").unwrap_or(&Value::Null) != &lock_value {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit leaf lock value differs from the Quote",
            ));
        }
        let output_key = XOnlyPublicKey::from_byte_array(
            funding
                .get("script_pubkey")
                .and_then(Value::as_str)
                .and_then(|script_pubkey| script_pubkey.strip_prefix("5120"))
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_exit_package_mismatch",
                        "exit funding script is not a v1 Taproot output",
                    )
                })?
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .ok()
                        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                })
                .collect::<Option<Vec<_>>>()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_exit_package_mismatch",
                        "exit funding Taproot key is malformed",
                    )
                })?,
        )
        .map_err(|_| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit funding Taproot key is invalid",
            )
        })?;
        verify_control_block(&output_key, &script, &control_block).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                format!("declared Taproot tree does not derive the funding output: {error}"),
            )
        })?;
        let package_payment_hash = object(
            document.get("secret_commitments").unwrap_or(&Value::Null),
            "exit secret commitments",
        )?
        .get("payment_hash")
        .and_then(Value::as_str);
        if package_payment_hash != Some(bound.payment_hash.as_str()) {
            return Err(SwapClientError::new(
                "swp_payment_hash_mismatch",
                "exit package payment hash differs from the Swap Contract",
            ));
        }
        let effect_role = match path {
            "claim" => "chain_claim",
            "refund" => "chain_refund",
            _ => {
                return Err(SwapClientError::new(
                    "swp_exit_package_mismatch",
                    "exit package path has no external-effect role",
                ));
            }
        };
        let expected_effect_id = effect_id(&bound.order.id, effect_role, leg)?;
        if package.effect_id()? != expected_effect_id {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package effect ID is not derived from its Order, role, and leg",
            ));
        }
        if !effect_bindings.iter().any(|binding| {
            binding.as_object().is_some_and(|binding| {
                binding.get("role").and_then(Value::as_str) == Some(effect_role)
                    && binding.get("leg_id").and_then(Value::as_str) == Some(leg)
            })
        }) {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package has no exact external-effect binding",
            ));
        }
        let admitted = commitments
            .iter()
            .enumerate()
            .find_map(|(index, commitment)| {
                commitment.as_object().and_then(|commitment| {
                    (commitment.get("participant_role").and_then(Value::as_str) == Some(role)
                        && commitment.get("leg_id").and_then(Value::as_str) == Some(leg)
                        && commitment.get("path").and_then(Value::as_str) == Some(path)
                        && commitment.get("package_mode").and_then(Value::as_str) == Some(mode)
                        && commitment.get("package_sha256").and_then(Value::as_str)
                            == Some(digest.as_str()))
                    .then_some(index)
                })
            });
        let Some(commitment_index) = admitted else {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "exit package has no exact Swap Contract commitment",
            ));
        };
        if !matched_commitments.insert(commitment_index) {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "multiple exit packages satisfy one Swap Contract commitment",
            ));
        }
    }
    let required_requester_commitments = commitments
        .iter()
        .enumerate()
        .filter(|(_, commitment)| {
            commitment.get("participant_role").and_then(Value::as_str) == Some("requester")
        })
        .map(|(index, _)| index)
        .collect::<BTreeSet<_>>();
    if matched_commitments != required_requester_commitments {
        return Err(SwapClientError::new(
            "swp_exit_package_missing",
            "not every requester exit commitment has a persisted package",
        ));
    }
    Ok(())
}

fn validate_funding_template(
    package: &ExitPackage,
    presigned: bool,
) -> Result<(), SwapClientError> {
    let root = object(package.document(), "exit package")?;
    let funding = object(root.get("funding").unwrap_or(&Value::Null), "exit funding")?;
    let transaction_id = package.funding_transaction_id()?;
    let declared_transaction_id = funding.get("transaction_id").and_then(Value::as_str);
    let transaction_template = match funding.get("transaction_template") {
        Some(Value::String(transaction_template)) => Some(transaction_template.as_str()),
        None | Some(Value::Null) => None,
        _ => {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "funding transaction template has an invalid shape",
            ));
        }
    };
    if transaction_template.is_none() {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "every exit package requires the complete committed funding transaction",
        ));
    }
    if presigned && declared_transaction_id.is_none() {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "pre-signed exit requires a complete, derivable funding outpoint",
        ));
    }
    let transaction_template = transaction_template.ok_or_else(|| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "exit package funding transaction is unavailable",
        )
    })?;
    let raw = decode_hex(transaction_template, "funding transaction template")?;
    if lower_hex(&sha256(&raw))
        != require_string(
            funding,
            "transaction_template_sha256",
            None,
            "swp_exit_package_unusable",
        )?
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "funding transaction bytes differ from their template digest",
        ));
    }
    let transaction = Transaction::parse(&raw).map_err(|error| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            format!("funding transaction template is invalid: {error}"),
        )
    })?;
    let derived_transaction_id = lower_hex(&transaction.txid().map_err(|error| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            format!("could not derive funding transaction ID: {error}"),
        )
    })?);
    if declared_transaction_id
        .is_some_and(|transaction_id| transaction_id != derived_transaction_id)
        || transaction_id.as_deref() != Some(derived_transaction_id.as_str())
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "funding transaction ID is not derived from the committed transaction bytes",
        ));
    }
    let output_index = required_u32(funding, "output_index")?;
    let output = transaction
        .outputs
        .get(usize::try_from(output_index).map_err(|_| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "funding output index is out of range",
            )
        })?)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "funding transaction does not contain the committed output",
            )
        })?;
    if output.value_sat
        != canonical_amount(require_string(
            funding,
            "amount",
            None,
            "swp_exit_package_unusable",
        )?)?
        || output.script_pubkey
            != decode_hex(
                require_string(funding, "script_pubkey", None, "swp_exit_package_unusable")?,
                "funding scriptPubKey",
            )?
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "funding transaction output differs from the package amount or script",
        ));
    }
    Ok(())
}

fn verify_exit_broadcast_policy(
    document: &Map<String, Value>,
    contract: &Map<String, Value>,
    leaf: &ParsedExitLeaf,
) -> Result<(), SwapClientError> {
    let exit = object(
        document.get("exit").unwrap_or(&Value::Null),
        "exit transaction",
    )?;
    let recovery = object(
        contract.get("recovery").unwrap_or(&Value::Null),
        "Swap Contract recovery",
    )?;
    let policy = object(
        recovery.get("exit_policy").unwrap_or(&Value::Null),
        "Swap Contract exit policy",
    )?;
    let earliest = canonical_amount(require_string(
        exit,
        "earliest_broadcast_height",
        None,
        "swp_exit_package_mismatch",
    )?)?;
    let latest = canonical_amount(require_string(
        exit,
        "latest_safe_broadcast_height",
        None,
        "swp_exit_package_mismatch",
    )?)?;
    if exit.get("earliest_broadcast_height") != policy.get("earliest_broadcast_height")
        || exit.get("latest_safe_broadcast_height") != policy.get("latest_safe_broadcast_height")
        || latest < earliest
        || matches!(leaf.condition, ExitLeafCondition::Cltv(lock) if earliest < u64::from(lock))
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "exit broadcast window is outside the quoted recovery bounds",
        ));
    }
    let fee = object(
        exit.get("fee_policy").unwrap_or(&Value::Null),
        "exit fee policy",
    )?;
    for member in ["target_blocks", "maximum_fee", "bump_mode"] {
        if fee.get(member) != policy.get(member) {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                format!("exit fee-policy member {member} differs from the Quote"),
            ));
        }
    }
    canonical_amount(require_string(
        fee,
        "maximum_fee",
        None,
        "swp_exit_package_mismatch",
    )?)?;
    Ok(())
}

fn verify_declared_swap_tree(
    verification: &Map<String, Value>,
    verifier: &Map<String, Value>,
    payment_hash: &str,
    selected_path: &str,
    selected_leaf: &ParsedExitLeaf,
) -> Result<(Vec<u8>, Vec<u8>, String), SwapClientError> {
    let cooperative_internal_key = cooperative_internal_key(verifier)?;
    let tree = verification
        .get("taproot_tree")
        .and_then(Value::as_array)
        .filter(|tree| tree.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "v1 exit verification requires the complete claim and refund tree",
            )
        })?;
    if verifier.get("taproot_tree") != Some(&Value::Array(tree.clone())) {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "exit package tree differs from the complete quoted tree",
        ));
    }
    let swap_tree_sha256 = lower_hex(&sha256(&canonical_json(&Value::Array(tree.clone()))?));
    let mut parsed = Vec::with_capacity(2);
    for declared in tree {
        let declared = object(declared, "declared Taproot leaf")?;
        let path = require_string(declared, "path", None, "swp_exit_package_mismatch")?;
        let role = require_string(
            declared,
            "participant_role",
            None,
            "swp_exit_package_mismatch",
        )?;
        if !matches!(role, "requester" | "provider") {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "declared Taproot leaf has an unknown participant role",
            ));
        }
        let script = decode_hex(
            require_string(declared, "script", None, "swp_exit_package_mismatch")?,
            "declared Taproot leaf",
        )?;
        let leaf = parse_exit_leaf_script(&script)?;
        let (condition, lock_value) = match leaf.condition {
            ExitLeafCondition::Hashlock(hash) => {
                if path != "claim" || lower_hex(&hash) != payment_hash {
                    return Err(SwapClientError::new(
                        "swp_exit_package_mismatch",
                        "declared claim leaf does not bind the contract payment hash",
                    ));
                }
                ("hashlock", Value::Null)
            }
            ExitLeafCondition::Cltv(lock) => {
                if path != "refund" {
                    return Err(SwapClientError::new(
                        "swp_exit_package_mismatch",
                        "declared CLTV leaf is not the refund path",
                    ));
                }
                ("cltv", Value::String(lock.to_string()))
            }
            ExitLeafCondition::Csv(lock) => {
                if path != "refund" {
                    return Err(SwapClientError::new(
                        "swp_exit_package_mismatch",
                        "declared CSV leaf is not the refund path",
                    ));
                }
                ("csv", Value::String(lock.to_string()))
            }
        };
        if declared.get("condition").and_then(Value::as_str) != Some(condition)
            || declared.get("signing_pubkey").and_then(Value::as_str)
                != Some(lower_hex(&leaf.signing_key.serialize()).as_str())
            || declared.get("lock_value").unwrap_or(&Value::Null) != &lock_value
        {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "declared Taproot leaf metadata differs from its executable script",
            ));
        }
        let hash = tapleaf_hash(0xc0, &script).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                format!("declared Taproot leaf is invalid: {error}"),
            )
        })?;
        parsed.push((path, role, script, leaf, hash));
    }
    if parsed.iter().filter(|leaf| leaf.0 == "claim").count() != 1
        || parsed.iter().filter(|leaf| leaf.0 == "refund").count() != 1
        || parsed.iter().filter(|leaf| leaf.1 == "requester").count() != 1
        || parsed.iter().filter(|leaf| leaf.1 == "provider").count() != 1
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "declared Taproot tree does not contain complementary unilateral paths",
        ));
    }
    let selected_index = parsed
        .iter()
        .position(|leaf| leaf.0 == selected_path && leaf.1 == "requester")
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "requester exit path is absent from the complete declared tree",
            )
        })?;
    let selected = &parsed[selected_index];
    if selected.3.signing_key != selected_leaf.signing_key
        || selected.3.condition != selected_leaf.condition
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "selected exit leaf differs from the declared requester path",
        ));
    }
    let merkle_root = tapbranch_hash(parsed[0].4, parsed[1].4);
    if verifier.get("taproot_merkle_root").and_then(Value::as_str)
        != Some(lower_hex(&merkle_root).as_str())
        || verifier
            .get("cooperative_internal_key")
            .and_then(Value::as_str)
            != Some(cooperative_internal_key.as_str())
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "quoted tree root or cooperative MuSig2 key is not derivable from contract inputs",
        ));
    }
    let control_block = decode_hex(
        require_string(
            verification,
            "taproot_control_block",
            None,
            "swp_exit_package_mismatch",
        )?,
        "exit Taproot control block",
    )?;
    if control_block.len() != 65
        || lower_hex(&control_block[1..33]) != cooperative_internal_key
        || control_block[33..] != parsed[1 - selected_index].4
    {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "exit control block contains an undeclared internal key or sibling",
        ));
    }
    Ok((selected.2.clone(), control_block, swap_tree_sha256))
}

fn tapbranch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut branch = [0_u8; 64];
    branch[..32].copy_from_slice(&left);
    branch[32..].copy_from_slice(&right);
    tagged_hash("TapBranch", &branch)
}

fn refund_action(
    package: Option<&ExitPackage>,
    observation: &LocalRecoveryObservation,
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<RecoveryAction, SwapClientError> {
    let Some(package) = package else {
        return Ok(RecoveryAction::ExplicitLoss {
            code: "swp_exit_package_missing".to_owned(),
        });
    };
    if !recovery_timeout_reached(package, observation)? {
        return Ok(RecoveryAction::WaitForTimeout);
    }
    let effect_id = package.effect_id()?.to_owned();
    if let Some(previous) = effects.get(&effect_id) {
        validate_recovery_effect(package, previous)?;
        return Ok(RecoveryAction::AlreadyExecuted {
            effect_id,
            external_identifier: previous.external_identifier.clone(),
        });
    }
    if package.mode()? == "presigned" {
        Ok(RecoveryAction::BroadcastPresigned { effect_id })
    } else {
        Ok(RecoveryAction::RequestWalletRefund { effect_id })
    }
}

fn exit_package<'a>(
    packages: &'a [ExitPackage],
    leg_id: &str,
    path: &str,
) -> Option<&'a ExitPackage> {
    packages.iter().find(|package| {
        package.path().ok() == Some(path)
            && package.document().get("leg_id").and_then(Value::as_str) == Some(leg_id)
    })
}

fn claim_action(
    package: Option<&ExitPackage>,
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<RecoveryAction, SwapClientError> {
    let Some(package) = package else {
        return Ok(RecoveryAction::ExplicitLoss {
            code: "swp_exit_package_missing".to_owned(),
        });
    };
    if package.mode()? == "presigned" {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "hashlock claim unexpectedly uses a pre-signed package",
        ));
    }
    let effect_id = package.effect_id()?.to_owned();
    if let Some(previous) = effects.get(&effect_id) {
        validate_recovery_effect(package, previous)?;
        return Ok(RecoveryAction::AlreadyExecuted {
            effect_id,
            external_identifier: previous.external_identifier.clone(),
        });
    }
    Ok(RecoveryAction::RequestWalletClaim { effect_id })
}

fn validate_recovery_effect(
    package: &ExitPackage,
    previous: &ExternalEffectResult,
) -> Result<(), SwapClientError> {
    let matches = if package.mode()? == "presigned" {
        let root = object(package.document(), "exit package")?;
        object(
            root.get("broadcast").unwrap_or(&Value::Null),
            "exit broadcast policy",
        )?
        .get("esplora_urls")
        .and_then(Value::as_array)
        .is_some_and(|endpoints| {
            endpoints.iter().any(|endpoint| {
                endpoint
                    .as_str()
                    .and_then(|endpoint| KeylessEsploraExecutor::request(package, endpoint).ok())
                    .and_then(|request| {
                        ExternalEffectRequest::EsploraBroadcast(request)
                            .sha256()
                            .ok()
                    })
                    .as_deref()
                    == Some(previous.request_sha256.as_str())
            })
        })
    } else {
        ExternalEffectRequest::WalletSigning(wallet_signing_request(package)?).sha256()?
            == previous.request_sha256
    };
    if matches {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "recorded exit effect differs from every allowed recovery request",
        ))
    }
}

fn recovery_timeout_condition(
    package: &ExitPackage,
) -> Result<Option<RecoveryTimeoutCondition>, SwapClientError> {
    match parse_exit_leaf(package)?.condition {
        ExitLeafCondition::Cltv(lock_height) => {
            Ok(Some(RecoveryTimeoutCondition::Cltv { lock_height }))
        }
        ExitLeafCondition::Csv(delay_blocks) => {
            Ok(Some(RecoveryTimeoutCondition::Csv { delay_blocks }))
        }
        ExitLeafCondition::Hashlock(_) => Ok(None),
    }
}

fn recovery_timeout_reached(
    package: &ExitPackage,
    observation: &LocalRecoveryObservation,
) -> Result<bool, SwapClientError> {
    match parse_exit_leaf(package)?.condition {
        ExitLeafCondition::Cltv(lock_height) => Ok(observation.current_height >= lock_height),
        ExitLeafCondition::Csv(delay_blocks) => observation
            .source_funding_confirmation_height
            .and_then(|height| height.checked_add(delay_blocks))
            .map(|maturity| observation.current_height >= maturity)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_unresolved_loss",
                    "local recovery observation omits the source confirmation height",
                )
            }),
        ExitLeafCondition::Hashlock(_) => Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "source refund package unexpectedly uses a hashlock",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitLeafCondition {
    Hashlock([u8; 32]),
    Cltv(u32),
    Csv(u32),
}

#[derive(Debug, Clone, Copy)]
struct ParsedExitLeaf {
    signing_key: XOnlyPublicKey,
    condition: ExitLeafCondition,
}

fn parse_exit_leaf(package: &ExitPackage) -> Result<ParsedExitLeaf, SwapClientError> {
    let root = object(package.document(), "exit package")?;
    let verification = object(
        root.get("verification").unwrap_or(&Value::Null),
        "exit verification",
    )?;
    let script = decode_hex(
        require_string(
            verification,
            "taproot_script",
            None,
            "swp_exit_package_unusable",
        )?,
        "exit Taproot script",
    )?;
    let leaf = parse_exit_leaf_script(&script)?;
    let path = package.path()?;
    match (path, leaf.condition) {
        ("claim", ExitLeafCondition::Hashlock(payment_hash)) => {
            let commitments = object(
                root.get("secret_commitments").unwrap_or(&Value::Null),
                "exit secret commitments",
            )?;
            if require_string(
                commitments,
                "payment_hash",
                None,
                "swp_exit_package_unusable",
            )? != lower_hex(&payment_hash)
            {
                return Err(SwapClientError::new(
                    "swp_payment_hash_mismatch",
                    "claim leaf hash differs from the exit-package commitment",
                ));
            }
        }
        ("refund", ExitLeafCondition::Cltv(_) | ExitLeafCondition::Csv(_)) => {}
        _ => {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "claim and refund paths use the wrong leaf condition",
            ));
        }
    }
    Ok(leaf)
}

fn parse_exit_leaf_script(script: &[u8]) -> Result<ParsedExitLeaf, SwapClientError> {
    let instructions = parse_swap_script(script).map_err(|error| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            format!("exit Taproot script is invalid: {error}"),
        )
    })?;
    let (key, condition) = match instructions.as_slice() {
        [
            ScriptInstruction::Opcode(0x82),
            ScriptInstruction::Push(size),
            ScriptInstruction::Opcode(0x88),
            ScriptInstruction::Opcode(0xa8),
            ScriptInstruction::Push(payment_hash),
            ScriptInstruction::Opcode(0x88),
            ScriptInstruction::Push(key),
            ScriptInstruction::Opcode(0xac),
        ] if size.as_slice() == [32] && payment_hash.len() == 32 && key.len() == 32 => {
            let payment_hash: [u8; 32] = payment_hash.as_slice().try_into().map_err(|_| {
                SwapClientError::new(
                    "swp_exit_package_unusable",
                    "hashlock payment hash has an invalid length",
                )
            })?;
            (key, ExitLeafCondition::Hashlock(payment_hash))
        }
        [
            ScriptInstruction::Push(value),
            ScriptInstruction::Opcode(0xb1),
            ScriptInstruction::Opcode(0x75),
            ScriptInstruction::Push(key),
            ScriptInstruction::Opcode(0xac),
        ] if key.len() == 32 => (key, ExitLeafCondition::Cltv(script_number(value)?)),
        [
            ScriptInstruction::Push(value),
            ScriptInstruction::Opcode(0xb2),
            ScriptInstruction::Opcode(0x75),
            ScriptInstruction::Push(key),
            ScriptInstruction::Opcode(0xac),
        ] if key.len() == 32 => (key, ExitLeafCondition::Csv(script_number(value)?)),
        _ => {
            return Err(SwapClientError::new(
                "swp_exit_package_unusable",
                "exit leaf is not an exact supported hashlock, CLTV, or CSV path",
            ));
        }
    };
    let signing_key = XOnlyPublicKey::from_byte_array(key.as_slice().try_into().map_err(|_| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "exit signing key has an invalid length",
        )
    })?)
    .map_err(|_| {
        SwapClientError::new("swp_exit_package_unusable", "exit signing key is invalid")
    })?;
    Ok(ParsedExitLeaf {
        signing_key,
        condition,
    })
}

fn script_number(bytes: &[u8]) -> Result<u32, SwapClientError> {
    if bytes.is_empty() || bytes.len() > 5 || bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "exit timelock must be a non-negative bounded script number",
        ));
    }
    if bytes.last().is_some_and(|byte| byte & 0x7f == 0)
        && (bytes.len() == 1 || bytes[bytes.len() - 2] & 0x80 == 0)
    {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "exit timelock script number is not minimally encoded",
        ));
    }
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    u32::try_from(value)
        .map_err(|_| SwapClientError::new("swp_exit_package_unusable", "exit timelock exceeds u32"))
}

fn validate_exit_leaf_template(
    package: &ExitPackage,
    transaction: &Transaction,
) -> Result<(), SwapClientError> {
    let [input] = transaction.inputs.as_slice() else {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "exit template must contain exactly one input",
        ));
    };
    match parse_exit_leaf(package)?.condition {
        ExitLeafCondition::Hashlock(_) => Ok(()),
        ExitLeafCondition::Cltv(required) => {
            if input.sequence == u32::MAX
                || !check_cltv(Timelock::BlockHeight(required), transaction.lock_time)
            {
                return Err(SwapClientError::new(
                    "swp_exit_package_unusable",
                    "exit transaction does not satisfy its CLTV leaf",
                ));
            }
            Ok(())
        }
        ExitLeafCondition::Csv(required) => {
            if transaction.version < 2 || !check_csv(required, input.sequence) {
                return Err(SwapClientError::new(
                    "swp_exit_package_unusable",
                    "exit transaction does not satisfy its CSV leaf",
                ));
            }
            Ok(())
        }
    }
}

fn validate_signed_transaction_matches(
    package: &ExitPackage,
    unsigned: &[u8],
    signed: &[u8],
) -> Result<(), SwapClientError> {
    let unsigned = Transaction::parse(unsigned).map_err(|error| {
        SwapClientError::new(
            "swp_external_signature_mismatch",
            format!("unsigned transaction is invalid: {error}"),
        )
    })?;
    let signed = Transaction::parse(signed).map_err(|error| {
        SwapClientError::new(
            "swp_external_signature_invalid",
            format!("wallet returned an invalid transaction: {error}"),
        )
    })?;
    let unsigned_base = unsigned.serialize(false).map_err(|error| {
        SwapClientError::new(
            "swp_external_signature_mismatch",
            format!("could not serialize unsigned transaction: {error}"),
        )
    })?;
    let signed_base = signed.serialize(false).map_err(|error| {
        SwapClientError::new(
            "swp_external_signature_mismatch",
            format!("could not serialize signed transaction: {error}"),
        )
    })?;
    if unsigned_base != signed_base {
        return Err(SwapClientError::new(
            "swp_external_signature_mismatch",
            "wallet changed the transaction template",
        ));
    }
    let [input] = signed.inputs.as_slice() else {
        return Err(SwapClientError::new(
            "swp_external_signature_invalid",
            "exit signing supports exactly one bound input",
        ));
    };
    if input.witness.len() < 3 {
        return Err(SwapClientError::new(
            "swp_external_signature_invalid",
            "wallet returned an incomplete Taproot script-path witness",
        ));
    }
    let control_block = input.witness.last().ok_or_else(|| {
        SwapClientError::new(
            "swp_external_signature_invalid",
            "wallet returned no Taproot control block",
        )
    })?;
    let script = input.witness.get(input.witness.len() - 2).ok_or_else(|| {
        SwapClientError::new(
            "swp_external_signature_invalid",
            "wallet returned no Taproot script",
        )
    })?;
    let root = object(package.document(), "exit package")?;
    let verification = object(
        root.get("verification").unwrap_or(&Value::Null),
        "exit verification",
    )?;
    let expected_script = decode_hex(
        require_string(
            verification,
            "taproot_script",
            None,
            "swp_exit_package_unusable",
        )?,
        "exit Taproot script",
    )?;
    let expected_control = decode_hex(
        require_string(
            verification,
            "taproot_control_block",
            None,
            "swp_exit_package_unusable",
        )?,
        "exit Taproot control block",
    )?;
    if script != &expected_script || control_block != &expected_control {
        return Err(SwapClientError::new(
            "swp_external_signature_mismatch",
            "wallet witness changed the bound Taproot path",
        ));
    }
    let leaf = parse_exit_leaf(package)?;
    let witness_stack = &input.witness[..input.witness.len() - 2];
    let signature = match (leaf.condition, witness_stack) {
        (ExitLeafCondition::Hashlock(payment_hash), [signature, preimage])
            if signature.len() == 64 && preimage.len() == 32 =>
        {
            let preimage: [u8; 32] = preimage.as_slice().try_into().map_err(|_| {
                SwapClientError::new(
                    "swp_external_signature_invalid",
                    "claim preimage has an invalid length",
                )
            })?;
            if !verify_preimage(&preimage, &payment_hash) {
                return Err(SwapClientError::new(
                    "swp_external_signature_invalid",
                    "claim witness does not satisfy the bound hashlock",
                ));
            }
            signature
        }
        (ExitLeafCondition::Cltv(_) | ExitLeafCondition::Csv(_), [signature])
            if signature.len() == 64 =>
        {
            validate_exit_leaf_template(package, &signed)?;
            signature
        }
        _ => {
            return Err(SwapClientError::new(
                "swp_external_signature_invalid",
                "wallet witness does not exactly satisfy the bound exit leaf",
            ));
        }
    };
    let digest = taproot_exit_sighash(package, &signed)?;
    let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
        SwapClientError::new(
            "swp_external_signature_invalid",
            "wallet Schnorr signature has an invalid length",
        )
    })?;
    verify_musig2_signature(&leaf.signing_key, &digest, &signature).map_err(|error| {
        SwapClientError::new(
            "swp_external_signature_invalid",
            format!("wallet Schnorr signature does not verify: {error}"),
        )
    })?;
    Ok(())
}

fn taproot_exit_sighash(
    package: &ExitPackage,
    transaction: &Transaction,
) -> Result<[u8; 32], SwapClientError> {
    let [input] = transaction.inputs.as_slice() else {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "exit signing supports exactly one bound input",
        ));
    };
    let root = object(package.document(), "exit package")?;
    let funding = object(root.get("funding").unwrap_or(&Value::Null), "exit funding")?;
    let verification = object(
        root.get("verification").unwrap_or(&Value::Null),
        "exit verification",
    )?;
    let amount = canonical_amount(require_string(
        funding,
        "amount",
        None,
        "swp_exit_package_unusable",
    )?)?;
    let script_pubkey = decode_hex(
        require_string(funding, "script_pubkey", None, "swp_exit_package_unusable")?,
        "funding scriptPubKey",
    )?;
    let taproot_script = decode_hex(
        require_string(
            verification,
            "taproot_script",
            None,
            "swp_exit_package_unusable",
        )?,
        "exit Taproot script",
    )?;
    let control_block = decode_hex(
        require_string(
            verification,
            "taproot_control_block",
            None,
            "swp_exit_package_unusable",
        )?,
        "exit Taproot control block",
    )?;
    let output_key_bytes = script_pubkey.strip_prefix(&[0x51, 0x20]).ok_or_else(|| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "funding scriptPubKey is not a v1 Taproot output",
        )
    })?;
    let output_key =
        XOnlyPublicKey::from_byte_array(output_key_bytes.try_into().map_err(|_| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "funding Taproot output key has an invalid length",
            )
        })?)
        .map_err(|_| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "funding Taproot output key is invalid",
            )
        })?;
    verify_control_block(&output_key, &taproot_script, &control_block).map_err(|error| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            format!("exit Taproot path does not match the funding output: {error}"),
        )
    })?;

    let mut prevout = Vec::with_capacity(36);
    prevout.extend_from_slice(&input.previous_txid);
    prevout.extend_from_slice(&input.previous_output.to_le_bytes());
    let mut encoded_script_pubkey = Vec::new();
    write_compact_size(script_pubkey.len(), &mut encoded_script_pubkey)?;
    encoded_script_pubkey.extend_from_slice(&script_pubkey);
    let mut encoded_outputs = Vec::new();
    for output in &transaction.outputs {
        encoded_outputs.extend_from_slice(&output.value_sat.to_le_bytes());
        write_compact_size(output.script_pubkey.len(), &mut encoded_outputs)?;
        encoded_outputs.extend_from_slice(&output.script_pubkey);
    }
    let mut message = Vec::new();
    message.push(0);
    message.push(0);
    message.extend_from_slice(&transaction.version.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_le_bytes());
    message.extend_from_slice(&sha256(&prevout));
    message.extend_from_slice(&sha256(&amount.to_le_bytes()));
    message.extend_from_slice(&sha256(&encoded_script_pubkey));
    message.extend_from_slice(&sha256(&input.sequence.to_le_bytes()));
    message.extend_from_slice(&sha256(&encoded_outputs));
    message.push(2);
    message.extend_from_slice(&0_u32.to_le_bytes());
    let leaf_version = control_block.first().copied().ok_or_else(|| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "exit Taproot control block is empty",
        )
    })? & 0xfe;
    message.extend_from_slice(
        &tapleaf_hash(leaf_version, &taproot_script).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                format!("exit Taproot leaf is invalid: {error}"),
            )
        })?,
    );
    message.push(0);
    message.extend_from_slice(&u32::MAX.to_le_bytes());
    Ok(tagged_hash("TapSighash", &message))
}

fn write_compact_size(value: usize, output: &mut Vec<u8>) -> Result<(), SwapClientError> {
    let value = u64::try_from(value).map_err(|_| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "serialized exit field length exceeds u64",
        )
    })?;
    match value {
        0..=0xfc => output.push(value as u8),
        0xfd..=0xffff => {
            output.push(0xfd);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xfe);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

fn effect_id(order_id: &str, effect_role: &str, leg_id: &str) -> Result<String, SwapClientError> {
    let order = decode_hex(order_id, "Order event ID")?;
    let mut preimage = b"openagents.mkt-swp.v1".to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&order);
    preimage.push(0);
    preimage.extend_from_slice(effect_role.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(leg_id.as_bytes());
    Ok(lower_hex(&sha256(&preimage)))
}

fn cooperative_internal_key(verifier: &Map<String, Value>) -> Result<String, SwapClientError> {
    let declared = verifier
        .get("cooperative_pubkeys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 2)
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "leg verifier requires two ordered cooperative spend keys",
            )
        })?;
    let expected_roles = ["requester", "provider"];
    let mut keys = Vec::with_capacity(2);
    for (declared, expected_role) in declared.iter().zip(expected_roles) {
        let declared = object(declared, "cooperative spend key")?;
        if declared.get("participant_role").and_then(Value::as_str) != Some(expected_role) {
            return Err(SwapClientError::new(
                "swp_exit_package_mismatch",
                "cooperative spend keys are not pinned in requester/provider order",
            ));
        }
        let key = decode_hex(
            require_string(declared, "public_key", None, "swp_exit_package_mismatch")?,
            "cooperative spend key",
        )?;
        keys.push(PublicKey::from_slice(&key).map_err(|_| {
            SwapClientError::new(
                "swp_exit_package_mismatch",
                "cooperative spend key is not a compressed secp256k1 key",
            )
        })?);
    }
    if keys[0] == keys[1] {
        return Err(SwapClientError::new(
            "swp_exit_package_mismatch",
            "cooperative requester and provider spend keys must be distinct",
        ));
    }
    musig2_aggregate_key(&keys)
        .map(|key| lower_hex(&key.serialize()))
        .map_err(|error| {
            SwapClientError::new(
                "swp_contract_signer_invalid",
                format!("could not derive cooperative MuSig2 key: {error}"),
            )
        })
}

fn validate_effect(effect: &ExternalEffectResult) -> Result<(), SwapClientError> {
    for (value, label) in [
        (&effect.order_id, "effect Order ID"),
        (&effect.effect_id, "effect ID"),
        (&effect.request_sha256, "effect request digest"),
        (&effect.result_sha256, "effect result digest"),
    ] {
        require_lower_hex_32(value, label)?;
    }
    if effect.external_identifier.is_empty()
        || effect.external_identifier.len() > 512
        || effect.external_identifier.chars().any(char::is_control)
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "external effect identifier is not bounded public metadata",
        ));
    }
    Ok(())
}

fn wallet_signing_request(package: &ExitPackage) -> Result<WalletSigningRequest, SwapClientError> {
    let unsigned = package.unsigned_transaction()?;
    Ok(WalletSigningRequest {
        effect_id: package.effect_id()?.to_owned(),
        path: package.path()?.to_owned(),
        unsigned_transaction: lower_hex(&unsigned),
        signature_hash: lower_hex(&package.signing_digest()?),
    })
}

fn validate_persisted_funding_request(
    config: &SwapClientConfig,
    records: &[Event],
    packages: &[ExitPackage],
    request: &FundingAuthorizationRequest,
) -> Result<(), SwapClientError> {
    let order_id = request.order_id.clone();
    let request = ExternalEffectRequest::Funding(request.clone());
    let effect = ExternalEffectResult {
        order_id,
        effect_id: request.effect_id().to_owned(),
        request_sha256: request.sha256()?,
        external_identifier: "persisted-funding-authorization".to_owned(),
        result_sha256: "00".repeat(32),
    };
    validate_effect_request_binding(config, records, packages, &request, &effect)
}

fn validate_effect_request_binding(
    config: &SwapClientConfig,
    records: &[Event],
    packages: &[ExitPackage],
    request: &ExternalEffectRequest,
    effect: &ExternalEffectResult,
) -> Result<(), SwapClientError> {
    let bound = BoundSession::from_records(config, records)?;
    bound.verify_contract_terms()?;
    bound.verify_requester_topology()?;
    verify_exit_packages(packages, &bound)?;
    if effect.order_id != bound.order.id
        || effect.effect_id != request.effect_id()
        || effect.request_sha256 != request.sha256()?
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "external effect row differs from its exact typed request",
        ));
    }
    match request {
        ExternalEffectRequest::Funding(request) => {
            if request.session_id != config.session_id
                || request.order_id != bound.order.id
                || request.quote_id != bound.quote.id
                || request.swap_type != bound.swap_type
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "funding effect does not bind the verified session",
                ));
            }
            let topology = requester_topology(bound.swap_type);
            let expected_effect_id = effect_id(
                &bound.order.id,
                topology.funding_effect_role,
                topology.funding_leg_id,
            )?;
            let verifier = verifier_for_leg(
                object(&bound.contract, "Swap Contract")?,
                topology.funding_leg_id,
            )?;
            match &request.action {
                FundingAction::BroadcastBitcoin {
                    effect_id,
                    leg_id,
                    raw_transaction,
                } => {
                    if !matches!(bound.swap_type, SwapType::Submarine | SwapType::Chain)
                        || effect_id != &expected_effect_id
                        || leg_id != topology.funding_leg_id
                        || verifier
                            .get("funding_transaction_sha256")
                            .and_then(Value::as_str)
                            != Some(
                                lower_hex(&sha256(&decode_hex(
                                    raw_transaction,
                                    "funding effect transaction",
                                )?))
                                .as_str(),
                            )
                    {
                        return Err(SwapClientError::new(
                            "swp_external_effect_conflict",
                            "Bitcoin funding effect differs from the bound contract action",
                        ));
                    }
                }
                FundingAction::PayLightningInvoice {
                    effect_id,
                    leg_id,
                    invoice,
                    maximum_routing_fee,
                    invoice_expires_at,
                    minimum_final_cltv_delta,
                    hold_invoice_required,
                    hold_expiry_height,
                } => {
                    let parsed_invoice = parse_bolt11(invoice).map_err(|error| {
                        SwapClientError::new(
                            "swp_external_effect_conflict",
                            format!("funding effect invoice is invalid: {error}"),
                        )
                    })?;
                    let expected_expiry = parsed_invoice
                        .timestamp
                        .checked_add(parsed_invoice.expiry_seconds);
                    let expected_hold_expiry = object(
                        object(&bound.contract, "Swap Contract")?
                            .get("timeout_ladder")
                            .unwrap_or(&Value::Null),
                        "reverse timeout ladder",
                    )?
                    .get("hold_expiry_height")
                    .and_then(Value::as_u64)
                    .and_then(|height| u32::try_from(height).ok());
                    if bound.swap_type != SwapType::Reverse
                        || effect_id != &expected_effect_id
                        || leg_id != topology.funding_leg_id
                        || verifier.get("invoice_sha256").and_then(Value::as_str)
                            != Some(lower_hex(&sha256(invoice.as_bytes())).as_str())
                        || Some(*invoice_expires_at) != expected_expiry
                        || verifier
                            .get("invoice_minimum_final_cltv_delta")
                            .and_then(Value::as_str)
                            .and_then(|value| value.parse::<u64>().ok())
                            != Some(*minimum_final_cltv_delta)
                        || object(&bound.contract, "Swap Contract")?
                            .get("lightning_routing_fee_budget")
                            .and_then(Value::as_str)
                            != Some(maximum_routing_fee.as_str())
                        || !*hold_invoice_required
                        || Some(*hold_expiry_height) != expected_hold_expiry
                    {
                        return Err(SwapClientError::new(
                            "swp_external_effect_conflict",
                            "Lightning funding effect differs from the bound contract action",
                        ));
                    }
                }
            }
        }
        ExternalEffectRequest::WalletSigning(request) => {
            let package = packages
                .iter()
                .find(|package| package.effect_id().ok() == Some(request.effect_id.as_str()))
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_external_effect_conflict",
                        "wallet-signing effect has no bound exit package",
                    )
                })?;
            if package.mode()? == "presigned" || &wallet_signing_request(package)? != request {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "wallet-signing effect differs from the exact exit request",
                ));
            }
        }
        ExternalEffectRequest::EsploraBroadcast(request) => {
            let package = packages
                .iter()
                .find(|package| package.effect_id().ok() == Some(request.effect_id.as_str()))
                .ok_or_else(|| {
                    SwapClientError::new(
                        "swp_external_effect_conflict",
                        "Esplora effect has no bound exit package",
                    )
                })?;
            let root = object(package.document(), "exit package")?;
            let endpoints = object(
                root.get("broadcast").unwrap_or(&Value::Null),
                "exit broadcast policy",
            )?
            .get("esplora_urls")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_external_effect_conflict",
                    "exit package has no Esplora endpoint allowlist",
                )
            })?;
            let matches_allowed_request = endpoints.iter().any(|endpoint| {
                endpoint
                    .as_str()
                    .and_then(|endpoint| KeylessEsploraExecutor::request(package, endpoint).ok())
                    .as_ref()
                    == Some(request)
            });
            if !matches_allowed_request {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "Esplora effect differs from every package-allowed broadcast request",
                ));
            }
        }
        ExternalEffectRequest::RailEvidence(request) => {
            validate_rail_evidence_request(&bound, request)?;
            if effect.result_sha256 != request.evidence_reference_sha256 {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "terminal rail effect result differs from its verified evidence reference",
                ));
            }
        }
        ExternalEffectRequest::LightningDisposition(request) => {
            validate_lightning_disposition_request(&bound, config, request)?;
            if effect.result_sha256 != request.evidence_reference_sha256 {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "Lightning disposition result differs from its verified local view",
                ));
            }
        }
    }
    Ok(())
}

fn validate_effect_row_binding(
    config: &SwapClientConfig,
    records: &[Event],
    packages: &[ExitPackage],
    effect: &ExternalEffectResult,
) -> Result<(), SwapClientError> {
    let bound = BoundSession::from_records(config, records)?;
    bound.verify_contract_terms()?;
    bound.verify_requester_topology()?;
    verify_exit_packages(packages, &bound)?;
    if effect.order_id != bound.order.id {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "persisted effect belongs to a different Order",
        ));
    }
    let topology = requester_topology(bound.swap_type);
    let mut effect_ids = vec![effect_id(
        &bound.order.id,
        topology.funding_effect_role,
        topology.funding_leg_id,
    )?];
    for exit in topology.exits {
        effect_ids.push(effect_id(
            &bound.order.id,
            if exit.path == "claim" {
                "chain_claim"
            } else {
                "chain_refund"
            },
            exit.leg_id,
        )?);
    }
    let contract = object(&bound.contract, "Swap Contract")?;
    for leg in contract
        .get("legs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(leg_id) = leg.get("leg_id").and_then(Value::as_str) {
            for outcome in ["completed", "refunded"] {
                effect_ids.push(effect_id(
                    &bound.order.id,
                    &format!("terminal_evidence_{outcome}"),
                    leg_id,
                )?);
            }
        }
    }
    if bound.swap_type == SwapType::Reverse {
        effect_ids.push(effect_id(
            &bound.order.id,
            "lightning_disposition",
            requester_topology(bound.swap_type).funding_leg_id,
        )?);
    }
    if !effect_ids.contains(&effect.effect_id) {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "persisted effect ID is not allocated by the accepted contract",
        ));
    }
    Ok(())
}

fn require_exact_funding_effect(
    funding_request: Option<&FundingAuthorizationRequest>,
    requests: &BTreeMap<String, ExternalEffectRequest>,
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    let funding_request = funding_request.ok_or_else(|| {
        SwapClientError::new(
            "swp_funding_not_authorized",
            "terminal observation has no verified persisted funding authorization",
        )
    })?;
    let typed_request = ExternalEffectRequest::Funding(funding_request.clone());
    let effect_id = funding_request.action.effect_id();
    let persisted_request = requests.get(effect_id).ok_or_else(|| {
        SwapClientError::new(
            "swp_funding_not_authorized",
            "terminal observation requires the exact persisted funding request",
        )
    })?;
    let effect = effects.get(effect_id).ok_or_else(|| {
        SwapClientError::new(
            "swp_funding_not_authorized",
            "terminal observation requires a durably recorded funding effect",
        )
    })?;
    if persisted_request != &typed_request
        || effect.order_id != funding_request.order_id
        || effect.effect_id != effect_id
        || effect.request_sha256 != typed_request.sha256()?
    {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "persisted funding effect differs from its verified authorization",
        ));
    }
    Ok(())
}

fn validate_post_funding_effects(
    funding_request: Option<&FundingAuthorizationRequest>,
    requests: &BTreeMap<String, ExternalEffectRequest>,
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    if requests.values().any(|request| {
        matches!(
            request,
            ExternalEffectRequest::RailEvidence(_) | ExternalEffectRequest::LightningDisposition(_)
        )
    }) {
        require_exact_funding_effect(funding_request, requests, effects)?;
    }
    Ok(())
}

fn validate_effect_ledger(
    config: &SwapClientConfig,
    records: &[Event],
    packages: &[ExitPackage],
    funding_request: Option<&FundingAuthorizationRequest>,
    requests: &BTreeMap<String, ExternalEffectRequest>,
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    if requests.len() != effects.len() || effects.len() > MAX_EXTERNAL_EFFECTS {
        return Err(SwapClientError::new(
            "swp_external_effect_conflict",
            "external effect ledger lacks exact request/result cardinality",
        ));
    }
    if let Some(request) = funding_request {
        validate_persisted_funding_request(config, records, packages, request)?;
    }
    for (effect_id, effect) in effects {
        validate_effect(effect)?;
        validate_effect_row_binding(config, records, packages, effect)?;
        let request = requests.get(effect_id).ok_or_else(|| {
            SwapClientError::new(
                "swp_external_effect_conflict",
                "external effect has no exact typed request",
            )
        })?;
        if request.effect_id() != effect_id || effect.effect_id != *effect_id {
            return Err(SwapClientError::new(
                "swp_external_effect_conflict",
                "external effect map key differs from its typed request or result",
            ));
        }
        validate_effect_request_binding(config, records, packages, request, effect)?;
    }
    validate_lifecycle(config, records, effects)?;
    validate_post_funding_effects(funding_request, requests, effects)
}

fn exactly_one<'a>(
    records: &'a [Event],
    kind: u16,
    code: &'static str,
) -> Result<&'a Event, SwapClientError> {
    let matches = records
        .iter()
        .filter(|event| event.kind == kind)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [event] => Ok(*event),
        _ => Err(SwapClientError::new(
            code,
            format!("session requires exactly one kind {kind} record"),
        )),
    }
}

fn require_marked_reference(
    event: &Event,
    marker: &str,
    expected: &str,
) -> Result<(), SwapClientError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 && matches[0].value() == Some(expected) {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("event does not contain the exact {marker} reference"),
        ))
    }
}

fn marked_reference<'a>(event: &'a Event, marker: &str) -> Result<&'a str, SwapClientError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [tag] => tag.value().ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("{marker} reference is empty"),
            )
        }),
        _ => Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("event requires exactly one {marker} reference"),
        )),
    }
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Result<&'a str, SwapClientError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [tag] if tag.as_slice().len() == 2 => tag.value().ok_or_else(|| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("{name} tag is empty"),
            )
        }),
        _ => Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("event requires exactly one {name} tag"),
        )),
    }
}

fn parse_content(event: &Event) -> Result<Value, SwapClientError> {
    let value: Value = serde_json::from_str(&event.content).map_err(|error| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("event content is invalid JSON: {error}"),
        )
    })?;
    reject_custody_material(&value)?;
    Ok(value)
}

fn role_for_author(
    config: &SwapClientConfig,
    pubkey: &str,
) -> Result<ParticipantRole, SwapClientError> {
    if pubkey == config.requester_pubkey {
        Ok(ParticipantRole::Requester)
    } else if pubkey == config.provider_pubkey {
        Ok(ParticipantRole::Provider)
    } else {
        Err(SwapClientError::new(
            "swp_contract_signer_invalid",
            "signed record author is not a session participant",
        ))
    }
}

fn quote_swap_type(records: &[Event]) -> Result<SwapType, SwapClientError> {
    let quote = exactly_one(records, MKT_QUOTE_KIND, "swp_contract_terms_mismatch")?;
    let content = parse_content(quote)?;
    let terms = object(
        object(
            content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP Quote",
        )?
        .get("terms")
        .unwrap_or(&Value::Null),
        "MKT-SWP Quote terms",
    )?;
    match terms.get("swap_type").and_then(Value::as_str) {
        Some("submarine") => Ok(SwapType::Submarine),
        Some("reverse") => Ok(SwapType::Reverse),
        Some("chain") => Ok(SwapType::Chain),
        _ => Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "Quote has an unsupported swap type",
        )),
    }
}

fn status_state(event: &Event) -> Result<String, SwapClientError> {
    let content = parse_content(event)?;
    object(
        content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP Status",
    )?
    .get("swp_state")
    .and_then(Value::as_str)
    .ok_or_else(|| SwapClientError::new("swp_status_transition_invalid", "Status has no swp_state"))
    .map(str::to_owned)
}

fn cooperative_signing_message(
    event: &Event,
    role: ParticipantRole,
) -> Result<Option<CooperativeSigningMessage>, SwapClientError> {
    let content = parse_content(event)?;
    let profile = object(
        content.get("mkt_swp").unwrap_or(&Value::Null),
        "MKT-SWP Status",
    )?;
    let Some(value) = profile.get("cooperative_signing") else {
        return Ok(None);
    };
    let message: CooperativeSigningMessage =
        serde_json::from_value(value.clone()).map_err(|error| {
            musig_error(format!(
                "cooperative signing message has an invalid shape: {error}"
            ))
        })?;
    message.validate(role)?;
    Ok(Some(message))
}

fn cooperative_status_transition(
    previous: &Event,
    current: &Event,
    config: &SwapClientConfig,
    previous_state: &str,
    current_state: &str,
) -> Result<bool, SwapClientError> {
    let previous_role = role_for_author(config, &previous.pubkey)?;
    let current_role = role_for_author(config, &current.pubkey)?;
    let previous = cooperative_signing_message(previous, previous_role)?;
    let current = cooperative_signing_message(current, current_role)?;
    match (previous, current) {
        (Some(previous), Some(current)) => Ok(previous_state == "cooperative_signing_pending"
            && current_state == previous_state
            && previous.context_sha256 == current.context_sha256
            && previous.participant_index == current.participant_index
            && cooperative_action_rank(current.action) > cooperative_action_rank(previous.action)),
        (None, Some(current)) => Ok(current_state == "cooperative_signing_pending"
            && matches!(
                previous_state,
                "funding_final"
                    | "source_funding_final"
                    | "destination_funding_final"
                    | "lightning_paid"
            )
            && matches!(
                current.action,
                CooperativeSigningAction::NonceCommitment | CooperativeSigningAction::Aborted
            )),
        (Some(_), None) => Ok(previous_state == "cooperative_signing_pending"
            && matches!(
                base_state_for(current_state),
                Some("executing" | "completed" | "refund_pending" | "refunded" | "failed")
            )),
        (None, None) => Ok(false),
    }
}

fn cooperative_action_rank(action: CooperativeSigningAction) -> u8 {
    match action {
        CooperativeSigningAction::NonceCommitment => 0,
        CooperativeSigningAction::PublicNonce => 1,
        CooperativeSigningAction::PartialSignature => 2,
        CooperativeSigningAction::FinalSignature => 3,
        CooperativeSigningAction::Aborted => 4,
    }
}

pub fn validate_cooperative_signing_exchange(
    messages: &[(ParticipantRole, CooperativeSigningMessage)],
) -> Result<(), SwapClientError> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, (_, message)) in messages.iter().enumerate() {
        groups
            .entry(message.context_sha256.clone())
            .or_default()
            .push(index);
    }
    for indexes in groups.values() {
        let first = indexes
            .first()
            .and_then(|index| messages.get(*index))
            .ok_or_else(|| musig_error("cooperative signing group is empty"))?;
        let context = &first.1.context;
        let mut seen = BTreeSet::new();
        let mut commitments: [Option<[u8; 32]>; 2] = [None, None];
        let mut public_nonces: [Option<[u8; 66]>; 2] = [None, None];
        let mut partial_signatures: [Option<[u8; 32]>; 2] = [None, None];
        let mut final_signature = false;
        let mut aborted = false;
        for index in indexes {
            let (role, message) = messages
                .get(*index)
                .ok_or_else(|| musig_error("cooperative signing index is invalid"))?;
            if aborted {
                return Err(musig_error(
                    "cooperative transcript continues after an abort",
                ));
            }
            message.validate(*role)?;
            if &message.context != context {
                return Err(musig_error(
                    "one cooperative context digest maps to different context bytes",
                ));
            }
            let contribution = (
                message.participant_index,
                cooperative_action_rank(message.action),
            );
            if !seen.insert(contribution) {
                return Err(musig_error(
                    "one participant supplied the same cooperative action twice",
                ));
            }
            let participant = usize::from(message.participant_index);
            if participant >= commitments.len() {
                return Err(musig_error(
                    "cooperative participant index is outside the committed key order",
                ));
            }
            match message.action {
                CooperativeSigningAction::NonceCommitment => {
                    commitments[participant] = Some(fixed_hex::<32>(
                        message.nonce_commitment.as_deref().ok_or_else(|| {
                            musig_error("cooperative nonce commitment is missing")
                        })?,
                        "cooperative nonce commitment",
                    )?);
                }
                CooperativeSigningAction::PublicNonce => {
                    let commitment = fixed_hex::<32>(
                        message.nonce_commitment.as_deref().ok_or_else(|| {
                            musig_error("cooperative nonce commitment is missing")
                        })?,
                        "cooperative nonce commitment",
                    )?;
                    if commitments.iter().any(Option::is_none)
                        || commitments[participant] != Some(commitment)
                    {
                        return Err(musig_error(
                            "cooperative public nonce lacks both prior exact commitments",
                        ));
                    }
                    public_nonces[participant] = Some(fixed_hex::<66>(
                        message
                            .public_nonce
                            .as_deref()
                            .ok_or_else(|| musig_error("cooperative public nonce is missing"))?,
                        "cooperative public nonce",
                    )?);
                }
                CooperativeSigningAction::PartialSignature => {
                    let supplied =
                        cooperative_public_nonces(message.public_nonces.as_deref().ok_or_else(
                            || musig_error("cooperative public nonce set is missing"),
                        )?)?;
                    if public_nonces.iter().any(Option::is_none)
                        || public_nonces[0] != Some(supplied[0])
                        || public_nonces[1] != Some(supplied[1])
                    {
                        return Err(musig_error(
                            "cooperative partial signature does not bind both revealed nonces",
                        ));
                    }
                    partial_signatures[participant] = Some(fixed_hex::<32>(
                        message.partial_signature.as_deref().ok_or_else(|| {
                            musig_error("cooperative partial signature is missing")
                        })?,
                        "cooperative partial signature",
                    )?);
                }
                CooperativeSigningAction::FinalSignature => {
                    let supplied_nonces =
                        cooperative_public_nonces(message.public_nonces.as_deref().ok_or_else(
                            || musig_error("cooperative public nonce set is missing"),
                        )?)?;
                    let supplied_partials = cooperative_partial_signatures(
                        message.partial_signatures.as_deref().ok_or_else(|| {
                            musig_error("cooperative partial signature set is missing")
                        })?,
                    )?;
                    if public_nonces[0] != Some(supplied_nonces[0])
                        || public_nonces[1] != Some(supplied_nonces[1])
                        || partial_signatures[0] != Some(supplied_partials[0])
                        || partial_signatures[1] != Some(supplied_partials[1])
                    {
                        return Err(musig_error(
                            "cooperative final signature lacks both verified contributions",
                        ));
                    }
                    final_signature = true;
                }
                CooperativeSigningAction::Aborted => aborted = true,
            }
        }
        if aborted && final_signature {
            return Err(musig_error(
                "cooperative transcript cannot be both finalized and aborted",
            ));
        }
    }
    Ok(())
}

fn cooperative_public_keys(values: &[String]) -> Result<Vec<PublicKey>, SwapClientError> {
    if values.len() != 2 || values[0] == values[1] {
        return Err(musig_error(
            "cooperative signing requires distinct requester/provider keys",
        ));
    }
    values
        .iter()
        .map(|value| {
            let encoded = fixed_hex::<33>(value, "cooperative participant key")?;
            PublicKey::from_slice(&encoded)
                .map_err(|_| musig_error("cooperative participant key is invalid"))
        })
        .collect()
}

fn cooperative_tweaks(values: &[CooperativeTweak]) -> Result<Vec<Musig2Tweak>, SwapClientError> {
    if values.is_empty() || values.len() > 8 {
        return Err(musig_error("cooperative tweak count is outside bounds"));
    }
    values
        .iter()
        .map(|tweak| {
            Ok(Musig2Tweak {
                value: fixed_hex::<32>(&tweak.value, "cooperative tweak")?,
                xonly: tweak.xonly,
            })
        })
        .collect()
}

fn cooperative_public_nonces(values: &[String]) -> Result<Vec<[u8; 66]>, SwapClientError> {
    if values.len() != 2 {
        return Err(musig_error(
            "cooperative signing requires two public nonces",
        ));
    }
    values
        .iter()
        .map(|value| {
            let nonce = fixed_hex::<66>(value, "cooperative public nonce")?;
            parse_public_nonce(&nonce)?;
            Ok(nonce)
        })
        .collect()
}

fn parse_public_nonce(nonce: &[u8; 66]) -> Result<(), SwapClientError> {
    PublicKey::from_slice(&nonce[..33])
        .and_then(|_| PublicKey::from_slice(&nonce[33..]))
        .map(|_| ())
        .map_err(|_| musig_error("cooperative public nonce contains an invalid point"))
}

fn cooperative_partial_signatures(values: &[String]) -> Result<Vec<[u8; 32]>, SwapClientError> {
    if values.len() != 2 {
        return Err(musig_error(
            "cooperative signing requires two partial signatures",
        ));
    }
    values
        .iter()
        .map(|value| fixed_hex::<32>(value, "cooperative partial signature"))
        .collect()
}

fn fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], SwapClientError> {
    let decoded = decode_hex(value, label)?;
    decoded
        .try_into()
        .map_err(|_| musig_error(format!("{label} must be exactly {N} bytes")))
}

fn musig_error(detail: impl Into<String>) -> SwapClientError {
    SwapClientError::new("swp_musig_transcript_invalid", detail)
}

fn core_musig_error(error: impl std::fmt::Display) -> SwapClientError {
    musig_error(error.to_string())
}

fn state_allowed_for_swap(role: ParticipantRole, state: &str, swap_type: SwapType) -> bool {
    if state == "cooperative_signing_pending" {
        return matches!(
            swap_type,
            SwapType::Submarine | SwapType::Reverse | SwapType::Chain
        );
    }
    let common = matches!(
        state,
        "completed" | "refunded" | "cancelled" | "expired" | "disputed" | "failed" | "unresolved"
    );
    if common {
        return true;
    }
    let observation = match swap_type {
        SwapType::Submarine | SwapType::Reverse => {
            matches!(state, "funding_observed" | "funding_final")
        }
        SwapType::Chain => matches!(
            state,
            "source_funding_observed"
                | "source_funding_final"
                | "destination_funding_observed"
                | "destination_funding_final"
        ),
    };
    if observation {
        return true;
    }
    match (swap_type, role) {
        (SwapType::Submarine, ParticipantRole::Requester) => matches!(
            state,
            "requester_verification_passed"
                | "requester_funding_broadcast"
                | "funding_required"
                | "refund_prepared"
                | "refund_pending"
        ),
        (SwapType::Submarine, ParticipantRole::Provider) => matches!(
            state,
            "accepted"
                | "lock_terms_ready"
                | "lightning_payment_pending"
                | "lightning_paid"
                | "provider_claim_pending"
                | "provider_claimed"
        ),
        (SwapType::Reverse, ParticipantRole::Requester) => matches!(
            state,
            "requester_invoice_verified"
                | "lightning_payment_pending"
                | "requester_lock_verified"
                | "requester_claim_pending"
                | "requester_claimed"
        ),
        (SwapType::Reverse, ParticipantRole::Provider) => matches!(
            state,
            "accepted"
                | "hold_invoice_ready"
                | "lightning_htlcs_held"
                | "provider_lock_terms_ready"
                | "provider_funding_broadcast"
                | "lightning_settlement_pending"
                | "lightning_paid"
                | "provider_refund_prepared"
                | "provider_refund_pending"
                | "provider_refunded"
                | "invoice_cancel_pending"
                | "invoice_cancelled"
        ),
        (SwapType::Chain, ParticipantRole::Requester) => matches!(
            state,
            "requester_source_verified"
                | "requester_source_broadcast"
                | "source_funding_required"
                | "requester_destination_verified"
                | "requester_destination_claim_pending"
                | "requester_destination_claimed"
                | "requester_source_refund_prepared"
                | "requester_source_refund_pending"
                | "requester_source_refunded"
        ),
        (SwapType::Chain, ParticipantRole::Provider) => matches!(
            state,
            "accepted"
                | "source_lock_terms_ready"
                | "destination_lock_terms_ready"
                | "provider_destination_broadcast"
                | "provider_source_claim_pending"
                | "provider_source_claimed"
                | "provider_destination_refund_prepared"
                | "provider_destination_refund_pending"
                | "provider_destination_refunded"
        ),
    }
}

fn transition_rank(swap_type: SwapType, state: &str) -> Option<u16> {
    let states: &[&str] = match swap_type {
        SwapType::Submarine => &[
            "accepted",
            "lock_terms_ready",
            "requester_verification_passed",
            "funding_required",
            "requester_funding_broadcast",
            "funding_observed",
            "funding_final",
            "lightning_payment_pending",
            "lightning_paid",
            "cooperative_signing_pending",
            "provider_claim_pending",
            "provider_claimed",
            "refund_prepared",
            "refund_pending",
            "refunded",
            "cancelled",
            "expired",
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
        SwapType::Reverse => &[
            "accepted",
            "hold_invoice_ready",
            "requester_invoice_verified",
            "lightning_payment_pending",
            "lightning_htlcs_held",
            "provider_lock_terms_ready",
            "requester_lock_verified",
            "provider_funding_broadcast",
            "funding_observed",
            "funding_final",
            "cooperative_signing_pending",
            "requester_claim_pending",
            "requester_claimed",
            "lightning_settlement_pending",
            "lightning_paid",
            "provider_refund_prepared",
            "provider_refund_pending",
            "provider_refunded",
            "invoice_cancel_pending",
            "invoice_cancelled",
            "refunded",
            "cancelled",
            "expired",
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
        SwapType::Chain => &[
            "accepted",
            "source_lock_terms_ready",
            "requester_source_verified",
            "source_funding_required",
            "requester_source_broadcast",
            "source_funding_observed",
            "source_funding_final",
            "destination_lock_terms_ready",
            "requester_destination_verified",
            "provider_destination_broadcast",
            "destination_funding_observed",
            "destination_funding_final",
            "requester_destination_claim_pending",
            "requester_destination_claimed",
            "provider_source_claim_pending",
            "provider_source_claimed",
            "provider_destination_refund_prepared",
            "provider_destination_refund_pending",
            "provider_destination_refunded",
            "requester_source_refund_prepared",
            "requester_source_refund_pending",
            "requester_source_refunded",
            "refunded",
            "cancelled",
            "expired",
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
    };
    states
        .iter()
        .position(|candidate| *candidate == state)
        .and_then(|position| u16::try_from(position).ok())
}

fn state_allowed_for_role(role: ParticipantRole, state: &str) -> bool {
    if matches!(
        state,
        "lightning_payment_pending"
            | "funding_observed"
            | "funding_final"
            | "source_funding_observed"
            | "source_funding_final"
            | "destination_funding_observed"
            | "destination_funding_final"
            | "cooperative_signing_pending"
            | "cancelled"
            | "expired"
            | "completed"
            | "refunded"
            | "disputed"
            | "failed"
            | "unresolved"
    ) {
        return true;
    }
    let requester = [
        "requester_verification_passed",
        "requester_invoice_verified",
        "requester_lock_verified",
        "requester_source_verified",
        "requester_destination_verified",
        "requester_funding_broadcast",
        "funding_required",
        "requester_source_broadcast",
        "source_funding_required",
        "requester_claim_pending",
        "requester_claimed",
        "requester_destination_claim_pending",
        "requester_destination_claimed",
        "refund_prepared",
        "refund_pending",
        "requester_source_refund_prepared",
        "requester_source_refund_pending",
        "requester_source_refunded",
    ];
    let provider = [
        "accepted",
        "lock_terms_ready",
        "hold_invoice_ready",
        "provider_lock_terms_ready",
        "source_lock_terms_ready",
        "destination_lock_terms_ready",
        "lightning_htlcs_held",
        "lightning_settlement_pending",
        "lightning_paid",
        "provider_funding_broadcast",
        "provider_destination_broadcast",
        "provider_claim_pending",
        "provider_claimed",
        "provider_source_claim_pending",
        "provider_source_claimed",
        "provider_refund_prepared",
        "provider_refund_pending",
        "provider_refunded",
        "provider_destination_refund_prepared",
        "provider_destination_refund_pending",
        "provider_destination_refunded",
        "invoice_cancel_pending",
        "invoice_cancelled",
    ];
    match role {
        ParticipantRole::Requester => requester.contains(&state),
        ParticipantRole::Provider => provider.contains(&state),
    }
}

fn base_state_for(state: &str) -> Option<&'static str> {
    if state == "accepted" {
        Some("accepted")
    } else if state.ends_with("terms_ready")
        || state.ends_with("verified")
        || state == "requester_verification_passed"
        || state == "hold_invoice_ready"
    {
        Some("awaiting_input")
    } else if matches!(state, "funding_required" | "source_funding_required") {
        Some("funding_required")
    } else if state.ends_with("funding_broadcast") || state.ends_with("funding_observed") {
        Some("funding_observed")
    } else if matches!(
        state,
        "lightning_settlement_pending" | "provider_source_claim_pending"
    ) {
        Some("settlement_pending")
    } else if state.ends_with("funding_final")
        || state.ends_with("payment_pending")
        || state.ends_with("htlcs_held")
        || state.ends_with("claim_pending")
        || state.ends_with("claimed")
        || state == "cooperative_signing_pending"
    {
        Some("executing")
    } else if matches!(state, "completed" | "lightning_paid") {
        Some("completed")
    } else if state == "cancelled" {
        Some("cancelled")
    } else if state == "expired" {
        Some("expired")
    } else if state.ends_with("refund_prepared")
        || state.ends_with("refund_pending")
        || state == "invoice_cancel_pending"
        || state == "refund_prepared"
    {
        Some("refund_pending")
    } else if state == "refunded" || state.ends_with("refunded") || state == "invoice_cancelled" {
        Some("refunded")
    } else if state == "disputed" {
        Some("disputed")
    } else if matches!(state, "failed" | "unresolved") {
        Some("failed")
    } else {
        None
    }
}

fn swp_profile_support() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }]
}

pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>, SwapClientError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), SwapClientError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| {
                    SwapClientError::new(
                        "swp_contract_digest_mismatch",
                        format!("could not encode contract string: {error}"),
                    )
                })?
                .as_bytes(),
        ),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(SwapClientError::new(
                    "swp_contract_digest_mismatch",
                    "contract digest input contains a non-integer JSON number",
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut members = values.iter().collect::<Vec<_>>();
            members.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, (name, value)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(name)
                        .map_err(|error| {
                            SwapClientError::new(
                                "swp_contract_digest_mismatch",
                                format!("could not encode contract member: {error}"),
                            )
                        })?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn reject_custody_material(value: &Value) -> Result<(), SwapClientError> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                let public_protocol_member = matches!(
                    normalized.as_str(),
                    "preimagerecoveryref" | "credentialexposure"
                );
                let contains_custody_name = !public_protocol_member
                    && [
                        "seed",
                        "preimage",
                        "privatekey",
                        "spendkey",
                        "claimkey",
                        "refundkey",
                        "macaroon",
                        "credential",
                    ]
                    .iter()
                    .any(|forbidden| normalized.contains(forbidden));
                if contains_custody_name
                    || matches!(
                        normalized.as_str(),
                        "mnemonic"
                            | "xprv"
                            | "claimsecret"
                            | "refundsecret"
                            | "nwc"
                            | "nwcstring"
                            | "nwcconnectionstring"
                            | "nwcuri"
                            | "bearertoken"
                            | "walletrpcpayload"
                            | "musigsecretnonce"
                            | "privkey"
                            | "secretkey"
                            | "secretnonce"
                            | "signingnonce"
                    )
                {
                    return Err(SwapClientError::new(
                        "swp_secret_material_forbidden",
                        format!("forbidden custody member {name:?}"),
                    ));
                }
                reject_custody_material(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_custody_material(child)?;
            }
        }
        Value::String(string)
            if string.starts_with("nostr+walletconnect://")
                || string.starts_with("xprv")
                || string.starts_with("tprv") =>
        {
            return Err(SwapClientError::new(
                "swp_secret_material_forbidden",
                "forbidden custody value",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn object<'a>(value: &'a Value, subject: &str) -> Result<&'a Map<String, Value>, SwapClientError> {
    value.as_object().ok_or_else(|| {
        SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("{subject} must be an object"),
        )
    })
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    expected: Option<&str>,
    code: &'static str,
) -> Result<&'a str, SwapClientError> {
    let value = object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| SwapClientError::new(code, format!("{name} must be a string")))?;
    if expected.is_some_and(|expected| value != expected) {
        return Err(SwapClientError::new(
            code,
            format!("{name} has an unexpected value"),
        ));
    }
    Ok(value)
}

fn require_role(object: &Map<String, Value>, name: &str) -> Result<(), SwapClientError> {
    if matches!(
        object.get(name).and_then(Value::as_str),
        Some("requester" | "provider")
    ) {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_exit_package_unusable",
            format!("{name} is not a participant role"),
        ))
    }
}

fn required_u32(object: &Map<String, Value>, name: &str) -> Result<u32, SwapClientError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            SwapClientError::new("swp_exit_package_unusable", format!("{name} must be a u32"))
        })
}

fn required_i32(object: &Map<String, Value>, name: &str) -> Result<i32, SwapClientError> {
    object
        .get(name)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                format!("{name} must be an i32"),
            )
        })
}

fn validate_positive(values: &[u32]) -> Result<(), SwapClientError> {
    if values.iter().all(|value| *value > 0) {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_timeout_ladder_unsafe",
            "timeout safety margins must be positive",
        ))
    }
}

fn canonical_amount(value: &str) -> Result<u64, SwapClientError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(SwapClientError::new(
            "swp_invalid_amount",
            "amount is not a canonical decimal string",
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| SwapClientError::new("swp_invalid_amount", "amount exceeds u64"))
}

#[cfg(feature = "mkt-swp-fixture-probe")]
#[doc(hidden)]
pub mod fixture_replay {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::market::MarketSigner;

    const MANIFEST: &str = include_str!("../../../tests/fixtures/nipmkt/swp-client-engine-v1.json");
    const FULL_SESSION_FIXTURES: &str =
        include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");
    const REQUESTER_API_FIXTURE: &str =
        include_str!("../../../tests/fixtures/nipmkt/swp-requester-api-v2.json");
    const REQUESTER_API_SOURCE: &str =
        include_str!("../../../tests/fixtures/nipmkt/swp-requester-api-source-v2.json");
    const SECTIONS: [&str; 8] = [
        "record_construction",
        "flows",
        "flow_topologies",
        "verify_before_fund",
        "sequencing",
        "external_effects",
        "recovery",
        "lifecycle",
    ];
    const CASE_NAMESET_SHA256: &str =
        "b33c5547a211da6ab7d202c8e7fa959ad13dab1d137c3a68cfbb86b4cffd9325";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReplaySummary {
        pub cases: usize,
        pub custody_tripwires: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ReplayFailure {
        code: u32,
        message: String,
    }

    impl ReplayFailure {
        pub const fn code(&self) -> u32 {
            self.code
        }

        fn new(code: u32, message: impl Into<String>) -> Self {
            Self {
                code,
                message: message.into(),
            }
        }
    }

    impl std::fmt::Display for ReplayFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl std::error::Error for ReplayFailure {}

    pub fn replay_embedded_manifest() -> Result<ReplaySummary, ReplayFailure> {
        replay_manifest_bytes(MANIFEST.as_bytes())
    }

    pub fn replay_requester_api_fixture() -> Result<(), ReplayFailure> {
        replay_requester_api_fixture_bytes(REQUESTER_API_FIXTURE.as_bytes())
    }

    #[doc(hidden)]
    pub fn replay_requester_api_fixture_bytes(bytes: &[u8]) -> Result<(), ReplayFailure> {
        let fixture: Value = serde_json::from_slice(bytes)
            .map_err(|error| ReplayFailure::new(70, format!("requester API JSON: {error}")))?;
        if fixture.get("schema").and_then(Value::as_str)
            != Some("openagents.mkt-swp.requester-api-fixture.v2")
        {
            return Err(ReplayFailure::new(
                71,
                "requester API schema is unsupported",
            ));
        }
        let operations = fixture
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplayFailure::new(72, "requester API operations are missing"))?;
        let operation_names = operations
            .iter()
            .filter_map(|operation| operation.get("name").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        if operation_names
            != BTreeSet::from([
                "requester_contract",
                "requester_contract_draft",
                "requester_order",
                "requester_session_view",
                "requester_session_view_from_snapshot",
            ])
        {
            return Err(ReplayFailure::new(
                73,
                "requester API operation set changed without a fixture version",
            ));
        }
        let definitions = fixture
            .get("$defs")
            .and_then(Value::as_object)
            .ok_or_else(|| ReplayFailure::new(74, "requester API definitions are missing"))?;
        for schema in definitions.values() {
            validate_requester_api_schema_shapes(schema, definitions)?;
        }
        for operation in operations {
            for member in ["input_schema", "output_schema", "error_schema"] {
                validate_requester_api_schema_shapes(
                    operation.get(member).unwrap_or(&Value::Null),
                    definitions,
                )?;
            }
        }
        let operation_schemas = operations
            .iter()
            .filter_map(|operation| {
                operation
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|name| (name, operation))
            })
            .collect::<BTreeMap<_, _>>();
        let source = fixture
            .get("source_fixture")
            .and_then(Value::as_object)
            .ok_or_else(|| ReplayFailure::new(75, "requester API source fixture is missing"))?;
        if source.get("path").and_then(Value::as_str)
            != Some("tests/fixtures/nipmkt/swp-full-sessions-v1.json")
            || source.get("sha256").and_then(Value::as_str)
                != Some(lower_hex(&Sha256::digest(FULL_SESSION_FIXTURES.as_bytes())).as_str())
        {
            return Err(ReplayFailure::new(
                76,
                "requester API source fixture digest differs from the embedded bytes",
            ));
        }
        let source_fixture: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
            .map_err(|error| ReplayFailure::new(76, format!("source fixture JSON: {error}")))?;
        let api_source = fixture
            .get("requester_api_source")
            .and_then(Value::as_object)
            .ok_or_else(|| ReplayFailure::new(76, "requester API v2 source is missing"))?;
        if api_source.get("path").and_then(Value::as_str)
            != Some("tests/fixtures/nipmkt/swp-requester-api-source-v2.json")
            || api_source.get("sha256").and_then(Value::as_str)
                != Some(lower_hex(&Sha256::digest(REQUESTER_API_SOURCE.as_bytes())).as_str())
        {
            return Err(ReplayFailure::new(
                76,
                "requester API v2 source digest differs from the embedded bytes",
            ));
        }
        let api_source_fixture: Value = serde_json::from_str(REQUESTER_API_SOURCE)
            .map_err(|error| ReplayFailure::new(76, format!("API source fixture JSON: {error}")))?;
        if api_source_fixture != generate_requester_api_v2_source()? {
            return Err(ReplayFailure::new(
                76,
                "requester API v2 source differs from the executable generator",
            ));
        }
        replay_requester_api_byte_parity(&api_source_fixture)?;
        let cases = fixture
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplayFailure::new(77, "requester API cases are missing"))?;
        let mut positive_operations = BTreeSet::new();
        let mut negative_operations = BTreeSet::new();
        let mut case_names = BTreeSet::new();
        for case in cases {
            let case = case
                .as_object()
                .ok_or_else(|| ReplayFailure::new(77, "requester API case is not an object"))?;
            let name = case
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| ReplayFailure::new(78, "requester API case has no name"))?;
            if !case_names.insert(name) {
                return Err(ReplayFailure::new(
                    79,
                    "requester API case name is duplicated",
                ));
            }
            let operation = case
                .get("operation")
                .and_then(Value::as_str)
                .filter(|operation| operation_names.contains(operation))
                .ok_or_else(|| ReplayFailure::new(80, "requester API case operation is invalid"))?;
            let input = case
                .get("input")
                .ok_or_else(|| ReplayFailure::new(81, "requester API case input is missing"))?;
            let input = resolve_requester_api_value(
                input,
                &fixture,
                &source_fixture,
                &api_source_fixture,
                0,
            )
            .map_err(|error| ReplayFailure::new(81, format!("{name} input: {error}")))?;
            let schemas = operation_schemas.get(operation).ok_or_else(|| {
                ReplayFailure::new(80, "requester API operation schema is missing")
            })?;
            validate_requester_api_instance(
                &input,
                schemas.get("input_schema").unwrap_or(&Value::Null),
                &fixture,
                "$input",
            )
            .map_err(|error| ReplayFailure::new(81, format!("{name}: {error}")))?;
            match replay_requester_api_case(operation, &input)
                .map_err(|error| ReplayFailure::new(82, error))?
            {
                Ok(output) => {
                    positive_operations.insert(operation);
                    validate_requester_api_instance(
                        &output,
                        schemas.get("output_schema").unwrap_or(&Value::Null),
                        &fixture,
                        "$output",
                    )
                    .map_err(|error| ReplayFailure::new(83, format!("{name}: {error}")))?;
                    let expected = case
                        .get("expected_sha256")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ReplayFailure::new(83, "positive requester API case has no digest")
                        })?;
                    let encoded = canonical_json(&output)
                        .map_err(|error| ReplayFailure::new(84, error.to_string()))?;
                    let actual = lower_hex(&Sha256::digest(encoded));
                    if actual != expected {
                        return Err(ReplayFailure::new(
                            85,
                            format!(
                                "requester API case {name} digest is {actual}, expected {expected}"
                            ),
                        ));
                    }
                    match name {
                        "requester-session-view-valid" => {
                            requester_api_assert_exact_delivery(&input, &output, name)?;
                        }
                        "requester-session-terminal-signed-only" => {
                            requester_api_assert_terminal_authority(&input, &output, false, name)?;
                        }
                        "requester-session-terminal-restored-authority" => {
                            requester_api_assert_terminal_authority(&input, &output, true, name)?;
                        }
                        _ => {}
                    }
                }
                Err(error) => {
                    negative_operations.insert(operation);
                    validate_requester_api_instance(
                        &json!({"code":error.code,"detail":error.detail}),
                        schemas.get("error_schema").unwrap_or(&Value::Null),
                        &fixture,
                        "$error",
                    )
                    .map_err(|schema_error| {
                        ReplayFailure::new(86, format!("{name}: {schema_error}"))
                    })?;
                    let expected = case
                        .get("expected_error")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ReplayFailure::new(
                                86,
                                format!("negative requester API case {name} has no error"),
                            )
                        })?;
                    if error.code != expected {
                        return Err(ReplayFailure::new(
                            87,
                            format!(
                                "requester API case {name} returned {}, expected {expected}",
                                error.code
                            ),
                        ));
                    }
                }
            }
        }
        if positive_operations != operation_names || negative_operations != operation_names {
            return Err(ReplayFailure::new(
                88,
                "every requester API operation requires positive and negative replay cases",
            ));
        }
        for required in [
            "requester-session-terminal-signed-only",
            "requester-session-terminal-restored-authority",
            "requester-session-terminal-request-digest-mutation",
            "requester-session-terminal-result-digest-mutation",
            "requester-session-terminal-cardinality-mutation",
            "requester-session-terminal-funding-mutation",
            "requester-session-terminal-funding-omission",
            "requester-order-price-feed-refused",
            "requester-contract-draft-price-feed-refused",
            "requester-contract-price-feed-refused",
            "requester-session-price-feed-refused",
            "requester-snapshot-price-feed-refused",
        ] {
            if !case_names.contains(required) {
                return Err(ReplayFailure::new(
                    88,
                    format!("requester API v2 corpus omits required case {required}"),
                ));
            }
        }
        Ok(())
    }

    fn replay_requester_api_byte_parity(source: &Value) -> Result<(), ReplayFailure> {
        let parity = source
            .get("byte_parity")
            .and_then(Value::as_object)
            .ok_or_else(|| ReplayFailure::new(76, "requester API byte parity is missing"))?;
        let raw = parity
            .get("raw_signed_event_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| ReplayFailure::new(76, "requester API byte parity has no raw hex"))?;
        let raw = decode_hex(raw, "requester API byte parity")
            .map_err(|error| ReplayFailure::new(76, error.to_string()))?;
        if !raw
            .windows("☃".len())
            .any(|window| window == "☃".as_bytes())
        {
            return Err(ReplayFailure::new(
                76,
                "requester API byte parity does not contain multibyte UTF-8",
            ));
        }
        let delivery = SignedRecordDelivery::from_direct(raw.clone(), 100)
            .map_err(|error| ReplayFailure::new(76, error.to_string()))?;
        if parity.get("event_id").and_then(Value::as_str) != Some(delivery.event_id())
            || parity.get("raw_sha256").and_then(Value::as_str)
                != Some(lower_hex(&Sha256::digest(&raw)).as_str())
        {
            return Err(ReplayFailure::new(
                76,
                "requester API multibyte byte parity changed",
            ));
        }
        Ok(())
    }

    fn requester_api_assert_exact_delivery(
        input: &Value,
        output: &Value,
        name: &str,
    ) -> Result<(), ReplayFailure> {
        let expected = requester_api_hex(
            input
                .pointer("/deliveries/0")
                .ok_or_else(|| ReplayFailure::new(85, format!("{name} has no delivery input")))?,
            "raw_signed_event_hex",
        )
        .map_err(|error| ReplayFailure::new(85, format!("{name}: {error}")))?;
        let expected_text = std::str::from_utf8(&expected).map_err(|error| {
            ReplayFailure::new(85, format!("{name} raw delivery is not UTF-8: {error}"))
        })?;
        if !expected_text.contains('\n') || !expected_text.starts_with("{\n  \"sig\"") {
            return Err(ReplayFailure::new(
                85,
                format!("{name} does not exercise noncanonical JSON bytes"),
            ));
        }
        let actual = output
            .pointer("/deliveries/0/raw_signed_event")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplayFailure::new(85, format!("{name} has no raw delivery output")))?
            .iter()
            .map(|byte| {
                byte.as_u64()
                    .and_then(|byte| u8::try_from(byte).ok())
                    .ok_or_else(|| ReplayFailure::new(85, format!("{name} has invalid raw bytes")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if actual != expected {
            return Err(ReplayFailure::new(
                85,
                format!("{name} did not preserve exact raw delivery bytes"),
            ));
        }
        Ok(())
    }

    fn requester_api_assert_terminal_authority(
        input: &Value,
        output: &Value,
        restored: bool,
        name: &str,
    ) -> Result<(), ReplayFailure> {
        if restored {
            let snapshot = requester_api_hex(input, "snapshot_json_hex")
                .map_err(|error| ReplayFailure::new(85, format!("{name}: {error}")))?;
            if !snapshot
                .windows("☃".len())
                .any(|window| window == "☃".as_bytes())
            {
                return Err(ReplayFailure::new(
                    85,
                    format!("{name} does not exercise multibyte snapshot bytes"),
                ));
            }
        }
        let terminal = output
            .get("terminal")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ReplayFailure::new(85, format!("{name} output has no terminal projection"))
            })?;
        if terminal.get("watch_terminal").and_then(Value::as_bool) != Some(restored)
            || terminal
                .get("local_effects_verified")
                .and_then(Value::as_bool)
                != Some(restored)
        {
            return Err(ReplayFailure::new(
                85,
                format!("{name} does not preserve the persisted-authority boundary"),
            ));
        }
        let expected_state = if restored {
            "terminal_verified"
        } else {
            "contract_terms_verified"
        };
        if output
            .pointer("/verification/state")
            .and_then(Value::as_str)
            != Some(expected_state)
        {
            return Err(ReplayFailure::new(
                85,
                format!("{name} has the wrong verification state"),
            ));
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn generate_requester_api_v2_source() -> Result<Value, ReplayFailure> {
        generate_requester_api_v2_source_inner().map_err(|error| ReplayFailure::new(93, error))
    }

    fn generate_requester_api_v2_source_inner() -> Result<Value, String> {
        let terminal = build_terminal_flow("submarine", "completed")?;
        let terminal_snapshot = terminal.persist().map_err(|error| error.to_string())?;
        let mut terminal_snapshot_value: Value = serde_json::from_slice(&terminal_snapshot)
            .map_err(|error| format!("terminal snapshot JSON: {error}"))?;
        terminal_snapshot_value["external_effects"][0]["external_identifier"] =
            Value::String("fixture:multibyte:☃".to_owned());
        let terminal_deliveries = terminal
            .signed_records()
            .iter()
            .map(|event| {
                serde_json::to_vec_pretty(event)
                    .map(|raw_signed_event| {
                        json!({
                            "raw_signed_event_hex":lower_hex(&raw_signed_event),
                            "observed_at":event.created_at,
                            "provenance":"direct",
                        })
                    })
                    .map_err(|error| format!("terminal delivery JSON: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot_hex = |value: &Value| {
            serde_json::to_vec(value)
                .map(|bytes| lower_hex(&bytes))
                .map_err(|error| format!("requester source snapshot JSON: {error}"))
        };

        let mut request_digest_mutated = terminal_snapshot_value.clone();
        request_digest_mutated["external_effects"][0]["request_sha256"] =
            Value::String("f1".repeat(32));
        let rail_effect_id = terminal_snapshot_value["external_effect_requests"]
            .as_array()
            .and_then(|requests| {
                requests
                    .iter()
                    .find(|request| request["request_type"] == "rail_evidence")
            })
            .and_then(|request| request.get("effect_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| "terminal source has no rail evidence request".to_owned())?;
        let mut result_digest_mutated = terminal_snapshot_value.clone();
        let result = result_digest_mutated["external_effects"]
            .as_array_mut()
            .and_then(|effects| {
                effects
                    .iter_mut()
                    .find(|effect| effect["effect_id"] == rail_effect_id)
            })
            .ok_or_else(|| "terminal source has no rail evidence result".to_owned())?;
        result["result_sha256"] = Value::String("f2".repeat(32));
        let mut cardinality_mutated = terminal_snapshot_value.clone();
        cardinality_mutated["external_effect_requests"]
            .as_array_mut()
            .and_then(Vec::pop)
            .ok_or_else(|| "terminal source has no request to omit".to_owned())?;
        let mut funding_mutated = terminal_snapshot_value.clone();
        funding_mutated["funding_request"]["quote_id"] = Value::String("f3".repeat(32));
        let mut funding_missing = terminal_snapshot_value.clone();
        funding_missing["funding_request"] = Value::Null;

        let (base, _) = load_fixture_session("flows", "submarine")?;
        let records = base.signed_records();
        let rfq = records
            .iter()
            .find(|event| event.kind == MKT_RFQ_KIND)
            .ok_or_else(|| "requester source has no RFQ".to_owned())?;
        let quote = records
            .iter()
            .find(|event| event.kind == MKT_QUOTE_KIND)
            .ok_or_else(|| "requester source has no Quote".to_owned())?;
        let requester_contract = records
            .iter()
            .find(|event| {
                event.kind == MKT_SWP_SWAP_CONTRACT_KIND
                    && event.pubkey == base.config().requester_pubkey
            })
            .ok_or_else(|| "requester source has no requester contract".to_owned())?;
        let mut quote_profile: Value = serde_json::from_str(&quote.content)
            .map_err(|error| format!("requester source Quote JSON: {error}"))?;
        quote_profile["mkt_swp"]["terms"]["price_feed"] = json!({
            "url":"https://prices.example.test/btc-usd",
            "value_pointer":"/data/price",
            "observed_value":"6543210",
            "response_sha256":"52".repeat(32),
            "observed_at":100,
            "max_age_seconds":30,
        });
        let factory = SwapRecordFactory::new(base.config().clone())
            .map_err(|error| format!("requester source factory: {error}"))?;
        let provider = fixture_signer(b"provider")?;
        let requester = fixture_signer(b"requester")?;
        let mut parity_tags = rfq.tags.clone();
        let parity_alt = parity_tags
            .iter_mut()
            .find(|tag| tag.name() == Some("alt"))
            .and_then(|tag| tag.0.get_mut(1))
            .ok_or_else(|| "requester byte-parity RFQ has no alt tag".to_owned())?;
        parity_alt.push_str(" ☃");
        let parity_event =
            requester.sign(rfq.created_at, rfq.kind, parity_tags, rfq.content.clone());
        let parity_raw = serde_json::to_vec_pretty(&parity_event)
            .map_err(|error| format!("requester byte-parity event JSON: {error}"))?;
        SignedRecordDelivery::from_direct(parity_raw.clone(), parity_event.created_at)
            .map_err(|error| format!("requester byte-parity delivery: {error}"))?;
        let feed_quote = fixture_signed(
            factory
                .soft_quote(
                    quote.created_at,
                    &fixture_distinct("requester-api", "feed", 0),
                    &rfq.id,
                    1_000,
                    quote_profile["mkt_swp"].clone(),
                )
                .map_err(|error| format!("requester source feed Quote: {error}"))?,
            &provider,
        )?;
        let feed_order = fixture_signed(
            factory
                .order(
                    102,
                    &fixture_distinct("requester-api", "feed", 1),
                    &feed_quote.id,
                    json!({"accepted_quote_id":feed_quote.id}),
                )
                .map_err(|error| format!("requester source feed Order: {error}"))?,
            &requester,
        )?;
        let contract_profile: Value = serde_json::from_str(&requester_contract.content)
            .map_err(|error| format!("requester source contract JSON: {error}"))?;
        let contract = contract_profile["mkt_swp"]["contract"].clone();
        let local_inputs = json!({
            "effect_bindings":contract["effect_bindings"],
            "exit_package_commitments":contract["exit_package_commitments"],
        });
        let feed_records = vec![rfq.clone(), feed_quote.clone(), feed_order.clone()];
        let feed_deliveries = feed_records
            .iter()
            .map(|event| {
                serde_json::to_vec(event)
                    .map(|raw_signed_event| {
                        json!({
                            "raw_signed_event_hex":lower_hex(&raw_signed_event),
                            "observed_at":102,
                            "provenance":"direct",
                        })
                    })
                    .map_err(|error| format!("feed delivery JSON: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let feed_snapshot = json!({
            "schema":SNAPSHOT_SCHEMA,
            "config":base.config(),
            "signed_records":feed_records,
            "exit_packages":[],
            "external_effects":[],
            "external_effect_requests":[],
            "funding_request":null,
        });

        Ok(json!({
            "schema":"openagents.mkt-swp.requester-api-source.v2",
            "byte_parity":{
                "raw_signed_event_hex":lower_hex(&parity_raw),
                "event_id":parity_event.id,
                "raw_sha256":lower_hex(&Sha256::digest(&parity_raw)),
            },
            "terminal":{
                "config":terminal.config(),
                "records":terminal.signed_records(),
                "deliveries":terminal_deliveries,
                "snapshot_json_hex":snapshot_hex(&terminal_snapshot_value)?,
                "request_digest_mutated_hex":snapshot_hex(&request_digest_mutated)?,
                "result_digest_mutated_hex":snapshot_hex(&result_digest_mutated)?,
                "cardinality_mutated_hex":snapshot_hex(&cardinality_mutated)?,
                "funding_mutated_hex":snapshot_hex(&funding_mutated)?,
                "funding_missing_hex":snapshot_hex(&funding_missing)?,
            },
            "feed":{
                "config":base.config(),
                "rfq":rfq,
                "quote":feed_quote,
                "order":feed_order,
                "contract":contract,
                "local_inputs":local_inputs,
                "records":feed_records,
                "deliveries":feed_deliveries,
                "snapshot_json_hex":snapshot_hex(&feed_snapshot)?,
            },
        }))
    }

    fn validate_requester_api_schema_shapes(
        value: &Value,
        definitions: &serde_json::Map<String, Value>,
    ) -> Result<(), ReplayFailure> {
        let object = value
            .as_object()
            .ok_or_else(|| ReplayFailure::new(89, "requester API schema is not an object"))?;
        const SUPPORTED: [&str; 16] = [
            "$ref",
            "type",
            "required",
            "properties",
            "additionalProperties",
            "minItems",
            "maxItems",
            "items",
            "minLength",
            "maxLength",
            "pattern",
            "minimum",
            "maximum",
            "const",
            "enum",
            "anyOf",
        ];
        for name in object.keys() {
            if !SUPPORTED.contains(&name.as_str()) && name != "oneOf" {
                return Err(ReplayFailure::new(
                    89,
                    format!("requester API schema keyword {name} is unsupported"),
                ));
            }
        }
        if object.contains_key("$ref") && object.len() != 1 {
            return Err(ReplayFailure::new(
                89,
                "requester API $ref schema contains ignored siblings",
            ));
        }
        for combinator in ["anyOf", "oneOf"] {
            if object.contains_key(combinator) && object.len() != 1 {
                return Err(ReplayFailure::new(
                    89,
                    format!("requester API {combinator} schema contains ignored siblings"),
                ));
            }
        }
        if object.contains_key("anyOf") && object.contains_key("oneOf") {
            return Err(ReplayFailure::new(
                89,
                "requester API schema mixes anyOf and oneOf",
            ));
        }
        if object.contains_key("$ref") && object.get("$ref").and_then(Value::as_str).is_none() {
            return Err(ReplayFailure::new(89, "requester API $ref is not a string"));
        }
        if object.contains_key("type")
            && !object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "object" | "array" | "string" | "integer" | "boolean" | "null"
                    )
                })
        {
            return Err(ReplayFailure::new(
                89,
                "requester API schema uses an unsupported type",
            ));
        }
        if !object.keys().any(|name| {
            matches!(
                name.as_str(),
                "$ref" | "type" | "const" | "enum" | "anyOf" | "oneOf"
            )
        }) {
            return Err(ReplayFailure::new(
                89,
                "requester API schema has no assertion",
            ));
        }
        if let Some(required) = object.get("required") {
            let required = required
                .as_array()
                .ok_or_else(|| ReplayFailure::new(89, "requester API required is not an array"))?;
            let names = required
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if names.len() != required.len()
                || names.iter().enumerate().any(|(index, name)| {
                    names
                        .iter()
                        .skip(index.saturating_add(1))
                        .any(|other| other == name)
                })
            {
                return Err(ReplayFailure::new(
                    89,
                    "requester API required members are invalid or duplicated",
                ));
            }
        }
        if let Some(values) = object.get("enum")
            && values.as_array().is_none_or(Vec::is_empty)
        {
            return Err(ReplayFailure::new(
                89,
                "requester API enum is empty or invalid",
            ));
        }
        if let Some(pattern) = object.get("pattern") {
            let pattern = pattern
                .as_str()
                .ok_or_else(|| ReplayFailure::new(89, "requester API pattern is not a string"))?;
            requester_api_pattern_matches("", pattern)
                .map_err(|error| ReplayFailure::new(89, error))?;
        }
        for (minimum, maximum, label) in [
            ("minItems", "maxItems", "array"),
            ("minLength", "maxLength", "string"),
        ] {
            let lower = match object.get(minimum) {
                Some(value) => Some(value.as_u64().ok_or_else(|| {
                    ReplayFailure::new(89, format!("requester API {minimum} is invalid"))
                })?),
                None => None,
            };
            let upper = match object.get(maximum) {
                Some(value) => Some(value.as_u64().ok_or_else(|| {
                    ReplayFailure::new(89, format!("requester API {maximum} is invalid"))
                })?),
                None => None,
            };
            if lower.zip(upper).is_some_and(|(lower, upper)| lower > upper) {
                return Err(ReplayFailure::new(
                    89,
                    format!("requester API {label} bounds are inverted"),
                ));
            }
        }
        if object.get("type").and_then(Value::as_str) == Some("object")
            && (object
                .get("properties")
                .and_then(Value::as_object)
                .is_none()
                || object.get("additionalProperties").and_then(Value::as_bool) != Some(false))
        {
            return Err(ReplayFailure::new(
                89,
                "requester API object schema is generic or open",
            ));
        }
        if object.get("type").and_then(Value::as_str) == Some("array")
            && (!object.contains_key("items")
                || object.get("maxItems").and_then(Value::as_u64).is_none())
        {
            return Err(ReplayFailure::new(
                90,
                "requester API array schema has no item schema or maximum bound",
            ));
        }
        if object.get("type").and_then(Value::as_str) == Some("string")
            && object.get("maxLength").and_then(Value::as_u64).is_none()
            && !object.contains_key("const")
            && !object.contains_key("enum")
        {
            return Err(ReplayFailure::new(
                90,
                "requester API string schema has no maximum bound",
            ));
        }
        if object.get("type").and_then(Value::as_str) == Some("integer")
            && (object.get("minimum").and_then(Value::as_i64).is_none()
                || object.get("maximum").and_then(Value::as_i64).is_none())
        {
            return Err(ReplayFailure::new(
                90,
                "requester API integer schema is unbounded",
            ));
        }
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let name = reference.strip_prefix("#/$defs/").ok_or_else(|| {
                ReplayFailure::new(91, "requester API schema reference is not local")
            })?;
            if !definitions.contains_key(name) {
                return Err(ReplayFailure::new(
                    92,
                    "requester API schema reference is unresolved",
                ));
            }
        }
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            for child in properties.values() {
                validate_requester_api_schema_shapes(child, definitions)?;
            }
        }
        if let Some(items) = object.get("items") {
            validate_requester_api_schema_shapes(items, definitions)?;
        }
        for combinator in ["anyOf", "oneOf"] {
            if let Some(options) = object.get(combinator) {
                let options = options
                    .as_array()
                    .filter(|options| !options.is_empty())
                    .ok_or_else(|| {
                        ReplayFailure::new(89, format!("requester API {combinator} is empty"))
                    })?;
                for option in options {
                    validate_requester_api_schema_shapes(option, definitions)?;
                }
            }
        }
        Ok(())
    }

    fn resolve_requester_api_value(
        value: &Value,
        artifact: &Value,
        source: &Value,
        api_source: &Value,
        depth: usize,
    ) -> Result<Value, String> {
        if depth > 64 {
            return Err("requester API fixture reference depth exceeds its bound".to_owned());
        }
        match value {
            Value::Object(object) => {
                if object.len() == 1 {
                    if let Some(pointer) = object.get("$artifact_ref").and_then(Value::as_str) {
                        let referenced = fixture_pointer(artifact, pointer, "$artifact_ref")?;
                        return resolve_requester_api_value(
                            referenced,
                            artifact,
                            source,
                            api_source,
                            depth + 1,
                        );
                    }
                    if let Some(pointer) = object.get("$artifact_json_ref").and_then(Value::as_str)
                    {
                        let referenced = fixture_pointer(artifact, pointer, "$artifact_json_ref")?;
                        let resolved = resolve_requester_api_value(
                            referenced,
                            artifact,
                            source,
                            api_source,
                            depth + 1,
                        )?;
                        return serde_json::to_string(&resolved)
                            .map(Value::String)
                            .map_err(|error| format!("artifact JSON cannot encode: {error}"));
                    }
                    if let Some(pointer) =
                        object.get("$artifact_json_hex_ref").and_then(Value::as_str)
                    {
                        let referenced =
                            fixture_pointer(artifact, pointer, "$artifact_json_hex_ref")?;
                        let resolved = resolve_requester_api_value(
                            referenced,
                            artifact,
                            source,
                            api_source,
                            depth + 1,
                        )?;
                        let encoded = serde_json::to_vec(&resolved)
                            .map_err(|error| format!("artifact JSON cannot encode: {error}"))?;
                        return Ok(Value::String(lower_hex(&encoded)));
                    }
                    if let Some(pointer) = object.get("$fixture_ref").and_then(Value::as_str) {
                        return Ok(fixture_pointer(source, pointer, "$fixture_ref")?.clone());
                    }
                    if let Some(pointer) = object.get("$fixture_json_ref").and_then(Value::as_str) {
                        return serde_json::to_string(fixture_pointer(
                            source,
                            pointer,
                            "$fixture_json_ref",
                        )?)
                        .map(Value::String)
                        .map_err(|error| format!("fixture snapshot JSON cannot encode: {error}"));
                    }
                    if let Some(pointer) =
                        object.get("$fixture_json_hex_ref").and_then(Value::as_str)
                    {
                        let encoded = serde_json::to_vec(fixture_pointer(
                            source,
                            pointer,
                            "$fixture_json_hex_ref",
                        )?)
                        .map_err(|error| format!("fixture JSON cannot encode: {error}"))?;
                        return Ok(Value::String(lower_hex(&encoded)));
                    }
                    if let Some(pointer) = object.get("$api_source_ref").and_then(Value::as_str) {
                        return Ok(fixture_pointer(api_source, pointer, "$api_source_ref")?.clone());
                    }
                }
                if let Some(event_pointer) =
                    object.get("$fixture_content_ref").and_then(Value::as_str)
                {
                    if object.keys().any(|name| {
                        !matches!(name.as_str(), "$fixture_content_ref" | "pointer" | "merge")
                    }) {
                        return Err(
                            "fixture content reference contains an unknown member".to_owned()
                        );
                    }
                    let event = fixture_pointer(source, event_pointer, "$fixture_content_ref")?;
                    let content =
                        event
                            .get("content")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                "fixture content reference is not a Nostr event".to_owned()
                            })?;
                    let content: Value = serde_json::from_str(content)
                        .map_err(|error| format!("fixture event content is invalid: {error}"))?;
                    let pointer = object
                        .get("pointer")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "fixture content reference has no pointer".to_owned())?;
                    let mut selected = content
                        .pointer(pointer)
                        .ok_or_else(|| format!("content pointer {pointer:?} does not resolve"))?
                        .clone();
                    if let Some(merge) = object.get("merge") {
                        let selected = selected.as_object_mut().ok_or_else(|| {
                            "fixture content merge target is not an object".to_owned()
                        })?;
                        let merge = merge.as_object().ok_or_else(|| {
                            "fixture content merge value is not an object".to_owned()
                        })?;
                        for (name, child) in merge {
                            selected.insert(name.clone(), child.clone());
                        }
                    }
                    return Ok(selected);
                }
                object
                    .iter()
                    .map(|(name, child)| {
                        resolve_requester_api_value(child, artifact, source, api_source, depth + 1)
                            .map(|child| (name.clone(), child))
                    })
                    .collect::<Result<serde_json::Map<_, _>, _>>()
                    .map(Value::Object)
            }
            Value::Array(values) => values
                .iter()
                .map(|child| {
                    resolve_requester_api_value(child, artifact, source, api_source, depth + 1)
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            _ => Ok(value.clone()),
        }
    }

    fn fixture_pointer<'a>(
        document: &'a Value,
        pointer: &str,
        label: &str,
    ) -> Result<&'a Value, String> {
        let pointer = pointer
            .strip_prefix('#')
            .ok_or_else(|| format!("{label} must be a document-local RFC 6901 pointer"))?;
        document
            .pointer(pointer)
            .ok_or_else(|| format!("{label} pointer {pointer:?} does not resolve"))
    }

    fn validate_requester_api_instance(
        value: &Value,
        schema: &Value,
        root: &Value,
        path: &str,
    ) -> Result<(), String> {
        let schema = schema
            .as_object()
            .ok_or_else(|| format!("{path} schema is not an object"))?;
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let resolved = fixture_pointer(root, reference, "schema $ref")?;
            return validate_requester_api_instance(value, resolved, root, path);
        }
        if let Some(options) = schema.get("anyOf").and_then(Value::as_array) {
            if options
                .iter()
                .any(|option| validate_requester_api_instance(value, option, root, path).is_ok())
            {
                return Ok(());
            }
            return Err(format!("{path} does not match any allowed schema"));
        }
        if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
            let matches = options
                .iter()
                .filter(|option| validate_requester_api_instance(value, option, root, path).is_ok())
                .count();
            if matches != 1 {
                return Err(format!(
                    "{path} matches {matches} schemas where exactly one is required"
                ));
            }
            return Ok(());
        }
        if let Some(expected) = schema.get("const")
            && value != expected
        {
            return Err(format!("{path} differs from its constant"));
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array)
            && !values.contains(value)
        {
            return Err(format!("{path} is outside its enumeration"));
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("object") => {
                let object = value
                    .as_object()
                    .ok_or_else(|| format!("{path} is not an object"))?;
                let properties = schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .ok_or_else(|| format!("{path} object schema has no properties"))?;
                if let Some(required) = schema.get("required").and_then(Value::as_array) {
                    for name in required.iter().filter_map(Value::as_str) {
                        if !object.contains_key(name) {
                            return Err(format!("{path} omits required member {name}"));
                        }
                    }
                }
                if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
                    for name in object.keys() {
                        if !properties.contains_key(name) {
                            return Err(format!("{path} contains unknown member {name}"));
                        }
                    }
                }
                for (name, child) in object {
                    if let Some(child_schema) = properties.get(name) {
                        validate_requester_api_instance(
                            child,
                            child_schema,
                            root,
                            &format!("{path}/{name}"),
                        )?;
                    }
                }
            }
            Some("array") => {
                let array = value
                    .as_array()
                    .ok_or_else(|| format!("{path} is not an array"))?;
                let minimum = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
                let maximum = schema
                    .get("maxItems")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("{path} array schema is unbounded"))?;
                let length = u64::try_from(array.len())
                    .map_err(|_| format!("{path} array length does not fit u64"))?;
                if length < minimum || length > maximum {
                    return Err(format!("{path} array length is outside its bounds"));
                }
                let item_schema = schema
                    .get("items")
                    .ok_or_else(|| format!("{path} array schema has no items"))?;
                for (index, child) in array.iter().enumerate() {
                    validate_requester_api_instance(
                        child,
                        item_schema,
                        root,
                        &format!("{path}/{index}"),
                    )?;
                }
            }
            Some("string") => {
                let string = value
                    .as_str()
                    .ok_or_else(|| format!("{path} is not a string"))?;
                let length = u64::try_from(string.chars().count())
                    .map_err(|_| format!("{path} string length does not fit u64"))?;
                let minimum = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
                let maximum = schema
                    .get("maxLength")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("{path} string schema is unbounded"))?;
                if length < minimum || length > maximum {
                    return Err(format!("{path} string length is outside its bounds"));
                }
                if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
                    && !requester_api_pattern_matches(string, pattern)?
                {
                    return Err(format!("{path} does not match {pattern}"));
                }
            }
            Some("integer") => {
                let integer = value
                    .as_i64()
                    .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
                    .ok_or_else(|| format!("{path} is not a bounded integer"))?;
                if schema
                    .get("minimum")
                    .and_then(Value::as_i64)
                    .is_some_and(|minimum| integer < minimum)
                    || schema
                        .get("maximum")
                        .and_then(Value::as_i64)
                        .is_some_and(|maximum| integer > maximum)
                {
                    return Err(format!("{path} integer is outside its bounds"));
                }
            }
            Some("boolean") if !value.is_boolean() => {
                return Err(format!("{path} is not a boolean"));
            }
            Some("null") if !value.is_null() => return Err(format!("{path} is not null")),
            Some("boolean" | "null") | None => {}
            Some(other) => return Err(format!("{path} uses unsupported schema type {other}")),
        }
        Ok(())
    }

    fn requester_api_pattern_matches(value: &str, pattern: &str) -> Result<bool, String> {
        let lower_hex = |value: &str| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        };
        match pattern {
            "^[0-9a-f]{64}$" => Ok(value.len() == 64 && lower_hex(value)),
            "^[0-9a-f]{128}$" => Ok(value.len() == 128 && lower_hex(value)),
            "^(0|[1-9][0-9]*)$" => Ok(value == "0"
                || value
                    .strip_prefix(|character: char| matches!(character, '1'..='9'))
                    .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))),
            "^[0-9a-f]+$" => Ok(!value.is_empty() && lower_hex(value)),
            "^([0-9a-f]{2})+$" => Ok(!value.is_empty() && value.len() % 2 == 0 && lower_hex(value)),
            "^(02|03)[0-9a-f]{64}$" => Ok(value.len() == 66
                && matches!(&value[..2], "02" | "03")
                && lower_hex(&value[2..])),
            "^bip122:[0-9a-f]{32}$" => Ok(value
                .strip_prefix("bip122:")
                .is_some_and(|suffix| suffix.len() == 32 && lower_hex(suffix))),
            "^https://" => Ok(value.starts_with("https://")),
            "^swp:1:" => Ok(value.starts_with("swp:1:")),
            _ => Err(format!(
                "requester API schema uses unsupported pattern {pattern}"
            )),
        }
    }

    fn replay_requester_api_case(
        operation: &str,
        input: &Value,
    ) -> Result<Result<Value, SwapClientError>, String> {
        let outcome = match operation {
            "requester_order" => {
                let config: SwapClientConfig = requester_api_input(input, "config")?;
                let rfq: Event = requester_api_input(input, "rfq")?;
                let quote: Event = requester_api_input(input, "quote")?;
                let factory = SwapRecordFactory::new(config).map_err(|error| error.to_string())?;
                let selection = input.get("selection").and_then(Value::as_object).cloned();
                factory
                    .requester_order(RequesterOrderInput {
                        rfq: &rfq,
                        quote: &quote,
                        created_at: requester_api_u64(input, "created_at")?,
                        observed_at: requester_api_u64(input, "observed_at")?,
                        distinct: requester_api_str(input, "distinct")?,
                        selection,
                    })
                    .and_then(requester_api_json)
            }
            "requester_contract_draft" => {
                let config: SwapClientConfig = requester_api_input(input, "config")?;
                let rfq: Event = requester_api_input(input, "rfq")?;
                let quote: Event = requester_api_input(input, "quote")?;
                let order: Event = requester_api_input(input, "order")?;
                let local_inputs: RequesterContractLocalInputs =
                    requester_api_input(input, "local_inputs")?;
                SwapRecordFactory::new(config)
                    .map_err(|error| error.to_string())?
                    .requester_contract_draft(
                        &rfq,
                        &quote,
                        &order,
                        requester_api_u64(input, "order_observed_at")?,
                        local_inputs,
                    )
            }
            "requester_contract" => {
                let config: SwapClientConfig = requester_api_input(input, "config")?;
                let rfq: Event = requester_api_input(input, "rfq")?;
                let quote: Event = requester_api_input(input, "quote")?;
                let order: Event = requester_api_input(input, "order")?;
                let contract = input
                    .get("contract")
                    .cloned()
                    .ok_or_else(|| "requester API input omits contract".to_owned())?;
                SwapRecordFactory::new(config)
                    .map_err(|error| error.to_string())?
                    .requester_contract(RequesterContractSigningInput {
                        rfq: &rfq,
                        quote: &quote,
                        order: &order,
                        order_observed_at: requester_api_u64(input, "order_observed_at")?,
                        created_at: requester_api_u64(input, "created_at")?,
                        distinct: requester_api_str(input, "distinct")?,
                        contract,
                    })
                    .and_then(requester_api_json)
            }
            "requester_session_view" => {
                let config: SwapClientConfig = requester_api_input(input, "config")?;
                let records: Vec<Event> = requester_api_input(input, "records")?;
                let deliveries = requester_api_input_deliveries(input)?;
                RequesterSessionView::from_signed_records(&config, &records, deliveries)
                    .and_then(requester_api_json)
            }
            "requester_session_view_from_snapshot" => {
                let snapshot = requester_api_hex(input, "snapshot_json_hex")?;
                let deliveries = requester_api_input_deliveries(input)?;
                RequesterSessionView::from_restored_snapshot(&snapshot, deliveries)
                    .and_then(requester_api_json)
            }
            _ => return Err(format!("unsupported requester API operation {operation}")),
        };
        Ok(outcome)
    }

    fn requester_api_input<T: serde::de::DeserializeOwned>(
        input: &Value,
        name: &str,
    ) -> Result<T, String> {
        serde_json::from_value(
            input
                .get(name)
                .cloned()
                .ok_or_else(|| format!("requester API input omits {name}"))?,
        )
        .map_err(|error| format!("requester API input {name} is invalid: {error}"))
    }

    fn requester_api_u64(input: &Value, name: &str) -> Result<u64, String> {
        input
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("requester API input {name} is not a u64"))
    }

    fn requester_api_str<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
        input
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("requester API input {name} is not a string"))
    }

    fn requester_api_hex(input: &Value, name: &str) -> Result<Vec<u8>, String> {
        decode_hex(requester_api_str(input, name)?, name).map_err(|error| error.to_string())
    }

    fn requester_api_input_deliveries(input: &Value) -> Result<Vec<SignedRecordDelivery>, String> {
        input
            .get("deliveries")
            .and_then(Value::as_array)
            .ok_or_else(|| "requester API input deliveries are not an array".to_owned())?
            .iter()
            .map(|delivery| {
                let raw = requester_api_hex(delivery, "raw_signed_event_hex")?;
                let observed_at = delivery
                    .get("observed_at")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "requester delivery observation is invalid".to_owned())?;
                SignedRecordDelivery::from_direct(raw, observed_at)
                    .map_err(|error| error.to_string())
            })
            .collect()
    }

    fn requester_api_json<T: Serialize>(value: T) -> Result<Value, SwapClientError> {
        serde_json::to_value(value).map_err(|error| {
            SwapClientError::new(
                "swp_contract_terms_mismatch",
                format!("requester API output encoding failed: {error}"),
            )
        })
    }

    #[doc(hidden)]
    pub fn replay_manifest_bytes(manifest: &[u8]) -> Result<ReplaySummary, ReplayFailure> {
        let manifest: Value = serde_json::from_slice(manifest)
            .map_err(|error| ReplayFailure::new(10, format!("manifest JSON: {error}")))?;
        if manifest.get("schema").and_then(Value::as_str)
            != Some("openagents.mkt-swp.client-engine-fixtures.v1")
        {
            return Err(ReplayFailure::new(11, "manifest schema is unsupported"));
        }
        replay_deterministic_artifacts(&manifest).map_err(|error| ReplayFailure::new(20, error))?;
        let mut names = BTreeSet::new();
        let mut flow_outcomes = BTreeSet::new();
        let mut cases = 0_usize;
        for section in SECTIONS {
            let entries = manifest
                .get(section)
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    ReplayFailure::new(30, format!("manifest section {section} is missing"))
                })?;
            for entry in entries {
                let name = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ReplayFailure::new(31, format!("{section} case has no name")))?;
                if !name.starts_with("swp-v1-") || !names.insert(name.to_owned()) {
                    return Err(ReplayFailure::new(
                        32,
                        format!("fixture case name is invalid or duplicated: {name}"),
                    ));
                }
                replay_case(section, entry, &mut flow_outcomes)
                    .map_err(|error| ReplayFailure::new(33, error))?;
                cases = cases
                    .checked_add(1)
                    .ok_or_else(|| ReplayFailure::new(34, "fixture case count overflowed"))?;
            }
        }
        let expected_flows = ["submarine", "reverse", "chain"]
            .into_iter()
            .flat_map(|swap_type| {
                ["completed", "refunded"]
                    .into_iter()
                    .map(move |outcome| (swap_type.to_owned(), outcome.to_owned()))
            })
            .collect::<BTreeSet<_>>();
        if flow_outcomes != expected_flows {
            return Err(ReplayFailure::new(
                40,
                "fixture flows do not replay all completed/refunded topologies",
            ));
        }
        let mut name_bytes = Vec::new();
        for name in &names {
            name_bytes.extend_from_slice(name.as_bytes());
            name_bytes.push(0);
        }
        if lower_hex(&sha256(&name_bytes)) != CASE_NAMESET_SHA256 {
            return Err(ReplayFailure::new(
                50,
                "fixture contains an unknown, removed, or renamed case",
            ));
        }
        let tripwires = manifest
            .get("custody_tripwires")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplayFailure::new(60, "custody tripwire corpus is missing"))?;
        let mut tripwire_members = BTreeSet::new();
        for tripwire in tripwires {
            let member = tripwire
                .get("member")
                .and_then(Value::as_str)
                .ok_or_else(|| ReplayFailure::new(61, "custody tripwire has no member"))?;
            if member.is_empty() || !tripwire_members.insert(member.to_owned()) {
                return Err(ReplayFailure::new(
                    62,
                    "custody tripwire is empty or duplicated",
                ));
            }
            let expected_error = tripwire
                .get("error")
                .and_then(Value::as_str)
                .ok_or_else(|| ReplayFailure::new(63, "custody tripwire has no error"))?;
            let mut body = serde_json::Map::new();
            body.insert(member.to_owned(), Value::String("forbidden".to_owned()));
            match reject_custody_material(&Value::Object(body)) {
                Err(error) if error.code == expected_error => {}
                Err(error) => {
                    return Err(ReplayFailure::new(
                        64,
                        format!(
                            "custody tripwire {member} returned {}, expected {expected_error}",
                            error.code
                        ),
                    ));
                }
                Ok(()) => {
                    return Err(ReplayFailure::new(
                        65,
                        format!("custody tripwire {member} was accepted"),
                    ));
                }
            }
        }
        Ok(ReplaySummary {
            cases,
            custody_tripwires: tripwire_members.len(),
        })
    }

    fn replay_deterministic_artifacts(manifest: &Value) -> Result<(), String> {
        let deterministic = manifest
            .get("deterministic_session")
            .and_then(Value::as_object)
            .ok_or_else(|| "deterministic session is missing".to_owned())?;
        let invoice_text = deterministic
            .get("invoice")
            .and_then(Value::as_str)
            .ok_or_else(|| "deterministic invoice is missing".to_owned())?;
        let invoice = parse_bolt11(invoice_text).map_err(|error| format!("BOLT11: {error}"))?;
        let payment_hash = deterministic
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "deterministic payment hash is missing".to_owned())?;
        if lower_hex(&invoice.payment_hash) != payment_hash
            || invoice.amount_msat
                != deterministic
                    .get("invoice_amount_msat")
                    .and_then(Value::as_str)
                    .and_then(|amount| amount.parse::<u64>().ok())
        {
            return Err(
                "deterministic invoice does not bind its amount and payment hash".to_owned(),
            );
        }
        let funding = deterministic
            .get("funding_transaction")
            .and_then(Value::as_str)
            .ok_or_else(|| "deterministic funding transaction is missing".to_owned())?;
        let transaction = Transaction::parse(
            &decode_hex(funding, "fixture funding transaction")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("funding transaction: {error}"))?;
        let output_index = deterministic
            .get("funding_output_index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| "deterministic funding output index is invalid".to_owned())?;
        let output = transaction
            .outputs
            .get(output_index)
            .ok_or_else(|| "deterministic funding output is absent".to_owned())?;
        let expected_amount = deterministic
            .get("funding_amount")
            .and_then(Value::as_str)
            .and_then(|amount| amount.parse::<u64>().ok())
            .ok_or_else(|| "deterministic funding amount is invalid".to_owned())?;
        if output.value_sat != expected_amount {
            return Err("deterministic funding amount differs from transaction bytes".to_owned());
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CaseOutcome {
        Result(&'static str),
        Error(&'static str),
        Action(&'static str),
    }

    fn replay_case(
        section: &str,
        entry: &Value,
        flow_outcomes: &mut BTreeSet<(String, String)>,
    ) -> Result<(), String> {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("{section} fixture case is not an object"))?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{section} fixture case has no name"))?;
        let outcome = match section {
            "record_construction" => {
                return Err(format!("{name} has no production replay implementation"));
            }
            "flows" => {
                let swap_type =
                    required_choice(object, "swap_type", &["submarine", "reverse", "chain"])?;
                let terminal = required_choice(object, "terminal", &["completed", "refunded"])?;
                build_terminal_flow(swap_type, terminal)?;
                flow_outcomes.insert((swap_type.to_owned(), terminal.to_owned()));
                return Ok(());
            }
            "flow_topologies" => {
                replay_topology_law(object)?;
                return Ok(());
            }
            "verify_before_fund" => replay_verify_before_fund_case(object)?,
            "sequencing" => replay_sequencing_case(object)?,
            "external_effects" => replay_external_effect_case(object)?,
            "recovery" => replay_recovery_case(object)?,
            "lifecycle" => replay_lifecycle_case(object)?,
            _ => return Err(format!("fixture section {section} is not executable")),
        };
        assert_case_outcome(name, object, outcome)
    }

    fn assert_case_outcome(
        name: &str,
        object: &serde_json::Map<String, Value>,
        actual: CaseOutcome,
    ) -> Result<(), String> {
        let expected = ["result", "error", "action"]
            .into_iter()
            .filter_map(|member| {
                object
                    .get(member)
                    .and_then(Value::as_str)
                    .map(|value| (member, value))
            })
            .collect::<Vec<_>>();
        let [expected] = expected.as_slice() else {
            return Err(format!("{name} has no single executable expectation"));
        };
        let matches = match (expected.0, actual) {
            ("result", CaseOutcome::Result(actual))
            | ("error", CaseOutcome::Error(actual))
            | ("action", CaseOutcome::Action(actual)) => expected.1 == actual,
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(format!(
                "{name} returned {actual:?}, expected {} {}",
                expected.0, expected.1
            ))
        }
    }

    fn error_outcome<T>(result: Result<T, SwapClientError>) -> Result<CaseOutcome, String> {
        match result {
            Ok(_) => Err("negative fixture unexpectedly succeeded".to_owned()),
            Err(error) => Ok(CaseOutcome::Error(error.code)),
        }
    }

    fn replay_topology_law(object: &serde_json::Map<String, Value>) -> Result<(), String> {
        let swap_type = match object.get("swap_type").and_then(Value::as_str) {
            Some("submarine") => SwapType::Submarine,
            Some("reverse") => SwapType::Reverse,
            Some("chain") => SwapType::Chain,
            _ => return Err("topology fixture has an unknown swap type".to_owned()),
        };
        let topology = requester_topology(swap_type);
        let funding = object
            .get("requester_funding")
            .and_then(Value::as_object)
            .ok_or_else(|| "topology fixture has no funding action".to_owned())?;
        let expected_action = match swap_type {
            SwapType::Reverse => "pay_lightning_invoice",
            SwapType::Submarine | SwapType::Chain => "broadcast_bitcoin",
        };
        let declared_exits = object
            .get("requester_exits")
            .and_then(Value::as_array)
            .ok_or_else(|| "topology fixture has no requester exits".to_owned())?
            .iter()
            .map(|exit| {
                let exit = exit
                    .as_object()
                    .ok_or_else(|| "topology exit is not an object".to_owned())?;
                Ok((
                    required_choice(exit, "leg_id", &["source", "destination"])?,
                    required_choice(exit, "path", &["claim", "refund"])?,
                    required_choice(exit, "condition", &["hashlock", "cltv", "csv"])?,
                ))
            })
            .collect::<Result<BTreeSet<_>, String>>()?;
        let executable_exits = topology
            .exits
            .iter()
            .map(|exit| (exit.leg_id, exit.path, exit.condition))
            .collect::<BTreeSet<_>>();
        if funding.get("leg_id").and_then(Value::as_str) != Some(topology.funding_leg_id)
            || funding.get("role").and_then(Value::as_str) != Some(topology.funding_effect_role)
            || funding.get("action").and_then(Value::as_str) != Some(expected_action)
            || declared_exits != executable_exits
        {
            return Err(
                "topology fixture differs from the executable requester topology".to_owned(),
            );
        }
        Ok(())
    }

    fn replay_verify_before_fund_case(
        object: &serde_json::Map<String, Value>,
    ) -> Result<CaseOutcome, String> {
        let mutation = object
            .get("mutation")
            .and_then(Value::as_str)
            .ok_or_else(|| "verify-before-fund case has no mutation".to_owned())?;
        let (group, key) = match mutation {
            "selection_outside" => ("specialized", "selection_outside"),
            "expired_quote" => ("specialized", "expired_quote"),
            "reverse_adapter_missing"
            | "reverse_readiness_mismatch"
            | "reverse_readiness_expired" => ("flows", "reverse"),
            _ => ("flows", "submarine"),
        };
        let (session, mut input) = load_fixture_session(group, key)?;
        match mutation {
            "payment_hash" => {
                input.payment_hash = "ff".repeat(32);
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "taproot_script" => {
                input.funding.taproot_script = "51".to_owned();
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "zero_confirmations" | "replaceable_funding" => {
                let raw_transaction = input.funding.raw_transaction.clone();
                let authorized = session
                    .verify_before_fund(input, |_| Ok(()))
                    .map_err(|error| format!("fixture authorization: {error}"))?;
                error_outcome(
                    authorized.observe_bitcoin_funding_with("source", |request| {
                        if request.transaction_template_sha256
                            != lower_hex(&sha256(
                                &decode_hex(&raw_transaction, "fixture funding transaction")
                                    .map_err(|error| error.to_string())?,
                            ))
                        {
                            return Err("Bitcoin observation request digest differs".to_owned());
                        }
                        Ok(LocalBitcoinObservation {
                            raw_transaction: raw_transaction.clone(),
                            confirmations: u32::from(mutation == "replaceable_funding"),
                            replacement_detected: mutation == "replaceable_funding",
                            competing_spend_detected: false,
                        })
                    }),
                )
            }
            "fund_deadline_reached" => {
                input.timeout_ladder = TimeoutLadder::Submarine {
                    current_height: 110,
                    fund_last: 110,
                    claim_last: 120,
                    refund_first: 140,
                    chain_finality_blocks: 1,
                    broadcast_safety_blocks: 2,
                    reorg_safety_blocks: 6,
                    invoice_expiration_time: 2_000,
                    claim_expected_time: 1_000,
                };
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "amountless_invoice" => {
                let fixture: Value = serde_json::from_str(include_str!(
                    "../../../tests/fixtures/nipmkt/swp-verification.json"
                ))
                .map_err(|error| format!("verification fixture JSON: {error}"))?;
                input
                    .invoice
                    .as_mut()
                    .ok_or_else(|| "submarine fixture has no invoice".to_owned())?
                    .invoice = fixture["bolt11"]["invoice"]
                    .as_str()
                    .ok_or_else(|| "amountless invoice fixture is missing".to_owned())?
                    .to_owned();
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "provider_contract_missing" | "rfq_missing" => {
                let mut records = session.signed_records().to_vec();
                if mutation == "provider_contract_missing" {
                    records.retain(|event| {
                        event.kind != MKT_SWP_SWAP_CONTRACT_KIND
                            || event.pubkey == session.config().requester_pubkey
                    });
                } else {
                    records.retain(|event| event.kind != MKT_RFQ_KIND);
                }
                error_outcome(
                    SwapSession::from_signed_records(
                        session.config().clone(),
                        records,
                        session.exit_packages().to_vec(),
                    )
                    .and_then(|session| session.verify_before_fund(input, |_| Ok(()))),
                )
            }
            "snapshot_seed" => {
                let mut snapshot: Value =
                    serde_json::from_slice(&session.persist().map_err(|error| error.to_string())?)
                        .map_err(|error| format!("fixture snapshot JSON: {error}"))?;
                snapshot
                    .as_object_mut()
                    .ok_or_else(|| "fixture snapshot is not an object".to_owned())?
                    .insert("seed".to_owned(), Value::String("forbidden".to_owned()));
                error_outcome(SwapSession::<AwaitingVerification>::restore(
                    &serde_json::to_vec(&snapshot)
                        .map_err(|error| format!("fixture snapshot JSON: {error}"))?,
                ))
            }
            "selection_outside" | "expired_quote" => {
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "expired_invoice" => {
                let invoice = input
                    .invoice
                    .as_mut()
                    .ok_or_else(|| "submarine fixture has no invoice".to_owned())?;
                invoice.observed_at = invoice.observed_at.saturating_add(1_000_000);
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "minimum_final_cltv" => {
                let invoice = input
                    .invoice
                    .as_mut()
                    .ok_or_else(|| "submarine fixture has no invoice".to_owned())?;
                invoice.required_minimum_final_cltv_delta =
                    invoice.required_minimum_final_cltv_delta.saturating_add(1);
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "funding_amount" => {
                input.funding.expected_amount = "99999".to_owned();
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "invoice_network" => {
                input
                    .invoice
                    .as_mut()
                    .ok_or_else(|| "submarine fixture has no invoice".to_owned())?
                    .expected_network = "testnet".to_owned();
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "exit_package_missing" => {
                let session = SwapSession::from_signed_records(
                    session.config().clone(),
                    session.signed_records().to_vec(),
                    Vec::new(),
                )
                .map_err(|error| format!("exit-free fixture session: {error}"))?;
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "reverse_adapter_missing" => {
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            "reverse_readiness_mismatch" | "reverse_readiness_expired" => {
                error_outcome(session.verify_before_fund_with_lightning(
                    input,
                    |request| {
                        Ok(LocalLightningReadiness {
                            invoice_sha256: request.invoice_sha256.clone(),
                            payment_hash: if mutation == "reverse_readiness_mismatch" {
                                "ff".repeat(32)
                            } else {
                                request.payment_hash.clone()
                            },
                            observed_at: if mutation == "reverse_readiness_expired" {
                                request.invoice_expires_at
                            } else {
                                request.invoice_expires_at.saturating_sub(1)
                            },
                            state: LightningReadinessState::Acceptable,
                        })
                    },
                    |_| Ok(()),
                ))
            }
            "contract_digest_fork"
            | "contract_order_mismatch"
            | "rfq_constraint_weakened"
            | "leg_execution_field" => replay_contract_refusal(session, input, mutation),
            "exit_funding_txid"
            | "exit_hidden_taproot_sibling"
            | "exit_signing_key"
            | "exit_lock_value"
            | "exit_internal_key"
            | "exit_verifier_digest"
            | "recovery_package_unusable"
            | "exit_package_malformed" => replay_exit_package_refusal(mutation),
            "persisted_funding_effect_conflict" => {
                replay_persisted_funding_conflict(session, input)
            }
            "effective_cancel_before_fund" => {
                let session = fixture_effectively_cancelled_session(session)?;
                error_outcome(session.verify_before_fund(input, |_| Ok(())))
            }
            _ => Err(format!("unknown verify-before-fund mutation {mutation}")),
        }
    }

    fn replay_contract_refusal(
        session: SwapSession<AwaitingVerification>,
        input: VerifyBeforeFundInput,
        mutation: &str,
    ) -> Result<CaseOutcome, String> {
        let requester = fixture_signer(b"requester")?;
        let provider = fixture_signer(b"provider")?;
        let factory =
            SwapRecordFactory::new(session.config().clone()).map_err(|error| error.to_string())?;
        let order_id = fixture_order_id(&session)?;
        let quote_id = session
            .signed_records()
            .iter()
            .find(|event| event.kind == MKT_QUOTE_KIND)
            .map(|event| event.id.clone())
            .ok_or_else(|| "fixture session has no Quote".to_owned())?;
        let mut records = session.signed_records().to_vec();
        if mutation == "rfq_constraint_weakened" {
            let index = records
                .iter()
                .position(|event| event.kind == MKT_RFQ_KIND)
                .ok_or_else(|| "fixture session has no RFQ".to_owned())?;
            let original = records[index].clone();
            let mut content = parse_content(&original).map_err(|error| error.to_string())?;
            content["mkt_swp"]["constraints"]["maximum_total_fee"] =
                Value::String("999999".to_owned());
            records[index] = requester.sign(
                original.created_at,
                original.kind,
                original.tags,
                serde_json::to_string(&content)
                    .map_err(|error| format!("mutated RFQ JSON: {error}"))?,
            );
        } else {
            let requester_index = records
                .iter()
                .position(|event| {
                    event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == requester.pubkey()
                })
                .ok_or_else(|| "fixture requester contract is missing".to_owned())?;
            let provider_index = records
                .iter()
                .position(|event| {
                    event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == provider.pubkey()
                })
                .ok_or_else(|| "fixture provider contract is missing".to_owned())?;
            let original = records[requester_index].clone();
            let content = parse_content(&original).map_err(|error| error.to_string())?;
            let contract = content["mkt_swp"]["contract"].clone();
            let (contract, contract_order_id, replace_requester) = match mutation {
                "contract_digest_fork" => {
                    let mut contract = contract;
                    contract["clock_skew_seconds"] = Value::String("61".to_owned());
                    (contract, order_id.clone(), false)
                }
                "contract_order_mismatch" => {
                    let mut contract = contract;
                    let different_order = "ef".repeat(32);
                    contract["order_id"] = Value::String(different_order.clone());
                    (contract, different_order, true)
                }
                "leg_execution_field" => {
                    let mut contract = contract;
                    contract["legs"][0]["refund_lock_value"] = Value::String("141".to_owned());
                    (contract, order_id.clone(), true)
                }
                _ => return Err(format!("unknown contract mutation {mutation}")),
            };
            let make_contract = |role, signer: &MarketSigner, original: &Event| {
                fixture_signed(
                    factory
                        .swap_contract(
                            role,
                            original.created_at,
                            tag_value(original, "d").map_err(|error| error.to_string())?,
                            SwapContractReferences {
                                order_id: &contract_order_id,
                                quote_id: &quote_id,
                                accepted_status_id: None,
                            },
                            contract.clone(),
                        )
                        .map_err(|error| error.to_string())?,
                    signer,
                )
            };
            if replace_requester {
                records[requester_index] =
                    make_contract(ParticipantRole::Requester, &requester, &original)?;
            }
            let original_provider = records[provider_index].clone();
            records[provider_index] =
                make_contract(ParticipantRole::Provider, &provider, &original_provider)?;
        }
        let session = match SwapSession::from_signed_records(
            session.config().clone(),
            records,
            session.exit_packages().to_vec(),
        ) {
            Ok(session) => session,
            Err(error) => return Ok(CaseOutcome::Error(error.code)),
        };
        error_outcome(session.verify_before_fund(input, |_| Ok(())))
    }

    fn replay_exit_package_refusal(mutation: &str) -> Result<CaseOutcome, String> {
        let fixture_key = if matches!(
            mutation,
            "exit_hidden_taproot_sibling"
                | "exit_signing_key"
                | "exit_internal_key"
                | "recovery_package_unusable"
        ) {
            "reverse"
        } else {
            "submarine"
        };
        let (session, input) = load_fixture_session("flows", fixture_key)?;
        let mut document = session
            .exit_packages()
            .first()
            .ok_or_else(|| "fixture session has no exit package".to_owned())?
            .document()
            .clone();
        match mutation {
            "exit_funding_txid" => {
                document["funding"]["transaction_id"] = Value::String("00".repeat(32));
            }
            "exit_hidden_taproot_sibling" => {
                let control = document["verification"]["taproot_control_block"]
                    .as_str()
                    .ok_or_else(|| "fixture exit has no control block".to_owned())?;
                document["verification"]["taproot_control_block"] =
                    Value::String(format!("{control}{}", "00".repeat(32)));
            }
            "exit_signing_key" => {
                let script = document["verification"]["taproot_script"]
                    .as_str()
                    .ok_or_else(|| "fixture exit has no Taproot script".to_owned())?;
                let prefix_end = script
                    .len()
                    .checked_sub(68)
                    .ok_or_else(|| "fixture Taproot script is too short".to_owned())?;
                document["verification"]["taproot_script"] = Value::String(format!(
                    "{}20{}ac",
                    &script[..prefix_end],
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                ));
            }
            "exit_lock_value" => {
                document["exit"]["lock_time"] = json!(141);
            }
            "exit_internal_key" => {
                let control = document["verification"]["taproot_control_block"]
                    .as_str()
                    .ok_or_else(|| "fixture exit has no control block".to_owned())?;
                let suffix = control
                    .get(66..)
                    .ok_or_else(|| "fixture control block is too short".to_owned())?;
                document["verification"]["taproot_control_block"] = Value::String(format!(
                    "{}{}{}",
                    &control[..2],
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    suffix
                ));
            }
            "exit_verifier_digest" => {
                document["verification"]["verifier_digest"] = Value::String("ff".repeat(32));
            }
            "recovery_package_unusable" => {
                document["funding"]["transaction_id"] = Value::Null;
                document["funding"]["transaction_template"] = Value::Null;
            }
            "exit_package_malformed" => {
                document
                    .as_object_mut()
                    .ok_or_else(|| "fixture exit is not an object".to_owned())?
                    .remove("schema");
            }
            _ => return Err(format!("unknown exit-package mutation {mutation}")),
        }
        let package = match ExitPackage::parse(document) {
            Ok(package) => package,
            Err(error) => return Ok(CaseOutcome::Error(error.code)),
        };
        let mut packages = session.exit_packages().to_vec();
        let first = packages
            .first_mut()
            .ok_or_else(|| "fixture session has no mutable exit package".to_owned())?;
        *first = package;
        let session = match SwapSession::from_signed_records(
            session.config().clone(),
            session.signed_records().to_vec(),
            packages,
        ) {
            Ok(session) => session,
            Err(error) => return Ok(CaseOutcome::Error(error.code)),
        };
        if fixture_key == "reverse" {
            error_outcome(session.verify_before_fund_with_lightning(
                input,
                |request| {
                    Ok(LocalLightningReadiness {
                        invoice_sha256: request.invoice_sha256.clone(),
                        payment_hash: request.payment_hash.clone(),
                        observed_at: request.invoice_expires_at.saturating_sub(1),
                        state: LightningReadinessState::Acceptable,
                    })
                },
                |_| Ok(()),
            ))
        } else {
            error_outcome(session.verify_before_fund(input, |_| Ok(())))
        }
    }

    fn replay_persisted_funding_conflict(
        session: SwapSession<AwaitingVerification>,
        input: VerifyBeforeFundInput,
    ) -> Result<CaseOutcome, String> {
        let mut session = session
            .verify_before_fund(input.clone(), |_| Ok(()))
            .map_err(|error| format!("fixture authorization: {error}"))?;
        record_fixture_funding_effect(&mut session, "submarine")?;
        let effect_id = session
            .funding_request()
            .map_err(|error| error.to_string())?
            .action
            .effect_id()
            .to_owned();
        let effect = session
            .external_effects
            .get_mut(&effect_id)
            .ok_or_else(|| "fixture session has no funding effect".to_owned())?;
        effect.request_sha256 = "ff".repeat(32);
        let session = SwapSession::<AwaitingVerification> {
            config: session.config,
            signed_records: session.signed_records,
            exit_packages: session.exit_packages,
            external_effects: session.external_effects,
            external_effect_requests: session.external_effect_requests,
            funding_request: None,
            _state: PhantomData,
        };
        error_outcome(session.verify_before_fund(input, |_| Ok(())))
    }

    fn replay_sequencing_case(
        object: &serde_json::Map<String, Value>,
    ) -> Result<CaseOutcome, String> {
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| "sequencing case has no operation".to_owned())?;
        match operation {
            "signed_status_base_state_mismatch" => {
                let (mut session, _) = load_fixture_session("flows", "submarine")?;
                let requester = fixture_signer(b"requester")?;
                let factory = SwapRecordFactory::new(session.config().clone())
                    .map_err(|error| error.to_string())?;
                let order_id = fixture_order_id(&session)?;
                let request = factory
                    .status(
                        ParticipantRole::Requester,
                        700,
                        &fixture_distinct("status", "base-mismatch", 0),
                        &order_id,
                        StatusState {
                            sequence: 0,
                            previous: None,
                            base_state: "completed",
                            swp_state: "completed",
                        },
                        Default::default(),
                    )
                    .map_err(|error| error.to_string())?;
                let mut tags = request.tags.clone();
                let state = tags
                    .iter_mut()
                    .find(|tag| tag.name() == Some("state"))
                    .and_then(|tag| tag.0.get_mut(1))
                    .ok_or_else(|| "signed Status fixture has no state tag".to_owned())?;
                *state = "awaiting_input".to_owned();
                let event = requester.sign(request.created_at, request.kind, tags, request.content);
                session
                    .ingest_signed_record(event)
                    .map_err(|error| format!("signed Status ingestion: {error}"))?;
                error_outcome(session.recovery_action_with(|request| {
                    Ok(LocalRecoveryObservation {
                        session_id: request.session_id.clone(),
                        order_id: request.order_id.clone(),
                        binding_sha256: request.binding_sha256.clone(),
                        current_height: 800,
                        source_funding_confirmation_height: Some(700),
                        counterparty_available: false,
                        completed: true,
                        record_loss: false,
                        rail_state_unknown: false,
                        lightning_state: Some(LightningRecoveryState::Paid),
                        chain_state: None,
                    })
                }))
            }
            "close_signer_local_other_gap" => {
                let mut session = build_terminal_flow("submarine", "completed")?;
                let provider = fixture_signer(b"provider")?;
                let factory = SwapRecordFactory::new(session.config().clone())
                    .map_err(|error| error.to_string())?;
                let order_id = fixture_order_id(&session)?;
                let gap = fixture_signed(
                    factory
                        .status(
                            ParticipantRole::Provider,
                            905,
                            &fixture_distinct("provider", "gap", 1),
                            &order_id,
                            StatusState {
                                sequence: 1,
                                previous: Some(&"78".repeat(32)),
                                base_state: "accepted",
                                swp_state: "accepted",
                            },
                            Default::default(),
                        )
                        .map_err(|error| error.to_string())?,
                    &provider,
                )?;
                session
                    .ingest_signed_record(gap)
                    .map_err(|error| format!("other-signer gap ingestion: {error}"))?;
                Ok(CaseOutcome::Result("accepted"))
            }
            _ => Err(format!("unknown sequencing operation {operation}")),
        }
    }

    fn replay_external_effect_case(
        object: &serde_json::Map<String, Value>,
    ) -> Result<CaseOutcome, String> {
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| "external-effect case has no operation".to_owned())?;
        match operation {
            "terminal_evidence_before_funding" => {
                let (session, _) = load_fixture_session("flows", "submarine")?;
                error_outcome(session.verify_terminal_rail_evidence_with(
                    "source",
                    "completed",
                    fixture_rail_evidence,
                ))
            }
            "terminal_evidence_without_funding_effect" => {
                let (session, input) = load_fixture_session("flows", "submarine")?;
                let session = session
                    .verify_before_fund(input, |_| Ok(()))
                    .map_err(|error| format!("fixture authorization: {error}"))?;
                error_outcome(session.verify_terminal_rail_evidence_with(
                    "source",
                    "completed",
                    fixture_rail_evidence,
                ))
            }
            "rail_evidence_orphan_restore" => {
                let (session, input) = load_fixture_session("flows", "submarine")?;
                let mut session = session
                    .verify_before_fund(input, |_| Ok(()))
                    .map_err(|error| format!("fixture authorization: {error}"))?;
                record_fixture_funding_effect(&mut session, "submarine")?;
                let verified = session
                    .verify_terminal_rail_evidence_with(
                        "source",
                        "completed",
                        fixture_rail_evidence,
                    )
                    .map_err(|error| format!("fixture rail evidence: {error}"))?;
                session
                    .record_verified_rail_evidence(verified)
                    .map_err(|error| format!("fixture rail effect: {error}"))?;
                SwapSession::<AwaitingVerification>::restore(
                    &session.persist().map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("orphan rail restore: {error}"))?;
                Ok(CaseOutcome::Result("restored"))
            }
            "lightning_disposition_orphan_restore" => {
                let (session, input) = load_fixture_session("flows", "reverse")?;
                let mut session = authorize_fixture_reverse(session, input)?;
                record_fixture_funding_effect(&mut session, "reverse")?;
                let disposition = session
                    .verify_reverse_no_fund_with(|request| {
                        Ok(LocalLightningDisposition {
                            invoice_sha256: request.invoice_sha256.clone(),
                            payment_hash: request.payment_hash.clone(),
                            observed_at: 800,
                            view_sha256: "86".repeat(32),
                            state: LightningDispositionState::UnpaidFinal,
                            principal_moved: false,
                            external_identifier: "fixture:reverse:unpaid-final".to_owned(),
                        })
                    })
                    .map_err(|error| format!("fixture Lightning disposition: {error}"))?;
                session
                    .record_verified_lightning_disposition(disposition)
                    .map_err(|error| format!("fixture disposition effect: {error}"))?;
                SwapSession::<AwaitingVerification>::restore(
                    &session.persist().map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("orphan disposition restore: {error}"))?;
                Ok(CaseOutcome::Result("restored"))
            }
            "reverse_progress_before_funding_effect" | "reverse_progress_terminal_state" => {
                let (session, input) = load_fixture_session("flows", "reverse")?;
                let mut session = authorize_fixture_reverse(session, input)?;
                if operation == "reverse_progress_terminal_state" {
                    record_fixture_funding_effect(&mut session, "reverse")?;
                }
                error_outcome(session.observe_reverse_payment_with(|request| {
                    Ok(LocalLightningProgress {
                        invoice_sha256: request.invoice_sha256.clone(),
                        payment_hash: request.payment_hash.clone(),
                        observed_at: 800,
                        view_sha256: "92".repeat(32),
                        state: if operation == "reverse_progress_terminal_state" {
                            LightningProgressState::Settled
                        } else {
                            LightningProgressState::PaymentPending
                        },
                    })
                }))
            }
            _ => Err(format!("unknown external-effect operation {operation}")),
        }
    }

    fn replay_recovery_case(
        object: &serde_json::Map<String, Value>,
    ) -> Result<CaseOutcome, String> {
        let (session, _) = load_fixture_session("flows", "reverse")?;
        let lightning_state = match object
            .get("lightning_state")
            .and_then(Value::as_str)
            .ok_or_else(|| "recovery case has no Lightning state".to_owned())?
        {
            "unpaid_final" => LightningRecoveryState::UnpaidFinal,
            "paid" => LightningRecoveryState::Paid,
            "pending" => LightningRecoveryState::Pending,
            state => return Err(format!("unknown recovery Lightning state {state}")),
        };
        let counterparty_available = object
            .get("counterparty_available")
            .and_then(Value::as_bool)
            .ok_or_else(|| "recovery case has no availability flag".to_owned())?;
        let action = session
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 800,
                    source_funding_confirmation_height: Some(700),
                    counterparty_available,
                    completed: false,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state: Some(lightning_state),
                    chain_state: Some(ChainRecoveryState::DestinationRefundedFinal),
                })
            })
            .map_err(|error| format!("fixture recovery: {error}"))?;
        Ok(CaseOutcome::Action(match action {
            RecoveryAction::Cancelled => "cancelled",
            RecoveryAction::ExplicitLoss { .. } => "explicit_loss",
            RecoveryAction::WaitForCounterparty => "wait_for_counterparty",
            action => return Err(format!("unexpected fixture recovery action {action:?}")),
        }))
    }

    fn replay_lifecycle_case(
        object: &serde_json::Map<String, Value>,
    ) -> Result<CaseOutcome, String> {
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| "lifecycle case has no operation".to_owned())?;
        match operation {
            "cancel_acceptor_effective" | "cancel_outsider_effective" => {
                replay_cancellation_case(operation)
            }
            "loss_accounting" => replay_loss_case(
                object
                    .get("mutation")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "loss case has no mutation".to_owned())?,
            ),
            _ => Err(format!("unknown lifecycle operation {operation}")),
        }
    }

    fn load_fixture_session(
        group: &str,
        key: &str,
    ) -> Result<(SwapSession<AwaitingVerification>, VerifyBeforeFundInput), String> {
        let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
            .map_err(|error| format!("full-session fixture JSON: {error}"))?;
        if fixtures.get("schema").and_then(Value::as_str)
            != Some("openagents.mkt-swp.full-session-fixtures.v1")
        {
            return Err("full-session fixture schema is unsupported".to_owned());
        }
        let fixture = fixtures
            .get(group)
            .and_then(|entries| entries.get(key))
            .and_then(Value::as_object)
            .ok_or_else(|| format!("full-session fixture is missing {group}.{key}"))?;
        let snapshot = serde_json::to_vec(
            fixture
                .get("snapshot")
                .ok_or_else(|| format!("{group}.{key} snapshot is missing"))?,
        )
        .map_err(|error| format!("full-session snapshot JSON: {error}"))?;
        let input = serde_json::from_value(
            fixture
                .get("verification")
                .cloned()
                .ok_or_else(|| format!("{group}.{key} verification input is missing"))?,
        )
        .map_err(|error| format!("full-session verification input: {error}"))?;
        let session = SwapSession::<AwaitingVerification>::restore(&snapshot)
            .map_err(|error| format!("full-session restore: {error}"))?;
        Ok((session, input))
    }

    fn authorize_fixture_reverse(
        session: SwapSession<AwaitingVerification>,
        input: VerifyBeforeFundInput,
    ) -> Result<SwapSession<FundingAuthorized>, String> {
        session
            .verify_before_fund_with_lightning(
                input,
                |request| {
                    Ok(LocalLightningReadiness {
                        invoice_sha256: request.invoice_sha256.clone(),
                        payment_hash: request.payment_hash.clone(),
                        observed_at: request.invoice_expires_at.saturating_sub(1),
                        state: LightningReadinessState::Acceptable,
                    })
                },
                |_| Ok(()),
            )
            .map_err(|error| format!("fixture reverse authorization: {error}"))
    }

    fn record_fixture_funding_effect(
        session: &mut SwapSession<FundingAuthorized>,
        swap_name: &str,
    ) -> Result<(), String> {
        let funding = session
            .funding_request()
            .map_err(|error| error.to_string())?
            .clone();
        let request = ExternalEffectRequest::Funding(funding.clone());
        session
            .record_external_effect(
                &request,
                format!("fixture:{swap_name}:funding"),
                "91".repeat(32),
            )
            .map_err(|error| format!("fixture funding effect: {error}"))?;
        Ok(())
    }

    fn fixture_rail_evidence(
        request: &RailObservationRequest,
    ) -> Result<LocalRailEvidence, String> {
        let requester = fixture_signer(b"requester")?;
        let transaction_id = "b0".repeat(32);
        Ok(LocalRailEvidence {
            artifact_sha256: "a0".repeat(32),
            observed_at: 800,
            view: "fixture terminal rail evidence".to_owned(),
            settlement_reference: if request.rail == "bitcoin" {
                if request.evidence_class == "bitcoin_spend" {
                    format!("{transaction_id}:0")
                } else {
                    transaction_id
                }
            } else {
                request.reference.clone()
            },
            verifier_pubkey: None,
            producer_pubkey: requester.pubkey().to_owned(),
            external_identifier: "fixture:terminal-evidence".to_owned(),
        })
    }

    fn fixture_order_id<State>(session: &SwapSession<State>) -> Result<String, String> {
        session
            .signed_records()
            .iter()
            .find(|event| event.kind == MKT_ORDER_KIND)
            .map(|event| event.id.clone())
            .ok_or_else(|| "fixture session has no Order".to_owned())
    }

    fn fixture_effectively_cancelled_session(
        mut session: SwapSession<AwaitingVerification>,
    ) -> Result<SwapSession<AwaitingVerification>, String> {
        let requester = fixture_signer(b"requester")?;
        let provider = fixture_signer(b"provider")?;
        let factory =
            SwapRecordFactory::new(session.config().clone()).map_err(|error| error.to_string())?;
        let order_id = fixture_order_id(&session)?;
        let request = fixture_signed(
            factory
                .cancel(
                    ParticipantRole::Requester,
                    700,
                    &fixture_distinct("cancel", "request", 2),
                    &order_id,
                    Cancellation {
                        action: "request",
                        reason: "user_request",
                        request_id: None,
                        accepted_id: None,
                    },
                    json!({}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        session
            .ingest_signed_record(request.clone())
            .map_err(|error| format!("fixture cancellation request: {error}"))?;
        let accepted = fixture_signed(
            factory
                .cancel(
                    ParticipantRole::Provider,
                    701,
                    &fixture_distinct("cancel", "accepted", 2),
                    &order_id,
                    Cancellation {
                        action: "accepted",
                        reason: "user_request",
                        request_id: Some(&request.id),
                        accepted_id: None,
                    },
                    json!({}),
                )
                .map_err(|error| error.to_string())?,
            &provider,
        )?;
        session
            .ingest_signed_record(accepted.clone())
            .map_err(|error| format!("fixture cancellation acceptance: {error}"))?;
        let effective = fixture_signed(
            factory
                .cancel(
                    ParticipantRole::Provider,
                    702,
                    &fixture_distinct("cancel", "effective", 2),
                    &order_id,
                    Cancellation {
                        action: "effective",
                        reason: "user_request",
                        request_id: Some(&request.id),
                        accepted_id: Some(&accepted.id),
                    },
                    json!({}),
                )
                .map_err(|error| error.to_string())?,
            &provider,
        )?;
        session
            .ingest_signed_record(effective)
            .map_err(|error| format!("fixture effective cancellation: {error}"))?;
        Ok(session)
    }

    fn replay_cancellation_case(operation: &str) -> Result<CaseOutcome, String> {
        let (mut session, _) = load_fixture_session("flows", "submarine")?;
        let requester = fixture_signer(b"requester")?;
        let provider = fixture_signer(b"provider")?;
        let factory =
            SwapRecordFactory::new(session.config().clone()).map_err(|error| error.to_string())?;
        let order_id = fixture_order_id(&session)?;
        let request = fixture_signed(
            factory
                .cancel(
                    ParticipantRole::Requester,
                    700,
                    &fixture_distinct("cancel", "request", 0),
                    &order_id,
                    Cancellation {
                        action: "request",
                        reason: "user_request",
                        request_id: None,
                        accepted_id: None,
                    },
                    json!({}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        session
            .ingest_signed_record(request.clone())
            .map_err(|error| format!("cancellation request ingestion: {error}"))?;
        let accepted = fixture_signed(
            factory
                .cancel(
                    ParticipantRole::Provider,
                    701,
                    &fixture_distinct("cancel", "accepted", 0),
                    &order_id,
                    Cancellation {
                        action: "accepted",
                        reason: "user_request",
                        request_id: Some(&request.id),
                        accepted_id: None,
                    },
                    json!({}),
                )
                .map_err(|error| error.to_string())?,
            &provider,
        )?;
        session
            .ingest_signed_record(accepted.clone())
            .map_err(|error| format!("cancellation acceptance ingestion: {error}"))?;
        let effective_request = factory
            .cancel(
                ParticipantRole::Provider,
                702,
                &fixture_distinct("cancel", "effective", 0),
                &order_id,
                Cancellation {
                    action: "effective",
                    reason: "user_request",
                    request_id: Some(&request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({}),
            )
            .map_err(|error| error.to_string())?;
        let effective = if operation == "cancel_acceptor_effective" {
            fixture_signed(effective_request, &provider)?
        } else {
            let outsider = fixture_signer(b"cancel-outsider")?;
            outsider.sign(
                effective_request.created_at,
                effective_request.kind,
                effective_request.tags,
                effective_request.content,
            )
        };
        match session.ingest_signed_record(effective) {
            Ok(true) if operation == "cancel_acceptor_effective" => {
                Ok(CaseOutcome::Result("accepted"))
            }
            Ok(_) => Err("cancellation fixture returned an unexpected replay result".to_owned()),
            Err(error) => Ok(CaseOutcome::Error(error.code)),
        }
    }

    fn replay_loss_case(mutation: &str) -> Result<CaseOutcome, String> {
        let (mut session, _) = load_fixture_session("flows", "submarine")?;
        let requester = fixture_signer(b"requester")?;
        let factory =
            SwapRecordFactory::new(session.config().clone()).map_err(|error| error.to_string())?;
        let order_id = fixture_order_id(&session)?;
        let bound = BoundSession::from_records(&session.config, &session.signed_records)
            .map_err(|error| format!("fixture bound session: {error}"))?;
        let contract =
            object(&bound.contract, "fixture Swap Contract").map_err(|error| error.to_string())?;
        let assets = contract
            .get("asset_pair")
            .and_then(Value::as_array)
            .filter(|assets| assets.len() == 2)
            .ok_or_else(|| "fixture contract has no asset pair".to_owned())?;
        let verifier = verifier_for_leg(contract, "source")
            .map_err(|error| format!("fixture source verifier: {error}"))?;
        let funding_transaction =
            require_string(verifier, "funding_transaction", None, "swp_unresolved_loss")
                .map_err(|error| error.to_string())?;
        let transaction = Transaction::parse(
            &decode_hex(funding_transaction, "fixture funding transaction")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("fixture funding transaction: {error}"))?;
        let evidence = json!({
            "class":"replacement",
            "rung":"measured",
            "rail":"bitcoin",
            "reference":lower_hex(&transaction.txid().map_err(|error| error.to_string())?),
            "artifact_sha256":verifier.get("funding_transaction_sha256"),
            "producer_pubkey":requester.pubkey(),
            "verifier_pubkey":null,
            "verifier_policy":verifier.get("verifier_policy"),
            "observed_at":800,
            "view":"fixture-height:800"
        });
        let input_amount = fixture_string(contract, "input_amount")?;
        let mut loss = json!({
            "input_asset_id":assets[0],
            "output_asset_id":assets[1],
            "input_committed":input_amount,
            "input_recovered":"0",
            "output_received":"0",
            "provider_fee_paid":"0",
            "miner_fee_paid":"0",
            "lightning_routing_fee_paid":"0",
            "guarantee_recovery_received":"0",
            "principal_unresolved":"0",
            "reservation_released":"0",
            "evidence_refs":[evidence],
            "unknown_fields":[],
        });
        let (outcome, unknown_field) = match mutation {
            "vanished_principal" => ("failed", None),
            "unknown_output_received" => ("unresolved", Some("output_received")),
            "unknown_miner_fee_paid" => ("unresolved", Some("miner_fee_paid")),
            "unknown_input_committed_failed" => ("failed", Some("input_committed")),
            "unknown_input_committed_disputed" => ("disputed", Some("input_committed")),
            "unknown_input_committed_unresolved" => ("unresolved", Some("input_committed")),
            _ => return Err(format!("unknown loss mutation {mutation}")),
        };
        if let Some(unknown_field) = unknown_field {
            loss.as_object_mut()
                .ok_or_else(|| "fixture loss is not an object".to_owned())?
                .remove(unknown_field);
            loss["unknown_fields"] = json!([unknown_field]);
        }
        let close = fixture_signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    810,
                    &fixture_distinct("loss", mutation, 0),
                    &order_id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 810,
                    },
                    json!({"loss_accounting":loss}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        error_outcome(session.ingest_signed_record(close))
    }

    fn required_choice<'a>(
        object: &'a serde_json::Map<String, Value>,
        member: &str,
        choices: &[&str],
    ) -> Result<&'a str, String> {
        let value = object
            .get(member)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("fixture member {member} is missing"))?;
        if !choices.contains(&value) {
            return Err(format!(
                "fixture member {member} has unsupported value {value}"
            ));
        }
        Ok(value)
    }

    fn build_terminal_flow(
        swap_name: &str,
        outcome: &str,
    ) -> Result<SwapSession<FundingAuthorized>, String> {
        let (session, verification) = load_fixture_session("flows", swap_name)?;
        let mut authorized = if swap_name == "reverse" {
            session
                .verify_before_fund_with_lightning(
                    verification,
                    |request| {
                        Ok(LocalLightningReadiness {
                            invoice_sha256: request.invoice_sha256.clone(),
                            payment_hash: request.payment_hash.clone(),
                            observed_at: request.invoice_expires_at.saturating_sub(1),
                            state: LightningReadinessState::Acceptable,
                        })
                    },
                    |_| Ok(()),
                )
                .map_err(|error| format!("verify-before-fund: {error}"))?
        } else {
            session
                .verify_before_fund(verification, |_| Ok(()))
                .map_err(|error| format!("verify-before-fund: {error}"))?
        };
        let funding_request = ExternalEffectRequest::Funding(
            authorized
                .funding_request()
                .map_err(|error| error.to_string())?
                .clone(),
        );
        authorized
            .record_external_effect(
                &funding_request,
                format!("fixture:{swap_name}:funding"),
                "91".repeat(32),
            )
            .map_err(|error| format!("funding effect: {error}"))?;
        if swap_name == "reverse" {
            authorized
                .clone()
                .observe_reverse_payment_with(|request| {
                    Ok(LocalLightningProgress {
                        invoice_sha256: request.invoice_sha256.clone(),
                        payment_hash: request.payment_hash.clone(),
                        observed_at: 1,
                        view_sha256: "92".repeat(32),
                        state: LightningProgressState::PaymentPending,
                    })
                })
                .map_err(|error| format!("reverse payment progression: {error}"))?;
        }
        replay_recovery_before_terminal(&authorized, swap_name, outcome)?;

        let bound = BoundSession::from_records(&authorized.config, &authorized.signed_records)
            .map_err(|error| format!("bound full-session fixture: {error}"))?;
        let contract = object(&bound.contract, "fixture Swap Contract")
            .map_err(|error| error.to_string())?
            .clone();
        let order_id = bound.order.id.clone();
        let leg_ids = contract
            .get("legs")
            .and_then(Value::as_array)
            .ok_or_else(|| "fixture contract has no legs".to_owned())?
            .iter()
            .map(|leg| {
                leg.get("leg_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| "fixture contract leg has no ID".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let requester = fixture_signer(b"requester")?;
        let mut evidence_refs = Vec::with_capacity(leg_ids.len());
        for (index, leg_id) in leg_ids.iter().enumerate() {
            let verified = authorized
                .verify_terminal_rail_evidence_with(leg_id, outcome, |request| {
                    let settlement_transaction = format!("{:02x}", 176 + index).repeat(32);
                    Ok(LocalRailEvidence {
                        artifact_sha256: format!("{:02x}", 160 + index).repeat(32),
                        observed_at: 800,
                        view: format!("fixture {swap_name} {} {outcome}", request.rail),
                        settlement_reference: if request.rail == "bitcoin" {
                            if request.evidence_class == "bitcoin_spend" {
                                format!("{settlement_transaction}:0")
                            } else {
                                settlement_transaction
                            }
                        } else {
                            request.reference.clone()
                        },
                        verifier_pubkey: None,
                        producer_pubkey: requester.pubkey().to_owned(),
                        external_identifier: format!(
                            "fixture:{swap_name}:{outcome}:{}",
                            request.rail
                        ),
                    })
                })
                .map_err(|error| format!("terminal evidence: {error}"))?;
            evidence_refs.push(verified.evidence_reference().clone());
            authorized
                .record_verified_rail_evidence(verified)
                .map_err(|error| format!("terminal evidence effect: {error}"))?;
        }
        authorized = SwapSession::<AwaitingVerification>::restore(
            &authorized.persist().map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("orphan evidence crash restore: {error}"))?
        .resume_funding_authorized()
        .map_err(|error| format!("resume after evidence crash: {error}"))?;

        let factory =
            SwapRecordFactory::new(authorized.config.clone()).map_err(|error| error.to_string())?;
        let status = fixture_signed(
            factory
                .status(
                    ParticipantRole::Requester,
                    900,
                    &fixture_distinct(swap_name, outcome, 0),
                    &order_id,
                    StatusState {
                        sequence: 0,
                        previous: None,
                        base_state: outcome,
                        swp_state: outcome,
                    },
                    Default::default(),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        authorized
            .ingest_signed_record(status.clone())
            .map_err(|error| format!("terminal Status ingestion: {error}"))?;
        let assets = contract
            .get("asset_pair")
            .and_then(Value::as_array)
            .filter(|assets| assets.len() == 2)
            .ok_or_else(|| "fixture contract has no asset pair".to_owned())?;
        let input_amount = fixture_string(&contract, "input_amount")?;
        let output_amount = fixture_string(&contract, "output_amount")?;
        let reservation_released = contract
            .get("reservation_commitment")
            .and_then(Value::as_object)
            .and_then(|reservation| reservation.get("reserved_amount"))
            .and_then(Value::as_str)
            .unwrap_or("0");
        let mut loss = json!({
            "input_asset_id":assets[0],
            "output_asset_id":assets[1],
            "input_committed":input_amount,
            "input_recovered":"0",
            "output_received":"0",
            "provider_fee_paid":"0",
            "miner_fee_paid":"0",
            "lightning_routing_fee_paid":"0",
            "guarantee_recovery_received":"0",
            "principal_unresolved":"0",
            "reservation_released":reservation_released,
            "evidence_refs":evidence_refs,
            "unknown_fields":[],
        });
        if outcome == "completed" {
            loss["output_received"] = json!(output_amount);
        } else {
            loss["input_recovered"] = json!(input_amount);
        }
        let close = fixture_signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    910,
                    &fixture_distinct(swap_name, outcome, 1),
                    &order_id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 910,
                    },
                    json!({"status_id":status.id,"loss_accounting":loss}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        authorized
            .ingest_signed_record(close)
            .map_err(|error| format!("terminal Close ingestion: {error}"))?;
        if outcome == "completed" {
            let recovery = authorized
                .recovery_action_with(|request| {
                    Ok(LocalRecoveryObservation {
                        session_id: request.session_id.clone(),
                        order_id: request.order_id.clone(),
                        binding_sha256: request.binding_sha256.clone(),
                        current_height: 1_000,
                        source_funding_confirmation_height: Some(800),
                        counterparty_available: false,
                        completed: true,
                        record_loss: false,
                        rail_state_unknown: false,
                        lightning_state: (swap_name != "chain")
                            .then_some(LightningRecoveryState::Paid),
                        chain_state: (swap_name != "submarine")
                            .then_some(ChainRecoveryState::DestinationFundedUnclaimed),
                    })
                })
                .map_err(|error| format!("terminal recovery: {error}"))?;
            if recovery != RecoveryAction::Completed {
                return Err("completed flow did not reach completed recovery".to_owned());
            }
        }
        Ok(authorized)
    }

    fn replay_recovery_before_terminal<State>(
        session: &SwapSession<State>,
        swap_name: &str,
        outcome: &str,
    ) -> Result<(), String> {
        let action = session
            .recovery_action_with(|request| {
                let (counterparty_available, lightning_state, chain_state) =
                    match (swap_name, outcome) {
                        ("submarine", "completed") => {
                            (true, Some(LightningRecoveryState::Pending), None)
                        }
                        ("submarine", "refunded") => {
                            (false, Some(LightningRecoveryState::UnpaidFinal), None)
                        }
                        ("reverse", "completed") => (
                            false,
                            Some(LightningRecoveryState::Pending),
                            Some(ChainRecoveryState::DestinationClaimable),
                        ),
                        ("reverse", "refunded") => (
                            false,
                            Some(LightningRecoveryState::UnpaidFinal),
                            Some(ChainRecoveryState::DestinationNotFunded),
                        ),
                        ("chain", "completed") => {
                            (false, None, Some(ChainRecoveryState::DestinationClaimable))
                        }
                        ("chain", "refunded") => (
                            false,
                            None,
                            Some(ChainRecoveryState::DestinationRefundedFinal),
                        ),
                        _ => return Err("unsupported fixture recovery flow".to_owned()),
                    };
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 1_000,
                    source_funding_confirmation_height: Some(800),
                    counterparty_available,
                    completed: false,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state,
                    chain_state,
                })
            })
            .map_err(|error| format!("pre-terminal recovery: {error}"))?;
        let expected = match (swap_name, outcome) {
            ("submarine", "completed") => {
                matches!(action, RecoveryAction::DirectCounterpartyCompletion)
            }
            ("submarine", "refunded") | ("chain", "refunded") => {
                matches!(action, RecoveryAction::BroadcastPresigned { .. })
            }
            ("reverse", "completed") | ("chain", "completed") => {
                matches!(action, RecoveryAction::RequestWalletClaim { .. })
            }
            ("reverse", "refunded") => matches!(action, RecoveryAction::Cancelled),
            _ => false,
        };
        if !expected {
            return Err(format!(
                "{swap_name} {outcome} fixture returned the wrong recovery action: {action:?}"
            ));
        }
        Ok(())
    }

    fn fixture_distinct(swap_name: &str, outcome: &str, stage: u8) -> String {
        lower_hex(&sha256(
            format!("immortal-mkt-swp-fixture:{swap_name}:{outcome}:{stage}").as_bytes(),
        ))
    }

    fn fixture_signer(label: &[u8]) -> Result<MarketSigner, String> {
        let key: [u8; 32] =
            Sha256::digest([b"immortal-mkt-swp-test-only:".as_slice(), label].concat()).into();
        MarketSigner::from_secret_bytes(key)
    }

    fn fixture_signed(request: MktSigningRequest, signer: &MarketSigner) -> Result<Event, String> {
        let event = signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request
            .verify_signed(event)
            .map_err(|error| error.to_string())
    }

    fn fixture_string<'a>(
        object: &'a serde_json::Map<String, Value>,
        member: &str,
    ) -> Result<&'a str, String> {
        object
            .get(member)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("fixture deterministic member {member} is missing"))
    }
}

fn network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "bitcoin",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}

fn validate_esplora_url(url: &str) -> Result<&str, SwapClientError> {
    let url = url.strip_suffix('/').unwrap_or(url);
    let (scheme, remainder) = url
        .strip_prefix("https://")
        .map(|remainder| ("https", remainder))
        .or_else(|| {
            url.strip_prefix("http://")
                .map(|remainder| ("http", remainder))
        })
        .ok_or_else(|| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                "Esplora endpoint must use HTTPS or loopback HTTP",
            )
        })?;
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || url.len() > 2_048
        || authority.contains('@')
        || url.contains('?')
        || url.contains('#')
        || url
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "Esplora endpoint is not a bounded public URL",
        ));
    }
    let host = parsed_authority_host(authority)?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if scheme == "http" && !loopback {
        return Err(SwapClientError::new(
            "swp_exit_package_unusable",
            "plaintext Esplora endpoints are restricted to loopback",
        ));
    }
    Ok(url)
}

fn parsed_authority_host(authority: &str) -> Result<&str, SwapClientError> {
    let invalid = || {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "Esplora endpoint authority is invalid",
        )
    };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']').ok_or_else(invalid)?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            Some(_) => return Err(invalid()),
            None => (authority, None),
        }
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))
        || port.is_some_and(|port| port.is_empty() || port.parse::<u16>().is_err() || port == "0")
    {
        return Err(invalid());
    }
    Ok(host)
}

pub(crate) fn require_lower_hex_32(value: &str, label: &str) -> Result<(), SwapClientError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            format!("{label} must be 64 lowercase hexadecimal characters"),
        ))
    }
}

fn require_lower_hex(value: &str, label: &str) -> Result<(), SwapClientError> {
    if !value.is_empty()
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SwapClientError::new(
            "swp_exit_package_unusable",
            format!("{label} must be nonempty lowercase hexadecimal bytes"),
        ))
    }
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, SwapClientError> {
    require_lower_hex(value, label)?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], SwapClientError> {
    require_lower_hex_32(value, label)?;
    decode_hex(value, label)?
        .try_into()
        .map_err(|_| SwapClientError::new("swp_contract_terms_mismatch", "hex length differs"))
}

fn hex_digit(byte: u8) -> Result<u8, SwapClientError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SwapClientError::new(
            "swp_contract_terms_mismatch",
            "hexadecimal value is invalid",
        )),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
