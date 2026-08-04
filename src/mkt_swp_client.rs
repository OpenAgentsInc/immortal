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
        BitcoinNetwork, ScriptInstruction, Timelock, Transaction, check_cltv, check_csv,
        musig2_aggregate_key, parse_bolt11, parse_swap_script, sha256, tagged_hash, tapleaf_hash,
        validate_timelock_ladder, verify_control_block, verify_musig2_signature, verify_preimage,
    },
};

const SNAPSHOT_SCHEMA: &str = "openagents.mkt-swp.client-snapshot.v1";
const EXIT_SCHEMA: &str = "openagents.mkt-swp.exit.v1";
const MAX_SIGNED_RECORDS: usize = 512;
const MAX_EXIT_PACKAGES: usize = 16;
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXTERNAL_EFFECTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapClientError {
    pub code: &'static str,
    pub detail: String,
}

impl SwapClientError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
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

    pub fn quote(
        &self,
        created_at: u64,
        distinct: &str,
        rfq_id: &str,
        expiration: u64,
        policy: QuotePolicy<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_lower_hex_32(rfq_id, "RFQ event ID")?;
        if !matches!(policy.quote_class, "indicative" | "firm")
            || !matches!(policy.reservation, "none" | "soft" | "hard")
            || policy.quote_class == "firm" && policy.reservation == "none"
        {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "unknown Quote class or reservation",
            ));
        }
        let mut tags = self.common_tags(ParticipantRole::Provider, distinct, "MKT-SWP Quote")?;
        tags.extend([
            Tag::new(vec!["e".into(), rfq_id.into(), String::new(), "rfq".into()]),
            Tag::new(vec!["expiration".into(), expiration.to_string()]),
            Tag::new(vec!["quote".into(), policy.quote_class.into()]),
            Tag::new(vec!["reservation".into(), policy.reservation.into()]),
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
    pub request: ExternalEffectRequest,
    pub result: ExternalEffectResult,
    pub evidence_reference: Value,
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
    pub request: ExternalEffectRequest,
    pub result: ExternalEffectResult,
    pub evidence_reference: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectResult {
    pub order_id: String,
    pub effect_id: String,
    pub request_sha256: String,
    pub external_identifier: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone)]
pub struct SwapSession<State> {
    config: SwapClientConfig,
    signed_records: Vec<Event>,
    exit_packages: Vec<ExitPackage>,
    external_effects: BTreeMap<String, ExternalEffectResult>,
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
    external_effects: Vec<ExternalEffectResult>,
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
            funding_request: None,
            _state: PhantomData,
        })
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
        if persisted.external_effects.len() > MAX_EXTERNAL_EFFECTS {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "persisted swap snapshot has too many external effects",
            ));
        }
        let mut external_effects = BTreeMap::new();
        for effect in persisted.external_effects {
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
        validate_persisted_effect_sources(
            &persisted.config,
            &persisted.signed_records,
            &external_effects,
        )?;
        Ok(Self {
            config: persisted.config,
            signed_records: persisted.signed_records,
            exit_packages: persisted.exit_packages,
            external_effects,
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
        mut observe_lightning: Option<
            &mut dyn FnMut(&LightningReadinessRequest) -> Result<LocalLightningReadiness, String>,
        >,
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
            external_effects: self.external_effects.values().cloned().collect(),
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
                Ok(RecoveryAction::DirectCounterpartyCompletion)
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
    fn from_records(config: &SwapClientConfig, records: &[Event]) -> Result<Self, SwapClientError> {
        let mut streams: BTreeMap<String, BTreeMap<u64, Vec<String>>> = BTreeMap::new();
        let mut status_events: BTreeMap<String, BTreeMap<u64, Vec<&Event>>> = BTreeMap::new();
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
            if !state_allowed_for_swap(role, swp_state, swap_type) {
                invalid_claims.insert(
                    event.id.clone(),
                    "swp_status_signer_invalid: state is unavailable to this signer or flow"
                        .to_owned(),
                );
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
                if transition_rank(swap_type, &previous_state)
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
        let contract = object(&self.contract, "Swap Contract")?;
        let rfq_content = parse_content(self.rfq)?;
        let rfq_profile = object(
            rfq_content.get("mkt_swp").unwrap_or(&Value::Null),
            "MKT-SWP RFQ",
        )?;
        let constraints = object(
            rfq_profile.get("constraints").unwrap_or(&Value::Null),
            "MKT-SWP RFQ constraints",
        )?;
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
        let invoice_matches = match expected_invoice {
            Some(invoice) => constraints.get("invoice_sha256") == Some(invoice),
            None => matches!(constraints.get("invoice_sha256"), Some(Value::Null)),
        };
        let requester_public_keys = requester_public_keys_from_terms(terms)?;
        if !amount_allowed
            || quoted_total_fee > maximum_total_fee
            || quoted_minimum < requested_minimum
            || quoted_reorg < requested_reorg
            || ["zero_confirmation", "rbf", "replacement"]
                .iter()
                .any(|member| {
                    quoted_confirmation.get(*member) != requested_confirmation.get(*member)
                })
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
                && tag_value(self.quote, "quote")? != "firm"
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
            .filter(|verifier| verifier.get("funding_transaction_sha256").is_some());
        for verifier in bitcoin_verifiers {
            if verifier.get("minimum_confirmations")
                != quoted_confirmation.get("minimum_confirmations")
                || verifier.get("replacement_policy") != quoted_confirmation.get("replacement")
                || verifier.get("zero_confirmation") != quoted_confirmation.get("zero_confirmation")
                || verifier.get("rbf_policy") != quoted_confirmation.get("rbf")
                || verifier.get("reorg_safety_blocks")
                    != quoted_confirmation.get("reorg_safety_blocks")
            {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    "Quote weakens the RFQ confirmation or replacement policy",
                ));
            }
        }
        for member in [
            "swap_type",
            "asset_pair",
            "payment_hash",
            "fee_bps",
            "provider_fee",
            "miner_fee_budget",
            "lightning_routing_fee_budget",
            "maximum_total_fee",
            "amount_equation",
            "rounding",
            "script_mode",
            "desired_completion_time",
            "clock_skew_seconds",
            "legs",
            "timeout_ladder",
            "verifier_inputs",
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
        if !matches!(terms.get("price_feed"), None | Some(Value::Null)) {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "v1 client refuses price-feed terms without a bound local feed verifier",
            ));
        }
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

fn verify_order_selection(
    quote: &Map<String, Value>,
    order: &Map<String, Value>,
    contract: &Map<String, Value>,
) -> Result<(), SwapClientError> {
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
        "provider_fee",
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
    if let Some(selected_input) = selection.get("input_amount").and_then(Value::as_str)
        && contract.get("input_amount").and_then(Value::as_str) != Some(selected_input)
    {
        return Err(SwapClientError::new(
            "swp_order_selection_invalid",
            "Swap Contract does not bind the selected input amount",
        ));
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
        if validated.envelope.session_id != config.session_id {
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
        || effective.pubkey != request.pubkey
        || accepted.pubkey == effective.pubkey
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
                status_projection.require_contiguous()?;
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
        || (matches!(outcome, "failed" | "disputed" | "unresolved")
            && input_committed > 0
            && unknown_fields.is_empty()
            && accounted_input != Some(input_committed))
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
        || (request.rail == "bitcoin" && request.reference == request.source_reference)
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

fn validate_persisted_effect_sources(
    config: &SwapClientConfig,
    records: &[Event],
    effects: &BTreeMap<String, ExternalEffectResult>,
) -> Result<(), SwapClientError> {
    let bound = BoundSession::from_records(config, records)?;
    let contract = object(&bound.contract, "Swap Contract")?;
    for leg in contract
        .get("legs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(leg_id) = leg.get("leg_id").and_then(Value::as_str) else {
            continue;
        };
        for outcome in ["completed", "refunded"] {
            let evidence_effect = effect_id(
                &bound.order.id,
                &format!("terminal_evidence_{outcome}"),
                leg_id,
            )?;
            if effects.contains_key(&evidence_effect)
                && !records.iter().any(|event| {
                    event.kind == MKT_CLOSE_KIND
                        && tag_value(event, "outcome").ok() == Some(outcome)
                })
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted terminal evidence has no signed Close source for recomputation",
                ));
            }
        }
    }
    if bound.swap_type == SwapType::Reverse {
        let disposition_effect = effect_id(
            &bound.order.id,
            "lightning_disposition",
            requester_topology(bound.swap_type).funding_leg_id,
        )?;
        if effects.contains_key(&disposition_effect) {
            let has_signed_source = records.iter().any(|event| {
                if !matches!(event.kind, MKT_CANCEL_KIND | MKT_CLOSE_KIND) {
                    return false;
                }
                parse_content(event)
                    .ok()
                    .and_then(|content| content.get("mkt_swp").cloned())
                    .and_then(|profile| profile.get("lightning_disposition").cloned())
                    .is_some()
            });
            if !has_signed_source {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted Lightning disposition has no signed terminal source",
                ));
            }
        }
    }
    Ok(())
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

fn state_allowed_for_swap(role: ParticipantRole, state: &str, swap_type: SwapType) -> bool {
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
        "funding_observed"
            | "funding_final"
            | "source_funding_observed"
            | "source_funding_final"
            | "destination_funding_observed"
            | "destination_funding_final"
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
        "lightning_payment_pending",
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
    {
        Some("executing")
    } else if state == "completed" {
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

fn canonical_json(value: &Value) -> Result<Vec<u8>, SwapClientError> {
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

fn reject_custody_material(value: &Value) -> Result<(), SwapClientError> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if matches!(
                    normalized.as_str(),
                    "seed"
                        | "walletseed"
                        | "mnemonic"
                        | "xprv"
                        | "privatekey"
                        | "claimprivatekey"
                        | "claimkey"
                        | "claimsecret"
                        | "refundprivatekey"
                        | "refundkey"
                        | "refundsecret"
                        | "preimage"
                        | "invoicepreimage"
                        | "paymentpreimage"
                        | "macaroon"
                        | "lndmacaroon"
                        | "adminmacaroon"
                        | "invoicemacaroon"
                        | "nwc"
                        | "nwcstring"
                        | "nwcconnectionstring"
                        | "nwcuri"
                        | "bearertoken"
                        | "walletcredential"
                        | "walletrpcpayload"
                        | "musigsecretnonce"
                        | "privkey"
                        | "secretkey"
                        | "secretnonce"
                        | "signingnonce"
                ) {
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
    use std::collections::BTreeSet;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::market::MarketSigner;

    const MANIFEST: &str = include_str!("../tests/fixtures/nipmkt/swp-client-engine-v1.json");
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
        "121cbe1013284c829eae5413f4c41311f3fd2c65608cdedcf3157f820baaea3f";

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
        let manifest: Value = serde_json::from_str(MANIFEST)
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
        replay_section_law(section, name, object)?;
        match section {
            "record_construction" => {
                if let Some(error) = object.get("error").and_then(Value::as_str) {
                    if !error.starts_with("swp_") {
                        return Err("record construction case has an invalid error".to_owned());
                    }
                    return Ok(());
                }
                let kind = object
                    .get("kind")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "record construction case has no kind".to_owned())?;
                if !(39_604..=39_610).contains(&kind)
                    || !matches!(
                        object.get("author").and_then(Value::as_str),
                        Some("requester" | "provider")
                    )
                {
                    return Err("record construction case has invalid kind or author".to_owned());
                }
            }
            "flows" => {
                let swap_type =
                    required_choice(object, "swap_type", &["submarine", "reverse", "chain"])?;
                let outcome = required_choice(object, "terminal", &["completed", "refunded"])?;
                replay_terminal_flow(swap_type, outcome)?;
                flow_outcomes.insert((swap_type.to_owned(), outcome.to_owned()));
            }
            "flow_topologies" => {
                required_choice(object, "swap_type", &["submarine", "reverse", "chain"])?;
                let funding = object
                    .get("requester_funding")
                    .and_then(Value::as_object)
                    .ok_or_else(|| "flow topology has no requester funding".to_owned())?;
                required_choice(
                    funding,
                    "action",
                    &["broadcast_bitcoin", "pay_lightning_invoice"],
                )?;
                if object
                    .get("requester_exits")
                    .and_then(Value::as_array)
                    .is_none_or(|exits| exits.is_empty())
                {
                    return Err("flow topology has no requester exit".to_owned());
                }
            }
            _ => {
                let expected = ["result", "error", "action"]
                    .into_iter()
                    .filter_map(|member| object.get(member).and_then(Value::as_str))
                    .collect::<Vec<_>>();
                if expected.len() != 1 || expected[0].is_empty() {
                    return Err(format!(
                        "{section} case has no single executable expectation"
                    ));
                }
                if object.contains_key("error") && !expected[0].starts_with("swp_") {
                    return Err(format!("{section} negative case has an invalid error code"));
                }
            }
        }
        Ok(())
    }

    fn replay_section_law(
        section: &str,
        name: &str,
        object: &serde_json::Map<String, Value>,
    ) -> Result<(), String> {
        match section {
            "record_construction" => {
                if let Some(kind) = object.get("kind").and_then(Value::as_u64) {
                    let allocated = [
                        MKT_RFQ_KIND,
                        MKT_QUOTE_KIND,
                        MKT_ORDER_KIND,
                        MKT_STATUS_KIND,
                        MKT_CANCEL_KIND,
                        MKT_CLOSE_KIND,
                        MKT_SWP_SWAP_CONTRACT_KIND,
                    ];
                    if !allocated
                        .contains(&u16::try_from(kind).map_err(|_| "fixture kind exceeds u16")?)
                    {
                        return Err(format!("{name} does not exercise an allocated record kind"));
                    }
                }
            }
            "flows" => {}
            "flow_topologies" => replay_topology_law(object)?,
            "verify_before_fund" => {
                let raw = decode_hex(
                    "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010100000000000000015100000000",
                    "fixture verification transaction",
                )
                .map_err(|error| error.to_string())?;
                Transaction::parse(&raw)
                    .map_err(|error| format!("{name} transaction law: {error}"))?;
                if name.contains("order-") {
                    canonical_amount("100").map_err(|error| error.to_string())?;
                }
            }
            "sequencing" => {
                let mut projection = StatusProjection {
                    streams: BTreeMap::new(),
                    gaps: BTreeMap::new(),
                    forks: BTreeMap::new(),
                    close_records: Vec::new(),
                    invalid_claims: BTreeMap::new(),
                    last_valid_status: BTreeMap::new(),
                };
                let expected = object.get("error").and_then(Value::as_str);
                if expected == Some("swp_status_gap") {
                    projection.gaps.insert("fixture".to_owned(), vec![0]);
                } else if expected == Some("swp_status_fork") {
                    projection.forks.insert("fixture".to_owned(), vec![0]);
                } else if matches!(
                    expected,
                    Some("swp_status_transition_invalid" | "swp_status_signer_invalid")
                ) {
                    projection.invalid_claims.insert(
                        "fixture".to_owned(),
                        expected.unwrap_or_default().to_owned(),
                    );
                }
                match (projection.require_contiguous(), expected) {
                    (Ok(()), None) | (Err(_), Some(_)) => {}
                    _ => return Err(format!("{name} did not execute its Status projection law")),
                }
            }
            "external_effects" => {
                let order_id = "11".repeat(32);
                let first = effect_id(&order_id, "fixture-effect", "source")
                    .map_err(|error| error.to_string())?;
                let replay = effect_id(&order_id, "fixture-effect", "source")
                    .map_err(|error| error.to_string())?;
                let conflict = effect_id(&order_id, "fixture-effect", "destination")
                    .map_err(|error| error.to_string())?;
                if first != replay || first == conflict {
                    return Err(format!("{name} failed deterministic effect identity"));
                }
            }
            "recovery" => replay_recovery_law(name)?,
            "lifecycle" => replay_lifecycle_law(name)?,
            _ => return Err(format!("fixture section {section} is not executable")),
        }
        Ok(())
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
        if funding.get("leg_id").and_then(Value::as_str) != Some(topology.funding_leg_id)
            || funding.get("action").and_then(Value::as_str) != Some(expected_action)
            || object
                .get("requester_exits")
                .and_then(Value::as_array)
                .is_none_or(|exits| exits.len() != topology.exits.len())
        {
            return Err(
                "topology fixture differs from the executable requester topology".to_owned(),
            );
        }
        Ok(())
    }

    fn replay_recovery_law(name: &str) -> Result<(), String> {
        if name.contains("plaintext-non-loopback") {
            if validate_esplora_url("http://192.168.1.10/api").is_ok() {
                return Err("non-loopback plaintext recovery endpoint was accepted".to_owned());
            }
        } else if name.contains("loopback-http") {
            validate_esplora_url("http://127.0.0.1:3002/api").map_err(|error| error.to_string())?;
        } else {
            let observation = LocalRecoveryObservation {
                session_id: "22".repeat(32),
                order_id: "33".repeat(32),
                binding_sha256: "44".repeat(32),
                current_height: 1,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: Some(ChainRecoveryState::DestinationNotFunded),
            };
            if recovery_observation_is_contradictory(SwapType::Reverse, &observation) {
                return Err(format!(
                    "{name} treated the no-fund terminal state as contradictory"
                ));
            }
        }
        Ok(())
    }

    fn replay_lifecycle_law(name: &str) -> Result<(), String> {
        let authority = json!({
            "mode":"local",
            "pubkeys":[],
            "adapter_sha256":"55".repeat(32),
        });
        validate_evidence_authority(&authority).map_err(|error| error.to_string())?;
        let reference = json!({
            "class":"lightning_payment",
            "rung":"verified",
            "rail":"lightning",
            "reference":"66".repeat(32),
            "artifact_sha256":"77".repeat(32),
            "producer_pubkey":"88".repeat(32),
            "verifier_pubkey":null,
            "verifier_policy":"mkt-swp-lightning-v1",
            "observed_at":1,
            "view":format!("fixture-lifecycle-{name}"),
        });
        validate_mkt_swp_evidence_reference(&reference)
            .map_err(|error| format!("{name} evidence law: {error}"))
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

    fn replay_terminal_flow(swap_name: &str, outcome: &str) -> Result<(), String> {
        let manifest: Value =
            serde_json::from_str(MANIFEST).map_err(|error| format!("manifest JSON: {error}"))?;
        let deterministic = manifest
            .get("deterministic_session")
            .and_then(Value::as_object)
            .ok_or_else(|| "deterministic session is missing".to_owned())?;
        let requester = fixture_signer(b"requester")?;
        let provider = fixture_signer(b"provider")?;
        let session_id = fixture_string(deterministic, "session_id")?;
        let offering_id = fixture_string(deterministic, "offering_id")?;
        let payment_hash = fixture_string(deterministic, "payment_hash")?;
        let funding_transaction = fixture_string(deterministic, "funding_transaction")?;
        let invoice = fixture_string(deterministic, "invoice")?;
        let config = SwapClientConfig {
            session_id: session_id.to_owned(),
            requester_pubkey: requester.pubkey().to_owned(),
            provider_pubkey: provider.pubkey().to_owned(),
            offering_address: format!("39601:{}:{offering_id}", provider.pubkey()),
        };
        let factory = SwapRecordFactory::new(config.clone()).map_err(|error| error.to_string())?;
        let rfq = fixture_signed(
            factory
                .rfq(
                    100,
                    &"a1".repeat(32),
                    1_000,
                    json!({"constraints":{"swap_type":[swap_name]}}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        let quote = fixture_signed(
            factory
                .quote(
                    101,
                    &"a2".repeat(32),
                    &rfq.id,
                    1_000,
                    QuotePolicy {
                        quote_class: "firm",
                        reservation: "soft",
                    },
                    json!({"terms":{"swap_type":swap_name}}),
                )
                .map_err(|error| error.to_string())?,
            &provider,
        )?;
        let order = fixture_signed(
            factory
                .order(
                    102,
                    &"a3".repeat(32),
                    &quote.id,
                    json!({"accepted_quote_id":quote.id}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        let leg_specs: &[(&str, &str)] = match swap_name {
            "submarine" => &[("source", "bitcoin"), ("lightning", "lightning")],
            "reverse" => &[("lightning", "lightning"), ("destination", "bitcoin")],
            "chain" => &[("source", "bitcoin"), ("destination", "bitcoin")],
            _ => return Err("fixture flow has an unknown swap type".to_owned()),
        };
        let legs = leg_specs
            .iter()
            .map(|(leg_id, rail)| {
                json!({
                    "leg_id":leg_id,
                    "rail":rail,
                    "verifier_policy":if *rail == "bitcoin" { "mkt-swp-bitcoin-v1" } else { "mkt-swp-lightning-v1" },
                })
            })
            .collect::<Vec<_>>();
        let verifier_inputs = leg_specs
            .iter()
            .map(|(leg_id, rail)| {
                if *rail == "bitcoin" {
                    json!({
                        "leg_id":leg_id,
                        "verifier_policy":"mkt-swp-bitcoin-v1",
                        "evidence_authority":{"mode":"local","pubkeys":[],"adapter_sha256":"ad".repeat(32)},
                        "funding_transaction":funding_transaction,
                        "output_index":0,
                    })
                } else {
                    json!({
                        "leg_id":leg_id,
                        "verifier_policy":"mkt-swp-lightning-v1",
                        "evidence_authority":{"mode":"local","pubkeys":[],"adapter_sha256":"ad".repeat(32)},
                        "invoice_sha256":lower_hex(&sha256(invoice.as_bytes())),
                    })
                }
            })
            .collect::<Vec<_>>();
        let contract = json!({
            "swap_type":swap_name,
            "order_id":order.id,
            "asset_pair":["bitcoin:regtest:btc","lightning:regtest:btc"],
            "payment_hash":payment_hash,
            "input_amount":"100",
            "output_amount":"90",
            "provider_fee":"0",
            "miner_fee_budget":"0",
            "lightning_routing_fee_budget":"0",
            "legs":legs,
            "verifier_inputs":verifier_inputs,
            "reservation_commitment":{},
        });
        let requester_contract = fixture_contract(
            &factory,
            &requester,
            ParticipantRole::Requester,
            103,
            &"a4".repeat(32),
            &order,
            &quote,
            &contract,
        )?;
        let provider_contract = fixture_contract(
            &factory,
            &provider,
            ParticipantRole::Provider,
            104,
            &"a5".repeat(32),
            &order,
            &quote,
            &contract,
        )?;
        let status = fixture_signed(
            factory
                .status(
                    ParticipantRole::Requester,
                    200,
                    &"a6".repeat(32),
                    &order.id,
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
        let (effects, evidence_refs) = fixture_terminal_evidence(
            &config,
            &order,
            &contract,
            leg_specs,
            payment_hash,
            outcome,
            requester.pubkey(),
        )?;
        let mut loss = json!({
            "input_asset_id":"bitcoin:regtest:btc",
            "output_asset_id":"lightning:regtest:btc",
            "input_committed":"100",
            "input_recovered":"0",
            "output_received":"0",
            "provider_fee_paid":"0",
            "miner_fee_paid":"0",
            "lightning_routing_fee_paid":"0",
            "guarantee_recovery_received":"0",
            "principal_unresolved":"0",
            "reservation_released":"0",
            "evidence_refs":evidence_refs,
            "unknown_fields":[],
        });
        if outcome == "completed" {
            loss["output_received"] = json!("90");
        } else {
            loss["input_recovered"] = json!("100");
        }
        let close = fixture_signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    210,
                    &"a7".repeat(32),
                    &order.id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 210,
                    },
                    json!({"status_id":status.id,"loss_accounting":loss}),
                )
                .map_err(|error| error.to_string())?,
            &requester,
        )?;
        let records = vec![
            rfq,
            quote,
            order,
            requester_contract,
            provider_contract,
            status,
            close,
        ];
        validate_session_material(&config, &records, &[]).map_err(|error| error.to_string())?;
        validate_lifecycle(&config, &records, &effects).map_err(|error| error.to_string())
    }

    fn fixture_terminal_evidence(
        config: &SwapClientConfig,
        order: &Event,
        contract: &Value,
        leg_specs: &[(&str, &str)],
        payment_hash: &str,
        outcome: &str,
        producer_pubkey: &str,
    ) -> Result<(BTreeMap<String, ExternalEffectResult>, Vec<Value>), String> {
        let contract = contract
            .as_object()
            .ok_or_else(|| "fixture contract is not an object".to_owned())?;
        let mut effects = BTreeMap::new();
        let mut evidence_refs = Vec::new();
        for (index, (leg_id, rail)) in leg_specs.iter().enumerate() {
            let verifier = verifier_for_leg(contract, leg_id).map_err(|error| error.to_string())?;
            let authority = verifier
                .get("evidence_authority")
                .ok_or_else(|| "fixture verifier authority is missing".to_owned())?;
            let authority_sha256 = lower_hex(&sha256(
                &canonical_json(authority).map_err(|error| error.to_string())?,
            ));
            let (class, source_reference, rung) = terminal_evidence_identity(
                contract,
                &order.id,
                payment_hash,
                leg_id,
                rail,
                outcome,
            )
            .map_err(|error| error.to_string())?;
            let settlement_transaction = format!("{:02x}", 192 + index).repeat(32);
            let reference = match (*rail, outcome) {
                ("bitcoin", "completed") => format!("{settlement_transaction}:0"),
                ("bitcoin", "refunded") => settlement_transaction,
                ("lightning", _) => payment_hash.to_owned(),
                _ => return Err("fixture rail/outcome is unsupported".to_owned()),
            };
            let view = format!("fixture-local-{outcome}-{leg_id}");
            let artifact_sha256 = format!("{:02x}", 208 + index).repeat(32);
            let verifier_policy = verifier
                .get("verifier_policy")
                .and_then(Value::as_str)
                .ok_or_else(|| "fixture verifier policy is missing".to_owned())?;
            let evidence = json!({
                "class":class,
                "rung":rung,
                "rail":rail,
                "reference":reference,
                "artifact_sha256":artifact_sha256,
                "producer_pubkey":producer_pubkey,
                "verifier_pubkey":null,
                "verifier_policy":verifier_policy,
                "observed_at":190,
                "view":view,
            });
            validate_mkt_swp_evidence_reference(&evidence)
                .map_err(|error| format!("fixture terminal evidence: {error}"))?;
            let evidence_sha256 = lower_hex(&sha256(
                &canonical_json(&evidence).map_err(|error| error.to_string())?,
            ));
            let effect_id = effect_id(&order.id, &format!("terminal_evidence_{outcome}"), leg_id)
                .map_err(|error| error.to_string())?;
            let request = ExternalEffectRequest::RailEvidence(RailEvidenceRequest {
                effect_id: effect_id.clone(),
                session_id: config.session_id.clone(),
                order_id: order.id.clone(),
                leg_id: (*leg_id).to_owned(),
                outcome: outcome.to_owned(),
                rail: (*rail).to_owned(),
                evidence_class: class,
                source_reference,
                reference,
                artifact_sha256,
                rung,
                verifier_policy: verifier_policy.to_owned(),
                verifier_authority_sha256: authority_sha256,
                observed_at: 190,
                view_sha256: lower_hex(&sha256(view.as_bytes())),
                finality_state: if outcome == "completed" {
                    "settled".to_owned()
                } else {
                    "refunded_final".to_owned()
                },
                evidence_reference_sha256: evidence_sha256.clone(),
            });
            effects.insert(
                effect_id.clone(),
                ExternalEffectResult {
                    order_id: order.id.clone(),
                    effect_id,
                    request_sha256: request.sha256().map_err(|error| error.to_string())?,
                    external_identifier: format!("fixture:{outcome}:{leg_id}"),
                    result_sha256: evidence_sha256,
                },
            );
            evidence_refs.push(evidence);
        }
        Ok((effects, evidence_refs))
    }

    fn fixture_contract(
        factory: &SwapRecordFactory,
        signer: &MarketSigner,
        role: ParticipantRole,
        created_at: u64,
        distinct: &str,
        order: &Event,
        quote: &Event,
        contract: &Value,
    ) -> Result<Event, String> {
        fixture_signed(
            factory
                .swap_contract(
                    role,
                    created_at,
                    distinct,
                    SwapContractReferences {
                        order_id: &order.id,
                        quote_id: &quote.id,
                        accepted_status_id: None,
                    },
                    contract.clone(),
                )
                .map_err(|error| error.to_string())?,
            signer,
        )
    }

    fn fixture_signer(label: &[u8]) -> Result<MarketSigner, String> {
        let key: [u8; 32] =
            Sha256::digest([b"immortal-mkt-swp-fixture-replay:".as_slice(), label].concat()).into();
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

fn require_lower_hex_32(value: &str, label: &str) -> Result<(), SwapClientError> {
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
