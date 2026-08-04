//! Transport-neutral MKT-SWP requester execution and recovery.
//!
//! The embedding wallet owns transport, signing, secrets, chain access, and
//! broadcast. This module validates signed protocol records and public rail
//! inputs, then exposes bounded requests to those external capabilities.

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ENVELOPE_SCHEMA, MKT_ORDER_KIND,
        MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
        MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport, Tag, validate_mkt_private_raw,
    },
    mkt_swp_verify::{
        BitcoinNetwork, ScriptInstruction, Timelock, Transaction, check_cltv, check_csv,
        parse_bolt11, parse_swap_script, sha256, tagged_hash, tapleaf_hash,
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
        if let Some(request_id) = cancellation.request_id {
            require_lower_hex_32(request_id, "Cancel request ID")?;
            tags.push(Tag::new(vec![
                "e".into(),
                request_id.into(),
                String::new(),
                "cancel".into(),
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
        let unsigned = package.unsigned_transaction()?;
        let transaction = Transaction::parse(&unsigned).map_err(|error| {
            SwapClientError::new(
                "swp_exit_package_unusable",
                format!("assembled exit transaction is invalid: {error}"),
            )
        })?;
        validate_exit_leaf_template(&package, &transaction)?;
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
        let transaction_id =
            require_string(funding, "transaction_id", None, "swp_exit_package_unusable")?;
        let mut previous_txid = decode_hex_32(transaction_id, "funding transaction ID")?;
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
    pub payment_hash: String,
    pub funding: FundingVerificationInput,
    pub invoice: Option<InvoiceVerificationInput>,
    pub timeout_ladder: TimeoutLadder,
    pub minimum_confirmations: u32,
    pub replacement_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingAuthorizationRequest {
    pub session_id: String,
    pub order_id: String,
    pub quote_id: String,
    pub swap_type: SwapType,
    pub action: FundingAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEffectResult {
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
}

impl SwapSession<AwaitingVerification> {
    pub fn from_signed_records(
        config: SwapClientConfig,
        signed_records: Vec<Event>,
        exit_packages: Vec<ExitPackage>,
    ) -> Result<Self, SwapClientError> {
        config.validate()?;
        validate_session_material(&config, &signed_records, &exit_packages)?;
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
        if persisted.external_effects.len() > MAX_EXTERNAL_EFFECTS {
            return Err(SwapClientError::new(
                "swp_unresolved_loss",
                "persisted swap snapshot has too many external effects",
            ));
        }
        let mut external_effects = BTreeMap::new();
        for effect in persisted.external_effects {
            validate_effect(&effect)?;
            if let Some(previous) =
                external_effects.insert(effect.effect_id.clone(), effect.clone())
                && previous != effect
            {
                return Err(SwapClientError::new(
                    "swp_external_effect_conflict",
                    "persisted effect ID has conflicting results",
                ));
            }
        }
        Ok(Self {
            config: persisted.config,
            signed_records: persisted.signed_records,
            exit_packages: persisted.exit_packages,
            external_effects,
            funding_request: None,
            _state: PhantomData,
        })
    }

    pub fn verify_before_fund<F>(
        self,
        input: VerifyBeforeFundInput,
        mut wallet_authorize: F,
    ) -> Result<SwapSession<FundingAuthorized>, SwapClientError>
    where
        F: FnMut(&FundingAuthorizationRequest) -> Result<(), String>,
    {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        bound.verify_contract_terms()?;
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
            SwapType::Reverse => FundingAction::PayLightningInvoice {
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
            },
        };
        let request = FundingAuthorizationRequest {
            session_id: self.config.session_id.clone(),
            order_id: bound.order.id.clone(),
            quote_id: bound.quote.id.clone(),
            swap_type: bound.swap_type,
            action,
        };
        wallet_authorize(&request).map_err(|error| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                format!("embedding wallet refused funding: {error}"),
            )
        })?;
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

    pub fn record_external_effect(
        &mut self,
        effect: ExternalEffectResult,
    ) -> Result<&ExternalEffectResult, SwapClientError> {
        validate_effect(&effect)?;
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

    pub fn sign_exit_with<F>(
        &self,
        package_index: usize,
        mut wallet_sign: F,
    ) -> Result<SignedExitTransaction, SwapClientError>
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
        let unsigned = package.unsigned_transaction()?;
        let request = WalletSigningRequest {
            effect_id: package.effect_id()?.to_owned(),
            path: package.path()?.to_owned(),
            unsigned_transaction: lower_hex(&unsigned),
            signature_hash: lower_hex(&package.signing_digest()?),
        };
        let signed = wallet_sign(&request).map_err(|error| {
            SwapClientError::new(
                "swp_funding_not_authorized",
                format!("embedding wallet refused exit signing: {error}"),
            )
        })?;
        validate_signed_transaction_matches(package, &unsigned, &signed)?;
        Ok(SignedExitTransaction {
            effect_id: request.effect_id,
            path: request.path,
            transaction: lower_hex(&signed),
        })
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

    pub fn recovery_action(
        &self,
        observation: &RecoveryObservation,
    ) -> Result<RecoveryAction, SwapClientError> {
        let bound = BoundSession::from_records(&self.config, &self.signed_records)?;
        if observation.completed {
            return Ok(RecoveryAction::Completed);
        }
        if observation.record_loss || observation.rail_state_unknown {
            return Ok(RecoveryAction::ExplicitLoss {
                code: "swp_unresolved_loss".to_owned(),
            });
        }
        match bound.swap_type {
            SwapType::Submarine if observation.counterparty_available => {
                Ok(RecoveryAction::DirectCounterpartyCompletion)
            }
            SwapType::Submarine => refund_action(
                exit_package(&self.exit_packages, "source", "refund"),
                observation,
            ),
            SwapType::Reverse if observation.claim_observed => {
                Ok(RecoveryAction::DirectCounterpartyCompletion)
            }
            SwapType::Reverse if observation.claim_ready => {
                claim_action(exit_package(&self.exit_packages, "destination", "claim"))
            }
            SwapType::Reverse => Ok(RecoveryAction::WaitForCounterparty),
            SwapType::Chain if observation.counterparty_available => {
                Ok(RecoveryAction::DirectCounterpartyCompletion)
            }
            SwapType::Chain => match observation.chain_state {
                Some(ChainRecoveryState::DestinationClaimable) => {
                    claim_action(exit_package(&self.exit_packages, "destination", "claim"))
                }
                Some(ChainRecoveryState::DestinationFundedUnclaimed) => {
                    Ok(RecoveryAction::WaitForDestinationRefund)
                }
                Some(
                    ChainRecoveryState::DestinationNotFunded
                    | ChainRecoveryState::DestinationRefundedFinal,
                ) => refund_action(
                    exit_package(&self.exit_packages, "source", "refund"),
                    observation,
                ),
                None => Ok(RecoveryAction::ExplicitLoss {
                    code: "swp_unresolved_loss".to_owned(),
                }),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct EsploraBroadcastRequest {
    pub method: &'static str,
    pub url: String,
    pub content_type: &'static str,
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
            method: "POST",
            url: format!("{base}/tx"),
            content_type: "text/plain",
            body: lower_hex(&transaction),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservation {
    pub counterparty_available: bool,
    pub timeout_reached: bool,
    pub claim_ready: bool,
    pub claim_observed: bool,
    pub completed: bool,
    pub record_loss: bool,
    pub rail_state_unknown: bool,
    pub chain_state: Option<ChainRecoveryState>,
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
    BroadcastPresigned { effect_id: String },
    RequestWalletClaim { effect_id: String },
    RequestWalletRefund { effect_id: String },
    WaitForCounterparty,
    WaitForDestinationRefund,
    WaitForTimeout,
    Completed,
    ExplicitLoss { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProjection {
    pub streams: BTreeMap<String, BTreeMap<u64, Vec<String>>>,
    pub gaps: BTreeMap<String, Vec<u64>>,
    pub forks: BTreeMap<String, Vec<u64>>,
    pub close_records: Vec<String>,
}

impl StatusProjection {
    fn from_records(config: &SwapClientConfig, records: &[Event]) -> Result<Self, SwapClientError> {
        let mut streams: BTreeMap<String, BTreeMap<u64, Vec<String>>> = BTreeMap::new();
        let mut status_events: BTreeMap<String, BTreeMap<u64, Vec<&Event>>> = BTreeMap::new();
        let mut close_records = Vec::new();
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
                return Err(SwapClientError::new(
                    "swp_status_signer_invalid",
                    "Status signer cannot claim this MKT-SWP state",
                ));
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
            let mut previous: Option<&Event> = None;
            for events in stream.values() {
                let [event] = events.as_slice() else {
                    continue;
                };
                let sequence = tag_value(event, "seq")?
                    .parse::<u64>()
                    .map_err(|_| SwapClientError::new("swp_status_gap", "Status seq is invalid"))?;
                if sequence == 0 {
                    if event.tags.iter().any(|tag| {
                        tag.name() == Some("e")
                            && tag.as_slice().get(3).map(String::as_str) == Some("previous")
                    }) {
                        return Err(SwapClientError::new(
                            "swp_status_transition_invalid",
                            "Status seq 0 must not have a previous reference",
                        ));
                    }
                } else if let Some(previous_event) = previous {
                    require_marked_reference(event, "previous", &previous_event.id)?;
                    let previous_state = status_state(previous_event)?;
                    let current_state = status_state(event)?;
                    if transition_rank(swap_type, &previous_state)
                        .zip(transition_rank(swap_type, &current_state))
                        .is_none_or(|(previous_rank, current_rank)| current_rank <= previous_rank)
                    {
                        return Err(SwapClientError::new(
                            "swp_status_transition_invalid",
                            "Status transition regresses or leaves the selected lifecycle",
                        ));
                    }
                }
                previous = Some(event);
            }
        }
        Ok(Self {
            streams,
            gaps,
            forks,
            close_records,
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
        Ok(())
    }
}

struct BoundSession<'a> {
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
        let expiration = tag_value(self.quote, "expiration")?
            .parse::<u64>()
            .map_err(|_| {
                SwapClientError::new("swp_quote_expired", "Quote expiration is invalid")
            })?;
        if expiration <= self.order.created_at {
            return Err(SwapClientError::new(
                "swp_quote_expired",
                "Quote expired before Order acceptance",
            ));
        }
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
        for member in [
            "swap_type",
            "asset_pair",
            "payment_hash",
            "legs",
            "timeout_ladder",
            "verifier_inputs",
            "recovery",
            "evm_leg",
        ] {
            if terms.get(member) != contract.get(member) {
                return Err(SwapClientError::new(
                    "swp_contract_terms_mismatch",
                    format!("Swap Contract member {member} differs from the Quote"),
                ));
            }
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
    for (leg_id, rail, funding_role, receiving_role) in topology.legs {
        let matching = legs.iter().filter(|leg| {
            leg.get("leg_id").and_then(Value::as_str) == Some(*leg_id)
                && leg.get("rail").and_then(Value::as_str) == Some(*rail)
                && leg.get("funding_role").and_then(Value::as_str) == Some(*funding_role)
                && leg.get("receiving_role").and_then(Value::as_str) == Some(*receiving_role)
        });
        if matching.count() != 1 {
            return Err(SwapClientError::new(
                "swp_contract_terms_mismatch",
                "Swap Contract flow signer or leg topology is invalid",
            ));
        }
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
        for name in ["input_amount", "output_amount"] {
            if quote_terms.get(name) != contract.get(name) {
                return Err(SwapClientError::new(
                    "swp_order_selection_invalid",
                    format!("Swap Contract changed unselected amount member {name}"),
                ));
            }
        }
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
    if let Some(selected_input) = selection.get("input_amount").and_then(Value::as_str) {
        let input = canonical_amount(selected_input)?;
        let provider_fee = contract_amount(contract, "provider_fee")?;
        let miner_fee = contract_amount(contract, "miner_fee_budget")?;
        let lightning_fee = contract_amount(contract, "lightning_routing_fee_budget")?;
        let expected_output = input
            .checked_sub(provider_fee)
            .and_then(|amount| amount.checked_sub(miner_fee))
            .and_then(|amount| amount.checked_sub(lightning_fee))
            .ok_or_else(|| {
                SwapClientError::new(
                    "swp_order_selection_invalid",
                    "selected amount cannot satisfy the quoted amount equation",
                )
            })?;
        if contract.get("input_amount").and_then(Value::as_str) != Some(selected_input)
            || contract_amount(contract, "output_amount")? != expected_output
            || !matches!(
                contract.get("amount_equation").and_then(Value::as_str),
                Some("input_minus_provider_and_quoted_fees" | "one_to_one_less_quoted_fees")
            )
        {
            return Err(SwapClientError::new(
                "swp_order_selection_invalid",
                "selected amount does not reproduce the frozen output amount",
            ));
        }
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
    for package in exit_packages {
        ExitPackage::parse(package.document.clone())?;
    }
    StatusProjection::from_records(config, records)?;
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
        for member in ["taproot_script", "taproot_control_block"] {
            if verification.get(member) != verifier.get(member) {
                return Err(SwapClientError::new(
                    "swp_exit_package_mismatch",
                    format!("exit verification member {member} differs from its leg verifier"),
                ));
            }
        }
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

fn refund_action(
    package: Option<&ExitPackage>,
    observation: &RecoveryObservation,
) -> Result<RecoveryAction, SwapClientError> {
    let Some(package) = package else {
        return Ok(RecoveryAction::ExplicitLoss {
            code: "swp_exit_package_missing".to_owned(),
        });
    };
    if !observation.timeout_reached {
        return Ok(RecoveryAction::WaitForTimeout);
    }
    let effect_id = package.effect_id()?.to_owned();
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

fn claim_action(package: Option<&ExitPackage>) -> Result<RecoveryAction, SwapClientError> {
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
    Ok(RecoveryAction::RequestWalletClaim {
        effect_id: package.effect_id()?.to_owned(),
    })
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
    let instructions = parse_swap_script(&script).map_err(|error| {
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
    let path = package.path()?;
    match (path, condition) {
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

fn validate_effect(effect: &ExternalEffectResult) -> Result<(), SwapClientError> {
    for (value, label) in [
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
        "completed" | "refunded" | "disputed" | "failed" | "unresolved"
    );
    if common {
        return true;
    }
    match (swap_type, role) {
        (SwapType::Submarine, ParticipantRole::Requester) => matches!(
            state,
            "requester_verification_passed"
                | "requester_funding_broadcast"
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
            "requester_funding_broadcast",
            "lightning_payment_pending",
            "lightning_paid",
            "provider_claim_pending",
            "provider_claimed",
            "refund_prepared",
            "refund_pending",
            "refunded",
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
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
        SwapType::Chain => &[
            "accepted",
            "source_lock_terms_ready",
            "requester_source_verified",
            "requester_source_broadcast",
            "destination_lock_terms_ready",
            "requester_destination_verified",
            "provider_destination_broadcast",
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
    let requester = [
        "requester_verification_passed",
        "requester_invoice_verified",
        "requester_lock_verified",
        "requester_source_verified",
        "requester_destination_verified",
        "requester_funding_broadcast",
        "requester_source_broadcast",
        "requester_claim_pending",
        "requester_claimed",
        "requester_destination_claim_pending",
        "requester_destination_claimed",
        "refund_prepared",
        "refund_pending",
        "requester_source_refund_prepared",
        "requester_source_refund_pending",
        "requester_source_refunded",
        "completed",
        "refunded",
        "disputed",
        "failed",
        "unresolved",
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
        "completed",
        "refunded",
        "disputed",
        "failed",
        "unresolved",
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
                        | "refundprivatekey"
                        | "preimage"
                        | "macaroon"
                        | "lndmacaroon"
                        | "nwc"
                        | "nwcstring"
                        | "nwcuri"
                        | "bearertoken"
                        | "walletcredential"
                        | "walletrpcpayload"
                        | "musigsecretnonce"
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
    let authority = url.strip_prefix("https://").ok_or_else(|| {
        SwapClientError::new(
            "swp_exit_package_unusable",
            "Esplora endpoint must use HTTPS",
        )
    })?;
    if authority.is_empty()
        || url.len() > 2_048
        || authority.contains('@')
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
    Ok(url)
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
