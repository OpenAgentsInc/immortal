//! Transport-neutral MKT-SWP provider sessions.
//!
//! The embedding provider owns transport, signing, inventory, credentials,
//! funds, and rail access. This module retains only signed protocol records,
//! public reservation confirmations, and idempotent effect receipts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use immortal_client::mkt_swp_client::{
    Cancellation, CloseOutcome, MktSigningRequest, ParticipantRole, StatusProjection, StatusState,
    SwapClientConfig, SwapClientError, SwapContractReferences, SwapRecordFactory,
    provider_support::{
        canonical_json, error as provider_error, reject_custody_material, require_lower_hex_32,
        require_signer_status_contiguous, status_projection as project_status,
        validate_contract_candidate, validate_no_spend_loss_accounting,
        validate_order_acceptance_deadline, validate_order_selection, validate_quote_against_rfq,
        validate_quote_profile,
    },
};
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
use immortal_client::mkt_swp_client::{
    CooperativeSigningContext, CooperativeSigningMessage, ExitPackage,
    provider_support::validate_provider_cooperative_context,
};
use immortal_core::domain::{
    Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ENVELOPE_SCHEMA, MKT_OFFERING_KIND, MKT_ORDER_KIND,
    MKT_PROVIDER_PROFILE_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_SWP_PROFILE_ID,
    MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport, Tag,
    validate_mkt_private_raw, validate_mkt_public_event, validate_mkt_swp_evidence_reference,
};

const PROVIDER_SNAPSHOT_SCHEMA: &str = "openagents.mkt-swp.provider-snapshot.v1";
pub(crate) const MAX_PROVIDER_RECORDS: usize = 512;
pub(crate) const MAX_PROVIDER_EFFECTS: usize = 128;
pub(crate) const MAX_PROVIDER_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MktPublicSigningRequest {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
    pub expected_event_id: String,
}

impl MktPublicSigningRequest {
    fn new(
        pubkey: &str,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        content: Value,
    ) -> Result<Self, SwapClientError> {
        require_lower_hex_32(pubkey, "provider pubkey")?;
        reject_custody_material(&content)?;
        let content = serde_json::to_string(&content).map_err(|error| {
            provider_error(
                "swp_terms_mismatch",
                format!("could not serialize discovery content: {error}"),
            )
        })?;
        let unsigned = Event {
            id: String::new(),
            pubkey: pubkey.to_owned(),
            created_at,
            kind,
            tags: tags.clone(),
            content: content.clone(),
            sig: String::new(),
        };
        validate_mkt_public_event(&unsigned).map_err(|error| {
            provider_error(
                "swp_terms_mismatch",
                format!("discovery request violates MKT-SWP: {error}"),
            )
        })?;
        let expected_event_id = unsigned.computed_id().map_err(|error| {
            provider_error(
                "swp_terms_mismatch",
                format!("could not compute discovery event ID: {error}"),
            )
        })?;
        Ok(Self {
            pubkey: pubkey.to_owned(),
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
            return Err(provider_error(
                "swp_external_signature_mismatch",
                "external signer changed the requested discovery event bytes",
            ));
        }
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .map_err(|error| {
                provider_error(
                    "swp_external_signature_invalid",
                    format!("external signer returned an invalid event: {error}"),
                )
            })?;
        validate_mkt_public_event(&event).map_err(|error| {
            provider_error(
                "swp_terms_mismatch",
                format!("signed discovery event violates MKT-SWP: {error}"),
            )
        })?;
        Ok(event)
    }
}

#[derive(Debug, Clone)]
pub struct ProviderDiscoveryFactory {
    provider_pubkey: String,
}

impl ProviderDiscoveryFactory {
    pub fn new(provider_pubkey: impl Into<String>) -> Result<Self, SwapClientError> {
        let provider_pubkey = provider_pubkey.into();
        require_lower_hex_32(&provider_pubkey, "provider pubkey")?;
        Ok(Self { provider_pubkey })
    }

    pub fn profile(
        &self,
        created_at: u64,
        provider_id: &str,
        status: &str,
        content: Value,
    ) -> Result<MktPublicSigningRequest, SwapClientError> {
        MktPublicSigningRequest::new(
            &self.provider_pubkey,
            created_at,
            MKT_PROVIDER_PROFILE_KIND,
            vec![
                pair("d", provider_id),
                pair("status", status),
                pair("published_at", &created_at.to_string()),
                Tag::new(vec![
                    "profile".into(),
                    MKT_SWP_PROFILE_ID.into(),
                    MKT_SWP_PROFILE_VERSION.to_string(),
                ]),
            ],
            content,
        )
    }

    pub fn offering(
        &self,
        created_at: u64,
        provider_id: &str,
        offering_id: &str,
        status: &str,
        content: Value,
    ) -> Result<MktPublicSigningRequest, SwapClientError> {
        MktPublicSigningRequest::new(
            &self.provider_pubkey,
            created_at,
            MKT_OFFERING_KIND,
            vec![
                pair("d", offering_id),
                pair("status", status),
                pair("published_at", &created_at.to_string()),
                Tag::new(vec![
                    "profile".into(),
                    MKT_SWP_PROFILE_ID.into(),
                    MKT_SWP_PROFILE_VERSION.to_string(),
                ]),
                pair(
                    "provider",
                    &format!("39600:{}:{provider_id}", self.provider_pubkey),
                ),
            ],
            content,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub reservation_id: String,
    pub capacity_bucket_id: String,
    pub reserved_asset_id: String,
    pub reserved_amount: String,
    pub reservation_expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationConfirmation {
    pub reservation_id: String,
    pub capacity_bucket_id: String,
    pub reserved_asset_id: String,
    pub reserved_amount: String,
    pub committed_capacity: String,
    pub reservation_expires_at: u64,
    pub allocation_sequence: String,
    pub proof_class: String,
    pub proof_ref: String,
    pub capacity_commitment_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEffectKind {
    Reserve,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationReleaseCause {
    EffectiveCancel,
    ReservationExpired,
    TerminalClose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEffectRequest {
    pub effect_id: String,
    pub operation: ProviderEffectKind,
    pub session_id: String,
    pub reservation_id: String,
    pub capacity_bucket_id: String,
    pub reserved_asset_id: String,
    pub reserved_amount: String,
    pub reservation_expires_at: u64,
    pub release_cause: Option<ReservationReleaseCause>,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEffectReceipt {
    pub effect_id: String,
    pub request_sha256: String,
    pub external_reference: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEffectRecord {
    request: ProviderEffectRequest,
    receipt: ProviderEffectReceipt,
    confirmation: Option<ReservationConfirmation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderSnapshot {
    schema: String,
    config: SwapClientConfig,
    signed_records: Vec<Event>,
    effects: BTreeMap<String, ProviderEffectRecord>,
    reservation: Option<ReservationConfirmation>,
    hard_quote_request: Option<MktSigningRequest>,
    released: bool,
}

#[derive(Debug, Clone)]
pub struct ProviderSession {
    config: SwapClientConfig,
    factory: SwapRecordFactory,
    signed_records: Vec<Event>,
    effects: BTreeMap<String, ProviderEffectRecord>,
    reservation: Option<ReservationConfirmation>,
    hard_quote_request: Option<MktSigningRequest>,
    released: bool,
}

impl ProviderSession {
    pub fn new(config: SwapClientConfig) -> Result<Self, SwapClientError> {
        let factory = SwapRecordFactory::new(config.clone())?;
        Ok(Self {
            config,
            factory,
            signed_records: Vec::new(),
            effects: BTreeMap::new(),
            reservation: None,
            hard_quote_request: None,
            released: false,
        })
    }

    pub fn config(&self) -> &SwapClientConfig {
        &self.config
    }

    pub fn signed_records(&self) -> &[Event] {
        &self.signed_records
    }

    pub fn reservation(&self) -> Option<&ReservationConfirmation> {
        self.reservation.as_ref()
    }

    pub fn reservation_released(&self) -> bool {
        self.released
    }

    pub fn status_projection(&self) -> Result<StatusProjection, SwapClientError> {
        project_status(&self.config, &self.signed_records)
    }

    pub fn persist(&self) -> Result<Vec<u8>, SwapClientError> {
        let snapshot = ProviderSnapshot {
            schema: PROVIDER_SNAPSHOT_SCHEMA.into(),
            config: self.config.clone(),
            signed_records: self.signed_records.clone(),
            effects: self.effects.clone(),
            reservation: self.reservation.clone(),
            hard_quote_request: self.hard_quote_request.clone(),
            released: self.released,
        };
        let value = serde_json::to_value(&snapshot).map_err(|error| {
            provider_error(
                "swp_provider_snapshot_invalid",
                format!("could not encode provider snapshot: {error}"),
            )
        })?;
        reject_custody_material(&value)?;
        let bytes = serde_json::to_vec(&snapshot).map_err(|error| {
            provider_error(
                "swp_provider_snapshot_invalid",
                format!("could not serialize provider snapshot: {error}"),
            )
        })?;
        if bytes.len() > MAX_PROVIDER_SNAPSHOT_BYTES {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot exceeds its byte bound",
            ));
        }
        Ok(bytes)
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, SwapClientError> {
        if bytes.len() > MAX_PROVIDER_SNAPSHOT_BYTES {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot exceeds its byte bound",
            ));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|error| {
            provider_error(
                "swp_provider_snapshot_invalid",
                format!("provider snapshot is invalid JSON: {error}"),
            )
        })?;
        reject_custody_material(&value)?;
        let snapshot: ProviderSnapshot = serde_json::from_value(value).map_err(|error| {
            provider_error(
                "swp_provider_snapshot_invalid",
                format!("provider snapshot shape is invalid: {error}"),
            )
        })?;
        if snapshot.schema != PROVIDER_SNAPSHOT_SCHEMA {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot schema is invalid",
            ));
        }
        validate_provider_collection_bounds(snapshot.signed_records.len(), snapshot.effects.len())?;
        let released = validate_effect_records(&snapshot.config, &snapshot.effects)?;
        if snapshot.released != released {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot release flag does not match its durable release effect",
            ));
        }
        let mut restored = Self::new(snapshot.config)?;
        restored.effects = snapshot.effects.clone();
        restored.reservation = snapshot.reservation.clone();
        restored.hard_quote_request = snapshot.hard_quote_request.clone();
        restored.released = released;
        for event in snapshot.signed_records {
            restored.ingest_signed(event)?;
        }
        if snapshot.reservation.as_ref()
            != snapshot
                .effects
                .values()
                .find_map(|effect| effect.confirmation.as_ref())
        {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot reservation does not match its reserve effect",
            ));
        }
        validate_hard_quote_request(
            &restored.config,
            restored.hard_quote_request.as_ref(),
            restored.reservation.as_ref(),
            &restored.signed_records,
        )?;
        Ok(restored)
    }

    pub fn ingest_signed(&mut self, event: Event) -> Result<bool, SwapClientError> {
        validate_session_event(&self.config, &event)?;
        if let Some(existing) = self
            .signed_records
            .iter()
            .find(|existing| existing.id == event.id)
        {
            if existing == &event {
                return Ok(false);
            }
            return Err(provider_error(
                "swp_idempotency_conflict",
                "provider history contains conflicting bytes for one event ID",
            ));
        }
        validate_provider_collection_bounds(self.signed_records.len() + 1, self.effects.len())?;
        self.validate_next_event(&event)?;
        self.signed_records.push(event);
        Ok(true)
    }

    pub fn indicative_quote(
        &self,
        created_at: u64,
        distinct: &str,
        expiration: u64,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let rfq = self.rfq()?;
        validate_quote_profile(&mkt_swp, "none")?;
        validate_quote_against_rfq(rfq, &mkt_swp, "indicative", created_at, expiration)?;
        self.factory
            .indicative_quote(created_at, distinct, &rfq.id, expiration, mkt_swp)
    }

    pub fn soft_quote(
        &self,
        created_at: u64,
        distinct: &str,
        expiration: u64,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let rfq = self.rfq()?;
        validate_quote_profile(&mkt_swp, "soft")?;
        validate_quote_against_rfq(rfq, &mkt_swp, "firm", created_at, expiration)?;
        self.factory
            .soft_quote(created_at, distinct, &rfq.id, expiration, mkt_swp)
    }

    pub fn hard_quote_with_reserve<F>(
        &mut self,
        created_at: u64,
        distinct: &str,
        expiration: u64,
        reservation: ReservationRequest,
        mut mkt_swp: Value,
        mut reserve: F,
    ) -> Result<MktSigningRequest, SwapClientError>
    where
        F: FnMut(&ProviderEffectRequest) -> Result<ReservationConfirmation, String>,
    {
        let rfq = self.rfq()?.clone();
        let rfq_id = rfq.id.clone();
        validate_quote_profile(&mkt_swp, "none")?;
        validate_quote_against_rfq(&rfq, &mkt_swp, "firm", created_at, expiration)?;
        validate_reservation_request(&reservation, created_at)?;
        let preflight_confirmation = ReservationConfirmation {
            reservation_id: reservation.reservation_id.clone(),
            capacity_bucket_id: reservation.capacity_bucket_id.clone(),
            reserved_asset_id: reservation.reserved_asset_id.clone(),
            reserved_amount: reservation.reserved_amount.clone(),
            committed_capacity: reservation.reserved_amount.clone(),
            reservation_expires_at: reservation.reservation_expires_at,
            allocation_sequence: "1".into(),
            proof_class: "handler_accounted".into(),
            proof_ref: "provider-preflight".into(),
            capacity_commitment_sha256: "00".repeat(32),
        };
        validate_reservation_confirmation(&reservation, &preflight_confirmation)?;
        let mut preflight_profile = mkt_swp.clone();
        insert_reservation_terms(&mut preflight_profile, &preflight_confirmation)?;
        validate_quote_profile(&preflight_profile, "hard")?;
        hard_quote_request(
            &self.config,
            created_at,
            distinct,
            &rfq_id,
            expiration,
            preflight_profile,
        )?;
        if let Some(existing) = self.reservation.as_ref() {
            if existing.reservation_id != reservation.reservation_id
                || existing.capacity_bucket_id != reservation.capacity_bucket_id
                || existing.reserved_asset_id != reservation.reserved_asset_id
                || existing.reserved_amount != reservation.reserved_amount
                || existing.reservation_expires_at != reservation.reservation_expires_at
            {
                return Err(provider_error(
                    "swp_idempotency_conflict",
                    "provider session cannot reserve a second hard-Quote allocation",
                ));
            }
        }
        let effect_request = reserve_effect_request(&self.config, &reservation)?;
        let confirmation = if let Some(record) = self.effects.get(&effect_request.effect_id) {
            ensure_effect_replay(record, &effect_request)?;
            record.confirmation.clone().ok_or_else(|| {
                provider_error(
                    "swp_idempotency_conflict",
                    "reserve effect replay has no reservation confirmation",
                )
            })?
        } else {
            validate_provider_collection_bounds(self.signed_records.len(), self.effects.len() + 1)?;
            let confirmation = reserve(&effect_request).map_err(|error| {
                provider_error(
                    "swp_reservation_unconfirmed",
                    format!("provider reserve callback rejected capacity: {error}"),
                )
            })?;
            validate_reservation_confirmation(&reservation, &confirmation)?;
            let result_sha256 =
                digest_value(&serde_json::to_value(&confirmation).map_err(|error| {
                    provider_error(
                        "swp_reservation_confirmation_invalid",
                        format!("could not encode reserve confirmation: {error}"),
                    )
                })?)?;
            let receipt = ProviderEffectReceipt {
                effect_id: effect_request.effect_id.clone(),
                request_sha256: effect_request.request_sha256.clone(),
                external_reference: confirmation.proof_ref.clone(),
                result_sha256,
            };
            self.effects.insert(
                effect_request.effect_id.clone(),
                ProviderEffectRecord {
                    request: effect_request,
                    receipt,
                    confirmation: Some(confirmation.clone()),
                },
            );
            self.reservation = Some(confirmation.clone());
            confirmation
        };
        insert_reservation_terms(&mut mkt_swp, &confirmation)?;
        validate_quote_profile(&mkt_swp, "hard")?;
        let request = hard_quote_request(
            &self.config,
            created_at,
            distinct,
            &rfq_id,
            expiration,
            mkt_swp,
        )?;
        if let Some(existing) = self.hard_quote_request.as_ref() {
            if existing == &request {
                return Ok(existing.clone());
            }
            return Err(provider_error(
                "swp_idempotency_conflict",
                "one confirmed reservation cannot back multiple hard Quote records",
            ));
        }
        self.hard_quote_request = Some(request.clone());
        Ok(request)
    }

    pub fn hard_quote_with_bound_reserve<F>(
        &mut self,
        created_at: u64,
        distinct: &str,
        expiration: u64,
        reservation: ReservationRequest,
        mkt_swp: Value,
        mut reserve_and_bind: F,
    ) -> Result<MktSigningRequest, SwapClientError>
    where
        F: FnMut(
            &ProviderEffectRequest,
            Option<&ReservationConfirmation>,
            Value,
        ) -> Result<(ReservationConfirmation, Value), String>,
    {
        let rfq = self.rfq()?.clone();
        let rfq_id = rfq.id.clone();
        validate_quote_profile(&mkt_swp, "none")?;
        validate_quote_against_rfq(&rfq, &mkt_swp, "firm", created_at, expiration)?;
        validate_reservation_request(&reservation, created_at)?;
        let preflight_confirmation = ReservationConfirmation {
            reservation_id: reservation.reservation_id.clone(),
            capacity_bucket_id: reservation.capacity_bucket_id.clone(),
            reserved_asset_id: reservation.reserved_asset_id.clone(),
            reserved_amount: reservation.reserved_amount.clone(),
            committed_capacity: reservation.reserved_amount.clone(),
            reservation_expires_at: reservation.reservation_expires_at,
            allocation_sequence: "1".into(),
            proof_class: "handler_accounted".into(),
            proof_ref: "provider-preflight".into(),
            capacity_commitment_sha256: "00".repeat(32),
        };
        validate_reservation_confirmation(&reservation, &preflight_confirmation)?;
        let mut preflight_profile = mkt_swp.clone();
        insert_reservation_terms(&mut preflight_profile, &preflight_confirmation)?;
        validate_quote_profile(&preflight_profile, "hard")?;
        hard_quote_request(
            &self.config,
            created_at,
            distinct,
            &rfq_id,
            expiration,
            preflight_profile,
        )?;
        if let Some(existing) = self.reservation.as_ref() {
            if existing.reservation_id != reservation.reservation_id
                || existing.capacity_bucket_id != reservation.capacity_bucket_id
                || existing.reserved_asset_id != reservation.reserved_asset_id
                || existing.reserved_amount != reservation.reserved_amount
                || existing.reservation_expires_at != reservation.reservation_expires_at
            {
                return Err(provider_error(
                    "swp_idempotency_conflict",
                    "provider session cannot reserve a second hard-Quote allocation",
                ));
            }
        }
        let effect_request = reserve_effect_request(&self.config, &reservation)?;
        let existing_confirmation = self
            .effects
            .get(&effect_request.effect_id)
            .map(|existing| {
                ensure_effect_replay(existing, &effect_request)?;
                existing.confirmation.clone().ok_or_else(|| {
                    provider_error(
                        "swp_idempotency_conflict",
                        "reserve-and-bind replay has no prior confirmation",
                    )
                })
            })
            .transpose()?;
        let (confirmation, mut bound_profile) =
            reserve_and_bind(&effect_request, existing_confirmation.as_ref(), mkt_swp).map_err(
                |error| {
                    provider_error(
                        "swp_reservation_unconfirmed",
                        format!("provider reserve-and-bind callback rejected capacity: {error}"),
                    )
                },
            )?;
        validate_reservation_confirmation(&reservation, &confirmation)?;
        validate_quote_profile(&bound_profile, "none")?;
        validate_quote_against_rfq(&rfq, &bound_profile, "firm", created_at, expiration)?;
        let result_sha256 =
            digest_value(&serde_json::to_value(&confirmation).map_err(|error| {
                provider_error(
                    "swp_reservation_confirmation_invalid",
                    format!("could not encode reserve confirmation: {error}"),
                )
            })?)?;
        let receipt = ProviderEffectReceipt {
            effect_id: effect_request.effect_id.clone(),
            request_sha256: effect_request.request_sha256.clone(),
            external_reference: confirmation.proof_ref.clone(),
            result_sha256,
        };
        let effect_record = ProviderEffectRecord {
            request: effect_request.clone(),
            receipt,
            confirmation: Some(confirmation.clone()),
        };
        if let Some(existing) = self.effects.get(&effect_request.effect_id) {
            ensure_effect_replay(existing, &effect_request)?;
            if existing != &effect_record {
                return Err(provider_error(
                    "swp_idempotency_conflict",
                    "reserve-and-bind replay changed its confirmation",
                ));
            }
        } else {
            validate_provider_collection_bounds(self.signed_records.len(), self.effects.len() + 1)?;
            self.effects
                .insert(effect_request.effect_id.clone(), effect_record);
        }
        self.reservation = Some(confirmation.clone());
        insert_reservation_terms(&mut bound_profile, &confirmation)?;
        validate_quote_profile(&bound_profile, "hard")?;
        let request = hard_quote_request(
            &self.config,
            created_at,
            distinct,
            &rfq_id,
            expiration,
            bound_profile,
        )?;
        if let Some(existing) = self.hard_quote_request.as_ref() {
            if existing == &request {
                return Ok(existing.clone());
            }
            return Err(provider_error(
                "swp_idempotency_conflict",
                "one confirmed reservation cannot back multiple hard Quote records",
            ));
        }
        self.hard_quote_request = Some(request.clone());
        Ok(request)
    }

    pub fn provider_status(
        &self,
        created_at: u64,
        distinct: &str,
        status: StatusState<'_>,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let request = self.factory.status(
            ParticipantRole::Provider,
            created_at,
            distinct,
            &self.order()?.id,
            status,
            extra,
        )?;
        let unsigned = unsigned_event(&request);
        self.validate_next_event(&unsigned)?;
        let mut candidate = self.signed_records.clone();
        candidate.push(unsigned.clone());
        let projection = project_status(&self.config, &candidate)?;
        require_signer_status_contiguous(&projection, &self.config.provider_pubkey)?;
        if projection.invalid_claims.contains_key(&unsigned.id) {
            return Err(provider_error(
                "swp_status_transition_invalid",
                "provider cannot author an invalid Status claim",
            ));
        }
        Ok(request)
    }

    #[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
    pub(crate) fn provider_cooperative_status(
        &self,
        created_at: u64,
        distinct: &str,
        status: StatusState<'_>,
        message: CooperativeSigningMessage,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let request = self.factory.cooperative_status(
            ParticipantRole::Provider,
            created_at,
            distinct,
            &self.order()?.id,
            status,
            message,
        )?;
        let unsigned = unsigned_event(&request);
        self.validate_next_event(&unsigned)?;
        let mut candidate = self.signed_records.clone();
        candidate.push(unsigned.clone());
        let projection = project_status(&self.config, &candidate)?;
        require_signer_status_contiguous(&projection, &self.config.provider_pubkey)?;
        if projection.invalid_claims.contains_key(&unsigned.id) {
            return Err(provider_error(
                "swp_status_transition_invalid",
                "provider cannot author an invalid cooperative Status claim",
            ));
        }
        Ok(request)
    }

    #[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
    pub(crate) fn validate_provider_cooperative_context(
        &self,
        context: &CooperativeSigningContext,
        package: &ExitPackage,
    ) -> Result<(), SwapClientError> {
        validate_provider_cooperative_context(&self.config, &self.signed_records, context, package)
    }

    pub fn provider_status_with_evidence(
        &self,
        created_at: u64,
        distinct: &str,
        status: StatusState<'_>,
        evidence: Value,
        mut extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, SwapClientError> {
        validate_mkt_swp_evidence_reference(&evidence).map_err(|error| {
            provider_error(
                "swp_evidence_invalid",
                format!("provider evidence reference is invalid: {error}"),
            )
        })?;
        reject_custody_material(&evidence)?;
        extra.insert("evidence".into(), evidence);
        self.provider_status(created_at, distinct, status, extra)
    }

    pub fn provider_swap_contract(
        &self,
        created_at: u64,
        distinct: &str,
        accepted_status_id: Option<&str>,
        contract: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let order = self.order()?;
        let quote = self.quote()?;
        let requester_contract = self
            .signed_records
            .iter()
            .find(|record| {
                record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                    && record.pubkey == self.config.requester_pubkey
            })
            .ok_or_else(|| {
                provider_error(
                    "swp_contract_missing",
                    "provider cannot countersign before the requester Swap Contract",
                )
            })?;
        let requester_profile = mkt_swp_body(requester_contract)?;
        let agreed_contract = requester_profile.get("contract").ok_or_else(|| {
            provider_error(
                "swp_contract_terms_mismatch",
                "requester Swap Contract has no contract object",
            )
        })?;
        if agreed_contract != &contract {
            return Err(provider_error(
                "swp_contract_digest_mismatch",
                "provider contract differs from the requester-signed contract",
            ));
        }
        validate_contract_candidate(&self.config, &self.signed_records, &contract)?;
        self.factory.swap_contract(
            ParticipantRole::Provider,
            created_at,
            distinct,
            SwapContractReferences {
                order_id: &order.id,
                quote_id: &quote.id,
                accepted_status_id,
            },
            contract,
        )
    }

    pub fn provider_cancel(
        &self,
        created_at: u64,
        distinct: &str,
        cancellation: Cancellation<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        let request = self.factory.cancel(
            ParticipantRole::Provider,
            created_at,
            distinct,
            &self.order()?.id,
            cancellation,
            mkt_swp,
        )?;
        self.validate_next_event(&unsigned_event(&request))?;
        Ok(request)
    }

    pub fn provider_close(
        &self,
        created_at: u64,
        distinct: &str,
        close: CloseOutcome<'_>,
        mkt_swp: Value,
    ) -> Result<MktSigningRequest, SwapClientError> {
        require_signer_status_contiguous(&self.status_projection()?, &self.config.provider_pubkey)?;
        let request = self.factory.close(
            ParticipantRole::Provider,
            created_at,
            distinct,
            &self.order()?.id,
            close,
            mkt_swp,
        )?;
        self.validate_next_event(&unsigned_event(&request))?;
        Ok(request)
    }

    pub fn provider_close_with_release<F>(
        &mut self,
        created_at: u64,
        distinct: &str,
        close: CloseOutcome<'_>,
        mkt_swp: Value,
        mut release: F,
    ) -> Result<(MktSigningRequest, ProviderEffectReceipt), SwapClientError>
    where
        F: FnMut(&ProviderEffectRequest) -> Result<ProviderEffectReceipt, String>,
    {
        require_signer_status_contiguous(&self.status_projection()?, &self.config.provider_pubkey)?;
        let request = self.factory.close(
            ParticipantRole::Provider,
            created_at,
            distinct,
            &self.order()?.id,
            close,
            mkt_swp,
        )?;
        let unsigned = unsigned_event(&request);
        self.validate_idempotency_key(&unsigned)?;
        let mut candidate = self.signed_records.clone();
        candidate.push(unsigned.clone());
        validate_close_history(
            &self.config,
            &candidate,
            &unsigned,
            self.reservation.as_ref(),
            self.released,
            true,
        )?;
        let receipt = self
            .release_reservation_inner(
                ReservationReleaseCause::TerminalClose,
                created_at,
                true,
                &mut release,
            )?
            .ok_or_else(|| {
                provider_error(
                    "swp_reservation_release_invalid",
                    "Close release requested without a reservation",
                )
            })?;
        Ok((request, receipt))
    }

    pub fn release_reservation<F>(
        &mut self,
        cause: ReservationReleaseCause,
        observed_at: u64,
        mut release: F,
    ) -> Result<Option<ProviderEffectReceipt>, SwapClientError>
    where
        F: FnMut(&ProviderEffectRequest) -> Result<ProviderEffectReceipt, String>,
    {
        self.release_reservation_inner(cause, observed_at, false, &mut release)
    }

    fn release_reservation_inner<F>(
        &mut self,
        cause: ReservationReleaseCause,
        observed_at: u64,
        validated_terminal_close: bool,
        mut release: F,
    ) -> Result<Option<ProviderEffectReceipt>, SwapClientError>
    where
        F: FnMut(&ProviderEffectRequest) -> Result<ProviderEffectReceipt, String>,
    {
        let Some(reservation) = self.reservation.as_ref() else {
            return Ok(None);
        };
        validate_release_cause(
            &self.signed_records,
            reservation,
            cause,
            observed_at,
            validated_terminal_close,
        )?;
        let effect_request = release_effect_request(&self.config, reservation, cause)?;
        if let Some(released) = self
            .effects
            .values()
            .find(|effect| effect.request.operation == ProviderEffectKind::Release)
        {
            if released.request == effect_request {
                self.released = true;
                return Ok(Some(released.receipt.clone()));
            }
            return Err(provider_error(
                "swp_idempotency_conflict",
                "provider reservation was already released for a different cause",
            ));
        }
        if let Some(record) = self.effects.get(&effect_request.effect_id) {
            ensure_effect_replay(record, &effect_request)?;
            self.released = true;
            return Ok(Some(record.receipt.clone()));
        }
        validate_provider_collection_bounds(self.signed_records.len(), self.effects.len() + 1)?;
        let receipt = release(&effect_request).map_err(|error| {
            provider_error(
                "swp_reservation_release_failed",
                format!("provider release callback failed: {error}"),
            )
        })?;
        validate_effect_receipt(&effect_request, &receipt)?;
        self.effects.insert(
            effect_request.effect_id.clone(),
            ProviderEffectRecord {
                request: effect_request,
                receipt: receipt.clone(),
                confirmation: None,
            },
        );
        self.released = true;
        Ok(Some(receipt))
    }

    fn rfq(&self) -> Result<&Event, SwapClientError> {
        exactly_one(&self.signed_records, MKT_RFQ_KIND, "RFQ")
    }

    fn quote(&self) -> Result<&Event, SwapClientError> {
        exactly_one(&self.signed_records, MKT_QUOTE_KIND, "Quote")
    }

    fn order(&self) -> Result<&Event, SwapClientError> {
        exactly_one(&self.signed_records, MKT_ORDER_KIND, "Order")
    }

    fn validate_next_event(&self, event: &Event) -> Result<(), SwapClientError> {
        match event.kind {
            MKT_RFQ_KIND => {
                require_author(&self.config, event, ParticipantRole::Requester)?;
                if self
                    .signed_records
                    .iter()
                    .any(|record| record.kind == MKT_RFQ_KIND)
                {
                    return Err(provider_error(
                        "swp_contract_terms_mismatch",
                        "provider session accepts exactly one RFQ",
                    ));
                }
            }
            MKT_QUOTE_KIND => {
                require_author(&self.config, event, ParticipantRole::Provider)?;
                require_reference(event, "rfq", &self.rfq()?.id)?;
                if self
                    .signed_records
                    .iter()
                    .any(|record| record.kind == MKT_QUOTE_KIND)
                {
                    return Err(provider_error(
                        "swp_idempotency_conflict",
                        "provider session accepts one immutable Quote",
                    ));
                }
                let reservation_class = tag_value(event, "reservation")?;
                let profile = Value::Object(mkt_swp_body(event)?);
                validate_quote_profile(&profile, reservation_class)?;
                let expiration = tag_value(event, "expiration")?
                    .parse::<u64>()
                    .map_err(|_| {
                        provider_error("swp_quote_expired", "Quote expiration is invalid")
                    })?;
                validate_quote_against_rfq(
                    self.rfq()?,
                    &profile,
                    tag_value(event, "quote")?,
                    event.created_at,
                    expiration,
                )?;
                if reservation_class == "hard" {
                    let confirmation = self.reservation.as_ref().ok_or_else(|| {
                        provider_error(
                            "swp_reservation_unconfirmed",
                            "hard Quote has no confirmed provider reservation",
                        )
                    })?;
                    validate_quote_confirmation(event, confirmation)?;
                    let request = self.hard_quote_request.as_ref().ok_or_else(|| {
                        provider_error(
                            "swp_reservation_unconfirmed",
                            "hard Quote was not produced by the confirmed reserve gate",
                        )
                    })?;
                    request.verify_signed(event.clone())?;
                }
            }
            MKT_ORDER_KIND => {
                require_author(&self.config, event, ParticipantRole::Requester)?;
                if self
                    .signed_records
                    .iter()
                    .any(|record| record.kind == MKT_ORDER_KIND)
                {
                    return Err(provider_error(
                        "swp_idempotency_conflict",
                        "provider session accepts one immutable Order",
                    ));
                }
                let quote = self.quote()?;
                require_reference(event, "quote", &quote.id)?;
                if tag_value(quote, "quote")? != "firm"
                    || !matches!(tag_value(quote, "reservation")?, "soft" | "hard")
                {
                    return Err(provider_error(
                        "swp_contract_terms_mismatch",
                        "Order must select a firm soft- or hard-reserved Quote",
                    ));
                }
                let expiration = tag_value(quote, "expiration")?
                    .parse::<u64>()
                    .map_err(|_| {
                        provider_error("swp_quote_expired", "Quote expiration is invalid")
                    })?;
                if event.created_at > expiration {
                    return Err(provider_error(
                        "swp_quote_expired",
                        "Order selected an expired Quote",
                    ));
                }
                let body = mkt_swp_body(event)?;
                if body.get("accepted_quote_id").and_then(Value::as_str) != Some(quote.id.as_str())
                {
                    return Err(provider_error(
                        "swp_contract_terms_mismatch",
                        "Order body does not select its referenced Quote",
                    ));
                }
                let quote_body = mkt_swp_body(quote)?;
                validate_order_acceptance_deadline(&quote_body, expiration, event.created_at)?;
                validate_order_selection(&quote_body, &body)?;
            }
            MKT_SWP_SWAP_CONTRACT_KIND => {
                let role = author_role(&self.config, event)?;
                if self.signed_records.iter().any(|record| {
                    record.kind == MKT_SWP_SWAP_CONTRACT_KIND && record.pubkey == event.pubkey
                }) {
                    return Err(provider_error(
                        "swp_idempotency_conflict",
                        "each participant may sign exactly one immutable Swap Contract",
                    ));
                }
                require_reference(event, "order", &self.order()?.id)?;
                require_reference(event, "quote", &self.quote()?.id)?;
                let body = mkt_swp_body(event)?;
                if body.get("signer_role").and_then(Value::as_str) != Some(role_name(role)) {
                    return Err(provider_error(
                        "swp_contract_signer_invalid",
                        "Swap Contract signer role does not match its author",
                    ));
                }
                let contract = body.get("contract").ok_or_else(|| {
                    provider_error(
                        "swp_contract_terms_mismatch",
                        "Swap Contract has no contract object",
                    )
                })?;
                if role == ParticipantRole::Requester {
                    let mut candidate = self.signed_records.clone();
                    candidate.push(event.clone());
                    validate_contract_candidate(&self.config, &candidate, contract)?;
                } else {
                    let requester_contract = self
                        .signed_records
                        .iter()
                        .find(|record| {
                            record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                                && record.pubkey == self.config.requester_pubkey
                        })
                        .ok_or_else(|| {
                            provider_error(
                                "swp_contract_missing",
                                "provider contract arrived before the requester contract",
                            )
                        })?;
                    if mkt_swp_body(requester_contract)?.get("contract") != Some(contract) {
                        return Err(provider_error(
                            "swp_contract_digest_mismatch",
                            "participant Swap Contracts contain different terms",
                        ));
                    }
                    let accepted_status = if has_reference(event, "status") {
                        Some(reference(event, "status")?)
                    } else {
                        None
                    };
                    let request = self.factory.swap_contract(
                        ParticipantRole::Provider,
                        event.created_at,
                        tag_value(event, "d")?,
                        SwapContractReferences {
                            order_id: &self.order()?.id,
                            quote_id: &self.quote()?.id,
                            accepted_status_id: accepted_status,
                        },
                        contract.clone(),
                    )?;
                    request.verify_signed(event.clone())?;
                }
            }
            MKT_STATUS_KIND | MKT_CANCEL_KIND | MKT_CLOSE_KIND => {
                author_role(&self.config, event)?;
                require_reference(event, "order", &self.order()?.id)?;
                let mut candidate = self.signed_records.clone();
                candidate.push(event.clone());
                if event.kind == MKT_STATUS_KIND {
                    project_status(&self.config, &candidate)?;
                } else if event.kind == MKT_CANCEL_KIND {
                    validate_cancel_history(&self.config, &candidate)?;
                } else {
                    validate_close_history(
                        &self.config,
                        &candidate,
                        event,
                        self.reservation.as_ref(),
                        self.released,
                        false,
                    )?;
                }
            }
            _ => {
                return Err(provider_error(
                    "swp_contract_terms_mismatch",
                    "provider session received an unsupported record kind",
                ));
            }
        }
        self.validate_idempotency_key(event)
    }

    fn validate_idempotency_key(&self, event: &Event) -> Result<(), SwapClientError> {
        if self.signed_records.iter().any(|record| {
            record.pubkey == event.pubkey
                && record.kind == event.kind
                && tag_value(record, "d").ok() == tag_value(event, "d").ok()
        }) {
            return Err(provider_error(
                "swp_idempotency_conflict",
                "provider session reused a record idempotency key with different bytes",
            ));
        }
        Ok(())
    }
}

fn validate_release_cause(
    records: &[Event],
    reservation: &ReservationConfirmation,
    cause: ReservationReleaseCause,
    observed_at: u64,
    validated_terminal_close: bool,
) -> Result<(), SwapClientError> {
    let valid = match cause {
        ReservationReleaseCause::EffectiveCancel => records.iter().any(|record| {
            record.kind == MKT_CANCEL_KIND && tag_value(record, "action").ok() == Some("effective")
        }),
        ReservationReleaseCause::ReservationExpired => {
            observed_at >= reservation.reservation_expires_at
        }
        ReservationReleaseCause::TerminalClose => {
            validated_terminal_close || records.iter().any(|record| record.kind == MKT_CLOSE_KIND)
        }
    };
    if !valid {
        return Err(provider_error(
            "swp_reservation_release_invalid",
            "provider release cause is not established by signed history or local time",
        ));
    }
    Ok(())
}

fn validate_session_event(config: &SwapClientConfig, event: &Event) -> Result<(), SwapClientError> {
    let raw = serde_json::to_vec(event).map_err(|error| {
        provider_error(
            "swp_contract_terms_mismatch",
            format!("could not serialize signed record: {error}"),
        )
    })?;
    let validated = validate_mkt_private_raw(&raw, &swp_profile_support()).map_err(|error| {
        provider_error(
            "swp_contract_terms_mismatch",
            format!("provider record violates MKT-SWP: {error}"),
        )
    })?;
    if validated.envelope.session_id != config.session_id {
        return Err(provider_error(
            "swp_contract_terms_mismatch",
            "provider record belongs to another session",
        ));
    }
    author_role(config, event)?;
    reject_custody_material(
        &serde_json::from_str::<Value>(&event.content).map_err(|error| {
            provider_error(
                "swp_contract_terms_mismatch",
                format!("provider record content is invalid JSON: {error}"),
            )
        })?,
    )
}

fn validate_provider_collection_bounds(
    record_count: usize,
    effect_count: usize,
) -> Result<(), SwapClientError> {
    if record_count > MAX_PROVIDER_RECORDS {
        return Err(provider_error(
            "swp_provider_history_exceeded",
            "provider signed-record history exceeds its bound",
        ));
    }
    if effect_count > MAX_PROVIDER_EFFECTS {
        return Err(provider_error(
            "swp_provider_effects_exceeded",
            "provider effect history exceeds its bound",
        ));
    }
    Ok(())
}

fn reserve_effect_request(
    config: &SwapClientConfig,
    reservation: &ReservationRequest,
) -> Result<ProviderEffectRequest, SwapClientError> {
    effect_request(config, reservation, ProviderEffectKind::Reserve, None)
}

fn release_effect_request(
    config: &SwapClientConfig,
    reservation: &ReservationConfirmation,
    cause: ReservationReleaseCause,
) -> Result<ProviderEffectRequest, SwapClientError> {
    let reservation = ReservationRequest {
        reservation_id: reservation.reservation_id.clone(),
        capacity_bucket_id: reservation.capacity_bucket_id.clone(),
        reserved_asset_id: reservation.reserved_asset_id.clone(),
        reserved_amount: reservation.reserved_amount.clone(),
        reservation_expires_at: reservation.reservation_expires_at,
    };
    effect_request(
        config,
        &reservation,
        ProviderEffectKind::Release,
        Some(cause),
    )
}

fn effect_request(
    config: &SwapClientConfig,
    reservation: &ReservationRequest,
    operation: ProviderEffectKind,
    release_cause: Option<ReservationReleaseCause>,
) -> Result<ProviderEffectRequest, SwapClientError> {
    let operation_name = match operation {
        ProviderEffectKind::Reserve => "reserve",
        ProviderEffectKind::Release => "release",
    };
    let cause_name = release_cause.map_or("none", |cause| match cause {
        ReservationReleaseCause::EffectiveCancel => "effective_cancel",
        ReservationReleaseCause::ReservationExpired => "reservation_expired",
        ReservationReleaseCause::TerminalClose => "terminal_close",
    });
    let effect_id = digest_bytes(
        format!(
            "mkt-swp-provider-v1\0{}\0{}\0{}\0{}",
            config.session_id, operation_name, reservation.reservation_id, cause_name
        )
        .as_bytes(),
    );
    let mut request = ProviderEffectRequest {
        effect_id,
        operation,
        session_id: config.session_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        capacity_bucket_id: reservation.capacity_bucket_id.clone(),
        reserved_asset_id: reservation.reserved_asset_id.clone(),
        reserved_amount: reservation.reserved_amount.clone(),
        reservation_expires_at: reservation.reservation_expires_at,
        release_cause,
        request_sha256: String::new(),
    };
    request.request_sha256 = digest_value(&serde_json::to_value(&request).map_err(|error| {
        provider_error(
            "swp_reservation_confirmation_invalid",
            format!("could not encode provider effect request: {error}"),
        )
    })?)?;
    Ok(request)
}

fn validate_reservation_request(
    request: &ReservationRequest,
    quote_created_at: u64,
) -> Result<(), SwapClientError> {
    require_lower_hex_32(&request.reservation_id, "reservation ID")?;
    validate_identifier(&request.capacity_bucket_id, "capacity bucket ID")?;
    validate_asset_id(&request.reserved_asset_id)?;
    let amount = canonical_positive_decimal(&request.reserved_amount, "reserved amount")?;
    if amount == 0 || request.reservation_expires_at < quote_created_at {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "reservation must cover a positive amount when the Quote is created",
        ));
    }
    Ok(())
}

fn validate_reservation_confirmation(
    request: &ReservationRequest,
    confirmation: &ReservationConfirmation,
) -> Result<(), SwapClientError> {
    if confirmation.reservation_id != request.reservation_id
        || confirmation.capacity_bucket_id != request.capacity_bucket_id
        || confirmation.reserved_asset_id != request.reserved_asset_id
        || confirmation.reserved_amount != request.reserved_amount
        || confirmation.reservation_expires_at != request.reservation_expires_at
    {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "reserve callback changed the requested reservation identity or terms",
        ));
    }
    let reserved = canonical_positive_decimal(&confirmation.reserved_amount, "reserved amount")?;
    let committed =
        canonical_positive_decimal(&confirmation.committed_capacity, "committed capacity")?;
    if committed < reserved {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "confirmed capacity is smaller than the reservation",
        ));
    }
    canonical_positive_decimal(&confirmation.allocation_sequence, "allocation sequence")?;
    if !matches!(
        confirmation.proof_class.as_str(),
        "handler_accounted"
            | "utxo_control"
            | "lightning_liquidity"
            | "funded_htlc"
            | "covenant_reserve"
            | "third_party_guarantee"
    ) {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "reserve callback returned a proof class that cannot support hard reservation",
        ));
    }
    validate_reference(&confirmation.proof_ref, "reservation proof reference")?;
    require_lower_hex_32(
        &confirmation.capacity_commitment_sha256,
        "capacity commitment",
    )
    .map_err(|error| provider_error("swp_reservation_confirmation_invalid", error.detail))
}

fn insert_reservation_terms(
    mkt_swp: &mut Value,
    confirmation: &ReservationConfirmation,
) -> Result<(), SwapClientError> {
    let object = mkt_swp.as_object_mut().ok_or_else(|| {
        provider_error(
            "swp_contract_terms_mismatch",
            "Quote profile body must be an object",
        )
    })?;
    if object.contains_key("reservation_terms") {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "caller cannot supply hard reservation terms before reserve confirmation",
        ));
    }
    object.insert(
        "reservation_terms".into(),
        json!({
            "reservation_id": confirmation.reservation_id,
            "capacity_bucket_id": confirmation.capacity_bucket_id,
            "reserved_asset_id": confirmation.reserved_asset_id,
            "reserved_amount": confirmation.reserved_amount,
            "handler_committed_capacity": confirmation.committed_capacity,
            "reservation_expires_at": confirmation.reservation_expires_at,
            "allocation_sequence": confirmation.allocation_sequence,
            "proof_class": confirmation.proof_class,
            "proof_ref": confirmation.proof_ref,
            "capacity_commitment_sha256": confirmation.capacity_commitment_sha256
        }),
    );
    Ok(())
}

fn validate_quote_confirmation(
    quote: &Event,
    confirmation: &ReservationConfirmation,
) -> Result<(), SwapClientError> {
    let body = mkt_swp_body(quote)?;
    let expected = body.get("reservation_terms").ok_or_else(|| {
        provider_error(
            "swp_reservation_unconfirmed",
            "hard Quote omits confirmed reservation terms",
        )
    })?;
    let mut quote_body = json!({});
    insert_reservation_terms(&mut quote_body, confirmation)?;
    if quote_body.get("reservation_terms") != Some(expected) {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "hard Quote reservation terms differ from the reserve callback confirmation",
        ));
    }
    Ok(())
}

fn validate_effect_receipt(
    request: &ProviderEffectRequest,
    receipt: &ProviderEffectReceipt,
) -> Result<(), SwapClientError> {
    if receipt.effect_id != request.effect_id || receipt.request_sha256 != request.request_sha256 {
        return Err(provider_error(
            "swp_idempotency_conflict",
            "provider effect receipt does not bind its request",
        ));
    }
    validate_reference(&receipt.external_reference, "provider effect reference")?;
    require_lower_hex_32(&receipt.result_sha256, "provider effect result digest")
}

fn validate_effect_records(
    config: &SwapClientConfig,
    records: &BTreeMap<String, ProviderEffectRecord>,
) -> Result<bool, SwapClientError> {
    let mut reserve_count = 0;
    let mut release_causes = BTreeSet::new();
    let mut release_count = 0;
    let mut reserve_request = None;
    let mut release_request = None;
    for (effect_id, record) in records {
        if effect_id != &record.request.effect_id || record.request.session_id != config.session_id
        {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider effect is keyed or session-bound incorrectly",
            ));
        }
        let expected = effect_request(
            config,
            &ReservationRequest {
                reservation_id: record.request.reservation_id.clone(),
                capacity_bucket_id: record.request.capacity_bucket_id.clone(),
                reserved_asset_id: record.request.reserved_asset_id.clone(),
                reserved_amount: record.request.reserved_amount.clone(),
                reservation_expires_at: record.request.reservation_expires_at,
            },
            record.request.operation,
            record.request.release_cause,
        )?;
        ensure_effect_replay(record, &expected)?;
        validate_effect_receipt(&record.request, &record.receipt)?;
        match record.request.operation {
            ProviderEffectKind::Reserve => {
                reserve_count += 1;
                if record.request.release_cause.is_some() {
                    return Err(provider_error(
                        "swp_provider_snapshot_invalid",
                        "reserve effect cannot carry a release cause",
                    ));
                }
                reserve_request = Some(&record.request);
                let confirmation = record.confirmation.as_ref().ok_or_else(|| {
                    provider_error(
                        "swp_provider_snapshot_invalid",
                        "reserve effect has no confirmation",
                    )
                })?;
                validate_reservation_confirmation(
                    &ReservationRequest {
                        reservation_id: record.request.reservation_id.clone(),
                        capacity_bucket_id: record.request.capacity_bucket_id.clone(),
                        reserved_asset_id: record.request.reserved_asset_id.clone(),
                        reserved_amount: record.request.reserved_amount.clone(),
                        reservation_expires_at: record.request.reservation_expires_at,
                    },
                    confirmation,
                )?;
            }
            ProviderEffectKind::Release => {
                release_count += 1;
                if record.request.release_cause.is_none()
                    || record.confirmation.is_some()
                    || !release_causes.insert(record.request.release_cause)
                {
                    return Err(provider_error(
                        "swp_provider_snapshot_invalid",
                        "release effect confirmation or cause is invalid",
                    ));
                }
                release_request = Some(&record.request);
            }
        }
    }
    if reserve_count > 1 {
        return Err(provider_error(
            "swp_provider_snapshot_invalid",
            "provider session contains multiple reserve effects",
        ));
    }
    if release_count > 1 {
        return Err(provider_error(
            "swp_provider_snapshot_invalid",
            "provider session contains multiple release effects",
        ));
    }
    if let Some(release) = release_request {
        let reserve = reserve_request.ok_or_else(|| {
            provider_error(
                "swp_provider_snapshot_invalid",
                "release effect has no matching reserve effect",
            )
        })?;
        if release.reservation_id != reserve.reservation_id
            || release.capacity_bucket_id != reserve.capacity_bucket_id
            || release.reserved_asset_id != reserve.reserved_asset_id
            || release.reserved_amount != reserve.reserved_amount
            || release.reservation_expires_at != reserve.reservation_expires_at
        {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "release effect does not match the reserved allocation",
            ));
        }
    }
    Ok(release_request.is_some())
}

fn validate_hard_quote_request(
    config: &SwapClientConfig,
    request: Option<&MktSigningRequest>,
    reservation: Option<&ReservationConfirmation>,
    records: &[Event],
) -> Result<(), SwapClientError> {
    let Some(request) = request else {
        if records.iter().any(|record| {
            record.kind == MKT_QUOTE_KIND && tag_value(record, "reservation").ok() == Some("hard")
        }) {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "persisted hard Quote has no reserve-gated signing request",
            ));
        }
        return Ok(());
    };
    if request.pubkey != config.provider_pubkey
        || request.kind != MKT_QUOTE_KIND
        || request
            .tags
            .iter()
            .filter(|tag| tag.name() == Some("session"))
            .any(|tag| tag.value() != Some(config.session_id.as_str()))
        || request
            .tags
            .iter()
            .filter(|tag| tag.name() == Some("quote"))
            .map(|tag| tag.value())
            .collect::<Vec<_>>()
            != [Some("firm")]
        || request
            .tags
            .iter()
            .filter(|tag| tag.name() == Some("reservation"))
            .map(|tag| tag.value())
            .collect::<Vec<_>>()
            != [Some("hard")]
    {
        return Err(provider_error(
            "swp_provider_snapshot_invalid",
            "persisted hard Quote request has the wrong signer, kind, session, or policy",
        ));
    }
    let unsigned = Event {
        id: String::new(),
        pubkey: request.pubkey.clone(),
        created_at: request.created_at,
        kind: request.kind,
        tags: request.tags.clone(),
        content: request.content.clone(),
        sig: String::new(),
    };
    if unsigned.computed_id().map_err(|error| {
        provider_error(
            "swp_provider_snapshot_invalid",
            format!("could not recompute persisted hard Quote request: {error}"),
        )
    })? != request.expected_event_id
    {
        return Err(provider_error(
            "swp_provider_snapshot_invalid",
            "persisted hard Quote request ID does not match its bytes",
        ));
    }
    let rfq = exactly_one(records, MKT_RFQ_KIND, "RFQ")?;
    require_reference(&unsigned, "rfq", &rfq.id)?;
    let content = mkt_swp_body(&unsigned)?;
    let envelope: Value = serde_json::from_str(&unsigned.content).map_err(|error| {
        provider_error(
            "swp_provider_snapshot_invalid",
            format!("persisted hard Quote content is invalid: {error}"),
        )
    })?;
    if envelope.get("session_id").and_then(Value::as_str) != Some(config.session_id.as_str())
        || content.is_empty()
    {
        return Err(provider_error(
            "swp_provider_snapshot_invalid",
            "persisted hard Quote request is not bound to its session body",
        ));
    }
    let reservation = reservation.ok_or_else(|| {
        provider_error(
            "swp_provider_snapshot_invalid",
            "persisted hard Quote request has no reservation confirmation",
        )
    })?;
    validate_quote_confirmation(&unsigned, reservation)?;
    let quotes = records
        .iter()
        .filter(|record| record.kind == MKT_QUOTE_KIND)
        .collect::<Vec<_>>();
    match quotes.as_slice() {
        [] => {}
        [quote] => {
            request.verify_signed((*quote).clone())?;
        }
        _ => {
            return Err(provider_error(
                "swp_provider_snapshot_invalid",
                "provider snapshot contains multiple Quote records",
            ));
        }
    }
    Ok(())
}

fn ensure_effect_replay(
    record: &ProviderEffectRecord,
    request: &ProviderEffectRequest,
) -> Result<(), SwapClientError> {
    if record.request != *request || record.receipt.request_sha256 != request.request_sha256 {
        return Err(provider_error(
            "swp_idempotency_conflict",
            "provider effect ID replay changed request bytes",
        ));
    }
    Ok(())
}

fn author_role(
    config: &SwapClientConfig,
    event: &Event,
) -> Result<ParticipantRole, SwapClientError> {
    if event.pubkey == config.requester_pubkey {
        Ok(ParticipantRole::Requester)
    } else if event.pubkey == config.provider_pubkey {
        Ok(ParticipantRole::Provider)
    } else {
        Err(provider_error(
            "swp_contract_signer_invalid",
            "provider record author is not a session participant",
        ))
    }
}

fn require_author(
    config: &SwapClientConfig,
    event: &Event,
    expected: ParticipantRole,
) -> Result<(), SwapClientError> {
    if author_role(config, event)? == expected {
        Ok(())
    } else {
        Err(provider_error(
            "swp_contract_signer_invalid",
            "provider flow record has the wrong participant author",
        ))
    }
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

fn hard_quote_request(
    config: &SwapClientConfig,
    created_at: u64,
    distinct: &str,
    rfq_id: &str,
    expiration: u64,
    mkt_swp: Value,
) -> Result<MktSigningRequest, SwapClientError> {
    require_lower_hex_32(distinct, "record idempotency key")?;
    require_lower_hex_32(rfq_id, "RFQ event ID")?;
    reject_custody_material(&mkt_swp)?;
    let tags = vec![
        pair("d", distinct),
        pair("session", &config.session_id),
        Tag::new(vec![
            "profile".into(),
            MKT_SWP_PROFILE_ID.into(),
            MKT_SWP_PROFILE_VERSION.to_string(),
        ]),
        Tag::new(vec![
            "p".into(),
            config.requester_pubkey.clone(),
            String::new(),
            "requester".into(),
        ]),
        pair("alt", "MKT-SWP Quote"),
        Tag::new(vec!["e".into(), rfq_id.into(), String::new(), "rfq".into()]),
        pair("expiration", &expiration.to_string()),
        pair("quote", "firm"),
        pair("reservation", "hard"),
    ];
    let content = serde_json::to_string(&json!({
        "schema": MKT_ENVELOPE_SCHEMA,
        "profile": MKT_SWP_PROFILE_ID,
        "profile_version": MKT_SWP_PROFILE_VERSION,
        "session_id": config.session_id,
        "mkt_swp": mkt_swp,
    }))
    .map_err(|error| {
        provider_error(
            "swp_contract_terms_mismatch",
            format!("could not serialize hard Quote signing content: {error}"),
        )
    })?;
    let unsigned = Event {
        id: String::new(),
        pubkey: config.provider_pubkey.clone(),
        created_at,
        kind: MKT_QUOTE_KIND,
        tags: tags.clone(),
        content: content.clone(),
        sig: String::new(),
    };
    let expected_event_id = unsigned.computed_id().map_err(|error| {
        provider_error(
            "swp_contract_terms_mismatch",
            format!("could not compute hard Quote signing request ID: {error}"),
        )
    })?;
    Ok(MktSigningRequest {
        pubkey: config.provider_pubkey.clone(),
        created_at,
        kind: MKT_QUOTE_KIND,
        tags,
        content,
        expected_event_id,
    })
}

fn role_name(role: ParticipantRole) -> &'static str {
    match role {
        ParticipantRole::Requester => "requester",
        ParticipantRole::Provider => "provider",
    }
}

fn exactly_one<'a>(
    records: &'a [Event],
    kind: u16,
    label: &str,
) -> Result<&'a Event, SwapClientError> {
    let matches = records
        .iter()
        .filter(|event| event.kind == kind)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [event] => Ok(*event),
        _ => Err(provider_error(
            "swp_contract_terms_mismatch",
            format!("provider session requires exactly one {label}"),
        )),
    }
}

fn require_reference(event: &Event, marker: &str, expected: &str) -> Result<(), SwapClientError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [tag] if tag.value() == Some(expected) => Ok(()),
        _ => Err(provider_error(
            "swp_contract_terms_mismatch",
            format!("provider record lacks its exact {marker} reference"),
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
            provider_error(
                "swp_contract_terms_mismatch",
                format!("provider record {name} tag is empty"),
            )
        }),
        _ => Err(provider_error(
            "swp_contract_terms_mismatch",
            format!("provider record requires exactly one {name} tag"),
        )),
    }
}

fn mkt_swp_body(event: &Event) -> Result<Map<String, Value>, SwapClientError> {
    let content: Value = serde_json::from_str(&event.content).map_err(|error| {
        provider_error(
            "swp_contract_terms_mismatch",
            format!("provider record content is invalid JSON: {error}"),
        )
    })?;
    reject_custody_material(&content)?;
    content
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            provider_error(
                "swp_contract_terms_mismatch",
                "provider record has no MKT-SWP body",
            )
        })
}

fn validate_identifier(value: &str, label: &str) -> Result<(), SwapClientError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            format!("{label} is not a bounded profile identifier"),
        ));
    }
    Ok(())
}

fn validate_asset_id(value: &str) -> Result<(), SwapClientError> {
    if !value.starts_with("swp:1:") || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            "reserved asset ID is invalid",
        ));
    }
    Ok(())
}

fn validate_reference(value: &str, label: &str) -> Result<(), SwapClientError> {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || [
            "seed",
            "walletseed",
            "mnemonic",
            "xprv",
            "privatekey",
            "claimprivatekey",
            "claimkey",
            "claimsecret",
            "refundprivatekey",
            "refundkey",
            "refundsecret",
            "preimage",
            "invoicepreimage",
            "paymentpreimage",
            "macaroon",
            "lndmacaroon",
            "adminmacaroon",
            "invoicemacaroon",
            "nwc",
            "nwcstring",
            "nwcconnectionstring",
            "nwcuri",
            "bearertoken",
            "walletcredential",
            "walletrpcpayload",
            "musigsecretnonce",
            "privkey",
            "secretkey",
            "secretnonce",
            "signingnonce",
        ]
        .iter()
        .any(|alias| normalized.contains(alias))
    {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            format!("{label} is empty, unbounded, or credential-shaped"),
        ));
    }
    Ok(())
}

fn validate_cancel_history(
    config: &SwapClientConfig,
    records: &[Event],
) -> Result<(), SwapClientError> {
    let cancels = records
        .iter()
        .filter(|record| record.kind == MKT_CANCEL_KIND)
        .collect::<Vec<_>>();
    let effective_count = cancels
        .iter()
        .filter(|cancel| tag_value(cancel, "action").ok() == Some("effective"))
        .count();
    if effective_count > 1 {
        return Err(provider_error(
            "swp_cancel_ineffective",
            "provider session contains multiple effective cancellation records",
        ));
    }
    for cancel in cancels {
        match tag_value(cancel, "action")? {
            "request" => {
                if has_reference(cancel, "cancel-request") || has_reference(cancel, "cancel-accept")
                {
                    return Err(provider_error(
                        "swp_cancel_ineffective",
                        "cancellation request has consent references",
                    ));
                }
            }
            "accepted" | "rejected" => {
                let request_id = reference(cancel, "cancel-request")?;
                let request = records
                    .iter()
                    .find(|record| record.kind == MKT_CANCEL_KIND && record.id == request_id)
                    .ok_or_else(|| {
                        provider_error(
                            "swp_cancel_ineffective",
                            "cancellation response references no request",
                        )
                    })?;
                if tag_value(request, "action")? != "request"
                    || author_role(config, request)? == author_role(config, cancel)?
                    || has_reference(cancel, "cancel-accept")
                {
                    return Err(provider_error(
                        "swp_cancel_ineffective",
                        "cancellation response is not exact counterparty consent",
                    ));
                }
            }
            "effective" => {
                let request_id = reference(cancel, "cancel-request")?;
                let accepted_id = reference(cancel, "cancel-accept")?;
                let request = records
                    .iter()
                    .find(|record| record.kind == MKT_CANCEL_KIND && record.id == request_id)
                    .ok_or_else(|| {
                        provider_error(
                            "swp_cancel_ineffective",
                            "effective cancellation references no request",
                        )
                    })?;
                let accepted = records
                    .iter()
                    .find(|record| record.kind == MKT_CANCEL_KIND && record.id == accepted_id)
                    .ok_or_else(|| {
                        provider_error(
                            "swp_cancel_ineffective",
                            "effective cancellation references no accepted consent",
                        )
                    })?;
                if tag_value(request, "action")? != "request"
                    || tag_value(accepted, "action")? != "accepted"
                    || reference(accepted, "cancel-request")? != request.id
                    || author_role(config, request)? == author_role(config, accepted)?
                    || author_role(config, cancel)? != author_role(config, request)?
                        && author_role(config, cancel)? != author_role(config, accepted)?
                {
                    return Err(provider_error(
                        "swp_cancel_ineffective",
                        "effective cancellation lacks exact bilateral consent",
                    ));
                }
            }
            _ => {
                return Err(provider_error(
                    "swp_cancel_ineffective",
                    "provider session received an unknown cancellation action",
                ));
            }
        }
    }
    Ok(())
}

fn validate_close_history(
    config: &SwapClientConfig,
    records: &[Event],
    close: &Event,
    reservation: Option<&ReservationConfirmation>,
    released: bool,
    allow_pending_release: bool,
) -> Result<(), SwapClientError> {
    if records
        .iter()
        .filter(|record| record.kind == MKT_CLOSE_KIND && record.pubkey == close.pubkey)
        .count()
        > 1
    {
        return Err(provider_error(
            "swp_unresolved_loss",
            "provider session contains multiple Close records",
        ));
    }
    let outcome = tag_value(close, "outcome")?;
    if close.pubkey == config.provider_pubkey
        && reservation.is_some()
        && !released
        && !allow_pending_release
    {
        return Err(provider_error(
            "swp_reservation_release_invalid",
            "provider must durably release a hard reservation before Close",
        ));
    }
    let profile = mkt_swp_body(close)?;
    let loss = profile
        .get("loss_accounting")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            provider_error(
                "swp_unresolved_loss",
                "provider Close requires loss_accounting",
            )
        })?;
    let asset_pair = quote_asset_pair(records)?;
    if loss.get("input_asset_id") != asset_pair.first()
        || loss.get("output_asset_id") != asset_pair.get(1)
    {
        return Err(provider_error(
            "swp_unresolved_loss",
            "provider Close loss accounting differs from the Quote asset pair",
        ));
    }
    if matches!(outcome, "cancelled" | "rejected" | "expired") {
        let released_amount = if let Some(reservation) = reservation {
            canonical_positive_decimal(&reservation.reserved_amount, "reserved amount")?
        } else {
            quote_reservation_amount(records)?
        };
        let released_amount = u64::try_from(released_amount).map_err(|_| {
            provider_error(
                "swp_unresolved_loss",
                "released reservation exceeds Close accounting bounds",
            )
        })?;
        validate_no_spend_loss_accounting(loss, released_amount)?;
    }
    let has_effective_cancel = records.iter().any(|record| {
        record.kind == MKT_CANCEL_KIND && tag_value(record, "action").ok() == Some("effective")
    });
    if outcome == "cancelled" && !has_effective_cancel {
        return Err(provider_error(
            "swp_cancel_ineffective",
            "cancelled Close has no effective bilateral cancellation",
        ));
    }
    if outcome == "cancelled" {
        let effective = records
            .iter()
            .find(|record| {
                record.kind == MKT_CANCEL_KIND
                    && tag_value(record, "action").ok() == Some("effective")
            })
            .ok_or_else(|| {
                provider_error(
                    "swp_cancel_ineffective",
                    "cancelled Close has no effective cancellation",
                )
            })?;
        if profile.get("cancel_id").and_then(Value::as_str) != Some(effective.id.as_str()) {
            return Err(provider_error(
                "swp_cancel_ineffective",
                "cancelled Close does not bind the effective cancellation",
            ));
        }
    }
    if matches!(outcome, "completed" | "refunded") {
        let projection = project_status(config, records)?;
        require_signer_status_contiguous(&projection, &close.pubkey)?;
        let status_id = profile
            .get("status_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                provider_error(
                    "swp_unresolved_loss",
                    "terminal Close does not bind a signer-local Status",
                )
            })?;
        let status = records
            .iter()
            .find(|record| {
                record.kind == MKT_STATUS_KIND
                    && record.id == status_id
                    && record.pubkey == close.pubkey
            })
            .ok_or_else(|| {
                provider_error(
                    "swp_unresolved_loss",
                    "terminal Close Status is absent or belongs to another signer",
                )
            })?;
        if status_swp_state(status)? != outcome
            || projection.last_valid_status.get(&close.pubkey) != Some(&status.id)
            || projection.invalid_claims.contains_key(&status.id)
        {
            return Err(provider_error(
                "swp_unresolved_loss",
                "terminal Close overclaims its signer-local Status ancestry",
            ));
        }
        let evidence = loss
            .get("evidence_refs")
            .and_then(Value::as_array)
            .filter(|evidence| !evidence.is_empty())
            .ok_or_else(|| {
                provider_error(
                    "swp_settlement_overclaim",
                    "completed or refunded Close requires verified rail evidence",
                )
            })?;
        for reference in evidence {
            validate_mkt_swp_evidence_reference(reference).map_err(|error| {
                provider_error(
                    "swp_evidence_invalid",
                    format!("Close evidence reference is invalid: {error}"),
                )
            })?;
            let rung = reference.get("rung").and_then(Value::as_str);
            if !matches!(rung, Some("verified" | "paid" | "settled")) {
                return Err(provider_error(
                    "swp_settlement_overclaim",
                    "terminal Close evidence is below the verified rung",
                ));
            }
        }
    }
    Ok(())
}

fn quote_asset_pair(records: &[Event]) -> Result<Vec<Value>, SwapClientError> {
    let quote = exactly_one(records, MKT_QUOTE_KIND, "Quote")?;
    mkt_swp_body(quote)?
        .get("terms")
        .and_then(Value::as_object)
        .and_then(|terms| terms.get("asset_pair"))
        .and_then(Value::as_array)
        .filter(|assets| assets.len() == 2)
        .cloned()
        .ok_or_else(|| {
            provider_error(
                "swp_unresolved_loss",
                "provider Close requires the Quote's ordered asset pair",
            )
        })
}

fn quote_reservation_amount(records: &[Event]) -> Result<u128, SwapClientError> {
    let quote = exactly_one(records, MKT_QUOTE_KIND, "Quote")?;
    match tag_value(quote, "reservation")? {
        "none" => Ok(0),
        "soft" | "hard" => canonical_positive_decimal(
            mkt_swp_body(quote)?
                .get("reservation_terms")
                .and_then(Value::as_object)
                .and_then(|terms| terms.get("reserved_amount"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    provider_error(
                        "swp_unresolved_loss",
                        "reserving Quote has no reserved amount",
                    )
                })?,
            "reserved amount",
        ),
        _ => Err(provider_error(
            "swp_unresolved_loss",
            "Quote reservation class is invalid",
        )),
    }
}

fn status_swp_state(status: &Event) -> Result<String, SwapClientError> {
    let content: Value = serde_json::from_str(&status.content).map_err(|error| {
        provider_error(
            "swp_status_transition_invalid",
            format!("Status content is invalid JSON: {error}"),
        )
    })?;
    content
        .get("mkt_swp")
        .and_then(Value::as_object)
        .and_then(|profile| profile.get("swp_state"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            provider_error(
                "swp_status_transition_invalid",
                "Status has no MKT-SWP state",
            )
        })
}

fn reference<'a>(event: &'a Event, marker: &str) -> Result<&'a str, SwapClientError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [tag] => tag.value().ok_or_else(|| {
            provider_error(
                "swp_cancel_ineffective",
                format!("{marker} cancellation reference is empty"),
            )
        }),
        _ => Err(provider_error(
            "swp_cancel_ineffective",
            format!("cancellation requires exactly one {marker} reference"),
        )),
    }
}

fn has_reference(event: &Event, marker: &str) -> bool {
    event.tags.iter().any(|tag| {
        tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
    })
}

fn canonical_positive_decimal(value: &str, label: &str) -> Result<u128, SwapClientError> {
    if value.is_empty()
        || value.len() > 39
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(provider_error(
            "swp_reservation_confirmation_invalid",
            format!("{label} is not a canonical decimal"),
        ));
    }
    value.parse::<u128>().map_err(|_| {
        provider_error(
            "swp_reservation_confirmation_invalid",
            format!("{label} exceeds its numeric bound"),
        )
    })
}

fn digest_value(value: &Value) -> Result<String, SwapClientError> {
    Ok(digest_bytes(&canonical_json(value)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn swp_profile_support() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }]
}

fn pair(name: &str, value: &str) -> Tag {
    Tag::new(vec![name.into(), value.into()])
}

pub mod fixture_replay {
    use std::collections::BTreeSet;

    use serde::Deserialize;
    use serde_json::{Map, Value, json};

    use immortal_client::mkt_swp_client::{
        Cancellation, CloseOutcome, MktSigningRequest, ParticipantRole, StatusState,
        SwapClientConfig, SwapContractReferences, SwapRecordFactory,
    };
    use immortal_core::{domain::Event, market::MarketSigner};

    use super::{
        MktPublicSigningRequest, ProviderDiscoveryFactory, ProviderEffectReceipt, ProviderSession,
        ReservationConfirmation, ReservationReleaseCause, ReservationRequest, SwapClientError,
        digest_bytes, mkt_swp_body, provider_error, tag_value, validate_mkt_swp_evidence_reference,
        validate_provider_collection_bounds,
    };

    const PROVIDER_MANIFEST: &str =
        include_str!("../../../tests/fixtures/nipmkt/swp-provider-engine-v1.json");
    const FULL_SESSION_FIXTURES: &str =
        include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema: String,
        source: Source,
        discovery: Vec<Discovery>,
        flows: Vec<Flow>,
        reservation_effects: Vec<ReservationEffect>,
        evidence: Vec<Evidence>,
        negative: Vec<Negative>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Source {
        lane: String,
        commit: String,
        specification: String,
        issue: String,
        profile: String,
        version: u64,
        scope: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Discovery {
        name: String,
        record: String,
        rotation: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Flow {
        name: String,
        swap_type: String,
        quote_class: String,
        reservation: String,
        records: Vec<String>,
        terminal: String,
        external_spend_effects: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ReservationEffect {
        name: String,
        operation: String,
        cause: Option<String>,
        replay: String,
        signing_request: Option<bool>,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Evidence {
        name: String,
        publication: String,
        valid: bool,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Negative {
        name: String,
        mutation: String,
        error: Option<String>,
        retained: Option<bool>,
        projection: Option<String>,
    }

    pub fn replay_embedded_manifest() -> Result<usize, SwapClientError> {
        replay_manifest(PROVIDER_MANIFEST)
    }

    pub fn replay_manifest(input: &str) -> Result<usize, SwapClientError> {
        let manifest: Manifest = serde_json::from_str(input).map_err(|error| {
            provider_error(
                "swp_provider_fixture_invalid",
                format!("provider fixture manifest is invalid: {error}"),
            )
        })?;
        if manifest.schema != "openagents.mkt-swp.provider-engine-fixtures.v1"
            || manifest.source.lane != "openagents"
            || manifest.source.commit.len() != 40
            || manifest.source.specification != "nips/openagents/MKT-SWP.md"
            || manifest.source.issue != "OpenAgentsInc/immortal#14"
            || manifest.source.profile != "mkt-swp"
            || manifest.source.version != 1
            || manifest.source.scope.is_empty()
        {
            return Err(invalid("provider fixture source metadata is invalid"));
        }
        let count = manifest.discovery.len()
            + manifest.flows.len()
            + manifest.reservation_effects.len()
            + manifest.evidence.len()
            + manifest.negative.len();
        if count != 30 {
            return Err(invalid("provider fixture case count changed"));
        }
        let mut names = BTreeSet::new();
        for case in &manifest.discovery {
            require_unique_name(&mut names, &case.name)?;
            replay_discovery(case)?;
        }
        for case in &manifest.flows {
            require_unique_name(&mut names, &case.name)?;
            replay_flow(case)?;
        }
        for case in &manifest.reservation_effects {
            require_unique_name(&mut names, &case.name)?;
            replay_reservation_effect(case)?;
        }
        for case in &manifest.evidence {
            require_unique_name(&mut names, &case.name)?;
            replay_evidence(case)?;
        }
        for case in &manifest.negative {
            require_unique_name(&mut names, &case.name)?;
            replay_negative(case)?;
        }
        if names != expected_names() {
            return Err(invalid("provider fixture nameset changed"));
        }
        Ok(count)
    }

    fn replay_discovery(case: &Discovery) -> Result<(), SwapClientError> {
        let (expected_record, expected_rotation) = match case.name.as_str() {
            "swp-v1-provider-profile-publish" => ("profile", 0),
            "swp-v1-provider-profile-rotate" => ("profile", 1),
            "swp-v1-provider-offering-publish" => ("offering", 0),
            "swp-v1-provider-offering-rotate" => ("offering", 1),
            _ => return Err(invalid("unknown provider discovery fixture")),
        };
        if case.record != expected_record || case.rotation != expected_rotation {
            return Err(invalid("provider discovery fixture expectation drifted"));
        }
        let setup = setup(0xa1)?;
        let factory = ProviderDiscoveryFactory::new(setup.provider.pubkey())?;
        let request = match case.record.as_str() {
            "profile" => factory.profile(
                100 + case.rotation,
                "fixture-provider",
                if case.rotation == 0 {
                    "active"
                } else {
                    "paused"
                },
                json!({"name":"Fixture provider"}),
            )?,
            "offering" => factory.offering(
                100 + case.rotation,
                "fixture-provider",
                "fixture-swaps",
                if case.rotation == 0 {
                    "active"
                } else {
                    "paused"
                },
                offering_content()?,
            )?,
            _ => return Err(invalid("unknown discovery record class")),
        };
        sign_public(request, &setup.provider).map(|_| ())
    }

    fn replay_flow(case: &Flow) -> Result<(), SwapClientError> {
        let expected_swap_type = match case.name.as_str() {
            "swp-v1-provider-submarine-no-spend" => "submarine",
            "swp-v1-provider-reverse-no-spend" => "reverse",
            "swp-v1-provider-chain-no-spend" => "chain",
            _ => return Err(invalid("unknown provider flow fixture")),
        };
        let expected_records = [
            "rfq",
            "quote",
            "order",
            "swap_contract",
            "status",
            "cancel",
            "close",
        ];
        if case.swap_type != expected_swap_type
            || case.quote_class != "firm"
            || case.reservation != "soft"
            || case.records != expected_records
            || case.terminal != "cancelled"
            || case.external_spend_effects != 0
        {
            return Err(invalid("provider flow fixture expectation drifted"));
        }
        execute_no_spend_flow(expected_swap_type)
    }

    fn replay_reservation_effect(case: &ReservationEffect) -> Result<(), SwapClientError> {
        let actual = match case.name.as_str() {
            "swp-v1-provider-hard-reserve-confirmed" => {
                require_reservation_case(case, "reserve", None, "same_result", Some(true), None)?;
                execute_hard_reserve(ReserveMutation::Confirmed)
            }
            "swp-v1-provider-hard-reserve-rejected" => {
                require_reservation_case(
                    case,
                    "reserve",
                    None,
                    "same_error",
                    Some(false),
                    Some("swp_reservation_unconfirmed"),
                )?;
                execute_hard_reserve(ReserveMutation::Rejected)
            }
            "swp-v1-provider-hard-reserve-mismatched" => {
                require_reservation_case(
                    case,
                    "reserve",
                    None,
                    "same_error",
                    Some(false),
                    Some("swp_reservation_confirmation_invalid"),
                )?;
                execute_hard_reserve(ReserveMutation::Mismatched)
            }
            "swp-v1-provider-release-on-cancel" => {
                require_reservation_case(
                    case,
                    "release",
                    Some("effective_cancel"),
                    "same_result",
                    None,
                    None,
                )?;
                execute_release(ReservationReleaseCause::EffectiveCancel)
            }
            "swp-v1-provider-release-on-expiry" => {
                require_reservation_case(
                    case,
                    "release",
                    Some("reservation_expired"),
                    "same_result",
                    None,
                    None,
                )?;
                execute_release(ReservationReleaseCause::ReservationExpired)
            }
            "swp-v1-provider-release-on-close" => {
                require_reservation_case(
                    case,
                    "release",
                    Some("terminal_close"),
                    "same_result",
                    None,
                    None,
                )?;
                execute_release(ReservationReleaseCause::TerminalClose)
            }
            _ => return Err(invalid("unknown provider reservation fixture")),
        };
        expect_error(case.error.as_deref(), actual)
    }

    fn replay_evidence(case: &Evidence) -> Result<(), SwapClientError> {
        let (publication, valid, expected_error, value) = match case.name.as_str() {
            "swp-v1-provider-status-private-evidence" => {
                ("private", true, None, valid_evidence("fixture-private"))
            }
            "swp-v1-provider-status-public-evidence" => (
                "public_reference",
                true,
                None,
                valid_evidence("fixture-public"),
            ),
            "swp-v1-provider-status-public-evidence-malformed" => (
                "public_reference",
                false,
                Some("swp_evidence_invalid"),
                json!({"class":"reservation","reference":"incomplete"}),
            ),
            _ => return Err(invalid("unknown provider evidence fixture")),
        };
        if case.publication != publication
            || case.valid != valid
            || case.error.as_deref() != expected_error
        {
            return Err(invalid("provider evidence fixture expectation drifted"));
        }
        let actual = validate_mkt_swp_evidence_reference(&value).map_err(|error| {
            provider_error(
                "swp_evidence_invalid",
                format!("provider fixture evidence is invalid: {error}"),
            )
        });
        expect_error(expected_error, actual)
    }

    fn replay_negative(case: &Negative) -> Result<(), SwapClientError> {
        let actual = match case.name.as_str() {
            "swp-v1-provider-rfq-wrong-author" => {
                require_negative(case, "rfq_author", Some("swp_contract_signer_invalid"))?;
                execute_wrong_rfq_author()
            }
            "swp-v1-provider-quote-rfq-mismatch" => {
                require_negative(
                    case,
                    "quote_rfq_constraints",
                    Some("swp_contract_terms_mismatch"),
                )?;
                execute_quote_rfq_mismatch()
            }
            "swp-v1-provider-order-not-selected" => {
                require_negative(
                    case,
                    "order_quote_reference",
                    Some("swp_contract_terms_mismatch"),
                )?;
                execute_bad_order(false)
            }
            "swp-v1-provider-order-indicative" => {
                require_negative(
                    case,
                    "order_indicative",
                    Some("swp_contract_terms_mismatch"),
                )?;
                execute_indicative_order()
            }
            "swp-v1-provider-second-order" => {
                require_negative(case, "second_order", Some("swp_idempotency_conflict"))?;
                execute_second_order()
            }
            "swp-v1-provider-second-requester-contract" => {
                require_negative(case, "second_contract", Some("swp_idempotency_conflict"))?;
                execute_second_requester_contract()
            }
            "swp-v1-provider-order-after-expiry" => {
                require_negative(case, "order_created_at", Some("swp_quote_expired"))?;
                execute_bad_order(true)
            }
            "swp-v1-provider-status-wrong-role" => {
                require_retained(case, "status_signer", "invalid_claim")?;
                execute_status_observation(StatusMutation::WrongFlow)
            }
            "swp-v1-provider-status-sequence-gap" => {
                require_retained(case, "status_sequence", "gap")?;
                execute_status_observation(StatusMutation::Gap)
            }
            "swp-v1-provider-status-transition-regression" => {
                require_retained(case, "status_state", "invalid_claim")?;
                execute_status_observation(StatusMutation::Regression)
            }
            "swp-v1-provider-status-fork" => {
                require_retained(case, "status_distinct", "fork")?;
                execute_status_observation(StatusMutation::Fork)
            }
            "swp-v1-provider-snapshot-custody-member" => {
                require_negative(case, "snapshot_seed", Some("swp_secret_material_forbidden"))?;
                execute_snapshot_custody()
            }
            "swp-v1-provider-history-over-bound" => {
                require_negative(
                    case,
                    "signed_records",
                    Some("swp_provider_history_exceeded"),
                )?;
                execute_history_bound()
            }
            "swp-v1-provider-effect-id-conflict" => {
                require_negative(case, "effect_request", Some("swp_idempotency_conflict"))?;
                execute_second_reserve()
            }
            _ => return Err(invalid("unknown provider negative fixture")),
        };
        expect_error(case.error.as_deref(), actual)
    }

    struct Setup {
        requester: MarketSigner,
        provider: MarketSigner,
        config: SwapClientConfig,
    }

    struct Ordered {
        setup: Setup,
        factory: SwapRecordFactory,
        provider: ProviderSession,
        rfq: Event,
        quote: Event,
        order: Event,
    }

    #[cfg(test)]
    pub(crate) struct CooperativeActorSetup {
        pub(crate) requester: MarketSigner,
        pub(crate) provider: MarketSigner,
        pub(crate) factory: SwapRecordFactory,
        pub(crate) session: ProviderSession,
        pub(crate) order: Event,
    }

    #[derive(Clone, Copy)]
    enum ReserveMutation {
        Confirmed,
        Rejected,
        Mismatched,
    }

    #[derive(Clone, Copy)]
    enum StatusMutation {
        WrongFlow,
        Gap,
        Regression,
        Fork,
    }

    fn setup(session_byte: u8) -> Result<Setup, SwapClientError> {
        let requester = MarketSigner::from_secret_bytes([1; 32]).map_err(|error| {
            provider_error(
                "swp_provider_fixture_invalid",
                format!("fixture requester key is invalid: {error}"),
            )
        })?;
        let provider = MarketSigner::from_secret_bytes([2; 32]).map_err(|error| {
            provider_error(
                "swp_provider_fixture_invalid",
                format!("fixture provider key is invalid: {error}"),
            )
        })?;
        let config = SwapClientConfig {
            session_id: format!("{session_byte:02x}").repeat(32),
            requester_pubkey: requester.pubkey().into(),
            provider_pubkey: provider.pubkey().into(),
            offering_address: format!("39601:{}:fixture-swaps", provider.pubkey()),
        };
        Ok(Setup {
            requester,
            provider,
            config,
        })
    }

    fn fixture_asset_pair(swap_type: &str) -> Value {
        let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
        let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
        match swap_type {
            "submarine" => json!([chain, lightning]),
            "reverse" => json!([lightning, chain]),
            "chain" => json!([
                chain,
                "swp:1:bip122:11111111111111111111111111111111:btc:chain"
            ]),
            _ => Value::Null,
        }
    }

    fn complete_quote_profile(swap_type: &str) -> Result<Value, SwapClientError> {
        let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
            .map_err(|error| invalid(&format!("full-session fixture JSON is invalid: {error}")))?;
        let records = fixtures
            .get("flows")
            .and_then(|flows| flows.get(swap_type))
            .and_then(|flow| flow.get("snapshot"))
            .and_then(|snapshot| snapshot.get("signed_records"))
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("full-session fixture records are missing"))?;
        let quote = records
            .iter()
            .find(|record| record.get("kind").and_then(Value::as_u64) == Some(39_605))
            .and_then(|record| record.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("full-session fixture Quote is missing"))?;
        serde_json::from_str::<Value>(quote)
            .map_err(|error| invalid(&format!("full-session Quote is invalid: {error}")))?
            .get("mkt_swp")
            .cloned()
            .ok_or_else(|| invalid("full-session Quote profile is missing"))
    }

    fn complete_rfq_profile(swap_type: &str) -> Result<Value, SwapClientError> {
        fixture_record_profile(swap_type, 39_604, None)
    }

    fn fixture_record_profile(
        swap_type: &str,
        kind: u64,
        signer_role: Option<&str>,
    ) -> Result<Value, SwapClientError> {
        let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
            .map_err(|error| invalid(&format!("full-session fixture JSON is invalid: {error}")))?;
        let records = fixtures
            .get("flows")
            .and_then(|flows| flows.get(swap_type))
            .and_then(|flow| flow.get("snapshot"))
            .and_then(|snapshot| snapshot.get("signed_records"))
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("full-session fixture records are missing"))?;
        let content = records
            .iter()
            .find(|record| {
                record.get("kind").and_then(Value::as_u64) == Some(kind)
                    && signer_role.is_none_or(|expected| {
                        record
                            .get("content")
                            .and_then(Value::as_str)
                            .and_then(|content| serde_json::from_str::<Value>(content).ok())
                            .and_then(|content| {
                                content
                                    .get("mkt_swp")
                                    .and_then(|profile| profile.get("signer_role"))
                                    .and_then(Value::as_str)
                                    .map(str::to_owned)
                            })
                            .as_deref()
                            == Some(expected)
                    })
            })
            .and_then(|record| record.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("full-session fixture record is missing"))?;
        serde_json::from_str::<Value>(content)
            .map_err(|error| invalid(&format!("full-session record is invalid: {error}")))?
            .get("mkt_swp")
            .cloned()
            .ok_or_else(|| invalid("full-session record profile is missing"))
    }

    fn complete_contract(
        swap_type: &str,
        config: &SwapClientConfig,
        rfq: &Event,
        quote: &Event,
        order: &Event,
    ) -> Result<Value, SwapClientError> {
        let mut contract = fixture_record_profile(swap_type, 39_610, Some("requester"))?
            .get("contract")
            .cloned()
            .ok_or_else(|| invalid("full-session fixture contract is missing"))?;
        contract["order_id"] = Value::String(order.id.clone());
        contract["quote_id"] = Value::String(quote.id.clone());
        let quote_profile = mkt_swp_body(quote)?;
        let reservation = quote_profile
            .get("reservation_terms")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("fixture Quote reservation terms are missing"))?;
        let proof_class = reservation
            .get("proof_class")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("fixture reservation proof class is missing"))?;
        let proof_strength = match proof_class {
            "provider_signed" => 10,
            "handler_accounted" => 20,
            "third_party_guarantee" => 40,
            "lightning_liquidity" => 50,
            "utxo_control" => 60,
            "funded_htlc" => 80,
            "covenant_reserve" => 100,
            _ => return Err(invalid("fixture reservation proof class is unsupported")),
        };
        let proof_ref = reservation
            .get("proof_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("fixture reservation proof reference is missing"))?;
        contract["reservation_commitment"] = json!({
            "session_id":config.session_id,
            "rfq_id":rfq.id,
            "quote_id":quote.id,
            "reservation_id":reservation["reservation_id"],
            "reservation_class":tag_value(quote, "reservation")?,
            "capacity_bucket_id":reservation["capacity_bucket_id"],
            "reserved_asset_id":reservation["reserved_asset_id"],
            "reserved_amount":reservation["reserved_amount"],
            "handler_committed_capacity":reservation["handler_committed_capacity"],
            "allocation_sequence":reservation["allocation_sequence"],
            "proof_class":proof_class,
            "proof_strength":proof_strength,
            "proof_ref_sha256":digest_bytes(proof_ref.as_bytes()),
            "capacity_commitment_sha256":reservation["capacity_commitment_sha256"],
            "reservation_expires_at":reservation["reservation_expires_at"],
            "profile_timeout_at":null,
            "covenant_commitment":null
        });
        Ok(contract)
    }

    fn complete_unreserved_quote_profile(swap_type: &str) -> Result<Value, SwapClientError> {
        let mut profile = complete_quote_profile(swap_type)?;
        profile
            .as_object_mut()
            .ok_or_else(|| invalid("full-session Quote profile is not an object"))?
            .remove("reservation_terms");
        Ok(profile)
    }

    fn fixture_zero_loss(swap_type: &str, reservation_released: &str) -> Value {
        let asset_pair = fixture_asset_pair(swap_type);
        json!({
            "input_asset_id":asset_pair[0],
            "output_asset_id":asset_pair[1],
            "input_committed":"0",
            "input_recovered":"0",
            "output_received":"0",
            "provider_fee_paid":"0",
            "miner_fee_paid":"0",
            "lightning_routing_fee_paid":"0",
            "guarantee_recovery_received":"0",
            "principal_unresolved":"0",
            "reservation_released":reservation_released,
            "evidence_refs":[],
            "unknown_fields":[]
        })
    }

    fn fixture_output_amount(swap_type: &str) -> &'static str {
        match swap_type {
            "submarine" => "1000",
            "reverse" => "890",
            "chain" => "98000",
            _ => "0",
        }
    }

    fn through_order(swap_type: &str, session_byte: u8) -> Result<Ordered, SwapClientError> {
        let setup = setup(session_byte)?;
        let factory = SwapRecordFactory::new(setup.config.clone())?;
        let rfq = sign_private(
            factory.rfq(100, &"11".repeat(32), 300, complete_rfq_profile(swap_type)?)?,
            &setup.requester,
        )?;
        let mut provider = ProviderSession::new(setup.config.clone())?;
        provider.ingest_signed(rfq.clone())?;
        let quote = sign_private(
            provider.soft_quote(
                101,
                &"12".repeat(32),
                300,
                complete_quote_profile(swap_type)?,
            )?,
            &setup.provider,
        )?;
        provider.ingest_signed(quote.clone())?;
        let order = sign_private(
            factory.order(
                102,
                &"13".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )?,
            &setup.requester,
        )?;
        provider.ingest_signed(order.clone())?;
        Ok(Ordered {
            setup,
            factory,
            provider,
            rfq,
            quote,
            order,
        })
    }

    #[cfg(test)]
    pub(crate) fn cooperative_actor_setup() -> Result<CooperativeActorSetup, SwapClientError> {
        let ordered = through_order("submarine", 0xc7)?;
        Ok(CooperativeActorSetup {
            requester: ordered.setup.requester,
            provider: ordered.setup.provider,
            factory: ordered.factory,
            session: ordered.provider,
            order: ordered.order,
        })
    }

    fn execute_no_spend_flow(swap_type: &str) -> Result<(), SwapClientError> {
        let mut ordered = through_order(swap_type, 0xa2)?;
        let contract = complete_contract(
            swap_type,
            &ordered.setup.config,
            &ordered.rfq,
            &ordered.quote,
            &ordered.order,
        )?;
        let requester_contract = sign_private(
            ordered.factory.swap_contract(
                ParticipantRole::Requester,
                103,
                &"14".repeat(32),
                SwapContractReferences {
                    order_id: &ordered.order.id,
                    quote_id: &ordered.quote.id,
                    accepted_status_id: None,
                },
                contract.clone(),
            )?,
            &ordered.setup.requester,
        )?;
        ordered.provider.ingest_signed(requester_contract)?;
        let provider_contract = sign_private(
            ordered
                .provider
                .provider_swap_contract(104, &"15".repeat(32), None, contract)?,
            &ordered.setup.provider,
        )?;
        ordered.provider.ingest_signed(provider_contract)?;
        let status = sign_private(
            ordered.provider.provider_status(
                105,
                &"16".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )?,
            &ordered.setup.provider,
        )?;
        ordered.provider.ingest_signed(status)?;
        let cancel_request = sign_private(
            ordered.factory.cancel(
                ParticipantRole::Requester,
                106,
                &"17".repeat(32),
                &ordered.order.id,
                Cancellation {
                    action: "request",
                    reason: "fixture_no_spend",
                    request_id: None,
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )?,
            &ordered.setup.requester,
        )?;
        ordered.provider.ingest_signed(cancel_request.clone())?;
        let accepted = sign_private(
            ordered.provider.provider_cancel(
                107,
                &"18".repeat(32),
                Cancellation {
                    action: "accepted",
                    reason: "fixture_no_spend",
                    request_id: Some(&cancel_request.id),
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )?,
            &ordered.setup.provider,
        )?;
        ordered.provider.ingest_signed(accepted.clone())?;
        let effective = sign_private(
            ordered.provider.provider_cancel(
                108,
                &"19".repeat(32),
                Cancellation {
                    action: "effective",
                    reason: "fixture_no_spend",
                    request_id: Some(&cancel_request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({"disposition":"no_funding_authorized"}),
            )?,
            &ordered.setup.provider,
        )?;
        ordered.provider.ingest_signed(effective.clone())?;
        let close = sign_private(
            ordered.provider.provider_close(
                109,
                &"20".repeat(32),
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: 109,
                },
                json!({
                    "final_state":"cancelled",
                    "external_spend_effects":0,
                    "cancel_id":effective.id,
                    "loss_accounting":fixture_zero_loss(
                        swap_type,
                        fixture_output_amount(swap_type)
                    )
                }),
            )?,
            &ordered.setup.provider,
        )?;
        ordered.provider.ingest_signed(close)?;
        ProviderSession::restore(&ordered.provider.persist()?).map(|_| ())
    }

    fn hard_session() -> Result<(Setup, ProviderSession, ReservationRequest), SwapClientError> {
        let setup = setup(0xa3)?;
        let factory = SwapRecordFactory::new(setup.config.clone())?;
        let rfq = sign_private(
            factory.rfq(
                100,
                &"21".repeat(32),
                300,
                complete_rfq_profile("submarine")?,
            )?,
            &setup.requester,
        )?;
        let mut provider = ProviderSession::new(setup.config.clone())?;
        provider.ingest_signed(rfq)?;
        let reservation = ReservationRequest {
            reservation_id: "22".repeat(32),
            capacity_bucket_id: "fixture-capacity".into(),
            reserved_asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:lightning".into(),
            reserved_amount: "1000".into(),
            reservation_expires_at: 250,
        };
        Ok((setup, provider, reservation))
    }

    fn confirmation(request: &super::ProviderEffectRequest) -> ReservationConfirmation {
        ReservationConfirmation {
            reservation_id: request.reservation_id.clone(),
            capacity_bucket_id: request.capacity_bucket_id.clone(),
            reserved_asset_id: request.reserved_asset_id.clone(),
            reserved_amount: request.reserved_amount.clone(),
            committed_capacity: "5000".into(),
            reservation_expires_at: request.reservation_expires_at,
            allocation_sequence: "1".into(),
            proof_class: "lightning_liquidity".into(),
            proof_ref: "fixture-node-view:1".into(),
            capacity_commitment_sha256: "23".repeat(32),
        }
    }

    fn execute_hard_reserve(mutation: ReserveMutation) -> Result<(), SwapClientError> {
        let (_setup, mut provider, reservation) = hard_session()?;
        let request = provider.hard_quote_with_reserve(
            101,
            &"24".repeat(32),
            200,
            reservation,
            complete_unreserved_quote_profile("submarine")?,
            |request| match mutation {
                ReserveMutation::Confirmed => Ok(confirmation(request)),
                ReserveMutation::Rejected => Err("fixture rejection".into()),
                ReserveMutation::Mismatched => {
                    let mut confirmation = confirmation(request);
                    confirmation.reserved_amount = "999".into();
                    Ok(confirmation)
                }
            },
        )?;
        if matches!(mutation, ReserveMutation::Confirmed) {
            let replay = provider.hard_quote_with_reserve(
                101,
                &"24".repeat(32),
                200,
                ReservationRequest {
                    reservation_id: "22".repeat(32),
                    capacity_bucket_id: "fixture-capacity".into(),
                    reserved_asset_id:
                        "swp:1:bip122:00000000000000000000000000000000:btc:lightning".into(),
                    reserved_amount: "1000".into(),
                    reservation_expires_at: 250,
                },
                complete_unreserved_quote_profile("submarine")?,
                |_| Err("reserve replay invoked callback".into()),
            )?;
            if request != replay {
                return Err(invalid("hard reserve replay changed signing bytes"));
            }
        }
        Ok(())
    }

    fn execute_release(cause: ReservationReleaseCause) -> Result<(), SwapClientError> {
        let (setup, mut provider, reservation) = hard_session()?;
        let quote = sign_private(
            provider.hard_quote_with_reserve(
                101,
                &"24".repeat(32),
                200,
                reservation,
                complete_unreserved_quote_profile("submarine")?,
                |request| Ok(confirmation(request)),
            )?,
            &setup.provider,
        )?;
        provider.ingest_signed(quote.clone())?;
        if cause != ReservationReleaseCause::ReservationExpired {
            let factory = SwapRecordFactory::new(setup.config.clone())?;
            let order = sign_private(
                factory.order(
                    102,
                    &"25".repeat(32),
                    &quote.id,
                    json!({"accepted_quote_id":quote.id}),
                )?,
                &setup.requester,
            )?;
            provider.ingest_signed(order.clone())?;
            if cause == ReservationReleaseCause::EffectiveCancel {
                let request = sign_private(
                    factory.cancel(
                        ParticipantRole::Requester,
                        103,
                        &"26".repeat(32),
                        &order.id,
                        Cancellation {
                            action: "request",
                            reason: "fixture_release",
                            request_id: None,
                            accepted_id: None,
                        },
                        json!({}),
                    )?,
                    &setup.requester,
                )?;
                provider.ingest_signed(request.clone())?;
                let accepted = sign_private(
                    provider.provider_cancel(
                        104,
                        &"27".repeat(32),
                        Cancellation {
                            action: "accepted",
                            reason: "fixture_release",
                            request_id: Some(&request.id),
                            accepted_id: None,
                        },
                        json!({}),
                    )?,
                    &setup.provider,
                )?;
                provider.ingest_signed(accepted.clone())?;
                let effective = sign_private(
                    provider.provider_cancel(
                        105,
                        &"28".repeat(32),
                        Cancellation {
                            action: "effective",
                            reason: "fixture_release",
                            request_id: Some(&request.id),
                            accepted_id: Some(&accepted.id),
                        },
                        json!({}),
                    )?,
                    &setup.provider,
                )?;
                provider.ingest_signed(effective)?;
            } else {
                let (close_request, receipt) = provider.provider_close_with_release(
                    103,
                    &"29".repeat(32),
                    CloseOutcome {
                        outcome: "rejected",
                        terminal_at: 103,
                    },
                    json!({
                        "final_state":"rejected",
                        "loss_accounting":fixture_zero_loss("submarine", "1000")
                    }),
                    |request| {
                        Ok(ProviderEffectReceipt {
                            effect_id: request.effect_id.clone(),
                            request_sha256: request.request_sha256.clone(),
                            external_reference: "fixture-release:1".into(),
                            result_sha256: "30".repeat(32),
                        })
                    },
                )?;
                if receipt.external_reference != "fixture-release:1" {
                    return Err(invalid("Close release receipt drifted"));
                }
                let close = sign_private(close_request, &setup.provider)?;
                provider.ingest_signed(close)?;
            }
        }
        let receipt = provider.release_reservation(cause, 250, |request| {
            Ok(ProviderEffectReceipt {
                effect_id: request.effect_id.clone(),
                request_sha256: request.request_sha256.clone(),
                external_reference: "fixture-release:1".into(),
                result_sha256: "30".repeat(32),
            })
        })?;
        let replay = provider.release_reservation(cause, 250, |_| {
            Err("release replay invoked callback".into())
        })?;
        if receipt != replay {
            return Err(invalid("release replay changed its receipt"));
        }
        Ok(())
    }

    fn execute_wrong_rfq_author() -> Result<(), SwapClientError> {
        let setup = setup(0xa4)?;
        let wrong_config = SwapClientConfig {
            requester_pubkey: setup.provider.pubkey().into(),
            provider_pubkey: setup.requester.pubkey().into(),
            offering_address: format!("39601:{}:fixture-swaps", setup.requester.pubkey()),
            ..setup.config.clone()
        };
        let wrong_factory = SwapRecordFactory::new(wrong_config)?;
        let rfq = sign_private(
            wrong_factory.rfq(100, &"31".repeat(32), 300, json!({"swap_type":"submarine"}))?,
            &setup.provider,
        )?;
        ProviderSession::new(setup.config)?
            .ingest_signed(rfq)
            .map(|_| ())
    }

    fn execute_bad_order(expired: bool) -> Result<(), SwapClientError> {
        let setup = setup(0xa5)?;
        let factory = SwapRecordFactory::new(setup.config.clone())?;
        let rfq = sign_private(
            factory.rfq(
                100,
                &"32".repeat(32),
                150,
                complete_rfq_profile("submarine")?,
            )?,
            &setup.requester,
        )?;
        let mut provider = ProviderSession::new(setup.config)?;
        provider.ingest_signed(rfq)?;
        let quote = sign_private(
            provider.soft_quote(
                101,
                &"33".repeat(32),
                150,
                complete_quote_profile("submarine")?,
            )?,
            &setup.provider,
        )?;
        provider.ingest_signed(quote.clone())?;
        let order = sign_private(
            factory.order(
                if expired { 151 } else { 102 },
                &"34".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":if expired { quote.id.clone() } else { "35".repeat(32) }}),
            )?,
            &setup.requester,
        )?;
        provider.ingest_signed(order).map(|_| ())
    }

    fn execute_quote_rfq_mismatch() -> Result<(), SwapClientError> {
        let setup = setup(0xaa)?;
        let factory = SwapRecordFactory::new(setup.config.clone())?;
        let rfq = sign_private(
            factory.rfq(
                100,
                &"50".repeat(32),
                300,
                complete_rfq_profile("submarine")?,
            )?,
            &setup.requester,
        )?;
        let mut provider = ProviderSession::new(setup.config)?;
        provider.ingest_signed(rfq)?;
        provider
            .soft_quote(
                101,
                &"51".repeat(32),
                300,
                complete_quote_profile("reverse")?,
            )
            .map(|_| ())
    }

    fn execute_indicative_order() -> Result<(), SwapClientError> {
        let setup = setup(0xa7)?;
        let factory = SwapRecordFactory::new(setup.config.clone())?;
        let mut rfq_profile = complete_rfq_profile("submarine")?;
        rfq_profile["constraints"]["firm_quote_required"] = Value::Bool(false);
        let rfq = sign_private(
            factory.rfq(100, &"44".repeat(32), 300, rfq_profile)?,
            &setup.requester,
        )?;
        let mut provider = ProviderSession::new(setup.config)?;
        provider.ingest_signed(rfq)?;
        let quote = sign_private(
            provider.indicative_quote(
                101,
                &"45".repeat(32),
                300,
                complete_unreserved_quote_profile("submarine")?,
            )?,
            &setup.provider,
        )?;
        provider.ingest_signed(quote.clone())?;
        let order = sign_private(
            factory.order(
                102,
                &"46".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )?,
            &setup.requester,
        )?;
        provider.ingest_signed(order).map(|_| ())
    }

    fn execute_second_order() -> Result<(), SwapClientError> {
        let mut ordered = through_order("submarine", 0xa8)?;
        let second_order = sign_private(
            ordered.factory.order(
                103,
                &"47".repeat(32),
                &ordered.quote.id,
                json!({"accepted_quote_id":ordered.quote.id}),
            )?,
            &ordered.setup.requester,
        )?;
        ordered.provider.ingest_signed(second_order).map(|_| ())
    }

    fn execute_second_requester_contract() -> Result<(), SwapClientError> {
        let mut ordered = through_order("submarine", 0xa9)?;
        let contract = complete_contract(
            "submarine",
            &ordered.setup.config,
            &ordered.rfq,
            &ordered.quote,
            &ordered.order,
        )?;
        let first = sign_private(
            ordered.factory.swap_contract(
                ParticipantRole::Requester,
                103,
                &"48".repeat(32),
                SwapContractReferences {
                    order_id: &ordered.order.id,
                    quote_id: &ordered.quote.id,
                    accepted_status_id: None,
                },
                contract.clone(),
            )?,
            &ordered.setup.requester,
        )?;
        ordered.provider.ingest_signed(first)?;
        let second = sign_private(
            ordered.factory.swap_contract(
                ParticipantRole::Requester,
                104,
                &"49".repeat(32),
                SwapContractReferences {
                    order_id: &ordered.order.id,
                    quote_id: &ordered.quote.id,
                    accepted_status_id: None,
                },
                contract,
            )?,
            &ordered.setup.requester,
        )?;
        ordered.provider.ingest_signed(second).map(|_| ())
    }

    fn execute_status_observation(mutation: StatusMutation) -> Result<(), SwapClientError> {
        let swap_type = if matches!(mutation, StatusMutation::WrongFlow) {
            "reverse"
        } else {
            "submarine"
        };
        let mut ordered = through_order(swap_type, 0xa6)?;
        match mutation {
            StatusMutation::WrongFlow => {
                let request = ordered.factory.status(
                    ParticipantRole::Requester,
                    104,
                    &"36".repeat(32),
                    &ordered.order.id,
                    StatusState {
                        sequence: 0,
                        previous: None,
                        base_state: "awaiting_input",
                        swp_state: "requester_verification_passed",
                    },
                    Map::new(),
                )?;
                ordered
                    .provider
                    .ingest_signed(sign_private(request, &ordered.setup.requester)?)?;
                if ordered
                    .provider
                    .status_projection()?
                    .invalid_claims
                    .is_empty()
                {
                    return Err(invalid("wrong-flow Status was not retained as invalid"));
                }
            }
            StatusMutation::Gap => {
                let status = sign_private(
                    ordered.factory.status(
                        ParticipantRole::Provider,
                        104,
                        &"37".repeat(32),
                        &ordered.order.id,
                        StatusState {
                            sequence: 1,
                            previous: Some(&"38".repeat(32)),
                            base_state: "executing",
                            swp_state: "lightning_payment_pending",
                        },
                        Map::new(),
                    )?,
                    &ordered.setup.provider,
                )?;
                ordered.provider.ingest_signed(status)?;
                if ordered.provider.status_projection()?.gaps.is_empty() {
                    return Err(invalid("Status gap was not retained in projection"));
                }
            }
            StatusMutation::Regression | StatusMutation::Fork => {
                let initial = sign_private(
                    ordered.provider.provider_status(
                        104,
                        &"39".repeat(32),
                        StatusState {
                            sequence: 0,
                            previous: None,
                            base_state: "accepted",
                            swp_state: "accepted",
                        },
                        Map::new(),
                    )?,
                    &ordered.setup.provider,
                )?;
                ordered.provider.ingest_signed(initial.clone())?;
                let status = sign_private(
                    ordered.factory.status(
                        ParticipantRole::Provider,
                        105,
                        &"40".repeat(32),
                        &ordered.order.id,
                        if matches!(mutation, StatusMutation::Regression) {
                            StatusState {
                                sequence: 1,
                                previous: Some(&initial.id),
                                base_state: "accepted",
                                swp_state: "accepted",
                            }
                        } else {
                            StatusState {
                                sequence: 0,
                                previous: None,
                                base_state: "accepted",
                                swp_state: "accepted",
                            }
                        },
                        Map::new(),
                    )?,
                    &ordered.setup.provider,
                )?;
                ordered.provider.ingest_signed(status)?;
                let projection = ordered.provider.status_projection()?;
                if matches!(mutation, StatusMutation::Regression)
                    && projection.invalid_claims.is_empty()
                    || matches!(mutation, StatusMutation::Fork) && projection.forks.is_empty()
                {
                    return Err(invalid("invalid Status was not retained in projection"));
                }
            }
        }
        Ok(())
    }

    fn execute_snapshot_custody() -> Result<(), SwapClientError> {
        let setup = setup(0xa7)?;
        let provider = ProviderSession::new(setup.config)?;
        let mut value: Value = serde_json::from_slice(&provider.persist()?).map_err(|error| {
            invalid(&format!(
                "could not parse provider fixture snapshot: {error}"
            ))
        })?;
        value
            .as_object_mut()
            .ok_or_else(|| invalid("provider fixture snapshot is not an object"))?
            .insert("seed".into(), Value::String("forbidden".into()));
        ProviderSession::restore(&serde_json::to_vec(&value).map_err(|error| {
            invalid(&format!(
                "could not encode provider fixture snapshot: {error}"
            ))
        })?)
        .map(|_| ())
    }

    fn execute_history_bound() -> Result<(), SwapClientError> {
        validate_provider_collection_bounds(super::MAX_PROVIDER_RECORDS + 1, 0)
    }

    fn execute_second_reserve() -> Result<(), SwapClientError> {
        let (_setup, mut provider, reservation) = hard_session()?;
        provider.hard_quote_with_reserve(
            101,
            &"41".repeat(32),
            200,
            reservation,
            complete_unreserved_quote_profile("submarine")?,
            |request| Ok(confirmation(request)),
        )?;
        provider
            .hard_quote_with_reserve(
                102,
                &"42".repeat(32),
                200,
                ReservationRequest {
                    reservation_id: "43".repeat(32),
                    capacity_bucket_id: "fixture-capacity".into(),
                    reserved_asset_id:
                        "swp:1:bip122:00000000000000000000000000000000:btc:lightning".into(),
                    reserved_amount: "1000".into(),
                    reservation_expires_at: 250,
                },
                complete_unreserved_quote_profile("submarine")?,
                |_| Err("second reserve callback must not run".into()),
            )
            .map(|_| ())
    }

    fn offering_content() -> Result<Value, SwapClientError> {
        Ok(json!({
            "mkt_swp": {
                "swap_types": ["submarine", "reverse", "chain"],
                "networks": [
                    "bip122:00000000000000000000000000000000",
                    "bip122:11111111111111111111111111111111"
                ],
                "script_modes": ["taproot-musig2-script-exit"],
                "reservation_proof_classes": ["handler_accounted", "lightning_liquidity"],
                "availability": "available",
                "evm_extension": "unsupported",
                "sides": [
                    {
                        "input_asset_id":"swp:1:bip122:00000000000000000000000000000000:btc:chain",
                        "output_asset_id":"swp:1:bip122:00000000000000000000000000000000:btc:lightning",
                        "min":"1","max":"1000000","fee_bps":"25"
                    },
                    {
                        "input_asset_id":"swp:1:bip122:00000000000000000000000000000000:btc:lightning",
                        "output_asset_id":"swp:1:bip122:00000000000000000000000000000000:btc:chain",
                        "min":"1","max":"1000000","fee_bps":"25"
                    },
                    {
                        "input_asset_id":"swp:1:bip122:00000000000000000000000000000000:btc:chain",
                        "output_asset_id":"swp:1:bip122:11111111111111111111111111111111:btc:chain",
                        "min":"1","max":"1000000","fee_bps":"25"
                    }
                ],
                "confirmation_policies": [{
                    "policy_id":"fixture","minimum_confirmations":"1",
                    "reorg_safety_blocks":"1","zero_confirmation":"forbidden",
                    "rbf":"track","replacement":"track"
                }]
            }
        }))
    }

    fn valid_evidence(reference: &str) -> Value {
        json!({
            "class":"reservation",
            "rung":"reserved",
            "rail":"provider",
            "reference":reference,
            "artifact_sha256":"44".repeat(32),
            "producer_pubkey":"45".repeat(32),
            "verifier_pubkey":null,
            "verifier_policy":null,
            "observed_at":100,
            "view":"fixture provider observation"
        })
    }

    fn sign_private(
        request: MktSigningRequest,
        signer: &MarketSigner,
    ) -> Result<Event, SwapClientError> {
        let event = signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request.verify_signed(event)
    }

    fn sign_public(
        request: MktPublicSigningRequest,
        signer: &MarketSigner,
    ) -> Result<Event, SwapClientError> {
        let event = signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request.verify_signed(event)
    }

    fn expect_error(
        expected: Option<&str>,
        actual: Result<(), SwapClientError>,
    ) -> Result<(), SwapClientError> {
        match (expected, actual) {
            (None, Ok(())) => Ok(()),
            (Some(expected), Err(error)) if error.code == expected => Ok(()),
            (None, Err(error)) => Err(invalid(&format!(
                "provider fixture unexpectedly failed with {}",
                error.code
            ))),
            (Some(expected), Ok(())) => Err(invalid(&format!(
                "provider fixture expected {expected} but succeeded"
            ))),
            (Some(expected), Err(error)) => Err(invalid(&format!(
                "provider fixture expected {expected} but got {}",
                error.code
            ))),
        }
    }

    fn require_reservation_case(
        case: &ReservationEffect,
        operation: &str,
        cause: Option<&str>,
        replay: &str,
        signing_request: Option<bool>,
        error: Option<&str>,
    ) -> Result<(), SwapClientError> {
        if case.operation == operation
            && case.cause.as_deref() == cause
            && case.replay == replay
            && case.signing_request == signing_request
            && case.error.as_deref() == error
        {
            Ok(())
        } else {
            Err(invalid("reservation fixture expectation drifted"))
        }
    }

    fn require_negative(
        case: &Negative,
        mutation: &str,
        error: Option<&str>,
    ) -> Result<(), SwapClientError> {
        if case.mutation == mutation
            && case.error.as_deref() == error
            && case.retained.is_none()
            && case.projection.is_none()
        {
            Ok(())
        } else {
            Err(invalid("negative fixture expectation drifted"))
        }
    }

    fn require_retained(
        case: &Negative,
        mutation: &str,
        projection: &str,
    ) -> Result<(), SwapClientError> {
        if case.mutation == mutation
            && case.error.is_none()
            && case.retained == Some(true)
            && case.projection.as_deref() == Some(projection)
        {
            Ok(())
        } else {
            Err(invalid("retained Status fixture expectation drifted"))
        }
    }

    fn require_unique_name(
        names: &mut BTreeSet<String>,
        name: &str,
    ) -> Result<(), SwapClientError> {
        if names.insert(name.into()) {
            Ok(())
        } else {
            Err(invalid("provider fixture contains a duplicate name"))
        }
    }

    fn expected_names() -> BTreeSet<String> {
        [
            "swp-v1-provider-profile-publish",
            "swp-v1-provider-profile-rotate",
            "swp-v1-provider-offering-publish",
            "swp-v1-provider-offering-rotate",
            "swp-v1-provider-submarine-no-spend",
            "swp-v1-provider-reverse-no-spend",
            "swp-v1-provider-chain-no-spend",
            "swp-v1-provider-hard-reserve-confirmed",
            "swp-v1-provider-hard-reserve-rejected",
            "swp-v1-provider-hard-reserve-mismatched",
            "swp-v1-provider-release-on-cancel",
            "swp-v1-provider-release-on-expiry",
            "swp-v1-provider-release-on-close",
            "swp-v1-provider-status-private-evidence",
            "swp-v1-provider-status-public-evidence",
            "swp-v1-provider-status-public-evidence-malformed",
            "swp-v1-provider-rfq-wrong-author",
            "swp-v1-provider-quote-rfq-mismatch",
            "swp-v1-provider-order-not-selected",
            "swp-v1-provider-order-indicative",
            "swp-v1-provider-second-order",
            "swp-v1-provider-second-requester-contract",
            "swp-v1-provider-order-after-expiry",
            "swp-v1-provider-status-wrong-role",
            "swp-v1-provider-status-sequence-gap",
            "swp-v1-provider-status-transition-regression",
            "swp-v1-provider-status-fork",
            "swp-v1-provider-snapshot-custody-member",
            "swp-v1-provider-history-over-bound",
            "swp-v1-provider-effect-id-conflict",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn invalid(detail: &str) -> SwapClientError {
        provider_error("swp_provider_fixture_invalid", detail)
    }

    #[cfg(test)]
    mod bound_reserve_tests {
        use std::cell::Cell;

        use super::*;

        #[test]
        fn bound_reserve_replay_preserves_exact_quote_bytes() {
            let (_setup, mut provider, reservation) = reverse_hard_session();
            let profile = complete_unreserved_quote_profile("reverse").expect("reverse profile");
            let expected_funding = profile["terms"]["verifier_inputs"]
                .as_array()
                .and_then(|verifiers| {
                    verifiers
                        .iter()
                        .find(|verifier| verifier["leg_id"] == "destination")
                })
                .and_then(|verifier| verifier["funding_transaction"].as_str())
                .expect("fixture reverse funding transaction")
                .to_owned();
            let reserve_attempts = Cell::new(0);
            let replay_confirmations = Cell::new(0);
            let first = provider
                .hard_quote_with_bound_reserve(
                    101,
                    &"34".repeat(32),
                    200,
                    reservation.clone(),
                    profile.clone(),
                    |request, existing_confirmation, profile| {
                        assert!(existing_confirmation.is_none());
                        reserve_attempts.set(reserve_attempts.get() + 1);
                        Ok((confirmation(request), profile))
                    },
                )
                .expect("first bound reserve");
            let replay = provider
                .hard_quote_with_bound_reserve(
                    101,
                    &"34".repeat(32),
                    200,
                    reservation,
                    profile,
                    |_request, existing_confirmation, profile| {
                        let existing_confirmation = existing_confirmation
                            .expect("replay must expose its durable confirmation");
                        replay_confirmations.set(replay_confirmations.get() + 1);
                        Ok((existing_confirmation.clone(), profile))
                    },
                )
                .expect("exact bound reserve replay");

            assert_eq!(reserve_attempts.get(), 1);
            assert_eq!(replay_confirmations.get(), 1);
            assert_eq!(first, replay);
            let content: Value = serde_json::from_str(&first.content).expect("Quote content");
            let committed = content["mkt_swp"]["terms"]["verifier_inputs"]
                .as_array()
                .and_then(|verifiers| {
                    verifiers
                        .iter()
                        .find(|verifier| verifier["leg_id"] == "destination")
                })
                .and_then(|verifier| verifier["funding_transaction"].as_str())
                .expect("bound reverse funding transaction");
            assert_eq!(committed, expected_funding);
        }

        #[test]
        fn bound_reserve_replay_rejects_confirmation_and_quote_conflicts() {
            let (_setup, mut provider, reservation) = reverse_hard_session();
            let profile = complete_unreserved_quote_profile("reverse").expect("reverse profile");
            provider
                .hard_quote_with_bound_reserve(
                    101,
                    &"35".repeat(32),
                    200,
                    reservation.clone(),
                    profile.clone(),
                    |request, existing_confirmation, profile| {
                        assert!(existing_confirmation.is_none());
                        Ok((confirmation(request), profile))
                    },
                )
                .expect("first bound reserve");

            let confirmation_conflict = provider
                .hard_quote_with_bound_reserve(
                    101,
                    &"35".repeat(32),
                    200,
                    reservation.clone(),
                    profile.clone(),
                    |_request, existing_confirmation, profile| {
                        let mut changed = existing_confirmation
                            .expect("replay must expose its durable confirmation")
                            .clone();
                        changed.proof_ref = "fixture-node-view:changed".to_owned();
                        Ok((changed, profile))
                    },
                )
                .expect_err("changed confirmation must conflict");
            assert_eq!(confirmation_conflict.code, "swp_idempotency_conflict");

            let quote_conflict = provider
                .hard_quote_with_bound_reserve(
                    102,
                    &"35".repeat(32),
                    200,
                    reservation,
                    profile,
                    |_request, existing_confirmation, profile| {
                        let confirmation = existing_confirmation
                            .expect("replay must expose its durable confirmation")
                            .clone();
                        Ok((confirmation, profile))
                    },
                )
                .expect_err("changed Quote signing bytes must conflict");
            assert_eq!(quote_conflict.code, "swp_idempotency_conflict");
        }

        fn reverse_hard_session() -> (Setup, ProviderSession, ReservationRequest) {
            let setup = setup(0xa4).expect("setup");
            let factory = SwapRecordFactory::new(setup.config.clone()).expect("factory");
            let rfq = sign_private(
                factory
                    .rfq(
                        100,
                        &"31".repeat(32),
                        300,
                        complete_rfq_profile("reverse").expect("reverse RFQ profile"),
                    )
                    .expect("RFQ request"),
                &setup.requester,
            )
            .expect("signed RFQ");
            let mut provider = ProviderSession::new(setup.config.clone()).expect("provider");
            provider.ingest_signed(rfq).expect("ingested RFQ");
            let reservation = ReservationRequest {
                reservation_id: "32".repeat(32),
                capacity_bucket_id: "fixture-chain-capacity".to_owned(),
                reserved_asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:chain"
                    .to_owned(),
                reserved_amount: "890".to_owned(),
                reservation_expires_at: 250,
            };
            (setup, provider, reservation)
        }
    }
}
