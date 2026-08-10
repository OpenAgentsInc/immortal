//! Durable revision-2 intent admission for the provider effect boundary.

use std::{collections::BTreeMap, fmt};

use immortal_core::domain::{
    Event, MKT_CLOSE_KIND, MKT_HARDENING_PROTOCOL_REVISION, MKT_HARDENING_SCHEMA, MKT_ORDER_KIND,
    MKT_QUOTE_KIND, MKT_RECEIPT_SCHEMA, MKT_RECEIPT_VERSION, MKT_STATUS_KIND,
    MKT_SWP_INTENT_ACK_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION,
    MKT_SWP_SETTLEMENT_RECEIPT_KIND, MktHardeningErrorCode, MktHardeningRecord,
    MktHardeningRecordKind, MktProfileSupport, MktReceiptFee, MktReceiptLeg, MktSettlementReceipt,
    Tag, canonical_mkt_receipt_content, mkt_receipt_id, validate_mkt_hardening_event,
    validate_mkt_private_with_profiles, verify_mkt_receipt_chain,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const JOURNAL_SCHEMA: &str = "openagents.mkt-swp.intent-journal.v2";
const JOURNAL_SCHEMA_V1: &str = "openagents.mkt-swp.intent-journal.v1";
const MAX_INTENT_BINDINGS: usize = 512;
const MAX_OUTCOMES: usize = 128;
const MAX_RECEIPTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderHardeningErrorCode {
    InvalidIntent,
    IdempotencyConflict,
    Replay,
    NonceWindow,
    UnsupportedRevision,
    Bounds,
    Persistence,
    Signature,
}

impl ProviderHardeningErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidIntent => "mkt-v2-intent-invalid",
            Self::IdempotencyConflict => "mkt-v2-idempotency-conflict",
            Self::Replay => "mkt-v2-replay",
            Self::NonceWindow => "mkt-v2-nonce-window",
            Self::UnsupportedRevision => "mkt-v2-unsupported-revision",
            Self::Bounds => "mkt-v2-intent-bounds",
            Self::Persistence => "mkt-v2-persistence-failed",
            Self::Signature => "mkt-v2-signature-invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHardeningError {
    pub code: ProviderHardeningErrorCode,
    pub detail: String,
}

impl fmt::Display for ProviderHardeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for ProviderHardeningError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentAckSigningRequest {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
    pub expected_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReceiptSigningRequest {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Tag>,
    pub content: String,
    pub expected_event_id: String,
}

impl SettlementReceiptSigningRequest {
    pub fn verify_signed(&self, event: Event) -> Result<Event, ProviderHardeningError> {
        if event.pubkey != self.pubkey
            || event.created_at != self.created_at
            || event.kind != self.kind
            || event.tags != self.tags
            || event.content != self.content
            || event.id != self.expected_event_id
        {
            return Err(error(
                ProviderHardeningErrorCode::Signature,
                "receipt signer changed the requested bytes",
            ));
        }
        validate_signed(&event)?;
        Ok(event)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReceiptClaim {
    pub failure_code: Option<String>,
    pub started_at: u64,
    pub finished_at: u64,
    pub legs: Vec<MktReceiptLeg>,
    pub fees: Vec<MktReceiptFee>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReceiptEmissionRequest {
    pub order_event_id: String,
    pub outcome_event_id: String,
    pub quote: Event,
    pub client_confirmation: Option<Event>,
    pub claim: SettlementReceiptClaim,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptEmission {
    New { receipt: Event },
    Replay { receipt: Event },
}

impl IntentAckSigningRequest {
    pub fn verify_signed(&self, event: Event) -> Result<Event, ProviderHardeningError> {
        if event.pubkey != self.pubkey
            || event.created_at != self.created_at
            || event.kind != self.kind
            || event.tags != self.tags
            || event.content != self.content
            || event.id != self.expected_event_id
        {
            return Err(error(
                ProviderHardeningErrorCode::Signature,
                "acknowledgment signer changed the requested bytes",
            ));
        }
        validate_signed(&event)?;
        Ok(event)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentAdmission {
    New {
        acknowledgment: Event,
    },
    Replay {
        acknowledgment: Event,
        outcomes: Vec<Event>,
        receipts: Vec<Event>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectAttemptClaim {
    Claimed,
    AlreadyClaimed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedriveRestatement {
    pub redrive_acknowledgment: Event,
    pub original_acknowledgment: Event,
    pub outcomes: Vec<Event>,
    pub receipts: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    receipt: Event,
    quote: Event,
    client_confirmation: Option<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentBinding {
    intent: Event,
    acknowledgment: Event,
    outcomes: Vec<Event>,
    #[serde(default)]
    receipts: Vec<StoredReceipt>,
    effect_attempt_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIntentJournal {
    schema: String,
    provider_pubkey: String,
    session_id: String,
    bindings: BTreeMap<String, IntentBinding>,
    nonces: BTreeMap<String, String>,
}

impl ProviderIntentJournal {
    pub fn new(
        provider_pubkey: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<Self, ProviderHardeningError> {
        let provider_pubkey = provider_pubkey.into();
        let session_id = session_id.into();
        lower_hex_32(&provider_pubkey, "provider pubkey")?;
        lower_hex_32(&session_id, "session id")?;
        Ok(Self {
            schema: JOURNAL_SCHEMA.to_owned(),
            provider_pubkey,
            session_id,
            bindings: BTreeMap::new(),
            nonces: BTreeMap::new(),
        })
    }

    pub fn provider_pubkey(&self) -> &str {
        &self.provider_pubkey
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn admit_with_ack<S, P>(
        &mut self,
        intent: Event,
        observed_at: u64,
        mut sign: S,
        mut persist_once: P,
    ) -> Result<IntentAdmission, ProviderHardeningError>
    where
        S: FnMut(&IntentAckSigningRequest) -> Result<Event, String>,
        P: FnMut(&[u8]) -> Result<(), String>,
    {
        validate_signed(&intent)?;
        let record = hardening_record(&intent, Some(observed_at))?;
        if record.kind == MktHardeningRecordKind::Acknowledgment {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "provider journal admits Orders and Re-drive intents, not acknowledgments",
            ));
        }
        if self.session_id != hardening_envelope(&intent)?.session_id {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "intent belongs to another provider session",
            ));
        }
        require_provider_recipient(&intent, &self.provider_pubkey)?;
        let scope = scope_key(&intent.pubkey, &record.idempotency_key);
        if let Some(existing) = self.bindings.get(&scope) {
            if existing.intent == intent {
                return Ok(IntentAdmission::Replay {
                    acknowledgment: existing.acknowledgment.clone(),
                    outcomes: existing.outcomes.clone(),
                    receipts: existing
                        .receipts
                        .iter()
                        .map(|stored| stored.receipt.clone())
                        .collect(),
                });
            }
            return Err(error(
                ProviderHardeningErrorCode::IdempotencyConflict,
                "idempotency key is already bound to different signed bytes",
            ));
        }
        let nonce = record.nonce.as_deref().ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "intent has no validated nonce",
            )
        })?;
        let nonce_scope = nonce_key(&intent.pubkey, nonce);
        if let Some(existing_id) = self.nonces.get(&nonce_scope) {
            if existing_id != &intent.id {
                return Err(error(
                    ProviderHardeningErrorCode::Replay,
                    "nonce is already bound to a different signed intent",
                ));
            }
        }
        if self.bindings.len() >= MAX_INTENT_BINDINGS {
            return Err(error(
                ProviderHardeningErrorCode::Bounds,
                "intent journal is full",
            ));
        }
        if record.kind == MktHardeningRecordKind::RedriveIntent {
            self.validate_redrive_target(&record)?;
        }

        let request = acknowledgment_request(&self.provider_pubkey, &intent, &record, observed_at)?;
        let acknowledgment = sign(&request).map_err(|detail| {
            error(
                ProviderHardeningErrorCode::Signature,
                format!("acknowledgment signing failed: {detail}"),
            )
        })?;
        let acknowledgment = request.verify_signed(acknowledgment)?;
        validate_acknowledgment(&self.provider_pubkey, &intent, &record, &acknowledgment)?;

        let old = self.clone();
        self.bindings.insert(
            scope,
            IntentBinding {
                intent: intent.clone(),
                acknowledgment: acknowledgment.clone(),
                outcomes: Vec::new(),
                receipts: Vec::new(),
                effect_attempt_claimed: false,
            },
        );
        self.nonces.insert(nonce_scope, intent.id.clone());
        if let Err(detail) = persist_once(&self.snapshot_bytes()?) {
            *self = old;
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                format!("intent acknowledgment was not persisted: {detail}"),
            ));
        }
        Ok(IntentAdmission::New { acknowledgment })
    }

    pub fn claim_effect_attempt<P>(
        &mut self,
        order_event_id: &str,
        mut persist_once: P,
    ) -> Result<EffectAttemptClaim, ProviderHardeningError>
    where
        P: FnMut(&[u8]) -> Result<(), String>,
    {
        let scope = self.scope_for_intent(order_event_id)?;
        let binding = self.bindings.get(&scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "effect claim references an unknown intent",
            )
        })?;
        if binding.intent.kind != MKT_ORDER_KIND {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "only a revision-2 Order can claim an effect attempt",
            ));
        }
        if binding.effect_attempt_claimed {
            return Ok(EffectAttemptClaim::AlreadyClaimed);
        }
        let old = self.clone();
        if let Some(binding) = self.bindings.get_mut(&scope) {
            binding.effect_attempt_claimed = true;
        }
        if let Err(detail) = persist_once(&self.snapshot_bytes()?) {
            *self = old;
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                format!("effect-attempt claim was not persisted: {detail}"),
            ));
        }
        Ok(EffectAttemptClaim::Claimed)
    }

    pub fn record_outcome<P>(
        &mut self,
        order_event_id: &str,
        outcome: Event,
        mut persist_once: P,
    ) -> Result<bool, ProviderHardeningError>
    where
        P: FnMut(&[u8]) -> Result<(), String>,
    {
        validate_signed(&outcome)?;
        if !matches!(outcome.kind, MKT_STATUS_KIND | MKT_CLOSE_KIND) {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "revision-2 outcome must be a signed Status or Close",
            ));
        }
        require_reference(&outcome, "order", order_event_id)?;
        let scope = self.scope_for_intent(order_event_id)?;
        let binding = self.bindings.get(&scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "outcome references an unknown Order",
            )
        })?;
        if let Some(existing) = binding.outcomes.iter().find(|event| event.id == outcome.id) {
            if existing == &outcome {
                return Ok(false);
            }
            return Err(error(
                ProviderHardeningErrorCode::IdempotencyConflict,
                "one outcome event id has conflicting signed bytes",
            ));
        }
        let total_outcomes = self
            .bindings
            .values()
            .map(|binding| binding.outcomes.len())
            .sum::<usize>();
        if total_outcomes >= MAX_OUTCOMES {
            return Err(error(
                ProviderHardeningErrorCode::Bounds,
                "outcome journal is full",
            ));
        }
        let old = self.clone();
        if let Some(binding) = self.bindings.get_mut(&scope) {
            binding.outcomes.push(outcome);
        }
        if let Err(detail) = persist_once(&self.snapshot_bytes()?) {
            *self = old;
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                format!("outcome was not persisted: {detail}"),
            ));
        }
        Ok(true)
    }

    pub fn emit_receipt_with_sign<S, P>(
        &mut self,
        request: SettlementReceiptEmissionRequest,
        mut sign: S,
        mut persist_once: P,
    ) -> Result<ReceiptEmission, ProviderHardeningError>
    where
        S: FnMut(&SettlementReceiptSigningRequest) -> Result<Event, String>,
        P: FnMut(&[u8]) -> Result<(), String>,
    {
        let SettlementReceiptEmissionRequest {
            order_event_id,
            outcome_event_id,
            quote,
            client_confirmation,
            claim,
            created_at,
        } = request;
        validate_signed(&quote)?;
        if quote.kind != MKT_QUOTE_KIND || quote.pubkey != self.provider_pubkey {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "receipt Quote must be signed by this provider",
            ));
        }
        let scope = self.scope_for_intent(&order_event_id)?;
        let binding = self.bindings.get(&scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "receipt references an unknown Order",
            )
        })?;
        if binding.intent.kind != MKT_ORDER_KIND {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "only a revision-2 Order can produce a receipt",
            ));
        }
        require_reference(&binding.intent, "quote", &quote.id)?;
        let outcome = binding
            .outcomes
            .iter()
            .find(|event| event.id == outcome_event_id)
            .filter(|event| event.kind == MKT_CLOSE_KIND)
            .cloned()
            .ok_or_else(|| {
                error(
                    ProviderHardeningErrorCode::InvalidIntent,
                    "receipt requires a durable terminal Close",
                )
            })?;
        let outcome_name = required_tag(&outcome, "outcome")?.to_owned();
        if let Some(confirmation) = client_confirmation.as_ref() {
            validate_signed(confirmation)?;
            if confirmation.pubkey != binding.intent.pubkey {
                return Err(error(
                    ProviderHardeningErrorCode::InvalidIntent,
                    "client confirmation is not signed by the requester",
                ));
            }
            require_reference(confirmation, "order", &order_event_id)?;
        }
        let session_id = hardening_envelope(&binding.intent)?.session_id;
        if hardening_envelope(&quote)?.session_id != session_id {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "receipt Quote belongs to another session",
            ));
        }
        let mut receipt_claim = MktSettlementReceipt {
            schema: MKT_RECEIPT_SCHEMA.to_owned(),
            version: MKT_RECEIPT_VERSION,
            receipt_id: String::new(),
            intent_event_id: binding.intent.id.clone(),
            acknowledgment_event_id: binding.acknowledgment.id.clone(),
            quote_event_id: quote.id.clone(),
            outcome_event_id: outcome.id.clone(),
            client_confirmation_event_id: client_confirmation
                .as_ref()
                .map(|event| event.id.clone()),
            outcome: outcome_name,
            failure_code: claim.failure_code,
            started_at: claim.started_at,
            finished_at: claim.finished_at,
            legs: claim.legs,
            fees: claim.fees,
        };
        receipt_claim.receipt_id = mkt_receipt_id(&receipt_claim).map_err(|detail| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                format!("receipt claim is invalid: {detail}"),
            )
        })?;

        if let Some(existing) = binding.receipts.iter().find(|stored| {
            stored.receipt.tags.iter().any(|tag| {
                tag.as_slice().get(3).map(String::as_str) == Some("outcome")
                    && tag.as_slice().get(1).map(String::as_str) == Some(outcome_event_id.as_str())
            })
        }) {
            let existing_claim = verify_mkt_receipt_chain(
                &existing.receipt,
                &binding.intent,
                &binding.acknowledgment,
                &existing.quote,
                &outcome,
                existing.client_confirmation.as_ref(),
            )
            .map_err(|detail| {
                error(
                    ProviderHardeningErrorCode::Persistence,
                    format!("durable receipt chain is invalid: {detail}"),
                )
            })?;
            if existing_claim != receipt_claim
                || existing.quote != quote
                || existing.client_confirmation != client_confirmation
            {
                return Err(error(
                    ProviderHardeningErrorCode::IdempotencyConflict,
                    "terminal Close is already bound to a different receipt claim",
                ));
            }
            return Ok(ReceiptEmission::Replay {
                receipt: existing.receipt.clone(),
            });
        }
        let total_receipts = self
            .bindings
            .values()
            .map(|binding| binding.receipts.len())
            .sum::<usize>();
        if total_receipts >= MAX_RECEIPTS {
            return Err(error(
                ProviderHardeningErrorCode::Bounds,
                "receipt journal is full",
            ));
        }

        let request = receipt_signing_request(
            &self.provider_pubkey,
            &binding.intent,
            &session_id,
            &receipt_claim,
            created_at,
        )?;
        hardening_envelope(&Event {
            id: request.expected_event_id.clone(),
            pubkey: request.pubkey.clone(),
            created_at: request.created_at,
            kind: request.kind,
            tags: request.tags.clone(),
            content: request.content.clone(),
            sig: "0".repeat(128),
        })?;
        let receipt = sign(&request).map_err(|detail| {
            error(
                ProviderHardeningErrorCode::Signature,
                format!("receipt signing failed: {detail}"),
            )
        })?;
        let receipt = request.verify_signed(receipt)?;
        verify_mkt_receipt_chain(
            &receipt,
            &binding.intent,
            &binding.acknowledgment,
            &quote,
            &outcome,
            client_confirmation.as_ref(),
        )
        .map_err(|detail| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                format!("signed receipt chain is invalid: {detail}"),
            )
        })?;

        let old = self.clone();
        if let Some(binding) = self.bindings.get_mut(&scope) {
            binding.receipts.push(StoredReceipt {
                receipt: receipt.clone(),
                quote,
                client_confirmation,
            });
        }
        if let Err(detail) = persist_once(&self.snapshot_bytes()?) {
            *self = old;
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                format!("receipt was not persisted: {detail}"),
            ));
        }
        Ok(ReceiptEmission::New { receipt })
    }

    pub fn restate(
        &self,
        redrive_event_id: &str,
    ) -> Result<RedriveRestatement, ProviderHardeningError> {
        let redrive_scope = self.scope_for_intent(redrive_event_id)?;
        let redrive = self.bindings.get(&redrive_scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive is not admitted",
            )
        })?;
        let redrive_record = hardening_record(&redrive.intent, None)?;
        if redrive_record.kind != MktHardeningRecordKind::RedriveIntent {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "restatement requires a Re-drive Intent",
            ));
        }
        let order_event_id = redrive_record.order_event_id.as_deref().ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive has no Order reference",
            )
        })?;
        let order_scope = self.scope_for_intent(order_event_id)?;
        let order = self.bindings.get(&order_scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive Order is not admitted",
            )
        })?;
        Ok(RedriveRestatement {
            redrive_acknowledgment: redrive.acknowledgment.clone(),
            original_acknowledgment: order.acknowledgment.clone(),
            outcomes: order.outcomes.clone(),
            receipts: order
                .receipts
                .iter()
                .map(|stored| stored.receipt.clone())
                .collect(),
        })
    }

    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, ProviderHardeningError> {
        serde_json::to_vec(self).map_err(|detail| {
            error(
                ProviderHardeningErrorCode::Persistence,
                format!("could not serialize intent journal: {detail}"),
            )
        })
    }

    pub fn restore(bytes: &[u8]) -> Result<Self, ProviderHardeningError> {
        let mut journal: Self = serde_json::from_slice(bytes).map_err(|detail| {
            error(
                ProviderHardeningErrorCode::Persistence,
                format!("intent journal snapshot is invalid: {detail}"),
            )
        })?;
        journal.validate_snapshot()?;
        journal.schema = JOURNAL_SCHEMA.to_owned();
        Ok(journal)
    }

    fn validate_snapshot(&self) -> Result<(), ProviderHardeningError> {
        if self.schema != JOURNAL_SCHEMA && self.schema != JOURNAL_SCHEMA_V1 {
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                "intent journal schema is unsupported",
            ));
        }
        lower_hex_32(&self.provider_pubkey, "provider pubkey")?;
        lower_hex_32(&self.session_id, "session id")?;
        if self.bindings.len() > MAX_INTENT_BINDINGS
            || self
                .bindings
                .values()
                .map(|binding| binding.outcomes.len())
                .sum::<usize>()
                > MAX_OUTCOMES
            || self
                .bindings
                .values()
                .map(|binding| binding.receipts.len())
                .sum::<usize>()
                > MAX_RECEIPTS
        {
            return Err(error(
                ProviderHardeningErrorCode::Bounds,
                "intent journal snapshot exceeds its bounds",
            ));
        }
        let mut nonces = BTreeMap::new();
        for (scope, binding) in &self.bindings {
            validate_signed(&binding.intent)?;
            let record = hardening_record(&binding.intent, None)?;
            if scope != &scope_key(&binding.intent.pubkey, &record.idempotency_key) {
                return Err(error(
                    ProviderHardeningErrorCode::Persistence,
                    "intent journal scope key does not match its signed event",
                ));
            }
            if hardening_envelope(&binding.intent)?.session_id != self.session_id {
                return Err(error(
                    ProviderHardeningErrorCode::Persistence,
                    "intent journal contains another session",
                ));
            }
            validate_acknowledgment(
                &self.provider_pubkey,
                &binding.intent,
                &record,
                &binding.acknowledgment,
            )?;
            let nonce = record.nonce.as_deref().ok_or_else(|| {
                error(
                    ProviderHardeningErrorCode::Persistence,
                    "stored intent has no nonce",
                )
            })?;
            nonces.insert(
                nonce_key(&binding.intent.pubkey, nonce),
                binding.intent.id.clone(),
            );
            for outcome in &binding.outcomes {
                validate_signed(outcome)?;
                require_reference(outcome, "order", &binding.intent.id)?;
            }
            for stored in &binding.receipts {
                let outcome_id = stored
                    .receipt
                    .tags
                    .iter()
                    .find(|tag| tag.as_slice().get(3).map(String::as_str) == Some("outcome"))
                    .and_then(|tag| tag.as_slice().get(1))
                    .ok_or_else(|| {
                        error(
                            ProviderHardeningErrorCode::Persistence,
                            "stored receipt has no terminal outcome reference",
                        )
                    })?;
                let outcome = binding
                    .outcomes
                    .iter()
                    .find(|event| &event.id == outcome_id)
                    .ok_or_else(|| {
                        error(
                            ProviderHardeningErrorCode::Persistence,
                            "stored receipt outcome is not durable",
                        )
                    })?;
                verify_mkt_receipt_chain(
                    &stored.receipt,
                    &binding.intent,
                    &binding.acknowledgment,
                    &stored.quote,
                    outcome,
                    stored.client_confirmation.as_ref(),
                )
                .map_err(|detail| {
                    error(
                        ProviderHardeningErrorCode::Persistence,
                        format!("stored receipt chain is invalid: {detail}"),
                    )
                })?;
            }
            if binding.intent.kind != MKT_ORDER_KIND
                && (binding.effect_attempt_claimed || !binding.receipts.is_empty())
            {
                return Err(error(
                    ProviderHardeningErrorCode::Persistence,
                    "read-only Re-drive contains effect or receipt state",
                ));
            }
        }
        if nonces != self.nonces {
            return Err(error(
                ProviderHardeningErrorCode::Persistence,
                "intent journal nonce index does not match its bindings",
            ));
        }
        Ok(())
    }

    fn validate_redrive_target(
        &self,
        record: &MktHardeningRecord,
    ) -> Result<(), ProviderHardeningError> {
        let order_id = record.order_event_id.as_deref().ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive has no Order reference",
            )
        })?;
        let scope = self.scope_for_intent(order_id)?;
        let order = self.bindings.get(&scope).ok_or_else(|| {
            error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive references an unknown Order",
            )
        })?;
        if record.ack_event_id.as_deref() != Some(order.acknowledgment.id.as_str()) {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive does not reference the original Order acknowledgment",
            ));
        }
        if let Some(last_known) = record.last_known_event_id.as_deref()
            && !order.outcomes.iter().any(|event| event.id == last_known)
        {
            return Err(error(
                ProviderHardeningErrorCode::InvalidIntent,
                "re-drive last-known event is not a durable Order outcome",
            ));
        }
        Ok(())
    }

    fn scope_for_intent(&self, event_id: &str) -> Result<String, ProviderHardeningError> {
        self.bindings
            .iter()
            .find(|(_, binding)| binding.intent.id == event_id)
            .map(|(scope, _)| scope.clone())
            .ok_or_else(|| {
                error(
                    ProviderHardeningErrorCode::InvalidIntent,
                    "intent event id is not present in the durable journal",
                )
            })
    }
}

fn receipt_signing_request(
    provider_pubkey: &str,
    intent: &Event,
    session_id: &str,
    receipt: &MktSettlementReceipt,
    created_at: u64,
) -> Result<SettlementReceiptSigningRequest, ProviderHardeningError> {
    let mut tags = vec![
        pair("d", &receipt.receipt_id),
        pair("session", session_id),
        Tag::new(vec![
            "profile".to_owned(),
            MKT_SWP_PROFILE_ID.to_owned(),
            MKT_SWP_PROFILE_VERSION.to_string(),
        ]),
        Tag::new(vec![
            "p".to_owned(),
            intent.pubkey.clone(),
            String::new(),
            "requester".to_owned(),
        ]),
        pair("alt", "MKT-SWP Settlement Receipt"),
        event_reference(&receipt.intent_event_id, "intent"),
        event_reference(&receipt.acknowledgment_event_id, "ack"),
        event_reference(&receipt.quote_event_id, "quote"),
        event_reference(&receipt.outcome_event_id, "outcome"),
    ];
    if let Some(client_confirmation) = receipt.client_confirmation_event_id.as_deref() {
        tags.push(event_reference(client_confirmation, "client-confirmation"));
    }
    tags.extend([
        pair("outcome", &receipt.outcome),
        pair("receipt", &MKT_RECEIPT_VERSION.to_string()),
    ]);
    let content = canonical_mkt_receipt_content(session_id, receipt).map_err(|detail| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("could not canonicalize receipt: {detail}"),
        )
    })?;
    let unsigned = Event {
        id: String::new(),
        pubkey: provider_pubkey.to_owned(),
        created_at,
        kind: MKT_SWP_SETTLEMENT_RECEIPT_KIND,
        tags: tags.clone(),
        content: content.clone(),
        sig: String::new(),
    };
    let expected_event_id = unsigned.computed_id().map_err(|detail| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("could not compute receipt event id: {detail}"),
        )
    })?;
    Ok(SettlementReceiptSigningRequest {
        pubkey: provider_pubkey.to_owned(),
        created_at,
        kind: MKT_SWP_SETTLEMENT_RECEIPT_KIND,
        tags,
        content,
        expected_event_id,
    })
}

fn acknowledgment_request(
    provider_pubkey: &str,
    intent: &Event,
    record: &MktHardeningRecord,
    observed_at: u64,
) -> Result<IntentAckSigningRequest, ProviderHardeningError> {
    let outcome_deadline = record.outcome_deadline_seconds.ok_or_else(|| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            "intent has no outcome deadline",
        )
    })?;
    let expiration = observed_at.saturating_add(outcome_deadline);
    let distinct = digest_hex(format!("mkt-v2-ack:{provider_pubkey}:{}", intent.id).as_bytes());
    let tags = vec![
        pair("d", &distinct),
        pair("session", hardening_envelope(intent)?.session_id.as_str()),
        Tag::new(vec![
            "profile".to_owned(),
            MKT_SWP_PROFILE_ID.to_owned(),
            MKT_SWP_PROFILE_VERSION.to_string(),
        ]),
        Tag::new(vec![
            "p".to_owned(),
            intent.pubkey.clone(),
            String::new(),
            "requester".to_owned(),
        ]),
        pair("alt", "MKT-SWP Intent Acknowledgment"),
        Tag::new(vec![
            "e".to_owned(),
            intent.id.clone(),
            String::new(),
            "intent".to_owned(),
        ]),
        pair("ack", "accepted"),
        pair("response", &record.response_pubkey),
        pair("expiration", &expiration.to_string()),
    ];
    let content = serde_json::to_string(&json!({
        "schema": MKT_HARDENING_SCHEMA,
        "protocol_rev": MKT_HARDENING_PROTOCOL_REVISION,
        "profile": MKT_SWP_PROFILE_ID,
        "profile_version": MKT_SWP_PROFILE_VERSION,
        "session_id": hardening_envelope(intent)?.session_id,
        "ack": {
            "intent_event_id": intent.id,
            "idempotency_key": record.idempotency_key,
            "disposition": "accepted",
            "accepted_at": observed_at,
            "error_code": Value::Null,
        }
    }))
    .map_err(|detail| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("could not serialize acknowledgment: {detail}"),
        )
    })?;
    let unsigned = Event {
        id: String::new(),
        pubkey: provider_pubkey.to_owned(),
        created_at: observed_at,
        kind: MKT_SWP_INTENT_ACK_KIND,
        tags: tags.clone(),
        content: content.clone(),
        sig: String::new(),
    };
    let expected_event_id = unsigned.computed_id().map_err(|detail| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("could not compute acknowledgment event id: {detail}"),
        )
    })?;
    Ok(IntentAckSigningRequest {
        pubkey: provider_pubkey.to_owned(),
        created_at: observed_at,
        kind: MKT_SWP_INTENT_ACK_KIND,
        tags,
        content,
        expected_event_id,
    })
}

fn validate_acknowledgment(
    provider_pubkey: &str,
    intent: &Event,
    intent_record: &MktHardeningRecord,
    acknowledgment: &Event,
) -> Result<(), ProviderHardeningError> {
    validate_signed(acknowledgment)?;
    let ack = hardening_record(acknowledgment, None)?;
    if acknowledgment.pubkey != provider_pubkey
        || ack.kind != MktHardeningRecordKind::Acknowledgment
        || ack.intent_event_id.as_deref() != Some(intent.id.as_str())
        || ack.idempotency_key != intent_record.idempotency_key
        || ack.response_pubkey != intent_record.response_pubkey
        || ack.disposition.as_deref() != Some("accepted")
    {
        return Err(error(
            ProviderHardeningErrorCode::InvalidIntent,
            "acknowledgment does not bind the admitted intent",
        ));
    }
    Ok(())
}

fn hardening_envelope(
    event: &Event,
) -> Result<immortal_core::domain::MktPrivateEnvelope, ProviderHardeningError> {
    let support = MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    };
    validate_mkt_private_with_profiles(event, &[support]).map_err(|detail| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("revision-2 record violates NIP-MKT: {detail}"),
        )
    })
}

fn hardening_record(
    event: &Event,
    observed_at: Option<u64>,
) -> Result<MktHardeningRecord, ProviderHardeningError> {
    let envelope = hardening_envelope(event)?;
    validate_mkt_hardening_event(event, &envelope, observed_at).map_err(|detail| {
        let code = match detail.code {
            MktHardeningErrorCode::InvalidIntent => ProviderHardeningErrorCode::InvalidIntent,
            MktHardeningErrorCode::NonceWindow => ProviderHardeningErrorCode::NonceWindow,
            MktHardeningErrorCode::UnsupportedRevision => {
                ProviderHardeningErrorCode::UnsupportedRevision
            }
        };
        error(code, detail.detail)
    })
}

fn validate_signed(event: &Event) -> Result<(), ProviderHardeningError> {
    event
        .validate_structure()
        .and_then(|()| event.validate_crypto())
        .map_err(|detail| {
            error(
                ProviderHardeningErrorCode::Signature,
                format!("signed record is invalid: {detail}"),
            )
        })
}

fn require_provider_recipient(
    event: &Event,
    provider_pubkey: &str,
) -> Result<(), ProviderHardeningError> {
    let matches = event.tags.iter().filter(|tag| {
        let values = tag.as_slice();
        values.first().map(String::as_str) == Some("p")
            && values.get(1).map(String::as_str) == Some(provider_pubkey)
            && values.get(3).map(String::as_str) == Some("provider")
    });
    if matches.count() != 1 {
        return Err(error(
            ProviderHardeningErrorCode::InvalidIntent,
            "intent must name this provider exactly once",
        ));
    }
    Ok(())
}

fn require_reference(
    event: &Event,
    marker: &str,
    expected: &str,
) -> Result<(), ProviderHardeningError> {
    let references = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().get(3).map(String::as_str) == Some(marker));
    let values = references
        .map(|tag| tag.as_slice().get(1).map(String::as_str))
        .collect::<Vec<_>>();
    if values.as_slice() != [Some(expected)] {
        return Err(error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("record does not reference the exact {marker} event"),
        ));
    }
    Ok(())
}

fn required_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, ProviderHardeningError> {
    let tags = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<_>>();
    if tags.len() != 1 || tags[0].as_slice().len() != 2 {
        return Err(error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("record requires exactly one {name} tag"),
        ));
    }
    tags[0].value().ok_or_else(|| {
        error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("record {name} tag has no value"),
        )
    })
}

fn lower_hex_32(value: &str, subject: &str) -> Result<(), ProviderHardeningError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            ProviderHardeningErrorCode::InvalidIntent,
            format!("{subject} must be 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

fn pair(name: &str, value: &str) -> Tag {
    Tag::new(vec![name.to_owned(), value.to_owned()])
}

fn event_reference(event_id: &str, marker: &str) -> Tag {
    Tag::new(vec![
        "e".to_owned(),
        event_id.to_owned(),
        String::new(),
        marker.to_owned(),
    ])
}

fn scope_key(requester_pubkey: &str, idempotency_key: &str) -> String {
    format!("{requester_pubkey}:{MKT_SWP_PROFILE_ID}:{idempotency_key}")
}

fn nonce_key(requester_pubkey: &str, nonce: &str) -> String {
    format!("{requester_pubkey}:{nonce}")
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn error(code: ProviderHardeningErrorCode, detail: impl Into<String>) -> ProviderHardeningError {
    ProviderHardeningError {
        code,
        detail: detail.into(),
    }
}
