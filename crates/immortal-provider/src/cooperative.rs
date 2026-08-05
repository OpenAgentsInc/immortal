//! Signed MKT-SWP provider-side cooperative settlement actor.

use std::{collections::BTreeMap, error::Error, fmt};

use immortal_client::mkt_swp_client::{
    CooperativeSigningAction, CooperativeSigningContext, CooperativeSigningMessage, ExitPackage,
    MktSigningRequest, ParticipantRole, StatusState, SwapClientError,
    provider_support::cooperative_signing_message,
};
use immortal_core::{
    domain::{Event, MKT_STATUS_KIND},
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, musig2_taproot_tweak,
        taproot_key_spend_sighash,
    },
};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};

use crate::{
    ProviderSession,
    settlement::{
        CooperativeSettlementTemplate, CooperativeSigningRound, SettlementBridge, SettlementError,
        SignedSettlementTransaction,
    },
};

const DISTINCT_DOMAIN: &[u8] = b"openagents.mkt-swp.cooperative-status.v1";

#[derive(Debug)]
pub enum CooperativeActorError {
    Protocol(SwapClientError),
    Settlement(SettlementError),
    State(&'static str),
}

impl fmt::Display for CooperativeActorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Settlement(error) => error.fmt(formatter),
            Self::State(detail) => formatter.write_str(detail),
        }
    }
}

impl Error for CooperativeActorError {}

impl From<SwapClientError> for CooperativeActorError {
    fn from(error: SwapClientError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SettlementError> for CooperativeActorError {
    fn from(error: SettlementError) -> Self {
        Self::Settlement(error)
    }
}

pub struct ProviderCooperativeActor {
    context: CooperativeSigningContext,
    context_sha256: String,
    round: Option<CooperativeSigningRound>,
    requester_commitment: Option<[u8; 32]>,
    requester_public_nonce: Option<[u8; 66]>,
    provider_public_nonce: Option<[u8; 66]>,
    requester_partial_signature: Option<[u8; 32]>,
    provider_partial_signature: Option<[u8; 32]>,
    requests: BTreeMap<&'static str, MktSigningRequest>,
    finalized: Option<SignedSettlementTransaction>,
}

impl fmt::Debug for ProviderCooperativeActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCooperativeActor")
            .field("context_sha256", &self.context_sha256)
            .field("has_round", &self.round.is_some())
            .field("requester_commitment", &self.requester_commitment)
            .field(
                "requester_public_nonce",
                &self.requester_public_nonce.is_some(),
            )
            .field(
                "provider_public_nonce",
                &self.provider_public_nonce.is_some(),
            )
            .field(
                "requester_partial_signature",
                &self.requester_partial_signature.is_some(),
            )
            .field(
                "provider_partial_signature",
                &self.provider_partial_signature.is_some(),
            )
            .field("finalized", &self.finalized.is_some())
            .field("secret_nonce", &"[REDACTED]")
            .finish()
    }
}

impl ProviderCooperativeActor {
    pub fn begin(
        session: &ProviderSession,
        package: &ExitPackage,
        context: CooperativeSigningContext,
        template: &CooperativeSettlementTemplate,
        bridge: &SettlementBridge<'_>,
        current_height: u32,
    ) -> Result<Self, CooperativeActorError> {
        session.validate_provider_cooperative_context(&context, package)?;
        validate_template_binding(&context, package, template)?;
        let context_sha256 = context.sha256()?;
        let round = bridge.begin_cooperative(template, current_height)?;
        if lower_hex(&round.signature_hash()) != context.signature_hash
            || lower_hex(&round.aggregate_key()) != context.aggregate_key
            || lower_hex(&round.unsigned_transaction()?) != context.unsigned_transaction
        {
            return Err(CooperativeActorError::State(
                "cooperative settlement round differs from the validated context",
            ));
        }
        Ok(Self {
            context,
            context_sha256,
            round: Some(round),
            requester_commitment: None,
            requester_public_nonce: None,
            provider_public_nonce: None,
            requester_partial_signature: None,
            provider_partial_signature: None,
            requests: BTreeMap::new(),
            finalized: None,
        })
    }

    pub fn nonce_commitment_status(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        if let Some(request) = self
            .requests
            .get(action_token(CooperativeSigningAction::NonceCommitment))
        {
            return Ok(request.clone());
        }
        let commitment = self
            .round
            .as_ref()
            .ok_or(CooperativeActorError::State(
                "cooperative actor is terminal",
            ))?
            .nonce_commitment();
        let message = CooperativeSigningMessage::nonce_commitment(
            self.context.clone(),
            ParticipantRole::Provider,
            commitment,
        )?;
        self.status_request(session, created_at, message)
    }

    pub fn observe_requester_commitment(
        &mut self,
        session: &ProviderSession,
        event: &Event,
        current_height: u32,
    ) -> Result<(), CooperativeActorError> {
        self.require_provider_action(session, CooperativeSigningAction::NonceCommitment)?;
        let message =
            self.requester_message(session, event, CooperativeSigningAction::NonceCommitment)?;
        let commitment = decode_fixed::<32>(message.nonce_commitment.as_deref().ok_or(
            CooperativeActorError::State("requester commitment Status has no commitment"),
        )?)?;
        match self.requester_commitment {
            Some(existing) if existing == commitment => return Ok(()),
            Some(_) => {
                return Err(CooperativeActorError::State(
                    "requester changed its nonce commitment",
                ));
            }
            None => {}
        }
        self.round
            .as_mut()
            .ok_or(CooperativeActorError::State(
                "cooperative actor is terminal",
            ))?
            .register_counterparty_nonce_commitment(commitment, current_height)?;
        self.requester_commitment = Some(commitment);
        Ok(())
    }

    pub fn public_nonce_status(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        current_height: u32,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        if let Some(request) = self
            .requests
            .get(action_token(CooperativeSigningAction::PublicNonce))
        {
            return Ok(request.clone());
        }
        self.require_provider_action(session, CooperativeSigningAction::NonceCommitment)?;
        if self.requester_commitment.is_none() {
            return Err(CooperativeActorError::State(
                "requester commitment is not stored",
            ));
        }
        let public_nonce = self
            .round
            .as_mut()
            .ok_or(CooperativeActorError::State(
                "cooperative actor is terminal",
            ))?
            .reveal_public_nonce(current_height)?;
        self.provider_public_nonce = Some(public_nonce);
        let message = CooperativeSigningMessage::public_nonce(
            self.context.clone(),
            ParticipantRole::Provider,
            public_nonce,
        )?;
        self.status_request(session, created_at, message)
    }

    pub fn observe_requester_public_nonce(
        &mut self,
        session: &ProviderSession,
        event: &Event,
    ) -> Result<(), CooperativeActorError> {
        self.require_provider_action(session, CooperativeSigningAction::PublicNonce)?;
        let message =
            self.requester_message(session, event, CooperativeSigningAction::PublicNonce)?;
        let public_nonce = decode_fixed::<66>(message.public_nonce.as_deref().ok_or(
            CooperativeActorError::State("requester public-nonce Status has no nonce"),
        )?)?;
        match self.requester_public_nonce {
            Some(existing) if existing == public_nonce => Ok(()),
            Some(_) => Err(CooperativeActorError::State(
                "requester changed its public nonce",
            )),
            None => {
                self.requester_public_nonce = Some(public_nonce);
                Ok(())
            }
        }
    }

    pub fn partial_signature_status(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        bridge: &SettlementBridge<'_>,
        current_height: u32,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        if let Some(request) = self
            .requests
            .get(action_token(CooperativeSigningAction::PartialSignature))
        {
            return Ok(request.clone());
        }
        self.require_provider_action(session, CooperativeSigningAction::PublicNonce)?;
        self.require_requester_action(session, CooperativeSigningAction::PublicNonce)?;
        let public_nonces = self.public_nonces()?;
        let partial_signature = bridge.sign_cooperative_partial(
            self.round.as_mut().ok_or(CooperativeActorError::State(
                "cooperative actor is terminal",
            ))?,
            current_height,
            &public_nonces,
        )?;
        self.provider_partial_signature = Some(partial_signature);
        let message = CooperativeSigningMessage::partial_signature(
            self.context.clone(),
            ParticipantRole::Provider,
            public_nonces,
            partial_signature,
        )?;
        self.status_request(session, created_at, message)
    }

    pub fn observe_requester_partial_signature(
        &mut self,
        session: &ProviderSession,
        event: &Event,
    ) -> Result<(), CooperativeActorError> {
        self.require_provider_action(session, CooperativeSigningAction::PartialSignature)?;
        let message =
            self.requester_message(session, event, CooperativeSigningAction::PartialSignature)?;
        let partial = decode_fixed::<32>(message.partial_signature.as_deref().ok_or(
            CooperativeActorError::State(
                "requester partial-signature Status has no partial signature",
            ),
        )?)?;
        match self.requester_partial_signature {
            Some(existing) if existing == partial => Ok(()),
            Some(_) => Err(CooperativeActorError::State(
                "requester changed its partial signature",
            )),
            None => {
                self.requester_partial_signature = Some(partial);
                Ok(())
            }
        }
    }

    pub fn final_signature_status(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        bridge: &SettlementBridge<'_>,
        current_height: u32,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        if let Some(request) = self
            .requests
            .get(action_token(CooperativeSigningAction::FinalSignature))
        {
            return Ok(request.clone());
        }
        self.require_provider_action(session, CooperativeSigningAction::PartialSignature)?;
        self.require_requester_action(session, CooperativeSigningAction::PartialSignature)?;
        let public_nonces = self.public_nonces()?;
        let partial_signatures = [
            self.requester_partial_signature
                .ok_or(CooperativeActorError::State(
                    "requester partial signature is not stored",
                ))?,
            self.provider_partial_signature
                .ok_or(CooperativeActorError::State(
                    "provider partial signature is not stored",
                ))?,
        ];
        let round = self.round.take().ok_or(CooperativeActorError::State(
            "cooperative actor is terminal",
        ))?;
        let finalized = bridge.finalize_cooperative(
            round,
            current_height,
            &public_nonces,
            &partial_signatures,
        )?;
        let message = CooperativeSigningMessage::final_signature(
            self.context.clone(),
            ParticipantRole::Provider,
            public_nonces,
            partial_signatures,
        )?;
        let request = self.status_request(session, created_at, message)?;
        self.finalized = Some(finalized);
        Ok(request)
    }

    pub fn take_finalized_after_signed_status(
        &mut self,
        session: &ProviderSession,
        event: &Event,
    ) -> Result<SignedSettlementTransaction, CooperativeActorError> {
        self.provider_message(session, event, CooperativeSigningAction::FinalSignature)?;
        self.finalized.take().ok_or(CooperativeActorError::State(
            "cooperative transaction is unavailable or was already released",
        ))
    }

    pub fn observe_requester_abort(
        &mut self,
        session: &ProviderSession,
        event: &Event,
    ) -> Result<(), CooperativeActorError> {
        self.requester_message(session, event, CooperativeSigningAction::Aborted)?;
        if let Some(round) = self.round.as_mut() {
            round.abort();
        }
        self.round = None;
        self.finalized = None;
        Ok(())
    }

    pub fn abort_status(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        reason: &'static str,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        if let Some(request) = self
            .requests
            .get(action_token(CooperativeSigningAction::Aborted))
        {
            return Ok(request.clone());
        }
        if let Some(round) = self.round.as_mut() {
            round.abort();
        }
        self.round = None;
        self.finalized = None;
        let message = CooperativeSigningMessage::aborted(
            self.context.clone(),
            ParticipantRole::Provider,
            reason,
        )?;
        self.status_request(session, created_at, message)
    }

    pub fn restart_abort_status(
        session: &ProviderSession,
        package: &ExitPackage,
        context: CooperativeSigningContext,
        created_at: u64,
        reason: &'static str,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        session.validate_provider_cooperative_context(&context, package)?;
        let message =
            CooperativeSigningMessage::aborted(context.clone(), ParticipantRole::Provider, reason)?;
        cooperative_status_request(session, created_at, &context, message)
    }

    fn status_request(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        message: CooperativeSigningMessage,
    ) -> Result<MktSigningRequest, CooperativeActorError> {
        let action = message.action;
        let request = cooperative_status_request(session, created_at, &self.context, message)?;
        self.requests.insert(action_token(action), request.clone());
        Ok(request)
    }

    fn requester_message(
        &self,
        session: &ProviderSession,
        event: &Event,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        self.stored_message(session, event, ParticipantRole::Requester, action)
    }

    fn provider_message(
        &self,
        session: &ProviderSession,
        event: &Event,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        let request =
            self.requests
                .get(action_token(action))
                .ok_or(CooperativeActorError::State(
                    "provider actor has no signing request for this action",
                ))?;
        request.verify_signed(event.clone())?;
        self.stored_message(session, event, ParticipantRole::Provider, action)
    }

    fn stored_message(
        &self,
        session: &ProviderSession,
        event: &Event,
        role: ParticipantRole,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        let stored = session
            .signed_records()
            .iter()
            .find(|stored| stored.id == event.id)
            .ok_or(CooperativeActorError::State(
                "cooperative Status is not stored in the provider session",
            ))?;
        if stored != event {
            return Err(CooperativeActorError::State(
                "cooperative Status differs from the exact stored event bytes",
            ));
        }
        if stored.kind != MKT_STATUS_KIND || stored.pubkey != participant_pubkey(session, role) {
            return Err(CooperativeActorError::State(
                "cooperative Status signer or kind is invalid",
            ));
        }
        let message = cooperative_signing_message(stored, role)?.ok_or(
            CooperativeActorError::State("stored Status has no cooperative signing message"),
        )?;
        if message.context != self.context
            || message.context_sha256 != self.context_sha256
            || message.action != action
        {
            return Err(CooperativeActorError::State(
                "stored Status does not match the actor context and action",
            ));
        }
        Ok(message)
    }

    fn require_provider_action(
        &self,
        session: &ProviderSession,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        let request =
            self.requests
                .get(action_token(action))
                .ok_or(CooperativeActorError::State(
                    "provider actor has no signing request for this action",
                ))?;
        let event = session
            .signed_records()
            .iter()
            .find(|event| event.id == request.expected_event_id)
            .ok_or(CooperativeActorError::State(
                "provider actor Status is not stored",
            ))?;
        request.verify_signed(event.clone())?;
        self.stored_message(session, event, ParticipantRole::Provider, action)
    }

    fn require_requester_action(
        &self,
        session: &ProviderSession,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        self.require_stored_action(session, ParticipantRole::Requester, action)
    }

    fn require_stored_action(
        &self,
        session: &ProviderSession,
        role: ParticipantRole,
        action: CooperativeSigningAction,
    ) -> Result<CooperativeSigningMessage, CooperativeActorError> {
        let matches = session.signed_records().iter().filter_map(|event| {
            if event.kind != MKT_STATUS_KIND || event.pubkey != participant_pubkey(session, role) {
                return None;
            }
            cooperative_signing_message(event, role)
                .transpose()
                .map(|result| result.map(|message| (event, message)))
        });
        let mut found = None;
        for result in matches {
            let (_, message) = result?;
            if message.context_sha256 == self.context_sha256 && message.action == action {
                if found.is_some() {
                    return Err(CooperativeActorError::State(
                        "cooperative transcript contains duplicate participant action",
                    ));
                }
                found = Some(message);
            }
        }
        found.ok_or(CooperativeActorError::State(
            "required cooperative Status is not stored",
        ))
    }

    fn public_nonces(&self) -> Result<[[u8; 66]; 2], CooperativeActorError> {
        Ok([
            self.requester_public_nonce
                .ok_or(CooperativeActorError::State(
                    "requester public nonce is not stored",
                ))?,
            self.provider_public_nonce
                .ok_or(CooperativeActorError::State(
                    "provider public nonce is not stored",
                ))?,
        ])
    }
}

fn cooperative_status_request(
    session: &ProviderSession,
    created_at: u64,
    context: &CooperativeSigningContext,
    message: CooperativeSigningMessage,
) -> Result<MktSigningRequest, CooperativeActorError> {
    let (sequence, previous) = next_provider_status(session)?;
    let distinct = cooperative_distinct(&context.sha256()?, message.action)?;
    session
        .provider_cooperative_status(
            created_at,
            &distinct,
            StatusState {
                sequence,
                previous: previous.as_deref(),
                base_state: "executing",
                swp_state: "cooperative_signing_pending",
            },
            message,
        )
        .map_err(Into::into)
}

fn next_provider_status(
    session: &ProviderSession,
) -> Result<(u64, Option<String>), CooperativeActorError> {
    let projection = session.status_projection()?;
    let Some(previous) = projection
        .last_valid_status
        .get(&session.config().provider_pubkey)
        .cloned()
    else {
        return Ok((0, None));
    };
    let event = session
        .signed_records()
        .iter()
        .find(|event| event.id == previous)
        .ok_or(CooperativeActorError::State(
            "provider status projection points outside stored history",
        ))?;
    let sequence = event
        .tags
        .iter()
        .find(|tag| tag.name() == Some("seq"))
        .and_then(|tag| tag.as_slice().get(1))
        .ok_or(CooperativeActorError::State(
            "provider status has no sequence tag",
        ))?
        .parse::<u64>()
        .map_err(|_| CooperativeActorError::State("provider status sequence is invalid"))?
        .checked_add(1)
        .ok_or(CooperativeActorError::State(
            "provider status sequence overflowed",
        ))?;
    Ok((sequence, Some(previous)))
}

fn validate_template_binding(
    context: &CooperativeSigningContext,
    package: &ExitPackage,
    template: &CooperativeSettlementTemplate,
) -> Result<(), CooperativeActorError> {
    let context_sha256 = decode_fixed::<32>(&context.sha256()?)?;
    let latest_safe_height = context
        .latest_safe_height
        .parse::<u32>()
        .map_err(|_| CooperativeActorError::State("cooperative deadline is invalid"))?;
    if template.provider_index != 1
        || template.transcript_digest != context_sha256
        || template.latest_safe_height != latest_safe_height
        || template
            .participant_keys
            .iter()
            .map(|key| lower_hex(key))
            .collect::<Vec<_>>()
            != context.participant_keys
    {
        return Err(CooperativeActorError::State(
            "cooperative settlement template differs from the signed context",
        ));
    }
    let keys = template
        .participant_keys
        .iter()
        .map(|key| PublicKey::from_slice(key))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CooperativeActorError::State("cooperative template key is invalid"))?;
    let tweak =
        musig2_taproot_tweak(&keys, template.taproot_merkle_root).map_err(SettlementError::from)?;
    let [declared_tweak] = context.tweaks.as_slice() else {
        return Err(CooperativeActorError::State(
            "cooperative context does not contain one Taproot tweak",
        ));
    };
    if declared_tweak.value != lower_hex(&tweak.value) || declared_tweak.xonly != tweak.xonly {
        return Err(CooperativeActorError::State(
            "cooperative template Taproot tree differs from the signed context",
        ));
    }
    let transaction = Transaction::new(
        template.settlement.transaction_version,
        vec![TransactionInput {
            previous_txid: template.settlement.previous_txid_wire,
            previous_output: template.settlement.previous_output,
            script_sig: Vec::new(),
            sequence: template.settlement.input_sequence,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: template.settlement.destination_value_sat,
            script_pubkey: template.settlement.destination_script_pubkey.clone(),
        }],
        template.settlement.lock_time,
    );
    let raw = transaction
        .serialize(false)
        .map_err(SettlementError::from)?;
    let prevouts = [TransactionOutput {
        value_sat: template.settlement.prevout_value_sat,
        script_pubkey: template.settlement.prevout_script_pubkey.clone(),
    }];
    let signature_hash =
        taproot_key_spend_sighash(&transaction, &prevouts, 0).map_err(SettlementError::from)?;
    let [context_prevout] = context.prevouts.as_slice() else {
        return Err(CooperativeActorError::State(
            "cooperative context does not contain one prevout",
        ));
    };
    if context.input_index != 0
        || context.unsigned_transaction != lower_hex(&raw)
        || context.signature_hash != lower_hex(&signature_hash)
        || context_prevout.amount != template.settlement.prevout_value_sat.to_string()
        || context_prevout.script_pubkey != lower_hex(&template.settlement.prevout_script_pubkey)
    {
        return Err(CooperativeActorError::State(
            "cooperative transaction template differs from the signed context",
        ));
    }
    let verification = package
        .document()
        .get("verification")
        .and_then(serde_json::Value::as_object)
        .ok_or(CooperativeActorError::State(
            "provider exit package has no verification object",
        ))?;
    let package_script = verification
        .get("taproot_script")
        .and_then(serde_json::Value::as_str)
        .ok_or(CooperativeActorError::State(
            "provider exit package has no Taproot script",
        ))?;
    let package_control_block = verification
        .get("taproot_control_block")
        .and_then(serde_json::Value::as_str)
        .ok_or(CooperativeActorError::State(
            "provider exit package has no Taproot control block",
        ))?;
    if decode_hex(package_script)? != template.settlement.taproot_script
        || decode_hex(package_control_block)? != template.settlement.taproot_control_block
    {
        return Err(CooperativeActorError::State(
            "provider exit package differs from the verified unilateral settlement path",
        ));
    }
    Ok(())
}

fn cooperative_distinct(
    context_sha256: &str,
    action: CooperativeSigningAction,
) -> Result<String, CooperativeActorError> {
    let context = decode_fixed::<32>(context_sha256)?;
    let action = action_token(action);
    let mut hasher = Sha256::new();
    hasher.update(DISTINCT_DOMAIN);
    hasher.update([0]);
    hasher.update(context);
    hasher.update([0]);
    hasher.update(action.as_bytes());
    Ok(lower_hex(&hasher.finalize()))
}

fn action_token(action: CooperativeSigningAction) -> &'static str {
    match action {
        CooperativeSigningAction::NonceCommitment => "nonce_commitment",
        CooperativeSigningAction::PublicNonce => "public_nonce",
        CooperativeSigningAction::PartialSignature => "partial_signature",
        CooperativeSigningAction::FinalSignature => "final_signature",
        CooperativeSigningAction::Aborted => "aborted",
    }
}

fn participant_pubkey(session: &ProviderSession, role: ParticipantRole) -> &str {
    match role {
        ParticipantRole::Requester => &session.config().requester_pubkey,
        ParticipantRole::Provider => &session.config().provider_pubkey,
    }
}

fn decode_fixed<const SIZE: usize>(value: &str) -> Result<[u8; SIZE], CooperativeActorError> {
    if value.len() != SIZE.saturating_mul(2)
        || value
            .as_bytes()
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CooperativeActorError::State(
            "cooperative transcript hex is not canonical",
        ));
    }
    let mut decoded = [0_u8; SIZE];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]);
        let low = decode_nibble(pair[1]);
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CooperativeActorError> {
    if value.len() % 2 != 0
        || value
            .as_bytes()
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CooperativeActorError::State(
            "provider exit package hex is not canonical",
        ));
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]))
        .collect())
}

fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use immortal_client::mkt_swp_client::{CooperativePrevout, CooperativeTweak};
    use immortal_core::{
        market::MarketSigner,
        mkt_swp_verify::{
            musig2_aggregate_key, musig2_nonce_gen, musig2_partial_sign,
            musig2_tweaked_aggregate_key, sha256, tapbranch_hash, tapleaf_hash, taproot_output_key,
        },
    };
    use secp256k1::{Parity, Secp256k1, SecretKey, XOnlyPublicKey};
    #[cfg(unix)]
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::OpenOptionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use crate::{
        settlement::SettlementTemplate,
        wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
    };

    use super::*;

    #[test]
    fn distinct_ids_use_stable_wire_tokens() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/swp-cooperative-signing-v1.json"
        ))
        .expect("cooperative fixture");
        assert_eq!(
            fixture["signed_actor"]["distinct_domain"],
            "openagents.mkt-swp.cooperative-status.v1"
        );
        let digest = "11".repeat(32);
        let cases = [
            (
                CooperativeSigningAction::NonceCommitment,
                "22aaff26e24402ce41c8749584cdf6d2be7bc8c4eb65d63b98e630a61db68fd9",
            ),
            (
                CooperativeSigningAction::PublicNonce,
                "37c748f1dc734a6d7509b48efdb4b7392a716bdd858d72ec66d265c849f3060e",
            ),
            (
                CooperativeSigningAction::PartialSignature,
                "ee6dc2b5afa8c2daea3430cff76fa1f749dd712e051632e29a5e1a560e25bb5e",
            ),
            (
                CooperativeSigningAction::FinalSignature,
                "b0459085daa86d0d5df980a4779c98486af1c3aebbecf334709c3b69f00b8431",
            ),
            (
                CooperativeSigningAction::Aborted,
                "29ca07a7c10aa8c3830f831fb6c0429fc63d56c2ab3c25d91a1a3041d4389d2e",
            ),
        ];
        for (action, expected) in cases {
            assert_eq!(
                cooperative_distinct(&digest, action).expect("stable distinct ID"),
                expected
            );
        }
    }

    #[test]
    fn actor_accepts_only_the_exact_stored_signed_status() {
        let mut setup = crate::session::fixture_replay::cooperative_actor_setup()
            .expect("cooperative actor session");
        let context = test_context(&setup.order.id);
        let message = CooperativeSigningMessage::nonce_commitment(
            context.clone(),
            ParticipantRole::Requester,
            [9; 32],
        )
        .expect("requester commitment");
        let request = setup
            .factory
            .cooperative_status(
                ParticipantRole::Requester,
                105,
                &"71".repeat(32),
                &setup.order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "executing",
                    swp_state: "cooperative_signing_pending",
                },
                message,
            )
            .expect("requester cooperative Status");
        let requester_signed = signed(request, &setup.requester);
        setup
            .session
            .ingest_signed(requester_signed.clone())
            .expect("stored requester Status");
        let mut actor = ProviderCooperativeActor {
            context_sha256: context.sha256().expect("context digest"),
            context,
            round: None,
            requester_commitment: None,
            requester_public_nonce: None,
            provider_public_nonce: None,
            requester_partial_signature: None,
            provider_partial_signature: None,
            requests: BTreeMap::new(),
            finalized: None,
        };
        actor
            .requester_message(
                &setup.session,
                &requester_signed,
                CooperativeSigningAction::NonceCommitment,
            )
            .expect("exact stored Status");

        let mut changed = requester_signed;
        changed.content.push(' ');
        assert!(matches!(
            actor.requester_message(
                &setup.session,
                &changed,
                CooperativeSigningAction::NonceCommitment,
            ),
            Err(CooperativeActorError::State(
                "cooperative Status differs from the exact stored event bytes"
            ))
        ));

        let provider_message = CooperativeSigningMessage::nonce_commitment(
            actor.context.clone(),
            ParticipantRole::Provider,
            [10; 32],
        )
        .expect("provider commitment");
        let provider_request = setup
            .factory
            .cooperative_status(
                ParticipantRole::Provider,
                106,
                &"72".repeat(32),
                &setup.order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "executing",
                    swp_state: "cooperative_signing_pending",
                },
                provider_message,
            )
            .expect("provider cooperative Status");
        let provider_signed = signed(provider_request.clone(), &setup.provider);
        setup
            .session
            .ingest_signed(provider_signed.clone())
            .expect("stored provider Status");
        actor.requests.insert(
            action_token(CooperativeSigningAction::NonceCommitment),
            provider_request,
        );
        actor
            .require_provider_action(&setup.session, CooperativeSigningAction::NonceCommitment)
            .expect("actor-authored provider Status");

        let mut changed_provider = provider_signed;
        changed_provider.content.push(' ');
        assert!(
            actor
                .provider_message(
                    &setup.session,
                    &changed_provider,
                    CooperativeSigningAction::NonceCommitment,
                )
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn signed_actor_completes_only_after_each_exact_status_is_stored() -> Result<(), Box<dyn Error>>
    {
        let mut setup = crate::session::fixture_replay::cooperative_actor_setup()?;
        let wallet = test_wallet()?;
        let provider_path = WalletPath::new(0, false, 7)?;
        let provider_key = wallet.derive_address(provider_path)?.internal_key;
        let (requester_secret, requester_key) = even_secret([7; 32])?;
        let participant_keys = [requester_key.serialize(), compressed_even(provider_key)];
        let keys = participant_keys
            .iter()
            .map(|key| PublicKey::from_slice(key))
            .collect::<Result<Vec<_>, _>>()?;
        let preimage = [8; 32];
        let requester_script =
            claim_script(preimage, requester_key.x_only_public_key().0.serialize());
        let provider_script = claim_script(preimage, provider_key);
        let requester_leaf = tapleaf_hash(0xc0, &requester_script)?;
        let provider_leaf = tapleaf_hash(0xc0, &provider_script)?;
        let merkle_root = tapbranch_hash(requester_leaf, provider_leaf);
        let internal_key = musig2_aggregate_key(&keys)?;
        let (output_key, output_parity) = taproot_output_key(internal_key, Some(merkle_root))?;
        let tweak = musig2_taproot_tweak(&keys, merkle_root)?;
        let aggregate_key = musig2_tweaked_aggregate_key(&keys, &[tweak])?;
        assert_eq!(aggregate_key, output_key);
        let prevout_script_pubkey =
            [&[0x51, 0x20][..], aggregate_key.serialize().as_slice()].concat();
        let settlement = SettlementTemplate {
            wallet_path: provider_path,
            previous_txid_wire: [4; 32],
            previous_output: 0,
            prevout_value_sat: 100_000,
            prevout_script_pubkey: prevout_script_pubkey.clone(),
            destination_value_sat: 99_000,
            destination_script_pubkey: [
                &[0x51, 0x20][..],
                XOnlyPublicKey::from_keypair(&secp256k1::Keypair::from_secret_key(
                    &Secp256k1::new(),
                    &requester_secret,
                ))
                .0
                .serialize()
                .as_slice(),
            ]
            .concat(),
            transaction_version: 2,
            input_sequence: u32::MAX - 1,
            lock_time: 0,
            taproot_script: provider_script,
            taproot_control_block: control_block(output_parity, internal_key, requester_leaf),
            maximum_fee_sat: 1_000,
            maximum_fee_rate_sat_per_vbyte: 20,
            maximum_weight: 1_600,
            dust_relay_fee_sat_per_kilobyte: 3_000,
        };
        let transaction = Transaction::new(
            settlement.transaction_version,
            vec![TransactionInput {
                previous_txid: settlement.previous_txid_wire,
                previous_output: settlement.previous_output,
                script_sig: Vec::new(),
                sequence: settlement.input_sequence,
                witness: Vec::new(),
            }],
            vec![TransactionOutput {
                value_sat: settlement.destination_value_sat,
                script_pubkey: settlement.destination_script_pubkey.clone(),
            }],
            settlement.lock_time,
        );
        let raw = transaction.serialize(false)?;
        let signature_hash = taproot_key_spend_sighash(
            &transaction,
            &[TransactionOutput {
                value_sat: settlement.prevout_value_sat,
                script_pubkey: settlement.prevout_script_pubkey.clone(),
            }],
            0,
        )?;
        let context = CooperativeSigningContext {
            schema: "openagents.mkt-swp.cooperative-signing.v1".into(),
            order_id: setup.order.id.clone(),
            swap_contract_sha256: "22".repeat(32),
            effect_id: test_effect_id(&setup.order.id, "source"),
            leg_id: "source".into(),
            unsigned_transaction: lower_hex(&raw),
            transaction_sha256: lower_hex(&sha256(&raw)),
            input_index: 0,
            prevouts: vec![CooperativePrevout {
                amount: settlement.prevout_value_sat.to_string(),
                script_pubkey: lower_hex(&settlement.prevout_script_pubkey),
            }],
            signature_hash: lower_hex(&signature_hash),
            sighash_type: "DEFAULT".into(),
            participant_keys: participant_keys.iter().map(|key| lower_hex(key)).collect(),
            tweaks: vec![CooperativeTweak {
                value: lower_hex(&tweak.value),
                xonly: tweak.xonly,
            }],
            aggregate_key: lower_hex(&aggregate_key.serialize()),
            exit_package_sha256: "33".repeat(32),
            latest_safe_height: "200".into(),
        };
        let transcript_digest = decode_fixed::<32>(&context.sha256()?)?;
        let template = CooperativeSettlementTemplate {
            settlement,
            participant_keys,
            provider_index: 1,
            taproot_merkle_root: merkle_root,
            transcript_digest,
            latest_safe_height: 200,
        };
        let bridge = SettlementBridge::new(&wallet);
        let round = bridge.begin_cooperative(&template, 150)?;
        let mut actor = ProviderCooperativeActor {
            context_sha256: context.sha256()?,
            context: context.clone(),
            round: Some(round),
            requester_commitment: None,
            requester_public_nonce: None,
            provider_public_nonce: None,
            requester_partial_signature: None,
            provider_partial_signature: None,
            requests: BTreeMap::new(),
            finalized: None,
        };
        let mut requester_nonce = musig2_nonce_gen(
            &requester_secret,
            &aggregate_key.serialize(),
            &signature_hash,
            &transcript_digest,
            [9; 32],
        )?;
        let requester_public_nonce = requester_nonce.public_nonce();

        let provider_commitment_request = actor.nonce_commitment_status(&setup.session, 105)?;
        let provider_commitment = signed(provider_commitment_request, &setup.provider);
        setup.session.ingest_signed(provider_commitment)?;

        let requester_commitment = requester_status(
            &setup,
            105,
            0,
            None,
            "81",
            CooperativeSigningMessage::nonce_commitment(
                context.clone(),
                ParticipantRole::Requester,
                sha256(&requester_public_nonce),
            )?,
        );
        setup.session.ingest_signed(requester_commitment.clone())?;
        actor.observe_requester_commitment(&setup.session, &requester_commitment, 150)?;

        let provider_nonce_request = actor.public_nonce_status(&setup.session, 106, 150)?;
        let provider_nonce = signed(provider_nonce_request, &setup.provider);
        setup.session.ingest_signed(provider_nonce)?;
        let requester_nonce_event = requester_status(
            &setup,
            106,
            1,
            Some(&requester_commitment.id),
            "82",
            CooperativeSigningMessage::public_nonce(
                context.clone(),
                ParticipantRole::Requester,
                requester_public_nonce,
            )?,
        );
        setup.session.ingest_signed(requester_nonce_event.clone())?;
        actor.observe_requester_public_nonce(&setup.session, &requester_nonce_event)?;

        let provider_partial_request =
            actor.partial_signature_status(&setup.session, 107, &bridge, 150)?;
        let provider_partial = signed(provider_partial_request, &setup.provider);
        setup.session.ingest_signed(provider_partial)?;
        let public_nonces = [
            requester_public_nonce,
            actor
                .provider_public_nonce
                .ok_or("provider public nonce is missing")?,
        ];
        let requester_partial = musig2_partial_sign(
            &mut requester_nonce,
            &requester_secret,
            &keys,
            &public_nonces,
            &[tweak],
            &signature_hash,
        )?;
        let requester_partial_event = requester_status(
            &setup,
            107,
            2,
            Some(&requester_nonce_event.id),
            "83",
            CooperativeSigningMessage::partial_signature(
                context,
                ParticipantRole::Requester,
                public_nonces,
                requester_partial,
            )?,
        );
        setup
            .session
            .ingest_signed(requester_partial_event.clone())?;
        actor.observe_requester_partial_signature(&setup.session, &requester_partial_event)?;

        let final_request = actor.final_signature_status(&setup.session, 108, &bridge, 150)?;
        assert!(actor.finalized.is_some());
        let final_event = signed(final_request, &setup.provider);
        assert!(
            actor
                .take_finalized_after_signed_status(&setup.session, &final_event)
                .is_err()
        );
        setup.session.ingest_signed(final_event.clone())?;
        let finalized = actor.take_finalized_after_signed_status(&setup.session, &final_event)?;
        let transaction = Transaction::parse(finalized.broadcast_bytes())?;
        assert_eq!(
            transaction
                .inputs
                .first()
                .ok_or("final transaction has no input")?
                .witness
                .len(),
            1
        );
        Ok(())
    }

    fn test_context(order_id: &str) -> CooperativeSigningContext {
        let secp = Secp256k1::new();
        let keys = [[1; 32], [2; 32]]
            .map(|secret| {
                let secret = SecretKey::from_byte_array(secret).expect("test secret");
                secret.public_key(&secp)
            })
            .to_vec();
        let tweak = musig2_taproot_tweak(&keys, [3; 32]).expect("Taproot tweak");
        let aggregate = musig2_tweaked_aggregate_key(&keys, &[tweak]).expect("aggregate key");
        let script_pubkey = [&[0x51, 0x20][..], aggregate.serialize().as_slice()].concat();
        let transaction = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [4; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX - 1,
                witness: Vec::new(),
            }],
            vec![TransactionOutput {
                value_sat: 99_000,
                script_pubkey: vec![0x51],
            }],
            0,
        );
        let prevouts = vec![TransactionOutput {
            value_sat: 100_000,
            script_pubkey: script_pubkey.clone(),
        }];
        let raw = transaction.serialize(false).expect("unsigned transaction");
        let signature_hash =
            taproot_key_spend_sighash(&transaction, &prevouts, 0).expect("signature hash");
        CooperativeSigningContext {
            schema: "openagents.mkt-swp.cooperative-signing.v1".into(),
            order_id: order_id.into(),
            swap_contract_sha256: "22".repeat(32),
            effect_id: test_effect_id(order_id, "source"),
            leg_id: "source".into(),
            unsigned_transaction: lower_hex(&raw),
            transaction_sha256: lower_hex(&sha256(&raw)),
            input_index: 0,
            prevouts: vec![CooperativePrevout {
                amount: "100000".into(),
                script_pubkey: lower_hex(&script_pubkey),
            }],
            signature_hash: lower_hex(&signature_hash),
            sighash_type: "DEFAULT".into(),
            participant_keys: keys.iter().map(|key| lower_hex(&key.serialize())).collect(),
            tweaks: vec![CooperativeTweak {
                value: lower_hex(&tweak.value),
                xonly: tweak.xonly,
            }],
            aggregate_key: lower_hex(&aggregate.serialize()),
            exit_package_sha256: "33".repeat(32),
            latest_safe_height: "500".into(),
        }
    }

    fn test_effect_id(order_id: &str, leg_id: &str) -> String {
        let order = decode_fixed::<32>(order_id).expect("Order ID");
        let mut preimage = b"openagents.mkt-swp.v1".to_vec();
        preimage.push(0);
        preimage.extend_from_slice(&order);
        preimage.push(0);
        preimage.extend_from_slice(b"cooperative_sign");
        preimage.push(0);
        preimage.extend_from_slice(leg_id.as_bytes());
        lower_hex(&sha256(&preimage))
    }

    fn signed(request: MktSigningRequest, signer: &MarketSigner) -> Event {
        let event = signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request.verify_signed(event).expect("signed request")
    }

    #[cfg(unix)]
    fn requester_status(
        setup: &crate::session::fixture_replay::CooperativeActorSetup,
        created_at: u64,
        sequence: u64,
        previous: Option<&str>,
        distinct_byte: &str,
        message: CooperativeSigningMessage,
    ) -> Event {
        let request = setup
            .factory
            .cooperative_status(
                ParticipantRole::Requester,
                created_at,
                &distinct_byte.repeat(32),
                &setup.order.id,
                StatusState {
                    sequence,
                    previous,
                    base_state: "executing",
                    swp_state: "cooperative_signing_pending",
                },
                message,
            )
            .expect("requester cooperative Status");
        signed(request, &setup.requester)
    }

    #[cfg(unix)]
    fn test_wallet() -> Result<ProviderWallet, Box<dyn Error>> {
        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "immortal-provider-cooperative-{}-{sequence}.seed",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all("2a".repeat(32).as_bytes())?;
        file.sync_all()?;
        drop(file);
        let wallet = ProviderWallet::load(&path, BitcoinNetwork::Regtest);
        fs::remove_file(path)?;
        Ok(wallet?)
    }

    #[cfg(unix)]
    fn even_secret(bytes: [u8; 32]) -> Result<(SecretKey, PublicKey), secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut secret = SecretKey::from_byte_array(bytes)?;
        let mut public = secret.public_key(&secp);
        if public.serialize()[0] == 0x03 {
            secret = secret.negate();
            public = secret.public_key(&secp);
        }
        Ok((secret, public))
    }

    #[cfg(unix)]
    fn compressed_even(key: [u8; 32]) -> [u8; 33] {
        let mut compressed = [0_u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&key);
        compressed
    }

    #[cfg(unix)]
    fn claim_script(preimage: [u8; 32], signing_key: [u8; 32]) -> Vec<u8> {
        let mut script = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
        script.extend_from_slice(&sha256(&preimage));
        script.extend_from_slice(&[0x88, 0x20]);
        script.extend_from_slice(&signing_key);
        script.push(0xac);
        script
    }

    #[cfg(unix)]
    fn control_block(
        output_parity: Parity,
        internal_key: XOnlyPublicKey,
        sibling: [u8; 32],
    ) -> Vec<u8> {
        let parity = if output_parity == Parity::Odd { 1 } else { 0 };
        let mut control = Vec::with_capacity(65);
        control.push(0xc0 | parity);
        control.extend_from_slice(&internal_key.serialize());
        control.extend_from_slice(&sibling);
        control
    }
}
