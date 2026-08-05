//! Provider-owned construction and signing for MKT-SWP script-path settlement.

use crate::wallet::{ProviderWallet, WalletError, WalletMusig2Nonce, WalletPath};
use immortal_core::mkt_swp_verify::{
    Musig2Tweak, ParsedSwapLeaf, SwapLeafCondition, Transaction, TransactionCost, TransactionInput,
    TransactionOutput, VerificationError, assemble_taproot_claim_witness,
    assemble_taproot_refund_witness, is_dust, musig2_aggregate_partial_signatures,
    musig2_taproot_tweak, musig2_tweaked_aggregate_key, parse_swap_leaf_script, sha256,
    taproot_key_spend_sighash, taproot_script_spend_sighash, validate_taproot_claim_witness,
    validate_taproot_refund_witness, validate_transaction_cost, verify_control_block,
    verify_musig2_signature,
};
use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementError {
    Wallet(WalletError),
    Core(VerificationError),
    WrongPath,
    PreimageMismatch,
    SigningKeyMismatch,
    SignatureInvalid,
    DustOutput,
    WeightLimit,
    CooperativeKeyMismatch,
    NonceCommitmentMismatch,
    CooperativeState,
    CooperativeExpired,
}

impl fmt::Display for SettlementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Wallet(_) => "provider wallet operation failed",
            Self::Core(_) => "settlement transaction validation failed",
            Self::WrongPath => "settlement script uses the wrong claim or refund path",
            Self::PreimageMismatch => "claim material does not match the settlement hashlock",
            Self::SigningKeyMismatch => "settlement script does not bind the selected wallet key",
            Self::SignatureInvalid => "settlement signature failed independent verification",
            Self::DustOutput => "settlement destination is below the configured dust threshold",
            Self::WeightLimit => "settlement transaction exceeds the configured weight limit",
            Self::CooperativeKeyMismatch => {
                "cooperative settlement does not bind the provider wallet and Taproot output"
            }
            Self::NonceCommitmentMismatch => {
                "cooperative public nonce does not match its prior commitment"
            }
            Self::CooperativeState => "cooperative signing round is not in the required state",
            Self::CooperativeExpired => "cooperative signing round exceeded its safe height",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SettlementError {}

impl From<WalletError> for SettlementError {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

impl From<VerificationError> for SettlementError {
    fn from(error: VerificationError) -> Self {
        Self::Core(error)
    }
}

pub struct ClaimPreimage([u8; 32]);

impl ClaimPreimage {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn payment_hash(&self) -> [u8; 32] {
        sha256(&self.0)
    }

    fn expose(&self) -> [u8; 32] {
        self.0
    }
}

impl From<crate::cln::ReleasedPaymentPreimage> for ClaimPreimage {
    fn from(preimage: crate::cln::ReleasedPaymentPreimage) -> Self {
        Self::new(preimage.into_bytes())
    }
}

impl From<crate::lightning::LightningPaymentPreimage> for ClaimPreimage {
    fn from(preimage: crate::lightning::LightningPaymentPreimage) -> Self {
        Self::new(preimage.into_bytes())
    }
}

impl Drop for ClaimPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for ClaimPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClaimPreimage([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementTemplate {
    pub wallet_path: WalletPath,
    pub previous_txid_wire: [u8; 32],
    pub previous_output: u32,
    pub prevout_value_sat: u64,
    pub prevout_script_pubkey: Vec<u8>,
    pub destination_value_sat: u64,
    pub destination_script_pubkey: Vec<u8>,
    pub transaction_version: i32,
    pub input_sequence: u32,
    pub lock_time: u32,
    pub taproot_script: Vec<u8>,
    pub taproot_control_block: Vec<u8>,
    pub maximum_fee_sat: u64,
    pub maximum_fee_rate_sat_per_vbyte: u64,
    pub maximum_weight: u64,
    pub dust_relay_fee_sat_per_kilobyte: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CooperativeSettlementTemplate {
    pub settlement: SettlementTemplate,
    pub cooperative_wallet_path: WalletPath,
    pub participant_keys: [[u8; 33]; 2],
    pub provider_index: u8,
    pub taproot_merkle_root: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub latest_safe_height: u32,
}

pub struct CooperativeSigningRound {
    template: CooperativeSettlementTemplate,
    transaction: Transaction,
    prevouts: Vec<TransactionOutput>,
    keys: Vec<PublicKey>,
    tweaks: Vec<Musig2Tweak>,
    aggregate_key: XOnlyPublicKey,
    signature_hash: [u8; 32],
    nonce: Option<WalletMusig2Nonce>,
    nonce_commitment: [u8; 32],
    counterparty_nonce_commitment: Option<[u8; 32]>,
    partial_released: bool,
    terminal: bool,
}

impl fmt::Debug for CooperativeSigningRound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningRound")
            .field("provider_index", &self.template.provider_index)
            .field("aggregate_key", &self.aggregate_key)
            .field("signature_hash", &self.signature_hash)
            .field("nonce_commitment", &self.nonce_commitment)
            .field(
                "counterparty_nonce_commitment",
                &self.counterparty_nonce_commitment,
            )
            .field("partial_released", &self.partial_released)
            .field("terminal", &self.terminal)
            .field("secret_nonce", &"[REDACTED]")
            .finish()
    }
}

impl CooperativeSigningRound {
    pub fn aggregate_key(&self) -> [u8; 32] {
        self.aggregate_key.serialize()
    }

    pub fn signature_hash(&self) -> [u8; 32] {
        self.signature_hash
    }

    pub fn unsigned_transaction(&self) -> Result<Vec<u8>, SettlementError> {
        self.transaction.serialize(false).map_err(Into::into)
    }

    pub fn nonce_commitment(&self) -> [u8; 32] {
        self.nonce_commitment
    }

    pub fn register_counterparty_nonce_commitment(
        &mut self,
        commitment: [u8; 32],
        current_height: u32,
    ) -> Result<(), SettlementError> {
        self.ensure_active(current_height)?;
        match self.counterparty_nonce_commitment {
            Some(existing) if existing == commitment => Ok(()),
            Some(_) => Err(SettlementError::NonceCommitmentMismatch),
            None => {
                self.counterparty_nonce_commitment = Some(commitment);
                Ok(())
            }
        }
    }

    pub fn reveal_public_nonce(
        &mut self,
        current_height: u32,
    ) -> Result<[u8; 66], SettlementError> {
        self.ensure_active(current_height)?;
        if self.counterparty_nonce_commitment.is_none() {
            return Err(SettlementError::CooperativeState);
        }
        self.nonce
            .as_ref()
            .map(WalletMusig2Nonce::public_nonce)
            .ok_or(SettlementError::CooperativeState)
    }

    pub fn abort(&mut self) {
        self.nonce.take();
        self.terminal = true;
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn ensure_active(&mut self, current_height: u32) -> Result<(), SettlementError> {
        if self.terminal {
            return Err(SettlementError::CooperativeState);
        }
        if current_height > self.template.latest_safe_height {
            self.abort();
            return Err(SettlementError::CooperativeExpired);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedSettlementTransaction {
    raw_transaction: Vec<u8>,
    transaction_id: [u8; 32],
    witness_transaction_id: [u8; 32],
    cost: TransactionCost,
}

impl SignedSettlementTransaction {
    pub fn broadcast_bytes(&self) -> &[u8] {
        &self.raw_transaction
    }

    pub fn into_broadcast_bytes(self) -> Vec<u8> {
        self.raw_transaction
    }

    pub fn transaction_id(&self) -> [u8; 32] {
        self.transaction_id
    }

    pub fn witness_transaction_id(&self) -> [u8; 32] {
        self.witness_transaction_id
    }

    pub fn cost(&self) -> TransactionCost {
        self.cost
    }
}

impl fmt::Debug for SignedSettlementTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedSettlementTransaction")
            .field("raw_transaction", &"[REDACTED]")
            .field("transaction_id", &self.transaction_id)
            .field("witness_transaction_id", &self.witness_transaction_id)
            .field("cost", &self.cost)
            .finish()
    }
}

pub struct SettlementBridge<'a> {
    wallet: &'a ProviderWallet,
}

impl<'a> SettlementBridge<'a> {
    pub fn new(wallet: &'a ProviderWallet) -> Self {
        Self { wallet }
    }

    pub fn claim(
        &self,
        template: &SettlementTemplate,
        preimage: ClaimPreimage,
    ) -> Result<SignedSettlementTransaction, SettlementError> {
        let payment_hash = preimage.payment_hash();
        let leaf = parse_swap_leaf_script(&template.taproot_script)?;
        let SwapLeafCondition::Hashlock(expected_payment_hash) = leaf.condition else {
            return Err(SettlementError::WrongPath);
        };
        if payment_hash != expected_payment_hash {
            return Err(SettlementError::PreimageMismatch);
        }
        self.ensure_wallet_key(template, &leaf)?;
        let mut transaction = unsigned_transaction(template);
        let prevouts = settlement_prevouts(template);
        let destination = transaction.outputs.first().ok_or(SettlementError::Core(
            VerificationError::Invalid("settlement transaction has no destination"),
        ))?;
        ensure_destination_policy(template, destination)?;
        let sighash = taproot_script_spend_sighash(
            &transaction,
            &prevouts,
            0,
            &template.taproot_script,
            &template.taproot_control_block,
        )?;
        let wallet_signature = self
            .wallet
            .sign_script_path(template.wallet_path, &sighash)?;
        ensure_signature_key(&leaf, wallet_signature.public_key)?;
        let mut exposed_preimage = preimage.expose();
        let witness = assemble_taproot_claim_witness(
            wallet_signature.signature,
            exposed_preimage,
            &template.taproot_script,
            &template.taproot_control_block,
        );
        exposed_preimage.fill(0);
        transaction.set_input_witness(0, witness?)?;
        let validated = validate_taproot_claim_witness(
            &transaction,
            &prevouts,
            0,
            &template.taproot_script,
            &template.taproot_control_block,
        )?;
        verify_validated_signature(&validated, sighash)?;
        finalize_transaction(template, transaction, &prevouts)
    }

    pub fn refund(
        &self,
        template: &SettlementTemplate,
    ) -> Result<SignedSettlementTransaction, SettlementError> {
        let leaf = parse_swap_leaf_script(&template.taproot_script)?;
        if !matches!(
            leaf.condition,
            SwapLeafCondition::Cltv(_) | SwapLeafCondition::Csv(_)
        ) {
            return Err(SettlementError::WrongPath);
        }
        self.ensure_wallet_key(template, &leaf)?;
        let mut transaction = unsigned_transaction(template);
        let prevouts = settlement_prevouts(template);
        let destination = transaction.outputs.first().ok_or(SettlementError::Core(
            VerificationError::Invalid("settlement transaction has no destination"),
        ))?;
        ensure_destination_policy(template, destination)?;
        let sighash = taproot_script_spend_sighash(
            &transaction,
            &prevouts,
            0,
            &template.taproot_script,
            &template.taproot_control_block,
        )?;
        let wallet_signature = self
            .wallet
            .sign_script_path(template.wallet_path, &sighash)?;
        ensure_signature_key(&leaf, wallet_signature.public_key)?;
        transaction.set_input_witness(
            0,
            assemble_taproot_refund_witness(
                wallet_signature.signature,
                &template.taproot_script,
                &template.taproot_control_block,
            )?,
        )?;
        let validated = validate_taproot_refund_witness(
            &transaction,
            &prevouts,
            0,
            &template.taproot_script,
            &template.taproot_control_block,
        )?;
        verify_validated_signature(&validated, sighash)?;
        finalize_transaction(template, transaction, &prevouts)
    }

    pub fn begin_cooperative(
        &self,
        template: &CooperativeSettlementTemplate,
        current_height: u32,
    ) -> Result<CooperativeSigningRound, SettlementError> {
        if template.latest_safe_height == 0 || current_height > template.latest_safe_height {
            return Err(SettlementError::CooperativeExpired);
        }
        let provider_index = usize::from(template.provider_index);
        if provider_index >= template.participant_keys.len() {
            return Err(SettlementError::CooperativeKeyMismatch);
        }
        let keys = template
            .participant_keys
            .iter()
            .map(|key| PublicKey::from_slice(key))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SettlementError::CooperativeKeyMismatch)?;
        if keys[0] == keys[1] {
            return Err(SettlementError::CooperativeKeyMismatch);
        }
        let wallet_key = self
            .wallet
            .derive_address(template.cooperative_wallet_path)?
            .internal_key;
        if keys[provider_index].x_only_public_key().0.serialize() != wallet_key
            || template.participant_keys[provider_index][0] != 0x02
        {
            return Err(SettlementError::CooperativeKeyMismatch);
        }
        let tweak = musig2_taproot_tweak(&keys, template.taproot_merkle_root)?;
        let tweaks = vec![tweak];
        let aggregate_key = musig2_tweaked_aggregate_key(&keys, &tweaks)?;
        let expected_script_pubkey =
            [&[0x51, 0x20][..], aggregate_key.serialize().as_slice()].concat();
        if template.settlement.prevout_script_pubkey != expected_script_pubkey {
            return Err(SettlementError::CooperativeKeyMismatch);
        }
        let unilateral_leaf = parse_swap_leaf_script(&template.settlement.taproot_script)?;
        self.ensure_wallet_key(&template.settlement, &unilateral_leaf)?;
        verify_control_block(
            &aggregate_key,
            &template.settlement.taproot_script,
            &template.settlement.taproot_control_block,
        )?;
        let transaction = unsigned_transaction(&template.settlement);
        let prevouts = settlement_prevouts(&template.settlement);
        let destination = transaction.outputs.first().ok_or(SettlementError::Core(
            VerificationError::Invalid("settlement transaction has no destination"),
        ))?;
        ensure_destination_policy(&template.settlement, destination)?;
        validate_transaction_cost(
            &transaction,
            &prevouts,
            template.settlement.maximum_fee_sat,
            template.settlement.maximum_fee_rate_sat_per_vbyte,
        )?;
        let signature_hash = taproot_key_spend_sighash(&transaction, &prevouts, 0)?;
        let nonce = self.wallet.begin_cooperative_signing(
            template.cooperative_wallet_path,
            template.transcript_digest,
            &keys,
            &tweaks,
            &signature_hash,
        )?;
        let nonce_commitment = sha256(&nonce.public_nonce());
        Ok(CooperativeSigningRound {
            template: template.clone(),
            transaction,
            prevouts,
            keys,
            tweaks,
            aggregate_key,
            signature_hash,
            nonce: Some(nonce),
            nonce_commitment,
            counterparty_nonce_commitment: None,
            partial_released: false,
            terminal: false,
        })
    }

    pub fn sign_cooperative_partial(
        &self,
        round: &mut CooperativeSigningRound,
        current_height: u32,
        public_nonces: &[[u8; 66]; 2],
    ) -> Result<[u8; 32], SettlementError> {
        round.ensure_active(current_height)?;
        if round.partial_released {
            return Err(SettlementError::CooperativeState);
        }
        let provider_index = usize::from(round.template.provider_index);
        let counterparty_index = 1_usize.saturating_sub(provider_index);
        let counterparty_commitment = round
            .counterparty_nonce_commitment
            .ok_or(SettlementError::CooperativeState)?;
        let own_public_nonce = round
            .nonce
            .as_ref()
            .map(WalletMusig2Nonce::public_nonce)
            .ok_or(SettlementError::CooperativeState)?;
        if public_nonces[provider_index] != own_public_nonce
            || sha256(&public_nonces[counterparty_index]) != counterparty_commitment
        {
            return Err(SettlementError::NonceCommitmentMismatch);
        }
        let result = self.wallet.sign_cooperative_partial(
            round
                .nonce
                .as_mut()
                .ok_or(SettlementError::CooperativeState)?,
            round.template.transcript_digest,
            public_nonces,
        );
        match result {
            Ok(partial) => {
                round.partial_released = true;
                round.nonce.take();
                Ok(partial)
            }
            Err(error) => {
                round.abort();
                Err(error.into())
            }
        }
    }

    pub fn finalize_cooperative(
        &self,
        mut round: CooperativeSigningRound,
        current_height: u32,
        public_nonces: &[[u8; 66]; 2],
        partial_signatures: &[[u8; 32]; 2],
    ) -> Result<SignedSettlementTransaction, SettlementError> {
        round.ensure_active(current_height)?;
        if !round.partial_released {
            return Err(SettlementError::CooperativeState);
        }
        let signature = musig2_aggregate_partial_signatures(
            &round.keys,
            public_nonces,
            &round.tweaks,
            &round.signature_hash,
            partial_signatures,
        )?;
        verify_musig2_signature(&round.aggregate_key, &round.signature_hash, &signature)?;
        let mut transaction = round.transaction;
        transaction.set_input_witness(0, vec![signature.to_vec()])?;
        finalize_transaction(&round.template.settlement, transaction, &round.prevouts)
    }

    fn ensure_wallet_key(
        &self,
        template: &SettlementTemplate,
        leaf: &ParsedSwapLeaf,
    ) -> Result<(), SettlementError> {
        let address = self.wallet.derive_address(template.wallet_path)?;
        if leaf.signing_key.serialize() != address.internal_key {
            return Err(SettlementError::SigningKeyMismatch);
        }
        Ok(())
    }
}

fn unsigned_transaction(template: &SettlementTemplate) -> Transaction {
    Transaction::new(
        template.transaction_version,
        vec![TransactionInput {
            previous_txid: template.previous_txid_wire,
            previous_output: template.previous_output,
            script_sig: Vec::new(),
            sequence: template.input_sequence,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: template.destination_value_sat,
            script_pubkey: template.destination_script_pubkey.clone(),
        }],
        template.lock_time,
    )
}

fn settlement_prevouts(template: &SettlementTemplate) -> Vec<TransactionOutput> {
    vec![TransactionOutput {
        value_sat: template.prevout_value_sat,
        script_pubkey: template.prevout_script_pubkey.clone(),
    }]
}

fn ensure_destination_policy(
    template: &SettlementTemplate,
    destination: &TransactionOutput,
) -> Result<(), SettlementError> {
    if is_dust(destination, template.dust_relay_fee_sat_per_kilobyte)? {
        return Err(SettlementError::DustOutput);
    }
    Ok(())
}

fn ensure_signature_key(
    leaf: &ParsedSwapLeaf,
    signature_public_key: [u8; 32],
) -> Result<(), SettlementError> {
    if leaf.signing_key.serialize() != signature_public_key {
        return Err(SettlementError::SigningKeyMismatch);
    }
    Ok(())
}

fn verify_validated_signature(
    validated: &immortal_core::mkt_swp_verify::ValidatedTaprootWitness,
    expected_sighash: [u8; 32],
) -> Result<(), SettlementError> {
    if validated.sighash != expected_sighash {
        return Err(SettlementError::SignatureInvalid);
    }
    let public_key = XOnlyPublicKey::from_byte_array(validated.signing_key.serialize())
        .map_err(|_| SettlementError::SignatureInvalid)?;
    let signature = Signature::from_byte_array(validated.signature);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &validated.sighash, &public_key)
        .map_err(|_| SettlementError::SignatureInvalid)
}

fn finalize_transaction(
    template: &SettlementTemplate,
    transaction: Transaction,
    prevouts: &[TransactionOutput],
) -> Result<SignedSettlementTransaction, SettlementError> {
    let cost = validate_transaction_cost(
        &transaction,
        prevouts,
        template.maximum_fee_sat,
        template.maximum_fee_rate_sat_per_vbyte,
    )?;
    if cost.weight > template.maximum_weight {
        return Err(SettlementError::WeightLimit);
    }
    Ok(SignedSettlementTransaction {
        raw_transaction: transaction.serialize(true)?,
        transaction_id: transaction.txid()?,
        witness_transaction_id: transaction.wtxid()?,
        cost,
    })
}
