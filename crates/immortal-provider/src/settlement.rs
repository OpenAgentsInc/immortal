//! Provider-owned construction and signing for MKT-SWP script-path settlement.

use crate::wallet::{ProviderWallet, WalletError, WalletPath};
use immortal_core::mkt_swp_verify::{
    ParsedSwapLeaf, SwapLeafCondition, Transaction, TransactionCost, TransactionInput,
    TransactionOutput, VerificationError, assemble_taproot_claim_witness,
    assemble_taproot_refund_witness, is_dust, parse_swap_leaf_script, sha256,
    taproot_script_spend_sighash, validate_taproot_claim_witness, validate_taproot_refund_witness,
    validate_transaction_cost,
};
use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};
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
