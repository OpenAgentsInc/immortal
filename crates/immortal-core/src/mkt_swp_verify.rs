//! Bounded Bitcoin and Lightning verification used by MKT-SWP clients and handlers.

use secp256k1::{
    Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
    ecdsa::{RecoverableSignature, RecoveryId, Signature as EcdsaSignature},
    schnorr::Signature as SchnorrSignature,
};
use sha2::{Digest, Sha256};

const MAX_TRANSACTION_BYTES: usize = 1_000_000;
const MAX_INPUTS: usize = 4_096;
const MAX_OUTPUTS: usize = 4_096;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_WITNESS_ITEMS: usize = 1_024;
const MAX_WITNESS_ITEM_BYTES: usize = 80_000;
const MAX_INVOICE_CHARS: usize = 7_089;
const MAX_MUSIG_KEYS: usize = 64;
const MAX_MUSIG_MESSAGE_BYTES: usize = 4_096;
const MAX_MUSIG_EXTRA_INPUT_BYTES: usize = 1_024;
const MAX_MUSIG_TWEAKS: usize = 8;
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const TAPROOT_LEAF_VERSION: u8 = 0xc0;
const TAPROOT_SIGHASH_DEFAULT: u8 = 0;
const TAPROOT_KEY_VERSION: u8 = 0;
const TAPROOT_NO_CODE_SEPARATOR: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    Bounds(&'static str),
    Encoding(&'static str),
    Invalid(&'static str),
    Unsupported(&'static str),
    Crypto(&'static str),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (class, message) = match self {
            Self::Bounds(message) => ("bounds", message),
            Self::Encoding(message) => ("encoding", message),
            Self::Invalid(message) => ("invalid", message),
            Self::Unsupported(message) => ("unsupported", message),
            Self::Crypto(message) => ("crypto", message),
        };
        write!(formatter, "{class}: {message}")
    }
}

impl std::error::Error for VerificationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Musig2Tweak {
    pub value: [u8; 32],
    pub xonly: bool,
}

pub struct Musig2SecretNonce {
    first: [u8; 32],
    second: [u8; 32],
    public_key: [u8; 33],
    public_nonce: [u8; 66],
    consumed: bool,
}

struct ConsumedMusig2Nonce {
    first: [u8; 32],
    second: [u8; 32],
    public_key: [u8; 33],
}

impl Drop for ConsumedMusig2Nonce {
    fn drop(&mut self) {
        self.first.fill(0);
        self.second.fill(0);
        self.public_key.fill(0);
    }
}

impl core::fmt::Debug for Musig2SecretNonce {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Musig2SecretNonce")
            .field("public_nonce", &self.public_nonce)
            .field("consumed", &self.consumed)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Musig2SecretNonce {
    pub fn public_nonce(&self) -> [u8; 66] {
        self.public_nonce
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    fn consume(&mut self) -> Result<ConsumedMusig2Nonce, VerificationError> {
        if self.consumed {
            return Err(VerificationError::Invalid("MuSig2 secret nonce reuse"));
        }
        self.consumed = true;
        let first = self.first;
        let second = self.second;
        let public_key = self.public_key;
        self.first.fill(0);
        self.second.fill(0);
        self.public_key.fill(0);
        Ok(ConsumedMusig2Nonce {
            first,
            second,
            public_key,
        })
    }
}

impl Drop for Musig2SecretNonce {
    fn drop(&mut self) {
        self.first.fill(0);
        self.second.fill(0);
        self.public_key.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    has_witness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInput {
    pub previous_txid: [u8; 32],
    pub previous_output: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutput {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

impl Transaction {
    pub fn new(
        version: i32,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: u32,
    ) -> Self {
        let has_witness = inputs.iter().any(|input| !input.witness.is_empty());
        Self {
            version,
            inputs,
            outputs,
            lock_time,
            has_witness,
        }
    }

    pub fn set_input_witness(
        &mut self,
        input_index: usize,
        witness: Vec<Vec<u8>>,
    ) -> Result<(), VerificationError> {
        validate_witness_items(&witness)?;
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(VerificationError::Bounds("witness input index"))?;
        input.witness = witness;
        self.has_witness = self.inputs.iter().any(|input| !input.witness.is_empty());
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, VerificationError> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(VerificationError::Bounds("transaction byte length"));
        }
        let mut reader = Reader::new(bytes);
        let version = reader.read_i32()?;
        let has_witness = reader.remaining() >= 2 && reader.peek()? == 0 && reader.peek_at(1)? != 0;
        if has_witness {
            reader.read_u8()?;
            if reader.read_u8()? != 1 {
                return Err(VerificationError::Unsupported("transaction witness flag"));
            }
        }
        let input_count = reader.read_compact_size(MAX_INPUTS)?;
        if input_count == 0 {
            return Err(VerificationError::Invalid("transaction has no inputs"));
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let previous_txid = reader.read_array()?;
            let previous_output = reader.read_u32()?;
            let script_sig = reader.read_var_bytes(MAX_SCRIPT_BYTES)?.to_vec();
            let sequence = reader.read_u32()?;
            inputs.push(TransactionInput {
                previous_txid,
                previous_output,
                script_sig,
                sequence,
                witness: Vec::new(),
            });
        }
        let output_count = reader.read_compact_size(MAX_OUTPUTS)?;
        if output_count == 0 {
            return Err(VerificationError::Invalid("transaction has no outputs"));
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(TransactionOutput {
                value_sat: reader.read_u64()?,
                script_pubkey: reader.read_var_bytes(MAX_SCRIPT_BYTES)?.to_vec(),
            });
        }
        if has_witness {
            for input in &mut inputs {
                let item_count = reader.read_compact_size(MAX_WITNESS_ITEMS)?;
                let mut witness = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    witness.push(reader.read_var_bytes(MAX_WITNESS_ITEM_BYTES)?.to_vec());
                }
                input.witness = witness;
            }
        }
        let lock_time = reader.read_u32()?;
        if reader.remaining() != 0 {
            return Err(VerificationError::Encoding("transaction trailing bytes"));
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
            has_witness,
        })
    }

    pub fn serialize(&self, include_witness: bool) -> Result<Vec<u8>, VerificationError> {
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(VerificationError::Bounds("transaction input count"));
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_OUTPUTS {
            return Err(VerificationError::Bounds("transaction output count"));
        }
        let include_witness = include_witness
            && self.has_witness
            && self.inputs.iter().any(|input| !input.witness.is_empty());
        let mut output = Vec::new();
        output.extend_from_slice(&self.version.to_le_bytes());
        if include_witness {
            output.extend_from_slice(&[0, 1]);
        }
        write_compact_size(self.inputs.len(), &mut output)?;
        for input in &self.inputs {
            if input.script_sig.len() > MAX_SCRIPT_BYTES {
                return Err(VerificationError::Bounds("scriptSig byte length"));
            }
            output.extend_from_slice(&input.previous_txid);
            output.extend_from_slice(&input.previous_output.to_le_bytes());
            write_var_bytes(&input.script_sig, &mut output)?;
            output.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(self.outputs.len(), &mut output)?;
        for transaction_output in &self.outputs {
            if transaction_output.script_pubkey.len() > MAX_SCRIPT_BYTES {
                return Err(VerificationError::Bounds("scriptPubKey byte length"));
            }
            output.extend_from_slice(&transaction_output.value_sat.to_le_bytes());
            write_var_bytes(&transaction_output.script_pubkey, &mut output)?;
        }
        if include_witness {
            for input in &self.inputs {
                if input.witness.len() > MAX_WITNESS_ITEMS {
                    return Err(VerificationError::Bounds("witness item count"));
                }
                write_compact_size(input.witness.len(), &mut output)?;
                for item in &input.witness {
                    if item.len() > MAX_WITNESS_ITEM_BYTES {
                        return Err(VerificationError::Bounds("witness item byte length"));
                    }
                    write_var_bytes(item, &mut output)?;
                }
            }
        }
        output.extend_from_slice(&self.lock_time.to_le_bytes());
        if output.len() > MAX_TRANSACTION_BYTES {
            return Err(VerificationError::Bounds(
                "serialized transaction byte length",
            ));
        }
        Ok(output)
    }

    pub fn txid(&self) -> Result<[u8; 32], VerificationError> {
        Ok(display_hash(double_sha256(&self.serialize(false)?)))
    }

    pub fn wtxid(&self) -> Result<[u8; 32], VerificationError> {
        Ok(display_hash(double_sha256(&self.serialize(true)?)))
    }

    pub fn weight(&self) -> Result<u64, VerificationError> {
        let stripped = u64::try_from(self.serialize(false)?.len())
            .map_err(|_| VerificationError::Bounds("stripped transaction size"))?;
        let total = u64::try_from(self.serialize(true)?.len())
            .map_err(|_| VerificationError::Bounds("witness transaction size"))?;
        stripped
            .checked_mul(3)
            .and_then(|weight| weight.checked_add(total))
            .ok_or(VerificationError::Bounds("transaction weight"))
    }

    pub fn virtual_size(&self) -> Result<u64, VerificationError> {
        self.weight()?
            .checked_add(3)
            .map(|weight| weight / 4)
            .ok_or(VerificationError::Bounds("transaction virtual size"))
    }
}

impl TransactionInput {
    pub fn serialize_without_witness(&self) -> Result<Vec<u8>, VerificationError> {
        if self.script_sig.len() > MAX_SCRIPT_BYTES {
            return Err(VerificationError::Bounds("scriptSig byte length"));
        }
        let mut output = Vec::with_capacity(41 + self.script_sig.len());
        output.extend_from_slice(&self.previous_txid);
        output.extend_from_slice(&self.previous_output.to_le_bytes());
        write_var_bytes(&self.script_sig, &mut output)?;
        output.extend_from_slice(&self.sequence.to_le_bytes());
        Ok(output)
    }
}

impl TransactionOutput {
    pub fn serialize(&self) -> Result<Vec<u8>, VerificationError> {
        if self.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(VerificationError::Bounds("scriptPubKey byte length"));
        }
        let mut output = Vec::with_capacity(9 + self.script_pubkey.len());
        output.extend_from_slice(&self.value_sat.to_le_bytes());
        write_var_bytes(&self.script_pubkey, &mut output)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapLeafCondition {
    Hashlock([u8; 32]),
    Cltv(u32),
    Csv(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedSwapLeaf {
    pub signing_key: XOnlyPublicKey,
    pub condition: SwapLeafCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedTaprootWitness {
    pub signature: [u8; 64],
    pub signing_key: XOnlyPublicKey,
    pub sighash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionCost {
    pub fee_sat: u64,
    pub weight: u64,
    pub virtual_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptInstruction {
    Opcode(u8),
    Push(Vec<u8>),
}

pub fn parse_swap_script(script: &[u8]) -> Result<Vec<ScriptInstruction>, VerificationError> {
    if script.is_empty() || script.len() > MAX_SCRIPT_BYTES {
        return Err(VerificationError::Bounds("swap script byte length"));
    }
    let mut instructions = Vec::new();
    let mut position = 0;
    while position < script.len() {
        let opcode = script[position];
        position += 1;
        let length = match opcode {
            1..=75 => Some(usize::from(opcode)),
            0x4c => Some(read_script_length(script, &mut position, 1)?),
            0x4d => Some(read_script_length(script, &mut position, 2)?),
            0x4e => Some(read_script_length(script, &mut position, 4)?),
            _ => None,
        };
        if let Some(length) = length {
            let end = position
                .checked_add(length)
                .ok_or(VerificationError::Bounds("script push overflow"))?;
            let data = script
                .get(position..end)
                .ok_or(VerificationError::Encoding("truncated script push"))?;
            instructions.push(ScriptInstruction::Push(data.to_vec()));
            position = end;
        } else {
            if !matches!(
                opcode,
                0x00 | 0x51
                    ..=0x60
                        | 0x63
                        | 0x64
                        | 0x67
                        | 0x68
                        | 0x69
                        | 0x75
                        | 0x76
                        | 0x82
                        | 0x87
                        | 0x88
                        | 0xa8
                        | 0xa9
                        | 0xb1
                        | 0xb2
                        | 0xac
                        | 0xad
            ) {
                return Err(VerificationError::Unsupported("swap script opcode"));
            }
            instructions.push(ScriptInstruction::Opcode(opcode));
        }
        if instructions.len() > 256 {
            return Err(VerificationError::Bounds("swap script instruction count"));
        }
    }
    Ok(instructions)
}

pub fn parse_swap_leaf_script(script: &[u8]) -> Result<ParsedSwapLeaf, VerificationError> {
    let instructions = parse_swap_script(script)?;
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
            let payment_hash = payment_hash
                .as_slice()
                .try_into()
                .map_err(|_| VerificationError::Encoding("hashlock payment hash length"))?;
            (key, SwapLeafCondition::Hashlock(payment_hash))
        }
        [
            ScriptInstruction::Push(value),
            ScriptInstruction::Opcode(0xb1),
            ScriptInstruction::Opcode(0x75),
            ScriptInstruction::Push(key),
            ScriptInstruction::Opcode(0xac),
        ] if key.len() == 32 => (key, SwapLeafCondition::Cltv(parse_script_number(value)?)),
        [
            ScriptInstruction::Push(value),
            ScriptInstruction::Opcode(0xb2),
            ScriptInstruction::Opcode(0x75),
            ScriptInstruction::Push(key),
            ScriptInstruction::Opcode(0xac),
        ] if key.len() == 32 => (key, SwapLeafCondition::Csv(parse_script_number(value)?)),
        _ => {
            return Err(VerificationError::Unsupported(
                "swap leaf is not an exact hashlock, CLTV, or CSV path",
            ));
        }
    };
    let signing_key = XOnlyPublicKey::from_byte_array(
        key.as_slice()
            .try_into()
            .map_err(|_| VerificationError::Encoding("swap leaf signing key length"))?,
    )
    .map_err(|_| VerificationError::Crypto("swap leaf signing key"))?;
    Ok(ParsedSwapLeaf {
        signing_key,
        condition,
    })
}

pub fn taproot_script_spend_signature_message(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
    script: &[u8],
    control_block: &[u8],
) -> Result<Vec<u8>, VerificationError> {
    validate_taproot_spend_inputs(transaction, prevouts, input_index, script, control_block)?;
    let input_index =
        u32::try_from(input_index).map_err(|_| VerificationError::Bounds("Taproot input index"))?;

    let mut serialized_prevouts = Vec::with_capacity(transaction.inputs.len() * 36);
    let mut serialized_amounts = Vec::with_capacity(prevouts.len() * 8);
    let mut serialized_script_pubkeys = Vec::new();
    let mut serialized_sequences = Vec::with_capacity(transaction.inputs.len() * 4);
    for (input, prevout) in transaction.inputs.iter().zip(prevouts) {
        serialized_prevouts.extend_from_slice(&input.previous_txid);
        serialized_prevouts.extend_from_slice(&input.previous_output.to_le_bytes());
        serialized_amounts.extend_from_slice(&prevout.value_sat.to_le_bytes());
        write_var_bytes(&prevout.script_pubkey, &mut serialized_script_pubkeys)?;
        serialized_sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let mut serialized_outputs = Vec::new();
    for output in &transaction.outputs {
        serialized_outputs.extend_from_slice(&output.serialize()?);
    }

    let mut message = Vec::with_capacity(212);
    message.push(0); // BIP-341 epoch.
    message.push(TAPROOT_SIGHASH_DEFAULT);
    message.extend_from_slice(&transaction.version.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_le_bytes());
    message.extend_from_slice(&sha256(&serialized_prevouts));
    message.extend_from_slice(&sha256(&serialized_amounts));
    message.extend_from_slice(&sha256(&serialized_script_pubkeys));
    message.extend_from_slice(&sha256(&serialized_sequences));
    message.extend_from_slice(&sha256(&serialized_outputs));
    message.push(2); // ext_flag=1 (script path), annex_present=0.
    message.extend_from_slice(&input_index.to_le_bytes());
    message.extend_from_slice(&tapleaf_hash(TAPROOT_LEAF_VERSION, script)?);
    message.push(TAPROOT_KEY_VERSION);
    message.extend_from_slice(&TAPROOT_NO_CODE_SEPARATOR.to_le_bytes());
    Ok(message)
}

pub fn taproot_script_spend_sighash(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
    script: &[u8],
    control_block: &[u8],
) -> Result<[u8; 32], VerificationError> {
    Ok(tagged_hash(
        "TapSighash",
        &taproot_script_spend_signature_message(
            transaction,
            prevouts,
            input_index,
            script,
            control_block,
        )?,
    ))
}

pub fn taproot_key_spend_signature_message(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
) -> Result<Vec<u8>, VerificationError> {
    validate_taproot_key_spend_inputs(transaction, prevouts, input_index)?;
    let input_index =
        u32::try_from(input_index).map_err(|_| VerificationError::Bounds("Taproot input index"))?;

    let mut serialized_prevouts = Vec::with_capacity(transaction.inputs.len() * 36);
    let mut serialized_amounts = Vec::with_capacity(prevouts.len() * 8);
    let mut serialized_script_pubkeys = Vec::new();
    let mut serialized_sequences = Vec::with_capacity(transaction.inputs.len() * 4);
    for (input, prevout) in transaction.inputs.iter().zip(prevouts) {
        serialized_prevouts.extend_from_slice(&input.previous_txid);
        serialized_prevouts.extend_from_slice(&input.previous_output.to_le_bytes());
        serialized_amounts.extend_from_slice(&prevout.value_sat.to_le_bytes());
        write_var_bytes(&prevout.script_pubkey, &mut serialized_script_pubkeys)?;
        serialized_sequences.extend_from_slice(&input.sequence.to_le_bytes());
    }
    let mut serialized_outputs = Vec::new();
    for output in &transaction.outputs {
        serialized_outputs.extend_from_slice(&output.serialize()?);
    }

    let mut message = Vec::with_capacity(175);
    message.push(0);
    message.push(TAPROOT_SIGHASH_DEFAULT);
    message.extend_from_slice(&transaction.version.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_le_bytes());
    message.extend_from_slice(&sha256(&serialized_prevouts));
    message.extend_from_slice(&sha256(&serialized_amounts));
    message.extend_from_slice(&sha256(&serialized_script_pubkeys));
    message.extend_from_slice(&sha256(&serialized_sequences));
    message.extend_from_slice(&sha256(&serialized_outputs));
    message.push(0); // ext_flag=0 (key path), annex_present=0.
    message.extend_from_slice(&input_index.to_le_bytes());
    Ok(message)
}

pub fn taproot_key_spend_sighash(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
) -> Result<[u8; 32], VerificationError> {
    Ok(tagged_hash(
        "TapSighash",
        &taproot_key_spend_signature_message(transaction, prevouts, input_index)?,
    ))
}

pub fn assemble_taproot_claim_witness(
    signature: [u8; 64],
    preimage: [u8; 32],
    script: &[u8],
    control_block: &[u8],
) -> Result<Vec<Vec<u8>>, VerificationError> {
    let leaf = parse_swap_leaf_script(script)?;
    let SwapLeafCondition::Hashlock(payment_hash) = leaf.condition else {
        return Err(VerificationError::Invalid(
            "claim witness requires hashlock leaf",
        ));
    };
    if !verify_preimage(&preimage, &payment_hash) {
        return Err(VerificationError::Invalid("claim witness preimage"));
    }
    validate_control_block_shape(control_block)?;
    Ok(vec![
        signature.to_vec(),
        preimage.to_vec(),
        script.to_vec(),
        control_block.to_vec(),
    ])
}

pub fn assemble_taproot_refund_witness(
    signature: [u8; 64],
    script: &[u8],
    control_block: &[u8],
) -> Result<Vec<Vec<u8>>, VerificationError> {
    let leaf = parse_swap_leaf_script(script)?;
    if !matches!(
        leaf.condition,
        SwapLeafCondition::Cltv(_) | SwapLeafCondition::Csv(_)
    ) {
        return Err(VerificationError::Invalid(
            "refund witness requires timelock leaf",
        ));
    }
    validate_control_block_shape(control_block)?;
    Ok(vec![
        signature.to_vec(),
        script.to_vec(),
        control_block.to_vec(),
    ])
}

pub fn validate_taproot_claim_witness(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
    expected_script: &[u8],
    expected_control_block: &[u8],
) -> Result<ValidatedTaprootWitness, VerificationError> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(VerificationError::Bounds("claim witness input index"))?;
    let [signature, preimage, script, control_block] = input.witness.as_slice() else {
        return Err(VerificationError::Invalid("claim witness shape"));
    };
    let signature = exact_default_signature(signature)?;
    let preimage: [u8; 32] = preimage
        .as_slice()
        .try_into()
        .map_err(|_| VerificationError::Invalid("claim preimage length"))?;
    if script != expected_script || control_block != expected_control_block {
        return Err(VerificationError::Invalid("claim witness path mismatch"));
    }
    let leaf = parse_swap_leaf_script(script)?;
    let SwapLeafCondition::Hashlock(payment_hash) = leaf.condition else {
        return Err(VerificationError::Invalid("claim witness leaf condition"));
    };
    if !verify_preimage(&preimage, &payment_hash) {
        return Err(VerificationError::Invalid("claim witness preimage"));
    }
    let sighash =
        taproot_script_spend_sighash(transaction, prevouts, input_index, script, control_block)?;
    Ok(ValidatedTaprootWitness {
        signature,
        signing_key: leaf.signing_key,
        sighash,
    })
}

pub fn validate_taproot_refund_witness(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
    expected_script: &[u8],
    expected_control_block: &[u8],
) -> Result<ValidatedTaprootWitness, VerificationError> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(VerificationError::Bounds("refund witness input index"))?;
    let [signature, script, control_block] = input.witness.as_slice() else {
        return Err(VerificationError::Invalid("refund witness shape"));
    };
    let signature = exact_default_signature(signature)?;
    if script != expected_script || control_block != expected_control_block {
        return Err(VerificationError::Invalid("refund witness path mismatch"));
    }
    let leaf = parse_swap_leaf_script(script)?;
    match leaf.condition {
        SwapLeafCondition::Cltv(required) => {
            if input.sequence == u32::MAX
                || !check_cltv(Timelock::BlockHeight(required), transaction.lock_time)
            {
                return Err(VerificationError::Invalid("refund CLTV is not satisfied"));
            }
        }
        SwapLeafCondition::Csv(required) => {
            if transaction.version < 2 || !check_csv(required, input.sequence) {
                return Err(VerificationError::Invalid("refund CSV is not satisfied"));
            }
        }
        SwapLeafCondition::Hashlock(_) => {
            return Err(VerificationError::Invalid("refund witness leaf condition"));
        }
    }
    let sighash =
        taproot_script_spend_sighash(transaction, prevouts, input_index, script, control_block)?;
    Ok(ValidatedTaprootWitness {
        signature,
        signing_key: leaf.signing_key,
        sighash,
    })
}

pub fn transaction_cost(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
) -> Result<TransactionCost, VerificationError> {
    if transaction.inputs.len() != prevouts.len() {
        return Err(VerificationError::Invalid("transaction prevout count"));
    }
    let input_value = prevouts.iter().try_fold(0_u64, |total, prevout| {
        total
            .checked_add(prevout.value_sat)
            .ok_or(VerificationError::Bounds("transaction input value"))
    })?;
    let output_value = transaction
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| {
            total
                .checked_add(output.value_sat)
                .ok_or(VerificationError::Bounds("transaction output value"))
        })?;
    let fee_sat = input_value
        .checked_sub(output_value)
        .ok_or(VerificationError::Invalid(
            "transaction spends more than its prevouts",
        ))?;
    Ok(TransactionCost {
        fee_sat,
        weight: transaction.weight()?,
        virtual_size: transaction.virtual_size()?,
    })
}

pub fn validate_transaction_cost(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    maximum_fee_sat: u64,
    maximum_fee_rate_sat_per_vbyte: u64,
) -> Result<TransactionCost, VerificationError> {
    let cost = transaction_cost(transaction, prevouts)?;
    let maximum_rate_fee = maximum_fee_rate_sat_per_vbyte
        .checked_mul(cost.virtual_size)
        .ok_or(VerificationError::Bounds("maximum transaction fee rate"))?;
    if cost.fee_sat > maximum_fee_sat || cost.fee_sat > maximum_rate_fee {
        return Err(VerificationError::Invalid("transaction fee exceeds policy"));
    }
    Ok(cost)
}

pub fn dust_threshold(
    script_pubkey: &[u8],
    dust_relay_fee_sat_per_kilobyte: u64,
) -> Result<u64, VerificationError> {
    if script_pubkey.len() > MAX_SCRIPT_BYTES {
        return Err(VerificationError::Bounds("dust scriptPubKey byte length"));
    }
    if script_pubkey.first() == Some(&0x6a) {
        return Ok(0);
    }
    let output_size = 8_u64
        .checked_add(compact_size_length(script_pubkey.len())?)
        .and_then(|size| size.checked_add(u64::try_from(script_pubkey.len()).ok()?))
        .ok_or(VerificationError::Bounds("dust output size"))?;
    let spend_size = if is_witness_program(script_pubkey) {
        67
    } else {
        148
    };
    fee_for_size(
        dust_relay_fee_sat_per_kilobyte,
        output_size
            .checked_add(spend_size)
            .ok_or(VerificationError::Bounds("dust spend size"))?,
    )
}

pub fn is_dust(
    output: &TransactionOutput,
    dust_relay_fee_sat_per_kilobyte: u64,
) -> Result<bool, VerificationError> {
    Ok(output.value_sat < dust_threshold(&output.script_pubkey, dust_relay_fee_sat_per_kilobyte)?)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn verify_preimage(preimage: &[u8; 32], payment_hash: &[u8; 32]) -> bool {
    constant_time_equal(&sha256(preimage), payment_hash)
}

pub fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> Result<[u8; 32], VerificationError> {
    if leaf_version & 1 != 0 || script.len() > MAX_SCRIPT_BYTES {
        return Err(VerificationError::Invalid(
            "tapleaf version or script length",
        ));
    }
    let mut message = vec![leaf_version];
    write_compact_size(script.len(), &mut message)?;
    message.extend_from_slice(script);
    Ok(tagged_hash("TapLeaf", &message))
}

pub fn tapbranch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut message = [0_u8; 64];
    message[..32].copy_from_slice(&first);
    message[32..].copy_from_slice(&second);
    tagged_hash("TapBranch", &message)
}

pub fn taproot_output_key(
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> Result<(XOnlyPublicKey, Parity), VerificationError> {
    let mut message = internal_key.serialize().to_vec();
    if let Some(root) = merkle_root {
        message.extend_from_slice(&root);
    }
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &message))
        .map_err(|_| VerificationError::Crypto("taproot tweak exceeds curve order"))?;
    internal_key
        .add_tweak(&Secp256k1::verification_only(), &tweak)
        .map_err(|_| VerificationError::Crypto("taproot output key tweak failed"))
}

pub fn verify_control_block(
    output_key: &XOnlyPublicKey,
    script: &[u8],
    control_block: &[u8],
) -> Result<(), VerificationError> {
    if control_block.len() < 33
        || control_block.len() > 33 + 32 * 128
        || (control_block.len() - 33) % 32 != 0
    {
        return Err(VerificationError::Encoding("taproot control block length"));
    }
    let leaf_version = control_block[0] & 0xfe;
    if leaf_version == 0x50 {
        return Err(VerificationError::Invalid("taproot annex leaf version"));
    }
    let internal_key = XOnlyPublicKey::from_byte_array(
        control_block[1..33]
            .try_into()
            .map_err(|_| VerificationError::Encoding("taproot internal key length"))?,
    )
    .map_err(|_| VerificationError::Crypto("taproot internal key"))?;
    let mut root = tapleaf_hash(leaf_version, script)?;
    for sibling in control_block[33..].chunks_exact(32) {
        let sibling: [u8; 32] = sibling
            .try_into()
            .map_err(|_| VerificationError::Encoding("taproot sibling length"))?;
        root = tapbranch_hash(root, sibling);
    }
    let (candidate, parity) = taproot_output_key(internal_key, Some(root))?;
    let expected_parity = if control_block[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    if candidate != *output_key || parity != expected_parity {
        return Err(VerificationError::Invalid(
            "taproot control block commitment",
        ));
    }
    Ok(())
}

pub fn musig2_aggregate_key(keys: &[PublicKey]) -> Result<XOnlyPublicKey, VerificationError> {
    if keys.is_empty() || keys.len() > MAX_MUSIG_KEYS {
        return Err(VerificationError::Bounds("MuSig2 participant count"));
    }
    let aggregate = musig2_aggregate_plain_key(keys)?;
    Ok(aggregate.x_only_public_key().0)
}

pub fn musig2_taproot_tweak(
    keys: &[PublicKey],
    merkle_root: [u8; 32],
) -> Result<Musig2Tweak, VerificationError> {
    let internal_key = musig2_aggregate_key(keys)?;
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&internal_key.serialize());
    message.extend_from_slice(&merkle_root);
    let value = tagged_hash("TapTweak", &message);
    Scalar::from_be_bytes(value)
        .map_err(|_| VerificationError::Crypto("taproot tweak exceeds curve order"))?;
    Ok(Musig2Tweak { value, xonly: true })
}

pub fn musig2_tweaked_aggregate_key(
    keys: &[PublicKey],
    tweaks: &[Musig2Tweak],
) -> Result<XOnlyPublicKey, VerificationError> {
    Ok(musig2_key_context(keys, tweaks)?.key.x_only_public_key().0)
}

pub fn musig2_nonce_gen(
    secret_key: &SecretKey,
    aggregate_key: &[u8; 32],
    message: &[u8],
    extra_input: &[u8],
    randomness: [u8; 32],
) -> Result<Musig2SecretNonce, VerificationError> {
    if message.len() > MAX_MUSIG_MESSAGE_BYTES {
        return Err(VerificationError::Bounds("MuSig2 message byte length"));
    }
    if extra_input.len() > MAX_MUSIG_EXTRA_INPUT_BYTES {
        return Err(VerificationError::Bounds("MuSig2 extra input byte length"));
    }
    let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), secret_key).serialize();
    let auxiliary = tagged_hash("MuSig/aux", &randomness);
    let mut randomized_secret = secret_key.secret_bytes();
    for (secret, mask) in randomized_secret.iter_mut().zip(auxiliary) {
        *secret ^= mask;
    }
    let mut input = Vec::with_capacity(
        32 + 1 + public_key.len() + 1 + 32 + 1 + 8 + message.len() + 4 + extra_input.len() + 1,
    );
    input.extend_from_slice(&randomized_secret);
    input.push(public_key.len() as u8);
    input.extend_from_slice(&public_key);
    input.push(32);
    input.extend_from_slice(aggregate_key);
    input.push(1);
    input.extend_from_slice(
        &u64::try_from(message.len())
            .map_err(|_| VerificationError::Bounds("MuSig2 message byte length"))?
            .to_be_bytes(),
    );
    input.extend_from_slice(message);
    input.extend_from_slice(
        &u32::try_from(extra_input.len())
            .map_err(|_| VerificationError::Bounds("MuSig2 extra input byte length"))?
            .to_be_bytes(),
    );
    input.extend_from_slice(extra_input);

    let first = musig2_nonce_scalar(&input, 0)?;
    let second = musig2_nonce_scalar(&input, 1)?;
    randomized_secret.fill(0);
    input.fill(0);
    let secp = Secp256k1::signing_only();
    let first_public = PublicKey::from_secret_key(&secp, &first).serialize();
    let second_public = PublicKey::from_secret_key(&secp, &second).serialize();
    let mut public_nonce = [0_u8; 66];
    public_nonce[..33].copy_from_slice(&first_public);
    public_nonce[33..].copy_from_slice(&second_public);
    Ok(Musig2SecretNonce {
        first: first.secret_bytes(),
        second: second.secret_bytes(),
        public_key,
        public_nonce,
        consumed: false,
    })
}

pub fn musig2_partial_sign(
    secret_nonce: &mut Musig2SecretNonce,
    secret_key: &SecretKey,
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    tweaks: &[Musig2Tweak],
    message: &[u8],
) -> Result<[u8; 32], VerificationError> {
    validate_musig2_session_bounds(keys, public_nonces, tweaks, message)?;
    let mut consumed_nonce = secret_nonce.consume()?;
    let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), secret_key);
    if public_key.serialize() != consumed_nonce.public_key {
        return Err(VerificationError::Invalid(
            "MuSig2 nonce key changed before signing",
        ));
    }
    let signer_index =
        keys.iter()
            .position(|key| key == &public_key)
            .ok_or(VerificationError::Invalid(
                "MuSig2 signer is not a participant",
            ))?;
    if public_nonces.get(signer_index) != Some(&secret_nonce.public_nonce) {
        return Err(VerificationError::Invalid(
            "MuSig2 signer public nonce mismatch",
        ));
    }
    let session = musig2_session_values(keys, public_nonces, tweaks, message)?;
    let mut first = SecretKey::from_byte_array(consumed_nonce.first)
        .map_err(|_| VerificationError::Crypto("MuSig2 first secret nonce"))?;
    consumed_nonce.first.fill(0);
    let mut second = SecretKey::from_byte_array(consumed_nonce.second)
        .map_err(|_| VerificationError::Crypto("MuSig2 second secret nonce"))?;
    consumed_nonce.second.fill(0);
    if session.nonce_odd {
        first = first.negate();
        second = second.negate();
    }
    let mut first_term = Some(first);
    let mut second_term = multiply_secret_term(&second, &session.nonce_coefficient)?;
    let mut nonce_term = add_secret_terms(&first_term, &second_term)?;
    first.non_secure_erase();
    second.non_secure_erase();
    erase_secret_term(&mut first_term);
    erase_secret_term(&mut second_term);

    let (serialized, list_hash, second_key) = musig2_key_material(keys);
    let coefficient = musig2_key_coefficient(serialized[signer_index], list_hash, second_key)?;
    let mut signing_key = *secret_key;
    if session.key_odd ^ session.key_context.gacc_negative {
        signing_key = signing_key.negate();
    }
    let mut coefficient_term = multiply_secret_term(&signing_key, &coefficient)?;
    let mut key_term = match coefficient_term.as_ref() {
        Some(term) => multiply_secret_term(term, &session.challenge)?,
        None => None,
    };
    signing_key.non_secure_erase();
    erase_secret_term(&mut coefficient_term);
    let mut partial_term = add_secret_terms(&nonce_term, &key_term)?;
    let partial = partial_term
        .as_ref()
        .map(|value| value.secret_bytes())
        .unwrap_or([0; 32]);
    erase_secret_term(&mut nonce_term);
    erase_secret_term(&mut key_term);
    erase_secret_term(&mut partial_term);
    verify_musig2_partial_signature_with_tweaks(
        keys,
        public_nonces,
        tweaks,
        signer_index,
        message,
        &partial,
    )?;
    Ok(partial)
}

pub fn verify_musig2_partial_signature(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    signer_index: usize,
    message: &[u8],
    partial_signature: &[u8; 32],
) -> Result<(), VerificationError> {
    verify_musig2_partial_signature_with_tweaks(
        keys,
        public_nonces,
        &[],
        signer_index,
        message,
        partial_signature,
    )
}

pub fn verify_musig2_partial_signature_with_tweaks(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    tweaks: &[Musig2Tweak],
    signer_index: usize,
    message: &[u8],
    partial_signature: &[u8; 32],
) -> Result<(), VerificationError> {
    validate_musig2_session_bounds(keys, public_nonces, tweaks, message)?;
    if signer_index >= keys.len() {
        return Err(VerificationError::Bounds("MuSig2 signer index"));
    }
    if *partial_signature >= CURVE_ORDER {
        return Err(VerificationError::Crypto("MuSig2 partial signature scalar"));
    }
    let session = musig2_session_values(keys, public_nonces, tweaks, message)?;
    let signer_nonce = musig2_effective_signer_nonce(
        &public_nonces[signer_index],
        &session.nonce_coefficient,
        session.nonce_odd,
    )?;
    let (serialized, list_hash, second_key) = musig2_key_material(keys);
    let coefficient = musig2_key_coefficient(serialized[signer_index], list_hash, second_key)?;
    let mut signer_key = point_multiply(keys[signer_index], &coefficient)?;
    signer_key = point_multiply_aggregate(signer_key, &session.challenge)?;
    if session.key_odd ^ session.key_context.gacc_negative {
        signer_key = signer_key.negate();
    }
    let expected = signer_nonce.add(signer_key)?;
    let supplied = point_from_scalar(*partial_signature)?;
    if supplied != expected {
        return Err(VerificationError::Crypto(
            "MuSig2 partial signature verification",
        ));
    }
    Ok(())
}

pub fn musig2_aggregate_partial_signatures(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    tweaks: &[Musig2Tweak],
    message: &[u8],
    partial_signatures: &[[u8; 32]],
) -> Result<[u8; 64], VerificationError> {
    validate_musig2_session_bounds(keys, public_nonces, tweaks, message)?;
    if partial_signatures.len() != keys.len() {
        return Err(VerificationError::Bounds("MuSig2 partial signature count"));
    }
    for (index, partial) in partial_signatures.iter().enumerate() {
        verify_musig2_partial_signature_with_tweaks(
            keys,
            public_nonces,
            tweaks,
            index,
            message,
            partial,
        )?;
    }
    let session = musig2_session_values(keys, public_nonces, tweaks, message)?;
    let mut scalar = [0_u8; 32];
    for partial in partial_signatures {
        if *partial >= CURVE_ORDER {
            return Err(VerificationError::Crypto("MuSig2 partial signature scalar"));
        }
        scalar = scalar_add_mod(scalar, *partial);
    }
    let tweak_term =
        scalar_multiply_public(session.challenge.to_be_bytes(), session.key_context.tacc)?;
    let tweak_term = if session.key_odd {
        scalar_negate_mod(tweak_term)
    } else {
        tweak_term
    };
    scalar = scalar_add_mod(scalar, tweak_term);
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&session.final_nonce.x_only_public_key().0.serialize());
    signature[32..].copy_from_slice(&scalar);
    verify_musig2_signature(
        &session.key_context.key.x_only_public_key().0,
        message,
        &signature,
    )?;
    Ok(signature)
}

pub fn verify_musig2_signature(
    aggregate_key: &XOnlyPublicKey,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), VerificationError> {
    let signature = SchnorrSignature::from_byte_array(*signature);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, message, aggregate_key)
        .map_err(|_| VerificationError::Crypto("MuSig2 aggregate signature"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bolt11Invoice {
    pub network: BitcoinNetwork,
    pub amount_msat: Option<u64>,
    pub timestamp: u64,
    pub payment_hash: [u8; 32],
    pub payment_secret: [u8; 32],
    pub payee: PublicKey,
    pub expiry_seconds: u64,
    pub minimum_final_cltv_delta: u64,
}

pub fn parse_bolt11(invoice: &str) -> Result<Bolt11Invoice, VerificationError> {
    if invoice.is_empty() || invoice.len() > MAX_INVOICE_CHARS || !invoice.is_ascii() {
        return Err(VerificationError::Bounds("BOLT11 invoice length"));
    }
    if invoice.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(VerificationError::Encoding("BOLT11 must be lowercase"));
    }
    let separator = invoice
        .rfind('1')
        .ok_or(VerificationError::Encoding("BOLT11 separator"))?;
    let human_readable = &invoice[..separator];
    let encoded = invoice
        .get(separator + 1..)
        .ok_or(VerificationError::Encoding("BOLT11 data"))?;
    let words = bech32_words(encoded)?;
    if words.len() < 6 + 7 + 104 {
        return Err(VerificationError::Encoding("BOLT11 data length"));
    }
    verify_bech32_checksum(human_readable, &words)?;
    let data = &words[..words.len() - 6];
    if data.len() < 7 + 104 {
        return Err(VerificationError::Encoding("BOLT11 signed data length"));
    }
    let signed_end = data.len() - 104;
    let signed_words = &data[..signed_end];
    let signature_bytes = convert_bits(&data[signed_end..], 5, 8, false)?;
    if signature_bytes.len() != 65 || signature_bytes[64] > 3 {
        return Err(VerificationError::Encoding("BOLT11 recoverable signature"));
    }
    let (network, amount_msat) = parse_invoice_hrp(human_readable)?;
    let timestamp = words_to_u64(&signed_words[..7])?;
    let mut payment_hash = None;
    let mut payment_secret = None;
    let mut explicit_payee = None;
    let mut has_description = false;
    let mut has_description_hash = false;
    let mut expiry_seconds = 3_600;
    let mut minimum_final_cltv_delta = 18;
    let mut position = 7;
    while position < signed_words.len() {
        if signed_words.len() - position < 3 {
            return Err(VerificationError::Encoding("BOLT11 tagged field header"));
        }
        let field_type = signed_words[position];
        let length =
            usize::from(signed_words[position + 1]) * 32 + usize::from(signed_words[position + 2]);
        position += 3;
        let end = position
            .checked_add(length)
            .ok_or(VerificationError::Bounds("BOLT11 field length"))?;
        let field = signed_words
            .get(position..end)
            .ok_or(VerificationError::Encoding("BOLT11 truncated field"))?;
        match field_type {
            1 => set_once_32(&mut payment_hash, field, "payment hash")?,
            16 => set_once_32(&mut payment_secret, field, "payment secret")?,
            13 => {
                if has_description {
                    return Err(VerificationError::Invalid("duplicate BOLT11 description"));
                }
                String::from_utf8(convert_bits(field, 5, 8, false)?)
                    .map_err(|_| VerificationError::Encoding("BOLT11 description UTF-8"))?;
                has_description = true;
            }
            23 => {
                if has_description_hash || field.len() != 52 {
                    return Err(VerificationError::Invalid("BOLT11 description hash"));
                }
                has_description_hash = true;
            }
            19 => {
                if explicit_payee.is_some() || field.len() != 53 {
                    return Err(VerificationError::Invalid("BOLT11 payee field"));
                }
                explicit_payee = Some(
                    PublicKey::from_slice(&convert_bits(field, 5, 8, false)?)
                        .map_err(|_| VerificationError::Crypto("BOLT11 payee key"))?,
                );
            }
            6 => expiry_seconds = minimal_word_integer(field, "BOLT11 expiry")?,
            24 => minimum_final_cltv_delta = minimal_word_integer(field, "BOLT11 CLTV delta")?,
            _ => {}
        }
        position = end;
    }
    if has_description == has_description_hash {
        return Err(VerificationError::Invalid("BOLT11 description choice"));
    }
    let mut signing_preimage = human_readable.as_bytes().to_vec();
    signing_preimage.extend_from_slice(&convert_bits(signed_words, 5, 8, true)?);
    let digest = sha256(&signing_preimage);
    let recovery_id = RecoveryId::try_from(i32::from(signature_bytes[64]))
        .map_err(|_| VerificationError::Crypto("BOLT11 recovery id"))?;
    let recoverable = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)
        .map_err(|_| VerificationError::Crypto("BOLT11 signature encoding"))?;
    let secp = Secp256k1::verification_only();
    let message = Message::from_digest(digest);
    let recovered = secp
        .recover_ecdsa(message, &recoverable)
        .map_err(|_| VerificationError::Crypto("BOLT11 signature recovery"))?;
    if let Some(payee) = explicit_payee {
        let standard = EcdsaSignature::from_compact(&signature_bytes[..64])
            .map_err(|_| VerificationError::Crypto("BOLT11 signature"))?;
        let mut normalized = standard;
        normalized.normalize_s();
        if normalized != standard || payee != recovered {
            return Err(VerificationError::Crypto("BOLT11 payee signature"));
        }
        secp.verify_ecdsa(message, &standard, &payee)
            .map_err(|_| VerificationError::Crypto("BOLT11 signature verification"))?;
    }
    Ok(Bolt11Invoice {
        network,
        amount_msat,
        timestamp,
        payment_hash: payment_hash
            .ok_or(VerificationError::Invalid("missing BOLT11 payment hash"))?,
        payment_secret: payment_secret
            .ok_or(VerificationError::Invalid("missing BOLT11 payment secret"))?,
        payee: recovered,
        expiry_seconds,
        minimum_final_cltv_delta,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timelock {
    BlockHeight(u32),
    UnixTime(u32),
}

pub fn validate_timelock_ladder(timelocks: &[Timelock]) -> Result<(), VerificationError> {
    if timelocks.len() < 2 || timelocks.len() > 16 {
        return Err(VerificationError::Bounds("timelock ladder length"));
    }
    for pair in timelocks.windows(2) {
        match pair {
            [Timelock::BlockHeight(earlier), Timelock::BlockHeight(later)] if earlier < later => {}
            [Timelock::UnixTime(earlier), Timelock::UnixTime(later)] if earlier < later => {}
            [Timelock::BlockHeight(_), Timelock::UnixTime(_)]
            | [Timelock::UnixTime(_), Timelock::BlockHeight(_)] => {
                return Err(VerificationError::Invalid("mixed timelock units"));
            }
            _ => return Err(VerificationError::Invalid("non-increasing timelock ladder")),
        }
    }
    Ok(())
}

pub fn check_cltv(lock_time: Timelock, transaction_lock_time: u32) -> bool {
    match lock_time {
        Timelock::BlockHeight(required) if transaction_lock_time < 500_000_000 => {
            transaction_lock_time >= required
        }
        Timelock::UnixTime(required) if transaction_lock_time >= 500_000_000 => {
            transaction_lock_time >= required
        }
        _ => false,
    }
}

pub fn check_csv(required: u32, sequence: u32) -> bool {
    const DISABLE_FLAG: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;
    const MASK: u32 = 0x0000_ffff;
    required & DISABLE_FLAG == 0
        && sequence & DISABLE_FLAG == 0
        && required & TYPE_FLAG == sequence & TYPE_FLAG
        && sequence & MASK >= required & MASK
}

fn parse_invoice_hrp(hrp: &str) -> Result<(BitcoinNetwork, Option<u64>), VerificationError> {
    let (prefix, network) = if hrp.starts_with("lnbcrt") {
        ("lnbcrt", BitcoinNetwork::Regtest)
    } else if hrp.starts_with("lntbs") {
        ("lntbs", BitcoinNetwork::Signet)
    } else if hrp.starts_with("lntb") {
        ("lntb", BitcoinNetwork::Testnet)
    } else if hrp.starts_with("lnbc") {
        ("lnbc", BitcoinNetwork::Bitcoin)
    } else {
        return Err(VerificationError::Unsupported("BOLT11 network"));
    };
    let amount = &hrp[prefix.len()..];
    if amount.is_empty() {
        return Ok((network, None));
    }
    let (digits, multiplier) = match amount.as_bytes().last().copied() {
        Some(unit @ (b'm' | b'u' | b'n' | b'p')) => (&amount[..amount.len() - 1], Some(unit)),
        _ => (amount, None),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(VerificationError::Encoding("BOLT11 amount"));
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| VerificationError::Bounds("BOLT11 amount"))?;
    let millisatoshis = match multiplier {
        None => value.checked_mul(100_000_000_000),
        Some(b'm') => value.checked_mul(100_000_000),
        Some(b'u') => value.checked_mul(100_000),
        Some(b'n') => value.checked_mul(100),
        Some(b'p') if value % 10 == 0 => Some(value / 10),
        Some(b'p') => None,
        _ => None,
    }
    .ok_or(VerificationError::Bounds("BOLT11 millisatoshi amount"))?;
    Ok((network, Some(millisatoshis)))
}

fn set_once_32(
    destination: &mut Option<[u8; 32]>,
    field: &[u8],
    label: &'static str,
) -> Result<(), VerificationError> {
    if destination.is_some() || field.len() != 52 {
        return Err(VerificationError::Invalid(label));
    }
    let bytes = convert_bits(field, 5, 8, false)?;
    *destination = Some(
        bytes
            .try_into()
            .map_err(|_| VerificationError::Encoding(label))?,
    );
    Ok(())
}

fn minimal_word_integer(words: &[u8], label: &'static str) -> Result<u64, VerificationError> {
    if words.is_empty() || (words.len() > 1 && words[0] == 0) || words.len() > 13 {
        return Err(VerificationError::Encoding(label));
    }
    words_to_u64(words)
}

fn words_to_u64(words: &[u8]) -> Result<u64, VerificationError> {
    let mut value = 0_u64;
    for word in words {
        value = value
            .checked_mul(32)
            .and_then(|value| value.checked_add(u64::from(*word)))
            .ok_or(VerificationError::Bounds("base32 integer"))?;
    }
    Ok(value)
}

fn bech32_words(encoded: &str) -> Result<Vec<u8>, VerificationError> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    encoded
        .bytes()
        .map(|byte| {
            CHARSET
                .iter()
                .position(|candidate| *candidate == byte)
                .and_then(|position| u8::try_from(position).ok())
                .ok_or(VerificationError::Encoding("BOLT11 bech32 character"))
        })
        .collect()
}

fn verify_bech32_checksum(hrp: &str, words: &[u8]) -> Result<(), VerificationError> {
    let mut values = Vec::with_capacity(hrp.len() * 2 + 1 + words.len());
    values.extend(hrp.bytes().map(|byte| byte >> 5));
    values.push(0);
    values.extend(hrp.bytes().map(|byte| byte & 31));
    values.extend_from_slice(words);
    let mut polymod = 1_u32;
    for value in values {
        let top = polymod >> 25;
        polymod = (polymod & 0x01ff_ffff) << 5 ^ u32::from(value);
        for (index, generator) in [
            0x3b6a_57b2_u32,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ]
        .iter()
        .enumerate()
        {
            if (top >> index) & 1 != 0 {
                polymod ^= generator;
            }
        }
    }
    if polymod != 1 {
        return Err(VerificationError::Encoding("BOLT11 checksum"));
    }
    Ok(())
}

fn convert_bits(
    input: &[u8],
    from_bits: u32,
    to_bits: u32,
    pad: bool,
) -> Result<Vec<u8>, VerificationError> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let maximum = (1_u32 << to_bits) - 1;
    let mut output = Vec::new();
    for value in input {
        if u32::from(*value) >> from_bits != 0 {
            return Err(VerificationError::Encoding("base conversion value"));
        }
        accumulator = (accumulator << from_bits) | u32::from(*value);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            output.push(((accumulator >> bits) & maximum) as u8);
        }
    }
    if pad {
        if bits != 0 {
            output.push(((accumulator << (to_bits - bits)) & maximum) as u8);
        }
    } else if bits >= from_bits || ((accumulator << (to_bits - bits)) & maximum) != 0 {
        return Err(VerificationError::Encoding(
            "noncanonical base conversion padding",
        ));
    }
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregatePoint {
    Infinity,
    Point(PublicKey),
}

impl AggregatePoint {
    fn add(self, other: Self) -> Result<Self, VerificationError> {
        match (self, other) {
            (Self::Infinity, point) | (point, Self::Infinity) => Ok(point),
            (Self::Point(left), Self::Point(right)) => {
                match PublicKey::combine_keys(&[&left, &right]) {
                    Ok(point) => Ok(Self::Point(point)),
                    Err(_) => Ok(Self::Infinity),
                }
            }
        }
    }

    fn multiply(self, scalar: &Scalar) -> Result<Self, VerificationError> {
        if scalar == &Scalar::ZERO {
            return Ok(Self::Infinity);
        }
        match self {
            Self::Infinity => Ok(Self::Infinity),
            Self::Point(point) => point
                .mul_tweak(&Secp256k1::verification_only(), scalar)
                .map(Self::Point)
                .map_err(|_| VerificationError::Crypto("MuSig2 point multiplication")),
        }
    }

    fn negate(self) -> Self {
        match self {
            Self::Infinity => Self::Infinity,
            Self::Point(point) => Self::Point(point.negate(&Secp256k1::verification_only())),
        }
    }

    fn serialize_extended(self) -> [u8; 33] {
        match self {
            Self::Infinity => [0; 33],
            Self::Point(point) => point.serialize(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Musig2KeyContext {
    key: PublicKey,
    gacc_negative: bool,
    tacc: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct Musig2SessionValues {
    key_context: Musig2KeyContext,
    nonce_coefficient: Scalar,
    final_nonce: PublicKey,
    challenge: Scalar,
    nonce_odd: bool,
    key_odd: bool,
}

fn validate_musig2_session_bounds(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    tweaks: &[Musig2Tweak],
    message: &[u8],
) -> Result<(), VerificationError> {
    if keys.is_empty() || keys.len() > MAX_MUSIG_KEYS || keys.len() != public_nonces.len() {
        return Err(VerificationError::Bounds("MuSig2 session participants"));
    }
    if tweaks.len() > MAX_MUSIG_TWEAKS {
        return Err(VerificationError::Bounds("MuSig2 tweak count"));
    }
    if message.len() > MAX_MUSIG_MESSAGE_BYTES {
        return Err(VerificationError::Bounds("MuSig2 message byte length"));
    }
    Ok(())
}

fn musig2_nonce_scalar(input: &[u8], index: u8) -> Result<SecretKey, VerificationError> {
    let mut nonce_input = Vec::with_capacity(input.len() + 1);
    nonce_input.extend_from_slice(input);
    nonce_input.push(index);
    let mut value = scalar_bytes_from_hash(tagged_hash("MuSig/nonce", &nonce_input));
    nonce_input.fill(0);
    let nonce = SecretKey::from_byte_array(value)
        .map_err(|_| VerificationError::Crypto("MuSig2 nonce generation produced zero"));
    value.fill(0);
    nonce
}

fn musig2_key_context(
    keys: &[PublicKey],
    tweaks: &[Musig2Tweak],
) -> Result<Musig2KeyContext, VerificationError> {
    if keys.is_empty() || keys.len() > MAX_MUSIG_KEYS || tweaks.len() > MAX_MUSIG_TWEAKS {
        return Err(VerificationError::Bounds("MuSig2 key context"));
    }
    let mut context = Musig2KeyContext {
        key: musig2_aggregate_plain_key(keys)?,
        gacc_negative: false,
        tacc: [0; 32],
    };
    let secp = Secp256k1::verification_only();
    for tweak in tweaks {
        let scalar = Scalar::from_be_bytes(tweak.value)
            .map_err(|_| VerificationError::Crypto("MuSig2 tweak exceeds curve order"))?;
        if tweak.xonly && context.key.x_only_public_key().1 == Parity::Odd {
            context.key = context.key.negate(&secp);
            context.gacc_negative = !context.gacc_negative;
            context.tacc = scalar_negate_mod(context.tacc);
        }
        context.key = context
            .key
            .add_exp_tweak(&secp, &scalar)
            .map_err(|_| VerificationError::Crypto("MuSig2 aggregate tweak"))?;
        context.tacc = scalar_add_mod(context.tacc, tweak.value);
    }
    Ok(context)
}

fn musig2_session_values(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    tweaks: &[Musig2Tweak],
    message: &[u8],
) -> Result<Musig2SessionValues, VerificationError> {
    validate_musig2_session_bounds(keys, public_nonces, tweaks, message)?;
    let key_context = musig2_key_context(keys, tweaks)?;
    let (aggregate_first, aggregate_second) = musig2_aggregate_nonces(public_nonces)?;
    let mut aggregate_nonce = [0_u8; 66];
    aggregate_nonce[..33].copy_from_slice(&aggregate_first.serialize_extended());
    aggregate_nonce[33..].copy_from_slice(&aggregate_second.serialize_extended());
    let mut coefficient_input = Vec::with_capacity(98 + message.len());
    coefficient_input.extend_from_slice(&aggregate_nonce);
    coefficient_input.extend_from_slice(&key_context.key.x_only_public_key().0.serialize());
    coefficient_input.extend_from_slice(message);
    let nonce_coefficient = scalar_from_hash(tagged_hash("MuSig/noncecoef", &coefficient_input))?;
    let combined_nonce = aggregate_first.add(aggregate_second.multiply(&nonce_coefficient)?)?;
    let final_nonce = match combined_nonce {
        AggregatePoint::Infinity => generator_point()?,
        AggregatePoint::Point(point) => point,
    };
    let mut challenge_input = Vec::with_capacity(64 + message.len());
    challenge_input.extend_from_slice(&final_nonce.x_only_public_key().0.serialize());
    challenge_input.extend_from_slice(&key_context.key.x_only_public_key().0.serialize());
    challenge_input.extend_from_slice(message);
    let challenge = scalar_from_hash(tagged_hash("BIP0340/challenge", &challenge_input))?;
    Ok(Musig2SessionValues {
        key_context,
        nonce_coefficient,
        final_nonce,
        challenge,
        nonce_odd: final_nonce.x_only_public_key().1 == Parity::Odd,
        key_odd: key_context.key.x_only_public_key().1 == Parity::Odd,
    })
}

fn musig2_aggregate_nonces(
    public_nonces: &[[u8; 66]],
) -> Result<(AggregatePoint, AggregatePoint), VerificationError> {
    let mut first = AggregatePoint::Infinity;
    let mut second = AggregatePoint::Infinity;
    for nonce in public_nonces {
        let first_point = PublicKey::from_slice(&nonce[..33])
            .map_err(|_| VerificationError::Crypto("MuSig2 first public nonce"))?;
        let second_point = PublicKey::from_slice(&nonce[33..])
            .map_err(|_| VerificationError::Crypto("MuSig2 second public nonce"))?;
        first = first.add(AggregatePoint::Point(first_point))?;
        second = second.add(AggregatePoint::Point(second_point))?;
    }
    Ok((first, second))
}

fn musig2_effective_signer_nonce(
    public_nonce: &[u8; 66],
    nonce_coefficient: &Scalar,
    aggregate_nonce_odd: bool,
) -> Result<AggregatePoint, VerificationError> {
    let first = AggregatePoint::Point(
        PublicKey::from_slice(&public_nonce[..33])
            .map_err(|_| VerificationError::Crypto("MuSig2 first public nonce"))?,
    );
    let second = AggregatePoint::Point(
        PublicKey::from_slice(&public_nonce[33..])
            .map_err(|_| VerificationError::Crypto("MuSig2 second public nonce"))?,
    );
    let nonce = first.add(second.multiply(nonce_coefficient)?)?;
    Ok(if aggregate_nonce_odd {
        nonce.negate()
    } else {
        nonce
    })
}

fn generator_point() -> Result<PublicKey, VerificationError> {
    let mut one = [0_u8; 32];
    one[31] = 1;
    let secret = SecretKey::from_byte_array(one)
        .map_err(|_| VerificationError::Crypto("generator scalar"))?;
    Ok(PublicKey::from_secret_key(
        &Secp256k1::signing_only(),
        &secret,
    ))
}

fn point_from_scalar(value: [u8; 32]) -> Result<AggregatePoint, VerificationError> {
    if value == [0; 32] {
        return Ok(AggregatePoint::Infinity);
    }
    let scalar = SecretKey::from_byte_array(value)
        .map_err(|_| VerificationError::Crypto("MuSig2 scalar point"))?;
    Ok(AggregatePoint::Point(PublicKey::from_secret_key(
        &Secp256k1::signing_only(),
        &scalar,
    )))
}

fn point_multiply(point: PublicKey, scalar: &Scalar) -> Result<AggregatePoint, VerificationError> {
    AggregatePoint::Point(point).multiply(scalar)
}

fn point_multiply_aggregate(
    point: AggregatePoint,
    scalar: &Scalar,
) -> Result<AggregatePoint, VerificationError> {
    point.multiply(scalar)
}

fn multiply_secret_term(
    secret: &SecretKey,
    scalar: &Scalar,
) -> Result<Option<SecretKey>, VerificationError> {
    if scalar == &Scalar::ZERO {
        return Ok(None);
    }
    (*secret)
        .mul_tweak(scalar)
        .map(Some)
        .map_err(|_| VerificationError::Crypto("MuSig2 secret scalar multiplication"))
}

fn add_secret_terms(
    left: &Option<SecretKey>,
    right: &Option<SecretKey>,
) -> Result<Option<SecretKey>, VerificationError> {
    match (left, right) {
        (None, right) => Ok(*right),
        (left, None) => Ok(*left),
        (Some(left), Some(right)) => match (*left).add_tweak(&Scalar::from(*right)) {
            Ok(sum) => Ok(Some(sum)),
            Err(_) => Ok(None),
        },
    }
}

fn erase_secret_term(term: &mut Option<SecretKey>) {
    if let Some(secret) = term.as_mut() {
        secret.non_secure_erase();
    }
    *term = None;
}

fn scalar_multiply_public(left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], VerificationError> {
    if left >= CURVE_ORDER || right >= CURVE_ORDER {
        return Err(VerificationError::Crypto(
            "MuSig2 scalar multiplication input",
        ));
    }
    let mut result = [0_u8; 32];
    for byte in left {
        for bit in (0..8).rev() {
            result = scalar_add_mod(result, result);
            if (byte >> bit) & 1 == 1 {
                result = scalar_add_mod(result, right);
            }
        }
    }
    Ok(result)
}

fn scalar_add_mod(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut sum = [0_u8; 33];
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let value = u16::from(left[index]) + u16::from(right[index]) + carry;
        sum[index + 1] = value as u8;
        carry = value >> 8;
    }
    sum[0] = carry as u8;
    let mut order = [0_u8; 33];
    order[1..].copy_from_slice(&CURVE_ORDER);
    if sum >= order {
        subtract_be(&mut sum, &order);
    }
    let mut reduced = [0_u8; 32];
    reduced.copy_from_slice(&sum[1..]);
    reduced
}

fn scalar_negate_mod(value: [u8; 32]) -> [u8; 32] {
    if value == [0; 32] {
        return value;
    }
    let mut order = CURVE_ORDER;
    subtract_be(&mut order, &value);
    order
}

fn subtract_be<const N: usize>(left: &mut [u8; N], right: &[u8; N]) {
    let mut borrow = 0_u16;
    for index in (0..N).rev() {
        let minuend = u16::from(left[index]);
        let subtrahend = u16::from(right[index]) + borrow;
        if minuend >= subtrahend {
            left[index] = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            left[index] = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
}

fn scalar_bytes_from_hash(mut hash: [u8; 32]) -> [u8; 32] {
    if hash >= CURVE_ORDER {
        subtract_be(&mut hash, &CURVE_ORDER);
    }
    hash
}

fn scalar_from_hash(hash: [u8; 32]) -> Result<Scalar, VerificationError> {
    Scalar::from_be_bytes(scalar_bytes_from_hash(hash))
        .map_err(|_| VerificationError::Crypto("scalar exceeds curve order"))
}

fn musig2_key_material(keys: &[PublicKey]) -> (Vec<[u8; 33]>, [u8; 32], [u8; 33]) {
    let serialized: Vec<[u8; 33]> = keys.iter().map(PublicKey::serialize).collect();
    let mut list = Vec::with_capacity(serialized.len() * 33);
    for key in &serialized {
        list.extend_from_slice(key);
    }
    let list_hash = tagged_hash("KeyAgg list", &list);
    let second = serialized
        .iter()
        .find(|key| **key != serialized[0])
        .copied()
        .unwrap_or([0_u8; 33]);
    (serialized, list_hash, second)
}

fn musig2_key_coefficient(
    key: [u8; 33],
    list_hash: [u8; 32],
    second_key: [u8; 33],
) -> Result<Scalar, VerificationError> {
    if key == second_key {
        return Ok(Scalar::ONE);
    }
    let mut input = Vec::with_capacity(65);
    input.extend_from_slice(&list_hash);
    input.extend_from_slice(&key);
    scalar_from_hash(tagged_hash("KeyAgg coefficient", &input))
}

fn musig2_aggregate_plain_key(keys: &[PublicKey]) -> Result<PublicKey, VerificationError> {
    let (serialized, list_hash, second) = musig2_key_material(keys);
    let secp = Secp256k1::verification_only();
    let mut weighted = Vec::with_capacity(keys.len());
    for (key, encoded) in keys.iter().zip(serialized) {
        weighted.push(
            key.mul_tweak(&secp, &musig2_key_coefficient(encoded, list_hash, second)?)
                .map_err(|_| VerificationError::Crypto("MuSig2 key coefficient"))?,
        );
    }
    combine_public_keys(&weighted, "MuSig2 aggregate key")
}

fn combine_public_keys(
    keys: &[PublicKey],
    label: &'static str,
) -> Result<PublicKey, VerificationError> {
    let references: Vec<&PublicKey> = keys.iter().collect();
    PublicKey::combine_keys(&references).map_err(|_| VerificationError::Crypto(label))
}

fn read_script_length(
    script: &[u8],
    position: &mut usize,
    byte_count: usize,
) -> Result<usize, VerificationError> {
    let end = position
        .checked_add(byte_count)
        .ok_or(VerificationError::Bounds("script length overflow"))?;
    let bytes = script
        .get(*position..end)
        .ok_or(VerificationError::Encoding("truncated script length"))?;
    *position = end;
    let mut value = 0_u32;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u32::from(*byte) << (index * 8);
    }
    usize::try_from(value).map_err(|_| VerificationError::Bounds("script push length"))
}

fn parse_script_number(bytes: &[u8]) -> Result<u32, VerificationError> {
    if bytes.is_empty() || bytes.len() > 5 || bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(VerificationError::Invalid("swap timelock script number"));
    }
    if bytes.last().is_some_and(|byte| byte & 0x7f == 0)
        && (bytes.len() == 1 || bytes[bytes.len() - 2] & 0x80 == 0)
    {
        return Err(VerificationError::Encoding(
            "noncanonical swap timelock script number",
        ));
    }
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    u32::try_from(value).map_err(|_| VerificationError::Bounds("swap timelock value"))
}

fn validate_taproot_spend_inputs(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
    script: &[u8],
    control_block: &[u8],
) -> Result<(), VerificationError> {
    if transaction.inputs.is_empty()
        || transaction.inputs.len() > MAX_INPUTS
        || transaction.inputs.len() != prevouts.len()
    {
        return Err(VerificationError::Invalid("Taproot prevout count"));
    }
    if transaction.outputs.is_empty() || transaction.outputs.len() > MAX_OUTPUTS {
        return Err(VerificationError::Bounds(
            "Taproot transaction output count",
        ));
    }
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(VerificationError::Bounds("Taproot input index"))?;
    if !input.script_sig.is_empty() {
        return Err(VerificationError::Invalid(
            "Taproot scriptSig must be empty",
        ));
    }
    for input in &transaction.inputs {
        if input.script_sig.len() > MAX_SCRIPT_BYTES {
            return Err(VerificationError::Bounds("Taproot scriptSig byte length"));
        }
    }
    for prevout in prevouts {
        if prevout.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(VerificationError::Bounds(
                "Taproot prevout scriptPubKey length",
            ));
        }
    }
    let prevout = &prevouts[input_index];
    let output_key = taproot_output_key_from_script_pubkey(&prevout.script_pubkey)?;
    if control_block.first().map(|byte| byte & 0xfe) != Some(TAPROOT_LEAF_VERSION) {
        return Err(VerificationError::Unsupported("Taproot leaf version"));
    }
    parse_swap_leaf_script(script)?;
    verify_control_block(&output_key, script, control_block)
}

fn validate_taproot_key_spend_inputs(
    transaction: &Transaction,
    prevouts: &[TransactionOutput],
    input_index: usize,
) -> Result<(), VerificationError> {
    if transaction.inputs.is_empty()
        || transaction.inputs.len() > MAX_INPUTS
        || transaction.inputs.len() != prevouts.len()
    {
        return Err(VerificationError::Invalid("Taproot prevout count"));
    }
    if transaction.outputs.is_empty() || transaction.outputs.len() > MAX_OUTPUTS {
        return Err(VerificationError::Bounds(
            "Taproot transaction output count",
        ));
    }
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(VerificationError::Bounds("Taproot input index"))?;
    if !input.script_sig.is_empty() {
        return Err(VerificationError::Invalid(
            "Taproot scriptSig must be empty",
        ));
    }
    for input in &transaction.inputs {
        if !input.script_sig.is_empty() {
            return Err(VerificationError::Invalid(
                "Taproot scriptSig must be empty",
            ));
        }
    }
    for prevout in prevouts {
        if prevout.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(VerificationError::Bounds(
                "Taproot prevout scriptPubKey length",
            ));
        }
    }
    taproot_output_key_from_script_pubkey(&prevouts[input_index].script_pubkey)?;
    Ok(())
}

fn taproot_output_key_from_script_pubkey(
    script_pubkey: &[u8],
) -> Result<XOnlyPublicKey, VerificationError> {
    let output_key =
        script_pubkey
            .strip_prefix(&[0x51, 0x20])
            .ok_or(VerificationError::Invalid(
                "prevout is not a v1 Taproot output",
            ))?;
    XOnlyPublicKey::from_byte_array(
        output_key
            .try_into()
            .map_err(|_| VerificationError::Encoding("Taproot output key length"))?,
    )
    .map_err(|_| VerificationError::Crypto("Taproot output key"))
}

fn validate_control_block_shape(control_block: &[u8]) -> Result<(), VerificationError> {
    if control_block.len() < 33
        || control_block.len() > 33 + 32 * 128
        || (control_block.len() - 33) % 32 != 0
        || control_block.first().map(|byte| byte & 0xfe) != Some(TAPROOT_LEAF_VERSION)
    {
        return Err(VerificationError::Encoding("Taproot control block shape"));
    }
    Ok(())
}

fn exact_default_signature(signature: &[u8]) -> Result<[u8; 64], VerificationError> {
    signature.try_into().map_err(|_| {
        VerificationError::Invalid("Taproot signature must use implicit SIGHASH_DEFAULT")
    })
}

fn validate_witness_items(witness: &[Vec<u8>]) -> Result<(), VerificationError> {
    if witness.len() > MAX_WITNESS_ITEMS {
        return Err(VerificationError::Bounds("witness item count"));
    }
    if witness
        .iter()
        .any(|item| item.len() > MAX_WITNESS_ITEM_BYTES)
    {
        return Err(VerificationError::Bounds("witness item byte length"));
    }
    Ok(())
}

fn compact_size_length(value: usize) -> Result<u64, VerificationError> {
    if value < 0xfd {
        Ok(1)
    } else if value <= usize::from(u16::MAX) {
        Ok(3)
    } else if value <= usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        Ok(5)
    } else {
        u64::try_from(value)
            .map(|_| 9)
            .map_err(|_| VerificationError::Bounds("compact size length"))
    }
}

fn is_witness_program(script_pubkey: &[u8]) -> bool {
    let Some((&version, rest)) = script_pubkey.split_first() else {
        return false;
    };
    let Some((&program_length, program)) = rest.split_first() else {
        return false;
    };
    matches!(version, 0x00 | 0x51..=0x60)
        && matches!(program_length, 2..=40)
        && program.len() == usize::from(program_length)
}

fn fee_for_size(rate_sat_per_kilobyte: u64, size: u64) -> Result<u64, VerificationError> {
    let fee = rate_sat_per_kilobyte
        .checked_mul(size)
        .ok_or(VerificationError::Bounds("fee calculation"))?
        / 1_000;
    Ok(if fee == 0 && rate_sat_per_kilobyte > 0 {
        1
    } else {
        fee
    })
}

fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}

fn display_hash(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes.reverse();
    bytes
}

fn write_var_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), VerificationError> {
    write_compact_size(bytes.len(), output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_compact_size(value: usize, output: &mut Vec<u8>) -> Result<(), VerificationError> {
    if value < 0xfd {
        output.push(value as u8);
    } else if value <= usize::from(u16::MAX) {
        output.push(0xfd);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        output.push(0xfe);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        output.push(0xff);
        output.extend_from_slice(&(value as u64).to_le_bytes());
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn peek(&self) -> Result<u8, VerificationError> {
        self.peek_at(0)
    }

    fn peek_at(&self, offset: usize) -> Result<u8, VerificationError> {
        self.bytes
            .get(self.position + offset)
            .copied()
            .ok_or(VerificationError::Encoding("truncated transaction"))
    }

    fn read_u8(&mut self) -> Result<u8, VerificationError> {
        let value = self.peek()?;
        self.position += 1;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], VerificationError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(VerificationError::Bounds("transaction offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(VerificationError::Encoding("truncated transaction"))?
            .try_into()
            .map_err(|_| VerificationError::Encoding("transaction field length"))?;
        self.position = end;
        Ok(value)
    }

    fn read_i32(&mut self) -> Result<i32, VerificationError> {
        Ok(i32::from_le_bytes(self.read_array()?))
    }

    fn read_u16(&mut self) -> Result<u16, VerificationError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, VerificationError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, VerificationError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_compact_size(&mut self, maximum: usize) -> Result<usize, VerificationError> {
        let marker = self.read_u8()?;
        let value = match marker {
            0..=0xfc => u64::from(marker),
            0xfd => {
                let value = u64::from(self.read_u16()?);
                if value < 0xfd {
                    return Err(VerificationError::Encoding("noncanonical compact size"));
                }
                value
            }
            0xfe => {
                let value = u64::from(self.read_u32()?);
                if value <= u64::from(u16::MAX) {
                    return Err(VerificationError::Encoding("noncanonical compact size"));
                }
                value
            }
            0xff => {
                let value = self.read_u64()?;
                if value <= u64::from(u32::MAX) {
                    return Err(VerificationError::Encoding("noncanonical compact size"));
                }
                value
            }
        };
        let value = usize::try_from(value)
            .map_err(|_| VerificationError::Bounds("compact size platform range"))?;
        if value > maximum {
            return Err(VerificationError::Bounds("compact size configured limit"));
        }
        Ok(value)
    }

    fn read_var_bytes(&mut self, maximum: usize) -> Result<&'a [u8], VerificationError> {
        let length = self.read_compact_size(maximum)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(VerificationError::Bounds("transaction offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(VerificationError::Encoding("truncated transaction bytes"))?;
        self.position = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Official BIP-327 vectors. Provenance and the replay/gap table live in
    // `tests/fixtures/bip327/README.md`. Everything reachable through the
    // public API is replayed from `tests/musig2_bip327.rs`; the cases below
    // are the ones that need a caller-fixed secret nonce or the exact
    // aggregate-nonce serialization, neither of which is — or should be —
    // a production input.
    const NONCE_GEN_VECTORS: &str =
        include_str!("../../../tests/fixtures/bip327/nonce_gen_vectors.json");
    const NONCE_AGG_VECTORS: &str =
        include_str!("../../../tests/fixtures/bip327/nonce_agg_vectors.json");
    const SIGN_VERIFY_VECTORS: &str =
        include_str!("../../../tests/fixtures/bip327/sign_verify_vectors.json");
    const SIG_AGG_VECTORS: &str =
        include_str!("../../../tests/fixtures/bip327/sig_agg_vectors.json");
    const TWEAK_VECTORS: &str = include_str!("../../../tests/fixtures/bip327/tweak_vectors.json");

    #[test]
    fn bip327_nonce_aggregation_valid_vectors() {
        let vectors: Value = serde_json::from_str(NONCE_AGG_VECTORS).expect("nonce_agg vectors");
        let cases = vectors["valid_test_cases"].as_array().expect("valid cases");
        assert_eq!(
            cases.len(),
            2,
            "upstream nonce_agg valid case count changed"
        );

        for (case_index, case) in cases.iter().enumerate() {
            let nonces = vector_nonces(&vectors["pnonces"], &case["pnonce_indices"]);
            let (first, second) =
                musig2_aggregate_nonces(&nonces).expect("official nonce aggregation");
            let mut aggregate = [0_u8; 66];
            aggregate[..33].copy_from_slice(&first.serialize_extended());
            aggregate[33..].copy_from_slice(&second.serialize_extended());
            assert_eq!(
                aggregate,
                vector_fixed::<66>(vector_text(&case["expected"])),
                "nonce_agg valid case {case_index} produced the wrong aggregate nonce",
            );
        }
    }

    #[test]
    fn bip327_nonce_aggregation_error_vectors() {
        let vectors: Value = serde_json::from_str(NONCE_AGG_VECTORS).expect("nonce_agg vectors");
        let cases = vectors["error_test_cases"].as_array().expect("error cases");
        assert_eq!(
            cases.len(),
            3,
            "upstream nonce_agg error case count changed"
        );

        for (case_index, case) in cases.iter().enumerate() {
            let nonces = vector_nonces(&vectors["pnonces"], &case["pnonce_indices"]);
            assert!(
                musig2_aggregate_nonces(&nonces).is_err(),
                "nonce_agg error case {case_index} aggregated a malformed public nonce",
            );
        }
    }

    #[test]
    fn bip327_nonce_generation_secnonce_vectors() {
        let vectors: Value = serde_json::from_str(NONCE_GEN_VECTORS).expect("nonce_gen vectors");
        let cases = vectors["test_cases"].as_array().expect("test cases");
        let mut replayed = 0;

        for (case_index, case) in cases.iter().enumerate() {
            // The all-optional-inputs-absent case has no representable
            // argument; see the fixture README.
            if case["sk"].is_null()
                || case["aggpk"].is_null()
                || case["msg"].is_null()
                || case["extra_in"].is_null()
            {
                continue;
            }
            let secret_key =
                SecretKey::from_byte_array(vector_fixed::<32>(vector_text(&case["sk"])))
                    .expect("official secret key");
            let nonce = musig2_nonce_gen(
                &secret_key,
                &vector_fixed::<32>(vector_text(&case["aggpk"])),
                &vector_decode(vector_text(&case["msg"])),
                &vector_decode(vector_text(&case["extra_in"])),
                vector_fixed::<32>(vector_text(&case["rand_"])),
            )
            .expect("official nonce generation");

            let expected = vector_decode(vector_text(&case["expected_secnonce"]));
            assert_eq!(expected.len(), 97);
            assert_eq!(
                nonce.first,
                expected[..32],
                "nonce_gen case {case_index} first secret nonce scalar differs",
            );
            assert_eq!(
                nonce.second,
                expected[32..64],
                "nonce_gen case {case_index} second secret nonce scalar differs",
            );
            assert_eq!(
                nonce.public_key,
                expected[64..],
                "nonce_gen case {case_index} bound public key differs",
            );
            replayed += 1;
        }

        assert_eq!(replayed, 3);
    }

    #[test]
    fn bip327_partial_signing_valid_vectors() {
        let vectors: Value =
            serde_json::from_str(SIGN_VERIFY_VECTORS).expect("sign_verify vectors");
        let secret_key =
            SecretKey::from_byte_array(vector_fixed::<32>(vector_text(&vectors["sk"])))
                .expect("official secret key");
        let cases = vectors["valid_test_cases"].as_array().expect("valid cases");
        assert_eq!(
            cases.len(),
            6,
            "upstream sign_verify valid case count changed"
        );

        for (case_index, case) in cases.iter().enumerate() {
            let keys = vector_keys(&vectors["pubkeys"], &case["key_indices"]);
            let nonces = vector_nonces(&vectors["pnonces"], &case["nonce_indices"]);
            let message = vector_decode(vector_text(
                &vectors["msgs"][vector_index(&case["msg_index"])],
            ));
            let signer_index = vector_index(&case["signer_index"]);
            let mut secret_nonce = vector_secret_nonce(
                vector_text(&vectors["secnonces"][0]),
                Some(nonces[signer_index]),
            );

            let partial = musig2_partial_sign(
                &mut secret_nonce,
                &secret_key,
                &keys,
                &nonces,
                &[],
                &message,
            )
            .unwrap_or_else(|error| {
                panic!("sign_verify valid case {case_index} failed to sign: {error}")
            });
            assert_eq!(
                partial,
                vector_fixed::<32>(vector_text(&case["expected"])),
                "sign_verify valid case {case_index} produced the wrong partial signature",
            );
            assert!(secret_nonce.is_consumed());
        }
    }

    #[test]
    fn bip327_tweaked_partial_signing_valid_vectors() {
        let vectors: Value = serde_json::from_str(TWEAK_VECTORS).expect("tweak vectors");
        let secret_key =
            SecretKey::from_byte_array(vector_fixed::<32>(vector_text(&vectors["sk"])))
                .expect("official secret key");
        let message = vector_decode(vector_text(&vectors["msg"]));
        let cases = vectors["valid_test_cases"].as_array().expect("valid cases");
        assert_eq!(cases.len(), 5, "upstream tweak valid case count changed");

        for (case_index, case) in cases.iter().enumerate() {
            let keys = vector_keys(&vectors["pubkeys"], &case["key_indices"]);
            let nonces = vector_nonces(&vectors["pnonces"], &case["nonce_indices"]);
            let tweaks = vector_tweaks(
                &vectors["tweaks"],
                &case["tweak_indices"],
                &case["is_xonly"],
            );
            let signer_index = vector_index(&case["signer_index"]);
            let mut secret_nonce = vector_secret_nonce(
                vector_text(&vectors["secnonce"]),
                Some(nonces[signer_index]),
            );

            let partial = musig2_partial_sign(
                &mut secret_nonce,
                &secret_key,
                &keys,
                &nonces,
                &tweaks,
                &message,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "tweak valid case {case_index} ({}) failed to sign: {error}",
                    vector_text(&case["comment"]),
                )
            });
            assert_eq!(
                partial,
                vector_fixed::<32>(vector_text(&case["expected"])),
                "tweak valid case {case_index} produced the wrong partial signature",
            );
        }
    }

    #[test]
    fn bip327_partial_signing_error_vectors() {
        let vectors: Value =
            serde_json::from_str(SIGN_VERIFY_VECTORS).expect("sign_verify vectors");
        let secret_key =
            SecretKey::from_byte_array(vector_fixed::<32>(vector_text(&vectors["sk"])))
                .expect("official secret key");
        let cases = vectors["sign_error_test_cases"]
            .as_array()
            .expect("sign error cases");
        let mut replayed = 0;

        for (case_index, case) in cases.iter().enumerate() {
            // The three "aggnonce" cases have no aggregate-nonce parameter to
            // corrupt here; `tests/musig2_bip327.rs` replays those bytes as
            // per-signer nonces instead. The "pubkey" case is refused before
            // any MuSig2 call because the key does not parse.
            if case["error"]["type"] != "value" {
                continue;
            }
            let indices = case["key_indices"].as_array().expect("key indices");
            let keys = vector_keys(&vectors["pubkeys"], &case["key_indices"]);
            let nonces: Vec<[u8; 66]> = (0..indices.len())
                .map(|position| vector_fixed::<66>(vector_text(&vectors["pnonces"][position])))
                .collect();
            let message = vector_decode(vector_text(
                &vectors["msgs"][vector_index(&case["msg_index"])],
            ));
            let secnonce =
                vector_text(&vectors["secnonces"][vector_index(&case["secnonce_index"])]);
            let mut secret_nonce = vector_secret_nonce(secnonce, Some(nonces[0]));

            let outcome = musig2_partial_sign(
                &mut secret_nonce,
                &secret_key,
                &keys,
                &nonces,
                &[],
                &message,
            );
            assert!(
                outcome.is_err(),
                "sign_error case {case_index} ({}) produced a partial signature",
                vector_text(&case["comment"]),
            );
            replayed += 1;
        }

        assert_eq!(
            replayed, 2,
            "expected the two non-aggnonce sign_error cases"
        );
    }

    #[test]
    fn bip327_signature_aggregation_binds_upstream_aggregate_nonces() {
        // The sig_agg vectors publish the aggregate nonce alongside the
        // per-signer nonces. Immortal derives the aggregate itself, so this
        // pins that derivation against upstream rather than trusting the
        // final signature to catch a mismatch.
        let vectors: Value = serde_json::from_str(SIG_AGG_VECTORS).expect("sig_agg vectors");
        for (case_index, case) in vectors["valid_test_cases"]
            .as_array()
            .expect("valid cases")
            .iter()
            .enumerate()
        {
            let nonces = vector_nonces(&vectors["pnonces"], &case["nonce_indices"]);
            let (first, second) =
                musig2_aggregate_nonces(&nonces).expect("official nonce aggregation");
            let mut aggregate = [0_u8; 66];
            aggregate[..33].copy_from_slice(&first.serialize_extended());
            aggregate[33..].copy_from_slice(&second.serialize_extended());
            assert_eq!(
                aggregate,
                vector_fixed::<66>(vector_text(&case["aggnonce"])),
                "sig_agg valid case {case_index} disagrees with the upstream aggregate nonce",
            );
        }
    }

    fn vector_secret_nonce(encoded: &str, public_nonce: Option<[u8; 66]>) -> Musig2SecretNonce {
        let bytes = vector_decode(encoded);
        assert_eq!(bytes.len(), 97, "BIP-327 secnonce is 97 bytes");
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        let mut public_key = [0_u8; 33];
        first.copy_from_slice(&bytes[..32]);
        second.copy_from_slice(&bytes[32..64]);
        public_key.copy_from_slice(&bytes[64..]);

        // Where the vector's secret nonce is a live scalar pair, confirm it
        // really is the preimage of the public nonce the same vector hands the
        // other signers before feeding it to the signer.
        if let (Some(expected), Ok(k1), Ok(k2)) = (
            public_nonce,
            SecretKey::from_byte_array(first),
            SecretKey::from_byte_array(second),
        ) {
            let secp = Secp256k1::signing_only();
            let mut derived = [0_u8; 66];
            derived[..33].copy_from_slice(&PublicKey::from_secret_key(&secp, &k1).serialize());
            derived[33..].copy_from_slice(&PublicKey::from_secret_key(&secp, &k2).serialize());
            assert_eq!(
                derived, expected,
                "BIP-327 secnonce does not match the paired public nonce",
            );
        }

        Musig2SecretNonce {
            first,
            second,
            public_key,
            public_nonce: public_nonce.unwrap_or([0_u8; 66]),
            consumed: false,
        }
    }

    fn vector_keys(pubkeys: &Value, indices: &Value) -> Vec<PublicKey> {
        indices
            .as_array()
            .expect("key indices")
            .iter()
            .map(|index| {
                PublicKey::from_slice(&vector_fixed::<33>(vector_text(
                    &pubkeys[vector_index(index)],
                )))
                .expect("official public key")
            })
            .collect()
    }

    fn vector_nonces(pnonces: &Value, indices: &Value) -> Vec<[u8; 66]> {
        indices
            .as_array()
            .expect("nonce indices")
            .iter()
            .map(|index| vector_fixed::<66>(vector_text(&pnonces[vector_index(index)])))
            .collect()
    }

    fn vector_tweaks(tweaks: &Value, indices: &Value, is_xonly: &Value) -> Vec<Musig2Tweak> {
        indices
            .as_array()
            .expect("tweak indices")
            .iter()
            .zip(is_xonly.as_array().expect("is_xonly flags"))
            .map(|(index, xonly)| Musig2Tweak {
                value: vector_fixed::<32>(vector_text(&tweaks[vector_index(index)])),
                xonly: xonly.as_bool().expect("is_xonly is a boolean"),
            })
            .collect()
    }

    fn vector_text(value: &Value) -> &str {
        value.as_str().expect("BIP-327 vector field is a string")
    }

    fn vector_index(value: &Value) -> usize {
        usize::try_from(value.as_u64().expect("BIP-327 index is an integer"))
            .expect("BIP-327 index fits in usize")
    }

    fn vector_decode(input: &str) -> Vec<u8> {
        assert!(input.len() % 2 == 0, "hex has an even length");
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (vector_nibble(pair[0]) << 4) | vector_nibble(pair[1]))
            .collect()
    }

    fn vector_fixed<const N: usize>(input: &str) -> [u8; N] {
        let decoded = vector_decode(input);
        assert_eq!(decoded.len(), N, "hex field has the wrong byte length");
        let mut output = [0_u8; N];
        output.copy_from_slice(&decoded);
        output
    }

    fn vector_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("BIP-327 vector must be hexadecimal"),
        }
    }

    #[test]
    fn bip327_partial_signing_vector_matches_and_consumes_nonce() {
        let secret_key = SecretKey::from_byte_array(hex(
            "7fb9e0e687ada1eebf7ecfe2f21e73ebdb51a7d450948dfe8d76d7f2d1007671",
        ))
        .expect("official BIP-327 secret key");
        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret_key);
        let public_nonce = hex(
            "0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480",
        );
        let mut secret_nonce = Musig2SecretNonce {
            first: hex("508b81a611f100a6b2b6b29656590898af488bcf2e1f55cf22e5cfb84421fe61"),
            second: hex("fa27fd49b1d50085b481285e1ca205d55c82cc1b31ff5cd54a489829355901f7"),
            public_key: public_key.serialize(),
            public_nonce,
            consumed: false,
        };
        let keys = [
            public_key,
            PublicKey::from_slice(&hex::<33>(
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ))
            .expect("official BIP-327 public key"),
            PublicKey::from_slice(&hex::<33>(
                "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba661",
            ))
            .expect("official BIP-327 public key"),
        ];
        let public_nonces = [
            public_nonce,
            hex(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            hex(
                "032de2662628c90b03f5e720284eb52ff7d71f4284f627b68a853d78c78e1ffe9303e4c5524e83ffe1493b9077cf1ca6beb2090c93d930321071ad40b2f44e599046",
            ),
        ];
        let message = hex::<32>("f95466d086770e689964664219266fe5ed215c92ae20bab5c9d79addddf3c0cf");
        let partial = musig2_partial_sign(
            &mut secret_nonce,
            &secret_key,
            &keys,
            &public_nonces,
            &[],
            &message,
        )
        .expect("official BIP-327 partial signature");
        assert_eq!(
            partial,
            hex("012abbcb52b3016ac03ad82395a1a415c48b93def78718e62a7a90052fe224fb")
        );
        assert!(secret_nonce.is_consumed());
        assert!(
            musig2_partial_sign(
                &mut secret_nonce,
                &secret_key,
                &keys,
                &public_nonces,
                &[],
                &message,
            )
            .is_err()
        );
    }

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
            output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        output
    }

    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("test vector must be lowercase hexadecimal"),
        }
    }
}
