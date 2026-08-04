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
        Self {
            version,
            inputs,
            outputs,
            lock_time,
            has_witness: false,
        }
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

pub fn verify_musig2_partial_signature(
    keys: &[PublicKey],
    public_nonces: &[[u8; 66]],
    signer_index: usize,
    message: &[u8],
    partial_signature: &[u8; 32],
) -> Result<(), VerificationError> {
    if keys.is_empty()
        || keys.len() > MAX_MUSIG_KEYS
        || keys.len() != public_nonces.len()
        || signer_index >= keys.len()
    {
        return Err(VerificationError::Bounds("MuSig2 session participants"));
    }
    let secp = Secp256k1::verification_only();
    let mut first_nonces = Vec::with_capacity(public_nonces.len());
    let mut second_nonces = Vec::with_capacity(public_nonces.len());
    for nonce in public_nonces {
        first_nonces.push(
            PublicKey::from_slice(&nonce[..33])
                .map_err(|_| VerificationError::Crypto("MuSig2 first public nonce"))?,
        );
        second_nonces.push(
            PublicKey::from_slice(&nonce[33..])
                .map_err(|_| VerificationError::Crypto("MuSig2 second public nonce"))?,
        );
    }
    let aggregate_first = combine_public_keys(&first_nonces, "MuSig2 aggregate first nonce")?;
    let aggregate_second = combine_public_keys(&second_nonces, "MuSig2 aggregate second nonce")?;
    let aggregate_key = musig2_aggregate_plain_key(keys)?;
    let aggregate_xonly = aggregate_key.x_only_public_key();
    let mut nonce_coefficient_input = Vec::with_capacity(98 + message.len());
    nonce_coefficient_input.extend_from_slice(&aggregate_first.serialize());
    nonce_coefficient_input.extend_from_slice(&aggregate_second.serialize());
    nonce_coefficient_input.extend_from_slice(&aggregate_xonly.0.serialize());
    nonce_coefficient_input.extend_from_slice(message);
    let nonce_coefficient =
        scalar_from_hash(tagged_hash("MuSig/noncecoef", &nonce_coefficient_input))?;
    let weighted_second = aggregate_second
        .mul_tweak(&secp, &nonce_coefficient)
        .map_err(|_| VerificationError::Crypto("MuSig2 weighted aggregate nonce"))?;
    let aggregate_nonce = PublicKey::combine_keys(&[&aggregate_first, &weighted_second])
        .map_err(|_| VerificationError::Crypto("MuSig2 final aggregate nonce"))?;
    let aggregate_nonce_xonly = aggregate_nonce.x_only_public_key();
    let mut challenge_input = Vec::with_capacity(64 + message.len());
    challenge_input.extend_from_slice(&aggregate_nonce_xonly.0.serialize());
    challenge_input.extend_from_slice(&aggregate_xonly.0.serialize());
    challenge_input.extend_from_slice(message);
    let challenge = scalar_from_hash(tagged_hash("BIP0340/challenge", &challenge_input))?;

    let signer_first = first_nonces[signer_index];
    let signer_second = second_nonces[signer_index]
        .mul_tweak(&secp, &nonce_coefficient)
        .map_err(|_| VerificationError::Crypto("MuSig2 weighted signer nonce"))?;
    let mut signer_nonce = PublicKey::combine_keys(&[&signer_first, &signer_second])
        .map_err(|_| VerificationError::Crypto("MuSig2 signer nonce"))?;
    if aggregate_nonce_xonly.1 == Parity::Odd {
        signer_nonce = signer_nonce.negate(&secp);
    }

    let (serialized, list_hash, second_key) = musig2_key_material(keys);
    let coefficient = musig2_key_coefficient(serialized[signer_index], list_hash, second_key)?;
    let mut signer_key = keys[signer_index]
        .mul_tweak(&secp, &coefficient)
        .and_then(|key| key.mul_tweak(&secp, &challenge))
        .map_err(|_| VerificationError::Crypto("MuSig2 signer challenge"))?;
    if aggregate_xonly.1 == Parity::Odd {
        signer_key = signer_key.negate(&secp);
    }
    let expected = PublicKey::combine_keys(&[&signer_nonce, &signer_key])
        .map_err(|_| VerificationError::Crypto("MuSig2 partial signature equation"))?;
    let scalar = SecretKey::from_byte_array(*partial_signature)
        .map_err(|_| VerificationError::Crypto("MuSig2 partial signature scalar"))?;
    let supplied = PublicKey::from_secret_key(&Secp256k1::signing_only(), &scalar);
    if supplied != expected {
        return Err(VerificationError::Crypto(
            "MuSig2 partial signature verification",
        ));
    }
    Ok(())
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

fn scalar_from_hash(mut hash: [u8; 32]) -> Result<Scalar, VerificationError> {
    const CURVE_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    if hash >= CURVE_ORDER {
        let mut borrow = 0_u16;
        for index in (0..32).rev() {
            let left = u16::from(hash[index]);
            let right = u16::from(CURVE_ORDER[index]) + borrow;
            if left >= right {
                hash[index] = (left - right) as u8;
                borrow = 0;
            } else {
                hash[index] = (left + 256 - right) as u8;
                borrow = 1;
            }
        }
    }
    Scalar::from_be_bytes(hash).map_err(|_| VerificationError::Crypto("scalar exceeds curve order"))
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
