//! Bounded Elements transaction and own-output verification for MKT-SWP Liquid legs.

use core::fmt;

use secp256k1::{
    Keypair, Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey, schnorr::Signature,
};

use crate::mkt_swp_verify::{sha256, tagged_hash};

const MAX_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_INPUTS: usize = 4_096;
const MAX_OUTPUTS: usize = 4_096;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_PROOF_BYTES: usize = 80_000;
const MAX_WITNESS_ITEMS: usize = 1_024;
const MAX_WITNESS_ITEM_BYTES: usize = 80_000;
const ELEMENTS_TAPROOT_LEAF_VERSION: u8 = 0xc4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidError {
    Bounds(&'static str),
    Encoding(&'static str),
    InvalidNetwork,
    InvalidAssetId,
    NetworkMismatch,
    OutputInvalid(&'static str),
    UnblindFailed,
    UnblindMismatch(&'static str),
    TaprootMismatch,
    Sighash(&'static str),
    Signature,
}

impl LiquidError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAssetId => "swp_invalid_asset_id",
            Self::InvalidNetwork | Self::NetworkMismatch => "swp_liquid_network_mismatch",
            Self::UnblindFailed => "swp_liquid_unblind_failed",
            Self::UnblindMismatch(_) => "swp_liquid_unblind_mismatch",
            Self::Bounds(_)
            | Self::Encoding(_)
            | Self::OutputInvalid(_)
            | Self::TaprootMismatch
            | Self::Sighash(_)
            | Self::Signature => "swp_liquid_output_invalid",
        }
    }
}

impl fmt::Display for LiquidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounds(detail) => write!(formatter, "Liquid bound exceeded: {detail}"),
            Self::Encoding(detail) => write!(formatter, "invalid Elements encoding: {detail}"),
            Self::InvalidNetwork => formatter.write_str("invalid Liquid network identifier"),
            Self::InvalidAssetId => formatter.write_str("invalid Liquid asset identifier"),
            Self::NetworkMismatch => {
                formatter.write_str("Liquid genesis reference or pegged asset differs")
            }
            Self::OutputInvalid(detail) => write!(formatter, "invalid Liquid output: {detail}"),
            Self::UnblindFailed => {
                formatter.write_str("selected Liquid output could not be unblinded locally")
            }
            Self::UnblindMismatch(detail) => {
                write!(formatter, "Liquid unblind result differs: {detail}")
            }
            Self::TaprootMismatch => {
                formatter.write_str("Liquid Taproot output does not match the committed tree")
            }
            Self::Sighash(detail) => write!(formatter, "invalid Liquid Taproot sighash: {detail}"),
            Self::Signature => formatter.write_str("invalid Liquid Taproot Schnorr signature"),
        }
    }
}

impl std::error::Error for LiquidError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LiquidNetworkId(String);

impl LiquidNetworkId {
    pub fn parse(value: &str) -> Result<Self, LiquidError> {
        let Some(reference) = value.strip_prefix("bip122:") else {
            return Err(LiquidError::InvalidNetwork);
        };
        if !is_lower_hex(reference, 32) {
            return Err(LiquidError::InvalidNetwork);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn from_genesis_hash(genesis_hash: &str) -> Result<Self, LiquidError> {
        if !is_lower_hex(genesis_hash, 64) {
            return Err(LiquidError::InvalidNetwork);
        }
        let reference = genesis_hash.get(..32).ok_or(LiquidError::InvalidNetwork)?;
        Self::parse(&format!("bip122:{reference}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LiquidAssetId([u8; 32]);

impl LiquidAssetId {
    pub fn parse(value: &str) -> Result<Self, LiquidError> {
        Ok(Self(
            parse_lower_hex_32(value).map_err(|_| LiquidError::InvalidAssetId)?,
        ))
    }

    pub fn from_display_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn display_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn mkt_asset_id(&self, network: &LiquidNetworkId) -> String {
        format!("swp:1:{}:elements:{}:liquid", network.as_str(), self)
    }

    pub fn parse_mkt(value: &str) -> Result<(LiquidNetworkId, Self), LiquidError> {
        let Some(rest) = value.strip_prefix("swp:1:") else {
            return Err(LiquidError::InvalidAssetId);
        };
        let Some((network_reference, rest)) = rest.split_once(":elements:") else {
            return Err(LiquidError::InvalidAssetId);
        };
        let Some(asset) = rest.strip_suffix(":liquid") else {
            return Err(LiquidError::InvalidAssetId);
        };
        let network = LiquidNetworkId::parse(network_reference)?;
        Ok((network, Self::parse(asset)?))
    }
}

impl fmt::Debug for LiquidAssetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "LiquidAssetId({self})")
    }
}

impl fmt::Display for LiquidAssetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialAsset {
    Explicit(LiquidAssetId),
    Commitment([u8; 33]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialValue {
    Explicit(u64),
    Commitment([u8; 33]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialNonce {
    Null,
    Explicit([u8; 33]),
    EphemeralKey([u8; 33]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidTransactionOutput {
    pub asset: ConfidentialAsset,
    pub value: ConfidentialValue,
    pub nonce: ConfidentialNonce,
    pub script_pubkey: Vec<u8>,
    pub surjection_proof_sha256: Option<[u8; 32]>,
    pub range_proof_sha256: Option<[u8; 32]>,
    pub surjection_proof: Vec<u8>,
    pub range_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidAssetIssuance {
    pub asset_blinding_nonce: [u8; 32],
    pub asset_entropy: [u8; 32],
    pub asset_amount: Option<ConfidentialValue>,
    pub token_amount: Option<ConfidentialValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidTransactionInput {
    pub previous_txid: [u8; 32],
    pub previous_output: u32,
    pub sequence: u32,
    pub script_sig: Vec<u8>,
    pub has_issuance: bool,
    pub is_pegin: bool,
    pub issuance: Option<LiquidAssetIssuance>,
    pub issuance_amount_range_proof: Vec<u8>,
    pub inflation_keys_range_proof: Vec<u8>,
    pub script_witness: Vec<Vec<u8>>,
    pub pegin_witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidPrevout {
    pub asset: ConfidentialAsset,
    pub value: ConfidentialValue,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LiquidGenesisHash([u8; 32]);

impl LiquidGenesisHash {
    pub fn parse_display(value: &str) -> Result<Self, LiquidError> {
        let mut bytes = parse_lower_hex_32(value).map_err(|_| LiquidError::InvalidNetwork)?;
        bytes.reverse();
        Ok(Self(bytes))
    }

    pub fn consensus_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidTransaction {
    pub version: i32,
    pub inputs: Vec<LiquidTransactionInput>,
    pub outputs: Vec<LiquidTransactionOutput>,
    pub lock_time: u32,
    pub transaction_id: [u8; 32],
    pub raw_sha256: [u8; 32],
    pub has_witness: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidVerificationAuthority {
    ExplicitOutput,
    LocalElementsdUnblind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLiquidOutput {
    pub asset: LiquidAssetId,
    pub amount_sat: u64,
    pub script_pubkey: Vec<u8>,
    pub transaction_sha256: [u8; 32],
    pub output_index: usize,
    pub authority: LiquidVerificationAuthority,
}

pub struct LocalElementsdUnblind<'a> {
    transaction: &'a LiquidTransaction,
}

impl<'a> LocalElementsdUnblind<'a> {
    /// Marks output bytes returned by the configured local Elements wallet's
    /// `unblindrawtransaction` call. The caller owns the node trust decision.
    pub fn trusted(transaction: &'a LiquidTransaction) -> Self {
        Self { transaction }
    }
}

pub fn parse_liquid_transaction(raw: &[u8]) -> Result<LiquidTransaction, LiquidError> {
    if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
        return Err(LiquidError::Bounds("transaction byte length"));
    }
    let mut reader = Reader::new(raw);
    let version = reader.read_i32_le()?;
    let flags = reader.read_u8()?;
    if flags > 1 {
        return Err(LiquidError::Encoding("transaction witness flag"));
    }
    let has_witness = flags == 1;
    let input_count = reader.read_compact_size(MAX_INPUTS, "input count")?;
    if input_count == 0 {
        return Err(LiquidError::Encoding("transaction has no inputs"));
    }
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let mut previous_txid: [u8; 32] = reader
            .read_exact(32)?
            .try_into()
            .map_err(|_| LiquidError::Encoding("input transaction ID"))?;
        previous_txid.reverse();
        let output_index = reader.read_u32_le()?;
        let script_sig = reader
            .read_var_bytes(MAX_SCRIPT_BYTES, "scriptSig")?
            .to_vec();
        let sequence = reader.read_u32_le()?;
        let has_issuance = output_index & (1 << 31) != 0;
        let is_pegin = output_index & (1 << 30) != 0;
        let issuance = if has_issuance {
            Some(LiquidAssetIssuance {
                asset_blinding_nonce: reader
                    .read_exact(32)?
                    .try_into()
                    .map_err(|_| LiquidError::Encoding("asset blinding nonce"))?,
                asset_entropy: reader
                    .read_exact(32)?
                    .try_into()
                    .map_err(|_| LiquidError::Encoding("asset entropy"))?,
                asset_amount: reader.read_optional_confidential_value()?,
                token_amount: reader.read_optional_confidential_value()?,
            })
        } else {
            None
        };
        inputs.push(LiquidTransactionInput {
            previous_txid,
            previous_output: output_index & 0x3fff_ffff,
            sequence,
            script_sig,
            has_issuance,
            is_pegin,
            issuance,
            issuance_amount_range_proof: Vec::new(),
            inflation_keys_range_proof: Vec::new(),
            script_witness: Vec::new(),
            pegin_witness: Vec::new(),
        });
    }
    let output_count = reader.read_compact_size(MAX_OUTPUTS, "output count")?;
    if output_count == 0 {
        return Err(LiquidError::Encoding("transaction has no outputs"));
    }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(LiquidTransactionOutput {
            asset: reader.read_asset()?,
            value: reader.read_value()?,
            nonce: reader.read_nonce()?,
            script_pubkey: reader
                .read_var_bytes(MAX_SCRIPT_BYTES, "scriptPubKey")?
                .to_vec(),
            surjection_proof_sha256: None,
            range_proof_sha256: None,
            surjection_proof: Vec::new(),
            range_proof: Vec::new(),
        });
    }
    let lock_time = reader.read_u32_le()?;
    let stripped_end = reader.position;
    if has_witness {
        for input in &mut inputs {
            input.issuance_amount_range_proof = reader
                .read_var_bytes(MAX_PROOF_BYTES, "issuance amount range proof")?
                .to_vec();
            input.inflation_keys_range_proof = reader
                .read_var_bytes(MAX_PROOF_BYTES, "inflation keys range proof")?
                .to_vec();
            input.script_witness = reader.read_witness_stack()?;
            input.pegin_witness = reader.read_witness_stack()?;
        }
        for output in &mut outputs {
            let surjection_proof = reader.read_var_bytes(MAX_PROOF_BYTES, "surjection proof")?;
            let range_proof = reader.read_var_bytes(MAX_PROOF_BYTES, "range proof")?;
            output.surjection_proof_sha256 =
                (!surjection_proof.is_empty()).then(|| sha256(surjection_proof));
            output.range_proof_sha256 = (!range_proof.is_empty()).then(|| sha256(range_proof));
            output.surjection_proof = surjection_proof.to_vec();
            output.range_proof = range_proof.to_vec();
        }
    }
    if !reader.is_finished() {
        return Err(LiquidError::Encoding("trailing transaction bytes"));
    }
    Ok(LiquidTransaction {
        version,
        inputs,
        outputs,
        lock_time,
        transaction_id: elements_transaction_id(raw, stripped_end)?,
        raw_sha256: sha256(raw),
        has_witness,
    })
}

pub fn verify_liquid_swap_output(
    transaction: &LiquidTransaction,
    unblind: Option<LocalElementsdUnblind<'_>>,
    output_index: usize,
    expected_asset: LiquidAssetId,
    expected_amount_sat: u64,
    expected_script_pubkey: &[u8],
) -> Result<VerifiedLiquidOutput, LiquidError> {
    if expected_amount_sat == 0 || expected_script_pubkey.is_empty() {
        return Err(LiquidError::OutputInvalid("zero amount or empty script"));
    }
    let output = transaction
        .outputs
        .get(output_index)
        .ok_or(LiquidError::OutputInvalid("output index"))?;
    if output.script_pubkey != expected_script_pubkey {
        return Err(LiquidError::OutputInvalid("scriptPubKey mismatch"));
    }
    let confidential_asset = matches!(output.asset, ConfidentialAsset::Commitment(_));
    let confidential_value = matches!(output.value, ConfidentialValue::Commitment(_));
    if confidential_asset && output.surjection_proof_sha256.is_none() {
        return Err(LiquidError::OutputInvalid("missing surjection proof"));
    }
    if confidential_value && output.range_proof_sha256.is_none() {
        return Err(LiquidError::OutputInvalid("missing range proof"));
    }
    let (asset, amount_sat, authority) = if confidential_asset || confidential_value {
        let unblinded = unblind.ok_or(LiquidError::UnblindFailed)?.transaction;
        if unblinded.version != transaction.version
            || unblinded.inputs != transaction.inputs
            || unblinded.outputs.len() != transaction.outputs.len()
            || unblinded.lock_time != transaction.lock_time
        {
            return Err(LiquidError::UnblindMismatch("transaction envelope"));
        }
        let revealed = unblinded
            .outputs
            .get(output_index)
            .ok_or(LiquidError::UnblindMismatch("output index"))?;
        if revealed.script_pubkey != output.script_pubkey {
            return Err(LiquidError::UnblindMismatch("scriptPubKey"));
        }
        let ConfidentialAsset::Explicit(asset) = revealed.asset else {
            return Err(LiquidError::UnblindMismatch("asset remains confidential"));
        };
        let ConfidentialValue::Explicit(amount_sat) = revealed.value else {
            return Err(LiquidError::UnblindMismatch("amount remains confidential"));
        };
        (
            asset,
            amount_sat,
            LiquidVerificationAuthority::LocalElementsdUnblind,
        )
    } else {
        let ConfidentialAsset::Explicit(asset) = output.asset else {
            return Err(LiquidError::OutputInvalid("asset shape"));
        };
        let ConfidentialValue::Explicit(amount_sat) = output.value else {
            return Err(LiquidError::OutputInvalid("amount shape"));
        };
        (
            asset,
            amount_sat,
            LiquidVerificationAuthority::ExplicitOutput,
        )
    };
    if asset != expected_asset {
        return Err(LiquidError::UnblindMismatch("asset"));
    }
    if amount_sat != expected_amount_sat {
        return Err(LiquidError::UnblindMismatch("amount"));
    }
    Ok(VerifiedLiquidOutput {
        asset,
        amount_sat,
        script_pubkey: output.script_pubkey.clone(),
        transaction_sha256: transaction.raw_sha256,
        output_index,
        authority,
    })
}

pub fn verify_liquid_network(
    expected_network: &LiquidNetworkId,
    expected_pegged_asset: LiquidAssetId,
    genesis_hash: &str,
    pegged_asset: &str,
) -> Result<(), LiquidError> {
    let observed_network = LiquidNetworkId::from_genesis_hash(genesis_hash)?;
    let observed_asset = LiquidAssetId::parse(pegged_asset)?;
    if &observed_network != expected_network || observed_asset != expected_pegged_asset {
        return Err(LiquidError::NetworkMismatch);
    }
    Ok(())
}

pub fn liquid_taproot_script_pubkey(
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> Result<Vec<u8>, LiquidError> {
    let (output_key, _) = liquid_taproot_output_key(internal_key, merkle_root)?;
    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.extend_from_slice(&[0x51, 0x20]);
    script_pubkey.extend_from_slice(&output_key.serialize());
    Ok(script_pubkey)
}

pub fn liquid_tapleaf_hash(script: &[u8]) -> Result<[u8; 32], LiquidError> {
    if script.len() > MAX_SCRIPT_BYTES {
        return Err(LiquidError::Bounds("Taproot leaf script byte length"));
    }
    let mut message = Vec::with_capacity(script.len().saturating_add(10));
    message.push(ELEMENTS_TAPROOT_LEAF_VERSION);
    write_compact_size(script.len(), &mut message)?;
    message.extend_from_slice(script);
    Ok(tagged_hash("TapLeaf/elements", &message))
}

pub fn liquid_tapbranch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (first, second) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut message = [0_u8; 64];
    message[..32].copy_from_slice(&first);
    message[32..].copy_from_slice(&second);
    tagged_hash("TapBranch/elements", &message)
}

pub fn liquid_taproot_output_key(
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> Result<(XOnlyPublicKey, Parity), LiquidError> {
    let mut message = internal_key.serialize().to_vec();
    if let Some(root) = merkle_root {
        message.extend_from_slice(&root);
    }
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak/elements", &message))
        .map_err(|_| LiquidError::OutputInvalid("Taproot tweak exceeds curve order"))?;
    internal_key
        .add_tweak(&Secp256k1::verification_only(), &tweak)
        .map_err(|_| LiquidError::OutputInvalid("Taproot output key tweak"))
}

pub fn verify_liquid_control_block(
    output_key: &XOnlyPublicKey,
    script: &[u8],
    control_block: &[u8],
) -> Result<(), LiquidError> {
    if control_block.len() < 33
        || control_block.len() > 33 + 32 * 128
        || (control_block.len() - 33) % 32 != 0
    {
        return Err(LiquidError::Sighash("control block length"));
    }
    if control_block[0] & 0xfe != ELEMENTS_TAPROOT_LEAF_VERSION {
        return Err(LiquidError::Sighash("unsupported Elements leaf version"));
    }
    let internal_key = XOnlyPublicKey::from_byte_array(
        control_block[1..33]
            .try_into()
            .map_err(|_| LiquidError::Sighash("control block internal key length"))?,
    )
    .map_err(|_| LiquidError::Sighash("control block internal key"))?;
    let mut root = liquid_tapleaf_hash(script)?;
    for sibling in control_block[33..].chunks_exact(32) {
        root = liquid_tapbranch_hash(
            root,
            sibling
                .try_into()
                .map_err(|_| LiquidError::Sighash("control block branch length"))?,
        );
    }
    let (candidate, parity) = liquid_taproot_output_key(internal_key, Some(root))?;
    let expected_parity = if control_block[0] & 1 == 0 {
        Parity::Even
    } else {
        Parity::Odd
    };
    if candidate != *output_key || parity != expected_parity {
        return Err(LiquidError::TaprootMismatch);
    }
    Ok(())
}

pub fn liquid_taproot_script_spend_sighash(
    transaction: &LiquidTransaction,
    prevouts: &[LiquidPrevout],
    input_index: usize,
    genesis_hash: LiquidGenesisHash,
    script: &[u8],
    control_block: &[u8],
    annex: Option<&[u8]>,
) -> Result<[u8; 32], LiquidError> {
    validate_sighash_inputs(transaction, prevouts, input_index, annex)?;
    let output_key = taproot_output_key_from_script_pubkey(&prevouts[input_index].script_pubkey)?;
    verify_liquid_control_block(&output_key, script, control_block)?;
    liquid_taproot_sighash_with_leaf_hash(
        transaction,
        prevouts,
        input_index,
        genesis_hash,
        liquid_tapleaf_hash(script)?,
        annex,
    )
}

fn liquid_taproot_sighash_with_leaf_hash(
    transaction: &LiquidTransaction,
    prevouts: &[LiquidPrevout],
    input_index: usize,
    genesis_hash: LiquidGenesisHash,
    leaf_hash: [u8; 32],
    annex: Option<&[u8]>,
) -> Result<[u8; 32], LiquidError> {
    validate_sighash_inputs(transaction, prevouts, input_index, annex)?;
    let mut message = Vec::new();
    message.extend_from_slice(&genesis_hash.consensus_bytes());
    message.extend_from_slice(&genesis_hash.consensus_bytes());
    message.push(0); // SIGHASH_DEFAULT
    message.extend_from_slice(&transaction.version.to_le_bytes());
    message.extend_from_slice(&transaction.lock_time.to_le_bytes());

    message.extend_from_slice(&hash_input_flags(&transaction.inputs));
    message.extend_from_slice(&hash_prevouts(&transaction.inputs));
    message.extend_from_slice(&hash_prevout_asset_values(prevouts));
    message.extend_from_slice(&hash_prevout_scripts(prevouts)?);
    message.extend_from_slice(&hash_sequences(&transaction.inputs));
    message.extend_from_slice(&hash_issuances(&transaction.inputs)?);
    message.extend_from_slice(&hash_issuance_proofs(&transaction.inputs)?);
    message.extend_from_slice(&hash_outputs(&transaction.outputs)?);
    message.extend_from_slice(&hash_output_witnesses(&transaction.outputs)?);

    message.push(if annex.is_some() { 3 } else { 2 });
    message.extend_from_slice(
        &u32::try_from(input_index)
            .map_err(|_| LiquidError::Bounds("Taproot input index"))?
            .to_le_bytes(),
    );
    if let Some(annex) = annex {
        let mut encoded = Vec::new();
        write_var_bytes(annex, &mut encoded)?;
        message.extend_from_slice(&sha256(&encoded));
    }
    message.extend_from_slice(&leaf_hash);
    message.push(0); // x-only public key version
    message.extend_from_slice(&u32::MAX.to_le_bytes());
    Ok(tagged_hash("TapSighash/elements", &message))
}

pub fn sign_liquid_taproot_sighash(sighash: [u8; 32], keypair: &Keypair) -> [u8; 64] {
    Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(&sighash, keypair)
        .to_byte_array()
}

pub fn verify_liquid_taproot_sighash_signature(
    sighash: [u8; 32],
    signature: &[u8; 64],
    signer: XOnlyPublicKey,
) -> Result<(), LiquidError> {
    let signature = Signature::from_byte_array(*signature);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &sighash, &signer)
        .map_err(|_| LiquidError::Signature)
}

pub fn verify_liquid_taproot_script_pubkey(
    script_pubkey: &[u8],
    internal_key: XOnlyPublicKey,
    merkle_root: Option<[u8; 32]>,
) -> Result<(), LiquidError> {
    if script_pubkey != liquid_taproot_script_pubkey(internal_key, merkle_root)? {
        return Err(LiquidError::TaprootMismatch);
    }
    Ok(())
}

fn validate_sighash_inputs(
    transaction: &LiquidTransaction,
    prevouts: &[LiquidPrevout],
    input_index: usize,
    annex: Option<&[u8]>,
) -> Result<(), LiquidError> {
    if transaction.inputs.is_empty()
        || transaction.inputs.len() > MAX_INPUTS
        || transaction.inputs.len() != prevouts.len()
    {
        return Err(LiquidError::Sighash("prevout count"));
    }
    if transaction.outputs.is_empty() || transaction.outputs.len() > MAX_OUTPUTS {
        return Err(LiquidError::Sighash("output count"));
    }
    transaction
        .inputs
        .get(input_index)
        .ok_or(LiquidError::Sighash("input index"))?;
    if transaction
        .inputs
        .iter()
        .any(|input| !input.script_sig.is_empty())
    {
        return Err(LiquidError::Sighash("Taproot scriptSig must be empty"));
    }
    if transaction
        .inputs
        .iter()
        .any(|input| input.has_issuance != input.issuance.is_some())
    {
        return Err(LiquidError::Sighash("issuance flag and payload differ"));
    }
    if prevouts
        .iter()
        .any(|prevout| prevout.script_pubkey.len() > MAX_SCRIPT_BYTES)
    {
        return Err(LiquidError::Bounds("prevout scriptPubKey byte length"));
    }
    if let Some(annex) = annex {
        if annex.first() != Some(&0x50) || annex.len() > MAX_WITNESS_ITEM_BYTES {
            return Err(LiquidError::Sighash("annex encoding"));
        }
    }
    Ok(())
}

fn taproot_output_key_from_script_pubkey(
    script_pubkey: &[u8],
) -> Result<XOnlyPublicKey, LiquidError> {
    let bytes = script_pubkey
        .strip_prefix(&[0x51, 0x20])
        .ok_or(LiquidError::Sighash("prevout is not a v1 Taproot output"))?;
    XOnlyPublicKey::from_byte_array(
        bytes
            .try_into()
            .map_err(|_| LiquidError::Sighash("Taproot output key length"))?,
    )
    .map_err(|_| LiquidError::Sighash("Taproot output key"))
}

fn hash_input_flags(inputs: &[LiquidTransactionInput]) -> [u8; 32] {
    let flags: Vec<u8> = inputs
        .iter()
        .map(|input| u8::from(input.has_issuance) << 7 | u8::from(input.is_pegin) << 6)
        .collect();
    sha256(&flags)
}

fn hash_prevouts(inputs: &[LiquidTransactionInput]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(inputs.len().saturating_mul(36));
    for input in inputs {
        let mut txid = input.previous_txid;
        txid.reverse();
        bytes.extend_from_slice(&txid);
        bytes.extend_from_slice(&input.previous_output.to_le_bytes());
    }
    sha256(&bytes)
}

fn hash_prevout_asset_values(prevouts: &[LiquidPrevout]) -> [u8; 32] {
    let mut bytes = Vec::new();
    for prevout in prevouts {
        encode_asset(&prevout.asset, &mut bytes);
        encode_value(Some(&prevout.value), &mut bytes);
    }
    sha256(&bytes)
}

fn hash_prevout_scripts(prevouts: &[LiquidPrevout]) -> Result<[u8; 32], LiquidError> {
    let mut bytes = Vec::new();
    for prevout in prevouts {
        write_var_bytes(&prevout.script_pubkey, &mut bytes)?;
    }
    Ok(sha256(&bytes))
}

fn hash_sequences(inputs: &[LiquidTransactionInput]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(inputs.len().saturating_mul(4));
    for input in inputs {
        bytes.extend_from_slice(&input.sequence.to_le_bytes());
    }
    sha256(&bytes)
}

fn hash_issuances(inputs: &[LiquidTransactionInput]) -> Result<[u8; 32], LiquidError> {
    let mut bytes = Vec::new();
    for input in inputs {
        if let Some(issuance) = &input.issuance {
            bytes.extend_from_slice(&issuance.asset_blinding_nonce);
            bytes.extend_from_slice(&issuance.asset_entropy);
            encode_value(issuance.asset_amount.as_ref(), &mut bytes);
            encode_value(issuance.token_amount.as_ref(), &mut bytes);
        } else {
            bytes.push(0);
        }
    }
    Ok(sha256(&bytes))
}

fn hash_issuance_proofs(inputs: &[LiquidTransactionInput]) -> Result<[u8; 32], LiquidError> {
    let mut bytes = Vec::new();
    for input in inputs {
        if input.issuance_amount_range_proof.len() > MAX_PROOF_BYTES
            || input.inflation_keys_range_proof.len() > MAX_PROOF_BYTES
        {
            return Err(LiquidError::Bounds("issuance proof byte length"));
        }
        write_var_bytes(&input.issuance_amount_range_proof, &mut bytes)?;
        write_var_bytes(&input.inflation_keys_range_proof, &mut bytes)?;
    }
    Ok(sha256(&bytes))
}

fn hash_outputs(outputs: &[LiquidTransactionOutput]) -> Result<[u8; 32], LiquidError> {
    let mut bytes = Vec::new();
    for output in outputs {
        if output.script_pubkey.len() > MAX_SCRIPT_BYTES {
            return Err(LiquidError::Bounds("output scriptPubKey byte length"));
        }
        encode_asset(&output.asset, &mut bytes);
        encode_value(Some(&output.value), &mut bytes);
        encode_nonce(&output.nonce, &mut bytes);
        write_var_bytes(&output.script_pubkey, &mut bytes)?;
    }
    Ok(sha256(&bytes))
}

fn hash_output_witnesses(outputs: &[LiquidTransactionOutput]) -> Result<[u8; 32], LiquidError> {
    let mut bytes = Vec::new();
    for output in outputs {
        if output.surjection_proof.len() > MAX_PROOF_BYTES
            || output.range_proof.len() > MAX_PROOF_BYTES
        {
            return Err(LiquidError::Bounds("output proof byte length"));
        }
        write_var_bytes(&output.surjection_proof, &mut bytes)?;
        write_var_bytes(&output.range_proof, &mut bytes)?;
    }
    Ok(sha256(&bytes))
}

fn encode_asset(asset: &ConfidentialAsset, output: &mut Vec<u8>) {
    match asset {
        ConfidentialAsset::Explicit(asset) => {
            output.push(1);
            let mut bytes = asset.display_bytes();
            bytes.reverse();
            output.extend_from_slice(&bytes);
        }
        ConfidentialAsset::Commitment(commitment) => output.extend_from_slice(commitment),
    }
}

fn encode_value(value: Option<&ConfidentialValue>, output: &mut Vec<u8>) {
    match value {
        None => output.push(0),
        Some(ConfidentialValue::Explicit(value)) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        Some(ConfidentialValue::Commitment(commitment)) => output.extend_from_slice(commitment),
    }
}

fn encode_nonce(nonce: &ConfidentialNonce, output: &mut Vec<u8>) {
    match nonce {
        ConfidentialNonce::Null => output.push(0),
        ConfidentialNonce::Explicit(nonce) | ConfidentialNonce::EphemeralKey(nonce) => {
            output.extend_from_slice(nonce);
        }
    }
}

fn write_var_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), LiquidError> {
    write_compact_size(bytes.len(), output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_compact_size(value: usize, output: &mut Vec<u8>) -> Result<(), LiquidError> {
    if value < 0xfd {
        output.push(u8::try_from(value).map_err(|_| LiquidError::Bounds("compact size"))?);
    } else if value <= usize::from(u16::MAX) {
        output.push(0xfd);
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| LiquidError::Bounds("compact size"))?
                .to_le_bytes(),
        );
    } else if value <= u32::MAX as usize {
        output.push(0xfe);
        output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| LiquidError::Bounds("compact size"))?
                .to_le_bytes(),
        );
    } else {
        output.push(0xff);
        output.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| LiquidError::Bounds("compact size"))?
                .to_le_bytes(),
        );
    }
    Ok(())
}

fn elements_transaction_id(raw: &[u8], stripped_end: usize) -> Result<[u8; 32], LiquidError> {
    let version = raw
        .get(..4)
        .ok_or(LiquidError::Encoding("transaction version"))?;
    let body = raw
        .get(5..stripped_end)
        .ok_or(LiquidError::Encoding("stripped transaction range"))?;
    let mut stripped = Vec::with_capacity(5 + body.len());
    stripped.extend_from_slice(version);
    stripped.push(0);
    stripped.extend_from_slice(body);
    let mut transaction_id = sha256(&sha256(&stripped));
    transaction_id.reverse();
    Ok(transaction_id)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_lower_hex_32(value: &str) -> Result<[u8; 32], ()> {
    if !is_lower_hex(value, 64) {
        return Err(());
    }
    let mut output = [0_u8; 32];
    for (index, destination) in output.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or(())?;
        let high = hex_nibble(*value.as_bytes().get(offset).ok_or(())?).ok_or(())?;
        let low = hex_nibble(*value.as_bytes().get(offset + 1).ok_or(())?).ok_or(())?;
        *destination = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn read_u8(&mut self) -> Result<u8, LiquidError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(LiquidError::Encoding("truncated byte"))?;
        self.position += 1;
        Ok(value)
    }

    fn read_u32_le(&mut self) -> Result<u32, LiquidError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| LiquidError::Encoding("u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_i32_le(&mut self) -> Result<i32, LiquidError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| LiquidError::Encoding("i32"))?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], LiquidError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(LiquidError::Bounds("reader offset"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(LiquidError::Encoding("truncated field"))?;
        self.position = end;
        Ok(value)
    }

    fn read_compact_size(
        &mut self,
        maximum: usize,
        field: &'static str,
    ) -> Result<usize, LiquidError> {
        let first = self.read_u8()?;
        let value = match first {
            0..=0xfc => u64::from(first),
            0xfd => {
                let bytes: [u8; 2] = self
                    .read_exact(2)?
                    .try_into()
                    .map_err(|_| LiquidError::Encoding(field))?;
                let value = u64::from(u16::from_le_bytes(bytes));
                if value < 0xfd {
                    return Err(LiquidError::Encoding("non-canonical compact size"));
                }
                value
            }
            0xfe => {
                let value = u64::from(self.read_u32_le()?);
                if value <= u64::from(u16::MAX) {
                    return Err(LiquidError::Encoding("non-canonical compact size"));
                }
                value
            }
            0xff => {
                let bytes: [u8; 8] = self
                    .read_exact(8)?
                    .try_into()
                    .map_err(|_| LiquidError::Encoding(field))?;
                let value = u64::from_le_bytes(bytes);
                if value <= u64::from(u32::MAX) {
                    return Err(LiquidError::Encoding("non-canonical compact size"));
                }
                value
            }
        };
        let value = usize::try_from(value).map_err(|_| LiquidError::Bounds(field))?;
        if value > maximum {
            return Err(LiquidError::Bounds(field));
        }
        Ok(value)
    }

    fn read_var_bytes(
        &mut self,
        maximum: usize,
        field: &'static str,
    ) -> Result<&'a [u8], LiquidError> {
        let length = self.read_compact_size(maximum, field)?;
        self.read_exact(length)
    }

    fn read_witness_stack(&mut self) -> Result<Vec<Vec<u8>>, LiquidError> {
        let count = self.read_compact_size(MAX_WITNESS_ITEMS, "witness item count")?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(
                self.read_var_bytes(MAX_WITNESS_ITEM_BYTES, "witness item")?
                    .to_vec(),
            );
        }
        Ok(items)
    }

    fn read_asset(&mut self) -> Result<ConfidentialAsset, LiquidError> {
        let header = self.read_u8()?;
        let bytes: [u8; 32] = self
            .read_exact(32)?
            .try_into()
            .map_err(|_| LiquidError::Encoding("asset"))?;
        match header {
            0x01 => {
                let mut display = bytes;
                display.reverse();
                Ok(ConfidentialAsset::Explicit(
                    LiquidAssetId::from_display_bytes(display),
                ))
            }
            0x0a | 0x0b => {
                let mut commitment = [0_u8; 33];
                commitment[0] = header;
                commitment[1..].copy_from_slice(&bytes);
                let mut public_key = commitment;
                public_key[0] = header - 8;
                PublicKey::from_slice(&public_key)
                    .map_err(|_| LiquidError::Encoding("asset commitment point"))?;
                Ok(ConfidentialAsset::Commitment(commitment))
            }
            _ => Err(LiquidError::Encoding("asset prefix")),
        }
    }

    fn read_value(&mut self) -> Result<ConfidentialValue, LiquidError> {
        self.read_optional_confidential_value()?
            .ok_or(LiquidError::Encoding("null output amount"))
    }

    fn read_optional_confidential_value(
        &mut self,
    ) -> Result<Option<ConfidentialValue>, LiquidError> {
        let header = self.read_u8()?;
        match header {
            0x00 => Ok(None),
            0x01 => {
                let bytes: [u8; 8] = self
                    .read_exact(8)?
                    .try_into()
                    .map_err(|_| LiquidError::Encoding("explicit amount"))?;
                Ok(Some(ConfidentialValue::Explicit(u64::from_be_bytes(bytes))))
            }
            0x08 | 0x09 => {
                let mut commitment = [0_u8; 33];
                commitment[0] = header;
                commitment[1..].copy_from_slice(self.read_exact(32)?);
                let mut public_key = commitment;
                public_key[0] = header - 6;
                PublicKey::from_slice(&public_key)
                    .map_err(|_| LiquidError::Encoding("value commitment point"))?;
                Ok(Some(ConfidentialValue::Commitment(commitment)))
            }
            _ => Err(LiquidError::Encoding("amount prefix")),
        }
    }

    fn read_nonce(&mut self) -> Result<ConfidentialNonce, LiquidError> {
        let header = self.read_u8()?;
        match header {
            0x00 => Ok(ConfidentialNonce::Null),
            0x01 => {
                let mut nonce = [0_u8; 33];
                nonce[0] = header;
                nonce[1..].copy_from_slice(self.read_exact(32)?);
                Ok(ConfidentialNonce::Explicit(nonce))
            }
            0x02 | 0x03 => {
                let mut nonce = [0_u8; 33];
                nonce[0] = header;
                nonce[1..].copy_from_slice(self.read_exact(32)?);
                Ok(ConfidentialNonce::EphemeralKey(nonce))
            }
            _ => Err(LiquidError::Encoding("nonce prefix")),
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use serde_json::Value;

    use super::{
        ConfidentialAsset, ConfidentialValue, LiquidAssetId, LiquidError, LiquidGenesisHash,
        LiquidNetworkId, LiquidPrevout, LiquidVerificationAuthority, LocalElementsdUnblind,
        liquid_tapbranch_hash, liquid_tapleaf_hash, liquid_taproot_script_pubkey,
        liquid_taproot_script_spend_sighash, parse_liquid_transaction, sign_liquid_taproot_sighash,
        verify_liquid_network, verify_liquid_swap_output, verify_liquid_taproot_script_pubkey,
        verify_liquid_taproot_sighash_signature,
    };

    const FIXTURE: &str = include_str!("../../../tests/fixtures/nipmkt/liquid-rail-v1.json");
    const GO_ELEMENTS_SIGHASH_FIXTURE: &str =
        include_str!("../../../tests/fixtures/nipmkt/go-elements-v0.5.5-taproot-sighash.json");

    #[test]
    fn signature_and_sighash_refusals_use_the_pinned_liquid_vocabulary() {
        assert_eq!(
            LiquidError::Sighash("fixture").code(),
            "swp_liquid_output_invalid"
        );
        assert_eq!(LiquidError::Signature.code(), "swp_liquid_output_invalid");
    }

    #[test]
    fn parses_and_verifies_own_confidential_output() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value = serde_json::from_str(FIXTURE)?;
        let network = fixture
            .get("network")
            .and_then(Value::as_object)
            .ok_or("network fixture")?;
        let expected_network = LiquidNetworkId::parse(
            network
                .get("network_id")
                .and_then(Value::as_str)
                .ok_or("network ID")?,
        )?;
        let expected_asset = LiquidAssetId::parse(
            network
                .get("pegged_asset")
                .and_then(Value::as_str)
                .ok_or("pegged asset")?,
        )?;
        verify_liquid_network(
            &expected_network,
            expected_asset,
            network
                .get("genesis_hash")
                .and_then(Value::as_str)
                .ok_or("genesis hash")?,
            network
                .get("pegged_asset")
                .and_then(Value::as_str)
                .ok_or("pegged asset")?,
        )?;
        assert_eq!(
            expected_asset.mkt_asset_id(&expected_network),
            network
                .get("asset_id")
                .and_then(Value::as_str)
                .ok_or("MKT asset ID")?
        );
        let (parsed_network, parsed_asset) = LiquidAssetId::parse_mkt(
            network
                .get("asset_id")
                .and_then(Value::as_str)
                .ok_or("MKT asset ID")?,
        )?;
        assert_eq!(parsed_network, expected_network);
        assert_eq!(parsed_asset, expected_asset);

        let vector = fixture
            .get("parser_vectors")
            .and_then(Value::as_array)
            .and_then(|vectors| vectors.first())
            .and_then(Value::as_object)
            .ok_or("positive vector")?;
        let transaction = parse_liquid_transaction(&decode_hex(
            vector
                .get("raw_transaction")
                .and_then(Value::as_str)
                .ok_or("raw transaction")?,
        )?)?;
        let unblinded = parse_liquid_transaction(&decode_hex(
            vector
                .get("trusted_local_unblind")
                .and_then(Value::as_str)
                .ok_or("unblind transaction")?,
        )?)?;
        let script_pubkey = decode_hex(
            vector
                .get("script_pubkey")
                .and_then(Value::as_str)
                .ok_or("scriptPubKey")?,
        )?;
        let verified = verify_liquid_swap_output(
            &transaction,
            Some(LocalElementsdUnblind::trusted(&unblinded)),
            0,
            expected_asset,
            100_000,
            &script_pubkey,
        )?;
        assert_eq!(verified.amount_sat, 100_000);
        assert_eq!(
            verified.authority,
            LiquidVerificationAuthority::LocalElementsdUnblind
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_or_changed_unblind_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value = serde_json::from_str(FIXTURE)?;
        let vector = fixture
            .get("parser_vectors")
            .and_then(Value::as_array)
            .and_then(|vectors| vectors.first())
            .and_then(Value::as_object)
            .ok_or("positive vector")?;
        let transaction = parse_liquid_transaction(&decode_hex(
            vector
                .get("raw_transaction")
                .and_then(Value::as_str)
                .ok_or("raw transaction")?,
        )?)?;
        let mut unblinded = parse_liquid_transaction(&decode_hex(
            vector
                .get("trusted_local_unblind")
                .and_then(Value::as_str)
                .ok_or("unblind transaction")?,
        )?)?;
        let asset = LiquidAssetId::parse("11".repeat(32).as_str())?;
        let script = decode_hex(
            vector
                .get("script_pubkey")
                .and_then(Value::as_str)
                .ok_or("scriptPubKey")?,
        )?;
        let missing = verify_liquid_swap_output(&transaction, None, 0, asset, 100_000, &script)
            .expect_err("confidential output needs local unblind evidence");
        assert_eq!(missing.code(), "swp_liquid_unblind_failed");

        unblinded.outputs[0].value = ConfidentialValue::Explicit(100_001);
        let changed = verify_liquid_swap_output(
            &transaction,
            Some(LocalElementsdUnblind::trusted(&unblinded)),
            0,
            asset,
            100_000,
            &script,
        )
        .expect_err("changed amount must fail");
        assert_eq!(changed.code(), "swp_liquid_unblind_mismatch");

        let mut missing_proof = transaction.clone();
        missing_proof.outputs[0].range_proof_sha256 = None;
        let error = verify_liquid_swap_output(
            &missing_proof,
            Some(LocalElementsdUnblind::trusted(&unblinded)),
            0,
            asset,
            100_000,
            &script,
        )
        .expect_err("confidential amount needs a range proof");
        assert_eq!(error.code(), "swp_liquid_output_invalid");
        Ok(())
    }

    #[test]
    fn enforces_bounds_and_liquid_taproot_tree() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            LiquidNetworkId::parse("liquidregtest"),
            Err(LiquidError::InvalidNetwork)
        ));
        assert!(matches!(
            LiquidAssetId::parse(&"AA".repeat(32)),
            Err(LiquidError::InvalidAssetId)
        ));
        assert!(parse_liquid_transaction(&[0_u8; 4]).is_err());

        let internal_key_bytes: [u8; 32] =
            decode_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?
                .try_into()
                .map_err(|_| "internal key length")?;
        let internal_key = XOnlyPublicKey::from_byte_array(internal_key_bytes)?;
        let script = liquid_taproot_script_pubkey(internal_key, None)?;
        verify_liquid_taproot_script_pubkey(&script, internal_key, None)?;
        let mut changed = script;
        changed[2] ^= 1;
        assert!(matches!(
            verify_liquid_taproot_script_pubkey(&changed, internal_key, None),
            Err(LiquidError::TaprootMismatch)
        ));
        Ok(())
    }

    #[test]
    fn replays_go_elements_claim_and_refund_sighashes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value = serde_json::from_str(FIXTURE)?;
        let vectors = fixture
            .get("taproot_sighash_vectors")
            .and_then(Value::as_array)
            .ok_or("Taproot sighash vectors")?;
        assert_eq!(vectors.len(), 2);
        for (vector_index, vector) in vectors.iter().enumerate() {
            let material = sighash_material(vector)?;
            let digest = liquid_taproot_script_spend_sighash(
                &material.transaction,
                &material.prevouts,
                material.input_index,
                material.genesis_hash,
                &material.script,
                &material.control_block,
                material.annex.as_deref(),
            )?;
            assert_eq!(digest, material.expected_sighash);
            verify_liquid_taproot_sighash_signature(digest, &material.signature, material.signer)?;

            let mut secret_bytes = [0_u8; 32];
            secret_bytes[31] = if vector_index == 0 { 3 } else { 4 };
            let keypair = Keypair::from_secret_key(
                &Secp256k1::signing_only(),
                &SecretKey::from_byte_array(secret_bytes)?,
            );
            let local_signature = sign_liquid_taproot_sighash(digest, &keypair);
            verify_liquid_taproot_sighash_signature(digest, &local_signature, material.signer)?;

            let leaf_hash = liquid_tapleaf_hash(&material.script)?;
            assert_eq!(leaf_hash, material.expected_leaf_hash);
            let sibling: [u8; 32] = material.control_block[33..65]
                .try_into()
                .map_err(|_| "control block sibling")?;
            assert_eq!(
                liquid_tapbranch_hash(leaf_hash, sibling),
                material.expected_merkle_root
            );
        }
        Ok(())
    }

    #[test]
    fn replays_official_go_elements_default_leaf_vector() -> Result<(), Box<dyn std::error::Error>>
    {
        let vector: Value = serde_json::from_str(GO_ELEMENTS_SIGHASH_FIXTURE)?;
        assert_eq!(
            required_string(&vector, "description")?,
            "witnessv1 sighash SIGHASH_DEFAULT with leafHash"
        );
        let transaction =
            parse_liquid_transaction(&decode_hex(required_string(&vector, "txHex")?)?)?;
        assert!(transaction.outputs.iter().any(|output| {
            !output.surjection_proof.is_empty() || !output.range_proof.is_empty()
        }));
        let prevouts = vector
            .get("prevouts")
            .and_then(Value::as_array)
            .ok_or("official prevouts")?
            .iter()
            .map(official_prevout)
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let input_index = usize::try_from(
            vector
                .get("inIndex")
                .and_then(Value::as_u64)
                .ok_or("official input index")?,
        )?;
        let sighash = super::liquid_taproot_sighash_with_leaf_hash(
            &transaction,
            &prevouts,
            input_index,
            LiquidGenesisHash::parse_display(required_string(&vector, "genesisHash")?)?,
            decode_hex_array(required_string(&vector, "leafHash")?)?,
            None,
        )?;
        assert_eq!(
            sighash,
            decode_hex_array(required_string(&vector, "expectedHash")?)?
        );
        Ok(())
    }

    #[test]
    fn rejects_every_committed_sighash_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value = serde_json::from_str(FIXTURE)?;
        let vectors = fixture
            .get("taproot_sighash_vectors")
            .and_then(Value::as_array)
            .ok_or("Taproot sighash vectors")?;
        let claim = sighash_material(vectors.first().ok_or("claim vector")?)?;
        let refund = sighash_material(vectors.get(1).ok_or("refund vector")?)?;
        let mutation_names = fixture
            .get("taproot_sighash_mutations")
            .and_then(Value::as_array)
            .ok_or("Taproot sighash mutations")?
            .iter()
            .filter_map(|mutation| mutation.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            mutation_names,
            [
                "liquid-v1-negative-annex",
                "liquid-v1-negative-script",
                "liquid-v1-negative-control-block",
                "liquid-v1-negative-input",
                "liquid-v1-negative-output",
                "liquid-v1-negative-prevout-asset",
                "liquid-v1-negative-prevout-value",
            ]
        );

        let mut changed_annex = refund.annex.clone().ok_or("refund annex")?;
        changed_annex[1] ^= 1;
        assert_signature_invalid(&refund, Some(&changed_annex))?;

        let mut changed_script = claim.script.clone();
        changed_script[1] ^= 1;
        assert!(matches!(
            verify_material(
                &claim,
                &claim.transaction,
                &claim.prevouts,
                &changed_script,
                &claim.control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::TaprootMismatch)
        ));

        let mut changed_control_block = claim.control_block.clone();
        changed_control_block[33] ^= 1;
        assert!(matches!(
            verify_material(
                &claim,
                &claim.transaction,
                &claim.prevouts,
                &claim.script,
                &changed_control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::TaprootMismatch)
        ));

        let mut changed_transaction = claim.transaction.clone();
        changed_transaction.inputs[0].sequence ^= 1;
        assert!(matches!(
            verify_material(
                &claim,
                &changed_transaction,
                &claim.prevouts,
                &claim.script,
                &claim.control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::Signature)
        ));

        changed_transaction = claim.transaction.clone();
        changed_transaction.outputs[0].value = ConfidentialValue::Explicit(1_001);
        assert!(matches!(
            verify_material(
                &claim,
                &changed_transaction,
                &claim.prevouts,
                &claim.script,
                &claim.control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::Signature)
        ));

        let mut changed_prevouts = claim.prevouts.clone();
        changed_prevouts[0].asset =
            ConfidentialAsset::Explicit(LiquidAssetId::parse(&"ab".repeat(32))?);
        assert!(matches!(
            verify_material(
                &claim,
                &claim.transaction,
                &changed_prevouts,
                &claim.script,
                &claim.control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::Signature)
        ));

        changed_prevouts = claim.prevouts.clone();
        changed_prevouts[0].value = ConfidentialValue::Explicit(50_001);
        assert!(matches!(
            verify_material(
                &claim,
                &claim.transaction,
                &changed_prevouts,
                &claim.script,
                &claim.control_block,
                claim.annex.as_deref()
            ),
            Err(LiquidError::Signature)
        ));
        Ok(())
    }

    struct SighashMaterial {
        transaction: super::LiquidTransaction,
        prevouts: Vec<LiquidPrevout>,
        input_index: usize,
        genesis_hash: LiquidGenesisHash,
        script: Vec<u8>,
        control_block: Vec<u8>,
        annex: Option<Vec<u8>>,
        signer: XOnlyPublicKey,
        expected_sighash: [u8; 32],
        expected_leaf_hash: [u8; 32],
        expected_merkle_root: [u8; 32],
        signature: [u8; 64],
    }

    fn sighash_material(vector: &Value) -> Result<SighashMaterial, Box<dyn std::error::Error>> {
        let transaction =
            parse_liquid_transaction(&decode_hex(required_string(vector, "raw_transaction")?)?)?;
        let prevouts = vector
            .get("prevouts")
            .and_then(Value::as_array)
            .ok_or("prevouts")?
            .iter()
            .map(|prevout| {
                Ok(LiquidPrevout {
                    asset: ConfidentialAsset::Explicit(LiquidAssetId::parse(required_string(
                        prevout, "asset",
                    )?)?),
                    value: ConfidentialValue::Explicit(required_string(prevout, "value")?.parse()?),
                    script_pubkey: decode_hex(required_string(prevout, "script_pubkey")?)?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(SighashMaterial {
            transaction,
            prevouts,
            input_index: usize::try_from(
                vector
                    .get("input_index")
                    .and_then(Value::as_u64)
                    .ok_or("input index")?,
            )?,
            genesis_hash: LiquidGenesisHash::parse_display(required_string(
                vector,
                "genesis_hash",
            )?)?,
            script: decode_hex(required_string(vector, "script")?)?,
            control_block: decode_hex(required_string(vector, "control_block")?)?,
            annex: vector
                .get("annex")
                .and_then(Value::as_str)
                .map(decode_hex)
                .transpose()?,
            signer: XOnlyPublicKey::from_byte_array(decode_hex_array(required_string(
                vector, "signer",
            )?)?)?,
            expected_sighash: decode_hex_array(required_string(vector, "sighash")?)?,
            expected_leaf_hash: decode_hex_array(required_string(vector, "leaf_hash")?)?,
            expected_merkle_root: decode_hex_array(required_string(vector, "merkle_root")?)?,
            signature: decode_hex_array(required_string(vector, "signature")?)?,
        })
    }

    fn official_prevout(prevout: &Value) -> Result<LiquidPrevout, Box<dyn std::error::Error>> {
        let asset = required_string(prevout, "asset")?;
        let value = decode_hex(required_string(prevout, "value")?)?;
        let (asset, value) = if value.len() == 9 {
            let explicit = value
                .strip_prefix(&[1])
                .ok_or("official explicit value prefix")?;
            (
                ConfidentialAsset::Explicit(LiquidAssetId::parse(asset)?),
                ConfidentialValue::Explicit(u64::from_be_bytes(
                    explicit
                        .try_into()
                        .map_err(|_| "official explicit value length")?,
                )),
            )
        } else {
            let mut asset_commitment = [0_u8; 33];
            asset_commitment[0] = 0x0a;
            let mut asset_bytes = decode_hex_array::<32>(asset)?;
            asset_bytes.reverse();
            asset_commitment[1..].copy_from_slice(&asset_bytes);
            (
                ConfidentialAsset::Commitment(asset_commitment),
                ConfidentialValue::Commitment(
                    value
                        .try_into()
                        .map_err(|_| "official confidential value length")?,
                ),
            )
        };
        Ok(LiquidPrevout {
            asset,
            value,
            script_pubkey: decode_hex(required_string(prevout, "script")?)?,
        })
    }

    fn verify_material(
        material: &SighashMaterial,
        transaction: &super::LiquidTransaction,
        prevouts: &[LiquidPrevout],
        script: &[u8],
        control_block: &[u8],
        annex: Option<&[u8]>,
    ) -> Result<(), LiquidError> {
        let sighash = liquid_taproot_script_spend_sighash(
            transaction,
            prevouts,
            material.input_index,
            material.genesis_hash,
            script,
            control_block,
            annex,
        )?;
        verify_liquid_taproot_sighash_signature(sighash, &material.signature, material.signer)
    }

    fn assert_signature_invalid(
        material: &SighashMaterial,
        annex: Option<&[u8]>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            verify_material(
                material,
                &material.transaction,
                &material.prevouts,
                &material.script,
                &material.control_block,
                annex,
            ),
            Err(LiquidError::Signature)
        ));
        Ok(())
    }

    fn required_string<'a>(
        value: &'a Value,
        field: &'static str,
    ) -> Result<&'a str, Box<dyn std::error::Error>> {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| field.into())
    }

    fn decode_hex_array<const LENGTH: usize>(
        value: &str,
    ) -> Result<[u8; LENGTH], Box<dyn std::error::Error>> {
        decode_hex(value)?
            .try_into()
            .map_err(|_| "fixture hex array length".into())
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if value.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        let mut bytes = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().chunks_exact(2) {
            let pair = core::str::from_utf8(pair)?;
            bytes.push(u8::from_str_radix(pair, 16)?);
        }
        Ok(bytes)
    }
}
