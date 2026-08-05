use std::fmt;

use immortal_core::mkt_swp_verify::{
    Transaction, TransactionInput, TransactionOutput, dust_threshold, is_dust,
    taproot_key_spend_sighash, transaction_cost,
};
use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};

use crate::wallet::{ProviderWallet, WalletPath};

const MAX_FUNDING_INPUTS: usize = 64;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_FEE_RATE_SAT_PER_VBYTE: u64 = 10_000;
const DUST_RELAY_FEE_SAT_PER_KB: u64 = 3_000;
const NON_RBF_LOCKTIME_SEQUENCE: u32 = 0xffff_fffe;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingError {
    Invalid(&'static str),
    Overflow(&'static str),
    InsufficientFunds,
    Wallet,
    Verification,
}

impl fmt::Display for FundingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Invalid(message) => *message,
            Self::Overflow(message) => *message,
            Self::InsufficientFunds => "selected UTXOs cannot fund the output and bounded fee",
            Self::Wallet => "provider wallet could not derive or sign a funding input",
            Self::Verification => "constructed funding transaction failed local verification",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FundingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingInput {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
    pub path: WalletPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingRequest {
    pub destination_script_pubkey: Vec<u8>,
    pub amount_sat: u64,
    pub fee_rate_sat_per_vbyte: u64,
    pub change_path: WalletPath,
    pub lock_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFundingTransaction {
    pub transaction: Transaction,
    pub raw_transaction: String,
    pub txid: String,
    pub fee_sat: u64,
    pub change_sat: Option<u64>,
}

pub fn build_funding_transaction(
    wallet: &ProviderWallet,
    inputs: &[FundingInput],
    request: &FundingRequest,
) -> Result<SignedFundingTransaction, FundingError> {
    validate_request(inputs, request)?;
    let mut inputs = inputs.to_vec();
    inputs.sort_by(|left, right| left.txid.cmp(&right.txid).then(left.vout.cmp(&right.vout)));
    if inputs
        .windows(2)
        .any(|pair| pair[0].txid == pair[1].txid && pair[0].vout == pair[1].vout)
    {
        return Err(FundingError::Invalid("funding inputs repeat an outpoint"));
    }

    let mut transaction_inputs = Vec::with_capacity(inputs.len());
    let mut prevouts = Vec::with_capacity(inputs.len());
    let mut input_total = 0_u64;
    for input in &inputs {
        let address = wallet
            .derive_address(input.path)
            .map_err(|_| FundingError::Wallet)?;
        input_total = input_total
            .checked_add(input.value_sat)
            .ok_or(FundingError::Overflow("funding input amount overflow"))?;
        transaction_inputs.push(TransactionInput {
            previous_txid: txid_wire_bytes(&input.txid)?,
            previous_output: input.vout,
            script_sig: Vec::new(),
            sequence: NON_RBF_LOCKTIME_SEQUENCE,
            witness: Vec::new(),
        });
        prevouts.push(TransactionOutput {
            value_sat: input.value_sat,
            script_pubkey: address.script_pubkey.to_vec(),
        });
    }

    let change = wallet
        .derive_address(request.change_path)
        .map_err(|_| FundingError::Wallet)?;
    let (mut transaction, change_sat) = plan_transaction(
        transaction_inputs,
        input_total,
        request,
        change.script_pubkey.to_vec(),
    )?;
    for (input_index, input) in inputs.iter().enumerate() {
        let sighash = taproot_key_spend_sighash(&transaction, &prevouts, input_index)
            .map_err(|_| FundingError::Verification)?;
        let signature = wallet
            .sign_key_path(input.path, &sighash)
            .map_err(|_| FundingError::Wallet)?;
        let expected_key = prevouts
            .get(input_index)
            .and_then(|prevout| prevout.script_pubkey.get(2..34))
            .ok_or(FundingError::Verification)?;
        if signature.public_key != expected_key {
            return Err(FundingError::Verification);
        }
        verify_signature(&signature.public_key, &signature.signature, &sighash)?;
        transaction
            .set_input_witness(input_index, vec![signature.signature.to_vec()])
            .map_err(|_| FundingError::Verification)?;
    }

    let cost = transaction_cost(&transaction, &prevouts).map_err(|_| FundingError::Verification)?;
    let required_fee = request
        .fee_rate_sat_per_vbyte
        .checked_mul(cost.virtual_size)
        .ok_or(FundingError::Overflow("funding fee overflow"))?;
    if cost.fee_sat < required_fee {
        return Err(FundingError::Verification);
    }
    let raw = transaction
        .serialize(true)
        .map_err(|_| FundingError::Verification)?;
    let txid = transaction.txid().map_err(|_| FundingError::Verification)?;
    Ok(SignedFundingTransaction {
        transaction,
        raw_transaction: encode_hex(&raw),
        txid: encode_hex(&txid),
        fee_sat: cost.fee_sat,
        change_sat,
    })
}

fn plan_transaction(
    inputs: Vec<TransactionInput>,
    input_total: u64,
    request: &FundingRequest,
    change_script_pubkey: Vec<u8>,
) -> Result<(Transaction, Option<u64>), FundingError> {
    let destination = TransactionOutput {
        value_sat: request.amount_sat,
        script_pubkey: request.destination_script_pubkey.clone(),
    };
    if is_dust(&destination, DUST_RELAY_FEE_SAT_PER_KB)
        .map_err(|_| FundingError::Invalid("funding destination script is invalid"))?
    {
        return Err(FundingError::Invalid("funding destination is dust"));
    }
    let change_dust = dust_threshold(&change_script_pubkey, DUST_RELAY_FEE_SAT_PER_KB)
        .map_err(|_| FundingError::Invalid("funding change script is invalid"))?;

    let with_change = Transaction::new(
        2,
        inputs.clone(),
        vec![
            destination.clone(),
            TransactionOutput {
                value_sat: change_dust,
                script_pubkey: change_script_pubkey.clone(),
            },
        ],
        request.lock_time,
    );
    let with_change_fee = estimated_fee(&with_change, request.fee_rate_sat_per_vbyte)?;
    let with_change_required = request
        .amount_sat
        .checked_add(with_change_fee)
        .and_then(|value| value.checked_add(change_dust))
        .ok_or(FundingError::Overflow("funding output amount overflow"))?;
    if input_total >= with_change_required {
        let change_sat = input_total
            .checked_sub(request.amount_sat)
            .and_then(|value| value.checked_sub(with_change_fee))
            .ok_or(FundingError::InsufficientFunds)?;
        return Ok((
            Transaction::new(
                2,
                inputs,
                vec![
                    destination,
                    TransactionOutput {
                        value_sat: change_sat,
                        script_pubkey: change_script_pubkey,
                    },
                ],
                request.lock_time,
            ),
            Some(change_sat),
        ));
    }

    let without_change = Transaction::new(2, inputs, vec![destination], request.lock_time);
    let required_fee = estimated_fee(&without_change, request.fee_rate_sat_per_vbyte)?;
    let required = request
        .amount_sat
        .checked_add(required_fee)
        .ok_or(FundingError::Overflow("funding output amount overflow"))?;
    if input_total < required {
        return Err(FundingError::InsufficientFunds);
    }
    Ok((without_change, None))
}

fn estimated_fee(
    transaction: &Transaction,
    fee_rate_sat_per_vbyte: u64,
) -> Result<u64, FundingError> {
    let mut estimated = transaction.clone();
    for input_index in 0..estimated.inputs.len() {
        estimated
            .set_input_witness(input_index, vec![vec![0_u8; 64]])
            .map_err(|_| FundingError::Verification)?;
    }
    estimated
        .virtual_size()
        .map_err(|_| FundingError::Verification)?
        .checked_mul(fee_rate_sat_per_vbyte)
        .ok_or(FundingError::Overflow("funding fee overflow"))
}

fn validate_request(inputs: &[FundingInput], request: &FundingRequest) -> Result<(), FundingError> {
    if inputs.is_empty() || inputs.len() > MAX_FUNDING_INPUTS {
        return Err(FundingError::Invalid(
            "funding input count is outside bounds",
        ));
    }
    if request.amount_sat == 0
        || request.fee_rate_sat_per_vbyte == 0
        || request.fee_rate_sat_per_vbyte > MAX_FEE_RATE_SAT_PER_VBYTE
        || request.destination_script_pubkey.is_empty()
        || request.destination_script_pubkey.len() > MAX_SCRIPT_BYTES
    {
        return Err(FundingError::Invalid(
            "funding amount, fee rate, or destination is outside bounds",
        ));
    }
    for input in inputs {
        if input.value_sat == 0 || !is_lower_hex_32(&input.txid) {
            return Err(FundingError::Invalid("funding input is invalid"));
        }
    }
    Ok(())
}

fn txid_wire_bytes(txid: &str) -> Result<[u8; 32], FundingError> {
    if !is_lower_hex_32(txid) {
        return Err(FundingError::Invalid("funding transaction ID is invalid"));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in txid.as_bytes().chunks_exact(2).rev().enumerate() {
        let high = hex_nibble(pair[0])
            .ok_or(FundingError::Invalid("funding transaction ID is invalid"))?;
        let low = hex_nibble(pair[1])
            .ok_or(FundingError::Invalid("funding transaction ID is invalid"))?;
        bytes[index] = high << 4 | low;
    }
    Ok(bytes)
}

fn verify_signature(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    sighash: &[u8; 32],
) -> Result<(), FundingError> {
    let public_key =
        XOnlyPublicKey::from_byte_array(*public_key).map_err(|_| FundingError::Verification)?;
    let signature = Signature::from_byte_array(*signature);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, sighash, &public_key)
        .map_err(|_| FundingError::Verification)
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use immortal_core::mkt_swp_verify::Transaction;

    use super::{
        FundingError, FundingInput, FundingRequest, NON_RBF_LOCKTIME_SEQUENCE,
        build_funding_transaction,
    };
    use crate::wallet::{BitcoinNetwork, ProviderWallet, WalletPath};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn funding_builder_signs_owned_inputs_and_returns_change() {
        let (wallet, seed_path) = random_wallet();
        let destination = wallet
            .derive_address(WalletPath::new(0, false, 1).expect("destination path"))
            .expect("destination address");
        let request = FundingRequest {
            destination_script_pubkey: destination.script_pubkey.to_vec(),
            amount_sat: 50_000,
            fee_rate_sat_per_vbyte: 2,
            change_path: WalletPath::new(0, true, 0).expect("change path"),
            lock_time: 200,
        };
        let input = FundingInput {
            txid: "11".repeat(32),
            vout: 3,
            value_sat: 100_000,
            path: WalletPath::new(0, false, 0).expect("input path"),
        };

        let signed =
            build_funding_transaction(&wallet, &[input], &request).expect("funding transaction");
        assert_eq!(signed.transaction.inputs[0].witness[0].len(), 64);
        assert_eq!(
            signed.transaction.inputs[0].sequence,
            NON_RBF_LOCKTIME_SEQUENCE
        );
        assert_eq!(signed.transaction.lock_time, 200);
        assert_eq!(signed.transaction.outputs[0].value_sat, 50_000);
        assert!(signed.change_sat.is_some_and(|change| change > 0));
        assert_eq!(
            Transaction::parse(&decode_hex(&signed.raw_transaction)).expect("parse signed"),
            signed.transaction
        );
        assert_eq!(signed.txid.len(), 64);
        drop(wallet);
        fs::remove_file(seed_path).expect("remove test wallet seed");
    }

    #[test]
    fn funding_builder_rejects_duplicates_and_shortfall() {
        let (wallet, seed_path) = random_wallet();
        let destination = wallet
            .derive_address(WalletPath::new(0, false, 1).expect("destination path"))
            .expect("destination address");
        let request = FundingRequest {
            destination_script_pubkey: destination.script_pubkey.to_vec(),
            amount_sat: 50_000,
            fee_rate_sat_per_vbyte: 2,
            change_path: WalletPath::new(0, true, 0).expect("change path"),
            lock_time: 0,
        };
        let input = FundingInput {
            txid: "22".repeat(32),
            vout: 0,
            value_sat: 50_000,
            path: WalletPath::new(0, false, 0).expect("input path"),
        };
        assert_eq!(
            build_funding_transaction(&wallet, std::slice::from_ref(&input), &request),
            Err(FundingError::InsufficientFunds)
        );
        let funded_input = FundingInput {
            value_sat: 100_000,
            ..input
        };
        assert_eq!(
            build_funding_transaction(&wallet, &[funded_input.clone(), funded_input], &request),
            Err(FundingError::Invalid("funding inputs repeat an outpoint"))
        );
        drop(wallet);
        fs::remove_file(seed_path).expect("remove test wallet seed");
    }

    fn random_wallet() -> (ProviderWallet, PathBuf) {
        let mut seed = [0_u8; 32];
        OpenOptions::new()
            .read(true)
            .open("/dev/urandom")
            .expect("open randomness")
            .read_exact(&mut seed)
            .expect("read randomness");
        let path = std::env::temp_dir().join(format!(
            "immortal-provider-funding-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create wallet seed");
        file.write_all(super::encode_hex(&seed).as_bytes())
            .expect("write wallet seed");
        seed.fill(0);
        drop(file);
        let wallet = ProviderWallet::load(&path, BitcoinNetwork::Regtest).expect("load wallet");
        (wallet, path)
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = super::hex_nibble(pair[0]).expect("hex high");
                let low = super::hex_nibble(pair[1]).expect("hex low");
                high << 4 | low
            })
            .collect()
    }
}
