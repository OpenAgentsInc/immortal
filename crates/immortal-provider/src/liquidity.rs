use std::{collections::BTreeMap, fmt};

use serde_json::{Value, json};

use crate::{
    bitcoind::{BitcoindClient, BitcoindError, RpcRequestId},
    funding::FundingInput,
    store::{OutPoint, ProviderStore, ProviderStoreError, StoredUtxo, UtxoObservation},
    wallet::{ProviderWallet, WalletError, WalletPath},
};

const MAX_GAP_LIMIT: u32 = 64;
const MAX_ELIGIBLE_UTXOS: usize = 64;
const MAX_SCAN_UNSPENTS: usize = 512;
const COINBASE_MATURITY: u32 = 100;
const MAX_BITCOIN_SATOSHIS: u128 = 2_100_000_000_000_000;

#[derive(Debug)]
pub enum LiquidityError {
    InvalidConfiguration(&'static str),
    InvalidScan(&'static str),
    Wallet(WalletError),
    Bitcoind(BitcoindError),
    Store(ProviderStoreError),
}

impl fmt::Display for LiquidityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid liquidity scan configuration: {detail}")
            }
            Self::InvalidScan(detail) => write!(formatter, "invalid scantxoutset result: {detail}"),
            Self::Wallet(error) => write!(formatter, "provider wallet discovery failed: {error}"),
            Self::Bitcoind(error) => write!(formatter, "provider UTXO scan failed: {error}"),
            Self::Store(_) => formatter.write_str("provider UTXO state update failed"),
        }
    }
}

impl std::error::Error for LiquidityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wallet(error) => Some(error),
            Self::Bitcoind(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::InvalidConfiguration(_) | Self::InvalidScan(_) => None,
        }
    }
}

impl From<WalletError> for LiquidityError {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

impl From<BitcoindError> for LiquidityError {
    fn from(error: BitcoindError) -> Self {
        Self::Bitcoind(error)
    }
}

impl From<ProviderStoreError> for LiquidityError {
    fn from(error: ProviderStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletScanPolicy {
    pub asset_id: String,
    pub account: u32,
    pub first_address_index: u32,
    pub gap_limit: u32,
    pub minimum_confirmations: u32,
    pub maximum_eligible_utxos: usize,
}

impl WalletScanPolicy {
    pub fn new(
        asset_id: impl Into<String>,
        account: u32,
        first_address_index: u32,
        gap_limit: u32,
        minimum_confirmations: u32,
        maximum_eligible_utxos: usize,
    ) -> Result<Self, LiquidityError> {
        let policy = Self {
            asset_id: asset_id.into(),
            account,
            first_address_index,
            gap_limit,
            minimum_confirmations,
            maximum_eligible_utxos,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), LiquidityError> {
        if !self.asset_id.starts_with("swp:1:")
            || self.asset_id.len() > 512
            || self.asset_id.chars().any(char::is_control)
        {
            return Err(LiquidityError::InvalidConfiguration(
                "asset ID is outside bounds",
            ));
        }
        if self.gap_limit == 0 || self.gap_limit > MAX_GAP_LIMIT {
            return Err(LiquidityError::InvalidConfiguration(
                "BIP-86 gap limit is outside bounds",
            ));
        }
        if self.maximum_eligible_utxos == 0 || self.maximum_eligible_utxos > MAX_ELIGIBLE_UTXOS {
            return Err(LiquidityError::InvalidConfiguration(
                "eligible UTXO limit is outside bounds",
            ));
        }
        if self.minimum_confirmations > i32::MAX as u32 {
            return Err(LiquidityError::InvalidConfiguration(
                "minimum confirmation count is outside bounds",
            ));
        }
        let last_index = self
            .first_address_index
            .checked_add(self.gap_limit - 1)
            .ok_or(LiquidityError::InvalidConfiguration(
                "BIP-86 scan window overflows",
            ))?;
        WalletPath::new(self.account, false, last_index).map_err(LiquidityError::Wallet)?;
        WalletPath::new(self.account, true, last_index).map_err(LiquidityError::Wallet)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletLiquidity {
    pub scan_height: u64,
    pub best_block: String,
    pub funding_inputs: Vec<FundingInput>,
}

pub async fn discover_wallet_utxos(
    bitcoind: &BitcoindClient,
    store: &ProviderStore,
    wallet: &ProviderWallet,
    request_id: &RpcRequestId,
    policy: &WalletScanPolicy,
    observed_at: u64,
) -> Result<WalletLiquidity, LiquidityError> {
    discover_with(bitcoind, store, wallet, request_id, policy, observed_at).await
}

pub fn btc_decimal_to_satoshis(value: &Value) -> Result<u64, LiquidityError> {
    let Value::Number(amount) = value else {
        return Err(LiquidityError::InvalidScan(
            "UTXO amount is not a JSON number",
        ));
    };
    parse_btc_number(&amount.to_string())
}

trait ScanSource {
    async fn scan_tx_out_set(
        &self,
        request_id: &RpcRequestId,
        descriptors: &[String],
    ) -> Result<Value, LiquidityError>;
}

impl ScanSource for BitcoindClient {
    async fn scan_tx_out_set(
        &self,
        request_id: &RpcRequestId,
        descriptors: &[String],
    ) -> Result<Value, LiquidityError> {
        self.call(request_id, "scantxoutset", json!(["start", descriptors]))
            .await
            .map_err(LiquidityError::Bitcoind)
    }
}

trait LiquidityStore {
    async fn observe(&self, observation: &UtxoObservation) -> Result<(), LiquidityError>;

    async fn available(
        &self,
        asset_id: &str,
        script_pubkeys: &[String],
        minimum_confirmations: u32,
        limit: usize,
    ) -> Result<Vec<StoredUtxo>, LiquidityError>;
}

impl LiquidityStore for ProviderStore {
    async fn observe(&self, observation: &UtxoObservation) -> Result<(), LiquidityError> {
        self.observe_utxo(observation)
            .await
            .map_err(LiquidityError::Store)
    }

    async fn available(
        &self,
        asset_id: &str,
        script_pubkeys: &[String],
        minimum_confirmations: u32,
        limit: usize,
    ) -> Result<Vec<StoredUtxo>, LiquidityError> {
        self.available_utxos(asset_id, script_pubkeys, minimum_confirmations, limit)
            .await
            .map_err(LiquidityError::Store)
    }
}

async fn discover_with<S: ScanSource, T: LiquidityStore>(
    source: &S,
    store: &T,
    wallet: &ProviderWallet,
    request_id: &RpcRequestId,
    policy: &WalletScanPolicy,
    observed_at: u64,
) -> Result<WalletLiquidity, LiquidityError> {
    policy.validate()?;
    if observed_at > i64::MAX as u64 {
        return Err(LiquidityError::InvalidConfiguration(
            "observation time is outside bounds",
        ));
    }
    let script_paths = derive_script_paths(wallet, policy)?;
    let script_pubkeys = script_paths.keys().cloned().collect::<Vec<_>>();
    let descriptors = script_pubkeys
        .iter()
        .map(|script| format!("raw({script})"))
        .collect::<Vec<_>>();
    let previously_available = store
        .available(
            &policy.asset_id,
            &script_pubkeys,
            0,
            policy.maximum_eligible_utxos,
        )
        .await?;
    let result = source.scan_tx_out_set(request_id, &descriptors).await?;
    let scan = parse_scan(result, &script_paths, &policy.asset_id, observed_at)?;
    let mut current = BTreeMap::new();
    for observation in &scan.observations {
        let key = (observation.outpoint.txid.clone(), observation.outpoint.vout);
        if current.insert(key, ()).is_some() {
            return Err(LiquidityError::InvalidScan("UTXO scan repeats an outpoint"));
        }
    }
    for observation in &scan.observations {
        store.observe(observation).await?;
    }
    for known in previously_available {
        if current.contains_key(&(known.outpoint.txid.clone(), known.outpoint.vout)) {
            continue;
        }
        store
            .observe(&UtxoObservation {
                outpoint: known.outpoint,
                asset_id: known.asset_id,
                amount: known.amount,
                script_pubkey: known.script_pubkey,
                state: "spent".to_owned(),
                confirmations: known.confirmations,
                block_hash: known.block_hash,
                replacement_txid: known.replacement_txid,
                observed_at,
            })
            .await?;
    }

    let available = store
        .available(
            &policy.asset_id,
            &script_pubkeys,
            policy.minimum_confirmations,
            policy.maximum_eligible_utxos,
        )
        .await?;
    let mut funding_inputs = Vec::with_capacity(available.len());
    for stored in available {
        if !current.contains_key(&(stored.outpoint.txid.clone(), stored.outpoint.vout)) {
            continue;
        }
        let path =
            script_paths
                .get(&stored.script_pubkey)
                .copied()
                .ok_or(LiquidityError::InvalidScan(
                    "stored UTXO script is outside the wallet scan window",
                ))?;
        funding_inputs.push(FundingInput {
            txid: stored.outpoint.txid,
            vout: stored.outpoint.vout,
            value_sat: stored.amount,
            path,
        });
    }
    Ok(WalletLiquidity {
        scan_height: scan.height,
        best_block: scan.best_block,
        funding_inputs,
    })
}

fn derive_script_paths(
    wallet: &ProviderWallet,
    policy: &WalletScanPolicy,
) -> Result<BTreeMap<String, WalletPath>, LiquidityError> {
    let mut scripts = BTreeMap::new();
    for change in [false, true] {
        for offset in 0..policy.gap_limit {
            let address_index = policy.first_address_index.checked_add(offset).ok_or(
                LiquidityError::InvalidConfiguration("BIP-86 scan window overflows"),
            )?;
            let path = WalletPath::new(policy.account, change, address_index)?;
            let address = wallet.derive_address(path)?;
            let script = encode_hex(&address.script_pubkey);
            if scripts.insert(script, path).is_some() {
                return Err(LiquidityError::InvalidScan(
                    "wallet scan window repeats a script",
                ));
            }
        }
    }
    Ok(scripts)
}

struct ParsedScan {
    height: u64,
    best_block: String,
    observations: Vec<UtxoObservation>,
}

fn parse_scan(
    result: Value,
    script_paths: &BTreeMap<String, WalletPath>,
    asset_id: &str,
    observed_at: u64,
) -> Result<ParsedScan, LiquidityError> {
    let object = result
        .as_object()
        .ok_or(LiquidityError::InvalidScan("result is not an object"))?;
    if object.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(LiquidityError::InvalidScan("scan did not complete"));
    }
    let height = object
        .get("height")
        .and_then(Value::as_u64)
        .ok_or(LiquidityError::InvalidScan("scan height is invalid"))?;
    let best_block = object
        .get("bestblock")
        .and_then(Value::as_str)
        .ok_or(LiquidityError::InvalidScan("best block is missing"))?;
    if !is_lower_hex_32(best_block) {
        return Err(LiquidityError::InvalidScan("best block is invalid"));
    }
    let unspents = object
        .get("unspents")
        .and_then(Value::as_array)
        .ok_or(LiquidityError::InvalidScan("unspents is not an array"))?;
    if unspents.len() > MAX_SCAN_UNSPENTS {
        return Err(LiquidityError::InvalidScan(
            "unspent result exceeds the scan bound",
        ));
    }
    let mut observations = Vec::with_capacity(unspents.len());
    for unspent in unspents {
        observations.push(parse_unspent(
            unspent,
            height,
            script_paths,
            asset_id,
            observed_at,
        )?);
    }
    Ok(ParsedScan {
        height,
        best_block: best_block.to_owned(),
        observations,
    })
}

fn parse_unspent(
    value: &Value,
    scan_height: u64,
    script_paths: &BTreeMap<String, WalletPath>,
    asset_id: &str,
    observed_at: u64,
) -> Result<UtxoObservation, LiquidityError> {
    let object = value.as_object().ok_or(LiquidityError::InvalidScan(
        "unspent entry is not an object",
    ))?;
    let txid = object
        .get("txid")
        .and_then(Value::as_str)
        .ok_or(LiquidityError::InvalidScan("UTXO txid is missing"))?;
    if !is_lower_hex_32(txid) {
        return Err(LiquidityError::InvalidScan("UTXO txid is invalid"));
    }
    let vout = object
        .get("vout")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(LiquidityError::InvalidScan("UTXO vout is invalid"))?;
    let script_pubkey = object
        .get("scriptPubKey")
        .and_then(Value::as_str)
        .ok_or(LiquidityError::InvalidScan("UTXO scriptPubKey is missing"))?;
    if !script_paths.contains_key(script_pubkey) {
        return Err(LiquidityError::InvalidScan(
            "UTXO script is outside the wallet scan window",
        ));
    }
    let amount = btc_decimal_to_satoshis(
        object
            .get("amount")
            .ok_or(LiquidityError::InvalidScan("UTXO amount is missing"))?,
    )?;
    if amount == 0 {
        return Err(LiquidityError::InvalidScan("UTXO amount is zero"));
    }
    let output_height = object
        .get("height")
        .and_then(Value::as_u64)
        .ok_or(LiquidityError::InvalidScan("UTXO height is invalid"))?;
    if output_height > scan_height {
        return Err(LiquidityError::InvalidScan(
            "UTXO height follows the scan tip",
        ));
    }
    let derived_confirmations = scan_height
        .checked_sub(output_height)
        .and_then(|difference| difference.checked_add(1))
        .and_then(|confirmations| u32::try_from(confirmations).ok())
        .ok_or(LiquidityError::InvalidScan(
            "UTXO confirmation count is invalid",
        ))?;
    let confirmations = match object.get("confirmations") {
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value == derived_confirmations)
            .ok_or(LiquidityError::InvalidScan(
                "UTXO confirmation count disagrees with its height",
            ))?,
        None => derived_confirmations,
    };
    let block_hash = match object.get("blockhash") {
        Some(Value::String(hash)) if is_lower_hex_32(hash) => Some(hash.clone()),
        Some(_) => return Err(LiquidityError::InvalidScan("UTXO block hash is invalid")),
        None => None,
    };
    let coinbase = match object.get("coinbase") {
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(LiquidityError::InvalidScan("coinbase marker is invalid")),
        None => false,
    };
    let state = if coinbase && confirmations < COINBASE_MATURITY {
        "unresolved"
    } else {
        "available"
    };
    Ok(UtxoObservation {
        outpoint: OutPoint {
            txid: txid.to_owned(),
            vout,
        },
        asset_id: asset_id.to_owned(),
        amount,
        script_pubkey: script_pubkey.to_owned(),
        state: state.to_owned(),
        confirmations,
        block_hash,
        replacement_txid: None,
        observed_at,
    })
}

fn parse_btc_number(value: &str) -> Result<u64, LiquidityError> {
    let (mantissa, exponent) =
        value
            .split_once(['e', 'E'])
            .map_or((value, 0_i32), |(mantissa, exponent)| {
                let exponent = exponent.parse::<i32>().unwrap_or(i32::MIN);
                (mantissa, exponent)
            });
    if exponent == i32::MIN || mantissa.starts_with('-') || mantissa.starts_with('+') {
        return Err(LiquidityError::InvalidScan("UTXO amount is invalid"));
    }
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(whole, fraction)| (whole, fraction));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LiquidityError::InvalidScan("UTXO amount is invalid"));
    }
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let magnitude = digits
        .parse::<u128>()
        .map_err(|_| LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
    let fraction_digits = i32::try_from(fraction.len())
        .map_err(|_| LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
    let satoshi_exponent = exponent
        .checked_sub(fraction_digits)
        .and_then(|value| value.checked_add(8))
        .ok_or(LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
    let satoshis = if satoshi_exponent >= 0 {
        let exponent = u32::try_from(satoshi_exponent)
            .map_err(|_| LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
        let scale = 10_u128
            .checked_pow(exponent)
            .ok_or(LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
        magnitude
            .checked_mul(scale)
            .ok_or(LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?
    } else {
        let exponent = satoshi_exponent
            .checked_neg()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
        let divisor = 10_u128
            .checked_pow(exponent)
            .ok_or(LiquidityError::InvalidScan("UTXO amount exceeds bounds"))?;
        if magnitude % divisor != 0 {
            return Err(LiquidityError::InvalidScan(
                "UTXO amount is not an exact satoshi amount",
            ));
        }
        magnitude / divisor
    };
    if satoshis > MAX_BITCOIN_SATOSHIS {
        return Err(LiquidityError::InvalidScan(
            "UTXO amount exceeds Bitcoin supply bounds",
        ));
    }
    u64::try_from(satoshis).map_err(|_| LiquidityError::InvalidScan("UTXO amount exceeds bounds"))
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    };

    use serde_json::{Value, json};

    use super::{
        LiquidityError, LiquidityStore, ScanSource, WalletScanPolicy, btc_decimal_to_satoshis,
        discover_with, encode_hex,
    };
    use crate::{
        bitcoind::RpcRequestId,
        store::{OutPoint, StoredUtxo, UtxoObservation},
        wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestScanSource {
        result: Value,
        descriptors: Mutex<Vec<String>>,
    }

    impl ScanSource for TestScanSource {
        async fn scan_tx_out_set(
            &self,
            _request_id: &RpcRequestId,
            descriptors: &[String],
        ) -> Result<Value, LiquidityError> {
            *self.descriptors.lock().expect("descriptor lock") = descriptors.to_vec();
            Ok(self.result.clone())
        }
    }

    struct TestStore {
        rows: Mutex<BTreeMap<(String, u32), StoredUtxo>>,
        observations: Mutex<Vec<UtxoObservation>>,
    }

    impl TestStore {
        fn new(rows: Vec<StoredUtxo>) -> Self {
            Self {
                rows: Mutex::new(
                    rows.into_iter()
                        .map(|row| ((row.outpoint.txid.clone(), row.outpoint.vout), row))
                        .collect(),
                ),
                observations: Mutex::new(Vec::new()),
            }
        }
    }

    impl LiquidityStore for TestStore {
        async fn observe(&self, observation: &UtxoObservation) -> Result<(), LiquidityError> {
            self.observations
                .lock()
                .expect("observation lock")
                .push(observation.clone());
            self.rows.lock().expect("row lock").insert(
                (observation.outpoint.txid.clone(), observation.outpoint.vout),
                StoredUtxo {
                    outpoint: observation.outpoint.clone(),
                    asset_id: observation.asset_id.clone(),
                    amount: observation.amount,
                    script_pubkey: observation.script_pubkey.clone(),
                    state: observation.state.clone(),
                    confirmations: observation.confirmations,
                    block_hash: observation.block_hash.clone(),
                    replacement_txid: observation.replacement_txid.clone(),
                    observed_at: observation.observed_at,
                },
            );
            Ok(())
        }

        async fn available(
            &self,
            asset_id: &str,
            script_pubkeys: &[String],
            minimum_confirmations: u32,
            limit: usize,
        ) -> Result<Vec<StoredUtxo>, LiquidityError> {
            let mut rows = self
                .rows
                .lock()
                .expect("row lock")
                .values()
                .filter(|row| {
                    row.asset_id == asset_id
                        && row.state == "available"
                        && row.confirmations >= minimum_confirmations
                        && script_pubkeys.contains(&row.script_pubkey)
                })
                .cloned()
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| {
                right
                    .amount
                    .cmp(&left.amount)
                    .then(left.outpoint.txid.cmp(&right.outpoint.txid))
                    .then(left.outpoint.vout.cmp(&right.outpoint.vout))
            });
            rows.truncate(limit);
            Ok(rows)
        }
    }

    #[test]
    fn btc_decimal_conversion_is_exact_without_float_arithmetic() {
        for (value, expected) in [
            (json!(0), 0),
            (json!(0.00000001), 1),
            (json!(0.00000003), 3),
            (json!(1.23456789), 123_456_789),
            (json!(21_000_000), 2_100_000_000_000_000),
        ] {
            assert_eq!(
                btc_decimal_to_satoshis(&value).expect("exact amount"),
                expected
            );
        }
        for value in [
            json!("0.00000001"),
            serde_json::from_str::<Value>("0.000000001").expect("sub-satoshi number"),
            json!(-1),
            serde_json::from_str::<Value>("21000000.00000001").expect("oversupply number"),
        ] {
            assert!(matches!(
                btc_decimal_to_satoshis(&value),
                Err(LiquidityError::InvalidScan(_))
            ));
        }
    }

    #[tokio::test]
    async fn discovery_scans_both_bip86_branches_tracks_public_state_and_maps_paths() {
        let (wallet, seed_path) = random_wallet();
        let receive_zero = wallet
            .derive_address(WalletPath::new(0, false, 0).expect("receive zero path"))
            .expect("receive zero address");
        let receive_one = wallet
            .derive_address(WalletPath::new(0, false, 1).expect("receive one path"))
            .expect("receive one address");
        let change_zero = wallet
            .derive_address(WalletPath::new(0, true, 0).expect("change zero path"))
            .expect("change zero address");
        let asset_id = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
        let stale = StoredUtxo {
            outpoint: OutPoint {
                txid: "11".repeat(32),
                vout: 0,
            },
            asset_id: asset_id.to_owned(),
            amount: 75_000,
            script_pubkey: encode_hex(&receive_zero.script_pubkey),
            state: "available".to_owned(),
            confirmations: 8,
            block_hash: Some("22".repeat(32)),
            replacement_txid: None,
            observed_at: 99,
        };
        let store = TestStore::new(vec![stale]);
        let source = TestScanSource {
            result: json!({
                "success":true,
                "height":200,
                "bestblock":"33".repeat(32),
                "unspents":[
                    {
                        "txid":"44".repeat(32),
                        "vout":1,
                        "scriptPubKey":encode_hex(&receive_one.script_pubkey),
                        "amount":0.00100001,
                        "height":195,
                        "blockhash":"55".repeat(32),
                        "confirmations":6,
                        "coinbase":false
                    },
                    {
                        "txid":"66".repeat(32),
                        "vout":2,
                        "scriptPubKey":encode_hex(&change_zero.script_pubkey),
                        "amount":0.00000001,
                        "height":200,
                        "blockhash":"33".repeat(32),
                        "confirmations":1,
                        "coinbase":false
                    }
                ]
            }),
            descriptors: Mutex::new(Vec::new()),
        };
        let policy = WalletScanPolicy::new(asset_id, 0, 0, 2, 2, 64).expect("scan policy");
        let liquidity = discover_with(
            &source,
            &store,
            &wallet,
            &RpcRequestId::new("liquidity:test:1").expect("request ID"),
            &policy,
            100,
        )
        .await
        .expect("wallet discovery");

        assert_eq!(liquidity.scan_height, 200);
        assert_eq!(liquidity.best_block, "33".repeat(32));
        assert_eq!(liquidity.funding_inputs.len(), 1);
        assert_eq!(liquidity.funding_inputs[0].txid, "44".repeat(32));
        assert_eq!(liquidity.funding_inputs[0].value_sat, 100_001);
        assert_eq!(
            liquidity.funding_inputs[0].path,
            WalletPath::new(0, false, 1).expect("mapped path")
        );

        let descriptors = source.descriptors.lock().expect("descriptor lock");
        assert_eq!(descriptors.len(), 4);
        assert!(descriptors.contains(&format!("raw({})", encode_hex(&receive_one.script_pubkey))));
        assert!(descriptors.contains(&format!("raw({})", encode_hex(&change_zero.script_pubkey))));
        let observations = store.observations.lock().expect("observation lock");
        assert_eq!(observations.len(), 3);
        assert!(observations.iter().any(|observation| {
            observation.outpoint.txid == "11".repeat(32) && observation.state == "spent"
        }));
        assert!(observations.iter().all(|observation| {
            observation.replacement_txid.is_none()
                && !observation.asset_id.contains("seed")
                && !observation.script_pubkey.contains("seed")
        }));

        drop(wallet);
        fs::remove_file(seed_path).expect("remove wallet seed");
    }

    #[tokio::test]
    async fn discovery_rejects_unrequested_scripts_before_persistence() {
        let (wallet, seed_path) = random_wallet();
        let store = TestStore::new(Vec::new());
        let source = TestScanSource {
            result: json!({
                "success":true,
                "height":20,
                "bestblock":"77".repeat(32),
                "unspents":[{
                    "txid":"88".repeat(32),
                    "vout":0,
                    "scriptPubKey":"5120".to_owned() + &"99".repeat(32),
                    "amount":1,
                    "height":20,
                    "confirmations":1
                }]
            }),
            descriptors: Mutex::new(Vec::new()),
        };
        let error = discover_with(
            &source,
            &store,
            &wallet,
            &RpcRequestId::new("liquidity:test:2").expect("request ID"),
            &WalletScanPolicy::new("swp:1:bitcoin-regtest", 0, 0, 1, 1, 1).expect("scan policy"),
            20,
        )
        .await
        .expect_err("foreign script must fail closed");
        assert!(matches!(error, LiquidityError::InvalidScan(_)));
        assert!(
            store
                .observations
                .lock()
                .expect("observation lock")
                .is_empty()
        );

        drop(wallet);
        fs::remove_file(seed_path).expect("remove wallet seed");
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
            "immortal-provider-liquidity-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create wallet seed");
        file.write_all(encode_hex(&seed).as_bytes())
            .expect("write wallet seed");
        seed.fill(0);
        drop(file);
        let wallet = ProviderWallet::load(&path, BitcoinNetwork::Regtest).expect("load wallet");
        (wallet, path)
    }
}
