use std::fmt;

use immortal_core::liquid::{
    LiquidAssetId, LiquidError, LiquidNetworkId, LiquidTransaction, parse_liquid_transaction,
    verify_liquid_network,
};
use serde_json::{Value, json};

use crate::bitcoind::{
    BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindError, BitcoindLimits, RpcRequestId,
};

const MAX_WALLET_NAME_BYTES: usize = 128;
pub const MAX_SPENDER_MEMPOOL_TRANSACTIONS: usize = 4_096;
pub const MAX_SPENDER_RECENT_BLOCKS: u32 = 144;
pub const MAX_SPENDER_BLOCK_TRANSACTIONS: usize = 100_000;
pub const MAX_SPENDER_INPUTS: usize = 4_096;
pub const ELEMENTSD_PRODUCTION_RUNTIME_METHODS: [&str; 19] = [
    "getblockchaininfo",
    "getsidechaininfo",
    "getblockcount",
    "getblockhash",
    "getblock",
    "getrawmempool",
    "getrawtransaction",
    "gettxout",
    "unblindrawtransaction",
    "testmempoolaccept",
    "sendrawtransaction",
    "listunspent",
    "getdescriptorinfo",
    "deriveaddresses",
    "walletcreatefundedpsbt",
    "walletprocesspsbt",
    "finalizepsbt",
    "getwalletinfo",
    "help",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElementsdError {
    InvalidConfiguration(&'static str),
    Rpc(BitcoindError),
    Json(&'static str),
    Liquid(LiquidError),
    MempoolRejected,
}

impl fmt::Display for ElementsdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid elementsd configuration: {detail}")
            }
            Self::Rpc(error) => write!(formatter, "elementsd RPC failed: {error}"),
            Self::Json(detail) => write!(formatter, "invalid elementsd result: {detail}"),
            Self::Liquid(error) => write!(formatter, "invalid Elements artifact: {error}"),
            Self::MempoolRejected => {
                formatter.write_str("elementsd rejected the signed transaction")
            }
        }
    }
}

impl std::error::Error for ElementsdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rpc(error) => Some(error),
            Self::Liquid(error) => Some(error),
            _ => None,
        }
    }
}

impl From<BitcoindError> for ElementsdError {
    fn from(error: BitcoindError) -> Self {
        Self::Rpc(error)
    }
}

impl From<LiquidError> for ElementsdError {
    fn from(error: LiquidError) -> Self {
        Self::Liquid(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ElementsdWalletName(String);

impl ElementsdWalletName {
    pub fn new(value: impl Into<String>) -> Result<Self, ElementsdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_WALLET_NAME_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ElementsdError::InvalidConfiguration(
                "wallet name is empty, too long, or contains a forbidden byte",
            ));
        }
        Ok(Self(value))
    }

    fn rpc_path(&self) -> String {
        format!("/wallet/{}", self.0)
    }
}

impl fmt::Debug for ElementsdWalletName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ElementsdWalletName([configured])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdNetworkView {
    pub network_id: LiquidNetworkId,
    pub genesis_hash: String,
    pub pegged_asset: LiquidAssetId,
    pub best_block_hash: String,
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdOutputObservation {
    pub raw_transaction: Vec<u8>,
    pub confirmations: u32,
    pub block_hash: Option<String>,
    pub unspent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdTransactionObservation {
    pub raw_transaction: Vec<u8>,
    pub confirmations: u32,
    pub block_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdSpendingObservation {
    pub funding_transaction_id: String,
    pub funding_output_index: u32,
    pub spending_transaction_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdWalletUtxo {
    pub transaction_id: String,
    pub output_index: u32,
    pub amount_sat: u64,
    pub script_pubkey: String,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdWalletCapacity {
    pub total_sat: u64,
    pub utxos: Vec<ElementsdWalletUtxo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementsdSignedFunding {
    pub transaction_id: String,
    pub raw_transaction: Vec<u8>,
    pub output_index: u32,
    pub amount_sat: u64,
    pub fee_sat: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementsdMempoolAdmission {
    New,
    ExactKnown,
}

#[derive(Clone)]
pub struct ElementsdClient {
    rpc: BitcoindClient,
    wallet: ElementsdWalletName,
    expected_network: LiquidNetworkId,
    expected_pegged_asset: LiquidAssetId,
}

impl fmt::Debug for ElementsdClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementsdClient")
            .field("rpc", &self.rpc)
            .field("wallet", &self.wallet)
            .field("expected_network", &self.expected_network)
            .field("expected_pegged_asset", &self.expected_pegged_asset)
            .finish()
    }
}

impl ElementsdClient {
    pub fn new(
        endpoint: BitcoindEndpoint,
        auth: BitcoindAuth,
        limits: BitcoindLimits,
        wallet: ElementsdWalletName,
        expected_network: LiquidNetworkId,
        expected_pegged_asset: LiquidAssetId,
    ) -> Result<Self, ElementsdError> {
        Ok(Self {
            rpc: BitcoindClient::new(endpoint, auth, limits)?,
            wallet,
            expected_network,
            expected_pegged_asset,
        })
    }

    pub fn expected_network(&self) -> &LiquidNetworkId {
        &self.expected_network
    }

    pub fn expected_pegged_asset(&self) -> LiquidAssetId {
        self.expected_pegged_asset
    }

    pub async fn genesis_hash(&self, request_id: &RpcRequestId) -> Result<String, ElementsdError> {
        let genesis_hash = self
            .rpc
            .call(request_id, "getblockhash", json!([0]))
            .await?
            .as_str()
            .ok_or(ElementsdError::Json("genesis result is not a hash"))?
            .to_owned();
        validate_lower_hex(&genesis_hash, 64, "genesis hash")?;
        if LiquidNetworkId::from_genesis_hash(&genesis_hash)? != self.expected_network {
            return Err(ElementsdError::Liquid(LiquidError::NetworkMismatch));
        }
        Ok(genesis_hash)
    }

    pub async fn probe(
        &self,
        request_prefix: &str,
    ) -> Result<ElementsdNetworkView, ElementsdError> {
        validate_request_prefix(request_prefix)?;
        let genesis_hash = self
            .rpc
            .call(
                &request_id(request_prefix, "genesis")?,
                "getblockhash",
                json!([0]),
            )
            .await?
            .as_str()
            .ok_or(ElementsdError::Json("genesis result is not a hash"))?
            .to_owned();
        validate_lower_hex(&genesis_hash, 64, "genesis hash")?;
        let sidechain = self
            .rpc
            .call(
                &request_id(request_prefix, "sidechain")?,
                "getsidechaininfo",
                json!([]),
            )
            .await?;
        let pegged_asset = sidechain
            .as_object()
            .and_then(|object| object.get("pegged_asset"))
            .and_then(Value::as_str)
            .ok_or(ElementsdError::Json("sidechain info has no pegged asset"))?;
        validate_lower_hex(pegged_asset, 64, "pegged asset")?;
        verify_liquid_network(
            &self.expected_network,
            self.expected_pegged_asset,
            &genesis_hash,
            pegged_asset,
        )?;
        let chain = self
            .rpc
            .call(
                &request_id(request_prefix, "tip")?,
                "getblockchaininfo",
                json!([]),
            )
            .await?;
        let chain = chain
            .as_object()
            .ok_or(ElementsdError::Json("chain info is not an object"))?;
        let best_block_hash = chain
            .get("bestblockhash")
            .and_then(Value::as_str)
            .ok_or(ElementsdError::Json("chain info has no best block hash"))?;
        validate_lower_hex(best_block_hash, 64, "best block hash")?;
        let height = chain
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or(ElementsdError::Json("chain info has no block height"))?;
        Ok(ElementsdNetworkView {
            network_id: self.expected_network.clone(),
            genesis_hash,
            pegged_asset: self.expected_pegged_asset,
            best_block_hash: best_block_hash.to_owned(),
            height,
        })
    }

    pub async fn startup_probe(
        &self,
        request_prefix: &str,
    ) -> Result<ElementsdNetworkView, ElementsdError> {
        let network = self.probe(request_prefix).await?;
        let wallet = self
            .rpc
            .call_path(
                &request_id(request_prefix, "wallet")?,
                &self.wallet.rpc_path(),
                "getwalletinfo",
                json!([]),
            )
            .await?;
        if !wallet.is_object() {
            return Err(ElementsdError::Json(
                "configured Elements wallet info is not an object",
            ));
        }
        for (index, method) in ELEMENTSD_PRODUCTION_RUNTIME_METHODS
            .iter()
            .filter(|method| !matches!(**method, "getwalletinfo" | "help"))
            .enumerate()
        {
            let help = self
                .rpc
                .call(
                    &request_id(request_prefix, &format!("capability-{index}"))?,
                    "help",
                    json!([method]),
                )
                .await?;
            let help = help.as_str().filter(|help| help.len() <= 1_048_576).ok_or(
                ElementsdError::Json("Elements capability help is not a bounded string"),
            )?;
            if help.split_ascii_whitespace().next() != Some(*method) {
                return Err(ElementsdError::Json(
                    "Elements capability help returned another method",
                ));
            }
        }
        Ok(network)
    }

    pub async fn raw_transaction(
        &self,
        request_id: &RpcRequestId,
        transaction_id: &str,
    ) -> Result<Vec<u8>, ElementsdError> {
        validate_lower_hex(transaction_id, 64, "transaction ID")?;
        let result = self
            .rpc
            .call(
                request_id,
                "getrawtransaction",
                json!([transaction_id, false]),
            )
            .await?;
        decode_hex_result(&result, "raw transaction")
    }

    pub async fn new_address(&self, request_id: &RpcRequestId) -> Result<String, ElementsdError> {
        let address = self
            .rpc
            .call_path(
                request_id,
                &self.wallet.rpc_path(),
                "getnewaddress",
                json!([]),
            )
            .await?
            .as_str()
            .filter(|address| !address.is_empty() && address.len() <= 128)
            .ok_or(ElementsdError::Json("new address result is invalid"))?
            .to_owned();
        if !address
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
        {
            return Err(ElementsdError::Json("new address contains an invalid byte"));
        }
        Ok(address)
    }

    pub async fn generate_to_address(
        &self,
        request_id: &RpcRequestId,
        blocks: u32,
        address: &str,
    ) -> Result<Vec<String>, ElementsdError> {
        if blocks == 0
            || blocks > 1_000
            || address.is_empty()
            || address.len() > 128
            || !address
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
        {
            return Err(ElementsdError::InvalidConfiguration(
                "block generation request is invalid",
            ));
        }
        let hashes = self
            .rpc
            .call(request_id, "generatetoaddress", json!([blocks, address]))
            .await?
            .as_array()
            .filter(|hashes| hashes.len() == blocks as usize)
            .ok_or(ElementsdError::Json(
                "generated block result has another cardinality",
            ))?
            .iter()
            .map(|hash| {
                let hash = hash
                    .as_str()
                    .ok_or(ElementsdError::Json("generated block hash is not a string"))?;
                validate_lower_hex(hash, 64, "generated block hash")?;
                Ok(hash.to_owned())
            })
            .collect::<Result<Vec<_>, ElementsdError>>()?;
        Ok(hashes)
    }

    pub async fn confirmed_pegged_capacity(
        &self,
        request_id: &RpcRequestId,
        minimum_confirmations: u32,
        maximum_outputs: usize,
    ) -> Result<ElementsdWalletCapacity, ElementsdError> {
        if minimum_confirmations == 0 || maximum_outputs == 0 || maximum_outputs > 64 {
            return Err(ElementsdError::InvalidConfiguration(
                "wallet capacity bounds are invalid",
            ));
        }
        let result = self
            .rpc
            .call_path(
                request_id,
                &self.wallet.rpc_path(),
                "listunspent",
                json!([
                    minimum_confirmations,
                    9_999_999,
                    [],
                    false,
                    {
                        "maximumCount":maximum_outputs,
                        "asset":self.expected_pegged_asset.to_string(),
                    }
                ]),
            )
            .await?;
        let entries = result
            .as_array()
            .ok_or(ElementsdError::Json("wallet UTXO result is not an array"))?;
        if entries.len() > maximum_outputs {
            return Err(ElementsdError::Json(
                "wallet UTXO result exceeds the requested bound",
            ));
        }
        let mut total_sat = 0_u64;
        let mut utxos = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or(ElementsdError::Json("wallet UTXO is not an object"))?;
            if entry.get("spendable").and_then(Value::as_bool) != Some(true)
                || entry.get("solvable").and_then(Value::as_bool) != Some(true)
                || entry.get("safe").and_then(Value::as_bool) != Some(true)
            {
                continue;
            }
            let asset = entry
                .get("asset")
                .and_then(Value::as_str)
                .ok_or(ElementsdError::Json("wallet UTXO has no asset"))?;
            if asset != self.expected_pegged_asset.to_string() {
                return Err(ElementsdError::Json(
                    "wallet UTXO asset differs from the pegged asset",
                ));
            }
            let transaction_id = entry
                .get("txid")
                .and_then(Value::as_str)
                .ok_or(ElementsdError::Json("wallet UTXO has no transaction ID"))?;
            validate_lower_hex(transaction_id, 64, "wallet UTXO transaction ID")?;
            let output_index = entry
                .get("vout")
                .and_then(Value::as_u64)
                .ok_or(ElementsdError::Json("wallet UTXO has no output index"))
                .and_then(|value| {
                    u32::try_from(value)
                        .map_err(|_| ElementsdError::Json("wallet UTXO output index exceeds u32"))
                })?;
            let amount_sat = btc_value_to_sat(
                entry
                    .get("amount")
                    .ok_or(ElementsdError::Json("wallet UTXO has no amount"))?,
            )?;
            if amount_sat == 0 {
                return Err(ElementsdError::Json("wallet UTXO amount is zero"));
            }
            let script_pubkey = entry
                .get("scriptPubKey")
                .and_then(Value::as_str)
                .ok_or(ElementsdError::Json("wallet UTXO has no scriptPubKey"))?;
            validate_lower_hex_bounded(script_pubkey, 2, 20_000, "wallet UTXO scriptPubKey")?;
            let confirmations = entry
                .get("confirmations")
                .and_then(Value::as_u64)
                .ok_or(ElementsdError::Json("wallet UTXO has no confirmations"))
                .and_then(|value| {
                    u32::try_from(value)
                        .map_err(|_| ElementsdError::Json("wallet UTXO confirmations exceed u32"))
                })?;
            if confirmations < minimum_confirmations {
                return Err(ElementsdError::Json(
                    "wallet UTXO has fewer confirmations than requested",
                ));
            }
            total_sat = total_sat
                .checked_add(amount_sat)
                .ok_or(ElementsdError::Json("wallet capacity overflows u64"))?;
            utxos.push(ElementsdWalletUtxo {
                transaction_id: transaction_id.to_owned(),
                output_index,
                amount_sat,
                script_pubkey: script_pubkey.to_owned(),
                confirmations,
            });
        }
        Ok(ElementsdWalletCapacity { total_sat, utxos })
    }

    pub async fn create_signed_funding(
        &self,
        request_prefix: &str,
        selected_inputs: &[ElementsdWalletUtxo],
        script_pubkey: &[u8],
        amount_sat: u64,
        fee_rate_sat_per_vbyte: u64,
        maximum_fee_sat: u64,
    ) -> Result<ElementsdSignedFunding, ElementsdError> {
        validate_request_prefix(request_prefix)?;
        if selected_inputs.len() != 1
            || script_pubkey.is_empty()
            || script_pubkey.len() > 10_000
            || amount_sat == 0
            || fee_rate_sat_per_vbyte == 0
            || fee_rate_sat_per_vbyte > 10_000
            || maximum_fee_sat == 0
        {
            return Err(ElementsdError::InvalidConfiguration(
                "funding construction bounds are invalid",
            ));
        }
        let descriptor = format!("raw({})", encode_hex(script_pubkey)?);
        let descriptor_result = self
            .rpc
            .call(
                &request_id(request_prefix, "descriptor")?,
                "getdescriptorinfo",
                json!([descriptor]),
            )
            .await?;
        let descriptor = descriptor_result
            .as_object()
            .and_then(|value| value.get("descriptor"))
            .and_then(Value::as_str)
            .ok_or(ElementsdError::Json("descriptor result has no descriptor"))?;
        if descriptor.len() > 20_128 {
            return Err(ElementsdError::Json("descriptor exceeds its bound"));
        }
        let address_result = self
            .rpc
            .call(
                &request_id(request_prefix, "address")?,
                "deriveaddresses",
                json!([descriptor]),
            )
            .await?;
        let addresses = address_result
            .as_array()
            .filter(|addresses| addresses.len() == 1)
            .ok_or(ElementsdError::Json(
                "descriptor did not derive exactly one address",
            ))?;
        let address = addresses
            .first()
            .and_then(Value::as_str)
            .filter(|address| !address.is_empty() && address.len() <= 128)
            .ok_or(ElementsdError::Json("derived address is invalid"))?;
        let inputs = selected_inputs
            .iter()
            .map(|input| {
                json!({
                    "txid":input.transaction_id,
                    "vout":input.output_index,
                    "sequence":0xffff_fffe_u32,
                })
            })
            .collect::<Vec<_>>();
        let mut output = serde_json::Map::new();
        output.insert(address.to_owned(), Value::String(sat_to_btc(amount_sat)));
        let funded = self
            .rpc
            .call_path(
                &request_id(request_prefix, "fund")?,
                &self.wallet.rpc_path(),
                "walletcreatefundedpsbt",
                json!([
                    inputs,
                    [Value::Object(output)],
                    0,
                    {
                        "add_inputs":false,
                        "include_unsafe":false,
                        "lockUnspents":true,
                        "replaceable":false,
                        "fee_rate":fee_rate_sat_per_vbyte.to_string(),
                    },
                    true,
                    2
                ]),
            )
            .await?;
        let funded = funded
            .as_object()
            .ok_or(ElementsdError::Json("funded PSBT result is not an object"))?;
        let psbt = funded
            .get("psbt")
            .and_then(Value::as_str)
            .filter(|psbt| !psbt.is_empty() && psbt.len() <= 8_000_000)
            .ok_or(ElementsdError::Json("funded PSBT is invalid"))?;
        let fee_sat = btc_value_to_sat(
            funded
                .get("fee")
                .ok_or(ElementsdError::Json("funded PSBT has no fee"))?,
        )?;
        if fee_sat == 0 || fee_sat > maximum_fee_sat {
            return Err(ElementsdError::Json(
                "funded PSBT exceeds the signed fee budget",
            ));
        }
        let processed = self
            .rpc
            .call_path(
                &request_id(request_prefix, "sign")?,
                &self.wallet.rpc_path(),
                "walletprocesspsbt",
                json!([psbt, true, "DEFAULT", true]),
            )
            .await?;
        let processed = processed
            .as_object()
            .ok_or(ElementsdError::Json("processed PSBT is not an object"))?;
        if processed.get("complete").and_then(Value::as_bool) != Some(true) {
            return Err(ElementsdError::Json("processed PSBT is incomplete"));
        }
        let psbt = processed
            .get("psbt")
            .and_then(Value::as_str)
            .ok_or(ElementsdError::Json("processed PSBT has no PSBT"))?;
        let finalized = self
            .rpc
            .call(
                &request_id(request_prefix, "finalize")?,
                "finalizepsbt",
                json!([psbt, true]),
            )
            .await?;
        let finalized = finalized
            .as_object()
            .ok_or(ElementsdError::Json("finalized PSBT is not an object"))?;
        if finalized.get("complete").and_then(Value::as_bool) != Some(true) {
            return Err(ElementsdError::Json("finalized PSBT is incomplete"));
        }
        let raw_transaction = decode_hex_result(
            finalized
                .get("hex")
                .ok_or(ElementsdError::Json("finalized PSBT has no transaction"))?,
            "finalized funding transaction",
        )?;
        let transaction = parse_liquid_transaction(&raw_transaction)?;
        let mut expected_inputs = selected_inputs
            .iter()
            .map(|input| (input.transaction_id.clone(), input.output_index))
            .collect::<Vec<_>>();
        expected_inputs.sort_unstable();
        if expected_inputs
            .windows(2)
            .any(|inputs| inputs.first() == inputs.get(1))
        {
            return Err(ElementsdError::InvalidConfiguration(
                "selected funding inputs contain a duplicate",
            ));
        }
        let mut actual_inputs = transaction
            .inputs
            .iter()
            .map(|input| {
                if input.has_issuance || input.is_pegin {
                    return Err(ElementsdError::Json(
                        "funding transaction contains a forbidden input shape",
                    ));
                }
                Ok((encode_hex(&input.previous_txid)?, input.previous_output))
            })
            .collect::<Result<Vec<_>, ElementsdError>>()?;
        actual_inputs.sort_unstable();
        if actual_inputs != expected_inputs {
            return Err(ElementsdError::Json(
                "funding transaction inputs differ from the durable reservation",
            ));
        }
        let fee_outputs = transaction
            .outputs
            .iter()
            .filter(|output| output.script_pubkey.is_empty())
            .collect::<Vec<_>>();
        let [fee_output] = fee_outputs.as_slice() else {
            return Err(ElementsdError::Json(
                "funding transaction has no unique fee output",
            ));
        };
        if fee_output.asset
            != immortal_core::liquid::ConfidentialAsset::Explicit(self.expected_pegged_asset)
            || fee_output.value != immortal_core::liquid::ConfidentialValue::Explicit(fee_sat)
        {
            return Err(ElementsdError::Json(
                "funding transaction fee differs from the wallet result",
            ));
        }
        let output_index = transaction
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(index, output)| {
                let exact = output.asset
                    == immortal_core::liquid::ConfidentialAsset::Explicit(
                        self.expected_pegged_asset,
                    )
                    && output.value
                        == immortal_core::liquid::ConfidentialValue::Explicit(amount_sat)
                    && output.script_pubkey == script_pubkey;
                exact.then_some(index)
            })
            .collect::<Vec<_>>();
        let [output_index] = output_index.as_slice() else {
            return Err(ElementsdError::Json(
                "funding transaction has no unique exact swap output",
            ));
        };
        Ok(ElementsdSignedFunding {
            transaction_id: encode_hex(&transaction.transaction_id)?,
            raw_transaction,
            output_index: u32::try_from(*output_index)
                .map_err(|_| ElementsdError::Json("funding output index exceeds u32"))?,
            amount_sat,
            fee_sat,
            script_pubkey: script_pubkey.to_vec(),
        })
    }

    pub async fn unblind_own_transaction(
        &self,
        request_id: &RpcRequestId,
        raw_transaction: &[u8],
    ) -> Result<LiquidTransaction, ElementsdError> {
        Ok(parse_liquid_transaction(
            &self
                .unblind_own_transaction_raw(request_id, raw_transaction)
                .await?,
        )?)
    }

    pub async fn unblind_own_transaction_raw(
        &self,
        request_id: &RpcRequestId,
        raw_transaction: &[u8],
    ) -> Result<Vec<u8>, ElementsdError> {
        let raw_transaction = encode_hex(raw_transaction)?;
        let result = self
            .rpc
            .call_path(
                request_id,
                &self.wallet.rpc_path(),
                "unblindrawtransaction",
                json!([raw_transaction]),
            )
            .await?;
        let object = result
            .as_object()
            .ok_or(ElementsdError::Json("unblind result is not an object"))?;
        if object
            .get("complete")
            .is_some_and(|complete| complete != true)
        {
            return Err(ElementsdError::Json("unblind result is incomplete"));
        }
        let raw = object
            .get("hex")
            .ok_or(ElementsdError::Json("unblind result has no hex"))?;
        decode_hex_result(raw, "unblinded transaction")
    }

    pub async fn observe_output(
        &self,
        request_prefix: &str,
        transaction_id: &str,
        output_index: u32,
    ) -> Result<ElementsdOutputObservation, ElementsdError> {
        validate_request_prefix(request_prefix)?;
        validate_lower_hex(transaction_id, 64, "transaction ID")?;
        let transaction = self
            .observe_transaction(&request_id(request_prefix, "transaction")?, transaction_id)
            .await?;
        let unspent = !self
            .rpc
            .call(
                &request_id(request_prefix, "unspent")?,
                "gettxout",
                json!([transaction_id, output_index, true]),
            )
            .await?
            .is_null();
        Ok(ElementsdOutputObservation {
            raw_transaction: transaction.raw_transaction,
            confirmations: transaction.confirmations,
            block_hash: transaction.block_hash,
            unspent,
        })
    }

    pub async fn observe_transaction(
        &self,
        request_id: &RpcRequestId,
        transaction_id: &str,
    ) -> Result<ElementsdTransactionObservation, ElementsdError> {
        validate_lower_hex(transaction_id, 64, "transaction ID")?;
        let transaction = self
            .rpc
            .call(
                request_id,
                "getrawtransaction",
                json!([transaction_id, true]),
            )
            .await?;
        let transaction = transaction
            .as_object()
            .ok_or(ElementsdError::Json("transaction result is not an object"))?;
        let raw_transaction = decode_hex_result(
            transaction
                .get("hex")
                .ok_or(ElementsdError::Json("transaction result has no hex"))?,
            "transaction hex",
        )?;
        let block_hash = match transaction.get("blockhash") {
            None | Some(Value::Null) => None,
            Some(Value::String(block_hash)) => {
                validate_lower_hex(block_hash, 64, "block hash")?;
                Some(block_hash.clone())
            }
            Some(_) => return Err(ElementsdError::Json("block hash is not a string")),
        };
        let confirmations = match transaction.get("confirmations") {
            Some(value) => value
                .as_u64()
                .ok_or(ElementsdError::Json(
                    "transaction confirmation count is not an unsigned integer",
                ))
                .and_then(|confirmations| {
                    u32::try_from(confirmations)
                        .map_err(|_| ElementsdError::Json("confirmation count exceeds u32"))
                })?,
            None if block_hash.is_none() => 0,
            None => {
                return Err(ElementsdError::Json(
                    "confirmed transaction result has no confirmation count",
                ));
            }
        };
        match (confirmations, block_hash.as_ref()) {
            (0, None) | (1.., Some(_)) => {}
            _ => {
                return Err(ElementsdError::Json(
                    "transaction confirmations and block hash are inconsistent",
                ));
            }
        }
        Ok(ElementsdTransactionObservation {
            raw_transaction,
            confirmations,
            block_hash,
        })
    }

    pub async fn spending_transaction(
        &self,
        request_prefix: &str,
        funding_transaction_id: &str,
        funding_output_index: u32,
    ) -> Result<ElementsdSpendingObservation, ElementsdError> {
        validate_request_prefix(request_prefix)?;
        validate_lower_hex(funding_transaction_id, 64, "funding transaction ID")?;
        if funding_output_index >= 1 << 30 {
            return Err(ElementsdError::InvalidConfiguration(
                "funding output index exceeds the Elements outpoint range",
            ));
        }
        let mempool = self
            .rpc
            .call(
                &request_id(request_prefix, "mempool")?,
                "getrawmempool",
                json!([false]),
            )
            .await?;
        let mempool = mempool
            .as_array()
            .filter(|transactions| transactions.len() <= MAX_SPENDER_MEMPOOL_TRANSACTIONS)
            .ok_or(ElementsdError::Json(
                "mempool spender scan exceeds its bound",
            ))?;
        let mut spending_transaction_id = None;
        for (index, transaction_id) in mempool.iter().enumerate() {
            let transaction_id = transaction_id.as_str().ok_or(ElementsdError::Json(
                "mempool transaction ID is not a string",
            ))?;
            validate_lower_hex(transaction_id, 64, "mempool transaction ID")?;
            let transaction = self
                .rpc
                .call(
                    &request_id(request_prefix, &format!("mempool-{index}"))?,
                    "getrawtransaction",
                    json!([transaction_id, true]),
                )
                .await?;
            record_spender(
                &mut spending_transaction_id,
                decoded_spender(&transaction, funding_transaction_id, funding_output_index)?,
            )?;
        }
        if spending_transaction_id.is_some() {
            return spending_observation(
                funding_transaction_id,
                funding_output_index,
                spending_transaction_id,
            );
        }

        let tip = self
            .rpc
            .call(
                &request_id(request_prefix, "block-count")?,
                "getblockcount",
                json!([]),
            )
            .await?
            .as_u64()
            .ok_or(ElementsdError::Json(
                "block count is not an unsigned integer",
            ))?;
        let first_height = tip.saturating_sub(u64::from(MAX_SPENDER_RECENT_BLOCKS - 1));
        for height in (first_height..=tip).rev() {
            let block_hash = self
                .rpc
                .call(
                    &request_id(request_prefix, &format!("block-hash-{height}"))?,
                    "getblockhash",
                    json!([height]),
                )
                .await?
                .as_str()
                .ok_or(ElementsdError::Json("block hash is not a string"))?
                .to_owned();
            validate_lower_hex(&block_hash, 64, "block hash")?;
            let block = self
                .rpc
                .call(
                    &request_id(request_prefix, &format!("block-{height}"))?,
                    "getblock",
                    json!([block_hash, 2]),
                )
                .await?;
            let block = block
                .as_object()
                .ok_or(ElementsdError::Json("decoded block is not an object"))?;
            if block.get("hash").and_then(Value::as_str) != Some(block_hash.as_str()) {
                return Err(ElementsdError::Json("decoded block returned another hash"));
            }
            let transactions = block
                .get("tx")
                .and_then(Value::as_array)
                .filter(|transactions| transactions.len() <= MAX_SPENDER_BLOCK_TRANSACTIONS)
                .ok_or(ElementsdError::Json(
                    "decoded block transaction scan exceeds its bound",
                ))?;
            for transaction in transactions {
                record_spender(
                    &mut spending_transaction_id,
                    decoded_spender(transaction, funding_transaction_id, funding_output_index)?,
                )?;
            }
            if spending_transaction_id.is_some() {
                return spending_observation(
                    funding_transaction_id,
                    funding_output_index,
                    spending_transaction_id,
                );
            }
        }
        let unspent = self
            .rpc
            .call(
                &request_id(request_prefix, "unspent")?,
                "gettxout",
                json!([funding_transaction_id, funding_output_index, true]),
            )
            .await?;
        if unspent.is_null() {
            return Err(ElementsdError::Json(
                "funding output was spent outside the bounded scan window",
            ));
        }
        if !unspent.is_object() {
            return Err(ElementsdError::Json(
                "funding output observation is not an object",
            ));
        }
        spending_observation(
            funding_transaction_id,
            funding_output_index,
            spending_transaction_id,
        )
    }

    pub async fn require_mempool_acceptance(
        &self,
        request_id: &RpcRequestId,
        signed_transaction: &[u8],
    ) -> Result<(), ElementsdError> {
        let raw = encode_hex(signed_transaction)?;
        let result = self
            .rpc
            .call(request_id, "testmempoolaccept", json!([[raw]]))
            .await?;
        let first = result
            .as_array()
            .and_then(|results| results.first())
            .and_then(Value::as_object)
            .ok_or(ElementsdError::Json("mempool result is not one object"))?;
        match first.get("allowed").and_then(Value::as_bool) {
            Some(true) => Ok(()),
            Some(false) => Err(ElementsdError::MempoolRejected),
            None => Err(ElementsdError::Json(
                "mempool result has no allowed boolean",
            )),
        }
    }

    pub async fn require_mempool_acceptance_or_exact_known(
        &self,
        request_id: &RpcRequestId,
        known_request_id: &RpcRequestId,
        signed_transaction: &[u8],
    ) -> Result<ElementsdMempoolAdmission, ElementsdError> {
        let raw = encode_hex(signed_transaction)?;
        let result = self
            .rpc
            .call(request_id, "testmempoolaccept", json!([[raw]]))
            .await?;
        let results = result
            .as_array()
            .ok_or(ElementsdError::Json("mempool result is not an array"))?;
        if results.len() != 1 {
            return Err(ElementsdError::Json(
                "mempool result does not contain exactly one object",
            ));
        }
        let result = results
            .first()
            .and_then(Value::as_object)
            .ok_or(ElementsdError::Json("mempool result is not one object"))?;
        match result.get("allowed").and_then(Value::as_bool) {
            Some(true) => return Ok(ElementsdMempoolAdmission::New),
            Some(false) => {}
            None => {
                return Err(ElementsdError::Json(
                    "mempool result has no allowed boolean",
                ));
            }
        }
        let reason =
            result
                .get("reject-reason")
                .and_then(Value::as_str)
                .ok_or(ElementsdError::Json(
                    "rejected mempool result has no reason",
                ))?;
        if !matches!(reason, "txn-already-in-mempool" | "txn-already-known") {
            return Err(ElementsdError::MempoolRejected);
        }
        let transaction = parse_liquid_transaction(signed_transaction)?;
        let transaction_id = encode_hex(&transaction.transaction_id)?;
        let observed = self
            .raw_transaction(known_request_id, &transaction_id)
            .await?;
        if observed != signed_transaction {
            return Err(ElementsdError::MempoolRejected);
        }
        Ok(ElementsdMempoolAdmission::ExactKnown)
    }

    pub async fn broadcast(
        &self,
        request_id: &RpcRequestId,
        signed_transaction: &[u8],
    ) -> Result<String, ElementsdError> {
        let raw = encode_hex(signed_transaction)?;
        let result = self
            .rpc
            .call(request_id, "sendrawtransaction", json!([raw]))
            .await?;
        let transaction_id = result
            .as_str()
            .ok_or(ElementsdError::Json("broadcast result is not a txid"))?;
        validate_lower_hex(transaction_id, 64, "broadcast transaction ID")?;
        Ok(transaction_id.to_owned())
    }
}

fn decoded_spender(
    transaction: &Value,
    funding_transaction_id: &str,
    funding_output_index: u32,
) -> Result<Option<String>, ElementsdError> {
    let transaction = transaction
        .as_object()
        .ok_or(ElementsdError::Json("decoded transaction is not an object"))?;
    let transaction_id =
        transaction
            .get("txid")
            .and_then(Value::as_str)
            .ok_or(ElementsdError::Json(
                "decoded transaction has no transaction ID",
            ))?;
    validate_lower_hex(transaction_id, 64, "decoded transaction ID")?;
    let inputs = transaction
        .get("vin")
        .and_then(Value::as_array)
        .filter(|inputs| inputs.len() <= MAX_SPENDER_INPUTS)
        .ok_or(ElementsdError::Json(
            "decoded transaction input scan exceeds its bound",
        ))?;
    let mut matching_inputs = 0_usize;
    for input in inputs {
        let input = input.as_object().ok_or(ElementsdError::Json(
            "decoded transaction input is not an object",
        ))?;
        match (
            input.get("txid").and_then(Value::as_str),
            input.get("vout").and_then(Value::as_u64),
        ) {
            (None, None) if input.get("coinbase").and_then(Value::as_str).is_some() => {}
            (Some(previous_transaction_id), Some(previous_output)) => {
                validate_lower_hex(previous_transaction_id, 64, "decoded input transaction ID")?;
                if previous_output >= 1 << 30 {
                    return Err(ElementsdError::Json(
                        "decoded input output index exceeds the Elements range",
                    ));
                }
                if previous_transaction_id == funding_transaction_id
                    && previous_output == u64::from(funding_output_index)
                {
                    matching_inputs = matching_inputs.saturating_add(1);
                }
            }
            _ => {
                return Err(ElementsdError::Json(
                    "decoded transaction input has an invalid outpoint",
                ));
            }
        }
    }
    match matching_inputs {
        0 => Ok(None),
        1 => Ok(Some(transaction_id.to_owned())),
        _ => Err(ElementsdError::Json(
            "decoded transaction spends the requested outpoint more than once",
        )),
    }
}

fn record_spender(
    observed: &mut Option<String>,
    candidate: Option<String>,
) -> Result<(), ElementsdError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    match observed {
        Some(existing) if existing != &candidate => Err(ElementsdError::Json(
            "multiple transactions spend the requested outpoint",
        )),
        Some(_) => Ok(()),
        None => {
            *observed = Some(candidate);
            Ok(())
        }
    }
}

fn spending_observation(
    funding_transaction_id: &str,
    funding_output_index: u32,
    spending_transaction_id: Option<String>,
) -> Result<ElementsdSpendingObservation, ElementsdError> {
    if spending_transaction_id.as_deref() == Some(funding_transaction_id) {
        return Err(ElementsdError::Json(
            "funding transaction cannot spend its own output",
        ));
    }
    Ok(ElementsdSpendingObservation {
        funding_transaction_id: funding_transaction_id.to_owned(),
        funding_output_index,
        spending_transaction_id,
    })
}

fn request_id(prefix: &str, suffix: &str) -> Result<RpcRequestId, ElementsdError> {
    Ok(RpcRequestId::new(format!("{prefix}:{suffix}"))?)
}

fn validate_request_prefix(prefix: &str) -> Result<(), ElementsdError> {
    if prefix.is_empty()
        || prefix.len() > 96
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ElementsdError::InvalidConfiguration(
            "request prefix is invalid",
        ));
    }
    Ok(())
}

fn validate_lower_hex(
    value: &str,
    length: usize,
    detail: &'static str,
) -> Result<(), ElementsdError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ElementsdError::InvalidConfiguration(detail));
    }
    Ok(())
}

fn validate_lower_hex_bounded(
    value: &str,
    minimum: usize,
    maximum: usize,
    detail: &'static str,
) -> Result<(), ElementsdError> {
    if value.len() < minimum
        || value.len() > maximum
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ElementsdError::Json(detail));
    }
    Ok(())
}

fn btc_value_to_sat(value: &Value) -> Result<u64, ElementsdError> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => return Err(ElementsdError::Json("BTC amount is not decimal")),
    };
    if value.starts_with('-') {
        return Err(ElementsdError::Json("BTC amount is not a positive decimal"));
    }
    let (mantissa, exponent) = value.split_once(['e', 'E']).map_or(
        Ok((value.as_str(), 0_i32)),
        |(mantissa, exponent)| {
            exponent
                .parse::<i32>()
                .ok()
                .filter(|exponent| (-128..=128).contains(exponent))
                .map(|exponent| (mantissa, exponent))
                .ok_or(ElementsdError::Json("BTC amount exponent is invalid"))
        },
    )?;
    let (whole, fractional) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || whole.len().saturating_add(fractional.len()) > 40
    {
        return Err(ElementsdError::Json("BTC amount is not an exact decimal"));
    }
    let digits = format!("{whole}{fractional}")
        .parse::<u128>()
        .map_err(|_| ElementsdError::Json("BTC amount exceeds u128"))?;
    let fractional_digits = i32::try_from(fractional.len())
        .map_err(|_| ElementsdError::Json("BTC amount precision exceeds i32"))?;
    let sat_shift = 8_i32
        .checked_add(exponent)
        .and_then(|shift| shift.checked_sub(fractional_digits))
        .ok_or(ElementsdError::Json("BTC amount scale overflows i32"))?;
    let sat = if sat_shift >= 0 {
        let multiplier = 10_u128
            .checked_pow(
                u32::try_from(sat_shift)
                    .map_err(|_| ElementsdError::Json("BTC amount positive scale exceeds u32"))?,
            )
            .ok_or(ElementsdError::Json("BTC amount scale exceeds u128"))?;
        digits
            .checked_mul(multiplier)
            .ok_or(ElementsdError::Json("BTC amount exceeds u128"))?
    } else {
        let divisor = 10_u128
            .checked_pow(sat_shift.unsigned_abs())
            .ok_or(ElementsdError::Json("BTC amount scale exceeds u128"))?;
        if digits % divisor != 0 {
            return Err(ElementsdError::Json("BTC amount has a fractional satoshi"));
        }
        digits / divisor
    };
    u64::try_from(sat).map_err(|_| ElementsdError::Json("BTC amount exceeds u64"))
}

fn sat_to_btc(amount_sat: u64) -> String {
    format!(
        "{}.{:08}",
        amount_sat / 100_000_000,
        amount_sat % 100_000_000
    )
}

fn encode_hex(bytes: &[u8]) -> Result<String, ElementsdError> {
    if bytes.is_empty() || bytes.len() > 4_000_000 {
        return Err(ElementsdError::InvalidConfiguration(
            "transaction byte length is invalid",
        ));
    }
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").map_err(|_| {
            ElementsdError::InvalidConfiguration("transaction could not be encoded")
        })?;
    }
    Ok(output)
}

fn decode_hex_result(value: &Value, detail: &'static str) -> Result<Vec<u8>, ElementsdError> {
    let value = value.as_str().ok_or(ElementsdError::Json(detail))?;
    if value.is_empty()
        || value.len() > 8_000_000
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ElementsdError::Json(detail));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = nibble(pair[0]).ok_or(ElementsdError::Json(detail))?;
        let low = nibble(pair[1]).ok_or(ElementsdError::Json(detail))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
