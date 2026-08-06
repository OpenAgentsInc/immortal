//! Verify-before-fund and unilateral-exit checks for MKT-SWP Liquid legs.

use core::fmt;

use immortal_core::{
    liquid::{
        ConfidentialAsset, ConfidentialValue, LiquidAssetId, LiquidError, LiquidGenesisHash,
        LiquidNetworkId, LiquidPrevout, LiquidTransaction, LiquidVerificationAuthority,
        LocalElementsdUnblind, liquid_taproot_script_spend_sighash, parse_liquid_transaction,
        verify_liquid_control_block, verify_liquid_swap_output,
        verify_liquid_taproot_script_pubkey, verify_liquid_taproot_sighash_signature,
    },
    mkt_swp_verify::{SwapLeafCondition, parse_swap_leaf_script, sha256},
};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

const LIQUID_EXIT_SCHEMA: &str = "openagents.mkt-swp.liquid-exit.v1";
const MAX_TRANSACTION_HEX_BYTES: usize = 8_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidClientError {
    pub code: &'static str,
    pub detail: String,
}

impl LiquidClientError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for LiquidClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for LiquidClientError {}

impl From<LiquidError> for LiquidClientError {
    fn from(error: LiquidError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidSwapType {
    Submarine,
    Reverse,
    Chain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidLegPurpose {
    RequesterBroadcast,
    CounterpartyLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidConfidentiality {
    Explicit,
    Confidential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiquidExitMode {
    #[serde(rename = "presigned")]
    Presigned,
    #[serde(rename = "wallet_sign")]
    Wallet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidFundingVerificationInput {
    pub raw_transaction: String,
    pub trusted_unblind_transaction: Option<String>,
    pub transaction_sha256: String,
    pub output_index: u32,
    pub asset_id: String,
    pub amount: String,
    pub script_pubkey: String,
    pub taproot_internal_key: String,
    pub taproot_merkle_root: Option<String>,
    pub confidentiality: LiquidConfidentiality,
    pub minimum_confirmations: u32,
    pub replacement_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidUnilateralExitPackage {
    pub schema: String,
    pub genesis_hash: String,
    pub network_id: String,
    pub asset_id: String,
    pub funding_transaction_id: String,
    pub funding_output_index: u32,
    pub funding_amount: String,
    pub funding_script_pubkey: String,
    pub path: String,
    pub script: String,
    pub control_block: String,
    pub timelock: u32,
    pub spend_input_index: u32,
    pub fee_output_index: u32,
    pub fee_amount: String,
    pub transaction_sha256: String,
    pub transaction: String,
    pub mode: LiquidExitMode,
    pub wallet_signing_handle_sha256: Option<String>,
    pub preimage_recovery_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidBeforeFundRequest {
    pub swap_type: LiquidSwapType,
    pub purpose: LiquidLegPurpose,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub funding: LiquidFundingVerificationInput,
    pub exit_package: LiquidUnilateralExitPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiquidFundingAuthorization {
    BroadcastLiquid {
        transaction_id: String,
        raw_transaction: String,
    },
    ContinueAfterLiquidLock {
        transaction_id: String,
        output_index: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidNodeRequest {
    pub transaction_id: String,
    pub transaction_sha256: String,
    pub output_index: u32,
    pub purpose: LiquidLegPurpose,
    pub raw_transaction: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLiquidObservation {
    pub transaction_id: String,
    pub transaction_sha256: String,
    pub confirmations: u32,
    pub mempool_accepted: bool,
    pub replacement_detected: bool,
    pub competing_spend_detected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidNodeAuthority {
    LocalElementsd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidUnblindRequest {
    pub network_id: String,
    pub pegged_asset: String,
    pub transaction_sha256: String,
    pub output_index: u32,
    pub raw_transaction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLiquidUnblind {
    pub authority: LiquidNodeAuthority,
    pub network_id: String,
    pub pegged_asset: String,
    pub transaction_sha256: String,
    pub output_index: u32,
    pub unblinded_transaction: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLiquidNodeObservation {
    pub authority: LiquidNodeAuthority,
    pub network_id: String,
    pub genesis_hash: String,
    pub pegged_asset: String,
    pub observation: LocalLiquidObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidVerificationProvenance {
    pub authority: LiquidNodeAuthority,
    pub network_id: String,
    pub genesis_hash: String,
    pub pegged_asset: String,
    pub funding_transaction_sha256: String,
    pub output_index: u32,
    pub confidentiality: LiquidConfidentiality,
    pub unblinded_transaction_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLiquidBeforeFund {
    pub transaction_id: String,
    pub output_index: u32,
    pub amount_sat: u64,
    pub authority: LiquidVerificationAuthority,
    pub exit_transaction_sha256: String,
    pub exit_signature_hash: String,
    pub exit_destination_script_pubkey: String,
    pub exit_fee_amount: String,
    pub exit_mode: LiquidExitMode,
    pub authorization: LiquidFundingAuthorization,
    pub provenance: Option<LiquidVerificationProvenance>,
}

#[derive(Debug, Clone)]
pub struct LiquidLegVerifier {
    network: LiquidNetworkId,
    pegged_asset: LiquidAssetId,
}

impl LiquidLegVerifier {
    pub fn new(network: LiquidNetworkId, pegged_asset: LiquidAssetId) -> Self {
        Self {
            network,
            pegged_asset,
        }
    }

    pub fn verify_before_fund<Observe>(
        &self,
        request: &LiquidBeforeFundRequest,
        mut observe_node: Observe,
    ) -> Result<VerifiedLiquidBeforeFund, LiquidClientError>
    where
        Observe: FnMut(&LiquidNodeRequest) -> Result<LocalLiquidObservation, String>,
    {
        self.verify_pair(request)?;
        let funding = self.verify_funding(
            &request.funding,
            request.swap_type,
            request.purpose,
            &mut observe_node,
        )?;
        let exit = self.verify_exit(&request.exit_package, &funding, request.purpose)?;
        let transaction_id = encode_hex(&funding.transaction.transaction_id);
        let authorization = match request.purpose {
            LiquidLegPurpose::RequesterBroadcast => LiquidFundingAuthorization::BroadcastLiquid {
                transaction_id: transaction_id.clone(),
                raw_transaction: request.funding.raw_transaction.clone(),
            },
            LiquidLegPurpose::CounterpartyLock => {
                LiquidFundingAuthorization::ContinueAfterLiquidLock {
                    transaction_id: transaction_id.clone(),
                    output_index: request.funding.output_index,
                }
            }
        };
        Ok(VerifiedLiquidBeforeFund {
            transaction_id,
            output_index: request.funding.output_index,
            amount_sat: funding.amount_sat,
            authority: funding.authority,
            exit_transaction_sha256: exit.transaction_sha256,
            exit_signature_hash: exit.signature_hash,
            exit_destination_script_pubkey: exit.destination_script_pubkey,
            exit_fee_amount: exit.fee_amount,
            exit_mode: request.exit_package.mode,
            authorization,
            provenance: None,
        })
    }

    pub fn verify_before_fund_with_local_adapters<Unblind, Observe>(
        &self,
        request: &LiquidBeforeFundRequest,
        mut unblind_output: Unblind,
        mut observe_node: Observe,
    ) -> Result<VerifiedLiquidBeforeFund, LiquidClientError>
    where
        Unblind: FnMut(&LiquidUnblindRequest) -> Result<LocalLiquidUnblind, String>,
        Observe: FnMut(&LiquidNodeRequest) -> Result<LocalLiquidNodeObservation, String>,
    {
        if request.funding.trusted_unblind_transaction.is_some() {
            return Err(LiquidClientError::new(
                "swp_liquid_unblind_failed",
                "production verification accepts unblind results only from the local elementsd adapter",
            ));
        }
        let network_id = self.network.as_str().to_owned();
        let pegged_asset = self.pegged_asset.to_string();
        let mut verified_request = request.clone();
        let unblinded_transaction_sha256 = match request.funding.confidentiality {
            LiquidConfidentiality::Explicit => None,
            LiquidConfidentiality::Confidential => {
                let adapter_request = LiquidUnblindRequest {
                    network_id: network_id.clone(),
                    pegged_asset: pegged_asset.clone(),
                    transaction_sha256: request.funding.transaction_sha256.clone(),
                    output_index: request.funding.output_index,
                    raw_transaction: request.funding.raw_transaction.clone(),
                };
                let result = unblind_output(&adapter_request).map_err(|error| {
                    LiquidClientError::new(
                        "swp_liquid_unblind_failed",
                        format!("local elementsd unblind adapter failed: {error}"),
                    )
                })?;
                if result.authority != LiquidNodeAuthority::LocalElementsd
                    || result.network_id != network_id
                    || result.pegged_asset != pegged_asset
                    || result.transaction_sha256 != adapter_request.transaction_sha256
                    || result.output_index != adapter_request.output_index
                {
                    return Err(LiquidClientError::new(
                        "swp_liquid_unblind_mismatch",
                        "local unblind provenance differs from the configured Liquid output",
                    ));
                }
                let unblinded =
                    decode_hex(&result.unblinded_transaction, "local unblind transaction")?;
                verified_request.funding.trusted_unblind_transaction =
                    Some(result.unblinded_transaction);
                Some(encode_hex(&sha256(&unblinded)))
            }
        };
        let mut local_genesis_hash = None;
        let mut verified = self.verify_before_fund(&verified_request, |node_request| {
            let result = observe_node(node_request)?;
            if result.authority != LiquidNodeAuthority::LocalElementsd
                || result.network_id != network_id
                || result.pegged_asset != pegged_asset
                || result.genesis_hash != request.exit_package.genesis_hash
            {
                return Err(
                    "local elementsd observation provenance differs from the configured network"
                        .to_owned(),
                );
            }
            LiquidGenesisHash::parse_display(&result.genesis_hash)
                .map_err(|_| "local elementsd returned an invalid genesis hash".to_owned())?;
            local_genesis_hash = Some(result.genesis_hash);
            Ok(result.observation)
        })?;
        let genesis_hash = local_genesis_hash.ok_or_else(|| {
            LiquidClientError::new(
                "swp_liquid_network_mismatch",
                "local elementsd observation omitted the exact genesis hash",
            )
        })?;
        verified.provenance = Some(LiquidVerificationProvenance {
            authority: LiquidNodeAuthority::LocalElementsd,
            network_id,
            genesis_hash,
            pegged_asset,
            funding_transaction_sha256: request.funding.transaction_sha256.clone(),
            output_index: request.funding.output_index,
            confidentiality: request.funding.confidentiality,
            unblinded_transaction_sha256,
        });
        Ok(verified)
    }

    fn verify_pair(&self, request: &LiquidBeforeFundRequest) -> Result<(), LiquidClientError> {
        let input = parse_asset_kind(&request.input_asset_id)?;
        let output = parse_asset_kind(&request.output_asset_id)?;
        let expected = match request.swap_type {
            LiquidSwapType::Submarine => (AssetKind::Liquid, AssetKind::Lightning),
            LiquidSwapType::Reverse => (AssetKind::Lightning, AssetKind::Liquid),
            LiquidSwapType::Chain => {
                if !matches!(
                    (input, output),
                    (AssetKind::BitcoinChain, AssetKind::Liquid)
                        | (AssetKind::Liquid, AssetKind::BitcoinChain)
                ) {
                    return Err(LiquidClientError::new(
                        "swp_invalid_pair",
                        "Liquid chain swaps require an ordered BTC/L-BTC pair",
                    ));
                }
                (input, output)
            }
        };
        if (input, output) != expected {
            return Err(LiquidClientError::new(
                "swp_invalid_pair",
                "ordered asset pair does not match the Liquid swap type",
            ));
        }
        let liquid_is_input = input == AssetKind::Liquid;
        let expected_purpose = if liquid_is_input {
            LiquidLegPurpose::RequesterBroadcast
        } else {
            LiquidLegPurpose::CounterpartyLock
        };
        if request.purpose != expected_purpose || request.funding.asset_id != self.liquid_asset_id()
        {
            return Err(LiquidClientError::new(
                "swp_contract_terms_mismatch",
                "Liquid leg purpose or asset differs from the ordered pair",
            ));
        }
        Ok(())
    }

    fn verify_funding<Observe>(
        &self,
        input: &LiquidFundingVerificationInput,
        swap_type: LiquidSwapType,
        purpose: LiquidLegPurpose,
        observe_node: &mut Observe,
    ) -> Result<VerifiedFunding, LiquidClientError>
    where
        Observe: FnMut(&LiquidNodeRequest) -> Result<LocalLiquidObservation, String>,
    {
        if input.transaction_sha256.len() != 64 {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "funding transaction digest is invalid",
            ));
        }
        let raw = decode_hex(&input.raw_transaction, "funding transaction")?;
        if encode_hex(&sha256(&raw)) != input.transaction_sha256 {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "funding transaction digest differs",
            ));
        }
        let transaction = parse_liquid_transaction(&raw)?;
        let unblinded = input
            .trusted_unblind_transaction
            .as_deref()
            .map(|raw| decode_hex(raw, "trusted unblind transaction"))
            .transpose()?
            .map(|raw| parse_liquid_transaction(&raw))
            .transpose()?;
        let expected_asset = self.parse_liquid_asset(&input.asset_id)?;
        let amount = parse_decimal(&input.amount, "Liquid funding amount")?;
        let script_pubkey = decode_hex(&input.script_pubkey, "Liquid funding scriptPubKey")?;
        let output = transaction
            .outputs
            .get(usize::try_from(input.output_index).map_err(|_| {
                LiquidClientError::new("swp_liquid_output_invalid", "output index exceeds usize")
            })?)
            .ok_or_else(|| {
                LiquidClientError::new("swp_liquid_output_invalid", "funding output is absent")
            })?;
        match input.confidentiality {
            LiquidConfidentiality::Explicit
                if !matches!(output.asset, ConfidentialAsset::Explicit(_))
                    || !matches!(output.value, ConfidentialValue::Explicit(_)) =>
            {
                return Err(LiquidClientError::new(
                    "swp_liquid_output_invalid",
                    "explicit Liquid terms received a confidential output",
                ));
            }
            LiquidConfidentiality::Confidential
                if matches!(output.asset, ConfidentialAsset::Explicit(_))
                    || matches!(output.value, ConfidentialValue::Explicit(_)) =>
            {
                return Err(LiquidClientError::new(
                    "swp_liquid_output_invalid",
                    "confidential Liquid terms were downgraded to an explicit output",
                ));
            }
            _ => {}
        }
        let verified = verify_liquid_swap_output(
            &transaction,
            unblinded.as_ref().map(LocalElementsdUnblind::trusted),
            usize::try_from(input.output_index).map_err(|_| {
                LiquidClientError::new("swp_liquid_output_invalid", "output index exceeds usize")
            })?,
            expected_asset,
            amount,
            &script_pubkey,
        )?;
        let internal_key = XOnlyPublicKey::from_byte_array(decode_hex_32(
            &input.taproot_internal_key,
            "Liquid Taproot internal key",
        )?)
        .map_err(|_| {
            LiquidClientError::new("swp_script_invalid", "Liquid Taproot key is invalid")
        })?;
        let merkle_root = input
            .taproot_merkle_root
            .as_deref()
            .map(|root| decode_hex_32(root, "Liquid Taproot merkle root"))
            .transpose()?;
        verify_liquid_taproot_script_pubkey(&script_pubkey, internal_key, merkle_root)?;
        if input.minimum_confirmations == 0 || input.replacement_policy != "reject" {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "Liquid finality or replacement policy is unsafe",
            ));
        }
        let request = LiquidNodeRequest {
            transaction_id: encode_hex(&transaction.transaction_id),
            transaction_sha256: input.transaction_sha256.clone(),
            output_index: input.output_index,
            purpose,
            raw_transaction: raw,
        };
        let observation = observe_node(&request).map_err(|error| {
            let code = if matches!(
                (swap_type, purpose),
                (LiquidSwapType::Chain, LiquidLegPurpose::CounterpartyLock)
            ) {
                "swp_funding_not_authorized"
            } else {
                "swp_liquid_output_invalid"
            };
            LiquidClientError::new(code, format!("local elementsd adapter failed: {error}"))
        })?;
        if observation.transaction_id != request.transaction_id
            || observation.transaction_sha256 != request.transaction_sha256
            || observation.replacement_detected
            || observation.competing_spend_detected
        {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "local elementsd view differs or reports a competing transaction",
            ));
        }
        match (swap_type, purpose) {
            (_, LiquidLegPurpose::RequesterBroadcast) if !observation.mempool_accepted => {
                return Err(LiquidClientError::new(
                    "swp_liquid_output_invalid",
                    "local elementsd did not accept the funding transaction",
                ));
            }
            (LiquidSwapType::Chain, LiquidLegPurpose::CounterpartyLock)
                if observation.confirmations != 0 =>
            {
                return Err(LiquidClientError::new(
                    "swp_liquid_output_invalid",
                    "Liquid destination preflight transaction was already broadcast",
                ));
            }
            (LiquidSwapType::Chain, LiquidLegPurpose::CounterpartyLock)
                if !observation.mempool_accepted =>
            {
                return Err(LiquidClientError::new(
                    "swp_funding_not_authorized",
                    "local elementsd rejected the unbroadcast Liquid destination template",
                ));
            }
            (LiquidSwapType::Reverse, LiquidLegPurpose::CounterpartyLock)
                if observation.confirmations < input.minimum_confirmations =>
            {
                return Err(LiquidClientError::new(
                    "swp_confirmation_insufficient",
                    "Liquid lock has fewer confirmations than the signed policy",
                ));
            }
            _ => {}
        }
        let prevout = LiquidPrevout {
            asset: output.asset.clone(),
            value: output.value.clone(),
            script_pubkey,
        };
        Ok(VerifiedFunding {
            transaction,
            output_index: input.output_index,
            amount_sat: verified.amount_sat,
            authority: verified.authority,
            prevout,
        })
    }

    fn verify_exit(
        &self,
        package: &LiquidUnilateralExitPackage,
        funding: &VerifiedFunding,
        purpose: LiquidLegPurpose,
    ) -> Result<VerifiedExit, LiquidClientError> {
        let expected_path = match purpose {
            LiquidLegPurpose::RequesterBroadcast => "refund",
            LiquidLegPurpose::CounterpartyLock => "claim",
        };
        let genesis_hash =
            LiquidGenesisHash::parse_display(&package.genesis_hash).map_err(|_| {
                LiquidClientError::new(
                    "swp_exit_package_mismatch",
                    "Liquid exit genesis hash is invalid",
                )
            })?;
        let genesis_network =
            LiquidNetworkId::from_genesis_hash(&package.genesis_hash).map_err(|_| {
                LiquidClientError::new(
                    "swp_exit_package_mismatch",
                    "Liquid exit genesis hash is invalid",
                )
            })?;
        if package.schema != LIQUID_EXIT_SCHEMA
            || genesis_network != self.network
            || package.network_id != self.network.as_str()
            || package.asset_id != self.liquid_asset_id()
            || package.funding_transaction_id != encode_hex(&funding.transaction.transaction_id)
            || package.funding_amount != funding.amount_sat.to_string()
            || package.funding_script_pubkey != encode_hex(&funding.prevout.script_pubkey)
            || package.path != expected_path
        {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit does not bind the verified funding output",
            ));
        }
        let transaction_raw = decode_hex(&package.transaction, "Liquid exit transaction")?;
        if encode_hex(&sha256(&transaction_raw)) != package.transaction_sha256 {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit transaction digest differs",
            ));
        }
        let transaction = parse_liquid_transaction(&transaction_raw)?;
        let input = transaction
            .inputs
            .get(usize::try_from(package.spend_input_index).map_err(|_| {
                LiquidClientError::new("swp_exit_package_unusable", "input index exceeds usize")
            })?)
            .ok_or_else(|| {
                LiquidClientError::new("swp_exit_package_unusable", "exit input is absent")
            })?;
        if input.previous_txid != funding.transaction.transaction_id
            || input.previous_output != package.funding_output_index
            || package.funding_output_index != funding.output_index
        {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit spends another outpoint or violates its timelock",
            ));
        }
        let output_key = funding
            .prevout
            .script_pubkey
            .get(2..34)
            .ok_or_else(|| {
                LiquidClientError::new(
                    "swp_exit_package_mismatch",
                    "funding output is not a v1 Taproot program",
                )
            })?
            .try_into()
            .map_err(|_| {
                LiquidClientError::new(
                    "swp_exit_package_mismatch",
                    "funding Taproot program has the wrong length",
                )
            })?;
        let output_key = XOnlyPublicKey::from_byte_array(output_key).map_err(|_| {
            LiquidClientError::new(
                "swp_exit_package_mismatch",
                "funding Taproot program is invalid",
            )
        })?;
        let exit_script = decode_hex(&package.script, "Liquid exit script")?;
        let exit_control_block = decode_hex(&package.control_block, "Liquid exit control block")?;
        verify_liquid_control_block(&output_key, &exit_script, &exit_control_block).map_err(
            |error| {
                LiquidClientError::new(
                    "swp_exit_package_mismatch",
                    format!("Liquid exit script path is invalid: {error}"),
                )
            },
        )?;
        let leaf = parse_swap_leaf_script(&exit_script).map_err(|error| {
            LiquidClientError::new(
                "swp_exit_package_mismatch",
                format!("Liquid exit leaf is invalid: {error}"),
            )
        })?;
        let timelock_matches = match (package.path.as_str(), leaf.condition) {
            ("claim", SwapLeafCondition::Hashlock(_)) => package.timelock == 0,
            ("refund", SwapLeafCondition::Cltv(height)) => {
                package.timelock == height
                    && transaction.lock_time >= height
                    && input.sequence != u32::MAX
            }
            ("refund", SwapLeafCondition::Csv(blocks)) => {
                const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
                const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
                package.timelock == blocks
                    && input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
                    && input.sequence & SEQUENCE_LOCKTIME_MASK >= blocks
            }
            _ => false,
        };
        if !timelock_matches {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit path and timelock do not match its script leaf",
            ));
        }
        if transaction.outputs.len() != 2 || package.fee_output_index > 1 {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit must contain one recovery output and one fee output",
            ));
        }
        let fee = transaction
            .outputs
            .get(usize::try_from(package.fee_output_index).map_err(|_| {
                LiquidClientError::new("swp_exit_package_unusable", "fee index exceeds usize")
            })?)
            .ok_or_else(|| {
                LiquidClientError::new("swp_exit_package_unusable", "fee output is absent")
            })?;
        let fee_amount = parse_decimal(&package.fee_amount, "Liquid exit fee")?;
        if fee.asset != ConfidentialAsset::Explicit(self.pegged_asset)
            || fee.value != ConfidentialValue::Explicit(fee_amount)
            || !fee.script_pubkey.is_empty()
        {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit fee output is not the exact explicit pegged-asset fee",
            ));
        }
        let recovery_output_index = if package.fee_output_index == 0 { 1 } else { 0 };
        let recovery_output = transaction
            .outputs
            .get(recovery_output_index)
            .ok_or_else(|| {
                LiquidClientError::new(
                    "swp_exit_package_unusable",
                    "Liquid exit recovery output is absent",
                )
            })?;
        let recovery_amount = funding.amount_sat.checked_sub(fee_amount).ok_or_else(|| {
            LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit fee exceeds the funded amount",
            )
        })?;
        if recovery_output.asset != ConfidentialAsset::Explicit(self.pegged_asset)
            || recovery_output.value != ConfidentialValue::Explicit(recovery_amount)
            || recovery_output.script_pubkey.is_empty()
        {
            return Err(LiquidClientError::new(
                "swp_exit_package_mismatch",
                "Liquid exit recovery output does not preserve the exact asset and principal",
            ));
        }
        let sighash = liquid_taproot_script_spend_sighash(
            &transaction,
            std::slice::from_ref(&funding.prevout),
            usize::try_from(package.spend_input_index).map_err(|_| {
                LiquidClientError::new(
                    "swp_exit_package_unusable",
                    "Liquid exit input index exceeds usize",
                )
            })?,
            genesis_hash,
            &exit_script,
            &exit_control_block,
            None,
        )?;
        match package.mode {
            LiquidExitMode::Presigned => {
                if package.path == "claim" {
                    return Err(LiquidClientError::new(
                        "swp_exit_package_unusable",
                        "Liquid hashlock claims require wallet_sign so the package contains no preimage",
                    ));
                }
                if package.wallet_signing_handle_sha256.is_some()
                    || package.preimage_recovery_ref.is_some()
                    || transaction.inputs.len() != 1
                    || package.spend_input_index != 0
                    || !input.pegin_witness.is_empty()
                {
                    return Err(LiquidClientError::new(
                        "swp_exit_package_unusable",
                        "pre-signed Liquid exit is not an exact single-input package",
                    ));
                }
                let (signature, witness_script, witness_control_block) =
                    match (package.path.as_str(), input.script_witness.as_slice()) {
                        ("refund", [signature, script, control_block]) if signature.len() == 64 => {
                            (signature, script, control_block)
                        }
                        _ => {
                            return Err(LiquidClientError::new(
                                "swp_exit_package_unusable",
                                "pre-signed Liquid exit has an invalid script witness shape",
                            ));
                        }
                    };
                if witness_script != &exit_script || witness_control_block != &exit_control_block {
                    return Err(LiquidClientError::new(
                        "swp_exit_package_mismatch",
                        "pre-signed Liquid exit witness reveals another script path",
                    ));
                }
                let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                    LiquidClientError::new(
                        "swp_exit_package_unusable",
                        "pre-signed Liquid exit signature has the wrong length",
                    )
                })?;
                verify_liquid_taproot_sighash_signature(sighash, &signature, leaf.signing_key)?;
            }
            LiquidExitMode::Wallet => {
                let handle = package
                    .wallet_signing_handle_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        LiquidClientError::new(
                            "swp_exit_package_unusable",
                            "wallet Liquid exit lacks a digest-bound signer handle",
                        )
                    })?;
                require_lower_hex_32(handle, "Liquid signer handle")?;
                match (
                    package.path.as_str(),
                    package.preimage_recovery_ref.as_deref(),
                ) {
                    ("claim", Some(preimage_handle)) => {
                        require_lower_hex_32(preimage_handle, "Liquid preimage recovery handle")?;
                        if preimage_handle == handle {
                            return Err(LiquidClientError::new(
                                "swp_exit_package_unusable",
                                "Liquid claim signer and preimage recovery handles must be distinct",
                            ));
                        }
                    }
                    ("claim", None) => {
                        return Err(LiquidClientError::new(
                            "swp_exit_package_unusable",
                            "Liquid claim lacks a digest-bound preimage recovery handle",
                        ));
                    }
                    ("refund", None) => {}
                    ("refund", Some(_)) => {
                        return Err(LiquidClientError::new(
                            "swp_exit_package_unusable",
                            "Liquid refund unexpectedly carries a preimage recovery handle",
                        ));
                    }
                    _ => {
                        return Err(LiquidClientError::new(
                            "swp_exit_package_unusable",
                            "Liquid wallet exit path is unsupported",
                        ));
                    }
                }
                if transaction.inputs.len() != 1
                    || package.spend_input_index != 0
                    || !input.script_witness.is_empty()
                    || !input.pegin_witness.is_empty()
                {
                    return Err(LiquidClientError::new(
                        "swp_exit_package_unusable",
                        "wallet_sign Liquid exit must be an exact secret-free single-input template",
                    ));
                }
            }
        }
        Ok(VerifiedExit {
            transaction_sha256: package.transaction_sha256.clone(),
            signature_hash: encode_hex(&sighash),
            destination_script_pubkey: encode_hex(&recovery_output.script_pubkey),
            fee_amount: fee_amount.to_string(),
        })
    }

    fn parse_liquid_asset(&self, value: &str) -> Result<LiquidAssetId, LiquidClientError> {
        let (network, asset) = LiquidAssetId::parse_mkt(value)?;
        if network != self.network || asset != self.pegged_asset {
            return Err(LiquidClientError::new(
                "swp_liquid_network_mismatch",
                "Liquid asset is not the configured network's pegged asset",
            ));
        }
        Ok(asset)
    }

    fn liquid_asset_id(&self) -> String {
        self.pegged_asset.mkt_asset_id(&self.network)
    }
}

pub fn verify_wallet_signed_exit(
    request: &LiquidBeforeFundRequest,
    signed_transaction: &[u8],
) -> Result<(), LiquidClientError> {
    if request.exit_package.mode != LiquidExitMode::Wallet {
        return Err(LiquidClientError::new(
            "swp_exit_package_unusable",
            "Liquid wallet signing requires a wallet_sign exit package",
        ));
    }
    let unsigned = parse_liquid_transaction(&decode_hex(
        &request.exit_package.transaction,
        "unsigned Liquid exit transaction",
    )?)?;
    let signed = parse_liquid_transaction(signed_transaction)?;
    if unsigned.version != signed.version
        || unsigned.lock_time != signed.lock_time
        || unsigned.transaction_id != signed.transaction_id
        || unsigned.outputs != signed.outputs
        || unsigned.inputs.len() != signed.inputs.len()
    {
        return Err(LiquidClientError::new(
            "swp_liquid_output_invalid",
            "wallet changed the Liquid exit transaction template",
        ));
    }
    for (unsigned_input, signed_input) in unsigned.inputs.iter().zip(&signed.inputs) {
        if unsigned_input.previous_txid != signed_input.previous_txid
            || unsigned_input.previous_output != signed_input.previous_output
            || unsigned_input.sequence != signed_input.sequence
            || unsigned_input.script_sig != signed_input.script_sig
            || unsigned_input.has_issuance != signed_input.has_issuance
            || unsigned_input.is_pegin != signed_input.is_pegin
            || unsigned_input.issuance != signed_input.issuance
            || unsigned_input.issuance_amount_range_proof
                != signed_input.issuance_amount_range_proof
            || unsigned_input.inflation_keys_range_proof != signed_input.inflation_keys_range_proof
            || unsigned_input.pegin_witness != signed_input.pegin_witness
        {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "wallet changed a bound Liquid exit input",
            ));
        }
    }
    let input_index = usize::try_from(request.exit_package.spend_input_index).map_err(|_| {
        LiquidClientError::new(
            "swp_liquid_output_invalid",
            "Liquid exit input index exceeds usize",
        )
    })?;
    let input = signed.inputs.get(input_index).ok_or_else(|| {
        LiquidClientError::new(
            "swp_liquid_output_invalid",
            "signed Liquid exit input is absent",
        )
    })?;
    let script = decode_hex(&request.exit_package.script, "Liquid exit script")?;
    let control_block = decode_hex(
        &request.exit_package.control_block,
        "Liquid exit control block",
    )?;
    let leaf = parse_swap_leaf_script(&script).map_err(|error| {
        LiquidClientError::new(
            "swp_liquid_output_invalid",
            format!("Liquid exit leaf is invalid: {error}"),
        )
    })?;
    let (signature, witness_script, witness_control_block) = match (
        request.exit_package.path.as_str(),
        input.script_witness.as_slice(),
    ) {
        ("claim", [signature, preimage, witness_script, witness_control_block])
            if signature.len() == 64 && preimage.len() == 32 =>
        {
            let SwapLeafCondition::Hashlock(payment_hash) = leaf.condition else {
                return Err(LiquidClientError::new(
                    "swp_liquid_output_invalid",
                    "Liquid claim witness does not use a hashlock leaf",
                ));
            };
            if sha256(preimage) != payment_hash {
                return Err(LiquidClientError::new(
                    "swp_exit_package_unusable",
                    "wallet returned the wrong Liquid claim preimage",
                ));
            }
            (signature, witness_script, witness_control_block)
        }
        ("refund", [signature, witness_script, witness_control_block]) if signature.len() == 64 => {
            (signature, witness_script, witness_control_block)
        }
        _ => {
            return Err(LiquidClientError::new(
                "swp_liquid_output_invalid",
                "wallet returned an invalid Liquid script-path witness",
            ));
        }
    };
    if witness_script != &script || witness_control_block != &control_block {
        return Err(LiquidClientError::new(
            "swp_liquid_output_invalid",
            "wallet selected another Liquid exit script path",
        ));
    }
    let funding = parse_liquid_transaction(&decode_hex(
        &request.funding.raw_transaction,
        "Liquid funding transaction",
    )?)?;
    let funding_output = funding
        .outputs
        .get(usize::try_from(request.funding.output_index).map_err(|_| {
            LiquidClientError::new(
                "swp_liquid_output_invalid",
                "Liquid funding output index exceeds usize",
            )
        })?)
        .ok_or_else(|| {
            LiquidClientError::new(
                "swp_liquid_output_invalid",
                "Liquid funding output is absent",
            )
        })?;
    let prevout = LiquidPrevout {
        asset: funding_output.asset.clone(),
        value: funding_output.value.clone(),
        script_pubkey: funding_output.script_pubkey.clone(),
    };
    let genesis_hash = LiquidGenesisHash::parse_display(&request.exit_package.genesis_hash)
        .map_err(|_| {
            LiquidClientError::new(
                "swp_liquid_network_mismatch",
                "Liquid exit genesis hash is invalid",
            )
        })?;
    let sighash = liquid_taproot_script_spend_sighash(
        &signed,
        &[prevout],
        input_index,
        genesis_hash,
        &script,
        &control_block,
        None,
    )?;
    let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
        LiquidClientError::new(
            "swp_liquid_output_invalid",
            "Liquid exit signature has the wrong length",
        )
    })?;
    verify_liquid_taproot_sighash_signature(sighash, &signature, leaf.signing_key)?;
    Ok(())
}

struct VerifiedFunding {
    transaction: LiquidTransaction,
    output_index: u32,
    amount_sat: u64,
    authority: LiquidVerificationAuthority,
    prevout: LiquidPrevout,
}

struct VerifiedExit {
    transaction_sha256: String,
    signature_hash: String,
    destination_script_pubkey: String,
    fee_amount: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetKind {
    BitcoinChain,
    Lightning,
    Liquid,
}

fn parse_asset_kind(value: &str) -> Result<AssetKind, LiquidClientError> {
    if let Some(rest) = value.strip_prefix("swp:1:") {
        if let Some((network, rail)) = rest.rsplit_once(":btc:") {
            LiquidNetworkId::parse(network)?;
            return match rail {
                "chain" => Ok(AssetKind::BitcoinChain),
                "lightning" => Ok(AssetKind::Lightning),
                _ => Err(LiquidClientError::new(
                    "swp_invalid_asset_id",
                    "Bitcoin asset ID has an unknown rail",
                )),
            };
        }
    }
    LiquidAssetId::parse_mkt(value)
        .map(|_| AssetKind::Liquid)
        .map_err(Into::into)
}

fn parse_decimal(value: &str, subject: &'static str) -> Result<u64, LiquidClientError> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0') && value != "0"
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LiquidClientError::new(
            "swp_invalid_amount",
            format!("{subject} is not canonical decimal"),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| LiquidClientError::new("swp_invalid_amount", format!("{subject} exceeds u64")))
}

fn require_lower_hex_32(value: &str, subject: &'static str) -> Result<(), LiquidClientError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LiquidClientError::new(
            "swp_exit_package_unusable",
            format!("{subject} is not lowercase 32-byte hex"),
        ));
    }
    Ok(())
}

fn decode_hex(value: &str, subject: &'static str) -> Result<Vec<u8>, LiquidClientError> {
    if value.is_empty()
        || value.len() > MAX_TRANSACTION_HEX_BYTES
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LiquidClientError::new(
            "swp_liquid_output_invalid",
            format!("{subject} is not bounded lowercase hex"),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = nibble(pair[0]).ok_or_else(|| {
            LiquidClientError::new("swp_liquid_output_invalid", format!("{subject} is invalid"))
        })?;
        let low = nibble(pair[1]).ok_or_else(|| {
            LiquidClientError::new("swp_liquid_output_invalid", format!("{subject} is invalid"))
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn decode_hex_32(value: &str, subject: &'static str) -> Result<[u8; 32], LiquidClientError> {
    decode_hex(value, subject)?
        .try_into()
        .map_err(|_| LiquidClientError::new("swp_liquid_output_invalid", subject))
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

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
