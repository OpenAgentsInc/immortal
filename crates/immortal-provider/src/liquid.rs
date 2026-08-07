//! Provider-side Liquid verification and broadcast boundary.

use core::fmt;

use immortal_client::liquid::{
    LiquidBeforeFundRequest, LiquidClientError, LiquidConfidentiality, LiquidExitMode,
    LiquidFundingAuthorization, LiquidFundingVerificationInput, LiquidLegPurpose,
    LiquidLegVerifier, LiquidSwapType, LiquidUnilateralExitPackage, LocalLiquidObservation,
    VerifiedLiquidBeforeFund, verify_wallet_signed_exit,
};
use immortal_client::mkt_swp_client::provider_support::canonical_json;
use immortal_core::{
    liquid::{
        ConfidentialAsset, ConfidentialValue, LiquidGenesisHash, LiquidPrevout, LiquidTransaction,
        LocalElementsdUnblind, liquid_taproot_script_spend_sighash, parse_liquid_transaction,
        verify_liquid_control_block, verify_liquid_swap_output,
        verify_liquid_taproot_script_pubkey, verify_liquid_taproot_sighash_signature,
    },
    mkt_swp_verify::{SwapLeafCondition, parse_swap_leaf_script, sha256},
};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    bitcoind::{BitcoindError, RpcRequestId},
    elementsd::{ElementsdClient, ElementsdError, ElementsdMempoolAdmission},
    store::{
        ProviderStore, ProviderStoreError, PublicEffectRequest, PublicEffectResult,
        PublicExitPackage,
    },
    wallet::{ProviderWallet, WalletError, WalletPath},
};

#[derive(Debug)]
pub enum LiquidProviderError {
    Invalid(&'static str),
    Client(LiquidClientError),
    Elementsd(ElementsdError),
    Store(ProviderStoreError),
    Wallet(WalletError),
}

impl fmt::Display for LiquidProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "invalid provider Liquid effect: {detail}"),
            Self::Client(error) => write!(formatter, "Liquid client verification failed: {error}"),
            Self::Elementsd(error) => write!(formatter, "elementsd effect failed: {error}"),
            Self::Store(error) => write!(formatter, "Liquid effect persistence failed: {error}"),
            Self::Wallet(error) => write!(formatter, "Liquid wallet effect failed: {error}"),
        }
    }
}

impl std::error::Error for LiquidProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Elementsd(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Wallet(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<ProviderStoreError> for LiquidProviderError {
    fn from(error: ProviderStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<LiquidClientError> for LiquidProviderError {
    fn from(error: LiquidClientError) -> Self {
        Self::Client(error)
    }
}

impl From<ElementsdError> for LiquidProviderError {
    fn from(error: ElementsdError) -> Self {
        Self::Elementsd(error)
    }
}

impl From<BitcoindError> for LiquidProviderError {
    fn from(error: BitcoindError) -> Self {
        Self::Elementsd(ElementsdError::Rpc(error))
    }
}

impl From<WalletError> for LiquidProviderError {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

#[derive(Debug)]
pub struct VerifiedProviderLiquid {
    request: LiquidBeforeFundRequest,
    verified: VerifiedLiquidBeforeFund,
}

impl VerifiedProviderLiquid {
    pub fn verified(&self) -> &VerifiedLiquidBeforeFund {
        &self.verified
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidEffectOperation {
    ChainFund,
    ChainExit,
    ChainClaim,
    ChainRefund,
    SubmarineClaim,
    ReverseFund,
    ReverseRefund,
}

impl LiquidEffectOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChainFund => "liquid_chain_fund",
            Self::ChainExit => "liquid_chain_exit",
            Self::ChainClaim => "liquid_chain_claim",
            Self::ChainRefund => "liquid_chain_refund",
            Self::SubmarineClaim => "liquid_submarine_claim",
            Self::ReverseFund => "liquid_reverse_fund",
            Self::ReverseRefund => "liquid_reverse_refund",
        }
    }

    const fn is_funding(self) -> bool {
        matches!(self, Self::ChainFund | Self::ReverseFund)
    }

    fn verify_exit_path(self, path: &str) -> Result<(), LiquidProviderError> {
        let matches = match self {
            Self::ChainExit => matches!(path, "claim" | "refund"),
            Self::ChainClaim | Self::SubmarineClaim => path == "claim",
            Self::ChainRefund | Self::ReverseRefund => path == "refund",
            Self::ChainFund | Self::ReverseFund => false,
        };
        if !matches {
            return Err(LiquidProviderError::Invalid(
                "Liquid effect operation differs from its exit path",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLiquidExitRequest {
    pub funding: LiquidFundingVerificationInput,
    pub exit_package: LiquidUnilateralExitPackage,
}

impl ProviderLiquidExitRequest {
    pub fn from_before_fund(request: &LiquidBeforeFundRequest) -> Self {
        let mut funding = request.funding.clone();
        funding.trusted_unblind_transaction = None;
        Self {
            funding,
            exit_package: request.exit_package.clone(),
        }
    }
}

#[derive(Debug)]
pub struct VerifiedProviderLiquidExit {
    request: ProviderLiquidExitRequest,
    transaction: LiquidTransaction,
}

impl VerifiedProviderLiquidExit {
    pub fn request(&self) -> &ProviderLiquidExitRequest {
        &self.request
    }

    pub fn transaction_id(&self) -> String {
        encode_hex(&self.transaction.transaction_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidBroadcastReceipt {
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidFundingObservation {
    pub transaction_id: String,
    pub transaction_sha256: String,
    pub raw_transaction: Vec<u8>,
    pub output_index: u32,
    pub confirmations: u32,
    pub block_hash: Option<String>,
    pub unspent: bool,
}

#[derive(Debug, Clone)]
pub struct LiquidProviderRail {
    elementsd: ElementsdClient,
    verifier: LiquidLegVerifier,
}

impl LiquidProviderRail {
    pub fn new(elementsd: ElementsdClient) -> Self {
        let verifier = LiquidLegVerifier::new(
            elementsd.expected_network().clone(),
            elementsd.expected_pegged_asset(),
        );
        Self {
            elementsd,
            verifier,
        }
    }

    pub fn network_id(&self) -> &str {
        self.elementsd.expected_network().as_str()
    }

    pub fn pegged_asset_id(&self) -> String {
        self.elementsd.expected_pegged_asset().to_string()
    }

    pub fn pegged_asset(&self) -> immortal_core::liquid::LiquidAssetId {
        self.elementsd.expected_pegged_asset()
    }

    pub fn mkt_asset_id(&self) -> String {
        self.elementsd
            .expected_pegged_asset()
            .mkt_asset_id(self.elementsd.expected_network())
    }

    pub async fn network_view(
        &self,
        request_prefix: &str,
    ) -> Result<crate::elementsd::ElementsdNetworkView, LiquidProviderError> {
        Ok(self.elementsd.probe(request_prefix).await?)
    }

    pub async fn confirmed_capacity(
        &self,
        request_id: &RpcRequestId,
        minimum_confirmations: u32,
        maximum_outputs: usize,
    ) -> Result<crate::elementsd::ElementsdWalletCapacity, LiquidProviderError> {
        Ok(self
            .elementsd
            .confirmed_pegged_capacity(request_id, minimum_confirmations, maximum_outputs)
            .await?)
    }

    pub async fn create_signed_funding(
        &self,
        request_prefix: &str,
        selected_inputs: &[crate::elementsd::ElementsdWalletUtxo],
        script_pubkey: &[u8],
        amount_sat: u64,
        fee_rate_sat_per_vbyte: u64,
        maximum_fee_sat: u64,
    ) -> Result<crate::elementsd::ElementsdSignedFunding, LiquidProviderError> {
        Ok(self
            .elementsd
            .create_signed_funding(
                request_prefix,
                selected_inputs,
                script_pubkey,
                amount_sat,
                fee_rate_sat_per_vbyte,
                maximum_fee_sat,
            )
            .await?)
    }

    pub async fn observe_funding_output(
        &self,
        request_prefix: &str,
        transaction_id: &str,
        output_index: u32,
    ) -> Result<LiquidFundingObservation, LiquidProviderError> {
        let observed = self
            .elementsd
            .observe_output(request_prefix, transaction_id, output_index)
            .await?;
        let transaction = parse_liquid_transaction(&observed.raw_transaction)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        if encode_hex(&transaction.transaction_id) != transaction_id {
            return Err(LiquidProviderError::Invalid(
                "elementsd returned another Liquid funding transaction",
            ));
        }
        Ok(LiquidFundingObservation {
            transaction_id: transaction_id.to_owned(),
            transaction_sha256: encode_hex(&sha256(&observed.raw_transaction)),
            raw_transaction: observed.raw_transaction,
            output_index,
            confirmations: observed.confirmations,
            block_hash: observed.block_hash,
            unspent: observed.unspent,
        })
    }

    pub async fn observe_transaction(
        &self,
        request_id: &RpcRequestId,
        transaction_id: &str,
    ) -> Result<crate::elementsd::ElementsdTransactionObservation, LiquidProviderError> {
        let observation = self
            .elementsd
            .observe_transaction(request_id, transaction_id)
            .await?;
        let transaction = parse_liquid_transaction(&observation.raw_transaction)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        if encode_hex(&transaction.transaction_id) != transaction_id {
            return Err(LiquidProviderError::Invalid(
                "elementsd returned another Liquid transaction",
            ));
        }
        Ok(observation)
    }

    pub async fn spending_transaction(
        &self,
        request_prefix: &str,
        funding_transaction_id: &str,
        funding_output_index: u32,
    ) -> Result<Option<String>, LiquidProviderError> {
        Ok(self
            .elementsd
            .spending_transaction(request_prefix, funding_transaction_id, funding_output_index)
            .await?
            .spending_transaction_id)
    }

    pub async fn genesis_hash(
        &self,
        request_id: &RpcRequestId,
    ) -> Result<LiquidGenesisHash, LiquidProviderError> {
        let hash = self.elementsd.genesis_hash(request_id).await?;
        LiquidGenesisHash::parse_display(&hash)
            .map_err(|error| LiquidProviderError::Client(error.into()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_signed_exit_package(
        &self,
        request_prefix: &str,
        wallet: &ProviderWallet,
        wallet_path: WalletPath,
        funding_raw: &[u8],
        funding_output_index: u32,
        funding_amount_sat: u64,
        funding_script_pubkey: &[u8],
        path: &str,
        script: &[u8],
        control_block: &[u8],
        timelock: u32,
        destination_script_pubkey: &[u8],
        fee_amount_sat: u64,
        preimage: Option<[u8; 32]>,
    ) -> Result<LiquidUnilateralExitPackage, LiquidProviderError> {
        let funding = parse_liquid_transaction(funding_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let funding_output = funding
            .outputs
            .get(usize::try_from(funding_output_index).map_err(|_| {
                LiquidProviderError::Invalid("Liquid funding output index exceeds usize")
            })?)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid funding output is absent",
            ))?;
        if funding_output.asset
            != ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset())
            || funding_output.value != ConfidentialValue::Explicit(funding_amount_sat)
            || funding_output.script_pubkey != funding_script_pubkey
        {
            return Err(LiquidProviderError::Invalid(
                "Liquid funding output differs from signed exit inputs",
            ));
        }
        let leaf = parse_swap_leaf_script(script)
            .map_err(|_| LiquidProviderError::Invalid("Liquid exit leaf is invalid"))?;
        let sequence = match (path, leaf.condition, preimage) {
            ("claim", SwapLeafCondition::Hashlock(payment_hash), Some(preimage))
                if sha256(&preimage) == payment_hash =>
            {
                u32::MAX
            }
            ("refund", SwapLeafCondition::Cltv(height), None) if timelock == height => 0xffff_fffe,
            ("refund", SwapLeafCondition::Csv(blocks), None) if timelock == blocks => blocks,
            _ => {
                return Err(LiquidProviderError::Invalid(
                    "Liquid exit path, timelock, or preimage differs from its leaf",
                ));
            }
        };
        let output_amount_sat = funding_amount_sat
            .checked_sub(fee_amount_sat)
            .filter(|amount| *amount > 0)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid exit fee consumes its principal",
            ))?;
        let unsigned_raw = serialize_explicit_exit(
            funding.transaction_id,
            funding_output_index,
            self.elementsd.expected_pegged_asset(),
            output_amount_sat,
            destination_script_pubkey,
            fee_amount_sat,
            timelock,
            sequence,
            None,
            None,
            script,
            control_block,
        )?;
        let unsigned = parse_liquid_transaction(&unsigned_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let genesis_hash_display = self
            .elementsd
            .genesis_hash(&RpcRequestId::new(format!("{request_prefix}:genesis"))?)
            .await?;
        let genesis_hash = LiquidGenesisHash::parse_display(&genesis_hash_display)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let prevouts = [LiquidPrevout {
            asset: ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset()),
            value: ConfidentialValue::Explicit(funding_amount_sat),
            script_pubkey: funding_script_pubkey.to_vec(),
        }];
        let signed = wallet.sign_liquid_script_path(
            wallet_path,
            &unsigned,
            &prevouts,
            0,
            genesis_hash,
            script,
            control_block,
        )?;
        if signed.public_key != leaf.signing_key.serialize() {
            return Err(LiquidProviderError::Invalid(
                "Liquid exit signer differs from its script leaf",
            ));
        }
        let transaction = serialize_explicit_exit(
            funding.transaction_id,
            funding_output_index,
            self.elementsd.expected_pegged_asset(),
            output_amount_sat,
            destination_script_pubkey,
            fee_amount_sat,
            timelock,
            sequence,
            Some(&signed.signature),
            preimage.as_ref(),
            script,
            control_block,
        )?;
        let parsed = parse_liquid_transaction(&transaction)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let signed_sighash = liquid_taproot_script_spend_sighash(
            &parsed,
            &prevouts,
            0,
            genesis_hash,
            script,
            control_block,
            None,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;
        verify_liquid_taproot_sighash_signature(
            signed_sighash,
            &signed.signature,
            leaf.signing_key,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;
        Ok(LiquidUnilateralExitPackage {
            schema: "openagents.mkt-swp.liquid-exit.v1".to_owned(),
            network_id: self.network_id().to_owned(),
            genesis_hash: genesis_hash_display,
            asset_id: self.mkt_asset_id(),
            funding_transaction_id: encode_hex(&funding.transaction_id),
            funding_output_index,
            funding_amount: funding_amount_sat.to_string(),
            funding_script_pubkey: encode_hex(funding_script_pubkey),
            path: path.to_owned(),
            script: encode_hex(script),
            control_block: encode_hex(control_block),
            timelock,
            spend_input_index: 0,
            fee_output_index: 1,
            fee_amount: fee_amount_sat.to_string(),
            transaction_sha256: encode_hex(&sha256(&transaction)),
            transaction: encode_hex(&transaction),
            mode: LiquidExitMode::Presigned,
            wallet_signing_handle_sha256: None,
            preimage_recovery_ref: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_wallet_claim_exit_package(
        &self,
        request_prefix: &str,
        funding_raw: &[u8],
        funding_output_index: u32,
        funding_amount_sat: u64,
        funding_script_pubkey: &[u8],
        script: &[u8],
        control_block: &[u8],
        destination_script_pubkey: &[u8],
        fee_amount_sat: u64,
        wallet_signing_handle_sha256: &str,
        preimage_recovery_ref: &str,
    ) -> Result<LiquidUnilateralExitPackage, LiquidProviderError> {
        decode_hex_32(wallet_signing_handle_sha256, "Liquid wallet-signing handle")?;
        decode_hex_32(preimage_recovery_ref, "Liquid preimage-recovery handle")?;
        if wallet_signing_handle_sha256 == preimage_recovery_ref {
            return Err(LiquidProviderError::Invalid(
                "Liquid signer and preimage handles must be distinct",
            ));
        }
        let funding = parse_liquid_transaction(funding_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let funding_output = funding
            .outputs
            .get(usize::try_from(funding_output_index).map_err(|_| {
                LiquidProviderError::Invalid("Liquid funding output index exceeds usize")
            })?)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid funding output is absent",
            ))?;
        if funding_output.asset
            != ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset())
            || funding_output.value != ConfidentialValue::Explicit(funding_amount_sat)
            || funding_output.script_pubkey != funding_script_pubkey
        {
            return Err(LiquidProviderError::Invalid(
                "Liquid funding output differs from wallet exit inputs",
            ));
        }
        let leaf = parse_swap_leaf_script(script)
            .map_err(|_| LiquidProviderError::Invalid("Liquid claim leaf is invalid"))?;
        if !matches!(leaf.condition, SwapLeafCondition::Hashlock(_)) {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet claim does not use a hashlock leaf",
            ));
        }
        let output_amount_sat = funding_amount_sat
            .checked_sub(fee_amount_sat)
            .filter(|amount| *amount > 0)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid exit fee consumes its principal",
            ))?;
        let transaction = serialize_explicit_exit(
            funding.transaction_id,
            funding_output_index,
            self.elementsd.expected_pegged_asset(),
            output_amount_sat,
            destination_script_pubkey,
            fee_amount_sat,
            0,
            u32::MAX,
            None,
            None,
            script,
            control_block,
        )?;
        let genesis_hash = self
            .elementsd
            .genesis_hash(&RpcRequestId::new(format!("{request_prefix}:genesis"))?)
            .await?;
        Ok(LiquidUnilateralExitPackage {
            schema: "openagents.mkt-swp.liquid-exit.v1".to_owned(),
            network_id: self.network_id().to_owned(),
            genesis_hash,
            asset_id: self.mkt_asset_id(),
            funding_transaction_id: encode_hex(&funding.transaction_id),
            funding_output_index,
            funding_amount: funding_amount_sat.to_string(),
            funding_script_pubkey: encode_hex(funding_script_pubkey),
            path: "claim".to_owned(),
            script: encode_hex(script),
            control_block: encode_hex(control_block),
            timelock: 0,
            spend_input_index: 0,
            fee_output_index: 1,
            fee_amount: fee_amount_sat.to_string(),
            transaction_sha256: encode_hex(&sha256(&transaction)),
            transaction: encode_hex(&transaction),
            mode: LiquidExitMode::Wallet,
            wallet_signing_handle_sha256: Some(wallet_signing_handle_sha256.to_owned()),
            preimage_recovery_ref: Some(preimage_recovery_ref.to_owned()),
        })
    }

    pub fn complete_wallet_claim_exit(
        &self,
        request: &LiquidBeforeFundRequest,
        wallet: &ProviderWallet,
        wallet_path: WalletPath,
        preimage: [u8; 32],
    ) -> Result<Vec<u8>, LiquidProviderError> {
        let package = &request.exit_package;
        if package.mode != LiquidExitMode::Wallet
            || package.path != "claim"
            || package.wallet_signing_handle_sha256.is_none()
            || package.preimage_recovery_ref.is_none()
            || package.wallet_signing_handle_sha256 == package.preimage_recovery_ref
        {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet completion requires distinct claim recovery handles",
            ));
        }
        let unsigned_raw = decode_hex(&package.transaction)?;
        if encode_hex(&sha256(&unsigned_raw)) != package.transaction_sha256 {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet template differs from its committed digest",
            ));
        }
        let unsigned = parse_liquid_transaction(&unsigned_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let input_index = usize::try_from(package.spend_input_index)
            .map_err(|_| LiquidProviderError::Invalid("Liquid wallet input index exceeds usize"))?;
        if input_index != 0 || package.fee_output_index != 1 {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet template uses unsupported input or fee indexes",
            ));
        }
        let funding_raw = decode_hex(&request.funding.raw_transaction)?;
        let funding = parse_liquid_transaction(&funding_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let funding_output = funding
            .outputs
            .get(usize::try_from(package.funding_output_index).map_err(|_| {
                LiquidProviderError::Invalid("Liquid funding output index exceeds usize")
            })?)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid wallet funding output is absent",
            ))?;
        let funding_amount_sat = package
            .funding_amount
            .parse::<u64>()
            .map_err(|_| LiquidProviderError::Invalid("Liquid funding amount is invalid"))?;
        let fee_amount_sat = package
            .fee_amount
            .parse::<u64>()
            .map_err(|_| LiquidProviderError::Invalid("Liquid exit fee is invalid"))?;
        let output_amount_sat = funding_amount_sat
            .checked_sub(fee_amount_sat)
            .filter(|amount| *amount > 0)
            .ok_or(LiquidProviderError::Invalid(
                "Liquid exit fee consumes its principal",
            ))?;
        let destination_script_pubkey = unsigned
            .outputs
            .first()
            .ok_or(LiquidProviderError::Invalid(
                "Liquid wallet payout output is absent",
            ))?
            .script_pubkey
            .as_slice();
        let script = decode_hex(&package.script)?;
        let control_block = decode_hex(&package.control_block)?;
        let leaf = parse_swap_leaf_script(&script)
            .map_err(|_| LiquidProviderError::Invalid("Liquid claim leaf is invalid"))?;
        let SwapLeafCondition::Hashlock(payment_hash) = leaf.condition else {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet claim does not use a hashlock leaf",
            ));
        };
        if sha256(&preimage) != payment_hash {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet claim preimage differs from its hashlock",
            ));
        }
        let genesis_hash = LiquidGenesisHash::parse_display(&package.genesis_hash)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let prevouts = [LiquidPrevout {
            asset: funding_output.asset.clone(),
            value: funding_output.value.clone(),
            script_pubkey: funding_output.script_pubkey.clone(),
        }];
        let signed = wallet.sign_liquid_script_path(
            wallet_path,
            &unsigned,
            &prevouts,
            input_index,
            genesis_hash,
            &script,
            &control_block,
        )?;
        if signed.public_key != leaf.signing_key.serialize() {
            return Err(LiquidProviderError::Invalid(
                "Liquid wallet signer differs from its claim leaf",
            ));
        }
        let transaction = serialize_explicit_exit(
            funding.transaction_id,
            package.funding_output_index,
            self.elementsd.expected_pegged_asset(),
            output_amount_sat,
            destination_script_pubkey,
            fee_amount_sat,
            package.timelock,
            u32::MAX,
            Some(&signed.signature),
            Some(&preimage),
            &script,
            &control_block,
        )?;
        verify_wallet_signed_exit(request, &transaction).map_err(LiquidProviderError::Client)?;
        Ok(transaction)
    }

    pub async fn verify_before_fund(
        &self,
        request: &LiquidBeforeFundRequest,
    ) -> Result<VerifiedProviderLiquid, LiquidProviderError> {
        let raw = decode_hex(&request.funding.raw_transaction)?;
        let transaction = parse_liquid_transaction(&raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let transaction_id = encode_hex(&transaction.transaction_id);
        let transaction_sha256 = encode_hex(&sha256(&raw));
        let prefix = request_prefix(&transaction_sha256)?;

        let trusted_unblind_transaction =
            if request.funding.confidentiality == LiquidConfidentiality::Confidential {
                Some(
                    self.elementsd
                        .unblind_own_transaction_raw(
                            &RpcRequestId::new(format!("{prefix}:unblind"))?,
                            &raw,
                        )
                        .await?,
                )
            } else {
                None
            };
        let observation = match (request.swap_type, request.purpose) {
            (_, LiquidLegPurpose::RequesterBroadcast) => {
                self.elementsd
                    .require_mempool_acceptance_or_exact_known(
                        &RpcRequestId::new(format!("{prefix}:mempool"))?,
                        &RpcRequestId::new(format!("{prefix}:mempool-known"))?,
                        &raw,
                    )
                    .await?;
                LocalLiquidObservation {
                    transaction_id: transaction_id.clone(),
                    transaction_sha256: transaction_sha256.clone(),
                    confirmations: 0,
                    mempool_accepted: true,
                    replacement_detected: false,
                    competing_spend_detected: false,
                }
            }
            (LiquidSwapType::Chain, LiquidLegPurpose::CounterpartyLock) => {
                self.elementsd
                    .require_mempool_acceptance(
                        &RpcRequestId::new(format!("{prefix}:mempool"))?,
                        &raw,
                    )
                    .await?;
                LocalLiquidObservation {
                    transaction_id: transaction_id.clone(),
                    transaction_sha256: transaction_sha256.clone(),
                    confirmations: 0,
                    mempool_accepted: true,
                    replacement_detected: false,
                    competing_spend_detected: false,
                }
            }
            (_, LiquidLegPurpose::CounterpartyLock) => {
                let observed = self
                    .elementsd
                    .observe_output(&prefix, &transaction_id, request.funding.output_index)
                    .await?;
                LocalLiquidObservation {
                    transaction_id: transaction_id.clone(),
                    transaction_sha256: encode_hex(&sha256(&observed.raw_transaction)),
                    confirmations: observed.confirmations,
                    mempool_accepted: false,
                    replacement_detected: false,
                    competing_spend_detected: !observed.unspent,
                }
            }
        };
        let mut verified_request = request.clone();
        verified_request.funding.trusted_unblind_transaction =
            trusted_unblind_transaction.as_deref().map(encode_hex);
        let verified = self
            .verifier
            .verify_before_fund(&verified_request, |_| Ok(observation.clone()))?;
        Ok(VerifiedProviderLiquid {
            request: verified_request,
            verified,
        })
    }

    pub async fn broadcast_funding(
        &self,
        verified: &VerifiedProviderLiquid,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        let LiquidFundingAuthorization::BroadcastLiquid {
            transaction_id,
            raw_transaction,
        } = &verified.verified.authorization
        else {
            return Err(LiquidProviderError::Invalid(
                "counterparty observation is not a funding broadcast",
            ));
        };
        if raw_transaction != &verified.request.funding.raw_transaction {
            return Err(LiquidProviderError::Invalid(
                "authorization bytes differ from the verified request",
            ));
        }
        let raw = decode_hex(raw_transaction)?;
        let prefix = request_prefix(&verified.request.funding.transaction_sha256)?;
        let admission = self
            .elementsd
            .require_mempool_acceptance_or_exact_known(
                &RpcRequestId::new(format!("{prefix}:broadcast-check"))?,
                &RpcRequestId::new(format!("{prefix}:broadcast-known"))?,
                &raw,
            )
            .await?;
        let observed = match admission {
            ElementsdMempoolAdmission::New => {
                self.elementsd
                    .broadcast(&RpcRequestId::new(format!("{prefix}:broadcast"))?, &raw)
                    .await?
            }
            ElementsdMempoolAdmission::ExactKnown => transaction_id.clone(),
        };
        if &observed != transaction_id {
            return Err(LiquidProviderError::Invalid(
                "elementsd returned another funding transaction ID",
            ));
        }
        Ok(LiquidBroadcastReceipt {
            transaction_id: observed,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_funding_effect(
        &self,
        store: &mut ProviderStore,
        effect_id: &str,
        session_id: &str,
        order_id: &str,
        leg_id: &str,
        request: &LiquidBeforeFundRequest,
        now: u64,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        self.execute_funding_effect_with_operation(
            store,
            effect_id,
            session_id,
            order_id,
            leg_id,
            LiquidEffectOperation::ChainFund,
            request,
            now,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_funding_effect_with_operation(
        &self,
        store: &mut ProviderStore,
        effect_id: &str,
        session_id: &str,
        order_id: &str,
        leg_id: &str,
        operation: LiquidEffectOperation,
        request: &LiquidBeforeFundRequest,
        now: u64,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        if !operation.is_funding() {
            return Err(LiquidProviderError::Invalid(
                "Liquid funding effect received an exit operation",
            ));
        }
        let public_request = serde_json::to_value(request)
            .map_err(|_| LiquidProviderError::Invalid("funding request is not serializable"))?;
        let request_sha256 =
            encode_hex(&sha256(&canonical_json(&public_request).map_err(|_| {
                LiquidProviderError::Invalid("funding request is not canonical")
            })?));
        let package = serde_json::to_value(&request.exit_package)
            .map_err(|_| LiquidProviderError::Invalid("exit package is not serializable"))?;
        let package_sha256 =
            encode_hex(&sha256(&canonical_json(&package).map_err(|_| {
                LiquidProviderError::Invalid("exit package is not canonical")
            })?));
        let package_id = encode_hex(&sha256(
            format!("openagents.immortal.liquid-exit.v1\0{effect_id}").as_bytes(),
        ));
        store
            .persist_exit_package(&PublicExitPackage {
                package_id,
                session_id: session_id.to_owned(),
                order_id: order_id.to_owned(),
                leg_id: leg_id.to_owned(),
                path: request.exit_package.path.clone(),
                package_sha256,
                public_package: package,
                created_at: now,
            })
            .await?;
        let persisted = PublicEffectRequest {
            effect_id: effect_id.to_owned(),
            session_id: session_id.to_owned(),
            operation: operation.as_str().to_owned(),
            request_sha256: request_sha256.clone(),
            public_request,
            created_at: now,
        };
        store.persist_effect_request(&persisted).await?;
        if let Some(existing) = store.public_effect(effect_id).await? {
            if existing.state == "applied" {
                let transaction_id =
                    existing
                        .external_reference
                        .ok_or(LiquidProviderError::Invalid(
                            "applied funding effect has no transaction ID",
                        ))?;
                return Ok(LiquidBroadcastReceipt { transaction_id });
            }
        }
        let verified = self
            .verify_provider_funding_before_broadcast(request)
            .await?;
        let receipt = self.broadcast_funding(&verified).await?;
        let public_result = json_result(&receipt.transaction_id, "funding");
        let result_sha256 =
            encode_hex(&sha256(&canonical_json(&public_result).map_err(|_| {
                LiquidProviderError::Invalid("funding result is not canonical")
            })?));
        store
            .complete_effect(&PublicEffectResult {
                effect_id: effect_id.to_owned(),
                request_sha256,
                result_sha256,
                public_result,
                external_reference: receipt.transaction_id.clone(),
                completed_at: now,
            })
            .await?;
        Ok(receipt)
    }

    pub async fn execute_unilateral_exit_effect(
        &self,
        store: &mut ProviderStore,
        effect_id: &str,
        session_id: &str,
        request: &LiquidBeforeFundRequest,
        now: u64,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        self.execute_unilateral_exit_effect_with_operation(
            store,
            effect_id,
            session_id,
            LiquidEffectOperation::ChainExit,
            request,
            now,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_unilateral_exit_effect_with_operation(
        &self,
        store: &mut ProviderStore,
        effect_id: &str,
        session_id: &str,
        operation: LiquidEffectOperation,
        request: &LiquidBeforeFundRequest,
        now: u64,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        operation.verify_exit_path(&request.exit_package.path)?;
        let public_request = serde_json::to_value(request)
            .map_err(|_| LiquidProviderError::Invalid("exit request is not serializable"))?;
        let request_sha256 =
            encode_hex(&sha256(&canonical_json(&public_request).map_err(|_| {
                LiquidProviderError::Invalid("exit request is not canonical")
            })?));
        let persisted = PublicEffectRequest {
            effect_id: effect_id.to_owned(),
            session_id: session_id.to_owned(),
            operation: operation.as_str().to_owned(),
            request_sha256: request_sha256.clone(),
            public_request,
            created_at: now,
        };
        store.persist_effect_request(&persisted).await?;
        if let Some(existing) = store.public_effect(effect_id).await? {
            if existing.state == "applied" {
                let transaction_id =
                    existing
                        .external_reference
                        .ok_or(LiquidProviderError::Invalid(
                            "applied exit effect has no transaction ID",
                        ))?;
                return Ok(LiquidBroadcastReceipt { transaction_id });
            }
        }
        let verified = self
            .verify_provider_funding_before_broadcast(request)
            .await?;
        let receipt = self.broadcast_unilateral_exit(&verified).await?;
        let public_result = json_result(&receipt.transaction_id, "unilateral_exit");
        let result_sha256 =
            encode_hex(&sha256(&canonical_json(&public_result).map_err(|_| {
                LiquidProviderError::Invalid("exit result is not canonical")
            })?));
        store
            .complete_effect(&PublicEffectResult {
                effect_id: effect_id.to_owned(),
                request_sha256,
                result_sha256,
                public_result,
                external_reference: receipt.transaction_id.clone(),
                completed_at: now,
            })
            .await?;
        Ok(receipt)
    }

    async fn verify_provider_funding_before_broadcast(
        &self,
        request: &LiquidBeforeFundRequest,
    ) -> Result<VerifiedProviderLiquid, LiquidProviderError> {
        let mut verification = request.clone();
        if verification.purpose == LiquidLegPurpose::CounterpartyLock {
            let liquid_asset = self.mkt_asset_id();
            let bitcoin_network = request
                .input_asset_id
                .strip_suffix(":btc:lightning")
                .or_else(|| request.input_asset_id.strip_suffix(":btc:chain"))
                .map(|prefix| format!("{prefix}:btc:chain"))
                .ok_or(LiquidProviderError::Invalid(
                    "provider-funded Liquid leg has no Bitcoin peer asset",
                ))?;
            verification.swap_type = immortal_client::liquid::LiquidSwapType::Chain;
            verification.purpose = LiquidLegPurpose::RequesterBroadcast;
            verification.input_asset_id = liquid_asset;
            verification.output_asset_id = bitcoin_network;
        }
        self.verify_before_fund(&verification).await
    }

    pub async fn verify_provider_claim(
        &self,
        request: &ProviderLiquidExitRequest,
    ) -> Result<VerifiedProviderLiquidExit, LiquidProviderError> {
        self.verify_provider_exit(request, "claim").await
    }

    pub async fn verify_provider_refund(
        &self,
        request: &ProviderLiquidExitRequest,
    ) -> Result<VerifiedProviderLiquidExit, LiquidProviderError> {
        self.verify_provider_exit(request, "refund").await
    }

    async fn verify_provider_exit(
        &self,
        request: &ProviderLiquidExitRequest,
        expected_path: &str,
    ) -> Result<VerifiedProviderLiquidExit, LiquidProviderError> {
        if request.funding.trusted_unblind_transaction.is_some() {
            return Err(LiquidProviderError::Invalid(
                "provider exit verification does not accept caller-supplied unblind bytes",
            ));
        }
        if request.funding.asset_id != self.mkt_asset_id()
            || request.funding.minimum_confirmations == 0
            || request.funding.replacement_policy != "reject"
        {
            return Err(LiquidProviderError::Invalid(
                "provider exit funding policy differs from the configured Liquid rail",
            ));
        }
        let funding_raw = decode_hex(&request.funding.raw_transaction)?;
        if encode_hex(&sha256(&funding_raw)) != request.funding.transaction_sha256 {
            return Err(LiquidProviderError::Invalid(
                "provider exit funding transaction digest differs",
            ));
        }
        let funding = parse_liquid_transaction(&funding_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let funding_output_index = usize::try_from(request.funding.output_index)
            .map_err(|_| LiquidProviderError::Invalid("funding output index exceeds usize"))?;
        let funding_output =
            funding
                .outputs
                .get(funding_output_index)
                .ok_or(LiquidProviderError::Invalid(
                    "provider exit funding output is absent",
                ))?;
        let funding_amount_sat = parse_positive_decimal(
            &request.funding.amount,
            "provider exit funding amount is not canonical",
        )?;
        let funding_script_pubkey = decode_hex(&request.funding.script_pubkey)?;
        let unblinded = match request.funding.confidentiality {
            LiquidConfidentiality::Explicit => None,
            LiquidConfidentiality::Confidential => {
                let prefix = request_prefix(&request.funding.transaction_sha256)?;
                let raw = self
                    .elementsd
                    .unblind_own_transaction_raw(
                        &RpcRequestId::new(format!("{prefix}:provider-exit-unblind"))?,
                        &funding_raw,
                    )
                    .await?;
                Some(
                    parse_liquid_transaction(&raw)
                        .map_err(|error| LiquidProviderError::Client(error.into()))?,
                )
            }
        };
        verify_liquid_swap_output(
            &funding,
            unblinded.as_ref().map(LocalElementsdUnblind::trusted),
            funding_output_index,
            self.elementsd.expected_pegged_asset(),
            funding_amount_sat,
            &funding_script_pubkey,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let taproot_internal_key = XOnlyPublicKey::from_byte_array(decode_hex_32(
            &request.funding.taproot_internal_key,
            "provider funding Taproot internal key",
        )?)
        .map_err(|_| LiquidProviderError::Invalid("provider funding Taproot key is invalid"))?;
        let taproot_merkle_root = request
            .funding
            .taproot_merkle_root
            .as_deref()
            .map(|root| decode_hex_32(root, "provider funding Taproot merkle root"))
            .transpose()?;
        verify_liquid_taproot_script_pubkey(
            &funding_script_pubkey,
            taproot_internal_key,
            taproot_merkle_root,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;

        let package = &request.exit_package;
        if package.schema != "openagents.mkt-swp.liquid-exit.v1"
            || package.network_id != self.network_id()
            || package.asset_id != self.mkt_asset_id()
            || package.funding_transaction_id != encode_hex(&funding.transaction_id)
            || package.funding_output_index != request.funding.output_index
            || package.funding_amount != request.funding.amount
            || package.funding_script_pubkey != request.funding.script_pubkey
            || package.path != expected_path
            || package.mode != LiquidExitMode::Presigned
            || package.wallet_signing_handle_sha256.is_some()
            || package.preimage_recovery_ref.is_some()
        {
            return Err(LiquidProviderError::Invalid(
                "provider exit package differs from its exact funding context",
            ));
        }
        let transaction_raw = decode_hex(&package.transaction)?;
        if encode_hex(&sha256(&transaction_raw)) != package.transaction_sha256 {
            return Err(LiquidProviderError::Invalid(
                "provider exit transaction digest differs",
            ));
        }
        let transaction = parse_liquid_transaction(&transaction_raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        if transaction.inputs.len() != 1
            || package.spend_input_index != 0
            || transaction.outputs.len() != 2
            || package.fee_output_index != 1
        {
            return Err(LiquidProviderError::Invalid(
                "provider exit is not the exact single-input two-output shape",
            ));
        }
        let input = transaction
            .inputs
            .first()
            .ok_or(LiquidProviderError::Invalid(
                "provider exit input is absent",
            ))?;
        if input.previous_txid != funding.transaction_id
            || input.previous_output != request.funding.output_index
            || input.has_issuance
            || input.is_pegin
            || !input.script_sig.is_empty()
            || !input.pegin_witness.is_empty()
        {
            return Err(LiquidProviderError::Invalid(
                "provider exit spends another outpoint or uses a forbidden input shape",
            ));
        }
        let fee_amount_sat = parse_positive_decimal(
            &package.fee_amount,
            "provider exit fee amount is not canonical",
        )?;
        let principal_amount_sat =
            funding_amount_sat
                .checked_sub(fee_amount_sat)
                .ok_or(LiquidProviderError::Invalid(
                    "provider exit fee exceeds its funding amount",
                ))?;
        let principal = transaction
            .outputs
            .first()
            .ok_or(LiquidProviderError::Invalid(
                "provider exit principal output is absent",
            ))?;
        let fee = transaction
            .outputs
            .get(1)
            .ok_or(LiquidProviderError::Invalid(
                "provider exit fee output is absent",
            ))?;
        if principal.asset != ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset())
            || principal.value != ConfidentialValue::Explicit(principal_amount_sat)
            || principal.script_pubkey.is_empty()
            || fee.asset != ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset())
            || fee.value != ConfidentialValue::Explicit(fee_amount_sat)
            || !fee.script_pubkey.is_empty()
        {
            return Err(LiquidProviderError::Invalid(
                "provider exit outputs do not conserve the explicit pegged asset",
            ));
        }

        let script = decode_hex(&package.script)?;
        let control_block = decode_hex(&package.control_block)?;
        let output_key = funding_script_pubkey
            .strip_prefix(&[0x51, 0x20])
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| XOnlyPublicKey::from_byte_array(bytes).ok())
            .ok_or(LiquidProviderError::Invalid(
                "provider funding output is not a valid Taproot program",
            ))?;
        verify_liquid_control_block(&output_key, &script, &control_block)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let leaf = parse_swap_leaf_script(&script)
            .map_err(|_| LiquidProviderError::Invalid("provider exit leaf is invalid"))?;
        let signature = match (
            expected_path,
            leaf.condition,
            input.script_witness.as_slice(),
        ) {
            (
                "claim",
                SwapLeafCondition::Hashlock(payment_hash),
                [
                    signature,
                    preimage,
                    witnessed_script,
                    witnessed_control_block,
                ],
            ) if signature.len() == 64
                && preimage.len() == 32
                && sha256(preimage) == payment_hash
                && witnessed_script == &script
                && witnessed_control_block == &control_block
                && package.timelock == 0 =>
            {
                signature
            }
            (
                "refund",
                SwapLeafCondition::Cltv(height),
                [signature, witnessed_script, witnessed_control_block],
            ) if signature.len() == 64
                && witnessed_script == &script
                && witnessed_control_block == &control_block
                && package.timelock == height
                && transaction.lock_time >= height
                && input.sequence != u32::MAX =>
            {
                signature
            }
            (
                "refund",
                SwapLeafCondition::Csv(blocks),
                [signature, witnessed_script, witnessed_control_block],
            ) if signature.len() == 64
                && witnessed_script == &script
                && witnessed_control_block == &control_block
                && package.timelock == blocks
                && input.sequence & (1 << 31) == 0
                && input.sequence & 0x0000_ffff >= blocks =>
            {
                signature
            }
            _ => {
                return Err(LiquidProviderError::Invalid(
                    "provider exit path, timelock, preimage, or witness shape differs",
                ));
            }
        };
        let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
            LiquidProviderError::Invalid("provider exit signature is not SIGHASH_DEFAULT")
        })?;
        let observed_genesis = self
            .elementsd
            .genesis_hash(&RpcRequestId::new(format!(
                "{}:provider-exit-genesis",
                request_prefix(&package.transaction_sha256)?
            ))?)
            .await?;
        if package.genesis_hash != observed_genesis {
            return Err(LiquidProviderError::Invalid(
                "provider exit genesis hash differs from the configured elementsd",
            ));
        }
        let genesis_hash = LiquidGenesisHash::parse_display(&package.genesis_hash)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let prevouts = [LiquidPrevout {
            asset: funding_output.asset.clone(),
            value: funding_output.value.clone(),
            script_pubkey: funding_script_pubkey,
        }];
        let sighash = liquid_taproot_script_spend_sighash(
            &transaction,
            &prevouts,
            0,
            genesis_hash,
            &script,
            &control_block,
            None,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;
        verify_liquid_taproot_sighash_signature(sighash, &signature, leaf.signing_key)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        Ok(VerifiedProviderLiquidExit {
            request: request.clone(),
            transaction,
        })
    }

    pub async fn broadcast_provider_exit(
        &self,
        verified: &VerifiedProviderLiquidExit,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        let package = &verified.request.exit_package;
        let raw = decode_hex(&package.transaction)?;
        let expected_transaction_id = verified.transaction_id();
        let prefix = request_prefix(&package.transaction_sha256)?;
        let admission = self
            .elementsd
            .require_mempool_acceptance_or_exact_known(
                &RpcRequestId::new(format!("{prefix}:provider-exit-check"))?,
                &RpcRequestId::new(format!("{prefix}:provider-exit-known"))?,
                &raw,
            )
            .await?;
        let observed = match admission {
            ElementsdMempoolAdmission::New => {
                self.elementsd
                    .broadcast(
                        &RpcRequestId::new(format!("{prefix}:provider-exit-broadcast"))?,
                        &raw,
                    )
                    .await?
            }
            ElementsdMempoolAdmission::ExactKnown => expected_transaction_id.clone(),
        };
        if observed != expected_transaction_id {
            return Err(LiquidProviderError::Invalid(
                "elementsd returned another provider exit transaction ID",
            ));
        }
        Ok(LiquidBroadcastReceipt {
            transaction_id: observed,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute_provider_exit_effect(
        &self,
        store: &mut ProviderStore,
        effect_id: &str,
        session_id: &str,
        order_id: &str,
        leg_id: &str,
        operation: LiquidEffectOperation,
        request: &ProviderLiquidExitRequest,
        now: u64,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        operation.verify_exit_path(&request.exit_package.path)?;
        let public_request = serde_json::to_value(request).map_err(|_| {
            LiquidProviderError::Invalid("provider exit request is not serializable")
        })?;
        let request_sha256 =
            encode_hex(&sha256(&canonical_json(&public_request).map_err(|_| {
                LiquidProviderError::Invalid("provider exit request is not canonical")
            })?));
        let package = serde_json::to_value(&request.exit_package).map_err(|_| {
            LiquidProviderError::Invalid("provider exit package is not serializable")
        })?;
        let package_sha256 = encode_hex(&sha256(&canonical_json(&package).map_err(|_| {
            LiquidProviderError::Invalid("provider exit package is not canonical")
        })?));
        let package_id = encode_hex(&sha256(
            format!("openagents.immortal.liquid-exit.v1\0{effect_id}").as_bytes(),
        ));
        store
            .persist_exit_package(&PublicExitPackage {
                package_id,
                session_id: session_id.to_owned(),
                order_id: order_id.to_owned(),
                leg_id: leg_id.to_owned(),
                path: request.exit_package.path.clone(),
                package_sha256,
                public_package: package,
                created_at: now,
            })
            .await?;
        store
            .persist_effect_request(&PublicEffectRequest {
                effect_id: effect_id.to_owned(),
                session_id: session_id.to_owned(),
                operation: operation.as_str().to_owned(),
                request_sha256: request_sha256.clone(),
                public_request,
                created_at: now,
            })
            .await?;
        if let Some(existing) = store.public_effect(effect_id).await? {
            if existing.state == "applied" {
                let transaction_id =
                    existing
                        .external_reference
                        .ok_or(LiquidProviderError::Invalid(
                            "applied provider exit effect has no transaction ID",
                        ))?;
                return Ok(LiquidBroadcastReceipt { transaction_id });
            }
        }
        let verified = match request.exit_package.path.as_str() {
            "claim" => self.verify_provider_claim(request).await?,
            "refund" => self.verify_provider_refund(request).await?,
            _ => {
                return Err(LiquidProviderError::Invalid(
                    "provider exit effect has an unsupported path",
                ));
            }
        };
        let receipt = self.broadcast_provider_exit(&verified).await?;
        let public_result = json_result(&receipt.transaction_id, "unilateral_exit");
        let result_sha256 =
            encode_hex(&sha256(&canonical_json(&public_result).map_err(|_| {
                LiquidProviderError::Invalid("provider exit result is not canonical")
            })?));
        store
            .complete_effect(&PublicEffectResult {
                effect_id: effect_id.to_owned(),
                request_sha256,
                result_sha256,
                public_result,
                external_reference: receipt.transaction_id.clone(),
                completed_at: now,
            })
            .await?;
        Ok(receipt)
    }

    pub async fn broadcast_unilateral_exit(
        &self,
        verified: &VerifiedProviderLiquid,
    ) -> Result<LiquidBroadcastReceipt, LiquidProviderError> {
        let package = &verified.request.exit_package;
        if package.transaction_sha256 != verified.verified.exit_transaction_sha256 {
            return Err(LiquidProviderError::Invalid(
                "exit package differs from verify-before-fund",
            ));
        }
        let raw = decode_hex(&package.transaction)?;
        if encode_hex(&sha256(&raw)) != package.transaction_sha256 {
            return Err(LiquidProviderError::Invalid(
                "exit bytes differ from verify-before-fund",
            ));
        }
        let transaction = parse_liquid_transaction(&raw)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let prefix = request_prefix(&package.transaction_sha256)?;
        self.verify_unilateral_exit_signature(verified, &transaction, &prefix)
            .await?;
        let expected_transaction_id = encode_hex(&transaction.transaction_id);
        let admission = self
            .elementsd
            .require_mempool_acceptance_or_exact_known(
                &RpcRequestId::new(format!("{prefix}:exit-check"))?,
                &RpcRequestId::new(format!("{prefix}:exit-known"))?,
                &raw,
            )
            .await?;
        let observed = match admission {
            ElementsdMempoolAdmission::New => {
                self.elementsd
                    .broadcast(&RpcRequestId::new(format!("{prefix}:exit"))?, &raw)
                    .await?
            }
            ElementsdMempoolAdmission::ExactKnown => expected_transaction_id.clone(),
        };
        if observed != expected_transaction_id {
            return Err(LiquidProviderError::Invalid(
                "elementsd returned another exit transaction ID",
            ));
        }
        Ok(LiquidBroadcastReceipt {
            transaction_id: observed,
        })
    }

    async fn verify_unilateral_exit_signature(
        &self,
        verified: &VerifiedProviderLiquid,
        transaction: &LiquidTransaction,
        request_prefix: &str,
    ) -> Result<(), LiquidProviderError> {
        let package = &verified.request.exit_package;
        if package.mode != LiquidExitMode::Presigned
            || package.wallet_signing_handle_sha256.is_some()
            || package.preimage_recovery_ref.is_some()
        {
            return Err(LiquidProviderError::Invalid(
                "unilateral exit is not a pre-signed transaction",
            ));
        }
        let input_index = usize::try_from(package.spend_input_index).map_err(|_| {
            LiquidProviderError::Invalid("unilateral exit input index exceeds usize")
        })?;
        let input = transaction
            .inputs
            .get(input_index)
            .ok_or(LiquidProviderError::Invalid(
                "unilateral exit input is absent",
            ))?;
        let script = decode_hex(&package.script)?;
        let control_block = decode_hex(&package.control_block)?;
        let leaf = parse_swap_leaf_script(&script)
            .map_err(|_| LiquidProviderError::Invalid("unilateral exit leaf is invalid"))?;
        let (signature, extra_witness) =
            input
                .script_witness
                .split_first()
                .ok_or(LiquidProviderError::Invalid(
                    "unilateral exit witness is absent",
                ))?;
        let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
            LiquidProviderError::Invalid("unilateral exit signature is not SIGHASH_DEFAULT")
        })?;
        let expected_tail = match (&package.path[..], leaf.condition) {
            ("claim", SwapLeafCondition::Hashlock(payment_hash)) => {
                let [preimage, witnessed_script, witnessed_control_block] = extra_witness else {
                    return Err(LiquidProviderError::Invalid(
                        "Liquid claim witness has the wrong shape",
                    ));
                };
                if sha256(preimage) != payment_hash {
                    return Err(LiquidProviderError::Invalid(
                        "Liquid claim witness has another preimage",
                    ));
                }
                (witnessed_script, witnessed_control_block)
            }
            ("refund", SwapLeafCondition::Cltv(_) | SwapLeafCondition::Csv(_)) => {
                let [witnessed_script, witnessed_control_block] = extra_witness else {
                    return Err(LiquidProviderError::Invalid(
                        "Liquid refund witness has the wrong shape",
                    ));
                };
                (witnessed_script, witnessed_control_block)
            }
            _ => {
                return Err(LiquidProviderError::Invalid(
                    "Liquid exit path and witness leaf differ",
                ));
            }
        };
        if expected_tail.0 != &script || expected_tail.1 != &control_block {
            return Err(LiquidProviderError::Invalid(
                "Liquid exit witness differs from its committed script path",
            ));
        }
        let genesis_hash = self
            .elementsd
            .genesis_hash(&RpcRequestId::new(format!(
                "{request_prefix}:exit-genesis"
            ))?)
            .await?;
        let genesis_hash = LiquidGenesisHash::parse_display(&genesis_hash)
            .map_err(|error| LiquidProviderError::Client(error.into()))?;
        let funding_script_pubkey = decode_hex(&package.funding_script_pubkey)?;
        let prevouts = [LiquidPrevout {
            asset: ConfidentialAsset::Explicit(self.elementsd.expected_pegged_asset()),
            value: ConfidentialValue::Explicit(verified.verified.amount_sat),
            script_pubkey: funding_script_pubkey,
        }];
        let sighash = liquid_taproot_script_spend_sighash(
            transaction,
            &prevouts,
            input_index,
            genesis_hash,
            &script,
            &control_block,
            None,
        )
        .map_err(|error| LiquidProviderError::Client(error.into()))?;
        verify_liquid_taproot_sighash_signature(sighash, &signature, leaf.signing_key)
            .map_err(|error| LiquidProviderError::Client(error.into()))
    }
}

#[allow(clippy::too_many_arguments)]
fn serialize_explicit_exit(
    funding_transaction_id: [u8; 32],
    funding_output_index: u32,
    asset: immortal_core::liquid::LiquidAssetId,
    output_amount_sat: u64,
    destination_script_pubkey: &[u8],
    fee_amount_sat: u64,
    lock_time: u32,
    sequence: u32,
    signature: Option<&[u8; 64]>,
    preimage: Option<&[u8; 32]>,
    script: &[u8],
    control_block: &[u8],
) -> Result<Vec<u8>, LiquidProviderError> {
    if funding_output_index >= 1 << 30
        || destination_script_pubkey.len() > 10_000
        || script.len() > 10_000
        || control_block.len() > 4_129
    {
        return Err(LiquidProviderError::Invalid(
            "Liquid exit exceeds a consensus serialization bound",
        ));
    }
    let mut raw = Vec::new();
    raw.extend_from_slice(&2_i32.to_le_bytes());
    raw.push(1);
    write_compact_size(1, &mut raw)?;
    let mut wire_transaction_id = funding_transaction_id;
    wire_transaction_id.reverse();
    raw.extend_from_slice(&wire_transaction_id);
    raw.extend_from_slice(&funding_output_index.to_le_bytes());
    write_var_bytes(&[], &mut raw)?;
    raw.extend_from_slice(&sequence.to_le_bytes());
    write_compact_size(2, &mut raw)?;
    write_explicit_output(
        asset,
        output_amount_sat,
        destination_script_pubkey,
        &mut raw,
    )?;
    write_explicit_output(asset, fee_amount_sat, &[], &mut raw)?;
    raw.extend_from_slice(&lock_time.to_le_bytes());
    write_var_bytes(&[], &mut raw)?;
    write_var_bytes(&[], &mut raw)?;
    if let Some(signature) = signature {
        write_compact_size(if preimage.is_some() { 4 } else { 3 }, &mut raw)?;
        write_var_bytes(signature, &mut raw)?;
        if let Some(preimage) = preimage {
            write_var_bytes(preimage, &mut raw)?;
        }
        write_var_bytes(script, &mut raw)?;
        write_var_bytes(control_block, &mut raw)?;
    } else {
        if preimage.is_some() {
            return Err(LiquidProviderError::Invalid(
                "unsigned Liquid exit cannot contain a preimage",
            ));
        }
        write_compact_size(0, &mut raw)?;
    }
    write_compact_size(0, &mut raw)?;
    for _ in 0..2 {
        write_var_bytes(&[], &mut raw)?;
        write_var_bytes(&[], &mut raw)?;
    }
    Ok(raw)
}

fn write_explicit_output(
    asset: immortal_core::liquid::LiquidAssetId,
    amount_sat: u64,
    script_pubkey: &[u8],
    raw: &mut Vec<u8>,
) -> Result<(), LiquidProviderError> {
    raw.push(1);
    let mut wire_asset = asset.display_bytes();
    wire_asset.reverse();
    raw.extend_from_slice(&wire_asset);
    raw.push(1);
    raw.extend_from_slice(&amount_sat.to_be_bytes());
    raw.push(0);
    write_var_bytes(script_pubkey, raw)
}

fn write_var_bytes(bytes: &[u8], raw: &mut Vec<u8>) -> Result<(), LiquidProviderError> {
    write_compact_size(bytes.len(), raw)?;
    raw.extend_from_slice(bytes);
    Ok(())
}

fn write_compact_size(value: usize, raw: &mut Vec<u8>) -> Result<(), LiquidProviderError> {
    if value < 0xfd {
        raw.push(
            u8::try_from(value)
                .map_err(|_| LiquidProviderError::Invalid("compact size exceeds u8"))?,
        );
    } else if value <= usize::from(u16::MAX) {
        raw.push(0xfd);
        raw.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| LiquidProviderError::Invalid("compact size exceeds u16"))?
                .to_le_bytes(),
        );
    } else if value <= u32::MAX as usize {
        raw.push(0xfe);
        raw.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| LiquidProviderError::Invalid("compact size exceeds u32"))?
                .to_le_bytes(),
        );
    } else {
        return Err(LiquidProviderError::Invalid(
            "compact size exceeds the provider bound",
        ));
    }
    Ok(())
}

fn json_result(transaction_id: &str, disposition: &str) -> serde_json::Value {
    serde_json::json!({
        "disposition":disposition,
        "transaction_id":transaction_id,
    })
}

fn request_prefix(transaction_sha256: &str) -> Result<String, LiquidProviderError> {
    let short = transaction_sha256
        .get(..16)
        .ok_or(LiquidProviderError::Invalid("transaction digest is short"))?;
    if !short
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LiquidProviderError::Invalid(
            "transaction digest is not lowercase hex",
        ));
    }
    Ok(format!("liquid:{short}"))
}

fn parse_positive_decimal(value: &str, detail: &'static str) -> Result<u64, LiquidProviderError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LiquidProviderError::Invalid(detail));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(LiquidProviderError::Invalid(detail))
}

fn decode_hex_32(value: &str, detail: &'static str) -> Result<[u8; 32], LiquidProviderError> {
    let bytes = decode_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| LiquidProviderError::Invalid(detail))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, LiquidProviderError> {
    if value.is_empty()
        || value.len() > 8_000_000
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LiquidProviderError::Invalid(
            "transaction is not bounded lowercase hex",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = nibble(pair[0]).ok_or(LiquidProviderError::Invalid("transaction hex"))?;
        let low = nibble(pair[1]).ok_or(LiquidProviderError::Invalid("transaction hex"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
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
