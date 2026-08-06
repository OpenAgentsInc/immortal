use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::liquid::{
    LiquidBeforeFundRequest, LiquidConfidentiality, LiquidFundingVerificationInput,
    LiquidLegPurpose, LiquidSwapType,
};
use immortal_client::mkt_swp_client::{
    Cancellation, CloseOutcome, CooperativePrevout, CooperativeSigningAction,
    CooperativeSigningContext, CooperativeSigningMessage, ExitPackage, MktSigningRequest,
    ParticipantRole, StatusState,
    provider_support::{
        build_provider_submarine_claim_exit_package, canonical_json, cooperative_signing_message,
        effect_id, validate_provider_submarine_claim_exit_package,
    },
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND,
        MKT_STATUS_KIND, MKT_SWP_SWAP_CONTRACT_KIND,
    },
    liquid::{
        ConfidentialAsset, ConfidentialValue, LiquidAssetId, LiquidPrevout, LiquidTransaction,
        liquid_taproot_script_spend_sighash, parse_liquid_transaction,
        verify_liquid_taproot_sighash_signature,
    },
    market::MarketSigner,
    mkt_swp_verify::{
        SwapLeafCondition, Transaction, TransactionOutput, musig2_taproot_tweak,
        parse_swap_leaf_script, sha256, taproot_key_spend_sighash, validate_taproot_claim_witness,
    },
};
use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Map, Value, json};
use tokio::runtime::Handle;

use crate::{
    ProviderEffectReceipt, ProviderEffectRequest, ProviderSession, ReservationConfirmation,
    ReservationRequest,
    bitcoind::{BitcoindClient, BitcoindError, ChainTip, RpcRequestId},
    cln::Millisatoshi,
    config::ZeroConfConfig,
    cooperative::ProviderCooperativeActor,
    elementsd::ElementsdWalletUtxo,
    funding::{FundingInput, FundingRequest, SignedFundingTransaction, build_funding_transaction},
    lightning::{LightningPreimage, LightningRail},
    liquid::{
        LiquidEffectOperation, LiquidFundingObservation, LiquidProviderRail,
        ProviderLiquidExitRequest,
    },
    liquidity::{WalletScanPolicy, discover_wallet_utxos},
    pricing::{
        CapacityBounds, DerivedQuote, FeerateObservation, LIQUID_CLAIM_VBYTES,
        LIQUID_REFUND_VBYTES, LIQUID_SINGLE_INPUT_FUNDING_VBYTES, PricingConfig, QuoteRequest,
        QuoteSide, SwapType as PricingSwapType, bitcoin_to_liquid_chain_quote_vbytes,
        claim_spend_vbytes, derive_quote_with_worst_case_vbytes, feerate_for_quote,
        funding_feerate_from_priced_vbytes, liquid_reverse_quote_vbytes,
        liquid_submarine_quote_vbytes, liquid_to_bitcoin_chain_quote_vbytes, lockup_vbytes,
        refund_spend_vbytes, worst_case_redeem_vbytes,
    },
    quote::{
        BuiltFundedQuote, FundedQuotePolicy, QuoteWalletAllocation, ReplacementPolicy,
        build_funded_chain_quote, build_funded_quote,
    },
    relay_actor::{
        DurableRecovery, ProviderMode, QuoteConstructionError, QuoteDisposition, RecordOrigin,
        has_kind_by_author, session_id, stalled_session_disposition, tag_value,
    },
    settlement::{
        ClaimPreimage, CooperativeSettlementTemplate, SettlementBridge, SettlementTemplate,
    },
    store::{
        HardReservationRequest, OutPoint, ProviderStore, PublicEffectRequest, PublicEffectResult,
        PublicExitPackage, ReservationOutcome, StoredUtxo, UtxoObservation, WatchJob,
        WatchJobRequest,
    },
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
    watchtower::{BroadcastWatchPayload, ClaimReleaseEvidence},
};

const PROVIDER_ID: &str = "immortal-funded";
const OFFERING_ID: &str = "immortal-funded-btc-lightning";
const SETTLEMENT_MAXIMUM_WEIGHT: u64 = 1_600;
const DUST_RELAY_FEE_SAT_PER_KILOBYTE: u64 = 3_000;
const HOLD_INVOICE_CLTV_EXPIRY: u32 = 80;
pub(crate) const MAXIMUM_WATCH_ATTEMPTS: u16 = 32;
pub(crate) const QUOTE_RAIL_SYNC_ATTEMPTS: usize = 40;
pub(crate) const QUOTE_RAIL_SYNC_DELAY: Duration = Duration::from_millis(250);

pub(crate) struct FundedMode {
    handle: Handle,
    store: ProviderStore,
    wallet: ProviderWallet,
    bitcoind: BitcoindClient,
    lightning: Arc<dyn LightningRail>,
    liquid: Option<LiquidProviderRail>,
    network: BitcoinNetwork,
    network_id: String,
    minimum_confirmations: u32,
    reorg_safety_blocks: u32,
    pricing: PricingConfig,
    lab_forces_fallback_feerate: bool,
    hold_invoice_expiry_seconds: u32,
    cooperative_signing: bool,
    zero_conf: Option<ZeroConfConfig>,
    session_invoices: BTreeMap<String, String>,
    reserved_inputs: BTreeMap<String, Vec<FundingInput>>,
    reserved_liquid_inputs: BTreeMap<String, Vec<ElementsdWalletUtxo>>,
    cooperative_actors: BTreeMap<String, FundedCooperativeSession>,
    cooperative_restart_aborts: BTreeMap<String, CooperativeRestartAbort>,
}

pub(crate) struct FundedModePolicy {
    pub network: BitcoinNetwork,
    pub cooperative_signing: bool,
    pub minimum_confirmations: u32,
    pub reorg_safety_blocks: u32,
    pub pricing: PricingConfig,
    pub lab_forces_fallback_feerate: bool,
    pub hold_invoice_expiry_seconds: u32,
    pub zero_conf: Option<ZeroConfConfig>,
}

fn derive_quote_with_capacity_disposition(
    pricing: &PricingConfig,
    feerate: &FeerateObservation,
    available: &CapacityBounds,
    total_capacity: u64,
    request: &QuoteRequest,
    created_at: u64,
    worst_case_vbytes: u64,
) -> Result<DerivedQuote, QuoteConstructionError> {
    match derive_quote_with_worst_case_vbytes(
        pricing,
        feerate,
        available,
        request,
        created_at,
        worst_case_vbytes,
    ) {
        Ok(quote) => Ok(quote),
        Err(error) => {
            if available.available_capacity != total_capacity.to_string() {
                let total = CapacityBounds {
                    capacity_bucket_id: available.capacity_bucket_id.clone(),
                    available_capacity: total_capacity.to_string(),
                };
                if derive_quote_with_worst_case_vbytes(
                    pricing,
                    feerate,
                    &total,
                    request,
                    created_at,
                    worst_case_vbytes,
                )
                .is_ok()
                {
                    return Err(QuoteConstructionError::reservation_overallocated(
                        error.to_string(),
                    ));
                }
            }
            Err(QuoteConstructionError::rejected(error.to_string()))
        }
    }
}

fn quote_feerate(
    pricing: &PricingConfig,
    lab_forces_fallback: bool,
    live: Option<u64>,
) -> Result<FeerateObservation, String> {
    let live = (!lab_forces_fallback)
        .then_some(live)
        .flatten()
        .map(|sat_per_vb| (sat_per_vb, "bitcoind-estimatesmartfee-2"));
    feerate_for_quote(pricing, live).map_err(|error| error.to_string())
}

#[derive(Clone)]
struct ChainTerms {
    rail: ChainRailKind,
    asset_id: String,
    network_id: String,
    amount_sat: u64,
    script_pubkey: Vec<u8>,
    claim_script: Vec<u8>,
    claim_control_block: Vec<u8>,
    refund_script: Vec<u8>,
    refund_control_block: Vec<u8>,
    taproot_internal_key: String,
    taproot_merkle_root: String,
    payment_hash: String,
    refund_height: u32,
    fee_rate_sat_per_vbyte: u64,
    lightning_fee_budget_sat: u64,
    lightning_amount_sat: u64,
    fund_last: Option<u32>,
    claim_last: Option<u32>,
    lock_last: Option<u32>,
    hold_expiry_height: Option<u32>,
    lightning_settlement_blocks: u32,
    broadcast_safety_blocks: u32,
    chain_current_height: Option<u32>,
    lightning_current_height: Option<u32>,
    height_observed_at: Option<u64>,
    height_observation_max_age_seconds: Option<u32>,
    chain_block_interval_seconds: Option<u64>,
    lightning_block_interval_seconds: Option<u64>,
    cross_domain_safety_seconds: Option<u64>,
    provider_refund_expected_at: Option<u64>,
    hold_expiry_expected_at: Option<u64>,
    committed_funding_transaction: Option<String>,
    committed_funding_sha256: String,
    output_index: u32,
    zero_confirmation: bool,
    desired_completion_time: u64,
}

struct ChainSwapTerms {
    source: ChainTerms,
    destination: ChainTerms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainRailKind {
    Bitcoin,
    Liquid,
}

#[derive(Debug, Clone)]
struct LiquidChainObservation {
    transaction_id: String,
    transaction_sha256: String,
    output_index: u32,
    confirmations: u32,
    block_hash: Option<String>,
    unspent: bool,
}

enum RailChainObservation {
    Bitcoin(ChainObservation),
    Liquid(LiquidChainObservation),
}

enum ZeroConfCheck {
    Accepted(ChainObservation),
    Final(ChainObservation),
    Downgrade {
        reason: &'static str,
        replacement_txid: Option<String>,
    },
}

impl RailChainObservation {
    fn confirmations(&self) -> u32 {
        match self {
            Self::Bitcoin(observation) => observation.confirmations,
            Self::Liquid(observation) => observation.confirmations,
        }
    }

    fn transaction_id(&self) -> &str {
        match self {
            Self::Bitcoin(observation) => &observation.transaction_id,
            Self::Liquid(observation) => &observation.transaction_id,
        }
    }

    fn output_index(&self) -> u32 {
        match self {
            Self::Bitcoin(observation) => observation.output_index,
            Self::Liquid(observation) => observation.output_index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldHtlcSummary {
    state: String,
    htlc_count: usize,
    total_msat: u64,
    minimum_cltv_expiry: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CooperativeProviderStep {
    Wait,
    NonceCommitment,
    PublicNonce,
    PartialSignature,
    FinalSignature,
    Aborted,
}

#[derive(Debug, Clone, Copy, Default)]
struct CooperativeTranscriptPresence {
    provider_commitment: bool,
    requester_commitment: bool,
    provider_public_nonce: bool,
    requester_public_nonce: bool,
    provider_partial_signature: bool,
    requester_partial_signature: bool,
    provider_final_signature: bool,
    provider_aborted: bool,
    requester_aborted: bool,
}

fn cooperative_provider_step(presence: CooperativeTranscriptPresence) -> CooperativeProviderStep {
    if presence.provider_final_signature || presence.provider_aborted {
        CooperativeProviderStep::Wait
    } else if presence.requester_aborted {
        CooperativeProviderStep::Aborted
    } else if presence.provider_partial_signature {
        if presence.requester_partial_signature {
            CooperativeProviderStep::FinalSignature
        } else {
            CooperativeProviderStep::Wait
        }
    } else if presence.provider_public_nonce {
        if presence.requester_public_nonce {
            CooperativeProviderStep::PartialSignature
        } else {
            CooperativeProviderStep::Wait
        }
    } else if presence.provider_commitment {
        if presence.requester_commitment {
            CooperativeProviderStep::PublicNonce
        } else {
            CooperativeProviderStep::Wait
        }
    } else {
        CooperativeProviderStep::NonceCommitment
    }
}

impl HeldHtlcSummary {
    fn public_artifact(&self, payment_hash: &str) -> Value {
        json!({
            "payment_hash":payment_hash,
            "state":self.state,
            "htlc_count":self.htlc_count,
            "total_msat":self.total_msat,
            "minimum_cltv_expiry":self.minimum_cltv_expiry,
        })
    }
}

enum ReverseHoldSafetyError {
    Invalid(&'static str),
    Unavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoldStateDecision {
    Wait,
    Verify,
    Cancel(&'static str),
    Unresolved(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReverseInvoiceCancellationAction {
    CancelRemotely,
    CompleteLocally,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReverseSpendDecision {
    Wait,
    ProviderRefund,
    SettleClaimAndRetireRefundWatch,
}

impl ReverseSpendDecision {
    fn refund_watch_completion_reason(self) -> Option<&'static str> {
        match self {
            Self::SettleClaimAndRetireRefundWatch => Some("claim_settled"),
            Self::Wait | Self::ProviderRefund => None,
        }
    }
}

struct ChainObservation {
    transaction: Transaction,
    transaction_id: String,
    output_index: u32,
    confirmations: u32,
    block_hash: Option<String>,
}

struct FundedCooperativeSession {
    actor: ProviderCooperativeActor,
    package: ExitPackage,
    context: CooperativeSigningContext,
    signing_request_sha256: String,
    claim_request_sha256: String,
}

struct CooperativeRestartAbort {
    package: ExitPackage,
    context: CooperativeSigningContext,
}

struct PreparedCooperativeSession {
    package: ExitPackage,
    context: CooperativeSigningContext,
    template: CooperativeSettlementTemplate,
}

struct PersistedCooperativeEffects {
    signing_request_sha256: String,
    claim_request_sha256: String,
}

struct FinalizedCooperative<'a> {
    context: &'a CooperativeSigningContext,
    package: &'a ExitPackage,
    signing_request_sha256: &'a str,
    claim_request_sha256: &'a str,
    final_status_id: &'a str,
    transaction: Vec<u8>,
    observed_at: u64,
}

impl FundedMode {
    pub(crate) fn new(
        handle: Handle,
        store: ProviderStore,
        wallet: ProviderWallet,
        bitcoind: BitcoindClient,
        lightning: Arc<dyn LightningRail>,
        liquid: Option<LiquidProviderRail>,
        policy: FundedModePolicy,
    ) -> Self {
        Self {
            handle,
            store,
            wallet,
            bitcoind,
            lightning,
            liquid,
            network: policy.network,
            network_id: network_id(policy.network).to_owned(),
            minimum_confirmations: policy.minimum_confirmations,
            reorg_safety_blocks: policy.reorg_safety_blocks,
            pricing: policy.pricing,
            lab_forces_fallback_feerate: policy.lab_forces_fallback_feerate,
            hold_invoice_expiry_seconds: policy.hold_invoice_expiry_seconds,
            cooperative_signing: policy.cooperative_signing,
            zero_conf: policy.zero_conf,
            session_invoices: BTreeMap::new(),
            reserved_inputs: BTreeMap::new(),
            reserved_liquid_inputs: BTreeMap::new(),
            cooperative_actors: BTreeMap::new(),
            cooperative_restart_aborts: BTreeMap::new(),
        }
    }

    fn quote(
        &mut self,
        rfq: &Event,
        created_at: u64,
    ) -> Result<Option<BuiltFundedQuote>, QuoteConstructionError> {
        let swap_type_name = rfq_swap_type(rfq)?;
        let swap_type = match swap_type_name.as_str() {
            "submarine" => PricingSwapType::Submarine,
            "reverse" => PricingSwapType::Reverse,
            "chain" => PricingSwapType::Chain,
            _ => {
                return Err("funded mode received an unsupported swap type"
                    .to_owned()
                    .into());
            }
        };
        if swap_type == PricingSwapType::Chain {
            let asset_pair = rfq_asset_pair(rfq)?;
            let zero_confirmation = self.zero_conf.is_some_and(|policy| {
                policy.chain && asset_pair[0] == format!("swp:1:{}:btc:chain", self.network_id)
            });
            let bitcoin_tip = self
                .handle
                .block_on(
                    self.bitcoind
                        .chain_tip(&rpc_id("quote-chain-bitcoin-tip", session_id(rfq)?)?),
                )
                .map_err(|error| format!("could not read Bitcoin chain tip for Quote: {error}"))?;
            let liquid = self
                .liquid
                .as_ref()
                .ok_or_else(|| "chain RFQ reached a disabled Liquid rail".to_owned())?;
            let view = self
                .handle
                .block_on(
                    liquid.network_view(&format!("quote-chain-liquid:{}", &session_id(rfq)?[..16])),
                )
                .map_err(|error| format!("could not read Liquid tip for Quote: {error}"))?;
            let liquid_tip = ChainTip {
                hash: view.best_block_hash,
                height: view.height,
            };
            let pricing = self.derive_pricing(rfq, swap_type, created_at)?;
            let zero_confirmation =
                zero_confirmation && self.zero_conf_amount_allowed(&pricing.input_amount)?;
            let quote = build_funded_chain_quote(
                rfq,
                &self.wallet,
                quote_allocation(session_id(rfq)?)?,
                &bitcoin_tip,
                &liquid_tip,
                self.quote_policy(&pricing, 0, zero_confirmation)?,
                created_at,
            )
            .map_err(|error| error.to_string())?;
            require_derived_pricing_terms(&quote, &pricing)?;
            return Ok(Some(quote));
        }
        let Some((bitcoin_tip, lightning_current_height)) =
            self.synchronized_quote_heights(session_id(rfq)?)?
        else {
            return Ok(None);
        };
        let asset_pair = rfq_asset_pair(rfq)?;
        let liquid_pair = self.liquid.as_ref().is_some_and(|liquid| {
            asset_pair
                .iter()
                .any(|asset| asset == &liquid.mkt_asset_id())
        });
        let chain_tip = if liquid_pair {
            let liquid = self
                .liquid
                .as_ref()
                .ok_or_else(|| "Liquid RFQ reached a disabled rail".to_owned())?;
            let view = self
                .handle
                .block_on(liquid.network_view(&format!("quote-liquid:{}", &session_id(rfq)?[..16])))
                .map_err(|error| format!("could not read Liquid tip for Quote: {error}"))?;
            ChainTip {
                hash: view.best_block_hash,
                height: view.height,
            }
        } else {
            bitcoin_tip
        };
        let pricing = self.derive_pricing(rfq, swap_type, created_at)?;
        let zero_conf_amount_allowed = self.zero_conf_amount_allowed(&pricing.input_amount)?;
        let invoice = if swap_type == PricingSwapType::Submarine {
            rfq_invoice(rfq)?
        } else {
            self.reverse_hold_invoice(rfq)?
        };
        let allocation = quote_allocation(session_id(rfq)?)?;
        let quote = build_funded_quote(
            rfq,
            &invoice,
            &self.wallet,
            allocation,
            &chain_tip,
            self.quote_policy(
                &pricing,
                lightning_current_height,
                swap_type == PricingSwapType::Submarine
                    && !liquid_pair
                    && zero_conf_amount_allowed
                    && self.zero_conf.is_some_and(|policy| policy.submarine),
            )?,
            created_at,
        )
        .map_err(|error| error.to_string())?;
        require_derived_pricing_terms(&quote, &pricing)?;
        Ok(Some(quote))
    }

    fn zero_conf_amount_allowed(&self, amount: &str) -> Result<bool, String> {
        let amount = canonical_u64(amount)?;
        Ok(self
            .zero_conf
            .is_some_and(|policy| amount <= policy.max_swap_sat))
    }

    fn quote_policy<'a>(
        &'a self,
        pricing: &DerivedQuote,
        lightning_current_height: u32,
        zero_confirmation: bool,
    ) -> Result<FundedQuotePolicy<'a>, String> {
        Ok(FundedQuotePolicy {
            network_id: &self.network_id,
            liquid: self
                .liquid
                .as_ref()
                .map(|liquid| crate::quote::LiquidQuotePolicy {
                    network_id: liquid.network_id(),
                    pegged_asset: liquid.pegged_asset(),
                }),
            cooperative_signing: self.cooperative_signing,
            lightning_current_height,
            fee_bps: u16::try_from(canonical_u64(&pricing.fee_bps)?)
                .map_err(|_| "derived spread exceeds the funded Quote range".to_owned())?,
            miner_fee_budget_sat: canonical_u64(&pricing.miner_fee_budget)?,
            lightning_routing_fee_budget_sat: canonical_u64(&pricing.lightning_routing_fee_budget)?,
            minimum_confirmations: self.minimum_confirmations,
            reorg_safety_blocks: self.reorg_safety_blocks,
            zero_confirmation,
            rbf: ReplacementPolicy::Reject,
            replacement: if zero_confirmation {
                ReplacementPolicy::Track
            } else {
                ReplacementPolicy::Reject
            },
            quote_validity_seconds: self.pricing.quote_expiry_seconds,
            funding_window_blocks: 12,
            broadcast_safety_blocks: 2,
            lightning_settlement_blocks: 18,
            expected_block_seconds: 600,
            clock_skew_seconds: 60,
            recovery_target_blocks: 2,
        })
    }

    fn derive_pricing(
        &self,
        rfq: &Event,
        swap_type: PricingSwapType,
        created_at: u64,
    ) -> Result<DerivedQuote, QuoteConstructionError> {
        let session = session_id(rfq)?;
        let live = if self.lab_forces_fallback_feerate {
            None
        } else {
            self.handle
                .block_on(
                    self.bitcoind
                        .estimated_feerate_sat_per_vbyte(&rpc_id("quote-feerate", session)?, 2),
                )
                .map_err(|error| format!("could not estimate the Quote feerate: {error}"))?
        };
        let feerate = quote_feerate(&self.pricing, self.lab_forces_fallback_feerate, live)?;
        let profile = record_profile(rfq)?;
        let constraints = profile
            .get("constraints")
            .and_then(Value::as_object)
            .ok_or_else(|| "funded RFQ has no constraints".to_owned())?;
        let amount = required_string(constraints, "input_amount")?.to_owned();
        let (capacity, total_capacity) =
            self.quote_capacity(rfq, session, swap_type, created_at)?;
        let request = QuoteRequest {
            swap_type,
            side: QuoteSide::Input,
            amount,
        };
        let worst_case_vbytes = quote_priced_vbytes(
            swap_type,
            &rfq_asset_pair(rfq)?,
            &self.network_id,
            self.liquid.as_ref(),
        )?;
        derive_quote_with_capacity_disposition(
            &self.pricing,
            &feerate,
            &capacity,
            total_capacity,
            &request,
            created_at,
            worst_case_vbytes,
        )
    }

    fn quote_capacity(
        &self,
        rfq: &Event,
        session_id: &str,
        swap_type: PricingSwapType,
        observed_at: u64,
    ) -> Result<(CapacityBounds, u64), String> {
        let asset_pair = rfq_asset_pair(rfq)?;
        let reserved_asset = match swap_type {
            PricingSwapType::Submarine => asset_pair[1].clone(),
            PricingSwapType::Reverse | PricingSwapType::Chain => asset_pair[1].clone(),
        };
        let liquid_asset = self.liquid.as_ref().map(LiquidProviderRail::mkt_asset_id);
        let (bucket_id, asset_id, total_capacity) = match swap_type {
            PricingSwapType::Submarine => (
                "lightning-outbound".to_owned(),
                reserved_asset,
                self.lightning_capacity_for_session(session_id)?,
            ),
            PricingSwapType::Reverse | PricingSwapType::Chain
                if liquid_asset.as_deref() == Some(reserved_asset.as_str()) =>
            {
                let liquid = self
                    .liquid
                    .as_ref()
                    .ok_or_else(|| "Liquid capacity requested while disabled".to_owned())?;
                let capacity = self
                    .handle
                    .block_on(liquid.confirmed_capacity(
                        &rpc_id("quote-liquid-wallet", session_id)?,
                        self.minimum_confirmations,
                        64,
                    ))
                    .map_err(|error| format!("could not price Liquid liquidity: {error}"))?;
                for utxo in &capacity.utxos {
                    self.handle
                        .block_on(self.store.observe_utxo(&UtxoObservation {
                            outpoint: OutPoint {
                                txid: utxo.transaction_id.clone(),
                                vout: utxo.output_index,
                            },
                            asset_id: reserved_asset.clone(),
                            amount: utxo.amount_sat,
                            script_pubkey: utxo.script_pubkey.clone(),
                            state: "available".to_owned(),
                            confirmations: utxo.confirmations,
                            block_hash: None,
                            replacement_txid: None,
                            observed_at,
                        }))
                        .map_err(|error| format!("could not retain Liquid capacity: {error}"))?;
                }
                let prefix = session_id
                    .get(..16)
                    .ok_or_else(|| "provider session ID is too short".to_owned())?;
                (
                    format!("liquid-{prefix}"),
                    reserved_asset,
                    capacity.total_sat,
                )
            }
            PricingSwapType::Reverse | PricingSwapType::Chain => {
                let asset_id = reserved_asset;
                let policy = WalletScanPolicy::new(
                    asset_id.clone(),
                    0,
                    0,
                    20,
                    self.minimum_confirmations,
                    64,
                )
                .map_err(|error| error.to_string())?;
                let liquidity = self
                    .handle
                    .block_on(discover_wallet_utxos(
                        &self.bitcoind,
                        &self.store,
                        &self.wallet,
                        &rpc_id("quote-wallet-scan", session_id)?,
                        &policy,
                        observed_at,
                    ))
                    .map_err(|error| format!("could not price provider liquidity: {error}"))?;
                let total_capacity = liquidity
                    .funding_inputs
                    .iter()
                    .try_fold(0_u64, |total, input| total.checked_add(input.value_sat))
                    .ok_or_else(|| "provider Quote capacity overflowed".to_owned())?;
                let prefix = session_id
                    .get(..16)
                    .ok_or_else(|| "provider session ID is too short".to_owned())?;
                (format!("btc-{prefix}"), asset_id, total_capacity)
            }
        };
        self.handle
            .block_on(self.store.configure_capacity_bucket(
                &bucket_id,
                &asset_id,
                total_capacity,
                observed_at,
            ))
            .map_err(|error| format!("could not configure Quote capacity: {error}"))?;
        let available_capacity = self
            .handle
            .block_on(self.store.available_capacity(&bucket_id))
            .map_err(|error| format!("could not read Quote capacity: {error}"))?;
        Ok((
            CapacityBounds {
                capacity_bucket_id: bucket_id,
                available_capacity: available_capacity.to_string(),
            },
            total_capacity,
        ))
    }

    fn synchronized_quote_heights(
        &self,
        session_id: &str,
    ) -> Result<Option<(ChainTip, u32)>, String> {
        let tip_request_id = rpc_id("quote-tip", session_id)?;
        let lightning_request_id = lightning_id("quote-height", session_id)?;
        for attempt in 0..QUOTE_RAIL_SYNC_ATTEMPTS {
            let chain_tip = match self
                .handle
                .block_on(self.bitcoind.chain_tip(&tip_request_id))
            {
                Ok(chain_tip) => chain_tip,
                Err(error) if transient_bitcoind_error(&error) => {
                    self.wait_for_quote_rail_retry(attempt);
                    continue;
                }
                Err(error) => {
                    return Err(format!("could not read chain tip for Quote: {error}"));
                }
            };
            let lightning_info = match self
                .handle
                .block_on(self.lightning.node_info(&lightning_request_id))
            {
                Ok(info) => info,
                Err(error) if error.is_transient() => {
                    self.wait_for_quote_rail_retry(attempt);
                    continue;
                }
                Err(error) => {
                    return Err(format!("could not read Lightning state for Quote: {error}"));
                }
            };
            if lightning_info.network != network_name(self.network) {
                return Err("Lightning network differs from provider configuration".to_owned());
            }
            let chain_height = u32::try_from(chain_tip.height)
                .map_err(|_| "bitcoind height exceeds the funded-v1 range".to_owned())?;
            if chain_height
                .checked_sub(lightning_info.block_height)
                .is_some_and(|lag| lag <= self.reorg_safety_blocks)
            {
                return Ok(Some((chain_tip, lightning_info.block_height)));
            }
            self.wait_for_quote_rail_retry(attempt);
        }
        eprintln!(
            "immortal-provider: deferring Quote until bitcoind and Lightning heights synchronize"
        );
        Ok(None)
    }

    fn wait_for_quote_rail_retry(&self, attempt: usize) {
        if attempt + 1 < QUOTE_RAIL_SYNC_ATTEMPTS {
            self.handle.block_on(async {
                tokio::time::sleep(QUOTE_RAIL_SYNC_DELAY).await;
            });
        }
    }

    fn reverse_hold_invoice(&mut self, rfq: &Event) -> Result<String, String> {
        let session = session_id(rfq)?;
        if let Some(invoice) = self.session_invoices.get(session) {
            return Ok(invoice.clone());
        }
        let profile = record_profile(rfq)?;
        let constraints = profile
            .get("constraints")
            .and_then(Value::as_object)
            .ok_or_else(|| "reverse RFQ has no constraints".to_owned())?;
        let payment_hash = constraints
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "reverse RFQ has no payment hash".to_owned())?;
        let amount_sat = canonical_u64(
            constraints
                .get("input_amount")
                .and_then(Value::as_str)
                .ok_or_else(|| "reverse RFQ has no input amount".to_owned())?,
        )?;
        let request_id = lightning_id("hold-invoice", session)?;
        let result = self.handle.block_on(
            self.lightning.hold_invoice(
                &request_id,
                payment_hash,
                Millisatoshi::from_satoshis(amount_sat)
                    .map_err(|error| format!("reverse amount is invalid: {error}"))?,
                self.hold_invoice_expiry_seconds,
                HOLD_INVOICE_CLTV_EXPIRY,
            ),
        );
        let invoice = match result {
            Ok(invoice) => invoice.bolt11,
            Err(_) => {
                let listed = self
                    .handle
                    .block_on(
                        self.lightning.hold_invoice_state(
                            &lightning_id("hold-recover", session)?,
                            payment_hash,
                        ),
                    )
                    .map_err(|error| format!("could not recover reverse hold invoice: {error}"))?;
                extract_hold_invoice(&listed, payment_hash)?
            }
        };
        self.session_invoices
            .insert(session.to_owned(), invoice.clone());
        Ok(invoice)
    }

    fn reserve(
        &mut self,
        request: &ProviderEffectRequest,
        quote_profile: Option<&Value>,
    ) -> Result<ReservationConfirmation, QuoteConstructionError> {
        let amount = canonical_u64(&request.reserved_amount)?;
        let now = unix_now()?;
        if now >= request.reservation_expires_at {
            return Err("reservation expired before capacity allocation"
                .to_owned()
                .into());
        }
        let (proof_class, selected_utxos, committed_capacity) = if self
            .liquid
            .as_ref()
            .is_some_and(|liquid| request.reserved_asset_id == liquid.mkt_asset_id())
        {
            let liquid = self
                .liquid
                .as_ref()
                .ok_or_else(|| "Liquid reservation reached a disabled rail".to_owned())?;
            let capacity = self
                .handle
                .block_on(liquid.confirmed_capacity(
                    &rpc_id("liquid-wallet-scan", &request.session_id)?,
                    self.minimum_confirmations,
                    64,
                ))
                .map_err(|error| format!("could not scan Liquid liquidity: {error}"))?;
            let miner_fee_budget_sat = quote_profile
                .and_then(|profile| profile.get("terms"))
                .and_then(Value::as_object)
                .and_then(|terms| terms.get("miner_fee_budget"))
                .and_then(Value::as_str)
                .ok_or_else(|| "Liquid reservation has no signed miner-fee budget".to_owned())
                .and_then(canonical_u64)?;
            let target = amount
                .checked_add(miner_fee_budget_sat)
                .ok_or_else(|| "Liquid capacity target overflowed".to_owned())?;
            let mut selected = None;
            for utxo in capacity.utxos {
                self.handle
                    .block_on(self.store.observe_utxo(&UtxoObservation {
                        outpoint: OutPoint {
                            txid: utxo.transaction_id.clone(),
                            vout: utxo.output_index,
                        },
                        asset_id: request.reserved_asset_id.clone(),
                        amount: utxo.amount_sat,
                        script_pubkey: utxo.script_pubkey.clone(),
                        state: "available".to_owned(),
                        confirmations: utxo.confirmations,
                        block_hash: None,
                        replacement_txid: None,
                        observed_at: now,
                    }))
                    .map_err(|error| format!("could not retain Liquid UTXO: {error}"))?;
                if selected.is_none() && utxo.amount_sat >= target {
                    selected = Some(utxo);
                }
            }
            let selected = selected.ok_or_else(|| {
                QuoteConstructionError::rejected(
                    "provider elementsd wallet has no single confirmed output covering amount and signed fee budget".to_owned(),
                )
            })?;
            let selected = vec![selected];
            let outpoints = selected
                .iter()
                .map(|utxo| OutPoint {
                    txid: utxo.transaction_id.clone(),
                    vout: utxo.output_index,
                })
                .collect();
            self.reserved_liquid_inputs
                .insert(request.session_id.clone(), selected);
            ("utxo_control", outpoints, capacity.total_sat)
        } else if request.reserved_asset_id.ends_with(":chain") {
            let policy = WalletScanPolicy::new(
                request.reserved_asset_id.clone(),
                0,
                0,
                20,
                self.minimum_confirmations,
                64,
            )
            .map_err(|error| error.to_string())?;
            let liquidity = self
                .handle
                .block_on(discover_wallet_utxos(
                    &self.bitcoind,
                    &self.store,
                    &self.wallet,
                    &rpc_id("wallet-scan", &request.session_id)?,
                    &policy,
                    now,
                ))
                .map_err(|error| format!("could not scan provider liquidity: {error}"))?;
            let target = amount
                .checked_add(2_000)
                .ok_or_else(|| "chain capacity target overflowed".to_owned())?;
            let mut selected = Vec::new();
            let mut selected_total = 0_u64;
            let total_capacity = liquidity
                .funding_inputs
                .iter()
                .try_fold(0_u64, |total, input| total.checked_add(input.value_sat))
                .ok_or_else(|| "chain capacity overflowed".to_owned())?;
            for input in liquidity.funding_inputs {
                if selected_total < target {
                    selected_total = selected_total
                        .checked_add(input.value_sat)
                        .ok_or_else(|| "selected chain capacity overflowed".to_owned())?;
                    selected.push(input);
                }
            }
            if selected_total < target {
                return Err("provider wallet has insufficient confirmed capacity"
                    .to_owned()
                    .into());
            }
            let outpoints = selected
                .iter()
                .map(|input| OutPoint {
                    txid: input.txid.clone(),
                    vout: input.vout,
                })
                .collect();
            self.reserved_inputs
                .insert(request.session_id.clone(), selected);
            ("utxo_control", outpoints, total_capacity)
        } else if request.reserved_asset_id.ends_with(":lightning") {
            (
                "lightning_liquidity",
                Vec::new(),
                self.lightning_capacity_for_session(&request.session_id)?,
            )
        } else {
            return Err("reservation asset is not a funded v1 rail"
                .to_owned()
                .into());
        };
        if committed_capacity < amount {
            return Err("provider rail has insufficient confirmed capacity"
                .to_owned()
                .into());
        }
        self.handle
            .block_on(self.store.configure_capacity_bucket(
                &request.capacity_bucket_id,
                &request.reserved_asset_id,
                committed_capacity,
                now,
            ))
            .map_err(|error| format!("could not configure capacity bucket: {error}"))?;

        let mut expected_sequence = 1_u64;
        let record = loop {
            let reservation = HardReservationRequest {
                reservation_id: request.reservation_id.clone(),
                effect_id: request.effect_id.clone(),
                session_id: request.session_id.clone(),
                bucket_id: request.capacity_bucket_id.clone(),
                asset_id: request.reserved_asset_id.clone(),
                amount,
                request_sha256: request.request_sha256.clone(),
                expected_allocation_sequence: expected_sequence,
                expires_at: request.reservation_expires_at,
                utxos: selected_utxos.clone(),
                created_at: now,
            };
            match self.handle.block_on(self.store.reserve(&reservation)) {
                Ok(ReservationOutcome::Reserved(record) | ReservationOutcome::Replay(record)) => {
                    break record;
                }
                Ok(ReservationOutcome::AllocationSequenceMismatch { current }) => {
                    expected_sequence = current
                        .checked_add(1)
                        .ok_or_else(|| "capacity allocation sequence overflowed".to_owned())?;
                }
                Ok(ReservationOutcome::InsufficientCapacity) => {
                    return Err(QuoteConstructionError::reservation_overallocated(
                        "capacity bucket is fully allocated".to_owned(),
                    ));
                }
                Ok(ReservationOutcome::UtxoUnavailable(_)) => {
                    return Err("selected chain capacity is no longer available"
                        .to_owned()
                        .into());
                }
                Err(error) => {
                    return Err(format!("capacity reservation failed: {error}").into());
                }
            }
        };
        let commitment =
            capacity_commitment(request, record.allocation_sequence, committed_capacity);
        Ok(ReservationConfirmation {
            reservation_id: request.reservation_id.clone(),
            capacity_bucket_id: request.capacity_bucket_id.clone(),
            reserved_asset_id: request.reserved_asset_id.clone(),
            reserved_amount: request.reserved_amount.clone(),
            committed_capacity: committed_capacity.to_string(),
            reservation_expires_at: request.reservation_expires_at,
            allocation_sequence: record.allocation_sequence.to_string(),
            proof_class: proof_class.to_owned(),
            proof_ref: format!("immortal-provider:{}", request.reservation_id),
            capacity_commitment_sha256: commitment,
        })
    }

    fn bind_reverse_funding_template(
        &self,
        session_id: &str,
        profile: Value,
    ) -> Result<Value, String> {
        let terms = profile
            .get("terms")
            .and_then(Value::as_object)
            .ok_or_else(|| "reverse Quote has no terms object".to_owned())?;
        let verifier = terms
            .get("verifier_inputs")
            .and_then(Value::as_array)
            .and_then(|verifiers| {
                verifiers.iter().find(|verifier| {
                    verifier.get("leg_id").and_then(Value::as_str) == Some("destination")
                })
            })
            .and_then(Value::as_object)
            .ok_or_else(|| "reverse Quote has no destination verifier".to_owned())?;
        let script_pubkey = decode_hex(required_string(verifier, "script_pubkey")?)?;
        let amount_sat = canonical_u64(required_string(verifier, "amount")?)?;
        let miner_fee_budget_sat = canonical_u64(required_string(terms, "miner_fee_budget")?)?;
        let funding_swap_type = funding_pricing_swap_type(terms)?;
        let priced_vbytes = contract_priced_vbytes(terms, funding_swap_type)?;
        let fee_rate_sat_per_vbyte =
            funding_feerate_from_priced_vbytes(priced_vbytes, miner_fee_budget_sat)
                .map_err(|error| error.to_string())?;
        let reservation_id = deterministic_id("reservation", session_id);
        if verifier.get("verifier_policy").and_then(Value::as_str) == Some("mkt-swp-liquid-v1") {
            let liquid = self
                .liquid
                .as_ref()
                .ok_or_else(|| "Liquid reverse Quote reached a disabled rail".to_owned())?;
            let inputs = match self.reserved_liquid_inputs.get(session_id) {
                Some(inputs) => inputs.clone(),
                None => self.recover_reserved_liquid_inputs(&reservation_id)?,
            };
            let maximum_funding_fee_sat =
                effect_fee_sat(LIQUID_SINGLE_INPUT_FUNDING_VBYTES, fee_rate_sat_per_vbyte)?;
            let funding = self
                .handle
                .block_on(liquid.create_signed_funding(
                    &format!("quote-funding:{}", &session_id[..16]),
                    &inputs,
                    &script_pubkey,
                    amount_sat,
                    fee_rate_sat_per_vbyte,
                    maximum_funding_fee_sat,
                ))
                .map_err(|error| format!("could not construct Liquid reverse funding: {error}"))?;
            return bind_liquid_funding_profile(profile, &funding);
        }
        let inputs = match self.reserved_inputs.get(session_id) {
            Some(inputs) => inputs.clone(),
            None => self.recover_reserved_inputs(session_id, &reservation_id)?,
        };
        let funding = self.build_reverse_funding(
            session_id,
            &inputs,
            script_pubkey,
            amount_sat,
            fee_rate_sat_per_vbyte,
        )?;
        bind_reverse_funding_profile(profile, &funding)
    }

    fn build_reverse_funding(
        &self,
        session_id: &str,
        inputs: &[FundingInput],
        destination_script_pubkey: Vec<u8>,
        amount_sat: u64,
        fee_rate_sat_per_vbyte: u64,
    ) -> Result<SignedFundingTransaction, String> {
        let maximum_funding_fee_sat = effect_fee_sat(lockup_vbytes(), fee_rate_sat_per_vbyte)?;
        let funding = build_funding_transaction(
            &self.wallet,
            inputs,
            &FundingRequest {
                destination_script_pubkey,
                amount_sat,
                fee_rate_sat_per_vbyte,
                change_path: funding_change_path(session_id)?,
                lock_time: 0,
            },
        )
        .map_err(|error| format!("could not construct reverse funding: {error}"))?;
        if funding.fee_sat > maximum_funding_fee_sat {
            return Err(
                "reverse funding transaction exceeds the signed miner-fee budget".to_owned(),
            );
        }
        Ok(funding)
    }

    fn lightning_capacity_for_session(&self, session_id: &str) -> Result<u64, String> {
        self.handle
            .block_on(
                self.lightning
                    .channel_capacity_sat(&lightning_id("capacity", session_id)?),
            )
            .map_err(|error| format!("could not inspect Lightning liquidity: {error}"))
    }

    fn observe_chain_funding(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
    ) -> Result<ChainObservation, String> {
        let response = self
            .handle
            .block_on(self.bitcoind.raw_transaction(
                &rpc_id("funding-observe", session_id)?,
                transaction_id,
                true,
            ))
            .map_err(|error| format!("could not observe swap funding: {error}"))?;
        chain_observation_from_response(&response, transaction_id, output_index, terms)
    }

    fn zero_conf_check(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
        required_confirmations: u32,
        inputs: &[OutPoint],
    ) -> Result<ZeroConfCheck, String> {
        let response = self.handle.block_on(self.bitcoind.raw_transaction(
            &rpc_id("zero-conf-transaction", session_id)?,
            transaction_id,
            true,
        ));
        let observation = match response {
            Ok(response) => {
                chain_observation_from_response(&response, transaction_id, output_index, terms)?
            }
            Err(BitcoindError::Rpc { code: -5 }) => {
                let (reason, replacement_txid) =
                    self.zero_conf_absence_reason(session_id, transaction_id, inputs, terms)?;
                return Ok(ZeroConfCheck::Downgrade {
                    reason,
                    replacement_txid,
                });
            }
            Err(error) => return Err(format!("could not recheck zero-conf funding: {error}")),
        };
        if observation.confirmations >= required_confirmations {
            return Ok(ZeroConfCheck::Final(observation));
        }
        let entry = match self.handle.block_on(
            self.bitcoind
                .mempool_entry(&rpc_id("zero-conf-mempool", session_id)?, transaction_id),
        ) {
            Ok(entry) => entry,
            Err(BitcoindError::Rpc { code: -5 }) => {
                let (reason, replacement_txid) =
                    self.zero_conf_absence_reason(session_id, transaction_id, inputs, terms)?;
                return Ok(ZeroConfCheck::Downgrade {
                    reason,
                    replacement_txid,
                });
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect zero-conf mempool entry: {error}"
                ));
            }
        };
        if let Err(error) = validate_zero_conf_mempool_entry(&entry) {
            let reason = match error.as_str() {
                "zero-conf funding is BIP125 replaceable" => "replacement",
                "zero-conf funding has an unconfirmed ancestor" => "ancestor_unconfirmed",
                _ => return Err(error),
            };
            return Ok(ZeroConfCheck::Downgrade {
                reason,
                replacement_txid: None,
            });
        }
        Ok(ZeroConfCheck::Accepted(observation))
    }

    fn zero_conf_absence_reason(
        &self,
        session_id: &str,
        transaction_id: &str,
        inputs: &[OutPoint],
        terms: &ChainTerms,
    ) -> Result<(&'static str, Option<String>), String> {
        if inputs.is_empty() || inputs.len() > 256 {
            return Err("zero-conf funding input proof is empty or unbounded".to_owned());
        }
        let request = inputs
            .iter()
            .map(|input| json!({"txid":input.txid,"vout":input.vout}))
            .collect::<Vec<_>>();
        let spenders = self
            .handle
            .block_on(self.bitcoind.call(
                &rpc_id("zero-conf-spenders", session_id)?,
                "gettxspendingprevout",
                json!([request]),
            ))
            .map_err(|error| format!("could not inspect zero-conf conflicting spends: {error}"))?;
        let spenders = spenders
            .as_array()
            .filter(|spenders| spenders.len() == inputs.len())
            .ok_or_else(|| "zero-conf conflicting-spend response is invalid".to_owned())?;
        for spender in spenders {
            let Some(spending_txid) = spender.get("spendingtxid").and_then(Value::as_str) else {
                continue;
            };
            required_hash(spending_txid, "zero-conf replacement transaction ID")?;
            if spending_txid == transaction_id {
                continue;
            }
            let response = self
                .handle
                .block_on(self.bitcoind.raw_transaction(
                    &rpc_id("zero-conf-competitor", session_id)?,
                    spending_txid,
                    true,
                ))
                .map_err(|error| format!("could not inspect zero-conf competitor: {error}"))?;
            let raw = response
                .get("hex")
                .and_then(Value::as_str)
                .ok_or_else(|| "zero-conf competitor has no raw transaction".to_owned())?;
            let competitor = Transaction::parse(&decode_hex(raw)?)
                .map_err(|error| format!("zero-conf competitor is invalid: {error}"))?;
            let reason = if competitor
                .inputs
                .iter()
                .any(|input| input.sequence < 0xffff_fffe)
            {
                "replacement"
            } else {
                "conflict"
            };
            return Ok((reason, Some(spending_txid.to_owned())));
        }
        for input in inputs {
            match self.handle.block_on(self.bitcoind.raw_transaction(
                &rpc_id("zero-conf-ancestor", session_id)?,
                &input.txid,
                true,
            )) {
                Ok(parent)
                    if parent
                        .get("confirmations")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        > 0 => {}
                Ok(_) | Err(BitcoindError::Rpc { code: -5 }) => {
                    return Ok(("ancestor_unconfirmed", None));
                }
                Err(error) => {
                    return Err(format!("could not inspect zero-conf ancestor: {error}"));
                }
            }
        }
        if terms.rail != ChainRailKind::Bitcoin {
            return Err("zero-conf recheck reached a non-Bitcoin rail".to_owned());
        }
        Ok(("mempool_missing", None))
    }

    fn observe_liquid_funding(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
    ) -> Result<LiquidChainObservation, String> {
        self.observe_liquid_funding_with_spend_state(
            session_id,
            transaction_id,
            output_index,
            terms,
            true,
        )
    }

    fn observe_liquid_funding_with_spend_state(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
        require_unspent: bool,
    ) -> Result<LiquidChainObservation, String> {
        if terms.rail != ChainRailKind::Liquid
            || terms.committed_funding_transaction.is_some() && output_index != terms.output_index
        {
            return Err("Liquid observation does not match the contracted leg".to_owned());
        }
        let liquid = self
            .liquid
            .as_ref()
            .ok_or_else(|| "Liquid observation reached a disabled rail".to_owned())?;
        if liquid.network_id() != terms.network_id || liquid.mkt_asset_id() != terms.asset_id {
            return Err("Liquid Contract differs from the configured network or asset".to_owned());
        }
        let observation = self
            .handle
            .block_on(liquid.observe_funding_output(
                &format!("funding-observe:{}", &session_id[..16]),
                transaction_id,
                output_index,
            ))
            .map_err(|error| format!("could not observe Liquid funding: {error}"))?;
        validate_liquid_chain_observation(observation, output_index, terms, require_unspent)
    }

    fn observe_contract_funding(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
    ) -> Result<RailChainObservation, String> {
        match terms.rail {
            ChainRailKind::Bitcoin => self
                .observe_chain_funding(session_id, transaction_id, output_index, terms)
                .map(RailChainObservation::Bitcoin),
            ChainRailKind::Liquid => self
                .observe_liquid_funding(session_id, transaction_id, output_index, terms)
                .map(RailChainObservation::Liquid),
        }
    }

    fn observe_claimed_contract_funding(
        &self,
        session_id: &str,
        transaction_id: &str,
        output_index: u32,
        terms: &ChainTerms,
    ) -> Result<RailChainObservation, String> {
        match terms.rail {
            ChainRailKind::Bitcoin => self
                .observe_chain_funding(session_id, transaction_id, output_index, terms)
                .map(RailChainObservation::Bitcoin),
            ChainRailKind::Liquid => self
                .observe_liquid_funding_with_spend_state(
                    session_id,
                    transaction_id,
                    output_index,
                    terms,
                    false,
                )
                .map(RailChainObservation::Liquid),
        }
    }

    fn settlement_template(
        &self,
        session_id: &str,
        observation: &ChainObservation,
        terms: &ChainTerms,
        path: SettlementPath,
    ) -> Result<SettlementTemplate, String> {
        let wallet_path = quote_allocation(session_id)?.unilateral_path;
        self.settlement_template_for_wallet_path(session_id, observation, terms, path, wallet_path)
    }

    fn settlement_template_for_wallet_path(
        &self,
        session_id: &str,
        observation: &ChainObservation,
        terms: &ChainTerms,
        path: SettlementPath,
        wallet_path: WalletPath,
    ) -> Result<SettlementTemplate, String> {
        let destination_path = settlement_destination_path(session_id)?;
        let destination = self
            .wallet
            .derive_address(destination_path)
            .map_err(|error| format!("could not derive settlement destination: {error}"))?;
        let settlement_fee_sat = exit_fee_sat(terms, path)?;
        let destination_value_sat = terms
            .amount_sat
            .checked_sub(settlement_fee_sat)
            .filter(|value| *value > 0)
            .ok_or_else(|| "settlement fee consumes the chain principal".to_owned())?;
        let (input_sequence, lock_time, script, control_block) = match path {
            SettlementPath::Claim => (
                0xffff_fffe,
                0,
                terms.claim_script.clone(),
                terms.claim_control_block.clone(),
            ),
            SettlementPath::Refund => (
                0xffff_fffe,
                terms.refund_height,
                terms.refund_script.clone(),
                terms.refund_control_block.clone(),
            ),
        };
        Ok(SettlementTemplate {
            wallet_path,
            previous_txid_wire: display_txid_wire(&observation.transaction_id)?,
            previous_output: observation.output_index,
            prevout_value_sat: terms.amount_sat,
            prevout_script_pubkey: terms.script_pubkey.clone(),
            destination_value_sat,
            destination_script_pubkey: destination.script_pubkey.to_vec(),
            transaction_version: 2,
            input_sequence,
            lock_time,
            taproot_script: script,
            taproot_control_block: control_block,
            maximum_fee_sat: settlement_fee_sat,
            maximum_fee_rate_sat_per_vbyte: 10_000,
            maximum_weight: SETTLEMENT_MAXIMUM_WEIGHT,
            dust_relay_fee_sat_per_kilobyte: DUST_RELAY_FEE_SAT_PER_KILOBYTE,
        })
    }

    fn prepare_cooperative_session(
        &self,
        session: &ProviderSession,
    ) -> Result<PreparedCooperativeSession, String> {
        if !self.cooperative_signing {
            return Err("cooperative signing process gate is disabled".to_owned());
        }
        let records = session.signed_records();
        let order = exactly_one_kind(records, MKT_ORDER_KIND, "Order")?;
        let requester_contract = exactly_one_kind_by_author(
            records,
            MKT_SWP_SWAP_CONTRACT_KIND,
            &session.config().requester_pubkey,
            "requester Swap Contract",
        )?;
        let provider_contract = exactly_one_kind_by_author(
            records,
            MKT_SWP_SWAP_CONTRACT_KIND,
            &session.config().provider_pubkey,
            "provider Swap Contract",
        )?;
        let requester_profile = record_profile(requester_contract)?;
        let provider_profile = record_profile(provider_contract)?;
        let contract = requester_profile
            .get("contract")
            .and_then(Value::as_object)
            .ok_or_else(|| "requester Swap Contract has no contract object".to_owned())?;
        if provider_profile.get("contract").and_then(Value::as_object) != Some(contract)
            || contract.get("musig2_execution").and_then(Value::as_bool) != Some(true)
        {
            return Err(
                "bilateral contract does not enable identical cooperative terms".to_owned(),
            );
        }
        let contract_sha256 = required_lower_hex(&requester_profile, "contract_sha256")?;
        if provider_profile
            .get("contract_sha256")
            .and_then(Value::as_str)
            != Some(contract_sha256.as_str())
        {
            return Err("bilateral contract digest differs".to_owned());
        }
        let swap_type = required_string(contract, "swap_type")?;
        let (leg_id, path, exit_role, settlement_path) = match swap_type {
            "submarine" => ("source", "claim", "chain_claim", SettlementPath::Claim),
            "reverse" => {
                return Err(
                    "reverse cooperative claim needs a preimage-release protocol before activation"
                        .to_owned(),
                );
            }
            _ => return Err("cooperative signing supports submarine swaps".to_owned()),
        };
        require_contract_effect_binding(contract, "cooperative_sign", leg_id)?;
        require_contract_effect_binding(contract, exit_role, leg_id)?;
        let verifier = contract_entry(contract, "verifier_inputs", leg_id, "Bitcoin verifier")?;
        let terms = chain_terms(session, swap_type)?;
        let funding_raw = terms
            .committed_funding_transaction
            .as_deref()
            .ok_or_else(|| "cooperative signing has no committed funding transaction".to_owned())?;
        let funding_bytes = decode_hex(funding_raw)?;
        let funding_transaction = Transaction::parse(&funding_bytes)
            .map_err(|error| format!("cooperative funding transaction is invalid: {error}"))?;
        let funding_txid = lower_hex(
            &funding_transaction
                .txid()
                .map_err(|error| format!("cooperative funding txid failed: {error}"))?,
        );
        let output_index = verifier
            .get("output_index")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| "cooperative funding output index is invalid".to_owned())?;
        let observation = ChainObservation {
            transaction: funding_transaction,
            transaction_id: funding_txid.clone(),
            output_index,
            confirmations: 0,
            block_hash: None,
        };
        let mut settlement = self.settlement_template(
            &session.config().session_id,
            &observation,
            &terms,
            settlement_path,
        )?;
        settlement.destination_script_pubkey = decode_hex(required_string(
            &verifier,
            "provider_exit_destination_script_pubkey",
        )?)?;
        let provider_exit_signer_ref = required_string(&verifier, "provider_exit_signer_ref")?;
        let expected_signer_ref = format!("immortal-provider:{leg_id}:{path}");
        if provider_exit_signer_ref != expected_signer_ref {
            return Err("cooperative provider signer reference differs from the Quote".to_owned());
        }
        let unsigned = Transaction::new(
            settlement.transaction_version,
            vec![immortal_core::mkt_swp_verify::TransactionInput {
                previous_txid: settlement.previous_txid_wire,
                previous_output: settlement.previous_output,
                script_sig: Vec::new(),
                sequence: settlement.input_sequence,
                witness: Vec::new(),
            }],
            vec![TransactionOutput {
                value_sat: settlement.destination_value_sat,
                script_pubkey: settlement.destination_script_pubkey.clone(),
            }],
            settlement.lock_time,
        );
        let unsigned_bytes = unsigned
            .serialize(false)
            .map_err(|error| format!("cooperative transaction serialization failed: {error}"))?;
        let recovery = verifier
            .get("provider_exit_policy")
            .and_then(Value::as_object)
            .ok_or_else(|| "cooperative verifier has no provider exit policy".to_owned())?;
        let latest = required_string(recovery, "latest_safe_broadcast_height")?;
        let package = build_provider_submarine_claim_exit_package(session.config(), records)
            .map_err(|error| format!("provider cooperative exit package build failed: {error}"))?;
        validate_provider_submarine_claim_exit_package(session.config(), records, &package)
            .map_err(|error| {
                format!("provider cooperative exit package verification failed: {error}")
            })?;
        if package
            .unsigned_transaction()
            .map_err(|error| format!("provider cooperative exit transaction failed: {error}"))?
            != unsigned_bytes
        {
            return Err(
                "provider cooperative exit package differs from the funded settlement template"
                    .to_owned(),
            );
        }
        let package_sha256 = package
            .commitment_sha256()
            .map_err(|error| format!("provider cooperative exit package digest failed: {error}"))?;
        let participant_keys = cooperative_participant_keys(&verifier)?;
        let public_keys = participant_keys
            .iter()
            .map(|key| PublicKey::from_slice(key))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "cooperative participant key is invalid".to_owned())?;
        let merkle_root = fixed_hex_32(required_string(&verifier, "taproot_merkle_root")?)?;
        let tweak = musig2_taproot_tweak(&public_keys, merkle_root)
            .map_err(|error| format!("cooperative Taproot tweak failed: {error}"))?;
        let signature_hash = taproot_key_spend_sighash(
            &unsigned,
            &[TransactionOutput {
                value_sat: terms.amount_sat,
                script_pubkey: terms.script_pubkey.clone(),
            }],
            0,
        )
        .map_err(|error| format!("cooperative signature hash failed: {error}"))?;
        let cooperative_effect_id = effect_id(&order.id, "cooperative_sign", leg_id)
            .map_err(|error| format!("cooperative effect ID failed: {error}"))?;
        let context = CooperativeSigningContext {
            schema: "openagents.mkt-swp.cooperative-signing.v1".to_owned(),
            order_id: order.id.clone(),
            swap_contract_sha256: contract_sha256,
            effect_id: cooperative_effect_id,
            leg_id: leg_id.to_owned(),
            unsigned_transaction: lower_hex(&unsigned_bytes),
            transaction_sha256: lower_hex(&sha256(&unsigned_bytes)),
            input_index: 0,
            prevouts: vec![CooperativePrevout {
                amount: terms.amount_sat.to_string(),
                script_pubkey: lower_hex(&terms.script_pubkey),
            }],
            signature_hash: lower_hex(&signature_hash),
            sighash_type: "DEFAULT".to_owned(),
            participant_keys: participant_keys.iter().map(|key| lower_hex(key)).collect(),
            tweaks: vec![immortal_client::mkt_swp_client::CooperativeTweak {
                value: lower_hex(&tweak.value),
                xonly: tweak.xonly,
            }],
            aggregate_key: required_string(&verifier, "taproot_output_key")?.to_owned(),
            exit_package_sha256: package_sha256,
            latest_safe_height: latest.to_owned(),
        };
        let transcript_digest = fixed_hex_32(
            &context
                .sha256()
                .map_err(|error| format!("cooperative context digest failed: {error}"))?,
        )?;
        let latest_safe_height = latest
            .parse::<u32>()
            .map_err(|_| "cooperative latest safe height is invalid".to_owned())?;
        Ok(PreparedCooperativeSession {
            package,
            context,
            template: CooperativeSettlementTemplate {
                settlement,
                cooperative_wallet_path: quote_allocation(&session.config().session_id)?
                    .cooperative_path,
                participant_keys,
                provider_index: 1,
                taproot_merkle_root: merkle_root,
                transcript_digest,
                latest_safe_height,
            },
        })
    }

    fn persist_effect_request(
        &self,
        session_id: &str,
        operation: &str,
        public_request: Value,
        now: u64,
    ) -> Result<(String, String), String> {
        let effect_id = deterministic_id(operation, session_id);
        let request_sha256 = value_digest(&public_request)?;
        self.handle
            .block_on(self.store.persist_effect_request(&PublicEffectRequest {
                effect_id: effect_id.clone(),
                session_id: session_id.to_owned(),
                operation: operation.to_owned(),
                request_sha256: request_sha256.clone(),
                public_request,
                created_at: now,
            }))
            .map_err(|error| format!("could not persist {operation} request: {error}"))?;
        Ok((effect_id, request_sha256))
    }

    fn persist_cooperative_public_records(
        &self,
        session_id: &str,
        prepared: &PreparedCooperativeSession,
        now: u64,
    ) -> Result<PersistedCooperativeEffects, String> {
        let document = prepared
            .package
            .document()
            .as_object()
            .ok_or_else(|| "cooperative exit package is not an object".to_owned())?;
        let package_sha256 = prepared
            .package
            .commitment_sha256()
            .map_err(|error| format!("cooperative exit package digest failed: {error}"))?;
        if package_sha256 != prepared.context.exit_package_sha256 {
            return Err("cooperative context changed its exit package digest".to_owned());
        }
        let order_id = required_string(document, "order_id")?;
        let leg_id = required_string(document, "leg_id")?;
        let path = prepared
            .package
            .path()
            .map_err(|error| format!("cooperative exit path is invalid: {error}"))?;
        self.handle
            .block_on(self.store.persist_exit_package(&PublicExitPackage {
                package_id: package_sha256.clone(),
                session_id: session_id.to_owned(),
                order_id: order_id.to_owned(),
                leg_id: leg_id.to_owned(),
                path: path.to_owned(),
                package_sha256: package_sha256.clone(),
                public_package: prepared.package.document().clone(),
                created_at: now,
            }))
            .map_err(|error| format!("could not persist cooperative exit package: {error}"))?;
        let public_request = json!({
            "context":prepared.context,
            "exit_package_sha256":package_sha256.clone(),
            "operation":"cooperative_sign",
        });
        let signing_request_sha256 = value_digest(&public_request)?;
        self.handle
            .block_on(self.store.persist_effect_request(&PublicEffectRequest {
                effect_id: prepared.context.effect_id.clone(),
                session_id: session_id.to_owned(),
                operation: "cooperative_sign".to_owned(),
                request_sha256: signing_request_sha256.clone(),
                public_request,
                created_at: now,
            }))
            .map_err(|error| format!("could not persist cooperative effect request: {error}"))?;
        let funding = document
            .get("funding")
            .and_then(Value::as_object)
            .ok_or_else(|| "cooperative exit package has no funding object".to_owned())?;
        let exit = document
            .get("exit")
            .and_then(Value::as_object)
            .ok_or_else(|| "cooperative exit package has no exit object".to_owned())?;
        let secrets = document
            .get("secret_commitments")
            .and_then(Value::as_object)
            .ok_or_else(|| "cooperative exit package has no secret commitments".to_owned())?;
        let claim_effect_id = prepared
            .package
            .effect_id()
            .map_err(|error| format!("cooperative claim effect ID is invalid: {error}"))?;
        let claim_request = json!({
            "exit_package_sha256":package_sha256,
            "funding_transaction_id":required_string(funding, "transaction_id")?,
            "output_index":funding.get("output_index").cloned().ok_or_else(|| "cooperative exit package has no funding output index".to_owned())?,
            "path":prepared.package.path().map_err(|error| format!("cooperative claim path is invalid: {error}"))?,
            "payment_hash":required_string(secrets, "payment_hash")?,
            "transaction_template_sha256":required_string(exit, "transaction_template_sha256")?,
        });
        let claim_request_sha256 = value_digest(&claim_request)?;
        self.handle
            .block_on(self.store.persist_effect_request(&PublicEffectRequest {
                effect_id: claim_effect_id.to_owned(),
                session_id: session_id.to_owned(),
                operation: "chain_claim".to_owned(),
                request_sha256: claim_request_sha256.clone(),
                public_request: claim_request,
                created_at: now,
            }))
            .map_err(|error| format!("could not persist cooperative claim request: {error}"))?;
        Ok(PersistedCooperativeEffects {
            signing_request_sha256,
            claim_request_sha256,
        })
    }

    fn begin_cooperative_session(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
    ) -> Result<MktSigningRequest, String> {
        let session_id = session.config().session_id.clone();
        let prepared = self.prepare_cooperative_session(session)?;
        let started_before_restart = self
            .handle
            .block_on(self.store.public_effect(&prepared.context.effect_id))
            .map_err(|error| format!("could not inspect cooperative restart state: {error}"))?
            .is_some();
        let effects =
            self.persist_cooperative_public_records(&session_id, &prepared, created_at)?;
        if started_before_restart {
            return ProviderCooperativeActor::restart_abort_status(
                session,
                &prepared.package,
                prepared.context,
                created_at,
                "counterparty_unavailable",
            )
            .map_err(|error| format!("could not construct cooperative restart abort: {error}"));
        }
        let current_height = self.chain_height("cooperative-begin", &session_id)?;
        let actor = ProviderCooperativeActor::begin(
            session,
            &prepared.package,
            prepared.context.clone(),
            &prepared.template,
            &SettlementBridge::new(&self.wallet),
            current_height,
        )
        .map_err(|error| format!("could not begin cooperative actor: {error}"))?;
        let replaced = self.cooperative_actors.insert(
            session_id.clone(),
            FundedCooperativeSession {
                actor,
                package: prepared.package,
                context: prepared.context,
                signing_request_sha256: effects.signing_request_sha256,
                claim_request_sha256: effects.claim_request_sha256,
            },
        );
        if replaced.is_some() {
            return Err("cooperative actor was replaced after nonce allocation".to_owned());
        }
        self.next_cooperative_action(session, created_at)?
            .ok_or_else(|| "new cooperative actor produced no nonce commitment".to_owned())
    }

    fn next_cooperative_action(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String> {
        let session_id = &session.config().session_id;
        if let Some(restart) = self.cooperative_restart_aborts.remove(session_id) {
            return ProviderCooperativeActor::restart_abort_status(
                session,
                &restart.package,
                restart.context,
                created_at,
                "counterparty_unavailable",
            )
            .map(Some)
            .map_err(|error| format!("could not construct cooperative restart abort: {error}"));
        }
        if !self.cooperative_actors.contains_key(session_id) {
            return Ok(None);
        }
        let records = session.signed_records();
        let provider = &session.config().provider_pubkey;
        let requester = &session.config().requester_pubkey;
        let presence = CooperativeTranscriptPresence {
            provider_commitment: has_cooperative_action(
                records,
                provider,
                ParticipantRole::Provider,
                CooperativeSigningAction::NonceCommitment,
            )?,
            requester_commitment: has_cooperative_action(
                records,
                requester,
                ParticipantRole::Requester,
                CooperativeSigningAction::NonceCommitment,
            )?,
            provider_public_nonce: has_cooperative_action(
                records,
                provider,
                ParticipantRole::Provider,
                CooperativeSigningAction::PublicNonce,
            )?,
            requester_public_nonce: has_cooperative_action(
                records,
                requester,
                ParticipantRole::Requester,
                CooperativeSigningAction::PublicNonce,
            )?,
            provider_partial_signature: has_cooperative_action(
                records,
                provider,
                ParticipantRole::Provider,
                CooperativeSigningAction::PartialSignature,
            )?,
            requester_partial_signature: has_cooperative_action(
                records,
                requester,
                ParticipantRole::Requester,
                CooperativeSigningAction::PartialSignature,
            )?,
            provider_final_signature: has_cooperative_action(
                records,
                provider,
                ParticipantRole::Provider,
                CooperativeSigningAction::FinalSignature,
            )?,
            provider_aborted: has_cooperative_action(
                records,
                provider,
                ParticipantRole::Provider,
                CooperativeSigningAction::Aborted,
            )?,
            requester_aborted: has_cooperative_action(
                records,
                requester,
                ParticipantRole::Requester,
                CooperativeSigningAction::Aborted,
            )?,
        };
        let step = cooperative_provider_step(presence);
        if step == CooperativeProviderStep::Wait {
            return Ok(None);
        }
        if step == CooperativeProviderStep::Aborted {
            return self
                .cooperative_actors
                .get_mut(session_id)
                .ok_or_else(|| "cooperative actor disappeared during abort".to_owned())?
                .actor
                .abort_status(session, created_at, "counterparty_unavailable")
                .map(Some)
                .map_err(|error| format!("could not construct cooperative abort: {error}"));
        }
        let current_height = self.chain_height("cooperative-advance", session_id)?;
        let active = self
            .cooperative_actors
            .get_mut(session_id)
            .ok_or_else(|| "cooperative actor disappeared during advance".to_owned())?;
        match step {
            CooperativeProviderStep::FinalSignature => active
                .actor
                .final_signature_status(
                    session,
                    created_at,
                    &SettlementBridge::new(&self.wallet),
                    current_height,
                )
                .map(Some)
                .map_err(|error| format!("could not finalize cooperative signature: {error}")),
            CooperativeProviderStep::PartialSignature => active
                .actor
                .partial_signature_status(
                    session,
                    created_at,
                    &SettlementBridge::new(&self.wallet),
                    current_height,
                )
                .map(Some)
                .map_err(|error| format!("could not construct cooperative partial: {error}")),
            CooperativeProviderStep::PublicNonce => active
                .actor
                .public_nonce_status(session, created_at, current_height)
                .map(Some)
                .map_err(|error| format!("could not reveal cooperative nonce: {error}")),
            CooperativeProviderStep::NonceCommitment => active
                .actor
                .nonce_commitment_status(session, created_at)
                .map(Some)
                .map_err(|error| format!("could not commit cooperative nonce: {error}")),
            CooperativeProviderStep::Wait | CooperativeProviderStep::Aborted => {
                Err("cooperative phase changed during action selection".to_owned())
            }
        }
    }

    fn observe_cooperative_record(
        &mut self,
        session: &ProviderSession,
        record: &Event,
        origin: RecordOrigin,
    ) -> Result<(), String> {
        if record.kind != MKT_STATUS_KIND {
            return Ok(());
        }
        let role = if record.pubkey == session.config().requester_pubkey {
            ParticipantRole::Requester
        } else if record.pubkey == session.config().provider_pubkey {
            ParticipantRole::Provider
        } else {
            return Ok(());
        };
        let Some(message) = cooperative_signing_message(record, role)
            .map_err(|error| format!("cooperative signed Status is invalid: {error}"))?
        else {
            return Ok(());
        };
        if !self.cooperative_signing {
            return Err("cooperative Status reached a disabled funded process".to_owned());
        }
        let session_id = session.config().session_id.clone();
        if self.cooperative_actors.contains_key(&session_id) {
            if role == ParticipantRole::Provider
                && message.action == CooperativeSigningAction::FinalSignature
            {
                let mut active = self.cooperative_actors.remove(&session_id).ok_or_else(|| {
                    "cooperative actor disappeared during finalization".to_owned()
                })?;
                let finalized = active
                    .actor
                    .take_finalized_after_signed_status(session, record)
                    .map_err(|error| {
                        format!("cooperative final transaction release failed: {error}")
                    })?;
                return self.persist_finalized_cooperative(
                    &session_id,
                    FinalizedCooperative {
                        context: &active.context,
                        package: &active.package,
                        signing_request_sha256: &active.signing_request_sha256,
                        claim_request_sha256: &active.claim_request_sha256,
                        final_status_id: &record.id,
                        transaction: finalized.into_broadcast_bytes(),
                        observed_at: record.created_at,
                    },
                );
            }
            if role == ParticipantRole::Provider
                && message.action == CooperativeSigningAction::Aborted
            {
                let active = self
                    .cooperative_actors
                    .remove(&session_id)
                    .ok_or_else(|| "cooperative actor disappeared during abort".to_owned())?;
                return self.complete_cooperative_abort(
                    &active.context,
                    &active.signing_request_sha256,
                    record,
                );
            }
            let commitment_height = (role == ParticipantRole::Requester
                && message.action == CooperativeSigningAction::NonceCommitment)
                .then(|| self.chain_height("cooperative-commitment", &session_id))
                .transpose()?;
            let active = self
                .cooperative_actors
                .get_mut(&session_id)
                .ok_or_else(|| "cooperative actor disappeared during observation".to_owned())?;
            match (role, message.action) {
                (ParticipantRole::Requester, CooperativeSigningAction::NonceCommitment) => {
                    active
                        .actor
                        .observe_requester_commitment(
                            session,
                            record,
                            commitment_height.ok_or_else(|| {
                                "cooperative commitment height disappeared".to_owned()
                            })?,
                        )
                        .map_err(|error| {
                            format!("requester cooperative commitment was refused: {error}")
                        })?;
                }
                (ParticipantRole::Requester, CooperativeSigningAction::PublicNonce) => active
                    .actor
                    .observe_requester_public_nonce(session, record)
                    .map_err(|error| format!("requester cooperative nonce was refused: {error}"))?,
                (ParticipantRole::Requester, CooperativeSigningAction::PartialSignature) => active
                    .actor
                    .observe_requester_partial_signature(session, record)
                    .map_err(|error| {
                        format!("requester cooperative partial was refused: {error}")
                    })?,
                (ParticipantRole::Requester, CooperativeSigningAction::Aborted) => active
                    .actor
                    .observe_requester_abort(session, record)
                    .map_err(|error| format!("requester cooperative abort was refused: {error}"))?,
                _ => {}
            }
            return Ok(());
        }

        let prepared = self.prepare_cooperative_session(session)?;
        if prepared.context != message.context {
            return Err("recovered cooperative context differs from the funded plan".to_owned());
        }
        let effects =
            self.persist_cooperative_public_records(&session_id, &prepared, record.created_at)?;
        match (origin, role, message.action) {
            (_, ParticipantRole::Provider, CooperativeSigningAction::FinalSignature) => {
                self.cooperative_restart_aborts.remove(&session_id);
                let finalized = finalized_from_signed_message(&message)?;
                self.persist_finalized_cooperative(
                    &session_id,
                    FinalizedCooperative {
                        context: &prepared.context,
                        package: &prepared.package,
                        signing_request_sha256: &effects.signing_request_sha256,
                        claim_request_sha256: &effects.claim_request_sha256,
                        final_status_id: &record.id,
                        transaction: finalized,
                        observed_at: record.created_at,
                    },
                )?;
            }
            (_, ParticipantRole::Provider, CooperativeSigningAction::Aborted) => {
                self.cooperative_restart_aborts.remove(&session_id);
                self.complete_cooperative_abort(
                    &prepared.context,
                    &effects.signing_request_sha256,
                    record,
                )?;
            }
            (RecordOrigin::Recovery, _, _) => {
                self.cooperative_restart_aborts.insert(
                    session_id,
                    CooperativeRestartAbort {
                        package: prepared.package,
                        context: prepared.context,
                    },
                );
            }
            _ => {
                return Err("cooperative Status has no live FundedMode actor".to_owned());
            }
        }
        Ok(())
    }

    fn persist_finalized_cooperative(
        &mut self,
        session_id: &str,
        finalized: FinalizedCooperative<'_>,
    ) -> Result<(), String> {
        let package_sha256 = finalized
            .package
            .commitment_sha256()
            .map_err(|error| format!("cooperative package digest failed: {error}"))?;
        self.complete_effect(
            &finalized.context.effect_id,
            finalized.signing_request_sha256,
            json!({
                "exit_package_sha256":package_sha256.clone(),
                "outcome":"signed",
                "status_id":finalized.final_status_id,
                "transaction_template_sha256":finalized.context.transaction_sha256,
            }),
            finalized.final_status_id,
            finalized.observed_at,
        )?;
        let raw_transaction = lower_hex(&finalized.transaction);
        let payload = BroadcastWatchPayload::cooperative_key_path(raw_transaction)
            .map_err(|error| format!("cooperative watch payload is invalid: {error}"))?;
        let claim_effect_id = finalized
            .package
            .effect_id()
            .map_err(|error| format!("cooperative claim effect ID is invalid: {error}"))?;
        let (job_id, watch_request_sha256) = self.enqueue_watch(
            session_id,
            claim_effect_id,
            "cooperative_broadcast",
            &payload,
            WatchDeadline::Time(finalized.observed_at),
            finalized.observed_at,
        )?;
        self.broadcast_watch_now(
            session_id,
            &job_id,
            &watch_request_sha256,
            &payload,
            finalized.observed_at,
        )?;
        self.complete_effect(
            claim_effect_id,
            finalized.claim_request_sha256,
            json!({
                "exit_package_sha256":package_sha256,
                "outcome":"broadcast",
                "transaction_id":payload.expected_txid,
            }),
            &payload.expected_txid,
            finalized.observed_at,
        )?;
        self.handle
            .block_on(self.store.set_exit_package_state(
                &finalized.context.exit_package_sha256,
                "broadcast",
                finalized.observed_at,
            ))
            .map(|_| ())
            .map_err(|error| format!("could not mark cooperative exit broadcast: {error}"))
    }

    fn complete_cooperative_abort(
        &mut self,
        context: &CooperativeSigningContext,
        effect_request_sha256: &str,
        record: &Event,
    ) -> Result<(), String> {
        let message = cooperative_signing_message(record, ParticipantRole::Provider)
            .map_err(|error| format!("provider cooperative abort is invalid: {error}"))?
            .ok_or_else(|| "provider cooperative abort message is missing".to_owned())?;
        self.complete_effect(
            &context.effect_id,
            effect_request_sha256,
            json!({
                "fallback":"script_path",
                "outcome":"aborted",
                "reason":message.abort_reason,
                "status_id":record.id,
            }),
            &record.id,
            record.created_at,
        )
    }

    fn complete_effect(
        &mut self,
        effect_id: &str,
        request_sha256: &str,
        public_result: Value,
        external_reference: &str,
        now: u64,
    ) -> Result<(), String> {
        let result_sha256 = value_digest(&public_result)?;
        self.handle
            .block_on(self.store.complete_effect(&PublicEffectResult {
                effect_id: effect_id.to_owned(),
                request_sha256: request_sha256.to_owned(),
                result_sha256,
                public_result,
                external_reference: external_reference.to_owned(),
                completed_at: now,
            }))
            .map(|_| ())
            .map_err(|error| format!("could not persist external effect result: {error}"))
    }

    fn release_session_reservation(&mut self, session_id: &str, now: u64) -> Result<(), String> {
        let reservation_id = deterministic_id("reservation", session_id);
        let Some(reservation) = self
            .handle
            .block_on(self.store.reservation(&reservation_id))
            .map_err(|error| format!("could not inspect terminal reservation: {error}"))?
        else {
            return Ok(());
        };
        if reservation.state == "unresolved" {
            return Err("terminal session has an unresolved reservation".to_owned());
        }
        self.handle
            .block_on(
                self.store
                    .release_reservation(&reservation_id, "session_terminal", now),
            )
            .map(|_| ())
            .map_err(|error| format!("could not release terminal reservation: {error}"))
    }

    fn reserve_zero_conf_risk(
        &mut self,
        session_id: &str,
        amount_sat: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, String> {
        let policy = self
            .zero_conf
            .ok_or_else(|| "zero-conf risk reached a disabled provider policy".to_owned())?;
        if amount_sat == 0 || amount_sat > policy.max_swap_sat {
            return Ok(false);
        }
        let bucket_id = "zero-conf-risk-btc";
        let asset_id = format!("swp:1:{}:btc:chain", self.network_id);
        self.handle
            .block_on(self.store.configure_capacity_bucket(
                bucket_id,
                &asset_id,
                policy.max_in_flight_sat,
                now,
            ))
            .map_err(|error| format!("could not configure zero-conf risk bucket: {error}"))?;
        let reservation_id = deterministic_id("zero-conf-risk", session_id);
        let effect_id = deterministic_id("zero-conf-reserve", session_id);
        let reservation_session_id = zero_conf_risk_session_id(session_id);
        let request_sha256 = value_digest(&json!({
            "amount":amount_sat.to_string(),
            "asset_id":asset_id,
            "bucket_id":bucket_id,
            "expires_at":expires_at,
            "market_session_id":session_id,
            "reservation_id":reservation_id,
            "reservation_session_id":reservation_session_id,
        }))?;
        let mut expected_sequence = 1_u64;
        loop {
            let request = HardReservationRequest {
                reservation_id: reservation_id.clone(),
                effect_id: effect_id.clone(),
                session_id: reservation_session_id.clone(),
                bucket_id: bucket_id.to_owned(),
                asset_id: asset_id.clone(),
                amount: amount_sat,
                request_sha256: request_sha256.clone(),
                expected_allocation_sequence: expected_sequence,
                expires_at,
                utxos: Vec::new(),
                created_at: now,
            };
            match self.handle.block_on(self.store.reserve(&request)) {
                Ok(ReservationOutcome::Reserved(_) | ReservationOutcome::Replay(_)) => {
                    return Ok(true);
                }
                Ok(ReservationOutcome::AllocationSequenceMismatch { current }) => {
                    expected_sequence = current
                        .checked_add(1)
                        .ok_or_else(|| "zero-conf allocation sequence overflowed".to_owned())?;
                }
                Ok(ReservationOutcome::InsufficientCapacity) => return Ok(false),
                Ok(ReservationOutcome::UtxoUnavailable(_)) => {
                    return Err(
                        "zero-conf risk reservation unexpectedly selected a UTXO".to_owned()
                    );
                }
                Err(error) => {
                    return Err(format!(
                        "could not reserve zero-conf risk capacity: {error}"
                    ));
                }
            }
        }
    }

    fn release_zero_conf_risk(&mut self, session_id: &str, now: u64) -> Result<(), String> {
        let reservation_id = deterministic_id("zero-conf-risk", session_id);
        let Some(reservation) = self
            .handle
            .block_on(self.store.reservation(&reservation_id))
            .map_err(|error| format!("could not inspect zero-conf risk reservation: {error}"))?
        else {
            return Ok(());
        };
        if reservation.state == "released" {
            return Ok(());
        }
        self.handle
            .block_on(self.store.release_reservation(
                &reservation_id,
                "zero_conf_final_or_downgraded",
                now,
            ))
            .map(|_| ())
            .map_err(|error| format!("could not release zero-conf risk reservation: {error}"))
    }

    fn release_reservation_effect(
        &mut self,
        request: &ProviderEffectRequest,
        now: u64,
    ) -> Result<ProviderEffectReceipt, String> {
        let release_cause = request
            .release_cause
            .ok_or_else(|| "reservation release effect has no cause".to_owned())?;
        let reason = match release_cause {
            crate::ReservationReleaseCause::EffectiveCancel => "effective_cancel",
            crate::ReservationReleaseCause::ReservationExpired => "reservation_expired",
            crate::ReservationReleaseCause::TerminalClose => "terminal_close",
        };
        self.handle
            .block_on(
                self.store
                    .release_reservation(&request.reservation_id, reason, now),
            )
            .map_err(|error| format!("could not release provider reservation: {error}"))?;
        let result = json!({
            "reservation_id":request.reservation_id,
            "release_cause":reason,
            "state":"released",
        });
        Ok(ProviderEffectReceipt {
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            external_reference: format!("provider-reservation:{}", request.reservation_id),
            result_sha256: value_digest(&result)?,
        })
    }

    fn chain_height(&self, label: &str, session_id: &str) -> Result<u32, String> {
        let tip = self
            .handle
            .block_on(self.bitcoind.chain_tip(&rpc_id(label, session_id)?))
            .map_err(|error| format!("could not inspect chain deadline: {error}"))?;
        u32::try_from(tip.height)
            .map_err(|_| "chain deadline height exceeds the funded-v1 range".to_owned())
    }

    fn terminal_close(
        &mut self,
        session: &mut ProviderSession,
        swap_type: &str,
        outcome: &'static str,
        created_at: u64,
    ) -> Result<MktSigningRequest, String> {
        let profile = terminal_close_profile(session, swap_type, outcome)?;
        self.release_zero_conf_risk(&session.config().session_id, created_at)?;
        let (request, receipt) = session
            .provider_close_with_release(
                created_at,
                &deterministic_id(&format!("{outcome}-close"), &session.config().session_id),
                CloseOutcome {
                    outcome,
                    terminal_at: created_at,
                },
                profile,
                |request| self.release_reservation_effect(request, created_at),
            )
            .map_err(|error| format!("could not construct provider {outcome} Close: {error}"))?;
        if receipt.external_reference.is_empty() {
            return Err("provider Close release receipt has no reference".to_owned());
        }
        Ok(request)
    }

    fn mark_hold_unresolved(
        &mut self,
        session_id: &str,
        payment_hash: &str,
        detail_code: &str,
        now: u64,
    ) -> Result<(), String> {
        if !matches!(
            detail_code,
            "invalid_hold_invoice_settled" | "hold_invoice_settled_before_funding"
        ) {
            return Err("invalid unresolved held-HTLC detail code".to_owned());
        }
        let reservation_id = deterministic_id("reservation", session_id);
        self.handle
            .block_on(self.store.mark_reservation_unresolved(
                &reservation_id,
                detail_code,
                &json!({
                    "payment_hash":payment_hash,
                    "failure_code":detail_code,
                }),
                now,
            ))
            .map(|_| ())
            .map_err(|error| format!("could not retain unresolved invalid-hold session: {error}"))
    }

    fn enqueue_watch(
        &self,
        session_id: &str,
        effect_id: &str,
        job_kind: &str,
        payload: &BroadcastWatchPayload,
        deadline: WatchDeadline,
        now: u64,
    ) -> Result<(String, String), String> {
        let job_id = deterministic_id(job_kind, session_id);
        let request_sha256 = payload
            .request_sha256()
            .map_err(|error| format!("watch payload is invalid: {error}"))?;
        let public_payload = payload
            .public_value()
            .map_err(|error| format!("watch payload is invalid: {error}"))?;
        self.handle
            .block_on(self.store.enqueue_watch_job(&WatchJobRequest {
                job_id: job_id.clone(),
                session_id: session_id.to_owned(),
                effect_id: Some(effect_id.to_owned()),
                job_kind: job_kind.to_owned(),
                request_sha256: request_sha256.clone(),
                public_payload,
                due_height: deadline.due_height(),
                due_at: deadline.due_at(),
                maximum_attempts: MAXIMUM_WATCH_ATTEMPTS,
                created_at: now,
            }))
            .map_err(|error| format!("could not enqueue {job_kind}: {error}"))?;
        Ok((job_id, request_sha256))
    }

    fn broadcast_watch_now(
        &mut self,
        session_id: &str,
        job_id: &str,
        request_sha256: &str,
        payload: &BroadcastWatchPayload,
        now: u64,
    ) -> Result<(), String> {
        let transaction_id = match self.handle.block_on(self.bitcoind.broadcast(
            &rpc_id("settlement-broadcast", session_id)?,
            &payload.raw_transaction,
            None,
        )) {
            Ok(transaction_id) => transaction_id,
            Err(BitcoindError::Rpc { code: -27 }) => {
                self.handle
                    .block_on(self.bitcoind.raw_transaction(
                        &rpc_id("settlement-replay", session_id)?,
                        &payload.expected_txid,
                        false,
                    ))
                    .map_err(|error| format!("could not verify settlement replay: {error}"))?;
                payload.expected_txid.clone()
            }
            Err(error) => return Err(format!("could not broadcast settlement: {error}")),
        };
        if transaction_id != payload.expected_txid {
            return Err("bitcoind returned another settlement transaction ID".to_owned());
        }
        let existing = self
            .handle
            .block_on(self.store.watch_job(job_id))
            .map_err(|error| format!("could not inspect settlement broadcast replay: {error}"))?
            .ok_or_else(|| "settlement watch disappeared after enqueue".to_owned())?;
        if existing.result_sha256.is_some() {
            if existing.broadcast_txid.as_deref() == Some(payload.expected_txid.as_str())
                && matches!(existing.state.as_str(), "broadcast" | "confirmed")
            {
                return Ok(());
            }
            return Err("settlement watch contains a conflicting broadcast result".to_owned());
        }
        let result = json!({"accepted_at":now,"txid":transaction_id});
        let result_sha256 = value_digest(&result)?;
        self.handle
            .block_on(self.store.record_broadcast(
                job_id,
                request_sha256,
                &result_sha256,
                &result,
                &payload.expected_txid,
                now,
            ))
            .map(|_| ())
            .map_err(|error| format!("could not record settlement broadcast: {error}"))
    }

    fn execute_submarine_claim(
        &mut self,
        session: &ProviderSession,
        observation: &ChainObservation,
        terms: &ChainTerms,
        invoice: &str,
        now: u64,
    ) -> Result<Value, String> {
        let session_id = &session.config().session_id;
        let public_request = json!({
            "amount_sat":terms.amount_sat,
            "invoice_sha256":lower_hex(&sha256(invoice.as_bytes())),
            "maximum_routing_fee_sat":terms.lightning_fee_budget_sat,
            "payment_hash":terms.payment_hash,
        });
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "invoice_pay", public_request, now)?;
        let maximum_fee = Millisatoshi::from_satoshis(terms.lightning_fee_budget_sat)
            .map_err(|error| format!("Lightning fee budget is invalid: {error}"))?;
        let (payment, released_preimage) = self
            .handle
            .block_on(self.lightning.pay_with_released_preimage(
                &lightning_id("invoice-pay", session_id)?,
                invoice,
                maximum_fee,
            ))
            .map_err(|error| format!("submarine invoice payment failed: {error}"))?;
        let routing_fee_msat = payment
            .amount_sent
            .as_millisatoshis()
            .checked_sub(payment.amount.as_millisatoshis())
            .ok_or_else(|| "Lightning payment amount underflowed".to_owned())?;
        if routing_fee_msat > maximum_fee.as_millisatoshis() {
            return Err("Lightning payment exceeded the signed fee budget".to_owned());
        }
        let settled_at = self.payment_settled_at(session_id, invoice, &terms.payment_hash)?;

        let mut public_result = json!({
            "amount_msat":payment.amount.as_millisatoshis(),
            "amount_sent_msat":payment.amount_sent.as_millisatoshis(),
            "payment_hash":payment.payment_hash,
        });
        let external_reference = if self.cooperative_signing {
            payment.payment_hash.clone()
        } else {
            let template =
                self.settlement_template(session_id, observation, terms, SettlementPath::Claim)?;
            let signed = SettlementBridge::new(&self.wallet)
                .claim(&template, ClaimPreimage::from(released_preimage))
                .map_err(|error| format!("could not construct submarine claim: {error}"))?;
            let raw_transaction = lower_hex(&signed.into_broadcast_bytes());
            let payload = BroadcastWatchPayload::released_claim(
                raw_transaction,
                ClaimReleaseEvidence {
                    payment_hash: terms.payment_hash.clone(),
                    settled_at,
                },
            )
            .map_err(|error| format!("could not bind submarine claim watch: {error}"))?;
            let (job_id, watch_request_sha256) = self.enqueue_watch(
                session_id,
                &effect_id,
                "claim_broadcast",
                &payload,
                WatchDeadline::Time(now),
                now,
            )?;
            self.broadcast_watch_now(session_id, &job_id, &watch_request_sha256, &payload, now)?;
            public_result
                .as_object_mut()
                .ok_or_else(|| "submarine payment result is not an object".to_owned())?
                .insert(
                    "claim_txid".to_owned(),
                    Value::String(payload.expected_txid.clone()),
                );
            payload.expected_txid
        };
        self.complete_effect(
            &effect_id,
            &request_sha256,
            public_result.clone(),
            &external_reference,
            now,
        )?;
        Ok(public_result)
    }

    fn execute_liquid_submarine_claim(
        &mut self,
        session: &ProviderSession,
        observation: &LiquidChainObservation,
        terms: &ChainTerms,
        invoice: &str,
        now: u64,
    ) -> Result<Value, String> {
        let session_id = &session.config().session_id;
        let public_request = json!({
            "amount_sat":terms.amount_sat,
            "invoice_sha256":lower_hex(&sha256(invoice.as_bytes())),
            "maximum_routing_fee_sat":terms.lightning_fee_budget_sat,
            "payment_hash":terms.payment_hash,
        });
        let (payment_effect_id, payment_request_sha256) =
            self.persist_effect_request(session_id, "invoice_pay", public_request, now)?;
        let maximum_fee = Millisatoshi::from_satoshis(terms.lightning_fee_budget_sat)
            .map_err(|error| format!("Lightning fee budget is invalid: {error}"))?;
        let (payment, released_preimage) = self
            .handle
            .block_on(self.lightning.pay_with_released_preimage(
                &lightning_id("invoice-pay", session_id)?,
                invoice,
                maximum_fee,
            ))
            .map_err(|error| format!("submarine invoice payment failed: {error}"))?;
        let routing_fee_msat = payment
            .amount_sent
            .as_millisatoshis()
            .checked_sub(payment.amount.as_millisatoshis())
            .ok_or_else(|| "Lightning payment amount underflowed".to_owned())?;
        if routing_fee_msat > maximum_fee.as_millisatoshis() {
            return Err("Lightning payment exceeded the signed fee budget".to_owned());
        }
        self.payment_settled_at(session_id, invoice, &terms.payment_hash)?;

        let liquid = self
            .liquid
            .clone()
            .ok_or_else(|| "Liquid submarine claim reached a disabled rail".to_owned())?;
        let claim_effect_id = deterministic_id("submarine_claim", session_id);
        let request = if let Some(request) = self.stored_provider_liquid_exit_request(
            &claim_effect_id,
            LiquidEffectOperation::SubmarineClaim,
        )? {
            request
        } else {
            let funding = self
                .handle
                .block_on(liquid.observe_transaction(
                    &rpc_id("liquid-submarine-funding", session_id)?,
                    &observation.transaction_id,
                ))
                .map_err(|error| format!("could not recover Liquid submarine funding: {error}"))?;
            let destination = self
                .wallet
                .derive_address(settlement_destination_path(session_id)?)
                .map_err(|error| format!("could not derive Liquid claim destination: {error}"))?;
            let package = self
                .handle
                .block_on(liquid.build_signed_exit_package(
                    &format!("submarine-claim:{}", &session_id[..16]),
                    &self.wallet,
                    quote_allocation(session_id)?.unilateral_path,
                    &funding.raw_transaction,
                    observation.output_index,
                    terms.amount_sat,
                    &terms.script_pubkey,
                    "claim",
                    &terms.claim_script,
                    &terms.claim_control_block,
                    0,
                    &destination.script_pubkey,
                    exit_fee_sat(terms, SettlementPath::Claim)?,
                    Some(released_preimage.into_bytes()),
                ))
                .map_err(|error| format!("could not sign Liquid submarine claim: {error}"))?;
            ProviderLiquidExitRequest {
                funding: LiquidFundingVerificationInput {
                    raw_transaction: lower_hex(&funding.raw_transaction),
                    trusted_unblind_transaction: None,
                    transaction_sha256: lower_hex(&sha256(&funding.raw_transaction)),
                    output_index: observation.output_index,
                    asset_id: terms.asset_id.clone(),
                    amount: terms.amount_sat.to_string(),
                    script_pubkey: lower_hex(&terms.script_pubkey),
                    taproot_internal_key: terms.taproot_internal_key.clone(),
                    taproot_merkle_root: Some(terms.taproot_merkle_root.clone()),
                    confidentiality: LiquidConfidentiality::Explicit,
                    minimum_confirmations: self.minimum_confirmations,
                    replacement_policy: "reject".to_owned(),
                },
                exit_package: package,
            }
        };
        if request.exit_package.path != "claim"
            || request.exit_package.funding_transaction_id != observation.transaction_id
            || request.exit_package.funding_output_index != observation.output_index
            || request.exit_package.funding_amount != terms.amount_sat.to_string()
            || request.funding.asset_id != terms.asset_id
            || request.funding.script_pubkey != lower_hex(&terms.script_pubkey)
        {
            return Err("stored Liquid submarine claim differs from the Contract".to_owned());
        }
        let order = exactly_one_kind(session.signed_records(), MKT_ORDER_KIND, "Order")?;
        let receipt = self
            .handle
            .block_on(liquid.execute_provider_exit_effect(
                &mut self.store,
                &claim_effect_id,
                session_id,
                &order.id,
                "source",
                LiquidEffectOperation::SubmarineClaim,
                &request,
                now,
            ))
            .map_err(|error| format!("could not broadcast Liquid submarine claim: {error}"))?;
        let public_result = json!({
            "amount_msat":payment.amount.as_millisatoshis(),
            "amount_sent_msat":payment.amount_sent.as_millisatoshis(),
            "claim_txid":receipt.transaction_id,
            "payment_hash":payment.payment_hash,
        });
        self.complete_effect(
            &payment_effect_id,
            &payment_request_sha256,
            public_result.clone(),
            &receipt.transaction_id,
            now,
        )?;
        Ok(public_result)
    }

    fn execute_submarine_fallback_claim(
        &mut self,
        session: &ProviderSession,
        terms: &ChainTerms,
        invoice: &str,
        now: u64,
    ) -> Result<WatchJob, String> {
        let session_id = &session.config().session_id;
        let funding_status = status_by_state(
            session.signed_records(),
            &session.config().requester_pubkey,
            "requester_funding_broadcast",
        )
        .ok_or_else(|| "submarine fallback lost its funding Status".to_owned())?;
        let (transaction_id, output_index) = status_transaction_reference(funding_status)?;
        let observation =
            self.observe_chain_funding(session_id, &transaction_id, output_index, terms)?;
        if observation.confirmations < self.minimum_confirmations {
            return Err("submarine fallback funding is no longer final".to_owned());
        }
        let prepared = self.prepare_cooperative_session(session)?;
        let claim_effect_id = prepared
            .package
            .effect_id()
            .map_err(|error| format!("submarine claim effect ID failed: {error}"))?
            .to_owned();
        let effects = self.persist_cooperative_public_records(session_id, &prepared, now)?;
        let maximum_fee = Millisatoshi::from_satoshis(terms.lightning_fee_budget_sat)
            .map_err(|error| format!("Lightning fee budget is invalid: {error}"))?;
        let (_, released_preimage) = self
            .handle
            .block_on(self.lightning.pay_with_released_preimage(
                &lightning_id("invoice-pay-fallback", session_id)?,
                invoice,
                maximum_fee,
            ))
            .map_err(|error| format!("could not recover submarine claim preimage: {error}"))?;
        let template =
            self.settlement_template(session_id, &observation, terms, SettlementPath::Claim)?;
        let signed = SettlementBridge::new(&self.wallet)
            .claim(&template, ClaimPreimage::from(released_preimage))
            .map_err(|error| format!("could not construct fallback claim: {error}"))?;
        let settled_at = self.payment_settled_at(session_id, invoice, &terms.payment_hash)?;
        let payload = BroadcastWatchPayload::released_claim(
            lower_hex(&signed.into_broadcast_bytes()),
            ClaimReleaseEvidence {
                payment_hash: terms.payment_hash.clone(),
                settled_at,
            },
        )
        .map_err(|error| format!("could not bind fallback claim watch: {error}"))?;
        let (job_id, watch_request_sha256) = self.enqueue_watch(
            session_id,
            &claim_effect_id,
            "claim_broadcast",
            &payload,
            WatchDeadline::Time(now),
            now,
        )?;
        self.broadcast_watch_now(session_id, &job_id, &watch_request_sha256, &payload, now)?;
        self.complete_effect(
            &claim_effect_id,
            &effects.claim_request_sha256,
            json!({
                "claim_txid":payload.expected_txid,
                "fallback":"script_path",
                "payment_hash":terms.payment_hash,
            }),
            &payload.expected_txid,
            now,
        )?;
        self.watch_job("claim_broadcast", session_id)
    }

    fn payment_settled_at(
        &self,
        session_id: &str,
        invoice: &str,
        payment_hash: &str,
    ) -> Result<u64, String> {
        self.handle
            .block_on(self.lightning.payment_settled_at(
                &lightning_id("invoice-pay-time", session_id)?,
                invoice,
                payment_hash,
            ))
            .map_err(|error| format!("could not recover completed Lightning payment: {error}"))
    }

    fn reverse_hold_state(&self, session_id: &str, payment_hash: &str) -> Result<String, String> {
        let response = self
            .handle
            .block_on(
                self.lightning
                    .hold_invoice_state(&lightning_id("hold-state", session_id)?, payment_hash),
            )
            .map_err(|error| format!("could not inspect reverse hold invoice: {error}"))?;
        let invoice = matching_hold_invoice(&response, payment_hash)?;
        invoice
            .get("state")
            .or_else(|| invoice.get("status"))
            .and_then(Value::as_str)
            .map(|state| state.to_ascii_lowercase())
            .ok_or_else(|| "reverse hold invoice has no state".to_owned())
    }

    fn verify_reverse_hold_safety(
        &self,
        session_id: &str,
        terms: &ChainTerms,
        observed_at: u64,
    ) -> Result<HeldHtlcSummary, ReverseHoldSafetyError> {
        let response = self
            .handle
            .block_on(
                self.lightning.hold_invoice_state(
                    &lightning_id("hold-safety", session_id)
                        .map_err(ReverseHoldSafetyError::Unavailable)?,
                    &terms.payment_hash,
                ),
            )
            .map_err(|error| {
                ReverseHoldSafetyError::Unavailable(format!(
                    "could not inspect held HTLC safety: {error}"
                ))
            })?;
        let invoice = matching_hold_invoice(&response, &terms.payment_hash)
            .map_err(ReverseHoldSafetyError::Unavailable)?;
        let tip = self
            .handle
            .block_on(
                self.bitcoind.chain_tip(
                    &rpc_id("hold-safety-tip", session_id)
                        .map_err(ReverseHoldSafetyError::Unavailable)?,
                ),
            )
            .map_err(|error| {
                ReverseHoldSafetyError::Unavailable(format!(
                    "could not inspect held HTLC chain height: {error}"
                ))
            })?;
        if terms.rail == ChainRailKind::Liquid {
            validate_cross_domain_held_htlcs(invoice, terms, tip.height, observed_at)
                .map_err(ReverseHoldSafetyError::Invalid)
        } else {
            validate_held_htlcs(invoice, terms, tip.height).map_err(ReverseHoldSafetyError::Invalid)
        }
    }

    fn recover_reserved_inputs(
        &self,
        session_id: &str,
        reservation_id: &str,
    ) -> Result<Vec<FundingInput>, String> {
        let stored = self
            .handle
            .block_on(self.store.reserved_utxos(reservation_id))
            .map_err(|error| format!("could not recover reserved UTXOs: {error}"))?;
        if stored.is_empty() {
            return Err("active reverse reservation has no reserved UTXOs".to_owned());
        }
        stored
            .iter()
            .map(|utxo| self.funding_input_from_stored(session_id, utxo))
            .collect()
    }

    fn recover_reserved_liquid_inputs(
        &self,
        reservation_id: &str,
    ) -> Result<Vec<ElementsdWalletUtxo>, String> {
        let stored = self
            .handle
            .block_on(self.store.reserved_utxos(reservation_id))
            .map_err(|error| format!("could not recover reserved Liquid UTXOs: {error}"))?;
        if stored.is_empty() {
            return Err("active Liquid reservation has no reserved UTXOs".to_owned());
        }
        stored
            .into_iter()
            .map(|utxo| {
                if self
                    .liquid
                    .as_ref()
                    .is_none_or(|liquid| utxo.asset_id != liquid.mkt_asset_id())
                {
                    return Err("reserved UTXO is not the configured Liquid asset".to_owned());
                }
                Ok(ElementsdWalletUtxo {
                    transaction_id: utxo.outpoint.txid,
                    output_index: utxo.outpoint.vout,
                    amount_sat: utxo.amount,
                    script_pubkey: utxo.script_pubkey,
                    confirmations: utxo.confirmations,
                })
            })
            .collect()
    }

    fn funding_input_from_stored(
        &self,
        _session_id: &str,
        stored: &StoredUtxo,
    ) -> Result<FundingInput, String> {
        for change in [false, true] {
            for address_index in 0..20 {
                let path = WalletPath::new(0, change, address_index)
                    .map_err(|error| format!("wallet scan path is invalid: {error}"))?;
                let address = self
                    .wallet
                    .derive_address(path)
                    .map_err(|error| format!("could not recover reserved wallet path: {error}"))?;
                if lower_hex(&address.script_pubkey) == stored.script_pubkey {
                    return Ok(FundingInput {
                        txid: stored.outpoint.txid.clone(),
                        vout: stored.outpoint.vout,
                        value_sat: stored.amount,
                        path,
                    });
                }
            }
        }
        Err("reserved UTXO is outside the funded wallet scan window".to_owned())
    }

    fn execute_reverse_funding(
        &mut self,
        session: &ProviderSession,
        terms: &ChainTerms,
        unilateral_path: WalletPath,
        now: u64,
    ) -> Result<(String, u32, Value), String> {
        if terms.rail == ChainRailKind::Liquid {
            return self.execute_liquid_reverse_funding(session, terms, now);
        }
        let session_id = &session.config().session_id;
        let reservation_id = deterministic_id("reservation", session_id);
        let inputs = match self.reserved_inputs.get(session_id) {
            Some(inputs) => inputs.clone(),
            None => self.recover_reserved_inputs(session_id, &reservation_id)?,
        };
        let funding = self.build_reverse_funding(
            session_id,
            &inputs,
            terms.script_pubkey.clone(),
            terms.amount_sat,
            terms.fee_rate_sat_per_vbyte,
        )?;
        validate_executable_reverse_funding(&funding, terms)?;
        let observation = ChainObservation {
            transaction: funding.transaction.clone(),
            transaction_id: funding.txid.clone(),
            output_index: 0,
            confirmations: 0,
            block_hash: None,
        };
        let refund = SettlementBridge::new(&self.wallet)
            .refund(&self.settlement_template_for_wallet_path(
                session_id,
                &observation,
                terms,
                SettlementPath::Refund,
                unilateral_path,
            )?)
            .map_err(|error| format!("could not construct reverse refund: {error}"))?;
        let refund_payload =
            BroadcastWatchPayload::refund(lower_hex(&refund.into_broadcast_bytes()))
                .map_err(|error| format!("could not bind reverse refund watch: {error}"))?;
        let public_request = json!({
            "amount_sat":terms.amount_sat,
            "funding_sha256":lower_hex(&sha256(&decode_hex(&funding.raw_transaction)?)),
            "input_count":inputs.len(),
            "script_pubkey":lower_hex(&terms.script_pubkey),
        });
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "chain_fund", public_request, now)?;
        self.enqueue_watch(
            session_id,
            &effect_id,
            "refund_broadcast",
            &refund_payload,
            WatchDeadline::Height(u64::from(terms.refund_height)),
            now,
        )?;

        let transaction_id = match self.handle.block_on(self.bitcoind.broadcast(
            &rpc_id("reverse-funding", session_id)?,
            &funding.raw_transaction,
            None,
        )) {
            Ok(transaction_id) => transaction_id,
            Err(BitcoindError::Rpc { code: -27 }) => {
                self.handle
                    .block_on(self.bitcoind.raw_transaction(
                        &rpc_id("reverse-funding-replay", session_id)?,
                        &funding.txid,
                        false,
                    ))
                    .map_err(|error| format!("could not verify reverse funding replay: {error}"))?;
                funding.txid.clone()
            }
            Err(error) => return Err(format!("could not broadcast reverse funding: {error}")),
        };
        if transaction_id != funding.txid {
            return Err("bitcoind returned another reverse funding transaction ID".to_owned());
        }
        let public_result = json!({
            "fee_sat":funding.fee_sat,
            "refund_txid":refund_payload.expected_txid,
            "transaction_id":transaction_id,
            "vout":0,
        });
        self.complete_effect(
            &effect_id,
            &request_sha256,
            public_result.clone(),
            &funding.txid,
            now,
        )?;
        Ok((funding.txid, 0, public_result))
    }

    fn execute_liquid_reverse_funding(
        &mut self,
        session: &ProviderSession,
        terms: &ChainTerms,
        now: u64,
    ) -> Result<(String, u32, Value), String> {
        let session_id = &session.config().session_id;
        let liquid = self
            .liquid
            .clone()
            .ok_or_else(|| "Liquid reverse funding reached a disabled rail".to_owned())?;
        let funding_hex = terms
            .committed_funding_transaction
            .as_deref()
            .ok_or_else(|| "Liquid reverse has no committed funding transaction".to_owned())?;
        let funding_raw = decode_hex(funding_hex)?;
        let funding = parse_liquid_transaction(&funding_raw)
            .map_err(|error| format!("committed Liquid reverse funding is invalid: {error}"))?;
        let reservation_id = deterministic_id("reservation", session_id);
        let reserved_inputs = match self.reserved_liquid_inputs.get(session_id) {
            Some(inputs) => inputs.clone(),
            None => self.recover_reserved_liquid_inputs(&reservation_id)?,
        };
        validate_liquid_funding_inputs(&funding, &reserved_inputs)?;
        if lower_hex(&sha256(&funding_raw)) != terms.committed_funding_sha256 {
            return Err("Liquid reverse funding changed after the bilateral commitment".to_owned());
        }
        let funding_fee_sat = liquid_funding_fee_sat(&funding, liquid.pegged_asset())?;
        let maximum_funding_fee_sat = effect_fee_sat(
            LIQUID_SINGLE_INPUT_FUNDING_VBYTES,
            terms.fee_rate_sat_per_vbyte,
        )?;
        if funding_fee_sat > maximum_funding_fee_sat {
            return Err("Liquid reverse funding exceeds the signed fee budget".to_owned());
        }
        let destination = self
            .wallet
            .derive_address(settlement_destination_path(session_id)?)
            .map_err(|error| format!("could not derive Liquid refund destination: {error}"))?;
        let exit_package = self
            .handle
            .block_on(liquid.build_signed_exit_package(
                &format!("reverse-refund:{}", &session_id[..16]),
                &self.wallet,
                quote_allocation(session_id)?.unilateral_path,
                &funding_raw,
                terms.output_index,
                terms.amount_sat,
                &terms.script_pubkey,
                "refund",
                &terms.refund_script,
                &terms.refund_control_block,
                terms.refund_height,
                &destination.script_pubkey,
                exit_fee_sat(terms, SettlementPath::Refund)?,
                None,
            ))
            .map_err(|error| format!("could not pre-sign Liquid reverse refund: {error}"))?;
        let request = LiquidBeforeFundRequest {
            swap_type: LiquidSwapType::Reverse,
            purpose: LiquidLegPurpose::CounterpartyLock,
            input_asset_id: format!("swp:1:{}:btc:lightning", network_id(self.network)),
            output_asset_id: terms.asset_id.clone(),
            funding: LiquidFundingVerificationInput {
                raw_transaction: funding_hex.to_owned(),
                trusted_unblind_transaction: None,
                transaction_sha256: terms.committed_funding_sha256.clone(),
                output_index: terms.output_index,
                asset_id: terms.asset_id.clone(),
                amount: terms.amount_sat.to_string(),
                script_pubkey: lower_hex(&terms.script_pubkey),
                taproot_internal_key: terms.taproot_internal_key.clone(),
                taproot_merkle_root: Some(terms.taproot_merkle_root.clone()),
                confidentiality: LiquidConfidentiality::Explicit,
                minimum_confirmations: self.minimum_confirmations,
                replacement_policy: "reject".to_owned(),
            },
            exit_package,
        };
        let order = exactly_one_kind(session.signed_records(), MKT_ORDER_KIND, "Order")?;
        let effect_id = deterministic_id("reverse_fund", session_id);
        let receipt = self
            .handle
            .block_on(liquid.execute_funding_effect_with_operation(
                &mut self.store,
                &effect_id,
                session_id,
                &order.id,
                "destination",
                LiquidEffectOperation::ReverseFund,
                &request,
                now,
            ))
            .map_err(|error| format!("could not execute Liquid reverse funding: {error}"))?;
        let refund = parse_liquid_transaction(&decode_hex(&request.exit_package.transaction)?)
            .map_err(|error| format!("signed Liquid reverse refund is invalid: {error}"))?;
        let result = json!({
            "fee_sat":funding_fee_sat,
            "refund_txid":lower_hex(&refund.transaction_id),
            "transaction_id":receipt.transaction_id,
            "vout":terms.output_index,
        });
        Ok((receipt.transaction_id, terms.output_index, result))
    }

    fn execute_chain_destination_funding(
        &mut self,
        session: &ProviderSession,
        source: &ChainTerms,
        destination: &ChainTerms,
        now: u64,
    ) -> Result<(String, u32, Value), String> {
        if destination.rail == ChainRailKind::Bitcoin {
            return self.execute_reverse_funding(
                session,
                destination,
                chain_destination_unilateral_path(&session.config().session_id)?,
                now,
            );
        }
        let liquid = self
            .liquid
            .clone()
            .ok_or_else(|| "chain destination reached a disabled Liquid rail".to_owned())?;
        let funding_hex = destination
            .committed_funding_transaction
            .as_deref()
            .ok_or_else(|| "Liquid destination has no committed funding transaction".to_owned())?;
        let funding_raw = decode_hex(funding_hex)?;
        let funding = parse_liquid_transaction(&funding_raw)
            .map_err(|error| format!("committed Liquid destination funding is invalid: {error}"))?;
        let reservation_id = deterministic_id("reservation", &session.config().session_id);
        let reserved_inputs = match self
            .reserved_liquid_inputs
            .get(&session.config().session_id)
        {
            Some(inputs) => inputs.clone(),
            None => self.recover_reserved_liquid_inputs(&reservation_id)?,
        };
        validate_liquid_funding_inputs(&funding, &reserved_inputs)?;
        if lower_hex(&sha256(&funding_raw)) != destination.committed_funding_sha256 {
            return Err(
                "Liquid destination funding changed after the bilateral commitment".to_owned(),
            );
        }
        let funding_fee_sat = liquid_funding_fee_sat(&funding, liquid.pegged_asset())?;
        let maximum_funding_fee_sat = effect_fee_sat(
            LIQUID_SINGLE_INPUT_FUNDING_VBYTES,
            destination.fee_rate_sat_per_vbyte,
        )?;
        if funding_fee_sat > maximum_funding_fee_sat {
            return Err("Liquid destination funding exceeds the signed fee budget".to_owned());
        }
        let destination_address = self
            .wallet
            .derive_address(settlement_destination_path(&session.config().session_id)?)
            .map_err(|error| format!("could not derive Liquid refund destination: {error}"))?;
        let exit_package = self
            .handle
            .block_on(liquid.build_signed_exit_package(
                &format!("chain-refund:{}", &session.config().session_id[..16]),
                &self.wallet,
                chain_destination_unilateral_path(&session.config().session_id)?,
                &funding_raw,
                destination.output_index,
                destination.amount_sat,
                &destination.script_pubkey,
                "refund",
                &destination.refund_script,
                &destination.refund_control_block,
                destination.refund_height,
                &destination_address.script_pubkey,
                exit_fee_sat(destination, SettlementPath::Refund)?,
                None,
            ))
            .map_err(|error| format!("could not pre-sign Liquid destination refund: {error}"))?;
        let request = LiquidBeforeFundRequest {
            swap_type: LiquidSwapType::Chain,
            purpose: LiquidLegPurpose::CounterpartyLock,
            input_asset_id: source.asset_id.clone(),
            output_asset_id: destination.asset_id.clone(),
            funding: LiquidFundingVerificationInput {
                raw_transaction: funding_hex.to_owned(),
                trusted_unblind_transaction: None,
                transaction_sha256: destination.committed_funding_sha256.clone(),
                output_index: destination.output_index,
                asset_id: destination.asset_id.clone(),
                amount: destination.amount_sat.to_string(),
                script_pubkey: lower_hex(&destination.script_pubkey),
                taproot_internal_key: destination.taproot_internal_key.clone(),
                taproot_merkle_root: Some(destination.taproot_merkle_root.clone()),
                confidentiality: LiquidConfidentiality::Explicit,
                minimum_confirmations: self.minimum_confirmations,
                replacement_policy: "reject".to_owned(),
            },
            exit_package,
        };
        let order = exactly_one_kind(session.signed_records(), MKT_ORDER_KIND, "Order")?;
        let effect_id = deterministic_id("chain_fund", &session.config().session_id);
        let receipt = self
            .handle
            .block_on(liquid.execute_funding_effect_with_operation(
                &mut self.store,
                &effect_id,
                &session.config().session_id,
                &order.id,
                "destination",
                LiquidEffectOperation::ChainFund,
                &request,
                now,
            ))
            .map_err(|error| format!("could not execute Liquid destination funding: {error}"))?;
        let refund = parse_liquid_transaction(&decode_hex(&request.exit_package.transaction)?)
            .map_err(|error| format!("signed Liquid refund is invalid: {error}"))?;
        let public_result = json!({
            "fee_sat":funding_fee_sat,
            "refund_txid":lower_hex(&refund.transaction_id),
            "transaction_id":receipt.transaction_id,
            "vout":destination.output_index,
        });
        Ok((
            receipt.transaction_id,
            destination.output_index,
            public_result,
        ))
    }

    fn chain_destination_claim_preimage(
        &self,
        session: &ProviderSession,
        destination_funding: &RailChainObservation,
        claim_transaction_id: &str,
        destination: &ChainTerms,
    ) -> Result<[u8; 32], String> {
        required_hash(claim_transaction_id, "destination claim transaction ID")?;
        match destination_funding {
            RailChainObservation::Bitcoin(funding) => {
                let response = self
                    .handle
                    .block_on(self.bitcoind.raw_transaction(
                        &rpc_id("chain-destination-claim", &session.config().session_id)?,
                        claim_transaction_id,
                        true,
                    ))
                    .map_err(|error| format!("could not observe destination claim: {error}"))?;
                let object = response
                    .as_object()
                    .ok_or_else(|| "destination claim observation is not an object".to_owned())?;
                if object.get("txid").and_then(Value::as_str) != Some(claim_transaction_id) {
                    return Err(
                        "destination claim observation returned another transaction".to_owned()
                    );
                }
                require_chain_finality(
                    object,
                    self.minimum_confirmations,
                    self.reorg_safety_blocks,
                )?;
                let raw = object.get("hex").and_then(Value::as_str).ok_or_else(|| {
                    "destination claim observation has no raw transaction".to_owned()
                })?;
                let transaction = Transaction::parse(&decode_hex(raw)?)
                    .map_err(|error| format!("destination claim is invalid: {error}"))?;
                if transaction.inputs.len() != 1
                    || display_txid(&transaction.inputs[0].previous_txid) != funding.transaction_id
                    || transaction.inputs[0].previous_output != funding.output_index
                {
                    return Err(
                        "destination claim does not exclusively spend the contracted output"
                            .to_owned(),
                    );
                }
                let validated = validate_taproot_claim_witness(
                    &transaction,
                    &[TransactionOutput {
                        value_sat: destination.amount_sat,
                        script_pubkey: destination.script_pubkey.clone(),
                    }],
                    0,
                    &destination.claim_script,
                    &destination.claim_control_block,
                )
                .map_err(|error| format!("destination claim witness is invalid: {error}"))?;
                verify_validated_signature(&validated)?;
                transaction.inputs[0]
                    .witness
                    .get(1)
                    .and_then(|preimage| preimage.as_slice().try_into().ok())
                    .ok_or_else(|| "destination claim has no exact public preimage".to_owned())
            }
            RailChainObservation::Liquid(funding) => {
                let liquid = self
                    .liquid
                    .as_ref()
                    .ok_or_else(|| "destination claim reached a disabled Liquid rail".to_owned())?;
                let observation = self
                    .handle
                    .block_on(liquid.observe_transaction(
                        &rpc_id(
                            "chain-liquid-destination-claim",
                            &session.config().session_id,
                        )?,
                        claim_transaction_id,
                    ))
                    .map_err(|error| {
                        format!("could not observe Liquid destination claim: {error}")
                    })?;
                if observation.confirmations
                    < required_chain_confirmations(
                        self.minimum_confirmations,
                        self.reorg_safety_blocks,
                    )?
                    || observation.block_hash.is_none()
                {
                    return Err(
                        "Liquid destination claim has not reached reorg-safe finality".to_owned(),
                    );
                }
                let transaction = parse_liquid_transaction(&observation.raw_transaction)
                    .map_err(|error| format!("Liquid destination claim is invalid: {error}"))?;
                if lower_hex(&transaction.transaction_id) != claim_transaction_id
                    || transaction.inputs.len() != 1
                    || lower_hex(&transaction.inputs[0].previous_txid) != funding.transaction_id
                    || transaction.inputs[0].previous_output != funding.output_index
                {
                    return Err(
                        "Liquid destination claim does not exclusively spend the contracted output"
                            .to_owned(),
                    );
                }
                let witness = &transaction.inputs[0].script_witness;
                let [signature, preimage, script, control_block] = witness.as_slice() else {
                    return Err("Liquid destination claim witness has the wrong shape".to_owned());
                };
                let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                    "Liquid destination claim signature is not default sighash".to_owned()
                })?;
                let preimage: [u8; 32] = preimage.as_slice().try_into().map_err(|_| {
                    "Liquid destination claim preimage has another length".to_owned()
                })?;
                if script != &destination.claim_script
                    || control_block != &destination.claim_control_block
                    || lower_hex(&sha256(&preimage)) != destination.payment_hash
                {
                    return Err(
                        "Liquid destination claim witness differs from the Contract".to_owned()
                    );
                }
                let leaf = parse_swap_leaf_script(script).map_err(|error| {
                    format!("Liquid destination claim leaf is invalid: {error}")
                })?;
                if !matches!(leaf.condition, SwapLeafCondition::Hashlock(hash) if hash == sha256(&preimage))
                {
                    return Err("Liquid destination claim leaf has another hashlock".to_owned());
                }
                let genesis_hash = self
                    .handle
                    .block_on(liquid.genesis_hash(&rpc_id(
                        "chain-liquid-destination-genesis",
                        &session.config().session_id,
                    )?))
                    .map_err(|error| format!("could not bind Liquid genesis: {error}"))?;
                let sighash = liquid_taproot_script_spend_sighash(
                    &transaction,
                    &[LiquidPrevout {
                        asset: ConfidentialAsset::Explicit(liquid.pegged_asset()),
                        value: ConfidentialValue::Explicit(destination.amount_sat),
                        script_pubkey: destination.script_pubkey.clone(),
                    }],
                    0,
                    genesis_hash,
                    script,
                    control_block,
                    None,
                )
                .map_err(|error| format!("Liquid destination claim sighash is invalid: {error}"))?;
                verify_liquid_taproot_sighash_signature(sighash, &signature, leaf.signing_key)
                    .map_err(|error| {
                        format!("Liquid destination claim signature is invalid: {error}")
                    })?;
                Ok(preimage)
            }
        }
    }

    fn execute_chain_source_claim(
        &mut self,
        session: &ProviderSession,
        source_funding: &RailChainObservation,
        source: &ChainTerms,
        destination: &ChainTerms,
        preimage: [u8; 32],
        now: u64,
    ) -> Result<(String, Value), String> {
        if lower_hex(&sha256(&preimage)) != source.payment_hash {
            return Err("chain source claim preimage differs from the Contract".to_owned());
        }
        let session_id = &session.config().session_id;
        match source_funding {
            RailChainObservation::Bitcoin(observation) => {
                let public_request = json!({
                    "destination_asset_id":destination.asset_id,
                    "destination_claim_sha256":lower_hex(&sha256(&preimage)),
                    "source_asset_id":source.asset_id,
                    "source_transaction_id":observation.transaction_id,
                    "source_vout":observation.output_index,
                });
                let (effect_id, request_sha256) =
                    self.persist_effect_request(session_id, "chain_claim", public_request, now)?;
                let template = self.settlement_template(
                    session_id,
                    observation,
                    source,
                    SettlementPath::Claim,
                )?;
                let signed = SettlementBridge::new(&self.wallet)
                    .claim(&template, ClaimPreimage::new(preimage))
                    .map_err(|error| format!("could not construct chain source claim: {error}"))?;
                let payload = BroadcastWatchPayload::released_claim(
                    lower_hex(&signed.into_broadcast_bytes()),
                    ClaimReleaseEvidence {
                        payment_hash: source.payment_hash.clone(),
                        settled_at: now,
                    },
                )
                .map_err(|error| format!("could not bind chain source claim watch: {error}"))?;
                let (job_id, watch_request_sha256) = self.enqueue_watch(
                    session_id,
                    &effect_id,
                    "chain_source_claim_broadcast",
                    &payload,
                    WatchDeadline::Time(now),
                    now,
                )?;
                self.broadcast_watch_now(
                    session_id,
                    &job_id,
                    &watch_request_sha256,
                    &payload,
                    now,
                )?;
                let result = json!({
                    "claim_txid":payload.expected_txid,
                    "payment_hash":source.payment_hash,
                });
                self.complete_effect(
                    &effect_id,
                    &request_sha256,
                    result.clone(),
                    &payload.expected_txid,
                    now,
                )?;
                Ok((payload.expected_txid, result))
            }
            RailChainObservation::Liquid(observation) => {
                let liquid = self.liquid.clone().ok_or_else(|| {
                    "chain source claim reached a disabled Liquid rail".to_owned()
                })?;
                let effect_id = deterministic_id("chain_claim", session_id);
                let request = if let Some(request) = self.stored_provider_liquid_exit_request(
                    &effect_id,
                    LiquidEffectOperation::ChainClaim,
                )? {
                    request
                } else {
                    let funding = self
                        .handle
                        .block_on(liquid.observe_transaction(
                            &rpc_id("chain-liquid-source-funding", session_id)?,
                            &observation.transaction_id,
                        ))
                        .map_err(|error| {
                            format!("could not recover Liquid source funding: {error}")
                        })?;
                    let destination_address = self
                        .wallet
                        .derive_address(settlement_destination_path(session_id)?)
                        .map_err(|error| {
                            format!("could not derive Liquid claim destination: {error}")
                        })?;
                    let package = self
                        .handle
                        .block_on(liquid.build_signed_exit_package(
                            &format!("chain-claim:{}", &session_id[..16]),
                            &self.wallet,
                            quote_allocation(session_id)?.unilateral_path,
                            &funding.raw_transaction,
                            observation.output_index,
                            source.amount_sat,
                            &source.script_pubkey,
                            "claim",
                            &source.claim_script,
                            &source.claim_control_block,
                            0,
                            &destination_address.script_pubkey,
                            exit_fee_sat(source, SettlementPath::Claim)?,
                            Some(preimage),
                        ))
                        .map_err(|error| format!("could not sign Liquid source claim: {error}"))?;
                    ProviderLiquidExitRequest {
                        funding: LiquidFundingVerificationInput {
                            raw_transaction: lower_hex(&funding.raw_transaction),
                            trusted_unblind_transaction: None,
                            transaction_sha256: lower_hex(&sha256(&funding.raw_transaction)),
                            output_index: observation.output_index,
                            asset_id: source.asset_id.clone(),
                            amount: source.amount_sat.to_string(),
                            script_pubkey: lower_hex(&source.script_pubkey),
                            taproot_internal_key: source.taproot_internal_key.clone(),
                            taproot_merkle_root: Some(source.taproot_merkle_root.clone()),
                            confidentiality: LiquidConfidentiality::Explicit,
                            minimum_confirmations: self.minimum_confirmations,
                            replacement_policy: "reject".to_owned(),
                        },
                        exit_package: package,
                    }
                };
                if request.exit_package.path != "claim"
                    || request.exit_package.funding_transaction_id != observation.transaction_id
                    || request.exit_package.funding_output_index != observation.output_index
                    || request.exit_package.funding_amount != source.amount_sat.to_string()
                    || request.funding.asset_id != source.asset_id
                    || request.funding.script_pubkey != lower_hex(&source.script_pubkey)
                {
                    return Err("stored Liquid source claim differs from the Contract".to_owned());
                }
                let order = exactly_one_kind(session.signed_records(), MKT_ORDER_KIND, "Order")?;
                let receipt = self
                    .handle
                    .block_on(liquid.execute_provider_exit_effect(
                        &mut self.store,
                        &effect_id,
                        session_id,
                        &order.id,
                        "source",
                        LiquidEffectOperation::ChainClaim,
                        &request,
                        now,
                    ))
                    .map_err(|error| format!("could not broadcast Liquid source claim: {error}"))?;
                let result = json!({
                    "claim_txid":receipt.transaction_id,
                    "payment_hash":source.payment_hash,
                });
                Ok((receipt.transaction_id, result))
            }
        }
    }

    fn chain_rail_height(
        &self,
        label: &str,
        session_id: &str,
        rail: ChainRailKind,
    ) -> Result<u64, String> {
        match rail {
            ChainRailKind::Bitcoin => self
                .handle
                .block_on(self.bitcoind.chain_tip(&rpc_id(label, session_id)?))
                .map(|tip| tip.height)
                .map_err(|error| format!("could not inspect Bitcoin recovery height: {error}")),
            ChainRailKind::Liquid => {
                let liquid = self
                    .liquid
                    .as_ref()
                    .ok_or_else(|| "Liquid recovery reached a disabled rail".to_owned())?;
                self.handle
                    .block_on(liquid.network_view(&format!("chain-recovery:{}", &session_id[..16])))
                    .map(|view| view.height)
                    .map_err(|error| format!("could not inspect Liquid recovery height: {error}"))
            }
        }
    }

    fn chain_effect_is_final(
        &self,
        label: &str,
        session_id: &str,
        rail: ChainRailKind,
        bitcoin_watch_kind: &str,
        transaction_id: &str,
        required_confirmations: u32,
    ) -> Result<bool, String> {
        required_hash(transaction_id, "chain effect transaction ID")?;
        match rail {
            ChainRailKind::Bitcoin => {
                let job = self.watch_job(bitcoin_watch_kind, session_id)?;
                let Some(observed_transaction_id) = job
                    .replacement_txid
                    .as_deref()
                    .or(job.broadcast_txid.as_deref())
                else {
                    return Ok(false);
                };
                if observed_transaction_id != transaction_id {
                    return Err("chain effect Status differs from its durable watch".to_owned());
                }
                Ok(job.state == "confirmed" && job.confirmations >= required_confirmations)
            }
            ChainRailKind::Liquid => {
                let liquid = self
                    .liquid
                    .as_ref()
                    .ok_or_else(|| "Liquid effect finality reached a disabled rail".to_owned())?;
                let observation = self
                    .handle
                    .block_on(
                        liquid.observe_transaction(&rpc_id(label, session_id)?, transaction_id),
                    )
                    .map_err(|error| format!("could not confirm Liquid chain effect: {error}"))?;
                Ok(observation.confirmations >= required_confirmations
                    && observation.block_hash.is_some())
            }
        }
    }

    fn chain_source_refund_is_final(
        &self,
        session: &ProviderSession,
        source: &ChainTerms,
        refund_status: &Event,
        required_confirmations: u32,
    ) -> Result<bool, String> {
        let session_id = &session.config().session_id;
        let refund_transaction_id = status_transaction_id(refund_status)?;
        let funding_status = status_by_state(
            session.signed_records(),
            &session.config().requester_pubkey,
            "requester_source_broadcast",
        )
        .ok_or_else(|| "requester source refund has no source funding Status".to_owned())?;
        let (funding_transaction_id, funding_output_index) =
            status_transaction_reference(funding_status)?;
        match source.rail {
            ChainRailKind::Bitcoin => {
                let funding = self.observe_chain_funding(
                    session_id,
                    &funding_transaction_id,
                    funding_output_index,
                    source,
                )?;
                let observed = self.reverse_spending_transaction(session_id, &funding)?;
                if observed.as_deref() != Some(refund_transaction_id.as_str()) {
                    return Err(
                        "requester source refund differs from the observed funding spend"
                            .to_owned(),
                    );
                }
                let response = self
                    .handle
                    .block_on(self.bitcoind.raw_transaction(
                        &rpc_id("chain-source-refund-final", session_id)?,
                        &refund_transaction_id,
                        true,
                    ))
                    .map_err(|error| {
                        format!("could not inspect requester source refund: {error}")
                    })?;
                let object = response.as_object().ok_or_else(|| {
                    "requester source refund response is not an object".to_owned()
                })?;
                if object.get("txid").and_then(Value::as_str)
                    != Some(refund_transaction_id.as_str())
                {
                    return Err("requester source refund returned another transaction".to_owned());
                }
                let confirmations = object
                    .get("confirmations")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                Ok(confirmations >= u64::from(required_confirmations)
                    && object.get("blockhash").and_then(Value::as_str).is_some())
            }
            ChainRailKind::Liquid => {
                let liquid = self
                    .liquid
                    .as_ref()
                    .ok_or_else(|| "Liquid source refund reached a disabled rail".to_owned())?;
                let observed = self
                    .handle
                    .block_on(liquid.spending_transaction(
                        &format!("liquid-source-refund:{}", &session_id[..16]),
                        &funding_transaction_id,
                        funding_output_index,
                    ))
                    .map_err(|error| format!("could not inspect Liquid source refund: {error}"))?;
                if observed.as_deref() != Some(refund_transaction_id.as_str()) {
                    return Err(
                        "requester Liquid source refund differs from the observed funding spend"
                            .to_owned(),
                    );
                }
                let refund = self
                    .handle
                    .block_on(liquid.observe_transaction(
                        &rpc_id("liquid-chain-source-refund-final", session_id)?,
                        &refund_transaction_id,
                    ))
                    .map_err(|error| {
                        format!("could not confirm requester Liquid source refund: {error}")
                    })?;
                Ok(refund.confirmations >= required_confirmations && refund.block_hash.is_some())
            }
        }
    }

    fn execute_chain_destination_refund(
        &mut self,
        session: &ProviderSession,
        destination: &ChainTerms,
        now: u64,
    ) -> Result<(String, Value), String> {
        let session_id = &session.config().session_id;
        match destination.rail {
            ChainRailKind::Bitcoin => {
                let job = self.watch_job("refund_broadcast", session_id)?;
                let transaction_id = job
                    .replacement_txid
                    .as_ref()
                    .or(job.broadcast_txid.as_ref())
                    .cloned()
                    .ok_or_else(|| "Bitcoin destination refund is not broadcast yet".to_owned())?;
                let result = json!({
                    "transaction_id":transaction_id,
                    "watch_job_id":job.job_id,
                    "watch_state":job.state,
                });
                Ok((transaction_id, result))
            }
            ChainRailKind::Liquid => {
                let liquid = self
                    .liquid
                    .clone()
                    .ok_or_else(|| "Liquid refund reached a disabled rail".to_owned())?;
                let refund_effect_id = deterministic_id("chain_refund", session_id);
                let (funding_effect_id, request) = if let Some(request) = self
                    .stored_provider_liquid_exit_request(
                        &refund_effect_id,
                        LiquidEffectOperation::ChainRefund,
                    )? {
                    (deterministic_id("chain_fund", session_id), request)
                } else {
                    let funding_effect_id = deterministic_id("chain_fund", session_id);
                    let funding_effect = self
                        .handle
                        .block_on(self.store.public_effect(&funding_effect_id))
                        .map_err(|error| {
                            format!("could not recover Liquid funding effect: {error}")
                        })?
                        .ok_or_else(|| {
                            "Liquid funding effect is absent after restart".to_owned()
                        })?;
                    if funding_effect.request.operation != "liquid_chain_fund"
                        || funding_effect.state != "applied"
                    {
                        return Err(
                            "Liquid funding effect is not an applied funding request".to_owned()
                        );
                    }
                    let request: LiquidBeforeFundRequest =
                        serde_json::from_value(funding_effect.request.public_request)
                            .map_err(|_| "stored Liquid funding request is invalid".to_owned())?;
                    (
                        funding_effect_id,
                        ProviderLiquidExitRequest::from_before_fund(&request),
                    )
                };
                if request.exit_package.path != "refund"
                    || request.exit_package.funding_output_index != destination.output_index
                    || request.exit_package.funding_amount != destination.amount_sat.to_string()
                    || request.funding.asset_id != destination.asset_id
                    || request.funding.script_pubkey != lower_hex(&destination.script_pubkey)
                {
                    return Err("stored Liquid refund package differs from the Contract".to_owned());
                }
                let order = exactly_one_kind(session.signed_records(), MKT_ORDER_KIND, "Order")?;
                let receipt = self
                    .handle
                    .block_on(liquid.execute_provider_exit_effect(
                        &mut self.store,
                        &refund_effect_id,
                        session_id,
                        &order.id,
                        "destination",
                        LiquidEffectOperation::ChainRefund,
                        &request,
                        now,
                    ))
                    .map_err(|error| {
                        format!("could not execute Liquid destination refund: {error}")
                    })?;
                let result = json!({
                    "transaction_id":receipt.transaction_id,
                    "funding_effect_id":funding_effect_id,
                    "refund_effect_id":refund_effect_id,
                });
                Ok((receipt.transaction_id, result))
            }
        }
    }

    fn stored_provider_liquid_exit_request(
        &self,
        effect_id: &str,
        operation: LiquidEffectOperation,
    ) -> Result<Option<ProviderLiquidExitRequest>, String> {
        let Some(effect) = self
            .handle
            .block_on(self.store.public_effect(effect_id))
            .map_err(|error| format!("could not recover Liquid exit effect: {error}"))?
        else {
            return Ok(None);
        };
        if effect.request.operation != operation.as_str() {
            return Err("Liquid exit effect has another operation".to_owned());
        }
        serde_json::from_value(effect.request.public_request)
            .map(Some)
            .map_err(|_| "stored Liquid exit request is invalid".to_owned())
    }

    fn applied_liquid_effect_transaction_id(
        &self,
        effect_id: &str,
        operation: LiquidEffectOperation,
    ) -> Result<String, String> {
        let effect = self
            .handle
            .block_on(self.store.public_effect(effect_id))
            .map_err(|error| format!("could not recover Liquid effect: {error}"))?
            .ok_or_else(|| "Liquid effect is absent after restart".to_owned())?;
        if effect.request.operation != operation.as_str() || effect.state != "applied" {
            return Err("Liquid effect is not the expected applied operation".to_owned());
        }
        let transaction_id = effect
            .external_reference
            .ok_or_else(|| "applied Liquid effect has no transaction ID".to_owned())?;
        required_hash(&transaction_id, "applied Liquid effect transaction ID")?;
        Ok(transaction_id)
    }

    fn reverse_spending_transaction(
        &self,
        session_id: &str,
        observation: &ChainObservation,
    ) -> Result<Option<String>, String> {
        let result = self
            .handle
            .block_on(self.bitcoind.call(
                &rpc_id("reverse-spend", session_id)?,
                "gettxspendingprevout",
                json!([[{
                    "txid":observation.transaction_id,
                    "vout":observation.output_index,
                }]]),
            ))
            .map_err(|error| format!("could not inspect reverse claim: {error}"))?;
        let entries = result
            .as_array()
            .ok_or_else(|| "reverse spend observation is not an array".to_owned())?;
        if entries.len() != 1 {
            return Err("reverse spend observation has an unexpected cardinality".to_owned());
        }
        Ok(entries[0]
            .get("spendingtxid")
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    fn settle_reverse_claim(
        &mut self,
        session: &ProviderSession,
        funding: &ChainObservation,
        spending_transaction_id: &str,
        terms: &ChainTerms,
        now: u64,
    ) -> Result<Value, String> {
        let session_id = &session.config().session_id;
        let response = self
            .handle
            .block_on(self.bitcoind.raw_transaction(
                &rpc_id("reverse-claim", session_id)?,
                spending_transaction_id,
                true,
            ))
            .map_err(|error| format!("could not read reverse claim: {error}"))?;
        let object = response
            .as_object()
            .ok_or_else(|| "reverse claim observation is not an object".to_owned())?;
        require_chain_finality(object, self.minimum_confirmations, self.reorg_safety_blocks)?;
        let raw = object
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "reverse claim observation has no raw transaction".to_owned())?;
        let transaction = Transaction::parse(&decode_hex(raw)?)
            .map_err(|error| format!("reverse claim transaction is invalid: {error}"))?;
        let input_index = transaction
            .inputs
            .iter()
            .position(|input| {
                display_txid(&input.previous_txid) == funding.transaction_id
                    && input.previous_output == funding.output_index
            })
            .ok_or_else(|| {
                "reverse claim does not spend the contracted funding output".to_owned()
            })?;
        let prevouts = transaction
            .inputs
            .iter()
            .map(|input| {
                if display_txid(&input.previous_txid) == funding.transaction_id
                    && input.previous_output == funding.output_index
                {
                    Ok(TransactionOutput {
                        value_sat: terms.amount_sat,
                        script_pubkey: terms.script_pubkey.clone(),
                    })
                } else {
                    Err("reverse claim has unsupported additional inputs".to_owned())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let validated = validate_taproot_claim_witness(
            &transaction,
            &prevouts,
            input_index,
            &terms.claim_script,
            &terms.claim_control_block,
        )
        .map_err(|error| format!("reverse claim witness is invalid: {error}"))?;
        verify_validated_signature(&validated)?;
        let preimage = transaction
            .inputs
            .get(input_index)
            .and_then(|input| input.witness.get(1))
            .filter(|preimage| preimage.len() == 32)
            .ok_or_else(|| "reverse claim has no exact public preimage".to_owned())?;
        if lower_hex(&sha256(preimage)) != terms.payment_hash {
            return Err("reverse claim preimage does not match the hold invoice".to_owned());
        }
        let preimage = <[u8; 32]>::try_from(preimage.as_slice())
            .map_err(|_| "reverse claim preimage has another length".to_owned())?;
        self.settle_reverse_preimage(session_id, spending_transaction_id, terms, preimage, now)
    }

    fn settle_reverse_preimage(
        &mut self,
        session_id: &str,
        spending_transaction_id: &str,
        terms: &ChainTerms,
        preimage: [u8; 32],
        now: u64,
    ) -> Result<Value, String> {
        let public_request = json!({
            "claim_txid":spending_transaction_id,
            "payment_hash":terms.payment_hash,
        });
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "invoice_settle", public_request, now)?;
        let preimage = LightningPreimage::new(preimage);
        let settle_result = self.handle.block_on(
            self.lightning
                .settle_hold_invoice(&lightning_id("hold-settle", session_id)?, preimage),
        );
        settle_result.map_err(|error| format!("could not settle reverse hold invoice: {error}"))?;
        self.complete_reverse_settlement_effect(
            session_id,
            spending_transaction_id,
            &terms.payment_hash,
            &effect_id,
            &request_sha256,
            now,
        )
    }

    fn reconcile_reverse_settlement_effect(
        &mut self,
        session_id: &str,
        spending_transaction_id: &str,
        payment_hash: &str,
        now: u64,
    ) -> Result<Value, String> {
        let public_request = json!({
            "claim_txid":spending_transaction_id,
            "payment_hash":payment_hash,
        });
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "invoice_settle", public_request, now)?;
        self.complete_reverse_settlement_effect(
            session_id,
            spending_transaction_id,
            payment_hash,
            &effect_id,
            &request_sha256,
            now,
        )
    }

    fn complete_reverse_settlement_effect(
        &mut self,
        session_id: &str,
        spending_transaction_id: &str,
        payment_hash: &str,
        effect_id: &str,
        request_sha256: &str,
        now: u64,
    ) -> Result<Value, String> {
        let state = self.reverse_hold_state(session_id, payment_hash)?;
        if !matches!(state.as_str(), "paid" | "settled") {
            return Err("reverse hold invoice did not reach a settled state".to_owned());
        }
        let public_result = json!({
            "claim_txid":spending_transaction_id,
            "payment_hash":payment_hash,
            "state":"settled",
        });
        self.complete_effect(
            effect_id,
            request_sha256,
            public_result.clone(),
            spending_transaction_id,
            now,
        )?;
        Ok(public_result)
    }

    fn reverse_claim_is_final(
        &self,
        session_id: &str,
        transaction_id: &str,
    ) -> Result<bool, String> {
        let response = self
            .handle
            .block_on(self.bitcoind.raw_transaction(
                &rpc_id("reverse-claim-finality", session_id)?,
                transaction_id,
                true,
            ))
            .map_err(|error| format!("could not inspect reverse claim finality: {error}"))?;
        let object = response
            .as_object()
            .ok_or_else(|| "reverse claim finality response is not an object".to_owned())?;
        if object.get("txid").and_then(Value::as_str) != Some(transaction_id) {
            return Err("reverse claim finality returned another transaction".to_owned());
        }
        match require_chain_finality(object, self.minimum_confirmations, self.reorg_safety_blocks) {
            Ok(()) => Ok(true),
            Err(error) if error == "chain transaction has not reached reorg-safe finality" => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn cancel_reverse_invoice(
        &mut self,
        session_id: &str,
        payment_hash: &str,
        now: u64,
    ) -> Result<Value, String> {
        let public_request = json!({"payment_hash":payment_hash});
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "invoice_cancel", public_request, now)?;
        let response = self
            .handle
            .block_on(self.lightning.hold_invoice_state(
                &lightning_id("hold-cancel-state", session_id)?,
                payment_hash,
            ))
            .map_err(|error| format!("could not inspect reverse hold invoice: {error}"))?;
        let invoice = matching_hold_invoice(&response, payment_hash)?;
        let state = hold_invoice_state(invoice)?;
        if reverse_invoice_cancellation_action(&state)?
            == ReverseInvoiceCancellationAction::CancelRemotely
        {
            self.handle
                .block_on(
                    self.lightning.cancel_hold_invoice(
                        &lightning_id("hold-cancel", session_id)?,
                        payment_hash,
                    ),
                )
                .map_err(|error| format!("could not cancel reverse hold invoice: {error}"))?;
            let response = self
                .handle
                .block_on(self.lightning.hold_invoice_state(
                    &lightning_id("hold-cancel-confirm", session_id)?,
                    payment_hash,
                ))
                .map_err(|error| {
                    format!("could not confirm reverse hold invoice cancellation: {error}")
                })?;
            let invoice = matching_hold_invoice(&response, payment_hash)?;
            let state = hold_invoice_state(invoice)?;
            if reverse_invoice_cancellation_action(&state)?
                != ReverseInvoiceCancellationAction::CompleteLocally
            {
                return Err("reverse hold invoice cancellation was not confirmed".to_owned());
            }
        }
        let result = json!({"payment_hash":payment_hash,"state":"cancelled"});
        self.complete_effect(
            &effect_id,
            &request_sha256,
            result.clone(),
            payment_hash,
            now,
        )?;
        Ok(result)
    }

    fn cancel_unfunded_reverse(&mut self, session_id: &str, now: u64) -> Result<(), String> {
        let records = self
            .handle
            .block_on(self.store.session_records(session_id, 120))
            .map_err(|error| format!("could not recover reverse cancellation history: {error}"))?;
        let Some(rfq) = records.iter().find(|record| record.kind == MKT_RFQ_KIND) else {
            return Ok(());
        };
        if rfq_swap_type(rfq)? != "reverse" {
            return Ok(());
        }
        let profile = record_profile(rfq)?;
        let payment_hash = profile
            .get("constraints")
            .and_then(Value::as_object)
            .and_then(|constraints| constraints.get("payment_hash"))
            .and_then(Value::as_str)
            .ok_or_else(|| "reverse RFQ has no cancellation payment hash".to_owned())?;
        let response = self
            .handle
            .block_on(self.lightning.hold_invoice_state(
                &lightning_id("hold-cancel-state", session_id)?,
                payment_hash,
            ))
            .map_err(|error| format!("could not inspect reverse hold invoice: {error}"))?;
        let Some(invoice) = matching_hold_invoice_optional(&response, payment_hash) else {
            return Ok(());
        };
        hold_invoice_state(invoice)?;
        self.cancel_reverse_invoice(session_id, payment_hash, now)?;
        Ok(())
    }

    fn dispose_unfunded_session(
        &mut self,
        session: &ProviderSession,
        reason_code: &str,
        observed_at: u64,
    ) -> Result<(), String> {
        let session_id = &session.config().session_id;
        self.cancel_unfunded_reverse(session_id, observed_at)?;
        self.release_session_reservation(session_id, observed_at)?;
        self.handle
            .block_on(
                self.store
                    .dispose_session(session_id, reason_code, observed_at),
            )
            .map(|_| ())
            .map_err(|error| format!("could not persist session disposition: {error}"))
    }

    fn reverse_invoice_for_session(&mut self, session: &ProviderSession) -> Result<String, String> {
        let session_id = &session.config().session_id;
        if let Some(invoice) = self.session_invoices.get(session_id) {
            return Ok(invoice.clone());
        }
        let terms = chain_terms(session, "reverse")?;
        let response = self
            .handle
            .block_on(self.lightning.hold_invoice_state(
                &lightning_id("hold-recover", session_id)?,
                &terms.payment_hash,
            ))
            .map_err(|error| format!("could not recover reverse hold invoice: {error}"))?;
        let invoice_record = matching_hold_invoice(&response, &terms.payment_hash)?;
        let invoice = invoice_record
            .get("invoice")
            .or_else(|| invoice_record.get("bolt11"))
            .and_then(Value::as_str)
            .ok_or_else(|| "recoverable reverse hold invoice has no BOLT11".to_owned())?
            .to_owned();
        self.session_invoices
            .insert(session_id.clone(), invoice.clone());
        Ok(invoice)
    }

    fn watch_job(&self, kind: &str, session_id: &str) -> Result<WatchJob, String> {
        let job_id = deterministic_id(kind, session_id);
        self.handle
            .block_on(self.store.watch_job(&job_id))
            .map_err(|error| format!("could not inspect {kind}: {error}"))?
            .ok_or_else(|| format!("session has no durable {kind} job"))
    }

    fn submarine_claim_watch(&self, session_id: &str) -> Result<WatchJob, String> {
        let cooperative_id = deterministic_id("cooperative_broadcast", session_id);
        if let Some(job) = self
            .handle
            .block_on(self.store.watch_job(&cooperative_id))
            .map_err(|error| format!("could not inspect cooperative claim: {error}"))?
        {
            return Ok(job);
        }
        self.watch_job("claim_broadcast", session_id)
    }

    fn next_reverse_after_funding(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        terms: &ChainTerms,
    ) -> Result<Option<MktSigningRequest>, String> {
        if terms.rail == ChainRailKind::Liquid {
            return self.next_liquid_reverse_after_funding(session, created_at, terms);
        }
        let records = session.signed_records();
        let funding_status = status_by_state(
            records,
            &session.config().provider_pubkey,
            "provider_funding_broadcast",
        )
        .ok_or_else(|| "reverse funding Status is unavailable".to_owned())?;
        let (transaction_id, output_index) = status_transaction_reference(funding_status)?;
        let observation = self.observe_chain_funding(
            &session.config().session_id,
            &transaction_id,
            output_index,
            terms,
        )?;
        if observation.confirmations < self.minimum_confirmations {
            return Err("reverse funding lost required confirmation".to_owned());
        }
        let refund_job = self.watch_job("refund_broadcast", &session.config().session_id)?;
        let observed_spending =
            self.reverse_spending_transaction(&session.config().session_id, &observation)?;
        if reverse_spend_decision(
            observed_spending.as_deref(),
            refund_job.broadcast_txid.as_deref(),
            refund_job.replacement_txid.as_deref(),
            false,
        ) == ReverseSpendDecision::ProviderRefund
        {
            let evidence = watch_evidence(session, &refund_job, "refund", "measured", created_at)?;
            return Self::next_status_with_evidence(
                session,
                created_at,
                "provider_refund_prepared",
                evidence,
                watch_extra(&refund_job),
            )
            .map(Some);
        }
        let announced_claim_status = status_by_state(
            records,
            &session.config().requester_pubkey,
            "requester_claimed",
        );
        let announced_claim = announced_claim_status
            .map(status_transaction_id)
            .transpose()?;
        let spending = match (observed_spending, announced_claim) {
            (Some(observed), Some(announced)) if observed != announced => {
                return Err(
                    "requester claim Status conflicts with the observed funding spend".to_owned(),
                );
            }
            (Some(observed), _) => Some(observed),
            (None, announced) => announced,
        };
        if let Some(spending_transaction_id) = spending {
            let Some(claim_status) = announced_claim_status else {
                return Ok(None);
            };
            let initial_decision = reverse_spend_decision(
                Some(&spending_transaction_id),
                refund_job.broadcast_txid.as_deref(),
                refund_job.replacement_txid.as_deref(),
                false,
            );
            if initial_decision == ReverseSpendDecision::ProviderRefund {
                let evidence =
                    watch_evidence(session, &refund_job, "refund", "measured", created_at)?;
                return Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_refund_prepared",
                    evidence,
                    watch_extra(&refund_job),
                )
                .map(Some);
            }
            let claim_is_final = self
                .reverse_claim_is_final(&session.config().session_id, &spending_transaction_id)?;
            let decision = reverse_spend_decision(
                Some(&spending_transaction_id),
                refund_job.broadcast_txid.as_deref(),
                refund_job.replacement_txid.as_deref(),
                claim_is_final,
            );
            let Some(completion_reason) = decision.refund_watch_completion_reason() else {
                return Ok(None);
            };
            let state =
                self.reverse_hold_state(&session.config().session_id, &terms.payment_hash)?;
            let result = if matches!(state.as_str(), "paid" | "settled") {
                self.reconcile_reverse_settlement_effect(
                    &session.config().session_id,
                    &spending_transaction_id,
                    &terms.payment_hash,
                    created_at,
                )?
            } else {
                self.settle_reverse_claim(
                    session,
                    &observation,
                    &spending_transaction_id,
                    terms,
                    created_at,
                )?
            };
            self.handle
                .block_on(self.store.complete_watch_job(
                    &refund_job.job_id,
                    completion_reason,
                    created_at,
                ))
                .map_err(|error| format!("could not retire reverse refund watch: {error}"))?;
            let evidence = bitcoin_spend_evidence(
                session,
                &observation.transaction_id,
                observation.output_index,
                "settled",
                &result,
                created_at,
                "requester claim verified before hold settlement",
            )?;
            return Self::next_status_with_evidence_after(
                session,
                created_at,
                "lightning_settlement_pending",
                &claim_status.id,
                evidence,
                Map::new(),
            )
            .map(Some);
        }

        let tip = self
            .handle
            .block_on(
                self.bitcoind
                    .chain_tip(&rpc_id("reverse-refund-tip", &session.config().session_id)?),
            )
            .map_err(|error| format!("could not inspect reverse refund height: {error}"))?;
        if tip.height < u64::from(terms.refund_height) {
            return Ok(None);
        }
        let evidence = watch_evidence(session, &refund_job, "refund", "reserved", created_at)?;
        Self::next_status_with_evidence(
            session,
            created_at,
            "provider_refund_prepared",
            evidence,
            watch_extra(&refund_job),
        )
        .map(Some)
    }

    fn next_liquid_reverse_after_funding(
        &mut self,
        session: &ProviderSession,
        created_at: u64,
        terms: &ChainTerms,
    ) -> Result<Option<MktSigningRequest>, String> {
        let records = session.signed_records();
        let session_id = &session.config().session_id;
        let funding_status = status_by_state(
            records,
            &session.config().provider_pubkey,
            "provider_funding_broadcast",
        )
        .ok_or_else(|| "Liquid reverse funding Status is unavailable".to_owned())?;
        let (funding_transaction_id, funding_output_index) =
            status_transaction_reference(funding_status)?;
        let announced_claim_status = status_by_state(
            records,
            &session.config().requester_pubkey,
            "requester_claimed",
        );
        let funding = if announced_claim_status.is_some() {
            self.observe_claimed_contract_funding(
                session_id,
                &funding_transaction_id,
                funding_output_index,
                terms,
            )?
        } else {
            self.observe_contract_funding(
                session_id,
                &funding_transaction_id,
                funding_output_index,
                terms,
            )?
        };
        let required_confirmations =
            required_chain_confirmations(self.minimum_confirmations, self.reorg_safety_blocks)?;
        if funding.confirmations() < required_confirmations {
            return Ok(None);
        }
        let liquid = self
            .liquid
            .clone()
            .ok_or_else(|| "Liquid reverse reached a disabled rail".to_owned())?;
        let funding_effect_id = deterministic_id("reverse_fund", session_id);
        let funding_effect = self
            .handle
            .block_on(self.store.public_effect(&funding_effect_id))
            .map_err(|error| format!("could not recover Liquid reverse funding effect: {error}"))?
            .ok_or_else(|| "Liquid reverse funding effect is absent after restart".to_owned())?;
        if funding_effect.request.operation != LiquidEffectOperation::ReverseFund.as_str()
            || funding_effect.state != "applied"
        {
            return Err("Liquid reverse funding effect is not applied".to_owned());
        }
        let funding_request: LiquidBeforeFundRequest =
            serde_json::from_value(funding_effect.request.public_request)
                .map_err(|_| "stored Liquid reverse funding request is invalid".to_owned())?;
        let refund_request = ProviderLiquidExitRequest::from_before_fund(&funding_request);
        let refund_effect_id = deterministic_id("reverse_refund", session_id);
        let recovered_refund = self
            .handle
            .block_on(self.store.public_effect(&refund_effect_id))
            .map_err(|error| format!("could not recover Liquid reverse refund: {error}"))?
            .map(|effect| {
                if effect.request.operation != LiquidEffectOperation::ReverseRefund.as_str() {
                    return Err("Liquid reverse refund effect has another operation".to_owned());
                }
                let request = serde_json::from_value(effect.request.public_request)
                    .map_err(|_| "stored Liquid reverse refund request is invalid".to_owned())?;
                Ok((effect.state, request))
            })
            .transpose()?;
        let recovered_refund_transaction_id = if let Some((_, request)) =
            recovered_refund.filter(|(state, _)| {
                recover_liquid_reverse_refund_before_claim(state, announced_claim_status.is_some())
            }) {
            let order = exactly_one_kind(records, MKT_ORDER_KIND, "Order")?;
            Some(
                self.handle
                    .block_on(liquid.execute_provider_exit_effect(
                        &mut self.store,
                        &refund_effect_id,
                        session_id,
                        &order.id,
                        "destination",
                        LiquidEffectOperation::ReverseRefund,
                        &request,
                        created_at,
                    ))
                    .map_err(|error| format!("could not recover Liquid reverse refund: {error}"))?
                    .transaction_id,
            )
        } else {
            None
        };
        if let Some(transaction_id) = recovered_refund_transaction_id {
            let artifact = json!({"refund_txid":transaction_id});
            let evidence = chain_spend_evidence(
                session,
                ChainRailKind::Liquid,
                &funding_transaction_id,
                funding_output_index,
                "measured",
                &artifact,
                created_at,
                "provider Liquid refund accepted by elementsd",
            )?;
            let mut extra = Map::new();
            extra.insert("transaction_id".to_owned(), Value::String(transaction_id));
            return Self::next_status_with_evidence(
                session,
                created_at,
                "provider_refund_prepared",
                evidence,
                extra,
            )
            .map(Some);
        }

        if let Some(claim_status) = announced_claim_status {
            let spending_transaction_id = status_transaction_id(claim_status)?;
            let observed_spending = self
                .handle
                .block_on(liquid.spending_transaction(
                    &format!("liquid-reverse-spend:{}", &session_id[..16]),
                    &funding_transaction_id,
                    funding_output_index,
                ))
                .map_err(|error| format!("could not inspect Liquid reverse spend: {error}"))?;
            match observed_spending.as_deref() {
                Some(observed) if observed == spending_transaction_id => {}
                Some(_) => {
                    return Err(
                        "requester claim Status conflicts with the observed Liquid spend"
                            .to_owned(),
                    );
                }
                None => return Ok(None),
            }
            let preimage = self.chain_destination_claim_preimage(
                session,
                &funding,
                &spending_transaction_id,
                terms,
            )?;
            let state = self.reverse_hold_state(session_id, &terms.payment_hash)?;
            let result = if matches!(state.as_str(), "paid" | "settled") {
                self.reconcile_reverse_settlement_effect(
                    session_id,
                    &spending_transaction_id,
                    &terms.payment_hash,
                    created_at,
                )?
            } else {
                self.settle_reverse_preimage(
                    session_id,
                    &spending_transaction_id,
                    terms,
                    preimage,
                    created_at,
                )?
            };
            let evidence = chain_spend_evidence(
                session,
                ChainRailKind::Liquid,
                &funding_transaction_id,
                funding_output_index,
                "settled",
                &result,
                created_at,
                "requester Liquid claim verified before hold settlement",
            )?;
            return Self::next_status_with_evidence_after(
                session,
                created_at,
                "lightning_settlement_pending",
                &claim_status.id,
                evidence,
                Map::new(),
            )
            .map(Some);
        }
        if self.chain_rail_height("liquid-reverse-refund-height", session_id, terms.rail)?
            < u64::from(terms.refund_height)
        {
            return Ok(None);
        }
        let order = exactly_one_kind(records, MKT_ORDER_KIND, "Order")?;
        let receipt = self
            .handle
            .block_on(liquid.execute_provider_exit_effect(
                &mut self.store,
                &refund_effect_id,
                session_id,
                &order.id,
                "destination",
                LiquidEffectOperation::ReverseRefund,
                &refund_request,
                created_at,
            ))
            .map_err(|error| format!("could not broadcast Liquid reverse refund: {error}"))?;
        let artifact = json!({"refund_txid":receipt.transaction_id});
        let evidence = chain_spend_evidence(
            session,
            ChainRailKind::Liquid,
            &funding_transaction_id,
            funding_output_index,
            "measured",
            &artifact,
            created_at,
            "provider Liquid refund accepted by elementsd",
        )?;
        let mut extra = Map::new();
        extra.insert(
            "transaction_id".to_owned(),
            Value::String(receipt.transaction_id),
        );
        Self::next_status_with_evidence(
            session,
            created_at,
            "provider_refund_prepared",
            evidence,
            extra,
        )
        .map(Some)
    }

    fn execute_chain_destination_status(
        &mut self,
        session: &mut ProviderSession,
        terms: &ChainSwapTerms,
        created_at: u64,
    ) -> Result<MktSigningRequest, String> {
        let (transaction_id, output_index, result) = self.execute_chain_destination_funding(
            session,
            &terms.source,
            &terms.destination,
            created_at,
        )?;
        let evidence = chain_transaction_evidence(
            session,
            terms.destination.rail,
            &transaction_id,
            "measured",
            &result,
            created_at,
            "provider destination funding accepted by the local node",
        )?;
        let mut extra = Map::new();
        extra.insert("transaction_id".to_owned(), Value::String(transaction_id));
        extra.insert("output_index".to_owned(), json!(output_index));
        Self::next_status_with_evidence(
            session,
            created_at,
            "provider_destination_broadcast",
            evidence,
            extra,
        )
    }

    fn next_chain_status(
        &mut self,
        session: &mut ProviderSession,
        requester_pubkey: &str,
        created_at: u64,
        provider_state: Option<&str>,
    ) -> Result<Option<MktSigningRequest>, String> {
        let records = session.signed_records();
        let terms = chain_swap_terms(session)?;
        let required_confirmations =
            required_chain_confirmations(self.minimum_confirmations, self.reorg_safety_blocks)?;
        if !matches!(provider_state, Some("refunded"))
            && status_by_state(
                records,
                &session.config().provider_pubkey,
                "provider_destination_broadcast",
            )
            .is_none()
            && let Some(source_refunded) =
                status_by_state(records, requester_pubkey, "requester_source_refunded")
        {
            if !self.chain_source_refund_is_final(
                session,
                &terms.source,
                source_refunded,
                required_confirmations,
            )? {
                return Ok(None);
            }
            require_requester_source_refund_evidence(session, source_refunded, &terms.source)?;
            let evidence =
                unfunded_destination_reservation_evidence(session, &terms.destination, created_at)?;
            return Self::next_status_with_evidence_after(
                session,
                created_at,
                "refunded",
                &source_refunded.id,
                evidence,
                Map::new(),
            )
            .map(Some);
        }
        match provider_state {
            Some("accepted") => {
                Self::next_status(session, created_at, "source_lock_terms_ready", Map::new())
                    .map(Some)
            }
            Some("source_lock_terms_ready") => {
                let Some(prerequisite) =
                    status_by_state(records, requester_pubkey, "requester_source_verified")
                else {
                    return Ok(None);
                };
                let extra = chain_destination_handoff_extra(&terms.destination)?;
                Self::next_status_after(
                    session,
                    created_at,
                    "destination_lock_terms_ready",
                    &prerequisite.id,
                    extra,
                )
                .map(Some)
            }
            Some("destination_lock_terms_ready") => {
                let Some(prerequisite) =
                    status_by_state(records, requester_pubkey, "requester_destination_verified")
                else {
                    return Ok(None);
                };
                Self::next_status_after(
                    session,
                    created_at,
                    "source_funding_required",
                    &prerequisite.id,
                    Map::new(),
                )
                .map(Some)
            }
            Some("source_funding_required") => {
                let Some(status) =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                else {
                    return Ok(None);
                };
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.source,
                )?;
                let evidence = rail_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "source_funding_observed",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            Some("source_funding_observed") => {
                let status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| {
                            "chain source observation lost its requester Status".to_owned()
                        })?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.source,
                )?;
                if observation.confirmations() < required_confirmations {
                    if !terms.source.zero_confirmation
                        || terms.source.rail != ChainRailKind::Bitcoin
                    {
                        return Ok(None);
                    }
                    let RailChainObservation::Bitcoin(observation) = observation else {
                        return Err(
                            "chain zero-conf admission reached a non-Bitcoin observation"
                                .to_owned(),
                        );
                    };
                    let inputs = zero_conf_inputs(&observation)?;
                    match self.zero_conf_check(
                        &session.config().session_id,
                        &transaction_id,
                        output_index,
                        &terms.source,
                        required_confirmations,
                        &inputs,
                    )? {
                        ZeroConfCheck::Accepted(observation) => {
                            if !self.reserve_zero_conf_risk(
                                &session.config().session_id,
                                terms.source.amount_sat,
                                terms.source.desired_completion_time,
                                created_at,
                            )? {
                                let extra = zero_conf_status_extra(
                                    &observation,
                                    "btc-zero-conf-bounded-v1",
                                    "confirmation_required",
                                    Some("aggregate_cap"),
                                    None,
                                )?;
                                return Self::next_status(
                                    session,
                                    created_at,
                                    "source_funding_confirmation_required",
                                    extra,
                                )
                                .map(Some);
                            }
                            let extra = zero_conf_status_extra(
                                &observation,
                                "btc-zero-conf-bounded-v1",
                                "accepted",
                                None,
                                None,
                            )?;
                            return Self::next_status(
                                session,
                                created_at,
                                "source_funding_zero_conf_accepted",
                                extra,
                            )
                            .map(Some);
                        }
                        ZeroConfCheck::Final(observation) => {
                            let observation = RailChainObservation::Bitcoin(observation);
                            let evidence = rail_output_evidence(
                                session,
                                &observation,
                                "verified",
                                created_at,
                            )?;
                            return Self::next_status_with_evidence(
                                session,
                                created_at,
                                "source_funding_final",
                                evidence,
                                rail_transaction_extra(&observation),
                            )
                            .map(Some);
                        }
                        ZeroConfCheck::Downgrade {
                            reason,
                            replacement_txid,
                        } => {
                            let extra = zero_conf_status_extra(
                                &observation,
                                "btc-zero-conf-bounded-v1",
                                "confirmation_required",
                                Some(reason),
                                replacement_txid.as_deref(),
                            )?;
                            return Self::next_status(
                                session,
                                created_at,
                                "source_funding_confirmation_required",
                                extra,
                            )
                            .map(Some);
                        }
                    }
                }
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "source_funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            Some("source_funding_zero_conf_accepted") => {
                let accepted_status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "source_funding_zero_conf_accepted",
                )
                .ok_or_else(|| "chain zero-conf acceptance Status is unavailable".to_owned())?;
                if unix_now()? <= accepted_status.created_at {
                    return Ok(None);
                }
                let source_status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| {
                            "chain zero-conf funding lost its requester source".to_owned()
                        })?;
                let (transaction_id, output_index) = status_transaction_reference(source_status)?;
                let inputs = zero_conf_status_inputs(
                    records,
                    &session.config().provider_pubkey,
                    "source_funding_zero_conf_accepted",
                )?;
                match self.zero_conf_check(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.source,
                    required_confirmations,
                    &inputs,
                )? {
                    ZeroConfCheck::Accepted(_) => self
                        .execute_chain_destination_status(session, &terms, created_at)
                        .map(Some),
                    ZeroConfCheck::Final(observation) => {
                        self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                        let observation = RailChainObservation::Bitcoin(observation);
                        let evidence =
                            rail_output_evidence(session, &observation, "verified", created_at)?;
                        Self::next_status_with_evidence(
                            session,
                            created_at,
                            "source_funding_final",
                            evidence,
                            rail_transaction_extra(&observation),
                        )
                        .map(Some)
                    }
                    ZeroConfCheck::Downgrade {
                        reason,
                        replacement_txid,
                    } => {
                        self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                        let extra = zero_conf_downgrade_extra(
                            records,
                            &session.config().provider_pubkey,
                            "source_funding_zero_conf_accepted",
                            reason,
                            replacement_txid.as_deref(),
                        )?;
                        Self::next_status(
                            session,
                            created_at,
                            "source_funding_confirmation_required",
                            extra,
                        )
                        .map(Some)
                    }
                }
            }
            Some("source_funding_confirmation_required") => {
                let source_status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| {
                            "chain confirmation-required state lost its requester source".to_owned()
                        })?;
                let (transaction_id, output_index) = status_transaction_reference(source_status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.source,
                )?;
                if observation.confirmations() < required_confirmations {
                    return Ok(None);
                }
                self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "source_funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            Some("source_funding_final") => {
                if status_by_state(records, requester_pubkey, "requester_destination_verified")
                    .is_none()
                {
                    return Err(
                        "chain destination funding lost requester verification before broadcast"
                            .to_owned(),
                    );
                }
                let source_status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| {
                            "chain destination funding lost the source Status".to_owned()
                        })?;
                let (source_transaction_id, source_output_index) =
                    status_transaction_reference(source_status)?;
                let source_observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &source_transaction_id,
                    source_output_index,
                    &terms.source,
                )?;
                if source_observation.confirmations() < required_confirmations {
                    return Err(
                        "chain source funding lost reorg-safe finality before destination funding"
                            .to_owned(),
                    );
                }
                self.execute_chain_destination_status(session, &terms, created_at)
                    .map(Some)
            }
            Some("provider_destination_broadcast") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_broadcast",
                )
                .ok_or_else(|| "chain destination broadcast Status is unavailable".to_owned())?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.destination,
                )?;
                let evidence = rail_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "destination_funding_observed",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            Some("destination_funding_observed") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_broadcast",
                )
                .ok_or_else(|| "chain destination broadcast Status is unavailable".to_owned())?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms.destination,
                )?;
                if observation.confirmations() < required_confirmations {
                    return Ok(None);
                }
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "destination_funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            Some("destination_funding_final") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_broadcast",
                )
                .ok_or_else(|| "chain destination funding Status is unavailable".to_owned())?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let claim_status =
                    status_by_state(records, requester_pubkey, "requester_destination_claimed");
                let observation = if claim_status.is_some() {
                    self.observe_claimed_contract_funding(
                        &session.config().session_id,
                        &transaction_id,
                        output_index,
                        &terms.destination,
                    )?
                } else {
                    self.observe_contract_funding(
                        &session.config().session_id,
                        &transaction_id,
                        output_index,
                        &terms.destination,
                    )?
                };
                if observation.confirmations() < required_confirmations {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("destination_funding_reorg"),
                    )
                    .map(Some);
                }
                if status_by_state(
                    records,
                    requester_pubkey,
                    "requester_destination_claim_pending",
                )
                .is_none()
                {
                    return Ok(None);
                }
                let Some(claim_status) = claim_status else {
                    let destination_status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_destination_broadcast",
                    )
                    .ok_or_else(|| "chain destination funding Status is unavailable".to_owned())?;
                    let (destination_transaction_id, destination_output_index) =
                        status_transaction_reference(destination_status)?;
                    let recovering_liquid_refund = terms.destination.rail == ChainRailKind::Liquid
                        && self
                            .stored_provider_liquid_exit_request(
                                &deterministic_id("chain_refund", &session.config().session_id),
                                LiquidEffectOperation::ChainRefund,
                            )?
                            .is_some();
                    if !recovering_liquid_refund {
                        let destination_observation = self.observe_contract_funding(
                            &session.config().session_id,
                            &destination_transaction_id,
                            destination_output_index,
                            &terms.destination,
                        )?;
                        if destination_observation.confirmations() < required_confirmations {
                            return Self::next_status(
                                session,
                                created_at,
                                "unresolved",
                                hold_failure_extra("destination_funding_reorg"),
                            )
                            .map(Some);
                        }
                        if self.chain_rail_height(
                            "chain-destination-refund-height",
                            &session.config().session_id,
                            terms.destination.rail,
                        )? < u64::from(terms.destination.refund_height)
                        {
                            return Ok(None);
                        }
                        if terms.destination.rail == ChainRailKind::Bitcoin {
                            let job =
                                self.watch_job("refund_broadcast", &session.config().session_id)?;
                            if job.broadcast_txid.is_none() && job.replacement_txid.is_none() {
                                return Ok(None);
                            }
                        }
                    }
                    let (refund_transaction_id, result) = self.execute_chain_destination_refund(
                        session,
                        &terms.destination,
                        created_at,
                    )?;
                    let destination_funding_transaction_id = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_destination_broadcast",
                    )
                    .ok_or_else(|| "chain destination funding Status is unavailable".to_owned())
                    .and_then(status_transaction_id)?;
                    let evidence = chain_spend_evidence(
                        session,
                        terms.destination.rail,
                        &destination_funding_transaction_id,
                        terms.destination.output_index,
                        "measured",
                        &result,
                        created_at,
                        "provider destination refund accepted by the local node",
                    )?;
                    let mut extra = Map::new();
                    extra.insert(
                        "transaction_id".to_owned(),
                        Value::String(refund_transaction_id),
                    );
                    return Self::next_status_with_evidence(
                        session,
                        created_at,
                        "provider_destination_refund_pending",
                        evidence,
                        extra,
                    )
                    .map(Some);
                };
                let claim_transaction_id = status_transaction_id(claim_status)?;
                let source_status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| "chain source funding Status is unavailable".to_owned())?;
                let (source_transaction_id, source_output_index) =
                    status_transaction_reference(source_status)?;
                let recovering_liquid_claim = terms.source.rail == ChainRailKind::Liquid
                    && self
                        .stored_provider_liquid_exit_request(
                            &deterministic_id("chain_claim", &session.config().session_id),
                            LiquidEffectOperation::ChainClaim,
                        )?
                        .is_some();
                let source_observation = if recovering_liquid_claim {
                    self.observe_claimed_contract_funding(
                        &session.config().session_id,
                        &source_transaction_id,
                        source_output_index,
                        &terms.source,
                    )?
                } else {
                    self.observe_contract_funding(
                        &session.config().session_id,
                        &source_transaction_id,
                        source_output_index,
                        &terms.source,
                    )?
                };
                if source_observation.confirmations() < required_confirmations {
                    return Err(
                        "chain source funding lost finality before the provider claim".to_owned(),
                    );
                }
                let preimage = self.chain_destination_claim_preimage(
                    session,
                    &observation,
                    &claim_transaction_id,
                    &terms.destination,
                )?;
                let (source_claim_transaction_id, result) = self.execute_chain_source_claim(
                    session,
                    &source_observation,
                    &terms.source,
                    &terms.destination,
                    preimage,
                    created_at,
                )?;
                let evidence = chain_spend_evidence(
                    session,
                    terms.source.rail,
                    source_observation.transaction_id(),
                    source_observation.output_index(),
                    "measured",
                    &result,
                    created_at,
                    "provider source claim accepted by the local node",
                )?;
                let mut extra = Map::new();
                extra.insert(
                    "transaction_id".to_owned(),
                    Value::String(source_claim_transaction_id),
                );
                Self::next_status_with_evidence_after(
                    session,
                    created_at,
                    "provider_source_claim_pending",
                    &claim_status.id,
                    evidence,
                    extra,
                )
                .map(Some)
            }
            Some("provider_destination_refund_pending") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_refund_pending",
                )
                .ok_or_else(|| "provider destination refund Status is unavailable".to_owned())?;
                let refund_transaction_id = status_transaction_id(status)?;
                if !self.chain_effect_is_final(
                    "chain-destination-refund-final",
                    &session.config().session_id,
                    terms.destination.rail,
                    "refund_broadcast",
                    &refund_transaction_id,
                    required_confirmations,
                )? {
                    return Ok(None);
                }
                let funding_status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_broadcast",
                )
                .ok_or_else(|| "chain destination funding Status is unavailable".to_owned())?;
                let (funding_transaction_id, funding_output_index) =
                    status_transaction_reference(funding_status)?;
                let artifact = json!({"refund_txid":refund_transaction_id});
                let evidence = chain_spend_evidence(
                    session,
                    terms.destination.rail,
                    &funding_transaction_id,
                    funding_output_index,
                    "settled",
                    &artifact,
                    created_at,
                    "provider destination refund reached reorg-safe finality",
                )?;
                let mut extra = Map::new();
                extra.insert(
                    "transaction_id".to_owned(),
                    Value::String(refund_transaction_id),
                );
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_destination_refunded",
                    evidence,
                    extra,
                )
                .map(Some)
            }
            Some("provider_destination_refunded") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_refunded",
                )
                .ok_or_else(|| "provider destination refund Status is unavailable".to_owned())?;
                let refund_transaction_id = status_transaction_id(status)?;
                if !self.chain_effect_is_final(
                    "chain-destination-refund-recheck",
                    &session.config().session_id,
                    terms.destination.rail,
                    "refund_broadcast",
                    &refund_transaction_id,
                    required_confirmations,
                )? {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("destination_refund_reorg"),
                    )
                    .map(Some);
                }
                let Some(source_refunded) =
                    status_by_state(records, requester_pubkey, "requester_source_refunded")
                else {
                    return Ok(None);
                };
                if !self.chain_source_refund_is_final(
                    session,
                    &terms.source,
                    source_refunded,
                    required_confirmations,
                )? {
                    return Ok(None);
                }
                require_requester_source_refund_evidence(session, source_refunded, &terms.source)?;
                Self::next_status_after(
                    session,
                    created_at,
                    "refunded",
                    &source_refunded.id,
                    Map::new(),
                )
                .map(Some)
            }
            Some("refunded") => {
                let source_refunded =
                    status_by_state(records, requester_pubkey, "requester_source_refunded")
                        .ok_or_else(|| {
                            "chain refunded state has no requester source refund".to_owned()
                        })?;
                if !self.chain_source_refund_is_final(
                    session,
                    &terms.source,
                    source_refunded,
                    required_confirmations,
                )? {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("source_refund_reorg"),
                    )
                    .map(Some);
                }
                if status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_broadcast",
                )
                .is_none()
                {
                    return self
                        .terminal_close(session, "chain", "refunded", created_at)
                        .map(Some);
                }
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_destination_refunded",
                )
                .ok_or_else(|| "provider destination refund Status is unavailable".to_owned())?;
                let refund_transaction_id = status_transaction_id(status)?;
                if !self.chain_effect_is_final(
                    "chain-destination-refund-close",
                    &session.config().session_id,
                    terms.destination.rail,
                    "refund_broadcast",
                    &refund_transaction_id,
                    required_confirmations,
                )? {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("destination_refund_reorg"),
                    )
                    .map(Some);
                }
                self.terminal_close(session, "chain", "refunded", created_at)
                    .map(Some)
            }
            Some("provider_source_claim_pending") => {
                let claim_status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_source_claim_pending",
                )
                .ok_or_else(|| "provider source claim Status is unavailable".to_owned())?;
                let claim_transaction_id = status_transaction_id(claim_status)?;
                let source_status =
                    status_by_state(records, requester_pubkey, "requester_source_broadcast")
                        .ok_or_else(|| "chain source funding Status is unavailable".to_owned())?;
                let (source_transaction_id, source_output_index) =
                    status_transaction_reference(source_status)?;
                let artifact = json!({"claim_txid":claim_transaction_id});
                if !self.chain_effect_is_final(
                    "chain-source-claim-final",
                    &session.config().session_id,
                    terms.source.rail,
                    "chain_source_claim_broadcast",
                    &claim_transaction_id,
                    required_confirmations,
                )? {
                    return Ok(None);
                }
                let evidence = chain_spend_evidence(
                    session,
                    terms.source.rail,
                    &source_transaction_id,
                    source_output_index,
                    "settled",
                    &artifact,
                    created_at,
                    "provider source claim reached reorg-safe finality",
                )?;
                let mut extra = Map::new();
                extra.insert(
                    "transaction_id".to_owned(),
                    Value::String(claim_transaction_id),
                );
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_source_claimed",
                    evidence,
                    extra,
                )
                .map(Some)
            }
            Some("provider_source_claimed") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_source_claimed",
                )
                .ok_or_else(|| "provider source claim Status is unavailable".to_owned())?;
                let claim_transaction_id = status_transaction_id(status)?;
                if !self.chain_effect_is_final(
                    "chain-source-claim-recheck",
                    &session.config().session_id,
                    terms.source.rail,
                    "chain_source_claim_broadcast",
                    &claim_transaction_id,
                    required_confirmations,
                )? {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("source_claim_reorg"),
                    )
                    .map(Some);
                }
                Self::next_status(session, created_at, "completed", Map::new()).map(Some)
            }
            Some("completed") => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_source_claimed",
                )
                .ok_or_else(|| "provider source claim Status is unavailable".to_owned())?;
                let claim_transaction_id = status_transaction_id(status)?;
                if !self.chain_effect_is_final(
                    "chain-source-claim-close",
                    &session.config().session_id,
                    terms.source.rail,
                    "chain_source_claim_broadcast",
                    &claim_transaction_id,
                    required_confirmations,
                )? {
                    return Self::next_status(
                        session,
                        created_at,
                        "unresolved",
                        hold_failure_extra("source_claim_reorg"),
                    )
                    .map(Some);
                }
                self.terminal_close(session, "chain", "completed", created_at)
                    .map(Some)
            }
            _ => Ok(None),
        }
    }

    fn next_status(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, String> {
        let (sequence, previous) = next_provider_status_position(session)?;
        let base_state = base_state(state)?;
        session
            .provider_status(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous: previous.as_deref(),
                    base_state,
                    swp_state: state,
                },
                extra,
            )
            .map_err(|error| format!("could not construct provider {state} Status: {error}"))
    }

    fn next_status_after(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        prerequisite_status_id: &str,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, String> {
        let (sequence, previous) = next_provider_status_position(session)?;
        session
            .provider_status_after(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous: previous.as_deref(),
                    base_state: base_state(state)?,
                    swp_state: state,
                },
                prerequisite_status_id,
                extra,
            )
            .map_err(|error| format!("could not construct provider {state} Status: {error}"))
    }

    fn hold_failure_status(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        failure_code: &str,
    ) -> Result<MktSigningRequest, String> {
        if !is_hold_failure_code(failure_code) {
            return Err("invalid held-HTLC failure code".to_owned());
        }
        Self::next_status(session, created_at, state, hold_failure_extra(failure_code))
    }

    fn deadline_failure_status(
        session: &ProviderSession,
        created_at: u64,
        failure_code: &str,
    ) -> Result<MktSigningRequest, String> {
        if !matches!(
            failure_code,
            "funding_deadline_expired" | "claim_deadline_expired"
        ) {
            return Err("invalid chain-deadline failure code".to_owned());
        }
        Self::next_status(
            session,
            created_at,
            "expired",
            hold_failure_extra(failure_code),
        )
    }

    fn next_status_with_evidence(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        evidence: Value,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, String> {
        let (sequence, previous) = next_provider_status_position(session)?;
        session
            .provider_status_with_evidence(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous: previous.as_deref(),
                    base_state: base_state(state)?,
                    swp_state: state,
                },
                evidence,
                extra,
            )
            .map_err(|error| format!("could not construct provider {state} Status: {error}"))
    }

    fn next_status_with_evidence_after(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        prerequisite_status_id: &str,
        evidence: Value,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, String> {
        let (sequence, previous) = next_provider_status_position(session)?;
        session
            .provider_status_with_evidence_after(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous: previous.as_deref(),
                    base_state: base_state(state)?,
                    swp_state: state,
                },
                prerequisite_status_id,
                evidence,
                extra,
            )
            .map_err(|error| format!("could not construct provider {state} Status: {error}"))
    }
}

fn funding_pricing_swap_type(terms: &Map<String, Value>) -> Result<PricingSwapType, String> {
    match terms.get("swap_type").and_then(Value::as_str) {
        Some("reverse") => Ok(PricingSwapType::Reverse),
        Some("chain") => Ok(PricingSwapType::Chain),
        _ => Err("funding Quote has an invalid swap type".to_owned()),
    }
}

fn contract_pricing_swap_type(terms: &Map<String, Value>) -> Result<PricingSwapType, String> {
    match terms.get("swap_type").and_then(Value::as_str) {
        Some("submarine") => Ok(PricingSwapType::Submarine),
        Some("reverse") => Ok(PricingSwapType::Reverse),
        Some("chain") => Ok(PricingSwapType::Chain),
        _ => Err("Swap Contract has an invalid swap type".to_owned()),
    }
}

fn quote_priced_vbytes(
    swap_type: PricingSwapType,
    asset_pair: &[String; 2],
    bitcoin_network_id: &str,
    liquid: Option<&LiquidProviderRail>,
) -> Result<u64, String> {
    let bitcoin_asset = format!("swp:1:{bitcoin_network_id}:btc:chain");
    let liquid_asset = liquid.map(LiquidProviderRail::mkt_asset_id);
    let rails = asset_pair
        .iter()
        .filter_map(|asset| {
            if asset == &bitcoin_asset {
                Some(ChainRailKind::Bitcoin)
            } else if liquid_asset.as_ref() == Some(asset) {
                Some(ChainRailKind::Liquid)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    priced_vbytes_for_rails(swap_type, &rails)
}

fn contract_priced_vbytes(
    contract: &Map<String, Value>,
    swap_type: PricingSwapType,
) -> Result<u64, String> {
    let rails = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| "funding Contract has no legs".to_owned())?
        .iter()
        .filter_map(|leg| match leg.get("rail").and_then(Value::as_str) {
            Some("bitcoin") => Some(Ok(ChainRailKind::Bitcoin)),
            Some("liquid") => Some(Ok(ChainRailKind::Liquid)),
            Some("lightning") => None,
            _ => Some(Err("funding Contract has an unsupported rail".to_owned())),
        })
        .collect::<Result<Vec<_>, _>>()?;
    priced_vbytes_for_rails(swap_type, &rails)
}

fn priced_vbytes_for_rails(
    swap_type: PricingSwapType,
    rails: &[ChainRailKind],
) -> Result<u64, String> {
    match (swap_type, rails) {
        (PricingSwapType::Submarine, [ChainRailKind::Bitcoin])
        | (PricingSwapType::Reverse, [ChainRailKind::Bitcoin])
        | (PricingSwapType::Chain, [ChainRailKind::Bitcoin]) => {
            Ok(worst_case_redeem_vbytes(swap_type))
        }
        (PricingSwapType::Submarine, [ChainRailKind::Liquid]) => {
            Ok(liquid_submarine_quote_vbytes())
        }
        (PricingSwapType::Reverse, [ChainRailKind::Liquid]) => Ok(liquid_reverse_quote_vbytes()),
        (PricingSwapType::Chain, [ChainRailKind::Bitcoin, ChainRailKind::Liquid]) => {
            Ok(bitcoin_to_liquid_chain_quote_vbytes())
        }
        (PricingSwapType::Chain, [ChainRailKind::Liquid, ChainRailKind::Bitcoin]) => {
            Ok(liquid_to_bitcoin_chain_quote_vbytes())
        }
        _ => Err("funding Quote rail topology is invalid".to_owned()),
    }
}

fn effect_fee_sat(vbytes: u64, fee_rate_sat_per_vbyte: u64) -> Result<u64, String> {
    vbytes
        .checked_mul(fee_rate_sat_per_vbyte)
        .ok_or_else(|| "rail fee budget overflows".to_owned())
}

fn exit_fee_sat(terms: &ChainTerms, path: SettlementPath) -> Result<u64, String> {
    let vbytes = match (terms.rail, path) {
        (ChainRailKind::Bitcoin, SettlementPath::Claim) => claim_spend_vbytes(),
        (ChainRailKind::Bitcoin, SettlementPath::Refund) => refund_spend_vbytes(),
        (ChainRailKind::Liquid, SettlementPath::Claim) => LIQUID_CLAIM_VBYTES,
        (ChainRailKind::Liquid, SettlementPath::Refund) => LIQUID_REFUND_VBYTES,
    };
    effect_fee_sat(vbytes, terms.fee_rate_sat_per_vbyte)
}

fn require_derived_pricing_terms(
    quote: &BuiltFundedQuote,
    derived: &DerivedQuote,
) -> Result<(), String> {
    if quote.expiration > derived.quote_expires_at {
        return Err("funded Quote exceeds its derived pricing expiry".to_owned());
    }
    let terms = quote
        .profile
        .get("terms")
        .and_then(Value::as_object)
        .ok_or_else(|| "funded Quote has no terms object".to_owned())?;
    for (name, expected) in derived.amount_terms() {
        if terms.get(&name) != Some(&expected) {
            return Err(format!(
                "funded Quote construction changed derived pricing term {name}"
            ));
        }
    }
    Ok(())
}

impl ProviderMode for FundedMode {
    fn mode_name(&self) -> &'static str {
        "funded"
    }

    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }

    fn offering_id(&self) -> &str {
        OFFERING_ID
    }

    fn discovery_metadata(&self) -> Value {
        json!({
            "name":"Immortal funded provider",
            "mode":"funded",
            "settlement_claim":"provider-owned Bitcoin and Core Lightning rails"
        })
    }

    fn offering(&self) -> Value {
        funded_offering(
            &self.network_id,
            self.minimum_confirmations,
            self.reorg_safety_blocks,
            &self.pricing,
            self.liquid.as_ref(),
            self.zero_conf,
        )
    }

    fn durable_recovery(&mut self, limit: usize) -> Result<DurableRecovery, String> {
        let recovery = self
            .handle
            .block_on(self.store.active_session_records(limit))
            .map_err(|error| format!("could not recover durable provider sessions: {error}"))?;
        Ok(DurableRecovery {
            records: recovery.records,
            has_prior_records: recovery.has_prior_records,
        })
    }

    fn durable_session_records(
        &mut self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<Event>, String> {
        self.handle
            .block_on(self.store.session_records(session_id, limit))
            .map_err(|error| {
                format!("could not recover durable provider session {session_id}: {error}")
            })
    }

    fn prepare_recovered_record(
        &mut self,
        session: &mut ProviderSession,
        record: &Event,
    ) -> Result<(), String> {
        if record.kind == MKT_CLOSE_KIND
            && record.pubkey == session.config().provider_pubkey
            && session.reservation().is_some()
            && !session.reservation_released()
        {
            let reservation_id = session
                .reservation()
                .ok_or_else(|| "provider Close recovery lost its reservation".to_owned())?
                .reservation_id
                .clone();
            let stored = self
                .handle
                .block_on(self.store.reservation(&reservation_id))
                .map_err(|error| format!("could not recover provider Close release: {error}"))?
                .ok_or_else(|| "provider Close has no durable reservation".to_owned())?;
            if stored.session_id != session.config().session_id
                || stored.state != "released"
                || stored.release_cause.as_deref() != Some("terminal_close")
            {
                return Err("provider Close has no matching durable terminal release".to_owned());
            }
            session
                .restore_terminal_close_release(record, |request| {
                    self.release_reservation_effect(request, record.created_at)
                })
                .map_err(|error| format!("could not restore provider Close release: {error}"))?;
            return Ok(());
        }
        if record.kind != MKT_QUOTE_KIND
            || record.pubkey != session.config().provider_pubkey
            || !record.tag_values("reservation").eq(["hard"])
            || session.reservation().is_some()
        {
            return Ok(());
        }

        let mut profile = record_profile(record)?;
        let confirmation = recovered_reservation_confirmation(&mut profile)?;
        let stored = self
            .handle
            .block_on(self.store.reservation(&confirmation.reservation_id))
            .map_err(|error| format!("could not recover hard-Quote reservation: {error}"))?
            .ok_or_else(|| "hard Quote has no durable reservation".to_owned())?;
        if !matches!(stored.state.as_str(), "active" | "released") {
            return Err("hard-Quote reservation is unresolved".to_owned());
        }
        let amount = canonical_u64(&confirmation.reserved_amount)?;
        let committed_capacity = canonical_u64(&confirmation.committed_capacity)?;
        if stored.reservation_id != confirmation.reservation_id
            || stored.session_id != session.config().session_id
            || stored.bucket_id != confirmation.capacity_bucket_id
            || stored.asset_id != confirmation.reserved_asset_id
            || stored.amount != amount
            || stored.expires_at != confirmation.reservation_expires_at
            || stored.allocation_sequence.to_string() != confirmation.allocation_sequence
            || committed_capacity < amount
        {
            return Err("hard Quote differs from its durable reservation".to_owned());
        }
        let proof_class = if confirmation.reserved_asset_id.ends_with(":chain")
            || self
                .liquid
                .as_ref()
                .is_some_and(|liquid| confirmation.reserved_asset_id == liquid.mkt_asset_id())
        {
            "utxo_control"
        } else if confirmation.reserved_asset_id.ends_with(":lightning") {
            "lightning_liquidity"
        } else {
            return Err("hard Quote reserves an unsupported funded rail".to_owned());
        };
        if confirmation.proof_class != proof_class
            || confirmation.proof_ref
                != format!("immortal-provider:{}", confirmation.reservation_id)
        {
            return Err("hard Quote has an invalid durable reservation proof".to_owned());
        }

        let reservation = ReservationRequest {
            reservation_id: confirmation.reservation_id.clone(),
            capacity_bucket_id: confirmation.capacity_bucket_id.clone(),
            reserved_asset_id: confirmation.reserved_asset_id.clone(),
            reserved_amount: confirmation.reserved_amount.clone(),
            reservation_expires_at: confirmation.reservation_expires_at,
        };
        let distinct = exact_tag_value(record, "d")?;
        let expiration = canonical_u64(exact_tag_value(record, "expiration")?)?;
        let request = session
            .hard_quote_with_reserve(
                record.created_at,
                distinct,
                expiration,
                reservation,
                Value::Object(profile),
                |effect_request| {
                    if stored.effect_id != effect_request.effect_id
                        || stored.request_sha256 != effect_request.request_sha256
                        || stored.session_id != effect_request.session_id
                        || stored.reservation_id != effect_request.reservation_id
                        || stored.bucket_id != effect_request.capacity_bucket_id
                        || stored.asset_id != effect_request.reserved_asset_id
                        || stored.amount.to_string() != effect_request.reserved_amount
                        || stored.expires_at != effect_request.reservation_expires_at
                        || confirmation.capacity_commitment_sha256
                            != capacity_commitment(
                                effect_request,
                                stored.allocation_sequence,
                                committed_capacity,
                            )
                    {
                        return Err("hard Quote differs from its durable reserve effect".to_owned());
                    }
                    Ok(confirmation.clone())
                },
            )
            .map_err(|error| format!("could not restore hard Quote: {error}"))?;
        if request.pubkey != record.pubkey
            || request.created_at != record.created_at
            || request.kind != record.kind
            || request.tags != record.tags
            || request.content != record.content
            || request.expected_event_id != record.id
        {
            return Err("restored hard Quote changed signed bytes".to_owned());
        }
        Ok(())
    }

    fn dispose_stalled_session(
        &mut self,
        session: &ProviderSession,
        requester_pubkey: &str,
        observed_at: u64,
    ) -> Result<Option<&'static str>, String> {
        let latest_state =
            latest_status_state(session.signed_records(), &session.config().provider_pubkey)?;
        if latest_state.as_deref() == Some("expired") {
            let expired = status_by_state(
                session.signed_records(),
                &session.config().provider_pubkey,
                "expired",
            )
            .ok_or_else(|| "expired provider session has no terminal Status".to_owned())?;
            let expired_profile = record_profile(expired)?;
            let failure_code = expired_profile.get("failure_code").and_then(Value::as_str);
            if matches!(
                failure_code,
                Some(
                    "invalid_hold_invoice"
                        | "hold_invoice_cancelled"
                        | "lock_deadline_expired"
                        | "funding_deadline_expired"
                        | "claim_deadline_expired"
                )
            ) {
                let reason =
                    failure_code.ok_or_else(|| "expired hold failure has no reason".to_owned())?;
                self.dispose_unfunded_session(session, reason, observed_at)?;
                return Ok(Some(match reason {
                    "invalid_hold_invoice" => "invalid_hold_invoice",
                    "hold_invoice_cancelled" => "hold_invoice_cancelled",
                    "lock_deadline_expired" => "lock_deadline_expired",
                    "funding_deadline_expired" => "funding_deadline_expired",
                    "claim_deadline_expired" => "claim_deadline_expired",
                    _ => return Err("expired session has an unsupported reason".to_owned()),
                }));
            }
        }
        if latest_state.as_deref() == Some("unresolved") {
            let unresolved = status_by_state(
                session.signed_records(),
                &session.config().provider_pubkey,
                "unresolved",
            )
            .ok_or_else(|| "unresolved provider session has no terminal Status".to_owned())?;
            let unresolved_profile = record_profile(unresolved)?;
            let failure_code = unresolved_profile
                .get("failure_code")
                .and_then(Value::as_str)
                .ok_or_else(|| "unresolved provider session has no failure code".to_owned())?;
            if matches!(
                failure_code,
                "invalid_hold_invoice_settled" | "hold_invoice_settled_before_funding"
            ) {
                self.handle
                    .block_on(self.store.dispose_session(
                        &session.config().session_id,
                        failure_code,
                        observed_at,
                    ))
                    .map_err(|error| {
                        format!("could not persist unresolved session disposition: {error}")
                    })?;
                return Ok(Some(if failure_code == "invalid_hold_invoice_settled" {
                    "invalid_hold_invoice_settled"
                } else {
                    "hold_invoice_settled_before_funding"
                }));
            }
        }
        let reason = stalled_session_disposition(session, requester_pubkey, observed_at)?;
        if let Some(reason) = reason {
            self.dispose_unfunded_session(session, reason, observed_at)?;
        }
        Ok(reason)
    }

    fn reject_session(
        &mut self,
        session: &ProviderSession,
        _requester_pubkey: &str,
        disposition: QuoteDisposition,
        observed_at: u64,
    ) -> Result<(), String> {
        self.dispose_unfunded_session(session, disposition.code(), observed_at)
    }

    fn construct_quote(
        &mut self,
        session: &mut ProviderSession,
        _requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, QuoteConstructionError> {
        let rfq = exactly_one_kind(session.signed_records(), MKT_RFQ_KIND, "RFQ")?.clone();
        let Some(quote) = self.quote(&rfq, created_at)? else {
            return Ok(None);
        };
        let reservation_id = deterministic_id("reservation", &session.config().session_id);
        let capacity_bucket_id = if self
            .liquid
            .as_ref()
            .is_some_and(|liquid| quote.reserved_asset_id == liquid.mkt_asset_id())
        {
            format!("liquid-{}", &session.config().session_id[..16])
        } else if quote.reserved_asset_id.ends_with(":chain") {
            format!("btc-{}", &session.config().session_id[..16])
        } else {
            "lightning-outbound".to_owned()
        };
        let reservation = ReservationRequest {
            reservation_id,
            capacity_bucket_id,
            reserved_asset_id: quote.reserved_asset_id,
            reserved_amount: quote.reserved_amount_sat.to_string(),
            reservation_expires_at: quote.expiration,
        };
        let session_id = session.config().session_id.clone();
        if matches!(rfq_swap_type(&rfq)?.as_str(), "reverse" | "chain") {
            let mut reserve_error = None;
            let result = session.hard_quote_with_bound_reserve(
                created_at,
                &deterministic_id("quote", &session_id),
                quote.expiration,
                reservation,
                quote.profile,
                |request, existing_confirmation, profile| {
                    let confirmation = match existing_confirmation {
                        Some(confirmation) => confirmation.clone(),
                        None => match self.reserve(request, Some(&profile)) {
                            Ok(confirmation) => confirmation,
                            Err(error) => {
                                let detail = error.to_string();
                                reserve_error = Some(error);
                                return Err(detail);
                            }
                        },
                    };
                    let profile = self.bind_reverse_funding_template(&session_id, profile)?;
                    Ok((confirmation, profile))
                },
            );
            return match result {
                Ok(request) => Ok(Some(request)),
                Err(error) => Err(reserve_error.unwrap_or_else(|| {
                    QuoteConstructionError::rejected(format!(
                        "could not construct funded hard Quote: {error}"
                    ))
                })),
            };
        }
        let mut reserve_error = None;
        let result = session.hard_quote_with_reserve(
            created_at,
            &deterministic_id("quote", &session_id),
            quote.expiration,
            reservation,
            quote.profile,
            |request| match self.reserve(request, None) {
                Ok(confirmation) => Ok(confirmation),
                Err(error) => {
                    let detail = error.to_string();
                    reserve_error = Some(error);
                    Err(detail)
                }
            },
        );
        match result {
            Ok(request) => Ok(Some(request)),
            Err(error) => Err(reserve_error.unwrap_or_else(|| {
                QuoteConstructionError::rejected(format!(
                    "could not construct funded hard Quote: {error}"
                ))
            })),
        }
    }

    fn observe_durable_signed_record(
        &mut self,
        session_id: &str,
        record: &Event,
        _origin: RecordOrigin,
        provider_authored: bool,
    ) -> Result<(), String> {
        self.handle
            .block_on(self.store.persist_session_record(record))
            .map_err(|error| format!("could not persist provider session record: {error}"))?;
        if is_effective_cancel(record) {
            self.cancel_unfunded_reverse(session_id, record.created_at)?;
        }
        if provider_authored && record.kind == MKT_CLOSE_KIND {
            let outcome = tag_value(record, "outcome")
                .ok_or_else(|| "provider Close has no outcome".to_owned())?;
            let reason = match outcome {
                "completed" => "provider_close_completed",
                "refunded" => "provider_close_refunded",
                "cancelled" => "provider_close_cancelled",
                "rejected" => "provider_close_rejected",
                "expired" => "provider_close_expired",
                "failed" => "provider_close_failed",
                "disputed" => "provider_close_disputed",
                "unresolved" => "provider_close_unresolved",
                _ => return Err("provider Close has an unsupported outcome".to_owned()),
            };
            self.handle
                .block_on(
                    self.store
                        .dispose_session(session_id, reason, record.created_at),
                )
                .map_err(|error| {
                    format!("could not persist provider Close disposition: {error}")
                })?;
        }
        Ok(())
    }

    fn observe_durable_signed_session_record(
        &mut self,
        session: &ProviderSession,
        record: &Event,
        origin: RecordOrigin,
        provider_authored: bool,
    ) -> Result<(), String> {
        self.observe_durable_signed_record(
            &session.config().session_id,
            record,
            origin,
            provider_authored,
        )?;
        self.observe_cooperative_record(session, record, origin)
    }

    fn next_after_contract_or_status(
        &mut self,
        session: &mut ProviderSession,
        requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String> {
        let records = session.signed_records();
        if !has_kind_by_author(records, MKT_ORDER_KIND, requester_pubkey) {
            return Ok(None);
        }
        let requester_contract = records.iter().find(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND && record.pubkey == requester_pubkey
        });
        let Some(requester_contract) = requester_contract else {
            return Ok(None);
        };
        if !records.iter().any(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                && record.pubkey == session.config().provider_pubkey
        }) {
            let contract = record_profile(requester_contract)?
                .get("contract")
                .cloned()
                .ok_or_else(|| "requester Swap Contract has no complete contract".to_owned())?;
            return session
                .provider_swap_contract(
                    created_at,
                    &deterministic_id("provider-contract", &session.config().session_id),
                    None,
                    contract,
                )
                .map(Some)
                .map_err(|error| format!("could not countersign requester contract: {error}"));
        }

        let cancel_request = records.iter().find(|record| {
            record.kind == MKT_CANCEL_KIND
                && record.pubkey == requester_pubkey
                && tag_value(record, "action") == Some("request")
        });
        if let Some(cancel_request) = cancel_request {
            let response = records.iter().find(|record| {
                record.kind == MKT_CANCEL_KIND
                    && record.pubkey == session.config().provider_pubkey
                    && matches!(tag_value(record, "action"), Some("accepted" | "rejected"))
            });
            if response.is_none() {
                let session_id = session.config().session_id.clone();
                let provider_state =
                    latest_status_state(records, &session.config().provider_pubkey)?;
                let requester_has_status = records.iter().any(|record| {
                    record.kind == MKT_STATUS_KIND && record.pubkey == requester_pubkey
                });
                let pre_effect =
                    funded_cancel_pre_effect(requester_has_status, provider_state.as_deref());
                let action = if pre_effect { "accepted" } else { "rejected" };
                let reason = if pre_effect {
                    "requester_no_fund_selection"
                } else {
                    "settlement_already_started"
                };
                return session
                    .provider_cancel(
                        created_at,
                        &deterministic_id(&format!("cancel-{action}"), &session_id),
                        Cancellation {
                            action,
                            reason,
                            request_id: Some(&cancel_request.id),
                            accepted_id: None,
                        },
                        json!({"disposition":if pre_effect {
                            "no_funding_authorized"
                        } else {
                            "settlement_already_started"
                        }}),
                    )
                    .map(Some)
                    .map_err(|error| format!("could not answer funded Cancel: {error}"));
            }
            let response =
                response.ok_or_else(|| "funded Cancel response disappeared".to_owned())?;
            if tag_value(response, "action") == Some("rejected") {
                return Ok(None);
            }
            if !records.iter().any(|record| {
                record.kind == MKT_CANCEL_KIND
                    && record.pubkey == session.config().provider_pubkey
                    && tag_value(record, "action") == Some("effective")
            }) {
                let session_id = session.config().session_id.clone();
                return session
                    .provider_cancel(
                        created_at,
                        &deterministic_id("cancel-effective", &session_id),
                        Cancellation {
                            action: "effective",
                            reason: "requester_no_fund_selection",
                            request_id: Some(&cancel_request.id),
                            accepted_id: Some(&response.id),
                        },
                        json!({"disposition":"no_funding_authorized"}),
                    )
                    .map(Some)
                    .map_err(|error| format!("could not make funded Cancel effective: {error}"));
            }
        }

        if records.iter().any(is_effective_cancel)
            && !has_kind_by_author(records, MKT_CLOSE_KIND, &session.config().provider_pubkey)
        {
            let swap_type = rfq_swap_type(exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?)?;
            return self
                .terminal_close(session, &swap_type, "cancelled", created_at)
                .map(Some);
        }

        let provider_state = latest_status_state(records, &session.config().provider_pubkey)?;
        if provider_state.is_none() {
            return Self::next_status(session, created_at, "accepted", Map::new()).map(Some);
        }
        let swap_type = rfq_swap_type(exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?)?;
        if swap_type == "chain" {
            return self.next_chain_status(
                session,
                requester_pubkey,
                created_at,
                provider_state.as_deref(),
            );
        }
        let terms = chain_terms(session, &swap_type)?;
        match (swap_type.as_str(), provider_state.as_deref()) {
            ("submarine", Some("accepted")) => {
                Self::next_status(session, created_at, "lock_terms_ready", Map::new()).map(Some)
            }
            ("submarine", Some("lock_terms_ready")) => {
                let Some(requester_status) =
                    status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                else {
                    return Ok(None);
                };
                let fund_last = terms
                    .fund_last
                    .ok_or_else(|| "submarine contract has no funding deadline".to_owned())?;
                let current_height = u32::try_from(self.chain_rail_height(
                    "submarine-fund-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "submarine funding height exceeds u32".to_owned())?;
                if deadline_expired(current_height, fund_last) {
                    return Self::deadline_failure_status(
                        session,
                        created_at,
                        "funding_deadline_expired",
                    )
                    .map(Some);
                }
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                let evidence = rail_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_observed",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            ("submarine", Some("funding_observed")) => {
                let requester_status =
                    status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                        .ok_or_else(|| {
                            "submarine funding observation lost its requester source".to_owned()
                        })?;
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations() < self.minimum_confirmations {
                    if !terms.zero_confirmation || terms.rail != ChainRailKind::Bitcoin {
                        return Ok(None);
                    }
                    let RailChainObservation::Bitcoin(observation) = observation else {
                        return Err(
                            "zero-conf admission reached a non-Bitcoin observation".to_owned()
                        );
                    };
                    let inputs = zero_conf_inputs(&observation)?;
                    match self.zero_conf_check(
                        &session.config().session_id,
                        &transaction_id,
                        output_index,
                        &terms,
                        self.minimum_confirmations,
                        &inputs,
                    )? {
                        ZeroConfCheck::Accepted(observation) => {
                            if !self.reserve_zero_conf_risk(
                                &session.config().session_id,
                                terms.amount_sat,
                                terms.desired_completion_time,
                                created_at,
                            )? {
                                let extra = zero_conf_status_extra(
                                    &observation,
                                    "btc-zero-conf-bounded-v1",
                                    "confirmation_required",
                                    Some("aggregate_cap"),
                                    None,
                                )?;
                                return Self::next_status(
                                    session,
                                    created_at,
                                    "funding_confirmation_required",
                                    extra,
                                )
                                .map(Some);
                            }
                            let extra = zero_conf_status_extra(
                                &observation,
                                "btc-zero-conf-bounded-v1",
                                "accepted",
                                None,
                                None,
                            )?;
                            return Self::next_status(
                                session,
                                created_at,
                                "funding_zero_conf_accepted",
                                extra,
                            )
                            .map(Some);
                        }
                        ZeroConfCheck::Final(observation) => {
                            let observation = RailChainObservation::Bitcoin(observation);
                            let evidence = rail_output_evidence(
                                session,
                                &observation,
                                "verified",
                                created_at,
                            )?;
                            return Self::next_status_with_evidence(
                                session,
                                created_at,
                                "funding_final",
                                evidence,
                                rail_transaction_extra(&observation),
                            )
                            .map(Some);
                        }
                        ZeroConfCheck::Downgrade {
                            reason,
                            replacement_txid,
                        } => {
                            let extra = zero_conf_status_extra(
                                &observation,
                                "btc-zero-conf-bounded-v1",
                                "confirmation_required",
                                Some(reason),
                                replacement_txid.as_deref(),
                            )?;
                            return Self::next_status(
                                session,
                                created_at,
                                "funding_confirmation_required",
                                extra,
                            )
                            .map(Some);
                        }
                    }
                }
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            ("submarine", Some("funding_zero_conf_accepted")) => {
                let accepted_status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "funding_zero_conf_accepted",
                )
                .ok_or_else(|| "zero-conf acceptance Status is unavailable".to_owned())?;
                if unix_now()? <= accepted_status.created_at {
                    return Ok(None);
                }
                let requester_status =
                    status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                        .ok_or_else(|| "zero-conf funding lost its requester source".to_owned())?;
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let inputs = zero_conf_status_inputs(
                    records,
                    &session.config().provider_pubkey,
                    "funding_zero_conf_accepted",
                )?;
                match self.zero_conf_check(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                    self.minimum_confirmations,
                    &inputs,
                )? {
                    ZeroConfCheck::Accepted(_) => Self::next_status(
                        session,
                        created_at,
                        "lightning_payment_pending",
                        Map::new(),
                    )
                    .map(Some),
                    ZeroConfCheck::Final(observation) => {
                        self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                        let observation = RailChainObservation::Bitcoin(observation);
                        let evidence =
                            rail_output_evidence(session, &observation, "verified", created_at)?;
                        Self::next_status_with_evidence(
                            session,
                            created_at,
                            "funding_final",
                            evidence,
                            rail_transaction_extra(&observation),
                        )
                        .map(Some)
                    }
                    ZeroConfCheck::Downgrade {
                        reason,
                        replacement_txid,
                    } => {
                        self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                        let extra = zero_conf_downgrade_extra(
                            records,
                            &session.config().provider_pubkey,
                            "funding_zero_conf_accepted",
                            reason,
                            replacement_txid.as_deref(),
                        )?;
                        Self::next_status(
                            session,
                            created_at,
                            "funding_confirmation_required",
                            extra,
                        )
                        .map(Some)
                    }
                }
            }
            ("submarine", Some("funding_confirmation_required")) => {
                let requester_status =
                    status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                        .ok_or_else(|| {
                            "confirmation-required funding lost its requester source".to_owned()
                        })?;
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations() < self.minimum_confirmations {
                    return Ok(None);
                }
                self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            ("submarine", Some("funding_final")) => {
                Self::next_status(session, created_at, "lightning_payment_pending", Map::new())
                    .map(Some)
            }
            ("submarine", Some("lightning_payment_pending")) => {
                let claim_last = terms
                    .claim_last
                    .ok_or_else(|| "submarine contract has no claim deadline".to_owned())?;
                let current_height = u32::try_from(self.chain_rail_height(
                    "submarine-claim-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "submarine claim height exceeds u32".to_owned())?;
                if deadline_expired(current_height, claim_last) {
                    return Self::deadline_failure_status(
                        session,
                        created_at,
                        "claim_deadline_expired",
                    )
                    .map(Some);
                }
                let requester_status =
                    status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                        .ok_or_else(|| {
                            "submarine payment lost its requester funding source".to_owned()
                        })?;
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations() < self.minimum_confirmations
                    && status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "funding_zero_conf_accepted",
                    )
                    .is_none()
                {
                    return Err(
                        "submarine funding lost required confirmation before payment".to_owned(),
                    );
                }
                if observation.confirmations() < self.minimum_confirmations {
                    let inputs = zero_conf_status_inputs(
                        records,
                        &session.config().provider_pubkey,
                        "funding_zero_conf_accepted",
                    )?;
                    match self.zero_conf_check(
                        &session.config().session_id,
                        &transaction_id,
                        output_index,
                        &terms,
                        self.minimum_confirmations,
                        &inputs,
                    )? {
                        ZeroConfCheck::Accepted(_) => {}
                        ZeroConfCheck::Final(_) => {
                            self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                        }
                        ZeroConfCheck::Downgrade {
                            reason,
                            replacement_txid,
                        } => {
                            self.release_zero_conf_risk(&session.config().session_id, created_at)?;
                            let extra = zero_conf_downgrade_extra(
                                records,
                                &session.config().provider_pubkey,
                                "funding_zero_conf_accepted",
                                reason,
                                replacement_txid.as_deref(),
                            )?;
                            return Self::next_status(
                                session,
                                created_at,
                                "funding_confirmation_required",
                                extra,
                            )
                            .map(Some);
                        }
                    }
                }
                if self.cooperative_signing && terms.rail == ChainRailKind::Bitcoin {
                    self.prepare_cooperative_session(session)?;
                }
                let invoice = rfq_invoice(exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?)?;
                let effect_height = u32::try_from(self.chain_rail_height(
                    "submarine-claim-effect-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "submarine claim effect height exceeds u32".to_owned())?;
                let Some(result) =
                    execute_before_exclusive_deadline(effect_height, claim_last, || {
                        match &observation {
                            RailChainObservation::Bitcoin(observation) => self
                                .execute_submarine_claim(
                                    session,
                                    observation,
                                    &terms,
                                    &invoice,
                                    created_at,
                                ),
                            RailChainObservation::Liquid(observation) => self
                                .execute_liquid_submarine_claim(
                                    session,
                                    observation,
                                    &terms,
                                    &invoice,
                                    created_at,
                                ),
                        }
                    })?
                else {
                    return Self::deadline_failure_status(
                        session,
                        created_at,
                        "claim_deadline_expired",
                    )
                    .map(Some);
                };
                let evidence = lightning_evidence(
                    session,
                    &terms.payment_hash,
                    "lightning_payment",
                    "settled",
                    &result,
                    created_at,
                    "provider paid the exact contracted invoice",
                )?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "lightning_paid",
                    evidence,
                    Map::new(),
                )
                .map(Some)
            }
            ("submarine", Some("lightning_paid")) => {
                if self.cooperative_signing && terms.rail == ChainRailKind::Bitcoin {
                    return self
                        .begin_cooperative_session(session, created_at)
                        .map(Some);
                }
                if terms.rail == ChainRailKind::Liquid {
                    let funding_status =
                        status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                            .ok_or_else(|| {
                            "Liquid submarine claim lost its funding Status".to_owned()
                        })?;
                    let (funding_transaction_id, funding_output_index) =
                        status_transaction_reference(funding_status)?;
                    let claim_effect_id =
                        deterministic_id("submarine_claim", &session.config().session_id);
                    let claim_transaction_id = self.applied_liquid_effect_transaction_id(
                        &claim_effect_id,
                        LiquidEffectOperation::SubmarineClaim,
                    )?;
                    let artifact = json!({"claim_txid":claim_transaction_id});
                    let evidence = chain_spend_evidence(
                        session,
                        ChainRailKind::Liquid,
                        &funding_transaction_id,
                        funding_output_index,
                        "measured",
                        &artifact,
                        created_at,
                        "provider Liquid claim accepted by elementsd",
                    )?;
                    let mut extra = Map::new();
                    extra.insert(
                        "transaction_id".to_owned(),
                        Value::String(claim_transaction_id),
                    );
                    return Self::next_status_with_evidence(
                        session,
                        created_at,
                        "provider_claim_pending",
                        evidence,
                        extra,
                    )
                    .map(Some);
                }
                let job = self.submarine_claim_watch(&session.config().session_id)?;
                let evidence = watch_evidence(session, &job, "claim", "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_claim_pending",
                    evidence,
                    watch_extra(&job),
                )
                .map(Some)
            }
            ("submarine", Some("cooperative_signing_pending")) => {
                if let Some(action) = self.next_cooperative_action(session, created_at)? {
                    return Ok(Some(action));
                }
                let provider = &session.config().provider_pubkey;
                let aborted = has_cooperative_action(
                    records,
                    provider,
                    ParticipantRole::Provider,
                    CooperativeSigningAction::Aborted,
                )?;
                let job = if aborted {
                    let invoice = rfq_invoice(exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?)?;
                    self.execute_submarine_fallback_claim(session, &terms, &invoice, created_at)?
                } else if has_cooperative_action(
                    records,
                    provider,
                    ParticipantRole::Provider,
                    CooperativeSigningAction::FinalSignature,
                )? {
                    self.submarine_claim_watch(&session.config().session_id)?
                } else {
                    return Ok(None);
                };
                let evidence = watch_evidence(session, &job, "claim", "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_claim_pending",
                    evidence,
                    watch_extra(&job),
                )
                .map(Some)
            }
            ("submarine", Some("provider_claim_pending")) => {
                if terms.rail == ChainRailKind::Liquid {
                    let status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_claim_pending",
                    )
                    .ok_or_else(|| "Liquid submarine claim Status is unavailable".to_owned())?;
                    let claim_transaction_id = status_transaction_id(status)?;
                    let required_confirmations = required_chain_confirmations(
                        self.minimum_confirmations,
                        self.reorg_safety_blocks,
                    )?;
                    if !self.chain_effect_is_final(
                        "liquid-submarine-claim-final",
                        &session.config().session_id,
                        ChainRailKind::Liquid,
                        "claim_broadcast",
                        &claim_transaction_id,
                        required_confirmations,
                    )? {
                        return Ok(None);
                    }
                    let funding_status =
                        status_by_state(records, requester_pubkey, "requester_funding_broadcast")
                            .ok_or_else(|| {
                            "Liquid submarine claim lost its funding Status".to_owned()
                        })?;
                    let (funding_transaction_id, funding_output_index) =
                        status_transaction_reference(funding_status)?;
                    let artifact = json!({"claim_txid":claim_transaction_id});
                    let evidence = chain_spend_evidence(
                        session,
                        ChainRailKind::Liquid,
                        &funding_transaction_id,
                        funding_output_index,
                        "settled",
                        &artifact,
                        created_at,
                        "provider Liquid claim reached reorg-safe finality",
                    )?;
                    let mut extra = Map::new();
                    extra.insert(
                        "transaction_id".to_owned(),
                        Value::String(claim_transaction_id),
                    );
                    return Self::next_status_with_evidence(
                        session,
                        created_at,
                        "provider_claimed",
                        evidence,
                        extra,
                    )
                    .map(Some);
                }
                let job = self.submarine_claim_watch(&session.config().session_id)?;
                if job.state != "confirmed"
                    || job.confirmations
                        < required_chain_confirmations(
                            self.minimum_confirmations,
                            self.reorg_safety_blocks,
                        )?
                {
                    return Ok(None);
                }
                let evidence =
                    watch_evidence(session, &job, "bitcoin_spend", "settled", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_claimed",
                    evidence,
                    watch_extra(&job),
                )
                .map(Some)
            }
            ("submarine", Some("provider_claimed")) => {
                Self::next_status(session, created_at, "completed", Map::new()).map(Some)
            }
            ("submarine", Some("completed")) => self
                .terminal_close(session, "submarine", "completed", created_at)
                .map(Some),
            ("reverse", Some("accepted")) => {
                let invoice = self.reverse_invoice_for_session(session)?;
                let mut extra = Map::new();
                extra.insert("invoice".to_owned(), Value::String(invoice));
                Self::next_status(session, created_at, "hold_invoice_ready", extra).map(Some)
            }
            ("reverse", Some("hold_invoice_ready")) => {
                let Some(lightning_pending) =
                    status_by_state(records, requester_pubkey, "lightning_payment_pending")
                else {
                    return Ok(None);
                };
                if status_by_state(records, requester_pubkey, "requester_invoice_verified")
                    .is_none()
                {
                    return Ok(None);
                }
                let lock_last = terms
                    .lock_last
                    .ok_or_else(|| "reverse contract has no lock deadline".to_owned())?;
                let current_height = u32::try_from(self.chain_rail_height(
                    "reverse-lock-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "reverse lock height exceeds u32".to_owned())?;
                if deadline_expired(current_height, lock_last) {
                    return Self::hold_failure_status(
                        session,
                        created_at,
                        "invoice_cancel_pending",
                        "lock_deadline_expired",
                    )
                    .map(Some);
                }
                let state =
                    self.reverse_hold_state(&session.config().session_id, &terms.payment_hash)?;
                match hold_state_decision(&state)? {
                    HoldStateDecision::Verify => {}
                    HoldStateDecision::Wait => return Ok(None),
                    HoldStateDecision::Cancel(failure_code) => {
                        return Self::hold_failure_status(
                            session,
                            created_at,
                            "invoice_cancel_pending",
                            failure_code,
                        )
                        .map(Some);
                    }
                    HoldStateDecision::Unresolved(failure_code) => {
                        self.mark_hold_unresolved(
                            &session.config().session_id,
                            &terms.payment_hash,
                            failure_code,
                            created_at,
                        )?;
                        return Self::hold_failure_status(
                            session,
                            created_at,
                            "unresolved",
                            failure_code,
                        )
                        .map(Some);
                    }
                }
                let summary = match self.verify_reverse_hold_safety(
                    &session.config().session_id,
                    &terms,
                    created_at,
                ) {
                    Ok(summary) => summary,
                    Err(ReverseHoldSafetyError::Invalid(reason)) => {
                        eprintln!("immortal-provider: cancelling invalid held HTLC set: {reason}");
                        return Self::hold_failure_status(
                            session,
                            created_at,
                            "invoice_cancel_pending",
                            "invalid_hold_invoice",
                        )
                        .map(Some);
                    }
                    Err(ReverseHoldSafetyError::Unavailable(error)) => return Err(error),
                };
                let result = summary.public_artifact(&terms.payment_hash);
                let evidence = lightning_evidence(
                    session,
                    &terms.payment_hash,
                    "lightning_htlc",
                    "verified",
                    &result,
                    created_at,
                    "provider CLN reports held HTLCs",
                )?;
                Self::next_status_with_evidence_after(
                    session,
                    created_at,
                    "lightning_htlcs_held",
                    &lightning_pending.id,
                    evidence,
                    Map::new(),
                )
                .map(Some)
            }
            ("reverse", Some("lightning_htlcs_held")) => {
                Self::next_status(session, created_at, "provider_lock_terms_ready", Map::new())
                    .map(Some)
            }
            ("reverse", Some("provider_lock_terms_ready")) => {
                let Some(lock_verified) =
                    status_by_state(records, requester_pubkey, "requester_lock_verified")
                else {
                    return Ok(None);
                };
                let lock_last = terms
                    .lock_last
                    .ok_or_else(|| "reverse contract has no lock deadline".to_owned())?;
                let current_height = u32::try_from(self.chain_rail_height(
                    "reverse-fund-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "reverse funding height exceeds u32".to_owned())?;
                if deadline_expired(current_height, lock_last) {
                    return Self::hold_failure_status(
                        session,
                        created_at,
                        "invoice_cancel_pending",
                        "lock_deadline_expired",
                    )
                    .map(Some);
                }
                match self.verify_reverse_hold_safety(
                    &session.config().session_id,
                    &terms,
                    created_at,
                ) {
                    Ok(_) => {}
                    Err(ReverseHoldSafetyError::Invalid(reason)) => {
                        eprintln!("immortal-provider: cancelling invalid held HTLC set: {reason}");
                        return Self::hold_failure_status(
                            session,
                            created_at,
                            "invoice_cancel_pending",
                            "invalid_hold_invoice",
                        )
                        .map(Some);
                    }
                    Err(ReverseHoldSafetyError::Unavailable(error)) => return Err(error),
                }
                let effect_height = u32::try_from(self.chain_rail_height(
                    "reverse-funding-effect-deadline",
                    &session.config().session_id,
                    terms.rail,
                )?)
                .map_err(|_| "reverse funding effect height exceeds u32".to_owned())?;
                let Some((transaction_id, output_index, result)) =
                    execute_before_exclusive_deadline(effect_height, lock_last, || {
                        self.execute_reverse_funding(
                            session,
                            &terms,
                            quote_allocation(&session.config().session_id)?.unilateral_path,
                            created_at,
                        )
                    })?
                else {
                    return Self::hold_failure_status(
                        session,
                        created_at,
                        "invoice_cancel_pending",
                        "lock_deadline_expired",
                    )
                    .map(Some);
                };
                let evidence = chain_transaction_evidence(
                    session,
                    terms.rail,
                    &transaction_id,
                    "measured",
                    &result,
                    created_at,
                    "provider funding accepted by the local chain node",
                )?;
                let mut extra = Map::new();
                extra.insert("transaction_id".to_owned(), Value::String(transaction_id));
                extra.insert("output_index".to_owned(), json!(output_index));
                Self::next_status_with_evidence_after(
                    session,
                    created_at,
                    "provider_funding_broadcast",
                    &lock_verified.id,
                    evidence,
                    extra,
                )
                .map(Some)
            }
            ("reverse", Some("provider_funding_broadcast")) => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_funding_broadcast",
                )
                .ok_or_else(|| "reverse funding Status is unavailable".to_owned())?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                let evidence = rail_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_observed",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            ("reverse", Some("funding_observed")) => {
                let status = status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_funding_broadcast",
                )
                .ok_or_else(|| "reverse funding Status is unavailable".to_owned())?;
                let (transaction_id, output_index) = status_transaction_reference(status)?;
                let observation = self.observe_contract_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations() < self.minimum_confirmations {
                    return Ok(None);
                }
                let evidence = rail_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_final",
                    evidence,
                    rail_transaction_extra(&observation),
                )
                .map(Some)
            }
            ("reverse", Some("funding_final")) => {
                self.next_reverse_after_funding(session, created_at, &terms)
            }
            ("reverse", Some("lightning_settlement_pending")) => {
                let state =
                    self.reverse_hold_state(&session.config().session_id, &terms.payment_hash)?;
                if !matches!(state.as_str(), "paid" | "settled") {
                    return Ok(None);
                }
                let result = json!({"payment_hash":terms.payment_hash,"state":state});
                let evidence = lightning_evidence(
                    session,
                    &terms.payment_hash,
                    "lightning_payment",
                    "settled",
                    &result,
                    created_at,
                    "provider CLN reports the hold invoice settled",
                )?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "lightning_paid",
                    evidence,
                    Map::new(),
                )
                .map(Some)
            }
            ("reverse", Some("lightning_paid")) => {
                Self::next_status(session, created_at, "completed", Map::new()).map(Some)
            }
            ("reverse", Some("completed")) => self
                .terminal_close(session, "reverse", "completed", created_at)
                .map(Some),
            ("reverse", Some("provider_refund_prepared")) => {
                if terms.rail == ChainRailKind::Liquid {
                    let status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_refund_prepared",
                    )
                    .ok_or_else(|| "Liquid reverse refund Status is unavailable".to_owned())?;
                    let refund_transaction_id = status_transaction_id(status)?;
                    let applied = self.applied_liquid_effect_transaction_id(
                        &deterministic_id("reverse_refund", &session.config().session_id),
                        LiquidEffectOperation::ReverseRefund,
                    )?;
                    if applied != refund_transaction_id {
                        return Err(
                            "Liquid reverse refund Status differs from its durable effect"
                                .to_owned(),
                        );
                    }
                    let funding_status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_funding_broadcast",
                    )
                    .ok_or_else(|| "Liquid reverse funding Status is unavailable".to_owned())?;
                    let (funding_transaction_id, funding_output_index) =
                        status_transaction_reference(funding_status)?;
                    let artifact = json!({"refund_txid":refund_transaction_id});
                    let evidence = chain_spend_evidence(
                        session,
                        ChainRailKind::Liquid,
                        &funding_transaction_id,
                        funding_output_index,
                        "measured",
                        &artifact,
                        created_at,
                        "provider Liquid refund accepted by elementsd",
                    )?;
                    let mut extra = Map::new();
                    extra.insert(
                        "transaction_id".to_owned(),
                        Value::String(refund_transaction_id),
                    );
                    return Self::next_status_with_evidence(
                        session,
                        created_at,
                        "provider_refund_pending",
                        evidence,
                        extra,
                    )
                    .map(Some);
                }
                let job = self.watch_job("refund_broadcast", &session.config().session_id)?;
                if !matches!(job.state.as_str(), "broadcast" | "confirmed") {
                    return Ok(None);
                }
                let evidence = watch_evidence(session, &job, "refund", "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_refund_pending",
                    evidence,
                    watch_extra(&job),
                )
                .map(Some)
            }
            ("reverse", Some("provider_refund_pending")) => {
                if terms.rail == ChainRailKind::Liquid {
                    let status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_refund_pending",
                    )
                    .ok_or_else(|| "Liquid reverse refund Status is unavailable".to_owned())?;
                    let refund_transaction_id = status_transaction_id(status)?;
                    let required_confirmations = required_chain_confirmations(
                        self.minimum_confirmations,
                        self.reorg_safety_blocks,
                    )?;
                    if !self.chain_effect_is_final(
                        "liquid-reverse-refund-final",
                        &session.config().session_id,
                        ChainRailKind::Liquid,
                        "refund_broadcast",
                        &refund_transaction_id,
                        required_confirmations,
                    )? {
                        return Ok(None);
                    }
                    let funding_status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_funding_broadcast",
                    )
                    .ok_or_else(|| "Liquid reverse funding Status is unavailable".to_owned())?;
                    let (funding_transaction_id, funding_output_index) =
                        status_transaction_reference(funding_status)?;
                    let artifact = json!({"refund_txid":refund_transaction_id});
                    let evidence = chain_spend_evidence(
                        session,
                        ChainRailKind::Liquid,
                        &funding_transaction_id,
                        funding_output_index,
                        "settled",
                        &artifact,
                        created_at,
                        "provider Liquid refund reached reorg-safe finality",
                    )?;
                    let mut extra = Map::new();
                    extra.insert(
                        "transaction_id".to_owned(),
                        Value::String(refund_transaction_id),
                    );
                    return Self::next_status_with_evidence(
                        session,
                        created_at,
                        "provider_refunded",
                        evidence,
                        extra,
                    )
                    .map(Some);
                }
                let job = self.watch_job("refund_broadcast", &session.config().session_id)?;
                if job.state != "confirmed"
                    || job.confirmations
                        < required_chain_confirmations(
                            self.minimum_confirmations,
                            self.reorg_safety_blocks,
                        )?
                {
                    return Ok(None);
                }
                let evidence = watch_evidence(session, &job, "refund", "settled", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_refunded",
                    evidence,
                    watch_extra(&job),
                )
                .map(Some)
            }
            ("reverse", Some("provider_refunded")) => {
                if terms.rail == ChainRailKind::Liquid {
                    let status = status_by_state(
                        records,
                        &session.config().provider_pubkey,
                        "provider_refunded",
                    )
                    .ok_or_else(|| "Liquid reverse refund Status is unavailable".to_owned())?;
                    let refund_transaction_id = status_transaction_id(status)?;
                    if !self.chain_effect_is_final(
                        "liquid-reverse-refund-recheck",
                        &session.config().session_id,
                        ChainRailKind::Liquid,
                        "refund_broadcast",
                        &refund_transaction_id,
                        required_chain_confirmations(
                            self.minimum_confirmations,
                            self.reorg_safety_blocks,
                        )?,
                    )? {
                        return Self::next_status(
                            session,
                            created_at,
                            "unresolved",
                            hold_failure_extra("refund_reorg"),
                        )
                        .map(Some);
                    }
                }
                self.cancel_reverse_invoice(
                    &session.config().session_id,
                    &terms.payment_hash,
                    created_at,
                )?;
                let result = json!({
                    "payment_hash":terms.payment_hash,
                    "state":"cancelled",
                });
                let evidence = lightning_evidence(
                    session,
                    &terms.payment_hash,
                    "invoice",
                    "verified",
                    &result,
                    created_at,
                    "provider CLN confirms refunded hold invoice cancellation",
                )?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "invoice_cancelled",
                    evidence,
                    Map::new(),
                )
                .map(Some)
            }
            ("reverse", Some("invoice_cancel_pending")) => {
                let failure_code = hold_failure_code(
                    records,
                    &session.config().provider_pubkey,
                    "invoice_cancel_pending",
                )?;
                match self.cancel_unfunded_reverse(&session.config().session_id, created_at) {
                    Ok(()) => {
                        let result = json!({
                            "payment_hash":terms.payment_hash,
                            "state":"cancelled",
                            "failure_code":failure_code,
                        });
                        let evidence = lightning_evidence(
                            session,
                            &terms.payment_hash,
                            "invoice",
                            "settled",
                            &result,
                            created_at,
                            "provider CLN confirms invalid hold invoice cancellation",
                        )?;
                        Self::next_status_with_evidence(
                            session,
                            created_at,
                            "invoice_cancelled",
                            evidence,
                            hold_failure_extra(&failure_code),
                        )
                        .map(Some)
                    }
                    Err(error)
                        if error
                            == "reverse invoice settled before an unfunded cancellation could complete" =>
                    {
                        self.mark_hold_unresolved(
                            &session.config().session_id,
                            &terms.payment_hash,
                            "invalid_hold_invoice_settled",
                            created_at,
                        )?;
                        Self::hold_failure_status(
                            session,
                            created_at,
                            "unresolved",
                            "invalid_hold_invoice_settled",
                        )
                        .map(Some)
                    }
                    Err(error) => Err(error),
                }
            }
            ("reverse", Some("invoice_cancelled")) => {
                if status_by_state(
                    records,
                    &session.config().provider_pubkey,
                    "provider_refunded",
                )
                .is_some()
                {
                    Self::next_status(session, created_at, "refunded", Map::new()).map(Some)
                } else {
                    let failure_code = hold_failure_code(
                        records,
                        &session.config().provider_pubkey,
                        "invoice_cancelled",
                    )?;
                    self.release_session_reservation(&session.config().session_id, created_at)?;
                    Self::hold_failure_status(session, created_at, "expired", &failure_code)
                        .map(Some)
                }
            }
            ("reverse", Some("refunded")) => self
                .terminal_close(session, "reverse", "refunded", created_at)
                .map(Some),
            _ => Ok(None),
        }
    }
}

fn bind_reverse_funding_profile(
    mut profile: Value,
    funding: &SignedFundingTransaction,
) -> Result<Value, String> {
    let raw_bytes = decode_hex(&funding.raw_transaction)?;
    let terms = profile
        .get_mut("terms")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "reverse Quote terms disappeared during binding".to_owned())?;
    let verifiers = terms
        .get_mut("verifier_inputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "reverse Quote verifier inputs disappeared during binding".to_owned())?;
    let verifier = verifiers
        .iter_mut()
        .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some("destination"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "reverse destination verifier disappeared during binding".to_owned())?;
    verifier.insert(
        "funding_transaction".to_owned(),
        Value::String(funding.raw_transaction.clone()),
    );
    verifier.insert(
        "funding_transaction_sha256".to_owned(),
        Value::String(lower_hex(&sha256(&raw_bytes))),
    );
    verifier.insert("output_index".to_owned(), json!(0));
    let verifier_digest = lower_hex(&sha256(
        &canonical_json(&Value::Object(verifier.clone()))
            .map_err(|_| "reverse funding verifier is not canonical".to_owned())?,
    ));
    let leg = terms
        .get_mut("legs")
        .and_then(Value::as_array_mut)
        .and_then(|legs| {
            legs.iter_mut()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some("destination"))
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "reverse Quote has no destination leg".to_owned())?;
    leg.insert("verifier_digest".to_owned(), Value::String(verifier_digest));
    Ok(profile)
}

fn bind_liquid_funding_profile(
    mut profile: Value,
    funding: &crate::elementsd::ElementsdSignedFunding,
) -> Result<Value, String> {
    let terms = profile
        .get_mut("terms")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Liquid reverse Quote terms disappeared during binding".to_owned())?;
    let verifier = terms
        .get_mut("verifier_inputs")
        .and_then(Value::as_array_mut)
        .and_then(|verifiers| {
            verifiers.iter_mut().find(|verifier| {
                verifier.get("leg_id").and_then(Value::as_str) == Some("destination")
            })
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            "Liquid reverse destination verifier disappeared during binding".to_owned()
        })?;
    if verifier.get("verifier_policy").and_then(Value::as_str) != Some("mkt-swp-liquid-v1")
        || decode_hex(required_string(verifier, "script_pubkey")?)? != funding.script_pubkey
        || canonical_u64(required_string(verifier, "amount")?)? != funding.amount_sat
    {
        return Err("Liquid funding differs from the quoted destination".to_owned());
    }
    verifier.insert(
        "funding_transaction".to_owned(),
        Value::String(lower_hex(&funding.raw_transaction)),
    );
    verifier.insert(
        "funding_transaction_sha256".to_owned(),
        Value::String(lower_hex(&sha256(&funding.raw_transaction))),
    );
    verifier.insert("output_index".to_owned(), json!(funding.output_index));
    let verifier_digest = lower_hex(&sha256(
        &canonical_json(&Value::Object(verifier.clone()))
            .map_err(|_| "Liquid funding verifier is not canonical".to_owned())?,
    ));
    let leg = terms
        .get_mut("legs")
        .and_then(Value::as_array_mut)
        .and_then(|legs| {
            legs.iter_mut()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some("destination"))
        })
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Liquid reverse destination leg disappeared during binding".to_owned())?;
    leg.insert("verifier_digest".to_owned(), Value::String(verifier_digest));
    Ok(profile)
}

fn validate_executable_reverse_funding(
    funding: &SignedFundingTransaction,
    terms: &ChainTerms,
) -> Result<(), String> {
    if terms.committed_funding_transaction.as_deref() == Some(funding.raw_transaction.as_str()) {
        Ok(())
    } else {
        Err("reverse funding changed after the bilateral commitment".to_owned())
    }
}

fn chain_observation_from_response(
    response: &Value,
    transaction_id: &str,
    output_index: u32,
    terms: &ChainTerms,
) -> Result<ChainObservation, String> {
    let object = response
        .as_object()
        .ok_or_else(|| "funding observation is not an object".to_owned())?;
    if object.get("txid").and_then(Value::as_str) != Some(transaction_id) {
        return Err("funding observation returned another transaction".to_owned());
    }
    let raw = object
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| "funding observation has no raw transaction".to_owned())?;
    if terms
        .committed_funding_transaction
        .as_deref()
        .is_some_and(|committed| committed != raw)
    {
        return Err(
            "observed funding differs from the bilateral transaction commitment".to_owned(),
        );
    }
    if !terms.committed_funding_sha256.is_empty()
        && terms.committed_funding_sha256 != lower_hex(&sha256(&decode_hex(raw)?))
    {
        return Err("observed funding differs from the bilateral digest commitment".to_owned());
    }
    let transaction = Transaction::parse(&decode_hex(raw)?)
        .map_err(|error| format!("funding transaction is invalid: {error}"))?;
    let computed_id = lower_hex(
        &transaction
            .txid()
            .map_err(|error| format!("funding transaction ID is invalid: {error}"))?,
    );
    if computed_id != transaction_id {
        return Err("funding raw transaction does not match its transaction ID".to_owned());
    }
    if transaction
        .inputs
        .iter()
        .any(|input| input.sequence < 0xffff_fffe)
    {
        return Err("funding transaction opts in to replacement against the contract".to_owned());
    }
    let output = transaction
        .outputs
        .get(usize::try_from(output_index).map_err(|_| "funding vout exceeds usize")?)
        .ok_or_else(|| "funding transaction has no contracted output".to_owned())?;
    if output.value_sat != terms.amount_sat || output.script_pubkey != terms.script_pubkey {
        return Err("funding output differs from the bilateral contract".to_owned());
    }
    let confirmations = object
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let confirmations = u32::try_from(confirmations)
        .map_err(|_| "funding confirmation count exceeds u32".to_owned())?;
    let block_hash = object
        .get("blockhash")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if confirmations > 0 && block_hash.is_none() {
        return Err("confirmed funding has no block hash".to_owned());
    }
    Ok(ChainObservation {
        transaction,
        transaction_id: transaction_id.to_owned(),
        output_index,
        confirmations,
        block_hash,
    })
}

fn validate_zero_conf_mempool_entry(entry: &Value) -> Result<(), String> {
    let entry = entry
        .as_object()
        .ok_or_else(|| "zero-conf mempool entry is not an object".to_owned())?;
    if entry.get("ancestorcount").and_then(Value::as_u64) != Some(1) {
        return Err("zero-conf funding has an unconfirmed ancestor".to_owned());
    }
    let dependencies = entry
        .get("depends")
        .and_then(Value::as_array)
        .ok_or_else(|| "zero-conf mempool entry has no bounded dependency set".to_owned())?;
    if !dependencies.is_empty() {
        return Err("zero-conf funding has an unconfirmed ancestor".to_owned());
    }
    if entry.get("bip125-replaceable").and_then(Value::as_bool) != Some(false) {
        return Err("zero-conf funding is BIP125 replaceable".to_owned());
    }
    Ok(())
}

fn zero_conf_risk_session_id(market_session_id: &str) -> String {
    deterministic_id("zero-conf-risk-session", market_session_id)
}

fn zero_conf_inputs(observation: &ChainObservation) -> Result<Vec<OutPoint>, String> {
    if observation.transaction.inputs.is_empty() || observation.transaction.inputs.len() > 256 {
        return Err("zero-conf funding input set is empty or unbounded".to_owned());
    }
    Ok(observation
        .transaction
        .inputs
        .iter()
        .map(|input| OutPoint {
            txid: display_txid(&input.previous_txid),
            vout: input.previous_output,
        })
        .collect())
}

fn zero_conf_status_extra(
    observation: &ChainObservation,
    policy_id: &str,
    decision: &str,
    reason: Option<&str>,
    replacement_txid: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let inputs = zero_conf_inputs(observation)?;
    let mut acceptance = json!({
        "amount":observation.transaction.outputs.get(usize::try_from(observation.output_index).map_err(|_| "zero-conf output index exceeds usize")?).ok_or_else(|| "zero-conf output is unavailable".to_owned())?.value_sat.to_string(),
        "decision":decision,
        "input_outpoints":inputs.iter().map(|input| json!({"txid":input.txid,"vout":input.vout})).collect::<Vec<_>>(),
        "output_index":observation.output_index,
        "policy_id":policy_id,
        "transaction_id":observation.transaction_id,
        "view":"provider_local_bitcoind",
    });
    let object = acceptance
        .as_object_mut()
        .ok_or_else(|| "zero-conf acceptance is not an object".to_owned())?;
    if let Some(reason) = reason {
        object.insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    if let Some(replacement_txid) = replacement_txid {
        required_hash(replacement_txid, "zero-conf replacement transaction ID")?;
        object.insert(
            "replacement_transaction_id".to_owned(),
            Value::String(replacement_txid.to_owned()),
        );
    }
    let mut extra = transaction_extra(observation);
    extra.insert("zero_confirmation_acceptance".to_owned(), acceptance);
    Ok(extra)
}

fn zero_conf_status_inputs(
    records: &[Event],
    provider_pubkey: &str,
    accepted_state: &str,
) -> Result<Vec<OutPoint>, String> {
    let status = status_by_state(records, provider_pubkey, accepted_state)
        .ok_or_else(|| "zero-conf acceptance Status is unavailable".to_owned())?;
    let profile = record_profile(status)?;
    let inputs = profile
        .get("zero_confirmation_acceptance")
        .and_then(|acceptance| acceptance.get("input_outpoints"))
        .and_then(Value::as_array)
        .filter(|inputs| !inputs.is_empty() && inputs.len() <= 256)
        .ok_or_else(|| "zero-conf acceptance has no bounded input proof".to_owned())?;
    inputs
        .iter()
        .map(|input| {
            let input = input
                .as_object()
                .ok_or_else(|| "zero-conf input proof is invalid".to_owned())?;
            let txid = required_string(input, "txid")?.to_owned();
            required_hash(&txid, "zero-conf input transaction ID")?;
            let vout = input
                .get("vout")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "zero-conf input output index is invalid".to_owned())?;
            Ok(OutPoint { txid, vout })
        })
        .collect()
}

fn zero_conf_downgrade_extra(
    records: &[Event],
    provider_pubkey: &str,
    accepted_state: &str,
    reason: &str,
    replacement_txid: Option<&str>,
) -> Result<Map<String, Value>, String> {
    let status = status_by_state(records, provider_pubkey, accepted_state)
        .ok_or_else(|| "zero-conf acceptance Status is unavailable".to_owned())?;
    let profile = record_profile(status)?;
    let mut acceptance = profile
        .get("zero_confirmation_acceptance")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "zero-conf acceptance proof is unavailable".to_owned())?;
    acceptance.insert(
        "decision".to_owned(),
        Value::String("confirmation_required".to_owned()),
    );
    acceptance.insert("reason".to_owned(), Value::String(reason.to_owned()));
    if let Some(replacement_txid) = replacement_txid {
        required_hash(replacement_txid, "zero-conf replacement transaction ID")?;
        acceptance.insert(
            "replacement_transaction_id".to_owned(),
            Value::String(replacement_txid.to_owned()),
        );
    }
    let mut extra = Map::new();
    for member in ["transaction_id", "output_index", "confirmations"] {
        if let Some(value) = profile.get(member) {
            extra.insert(member.to_owned(), value.clone());
        }
    }
    extra.insert(
        "zero_confirmation_acceptance".to_owned(),
        Value::Object(acceptance),
    );
    Ok(extra)
}

fn validate_liquid_chain_observation(
    observation: LiquidFundingObservation,
    output_index: u32,
    terms: &ChainTerms,
    require_unspent: bool,
) -> Result<LiquidChainObservation, String> {
    let observed_raw = lower_hex(&observation.raw_transaction);
    if let Some(committed) = terms.committed_funding_transaction.as_deref() {
        if observation.transaction_sha256 != terms.committed_funding_sha256
            || committed != observed_raw
        {
            return Err(
                "observed Liquid funding differs from the bilateral byte commitment".to_owned(),
            );
        }
    }
    let transaction = parse_liquid_transaction(&observation.raw_transaction)
        .map_err(|error| format!("observed Liquid funding is invalid: {error}"))?;
    if lower_hex(&transaction.transaction_id) != observation.transaction_id {
        return Err("observed Liquid funding transaction ID differs from its bytes".to_owned());
    }
    let output = transaction
        .outputs
        .get(usize::try_from(output_index).map_err(|_| "Liquid vout exceeds usize")?)
        .ok_or_else(|| "Liquid funding transaction has no contracted output".to_owned())?;
    let (_, expected_asset) = LiquidAssetId::parse_mkt(&terms.asset_id)
        .map_err(|error| format!("contracted Liquid asset is invalid: {error}"))?;
    if output.asset != ConfidentialAsset::Explicit(expected_asset)
        || output.value != ConfidentialValue::Explicit(terms.amount_sat)
        || output.script_pubkey != terms.script_pubkey
    {
        return Err("Liquid funding output differs from the bilateral Contract".to_owned());
    }
    if observation.confirmations > 0 && observation.block_hash.is_none() {
        return Err("confirmed Liquid funding has no block hash".to_owned());
    }
    if require_unspent && !observation.unspent {
        return Err("Liquid funding has a competing or already-spent outpoint".to_owned());
    }
    Ok(LiquidChainObservation {
        transaction_id: observation.transaction_id,
        transaction_sha256: observation.transaction_sha256,
        output_index,
        confirmations: observation.confirmations,
        block_hash: observation.block_hash,
        unspent: observation.unspent,
    })
}

#[derive(Clone, Copy)]
enum SettlementPath {
    Claim,
    Refund,
}

#[derive(Clone, Copy)]
enum WatchDeadline {
    Height(u64),
    Time(u64),
}

impl WatchDeadline {
    fn due_height(self) -> Option<u64> {
        match self {
            Self::Height(height) => Some(height),
            Self::Time(_) => None,
        }
    }

    fn due_at(self) -> Option<u64> {
        match self {
            Self::Height(_) => None,
            Self::Time(time) => Some(time),
        }
    }
}

fn terminal_close_profile(
    session: &ProviderSession,
    swap_type: &str,
    outcome: &str,
) -> Result<Value, String> {
    let records = session.signed_records();
    let contract_event = records
        .iter()
        .find(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                && record.pubkey == session.config().provider_pubkey
        })
        .ok_or_else(|| "provider Close has no provider-signed contract".to_owned())?;
    let profile = record_profile(contract_event)?;
    let contract = profile
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| "provider Close contract is not an object".to_owned())?;
    if contract.get("swap_type").and_then(Value::as_str) != Some(swap_type) {
        return Err("provider Close swap type differs from the contract".to_owned());
    }
    let assets = contract
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|assets| assets.len() == 2)
        .ok_or_else(|| "provider Close contract has no ordered asset pair".to_owned())?;
    let reservation_released = contract
        .get("reservation_commitment")
        .and_then(Value::as_object)
        .and_then(|reservation| reservation.get("reserved_amount"))
        .and_then(Value::as_str)
        .ok_or_else(|| "provider Close contract has no reserved amount".to_owned())?;
    if outcome == "cancelled" {
        let effective = records
            .iter()
            .find(|record| is_effective_cancel(record))
            .ok_or_else(|| "cancelled provider Close has no effective cancellation".to_owned())?;
        return Ok(json!({
            "final_state":"cancelled",
            "external_spend_effects":0,
            "loss_classification":"none",
            "cancel_id":effective.id,
            "loss_accounting":{
                "input_asset_id":assets[0],
                "output_asset_id":assets[1],
                "input_committed":"0",
                "input_recovered":"0",
                "output_received":"0",
                "provider_fee_paid":"0",
                "miner_fee_paid":"0",
                "lightning_routing_fee_paid":"0",
                "guarantee_recovery_received":"0",
                "principal_unresolved":"0",
                "reservation_released":reservation_released,
                "evidence_refs":[],
                "unknown_fields":[],
            }
        }));
    }
    if !matches!(outcome, "completed" | "refunded") {
        return Err("provider Close outcome is unsupported by funded v1".to_owned());
    }
    let terminal_status = status_by_state(records, &session.config().provider_pubkey, outcome)
        .ok_or_else(|| format!("provider Close has no {outcome} Status"))?;
    let evidence_expectations = if swap_type == "chain" {
        chain_terminal_evidence_expectations(
            contract,
            outcome,
            status_by_state(
                records,
                &session.config().provider_pubkey,
                "provider_destination_broadcast",
            )
            .is_some(),
        )?
    } else {
        let leg_id = if swap_type == "submarine" {
            "source"
        } else {
            "destination"
        };
        let chain_leg = contract_entry(contract, "legs", leg_id, "terminal chain leg")?;
        terminal_evidence_expectations(swap_type, outcome, required_string(&chain_leg, "rail")?)?
    };
    let evidence_refs = evidence_expectations
        .iter()
        .map(|expectation| {
            let author = if expectation.state == "requester_source_refunded" {
                &session.config().requester_pubkey
            } else {
                &session.config().provider_pubkey
            };
            status_evidence(records, author, expectation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let input_amount = required_string(contract, "input_amount")?;
    let output_amount = required_string(contract, "output_amount")?;
    let (input_recovered, output_received, provider_fee, miner_fee, lightning_fee) =
        if outcome == "completed" {
            (
                "0",
                output_amount,
                required_string(contract, "provider_fee")?,
                required_string(contract, "miner_fee_budget")?,
                required_string(contract, "lightning_routing_fee_budget")?,
            )
        } else {
            (input_amount, "0", "0", "0", "0")
        };
    Ok(json!({
        "final_state":outcome,
        "status_id":terminal_status.id,
        "external_spend_effects":2,
        "loss_classification":"none",
        "loss_accounting":{
            "input_asset_id":assets[0],
            "output_asset_id":assets[1],
            "input_committed":input_amount,
            "input_recovered":input_recovered,
            "output_received":output_received,
            "provider_fee_paid":provider_fee,
            "miner_fee_paid":miner_fee,
            "lightning_routing_fee_paid":lightning_fee,
            "guarantee_recovery_received":"0",
            "principal_unresolved":"0",
            "reservation_released":reservation_released,
            "evidence_refs":evidence_refs,
            "unknown_fields":[],
        }
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalEvidenceExpectation {
    state: &'static str,
    rail: &'static str,
    class: &'static str,
    rung: &'static str,
}

fn terminal_evidence_expectations(
    swap_type: &str,
    outcome: &str,
    chain_rail: &str,
) -> Result<[TerminalEvidenceExpectation; 2], String> {
    let expectation = |state, rail, class, rung| TerminalEvidenceExpectation {
        state,
        rail,
        class,
        rung,
    };
    let chain = match chain_rail {
        "bitcoin" => ("bitcoin", "bitcoin_spend"),
        "liquid" => ("liquid", "liquid_spend"),
        _ => return Err("provider Close chain evidence uses an unsupported rail".to_owned()),
    };
    match (swap_type, outcome) {
        ("submarine", "completed") => Ok([
            expectation("provider_claimed", chain.0, chain.1, "settled"),
            expectation(
                "lightning_paid",
                "lightning",
                "lightning_payment",
                "settled",
            ),
        ]),
        ("reverse", "completed") => Ok([
            expectation(
                "lightning_paid",
                "lightning",
                "lightning_payment",
                "settled",
            ),
            expectation("lightning_settlement_pending", chain.0, chain.1, "settled"),
        ]),
        ("reverse", "refunded") => Ok([
            expectation("invoice_cancelled", "lightning", "invoice", "verified"),
            expectation(
                "provider_refunded",
                chain.0,
                if chain_rail == "bitcoin" {
                    "refund"
                } else {
                    chain.1
                },
                "settled",
            ),
        ]),
        _ => Err("provider Close has no funded-v1 evidence mapping".to_owned()),
    }
}

fn chain_terminal_evidence_expectations(
    contract: &Map<String, Value>,
    outcome: &str,
    destination_funded: bool,
) -> Result<[TerminalEvidenceExpectation; 2], String> {
    let source = contract_entry(contract, "legs", "source", "chain source leg")?;
    let destination = contract_entry(contract, "legs", "destination", "chain destination leg")?;
    match (
        outcome,
        required_string(&source, "rail")?,
        required_string(&destination, "rail")?,
    ) {
        ("completed", "bitcoin", "liquid") => Ok([
            TerminalEvidenceExpectation {
                state: "provider_source_claimed",
                rail: "bitcoin",
                class: "bitcoin_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "destination_funding_final",
                rail: "liquid",
                class: "liquid_output",
                rung: "verified",
            },
        ]),
        ("completed", "liquid", "bitcoin") => Ok([
            TerminalEvidenceExpectation {
                state: "provider_source_claimed",
                rail: "liquid",
                class: "liquid_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "destination_funding_final",
                rail: "bitcoin",
                class: "bitcoin_output",
                rung: "verified",
            },
        ]),
        ("refunded", "bitcoin", "liquid") if destination_funded => Ok([
            TerminalEvidenceExpectation {
                state: "requester_source_refunded",
                rail: "bitcoin",
                class: "bitcoin_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "provider_destination_refunded",
                rail: "liquid",
                class: "liquid_spend",
                rung: "settled",
            },
        ]),
        ("refunded", "liquid", "bitcoin") if destination_funded => Ok([
            TerminalEvidenceExpectation {
                state: "requester_source_refunded",
                rail: "liquid",
                class: "liquid_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "provider_destination_refunded",
                rail: "bitcoin",
                class: "bitcoin_spend",
                rung: "settled",
            },
        ]),
        ("refunded", "bitcoin", "liquid") => Ok([
            TerminalEvidenceExpectation {
                state: "requester_source_refunded",
                rail: "bitcoin",
                class: "bitcoin_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "refunded",
                rail: "liquid",
                class: "reservation",
                rung: "verified",
            },
        ]),
        ("refunded", "liquid", "bitcoin") => Ok([
            TerminalEvidenceExpectation {
                state: "requester_source_refunded",
                rail: "liquid",
                class: "liquid_spend",
                rung: "settled",
            },
            TerminalEvidenceExpectation {
                state: "refunded",
                rail: "bitcoin",
                class: "reservation",
                rung: "verified",
            },
        ]),
        _ => Err("chain Close has an unsupported outcome or rail pair".to_owned()),
    }
}

fn status_evidence(
    records: &[Event],
    author: &str,
    expectation: &TerminalEvidenceExpectation,
) -> Result<Value, String> {
    let evidence = status_by_state(records, author, expectation.state)
        .ok_or_else(|| {
            format!(
                "provider has no {} terminal evidence Status",
                expectation.state
            )
        })
        .and_then(record_profile)?
        .get("evidence")
        .cloned()
        .ok_or_else(|| format!("provider {} Status has no evidence", expectation.state))?;
    if evidence.get("rail").and_then(Value::as_str) != Some(expectation.rail)
        || evidence.get("class").and_then(Value::as_str) != Some(expectation.class)
        || evidence.get("rung").and_then(Value::as_str) != Some(expectation.rung)
    {
        return Err(format!(
            "provider {} Status is not exact terminal {} evidence",
            expectation.state, expectation.rail
        ));
    }
    Ok(evidence)
}

fn require_requester_source_refund_evidence(
    session: &ProviderSession,
    source_refunded: &Event,
    source: &ChainTerms,
) -> Result<(), String> {
    let (rail, class) = match source.rail {
        ChainRailKind::Bitcoin => ("bitcoin", "bitcoin_spend"),
        ChainRailKind::Liquid => ("liquid", "liquid_spend"),
    };
    let expectation = TerminalEvidenceExpectation {
        state: "requester_source_refunded",
        rail,
        class,
        rung: "settled",
    };
    let evidence = status_evidence(
        session.signed_records(),
        &session.config().requester_pubkey,
        &expectation,
    )?;
    let funding_status = status_by_state(
        session.signed_records(),
        &session.config().requester_pubkey,
        "requester_source_broadcast",
    )
    .ok_or_else(|| "requester source refund has no source funding Status".to_owned())?;
    let (funding_transaction_id, funding_output_index) =
        status_transaction_reference(funding_status)?;
    if source_refunded.pubkey != session.config().requester_pubkey
        || evidence.get("producer_pubkey").and_then(Value::as_str)
            != Some(session.config().requester_pubkey.as_str())
        || evidence.get("reference").and_then(Value::as_str)
            != Some(format!("{funding_transaction_id}:{funding_output_index}").as_str())
    {
        return Err(
            "requester source refund evidence does not release the source outpoint".to_owned(),
        );
    }
    Ok(())
}

fn unfunded_destination_reservation_evidence(
    session: &ProviderSession,
    destination: &ChainTerms,
    observed_at: u64,
) -> Result<Value, String> {
    let reservation = session
        .reservation()
        .ok_or_else(|| "unfunded chain destination has no provider reservation".to_owned())?;
    let contract_event = session
        .signed_records()
        .iter()
        .find(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                && record.pubkey == session.config().provider_pubkey
        })
        .ok_or_else(|| "unfunded chain destination has no provider Contract".to_owned())?;
    let profile = record_profile(contract_event)?;
    let commitment = profile
        .get("contract")
        .and_then(Value::as_object)
        .and_then(|contract| contract.get("reservation_commitment"))
        .ok_or_else(|| "unfunded chain destination has no reservation commitment".to_owned())?;
    unfunded_destination_reservation_evidence_value(
        &session.config().provider_pubkey,
        destination.rail,
        &reservation.reservation_id,
        commitment,
        observed_at,
    )
}

fn unfunded_destination_reservation_evidence_value(
    provider_pubkey: &str,
    destination_rail: ChainRailKind,
    reservation_id: &str,
    commitment: &Value,
    observed_at: u64,
) -> Result<Value, String> {
    required_hash(provider_pubkey, "provider public key")?;
    required_hash(reservation_id, "reservation ID")?;
    if commitment.get("reservation_id").and_then(Value::as_str) != Some(reservation_id) {
        return Err("provider reservation differs from the bilateral Contract".to_owned());
    }
    let (rail, verifier_policy) = match destination_rail {
        ChainRailKind::Bitcoin => ("bitcoin", "mkt-swp-bitcoin-v1"),
        ChainRailKind::Liquid => ("liquid", "mkt-swp-liquid-v1"),
    };
    Ok(json!({
        "artifact_sha256":value_digest(commitment)?,
        "class":"reservation",
        "observed_at":observed_at,
        "producer_pubkey":provider_pubkey,
        "rail":rail,
        "reference":reservation_id,
        "rung":"verified",
        "verifier_policy":verifier_policy,
        "verifier_pubkey":null,
        "view":"contract:destination-unfunded",
    }))
}

fn chain_terms(session: &ProviderSession, swap_type: &str) -> Result<ChainTerms, String> {
    let expected_leg = match swap_type {
        "submarine" => "source",
        "reverse" => "destination",
        _ => return Err("funded executor received an unsupported swap type".to_owned()),
    };
    let contract_event = session
        .signed_records()
        .iter()
        .find(|record| record.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .ok_or_else(|| "funded executor has no bilateral contract".to_owned())?;
    let profile = record_profile(contract_event)?;
    let contract = profile
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no contract object".to_owned())?;
    if contract.get("swap_type").and_then(Value::as_str) != Some(swap_type) {
        return Err("Swap Contract type differs from the session".to_owned());
    }
    let verifier = contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers.iter().find(|verifier| {
                verifier.get("leg_id").and_then(Value::as_str) == Some(expected_leg)
            })
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no Bitcoin verifier".to_owned())?;
    let leg = contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(expected_leg))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no Bitcoin leg".to_owned())?;
    let lightning_leg = contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some("lightning"))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no Lightning leg".to_owned())?;
    let timeout_ladder = contract
        .get("timeout_ladder")
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no timeout ladder".to_owned())?;
    let amount_sat = canonical_u64(required_string(verifier, "amount")?)?;
    if canonical_u64(required_string(leg, "amount")?)? != amount_sat {
        return Err("Bitcoin leg and verifier amounts differ".to_owned());
    }
    let payment_hash = required_lower_hex(verifier, "payment_hash")
        .or_else(|_| required_lower_hex(contract, "payment_hash"))?;
    if required_lower_hex(leg, "payment_hash")? != payment_hash {
        return Err("Bitcoin leg and verifier payment hashes differ".to_owned());
    }
    let refund_height =
        canonical_u64(required_string(leg, "refund_lock_value")?).and_then(|value| {
            u32::try_from(value).map_err(|_| "refund height exceeds u32".to_owned())
        })?;
    let rail = match required_string(leg, "rail")? {
        "bitcoin" => ChainRailKind::Bitcoin,
        "liquid" => ChainRailKind::Liquid,
        _ => return Err("Swap Contract chain leg has an unsupported rail".to_owned()),
    };
    let asset_id = required_string(leg, "asset_id")?.to_owned();
    let network_id = required_string(leg, "network_id")?.to_owned();
    let committed_funding_transaction = required_string(verifier, "funding_transaction")?;
    let committed_funding_bytes = decode_hex(committed_funding_transaction)?;
    let committed_funding_sha256 = required_lower_hex(verifier, "funding_transaction_sha256")?;
    let output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "funding output index is incomplete or invalid".to_owned())?;
    let zero_confirmation = required_string(verifier, "zero_confirmation")? == "allowed";
    if zero_confirmation
        && (rail != ChainRailKind::Bitcoin
            || required_string(verifier, "rbf_policy")? != "reject"
            || required_string(verifier, "replacement_policy")? != "track")
    {
        return Err("zero-confirmation verifier policy is unsafe".to_owned());
    }
    if committed_funding_sha256 != lower_hex(&sha256(&committed_funding_bytes)) {
        return Err("funding transaction commitment is incomplete or invalid".to_owned());
    }
    let (fund_last, claim_last, lock_last) = match swap_type {
        "submarine" => {
            let fund_last = timeout_height(timeout_ladder, "fund_last")?;
            let claim_last = timeout_height(timeout_ladder, "claim_last")?;
            if fund_last >= claim_last || claim_last >= refund_height {
                return Err("submarine timeout deadlines are not strictly ordered".to_owned());
            }
            (Some(fund_last), Some(claim_last), None)
        }
        "reverse" => {
            let lock_last = timeout_height(timeout_ladder, "lock_last")?;
            let user_claim_last = timeout_height(timeout_ladder, "user_claim_last")?;
            if lock_last >= user_claim_last || user_claim_last >= refund_height {
                return Err("reverse timeout deadlines are not strictly ordered".to_owned());
            }
            (None, None, Some(lock_last))
        }
        _ => return Err("funded executor received an unsupported swap type".to_owned()),
    };
    let miner_fee_budget_sat = canonical_u64(required_string(contract, "miner_fee_budget")?)?;
    let desired_completion_time = contract
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Swap Contract has no desired completion time".to_owned())?;
    let pricing_swap_type = contract_pricing_swap_type(contract)?;
    let fee_rate_sat_per_vbyte = funding_feerate_from_priced_vbytes(
        contract_priced_vbytes(contract, pricing_swap_type)?,
        miner_fee_budget_sat,
    )
    .map_err(|error| error.to_string())?;
    Ok(ChainTerms {
        rail,
        asset_id,
        network_id,
        amount_sat,
        script_pubkey: decode_hex(required_string(verifier, "script_pubkey")?)?,
        claim_script: decode_hex(required_string(verifier, "claim_script")?)?,
        claim_control_block: decode_hex(required_string(verifier, "taproot_claim_control_block")?)?,
        refund_script: decode_hex(required_string(verifier, "refund_script")?)?,
        refund_control_block: decode_hex(required_string(
            verifier,
            "taproot_refund_control_block",
        )?)?,
        taproot_internal_key: required_lower_hex(verifier, "taproot_internal_key")?,
        taproot_merkle_root: required_lower_hex(verifier, "taproot_merkle_root")?,
        payment_hash,
        refund_height,
        fee_rate_sat_per_vbyte,
        lightning_fee_budget_sat: canonical_u64(required_string(
            contract,
            "lightning_routing_fee_budget",
        )?)?,
        lightning_amount_sat: canonical_u64(required_string(lightning_leg, "amount")?)?,
        fund_last,
        claim_last,
        lock_last,
        hold_expiry_height: timeout_ladder
            .get("hold_expiry_height")
            .and_then(Value::as_u64)
            .map(|height| {
                u32::try_from(height).map_err(|_| "hold expiry height exceeds u32".to_owned())
            })
            .transpose()?,
        lightning_settlement_blocks: timeout_ladder
            .get("lightning_settlement_blocks")
            .and_then(Value::as_u64)
            .map(|blocks| {
                u32::try_from(blocks)
                    .map_err(|_| "Lightning settlement margin exceeds u32".to_owned())
            })
            .transpose()?
            .unwrap_or(0),
        broadcast_safety_blocks: timeout_ladder
            .get("broadcast_safety_blocks")
            .and_then(Value::as_u64)
            .map(|blocks| {
                u32::try_from(blocks).map_err(|_| "broadcast safety margin exceeds u32".to_owned())
            })
            .transpose()?
            .unwrap_or(0),
        chain_current_height: optional_u32(timeout_ladder, "current_height")?,
        lightning_current_height: optional_u32(timeout_ladder, "lightning_current_height")?,
        height_observed_at: timeout_ladder
            .get("height_observed_at")
            .and_then(Value::as_u64),
        height_observation_max_age_seconds: optional_u32(
            timeout_ladder,
            "height_observation_max_age_seconds",
        )?,
        chain_block_interval_seconds: timeout_ladder
            .get("chain_block_interval_seconds")
            .and_then(Value::as_u64),
        lightning_block_interval_seconds: timeout_ladder
            .get("lightning_block_interval_seconds")
            .and_then(Value::as_u64),
        cross_domain_safety_seconds: timeout_ladder
            .get("cross_domain_safety_seconds")
            .and_then(Value::as_u64),
        provider_refund_expected_at: timeout_ladder
            .get("provider_refund_expected_at")
            .and_then(Value::as_u64),
        hold_expiry_expected_at: timeout_ladder
            .get("hold_expiry_expected_at")
            .and_then(Value::as_u64),
        committed_funding_transaction: Some(committed_funding_transaction.to_owned()),
        committed_funding_sha256,
        output_index,
        zero_confirmation,
        desired_completion_time,
    })
}

fn chain_swap_terms(session: &ProviderSession) -> Result<ChainSwapTerms, String> {
    let contract_event = session
        .signed_records()
        .iter()
        .find(|record| record.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .ok_or_else(|| "funded executor has no bilateral contract".to_owned())?;
    let profile = record_profile(contract_event)?;
    let contract = profile
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| "Swap Contract has no contract object".to_owned())?;
    if contract.get("swap_type").and_then(Value::as_str) != Some("chain") {
        return Err("Swap Contract type differs from the chain session".to_owned());
    }
    let timeout_ladder = contract
        .get("timeout_ladder")
        .and_then(Value::as_object)
        .ok_or_else(|| "chain Swap Contract has no timeout ladder".to_owned())?;
    let destination_refund_time = timeout_ladder
        .get("destination_refund_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| "chain timeout ladder has no destination refund time".to_owned())?;
    let source_refund_time = timeout_ladder
        .get("source_refund_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| "chain timeout ladder has no source refund time".to_owned())?;
    if destination_refund_time >= source_refund_time
        || contract
            .get("desired_completion_time")
            .and_then(Value::as_u64)
            .is_none_or(|deadline| source_refund_time > deadline)
    {
        return Err("chain timeout ladder does not preserve the source recovery margin".to_owned());
    }
    let source = chain_contract_leg_terms(contract, "source", false)?;
    let destination = chain_contract_leg_terms(contract, "destination", true)?;
    if source.payment_hash != destination.payment_hash
        || source.asset_id == destination.asset_id
        || source.rail == destination.rail
    {
        return Err("chain legs do not bind one payment hash and two distinct rails".to_owned());
    }
    Ok(ChainSwapTerms {
        source,
        destination,
    })
}

fn chain_destination_handoff_extra(destination: &ChainTerms) -> Result<Map<String, Value>, String> {
    let funding_transaction = destination
        .committed_funding_transaction
        .as_ref()
        .ok_or_else(|| "chain destination has no committed funding transaction".to_owned())?;
    if lower_hex(&sha256(&decode_hex(funding_transaction)?)) != destination.committed_funding_sha256
    {
        return Err("chain destination funding handoff differs from its digest".to_owned());
    }
    let mut extra = Map::new();
    extra.insert(
        "funding_transaction".to_owned(),
        Value::String(funding_transaction.clone()),
    );
    extra.insert(
        "funding_transaction_sha256".to_owned(),
        Value::String(destination.committed_funding_sha256.clone()),
    );
    Ok(extra)
}

fn chain_contract_leg_terms(
    contract: &Map<String, Value>,
    leg_id: &str,
    require_funding_commitment: bool,
) -> Result<ChainTerms, String> {
    let verifier = contract_entry(contract, "verifier_inputs", leg_id, "chain verifier input")?;
    let leg = contract_entry(contract, "legs", leg_id, "chain leg")?;
    let expected_funding_role = if leg_id == "source" {
        "requester"
    } else {
        "provider"
    };
    let expected_receiving_role = if leg_id == "source" {
        "provider"
    } else {
        "requester"
    };
    if required_string(&leg, "funding_role")? != expected_funding_role
        || required_string(&leg, "receiving_role")? != expected_receiving_role
    {
        return Err(format!("chain {leg_id} leg has inverted participant roles"));
    }
    let amount_sat = canonical_u64(required_string(&verifier, "amount")?)?;
    if canonical_u64(required_string(&leg, "amount")?)? != amount_sat {
        return Err(format!("chain {leg_id} leg and verifier amounts differ"));
    }
    let payment_hash = required_lower_hex(&verifier, "payment_hash")
        .or_else(|_| required_lower_hex(contract, "payment_hash"))?;
    if required_lower_hex(&leg, "payment_hash")? != payment_hash {
        return Err(format!("chain {leg_id} payment hash differs"));
    }
    let refund_height =
        canonical_u64(required_string(&leg, "refund_lock_value")?).and_then(|height| {
            u32::try_from(height).map_err(|_| format!("chain {leg_id} refund height exceeds u32"))
        })?;
    let rail = match required_string(&leg, "rail")? {
        "bitcoin" => ChainRailKind::Bitcoin,
        "liquid" => ChainRailKind::Liquid,
        _ => return Err(format!("chain {leg_id} uses an unsupported rail")),
    };
    let asset_id = required_string(&leg, "asset_id")?.to_owned();
    let network_id = required_string(&leg, "network_id")?.to_owned();
    let funding_transaction = verifier.get("funding_transaction").and_then(Value::as_str);
    let zero_confirmation = required_string(&verifier, "zero_confirmation")? == "allowed";
    if zero_confirmation
        && (leg_id != "source"
            || rail != ChainRailKind::Bitcoin
            || required_string(&verifier, "rbf_policy")? != "reject"
            || required_string(&verifier, "replacement_policy")? != "track")
    {
        return Err(format!("chain {leg_id} zero-confirmation policy is unsafe"));
    }
    let funding_sha256 = verifier
        .get("funding_transaction_sha256")
        .and_then(Value::as_str);
    let funding_output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let (committed_funding_transaction, committed_funding_sha256, output_index) =
        match (funding_transaction, funding_sha256, funding_output_index) {
            (Some(transaction), Some(digest), Some(output_index)) => {
                required_hash(digest, "chain funding transaction digest")?;
                let bytes = decode_hex(transaction)?;
                if lower_hex(&sha256(&bytes)) != digest {
                    return Err(format!(
                        "chain {leg_id} funding bytes differ from their digest"
                    ));
                }
                (
                    Some(transaction.to_owned()),
                    digest.to_owned(),
                    output_index,
                )
            }
            (None, None, None) if !require_funding_commitment => (None, String::new(), 0),
            _ => {
                return Err(format!(
                    "chain {leg_id} funding commitment is absent or incomplete"
                ));
            }
        };
    let miner_fee_budget_sat = canonical_u64(required_string(contract, "miner_fee_budget")?)?;
    let desired_completion_time = contract
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .ok_or_else(|| "chain Swap Contract has no desired completion time".to_owned())?;
    let fee_rate_sat_per_vbyte = funding_feerate_from_priced_vbytes(
        contract_priced_vbytes(contract, PricingSwapType::Chain)?,
        miner_fee_budget_sat,
    )
    .map_err(|error| error.to_string())?;
    Ok(ChainTerms {
        rail,
        asset_id,
        network_id,
        amount_sat,
        script_pubkey: decode_hex(required_string(&verifier, "script_pubkey")?)?,
        claim_script: decode_hex(required_string(&verifier, "claim_script")?)?,
        claim_control_block: decode_hex(required_string(
            &verifier,
            "taproot_claim_control_block",
        )?)?,
        refund_script: decode_hex(required_string(&verifier, "refund_script")?)?,
        refund_control_block: decode_hex(required_string(
            &verifier,
            "taproot_refund_control_block",
        )?)?,
        taproot_internal_key: required_lower_hex(&verifier, "taproot_internal_key")?,
        taproot_merkle_root: required_lower_hex(&verifier, "taproot_merkle_root")?,
        payment_hash,
        refund_height,
        fee_rate_sat_per_vbyte,
        lightning_fee_budget_sat: 0,
        lightning_amount_sat: 0,
        fund_last: None,
        claim_last: None,
        lock_last: None,
        hold_expiry_height: None,
        lightning_settlement_blocks: 0,
        broadcast_safety_blocks: 0,
        chain_current_height: None,
        lightning_current_height: None,
        height_observed_at: None,
        height_observation_max_age_seconds: None,
        chain_block_interval_seconds: None,
        lightning_block_interval_seconds: None,
        cross_domain_safety_seconds: None,
        provider_refund_expected_at: None,
        hold_expiry_expected_at: None,
        committed_funding_transaction,
        committed_funding_sha256,
        output_index,
        zero_confirmation,
        desired_completion_time,
    })
}

fn timeout_height(timeout_ladder: &Map<String, Value>, member: &str) -> Result<u32, String> {
    timeout_ladder
        .get(member)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("timeout ladder has no {member}"))
        .and_then(|height| {
            u32::try_from(height).map_err(|_| format!("timeout ladder {member} exceeds u32"))
        })
}

fn optional_u32(object: &Map<String, Value>, member: &str) -> Result<Option<u32>, String> {
    object
        .get(member)
        .and_then(Value::as_u64)
        .map(|value| {
            u32::try_from(value).map_err(|_| format!("contract member {member} exceeds u32"))
        })
        .transpose()
}

fn required_string<'a>(object: &'a Map<String, Value>, member: &str) -> Result<&'a str, String> {
    object
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("contract member {member} is missing"))
}

fn required_lower_hex(object: &Map<String, Value>, member: &str) -> Result<String, String> {
    let value = required_string(object, member)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "contract member {member} is not lowercase 32-byte hex"
        ));
    }
    Ok(value.to_owned())
}

fn contract_entry(
    contract: &Map<String, Value>,
    collection: &str,
    leg_id: &str,
    label: &str,
) -> Result<Map<String, Value>, String> {
    contract
        .get(collection)
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| format!("cooperative contract has no {label}"))
}

fn require_contract_effect_binding(
    contract: &Map<String, Value>,
    role: &str,
    leg_id: &str,
) -> Result<(), String> {
    if contract
        .get("effect_bindings")
        .and_then(Value::as_array)
        .is_some_and(|bindings| {
            bindings.iter().any(|binding| {
                binding.get("role").and_then(Value::as_str) == Some(role)
                    && binding.get("leg_id").and_then(Value::as_str) == Some(leg_id)
            })
        })
    {
        Ok(())
    } else {
        Err(format!(
            "cooperative contract has no {role} effect for {leg_id}"
        ))
    }
}

fn cooperative_participant_keys(verifier: &Map<String, Value>) -> Result<[[u8; 33]; 2], String> {
    let declared = verifier
        .get("cooperative_pubkeys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 2)
        .ok_or_else(|| "cooperative verifier does not have two participant keys".to_owned())?;
    let mut result = [[0_u8; 33]; 2];
    for (index, (role, entry)) in ["requester", "provider"]
        .into_iter()
        .zip(declared)
        .enumerate()
    {
        if entry.get("participant_role").and_then(Value::as_str) != Some(role) {
            return Err(
                "cooperative participant keys are not in requester/provider order".to_owned(),
            );
        }
        let encoded = entry
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| "cooperative participant key is missing".to_owned())?;
        let bytes = decode_hex(encoded)?;
        result[index] = bytes
            .try_into()
            .map_err(|_| "cooperative participant key is not compressed".to_owned())?;
    }
    Ok(result)
}

fn fixed_hex_32(encoded: &str) -> Result<[u8; 32], String> {
    decode_hex(encoded)?
        .try_into()
        .map_err(|_| "cooperative digest is not 32 bytes".to_owned())
}

fn has_cooperative_action(
    records: &[Event],
    author: &str,
    role: ParticipantRole,
    action: CooperativeSigningAction,
) -> Result<bool, String> {
    records
        .iter()
        .filter(|record| record.pubkey == author && record.kind == MKT_STATUS_KIND)
        .try_fold(false, |found, record| {
            if found {
                return Ok(true);
            }
            cooperative_signing_message(record, role)
                .map(|message| message.is_some_and(|message| message.action == action))
                .map_err(|error| format!("cooperative transcript is invalid: {error}"))
        })
}

fn finalized_from_signed_message(message: &CooperativeSigningMessage) -> Result<Vec<u8>, String> {
    if message.action != CooperativeSigningAction::FinalSignature {
        return Err("cooperative recovery record is not a final signature".to_owned());
    }
    let signature = message
        .final_signature
        .as_deref()
        .ok_or_else(|| "cooperative final Status has no final signature".to_owned())?;
    let signature = decode_hex(signature)?;
    if signature.len() != 64 {
        return Err("cooperative final signature is not 64 bytes".to_owned());
    }
    let raw = decode_hex(&message.context.unsigned_transaction)?;
    let mut transaction = Transaction::parse(&raw)
        .map_err(|error| format!("cooperative recovery transaction is invalid: {error}"))?;
    transaction
        .set_input_witness(
            usize::try_from(message.context.input_index)
                .map_err(|_| "cooperative recovery input index is invalid".to_owned())?,
            vec![signature],
        )
        .map_err(|error| format!("cooperative recovery witness failed: {error}"))?;
    transaction
        .serialize(true)
        .map_err(|error| format!("cooperative recovery serialization failed: {error}"))
}

fn status_by_state<'a>(records: &'a [Event], author: &str, state: &str) -> Option<&'a Event> {
    records.iter().find(|record| {
        record.kind == MKT_STATUS_KIND
            && record.pubkey == author
            && record_profile(record)
                .ok()
                .and_then(|profile| profile.get("swp_state").cloned())
                .and_then(|value| value.as_str().map(str::to_owned))
                .as_deref()
                == Some(state)
    })
}

fn hold_failure_code(records: &[Event], author: &str, state: &str) -> Result<String, String> {
    let profile = status_by_state(records, author, state)
        .ok_or_else(|| format!("provider has no {state} Status"))
        .and_then(record_profile)?;
    let code = profile
        .get("failure_code")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("provider {state} Status has no failure code"))?;
    if !is_hold_failure_code(code) {
        return Err(format!(
            "provider {state} Status has an invalid failure code"
        ));
    }
    Ok(code.to_owned())
}

fn is_hold_failure_code(code: &str) -> bool {
    matches!(
        code,
        "invalid_hold_invoice"
            | "hold_invoice_cancelled"
            | "invalid_hold_invoice_settled"
            | "hold_invoice_settled_before_funding"
            | "lock_deadline_expired"
    )
}

fn hold_state_decision(state: &str) -> Result<HoldStateDecision, String> {
    match state {
        "unpaid" => Ok(HoldStateDecision::Wait),
        "accepted" | "held" => Ok(HoldStateDecision::Verify),
        "cancelled" => Ok(HoldStateDecision::Cancel("hold_invoice_cancelled")),
        "paid" | "settled" => Ok(HoldStateDecision::Unresolved(
            "hold_invoice_settled_before_funding",
        )),
        _ => Err("reverse hold invoice has an unsupported state".to_owned()),
    }
}

fn deadline_expired(current_height: u32, exclusive_deadline: u32) -> bool {
    current_height >= exclusive_deadline
}

fn execute_before_exclusive_deadline<T, E>(
    current_height: u32,
    exclusive_deadline: u32,
    effect: impl FnOnce() -> Result<T, E>,
) -> Result<Option<T>, E> {
    if deadline_expired(current_height, exclusive_deadline) {
        Ok(None)
    } else {
        effect().map(Some)
    }
}

fn reverse_spend_decision(
    spending_transaction_id: Option<&str>,
    refund_broadcast_txid: Option<&str>,
    refund_replacement_txid: Option<&str>,
    claim_is_final: bool,
) -> ReverseSpendDecision {
    let Some(spending_transaction_id) = spending_transaction_id else {
        return ReverseSpendDecision::Wait;
    };
    if refund_broadcast_txid == Some(spending_transaction_id)
        || refund_replacement_txid == Some(spending_transaction_id)
    {
        return ReverseSpendDecision::ProviderRefund;
    }
    if claim_is_final {
        ReverseSpendDecision::SettleClaimAndRetireRefundWatch
    } else {
        ReverseSpendDecision::Wait
    }
}

fn recover_liquid_reverse_refund_before_claim(
    refund_effect_state: &str,
    requester_claim_announced: bool,
) -> bool {
    refund_effect_state == "applied" || !requester_claim_announced
}

fn validate_liquid_funding_inputs(
    transaction: &LiquidTransaction,
    reserved_inputs: &[ElementsdWalletUtxo],
) -> Result<(), String> {
    let mut expected = reserved_inputs
        .iter()
        .map(|input| (input.transaction_id.clone(), input.output_index))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if expected.len() != 1 {
        return Err("durable Liquid reservation contains invalid inputs".to_owned());
    }
    let mut actual = transaction
        .inputs
        .iter()
        .map(|input| {
            if input.has_issuance || input.is_pegin {
                return Err("Liquid funding contains a forbidden input shape".to_owned());
            }
            Ok((lower_hex(&input.previous_txid), input.previous_output))
        })
        .collect::<Result<Vec<_>, String>>()?;
    actual.sort_unstable();
    if actual != expected {
        return Err("Liquid funding inputs differ from the durable reservation".to_owned());
    }
    Ok(())
}

fn liquid_funding_fee_sat(
    transaction: &LiquidTransaction,
    pegged_asset: LiquidAssetId,
) -> Result<u64, String> {
    let fee_outputs = transaction
        .outputs
        .iter()
        .filter(|output| output.script_pubkey.is_empty())
        .collect::<Vec<_>>();
    let [fee] = fee_outputs.as_slice() else {
        return Err("Liquid funding transaction has no unique fee output".to_owned());
    };
    if fee.asset != ConfidentialAsset::Explicit(pegged_asset) {
        return Err("Liquid funding fee is not the configured pegged asset".to_owned());
    }
    match fee.value {
        ConfidentialValue::Explicit(value) if value > 0 => Ok(value),
        _ => Err("Liquid funding fee is not an explicit positive amount".to_owned()),
    }
}

fn hold_failure_extra(code: &str) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("failure_code".to_owned(), Value::String(code.to_owned()));
    extra
}

fn is_effective_cancel(record: &Event) -> bool {
    record.kind == MKT_CANCEL_KIND && record.tag_values("action").eq(["effective"])
}

fn funded_cancel_pre_effect(requester_has_status: bool, provider_state: Option<&str>) -> bool {
    !requester_has_status && matches!(provider_state, None | Some("accepted" | "lock_terms_ready"))
}

fn status_transaction_reference(status: &Event) -> Result<(String, u32), String> {
    let profile = record_profile(status)?;
    let transaction_id = status_transaction_id_from_profile(&profile)?;
    let output_index = profile
        .get("output_index")
        .or_else(|| profile.get("vout"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "funding Status has no bounded output_index".to_owned())?;
    Ok((transaction_id, output_index))
}

fn status_transaction_id(status: &Event) -> Result<String, String> {
    status_transaction_id_from_profile(&record_profile(status)?)
}

fn status_transaction_id_from_profile(profile: &Map<String, Value>) -> Result<String, String> {
    let transaction_id = profile
        .get("transaction_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Status has no transaction_id".to_owned())?;
    required_hash(transaction_id, "Status transaction ID")?;
    Ok(transaction_id.to_owned())
}

fn transaction_extra(observation: &ChainObservation) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert(
        "transaction_id".to_owned(),
        Value::String(observation.transaction_id.clone()),
    );
    extra.insert("output_index".to_owned(), json!(observation.output_index));
    extra.insert("confirmations".to_owned(), json!(observation.confirmations));
    if let Some(block_hash) = observation.block_hash.as_ref() {
        extra.insert("block_hash".to_owned(), Value::String(block_hash.clone()));
    }
    extra
}

fn rail_transaction_extra(observation: &RailChainObservation) -> Map<String, Value> {
    match observation {
        RailChainObservation::Bitcoin(observation) => transaction_extra(observation),
        RailChainObservation::Liquid(observation) => {
            let mut extra = Map::new();
            extra.insert(
                "transaction_id".to_owned(),
                Value::String(observation.transaction_id.clone()),
            );
            extra.insert("output_index".to_owned(), json!(observation.output_index));
            extra.insert("confirmations".to_owned(), json!(observation.confirmations));
            extra.insert(
                "transaction_sha256".to_owned(),
                Value::String(observation.transaction_sha256.clone()),
            );
            extra.insert("unspent".to_owned(), Value::Bool(observation.unspent));
            if let Some(block_hash) = observation.block_hash.as_ref() {
                extra.insert("block_hash".to_owned(), Value::String(block_hash.clone()));
            }
            extra
        }
    }
}

fn watch_extra(job: &WatchJob) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("watch_job_id".to_owned(), Value::String(job.job_id.clone()));
    extra.insert("watch_state".to_owned(), Value::String(job.state.clone()));
    extra.insert("confirmations".to_owned(), json!(job.confirmations));
    if let Some(transaction_id) = job
        .replacement_txid
        .as_ref()
        .or(job.broadcast_txid.as_ref())
    {
        extra.insert(
            "transaction_id".to_owned(),
            Value::String(transaction_id.clone()),
        );
    }
    extra
}

fn bitcoin_output_evidence(
    session: &ProviderSession,
    observation: &ChainObservation,
    rung: &str,
    observed_at: u64,
) -> Result<Value, String> {
    let raw = observation
        .transaction
        .serialize(true)
        .map_err(|error| format!("could not serialize observed funding: {error}"))?;
    Ok(json!({
        "artifact_sha256":lower_hex(&sha256(&raw)),
        "class":"bitcoin_output",
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":"bitcoin",
        "reference":format!("{}:{}", observation.transaction_id, observation.output_index),
        "rung":rung,
        "verifier_policy":"mkt-swp-bitcoin-v1",
        "verifier_pubkey":null,
        "view":observation.block_hash.as_deref().unwrap_or("mempool"),
    }))
}

fn rail_output_evidence(
    session: &ProviderSession,
    observation: &RailChainObservation,
    rung: &str,
    observed_at: u64,
) -> Result<Value, String> {
    match observation {
        RailChainObservation::Bitcoin(observation) => {
            bitcoin_output_evidence(session, observation, rung, observed_at)
        }
        RailChainObservation::Liquid(observation) => Ok(json!({
            "artifact_sha256":observation.transaction_sha256,
            "class":"liquid_output",
            "observed_at":observed_at,
            "producer_pubkey":session.config().provider_pubkey,
            "rail":"liquid",
            "reference":format!("{}:{}", observation.transaction_id, observation.output_index),
            "rung":rung,
            "verifier_policy":"mkt-swp-liquid-v1",
            "verifier_pubkey":null,
            "view":observation.block_hash.as_deref().unwrap_or("mempool")
        })),
    }
}

fn chain_transaction_evidence(
    session: &ProviderSession,
    rail: ChainRailKind,
    transaction_id: &str,
    rung: &str,
    artifact: &Value,
    observed_at: u64,
    view: &str,
) -> Result<Value, String> {
    required_hash(transaction_id, "chain transaction evidence ID")?;
    let (rail, class, verifier_policy) = match rail {
        ChainRailKind::Bitcoin => ("bitcoin", "bitcoin_transaction", "mkt-swp-bitcoin-v1"),
        ChainRailKind::Liquid => ("liquid", "liquid_transaction", "mkt-swp-liquid-v1"),
    };
    Ok(json!({
        "artifact_sha256":value_digest(artifact)?,
        "class":class,
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":rail,
        "reference":transaction_id,
        "rung":rung,
        "verifier_policy":verifier_policy,
        "verifier_pubkey":null,
        "view":view,
    }))
}

#[allow(clippy::too_many_arguments)]
fn chain_spend_evidence(
    session: &ProviderSession,
    rail: ChainRailKind,
    spent_transaction_id: &str,
    spent_output_index: u32,
    rung: &str,
    artifact: &Value,
    observed_at: u64,
    view: &str,
) -> Result<Value, String> {
    required_hash(spent_transaction_id, "chain spend transaction ID")?;
    let (rail, class, verifier_policy) = match rail {
        ChainRailKind::Bitcoin => ("bitcoin", "bitcoin_spend", "mkt-swp-bitcoin-v1"),
        ChainRailKind::Liquid => ("liquid", "liquid_spend", "mkt-swp-liquid-v1"),
    };
    Ok(json!({
        "artifact_sha256":value_digest(artifact)?,
        "class":class,
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":rail,
        "reference":format!("{spent_transaction_id}:{spent_output_index}"),
        "rung":rung,
        "verifier_policy":verifier_policy,
        "verifier_pubkey":null,
        "view":view,
    }))
}

fn bitcoin_spend_evidence(
    session: &ProviderSession,
    spent_transaction_id: &str,
    spent_output_index: u32,
    rung: &str,
    artifact: &Value,
    observed_at: u64,
    view: &str,
) -> Result<Value, String> {
    Ok(json!({
        "artifact_sha256":value_digest(artifact)?,
        "class":"bitcoin_spend",
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":"bitcoin",
        "reference":bitcoin_spend_reference(spent_transaction_id, spent_output_index)?,
        "rung":rung,
        "verifier_policy":"mkt-swp-bitcoin-v1",
        "verifier_pubkey":null,
        "view":view,
    }))
}

fn bitcoin_spend_reference(
    spent_transaction_id: &str,
    spent_output_index: u32,
) -> Result<String, String> {
    required_hash(
        spent_transaction_id,
        "Bitcoin spend evidence transaction ID",
    )?;
    Ok(format!("{spent_transaction_id}:{spent_output_index}"))
}

fn lightning_evidence(
    session: &ProviderSession,
    payment_hash: &str,
    class: &str,
    rung: &str,
    artifact: &Value,
    observed_at: u64,
    view: &str,
) -> Result<Value, String> {
    required_hash(payment_hash, "Lightning evidence payment hash")?;
    Ok(json!({
        "artifact_sha256":value_digest(artifact)?,
        "class":class,
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":"lightning",
        "reference":payment_hash,
        "rung":rung,
        "verifier_policy":"mkt-swp-lightning-v1",
        "verifier_pubkey":null,
        "view":view,
    }))
}

fn watch_evidence(
    session: &ProviderSession,
    job: &WatchJob,
    class: &str,
    rung: &str,
    observed_at: u64,
) -> Result<Value, String> {
    let payload: BroadcastWatchPayload = serde_json::from_value(job.public_payload.clone())
        .map_err(|_| "watch payload is not a broadcast payload".to_owned())?;
    let reference = if class == "bitcoin_spend" {
        let spent = payload
            .inputs
            .first()
            .ok_or_else(|| "Bitcoin spend watch has no input outpoint".to_owned())?;
        bitcoin_spend_reference(&spent.txid, spent.vout)?
    } else {
        job.replacement_txid
            .as_deref()
            .or(job.broadcast_txid.as_deref())
            .unwrap_or(&payload.expected_txid)
            .to_owned()
    };
    Ok(json!({
        "artifact_sha256":job.request_sha256,
        "class":class,
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":"bitcoin",
        "reference":reference,
        "rung":rung,
        "verifier_policy":"mkt-swp-bitcoin-v1",
        "verifier_pubkey":null,
        "view":format!("watch:{}", job.state),
    }))
}

fn matching_hold_invoice<'a>(response: &'a Value, payment_hash: &str) -> Result<&'a Value, String> {
    matching_hold_invoice_optional(response, payment_hash)
        .ok_or_else(|| "CLN has no matching recoverable hold invoice".to_owned())
}

fn matching_hold_invoice_optional<'a>(
    response: &'a Value,
    payment_hash: &str,
) -> Option<&'a Value> {
    response
        .get("holdinvoices")
        .or_else(|| response.get("invoices"))
        .and_then(Value::as_array)
        .and_then(|invoices| {
            invoices.iter().find(|invoice| {
                invoice.get("payment_hash").and_then(Value::as_str) == Some(payment_hash)
            })
        })
}

fn hold_invoice_state(invoice: &Value) -> Result<String, String> {
    invoice
        .get("state")
        .or_else(|| invoice.get("status"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| "reverse hold invoice has no state".to_owned())
}

fn reverse_invoice_cancellation_action(
    state: &str,
) -> Result<ReverseInvoiceCancellationAction, String> {
    match state {
        "unpaid" | "accepted" | "held" => Ok(ReverseInvoiceCancellationAction::CancelRemotely),
        "cancelled" => Ok(ReverseInvoiceCancellationAction::CompleteLocally),
        "paid" | "settled" => {
            Err("reverse invoice settled before an unfunded cancellation could complete".to_owned())
        }
        _ => Err("reverse hold invoice has an unsupported cancellation state".to_owned()),
    }
}

fn validate_held_htlcs(
    invoice: &Value,
    terms: &ChainTerms,
    current_height: u64,
) -> Result<HeldHtlcSummary, &'static str> {
    let state = invoice
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "accepted" | "held"))
        .ok_or("reverse invoice is not in an accepted hold state")?;
    if state.len() > 16 {
        return Err("reverse invoice hold state exceeds its bound");
    }
    let htlcs = invoice
        .get("htlcs")
        .and_then(Value::as_array)
        .filter(|htlcs| !htlcs.is_empty() && htlcs.len() <= 64)
        .ok_or("reverse invoice has no bounded held HTLC set")?;
    let expected_msat = terms
        .lightning_amount_sat
        .checked_mul(1_000)
        .ok_or("reverse Lightning amount overflowed")?;
    let required_expiry = u64::from(terms.refund_height)
        .checked_add(u64::from(terms.broadcast_safety_blocks))
        .and_then(|height| height.checked_add(u64::from(terms.lightning_settlement_blocks)))
        .ok_or("reverse held-HTLC safety margin overflowed")?;
    let signed_expiry = u64::from(
        terms
            .hold_expiry_height
            .ok_or("reverse contract has no signed hold expiry height")?,
    );
    if signed_expiry <= required_expiry || signed_expiry <= current_height {
        return Err("signed reverse hold expiry cannot cover the refund ladder");
    }
    let mut total_msat = 0_u64;
    let mut minimum_cltv_expiry = u64::MAX;
    for htlc in htlcs {
        if htlc.get("state").and_then(Value::as_str) != Some("accepted") {
            return Err("reverse invoice contains an HTLC outside the accepted state");
        }
        let amount_msat = htlc
            .get("msat")
            .and_then(Value::as_u64)
            .ok_or("held HTLC amount is invalid")?;
        total_msat = total_msat
            .checked_add(amount_msat)
            .ok_or("held HTLC amount overflowed")?;
        let expiry = htlc
            .get("cltv_expiry")
            .and_then(Value::as_u64)
            .ok_or("held HTLC has no block expiry")?;
        if expiry < signed_expiry || expiry <= required_expiry || expiry <= current_height {
            return Err("held HTLC expires before the signed recovery margin");
        }
        minimum_cltv_expiry = minimum_cltv_expiry.min(expiry);
    }
    if total_msat != expected_msat {
        return Err("held HTLC amount differs from the bilateral contract");
    }
    Ok(HeldHtlcSummary {
        state: state.to_owned(),
        htlc_count: htlcs.len(),
        total_msat,
        minimum_cltv_expiry,
    })
}

fn validate_cross_domain_held_htlcs(
    invoice: &Value,
    terms: &ChainTerms,
    current_lightning_height: u64,
    observed_at: u64,
) -> Result<HeldHtlcSummary, &'static str> {
    let state = invoice
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "accepted" | "held"))
        .ok_or("reverse invoice is not in an accepted hold state")?;
    if state.len() > 16 {
        return Err("reverse invoice hold state exceeds its bound");
    }
    let htlcs = invoice
        .get("htlcs")
        .and_then(Value::as_array)
        .filter(|htlcs| !htlcs.is_empty() && htlcs.len() <= 64)
        .ok_or("reverse invoice has no bounded held HTLC set")?;
    let signed_chain_height = terms
        .chain_current_height
        .ok_or("Liquid reverse contract has no signed chain height")?;
    let signed_lightning_height = terms
        .lightning_current_height
        .ok_or("Liquid reverse contract has no signed Lightning height")?;
    let height_observed_at = terms
        .height_observed_at
        .ok_or("Liquid reverse contract has no height observation time")?;
    let maximum_age = terms
        .height_observation_max_age_seconds
        .filter(|age| *age > 0 && *age <= 120)
        .ok_or("Liquid reverse contract has an invalid height observation age")?;
    if observed_at < height_observed_at || observed_at - height_observed_at > u64::from(maximum_age)
    {
        return Err("Liquid reverse height observation is stale");
    }
    let chain_interval = terms
        .chain_block_interval_seconds
        .filter(|seconds| *seconds > 0)
        .ok_or("Liquid reverse contract has no chain block interval")?;
    let lightning_interval = terms
        .lightning_block_interval_seconds
        .filter(|seconds| *seconds > 0)
        .ok_or("Liquid reverse contract has no Lightning block interval")?;
    let cross_domain_safety = terms
        .cross_domain_safety_seconds
        .filter(|seconds| *seconds > 0)
        .ok_or("Liquid reverse contract has no cross-domain safety margin")?;
    let signed_expiry = terms
        .hold_expiry_height
        .ok_or("reverse contract has no signed hold expiry height")?;
    if current_lightning_height >= u64::from(signed_expiry)
        || current_lightning_height < u64::from(signed_lightning_height)
    {
        return Err("signed reverse hold expiry is outside the current Lightning view");
    }
    let chain_blocks = terms
        .refund_height
        .checked_sub(signed_chain_height)
        .and_then(|blocks| blocks.checked_add(terms.broadcast_safety_blocks))
        .ok_or("Liquid reverse refund conversion underflowed")?;
    let lightning_blocks = signed_expiry
        .checked_sub(signed_lightning_height)
        .ok_or("Liquid reverse hold conversion underflowed")?;
    let expected_refund = height_observed_at
        .checked_add(
            u64::from(chain_blocks)
                .checked_mul(chain_interval)
                .ok_or("Liquid reverse refund conversion overflowed")?,
        )
        .ok_or("Liquid reverse refund time overflowed")?;
    let expected_hold_expiry = height_observed_at
        .checked_add(
            u64::from(lightning_blocks)
                .checked_mul(lightning_interval)
                .ok_or("Liquid reverse hold conversion overflowed")?,
        )
        .ok_or("Liquid reverse hold time overflowed")?;
    let required_hold_time = expected_refund
        .checked_add(
            u64::from(terms.lightning_settlement_blocks)
                .checked_mul(lightning_interval)
                .ok_or("Liquid reverse settlement conversion overflowed")?,
        )
        .and_then(|time| time.checked_add(cross_domain_safety))
        .ok_or("Liquid reverse cross-domain margin overflowed")?;
    if terms.provider_refund_expected_at != Some(expected_refund)
        || terms.hold_expiry_expected_at != Some(expected_hold_expiry)
        || required_hold_time >= expected_hold_expiry
    {
        return Err("Liquid reverse signed cross-domain timeout conversion is unsafe");
    }
    let expected_msat = terms
        .lightning_amount_sat
        .checked_mul(1_000)
        .ok_or("reverse Lightning amount overflowed")?;
    let mut total_msat = 0_u64;
    let mut minimum_cltv_expiry = u64::MAX;
    for htlc in htlcs {
        if htlc.get("state").and_then(Value::as_str) != Some("accepted") {
            return Err("reverse invoice contains an HTLC outside the accepted state");
        }
        let amount_msat = htlc
            .get("msat")
            .and_then(Value::as_u64)
            .ok_or("held HTLC amount is invalid")?;
        total_msat = total_msat
            .checked_add(amount_msat)
            .ok_or("held HTLC amount overflowed")?;
        let expiry = htlc
            .get("cltv_expiry")
            .and_then(Value::as_u64)
            .ok_or("held HTLC has no block expiry")?;
        if expiry < u64::from(signed_expiry) || expiry <= current_lightning_height {
            return Err("held HTLC expires before the signed recovery margin");
        }
        minimum_cltv_expiry = minimum_cltv_expiry.min(expiry);
    }
    if total_msat != expected_msat {
        return Err("held HTLC amount differs from the bilateral contract");
    }
    Ok(HeldHtlcSummary {
        state: state.to_owned(),
        htlc_count: htlcs.len(),
        total_msat,
        minimum_cltv_expiry,
    })
}

fn require_chain_finality(
    observation: &Map<String, Value>,
    minimum_confirmations: u32,
    reorg_safety_blocks: u32,
) -> Result<(), String> {
    let required = minimum_confirmations
        .checked_add(reorg_safety_blocks)
        .ok_or_else(|| "claim finality requirement overflowed".to_owned())?;
    let confirmations = observation
        .get("confirmations")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    if confirmations < required {
        return Err("chain transaction has not reached reorg-safe finality".to_owned());
    }
    let block_hash = observation
        .get("blockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| "final chain transaction has no block hash".to_owned())?;
    required_hash(block_hash, "chain block hash")
}

fn verify_validated_signature(
    witness: &immortal_core::mkt_swp_verify::ValidatedTaprootWitness,
) -> Result<(), String> {
    let signature = Signature::from_byte_array(witness.signature);
    let signing_key = XOnlyPublicKey::from_byte_array(witness.signing_key.serialize())
        .map_err(|_| "claim signing key is invalid".to_owned())?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &witness.sighash, &signing_key)
        .map_err(|_| "claim signature failed independent verification".to_owned())
}

fn settlement_destination_path(session_id: &str) -> Result<WalletPath, String> {
    let digest = sha256(format!("settlement-destination\0{session_id}").as_bytes());
    let index = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) % 20;
    WalletPath::new(0, true, index)
        .map_err(|error| format!("settlement destination path is invalid: {error}"))
}

fn chain_destination_unilateral_path(session_id: &str) -> Result<WalletPath, String> {
    let allocation = quote_allocation(session_id)?;
    WalletPath::new(
        allocation.unilateral_path.account,
        allocation.unilateral_path.change,
        allocation
            .unilateral_path
            .address_index
            .checked_add(2)
            .ok_or_else(|| "chain destination wallet path overflows".to_owned())?,
    )
    .map_err(|error| format!("chain destination wallet path is invalid: {error}"))
}

fn funding_change_path(session_id: &str) -> Result<WalletPath, String> {
    let digest = sha256(format!("funding-change\0{session_id}").as_bytes());
    let index = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) % 20;
    WalletPath::new(0, true, index)
        .map_err(|error| format!("funding change path is invalid: {error}"))
}

fn value_digest(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .map_err(|error| format!("public artifact is not serializable: {error}"))
}

fn required_hash(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not lowercase 32-byte hex"))
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > 2_000_000 {
        return Err("hexadecimal artifact is empty, odd, or unbounded".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?))
        .collect()
}

fn display_txid_wire(value: &str) -> Result<[u8; 32], String> {
    required_hash(value, "transaction ID")?;
    let mut bytes: [u8; 32] = decode_hex(value)?
        .try_into()
        .map_err(|_| "transaction ID is not 32 bytes".to_owned())?;
    bytes.reverse();
    Ok(bytes)
}

fn display_txid(wire: &[u8; 32]) -> String {
    let mut bytes = *wire;
    bytes.reverse();
    lower_hex(&bytes)
}

pub(crate) fn signer_from_environment() -> Result<MarketSigner, String> {
    let secret = env::var("IMMORTAL_PROVIDER_IDENTITY_SECRET")
        .map_err(|_| "IMMORTAL_PROVIDER_IDENTITY_SECRET is required".to_owned())?;
    if secret.len() != 64
        || secret
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(
            "IMMORTAL_PROVIDER_IDENTITY_SECRET must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    let mut bytes = [0_u8; 32];
    for (output, pair) in bytes.iter_mut().zip(secret.as_bytes().chunks_exact(2)) {
        *output = hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?;
    }
    let signer = MarketSigner::from_secret_bytes(bytes)
        .map_err(|error| format!("provider identity key is invalid: {error}"));
    bytes.fill(0);
    signer
}

fn funded_offering(
    network_id: &str,
    minimum_confirmations: u32,
    reorg: u32,
    pricing: &PricingConfig,
    liquid: Option<&LiquidProviderRail>,
    zero_conf: Option<ZeroConfConfig>,
) -> Value {
    let chain = format!("swp:1:{network_id}:btc:chain");
    let lightning = format!("swp:1:{network_id}:btc:lightning");
    let mut offering = json!({
        "mkt_swp":{
            "swap_types":["submarine","reverse"],
            "sides":[
                {"input_asset_id":chain,"output_asset_id":lightning,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()},
                {"input_asset_id":lightning,"output_asset_id":chain,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()}
            ],
            "networks":[network_id],
            "script_modes":["taproot-musig2-script-exit"],
            "reservation_proof_classes":["utxo_control","lightning_liquidity"],
            "confirmation_policies":[{
                "policy_id":"btc-confirmed-no-rbf",
                "minimum_confirmations":minimum_confirmations.to_string(),
                "reorg_safety_blocks":reorg.to_string(),
                "zero_confirmation":"forbidden",
                "rbf":"reject",
                "replacement":"reject"
            }],
            "availability":"limited",
            "evm_extension":"unsupported"
        }
    });
    if let Some(zero_conf) = zero_conf {
        let mut swap_types = Vec::new();
        if zero_conf.submarine {
            swap_types.push("submarine");
        }
        if zero_conf.chain && liquid.is_some() {
            swap_types.push("chain");
        }
        if let Some(policies) = offering["mkt_swp"]["confirmation_policies"].as_array_mut() {
            policies.push(json!({
                "aggregate_in_flight_cap":zero_conf.max_in_flight_sat.to_string(),
                "eligible_swap_types":swap_types,
                "maximum_swap_amount":zero_conf.max_swap_sat.to_string(),
                "minimum_confirmations":minimum_confirmations.to_string(),
                "policy_id":"btc-zero-conf-bounded-v1",
                "reorg_safety_blocks":reorg.to_string(),
                "zero_confirmation":"allowed",
                "rbf":"reject",
                "replacement":"track"
            }));
        }
    }
    let Some(liquid) = liquid else {
        return offering;
    };
    let liquid_asset = liquid.mkt_asset_id();
    let Some(profile) = offering.get_mut("mkt_swp").and_then(Value::as_object_mut) else {
        return offering;
    };
    let Some(swap_types) = profile.get_mut("swap_types").and_then(Value::as_array_mut) else {
        return offering;
    };
    swap_types.push(Value::String("chain".to_owned()));
    let Some(sides) = profile.get_mut("sides").and_then(Value::as_array_mut) else {
        return offering;
    };
    sides.extend([
        json!({"input_asset_id":liquid_asset,"output_asset_id":lightning,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()}),
        json!({"input_asset_id":lightning,"output_asset_id":liquid_asset,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()}),
        json!({"input_asset_id":chain,"output_asset_id":liquid_asset,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()}),
        json!({"input_asset_id":liquid_asset,"output_asset_id":chain,"min":pricing.min_swap_sat.to_string(),"max":pricing.max_swap_sat.to_string(),"fee_bps":pricing.spread_bps.to_string()}),
    ]);
    let Some(networks) = profile.get_mut("networks").and_then(Value::as_array_mut) else {
        return offering;
    };
    networks.push(Value::String(liquid.network_id().to_owned()));
    offering
}

fn quote_allocation(session_id: &str) -> Result<QuoteWalletAllocation, String> {
    let digest = sha256(session_id.as_bytes());
    let index = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) & 0x7fff_fffc;
    Ok(QuoteWalletAllocation {
        unilateral_path: WalletPath::new(1, false, index)
            .map_err(|error| format!("provider quote key path is invalid: {error}"))?,
        cooperative_path: WalletPath::new(1, false, index.saturating_add(1))
            .map_err(|error| format!("provider quote key path is invalid: {error}"))?,
    })
}

fn capacity_commitment(request: &ProviderEffectRequest, sequence: u64, capacity: u64) -> String {
    let bytes = format!(
        "openagents.immortal.capacity.v1\0{}\0{}\0{}\0{}\0{}",
        request.reservation_id,
        request.reserved_asset_id,
        request.reserved_amount,
        sequence,
        capacity
    );
    lower_hex(&sha256(bytes.as_bytes()))
}

fn record_profile(event: &Event) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Value>(&event.content)
        .map_err(|error| format!("MKT-SWP content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "MKT-SWP record has no profile object".to_owned())
}

fn recovered_reservation_confirmation(
    profile: &mut Map<String, Value>,
) -> Result<ReservationConfirmation, String> {
    let terms = profile
        .remove("reservation_terms")
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| "hard Quote has no reservation terms".to_owned())?;
    let reservation_expires_at = terms
        .get("reservation_expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| "hard Quote has no reservation expiry".to_owned())?;
    Ok(ReservationConfirmation {
        reservation_id: required_string(&terms, "reservation_id")?.to_owned(),
        capacity_bucket_id: required_string(&terms, "capacity_bucket_id")?.to_owned(),
        reserved_asset_id: required_string(&terms, "reserved_asset_id")?.to_owned(),
        reserved_amount: required_string(&terms, "reserved_amount")?.to_owned(),
        committed_capacity: required_string(&terms, "handler_committed_capacity")?.to_owned(),
        reservation_expires_at,
        allocation_sequence: required_string(&terms, "allocation_sequence")?.to_owned(),
        proof_class: required_string(&terms, "proof_class")?.to_owned(),
        proof_ref: required_string(&terms, "proof_ref")?.to_owned(),
        capacity_commitment_sha256: required_string(&terms, "capacity_commitment_sha256")?
            .to_owned(),
    })
}

fn exact_tag_value<'a>(event: &'a Event, name: &'a str) -> Result<&'a str, String> {
    let mut values = event.tag_values(name);
    let value = values
        .next()
        .ok_or_else(|| format!("hard Quote has no {name} tag"))?;
    if values.next().is_some() {
        return Err(format!("hard Quote has duplicate {name} tags"));
    }
    Ok(value)
}

fn rfq_swap_type(event: &Event) -> Result<String, String> {
    record_profile(event)?
        .get("constraints")
        .and_then(Value::as_object)
        .and_then(|constraints| constraints.get("swap_type"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "RFQ has no swap type".to_owned())
}

fn rfq_asset_pair(event: &Event) -> Result<[String; 2], String> {
    let profile = record_profile(event)?;
    let pair = profile
        .get("constraints")
        .and_then(Value::as_object)
        .and_then(|constraints| constraints.get("asset_pair"))
        .and_then(Value::as_array)
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| "funded RFQ has no exact asset pair".to_owned())?;
    let input = pair
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| "funded RFQ input asset is invalid".to_owned())?;
    let output = pair
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| "funded RFQ output asset is invalid".to_owned())?;
    Ok([input.to_owned(), output.to_owned()])
}

fn rfq_invoice(event: &Event) -> Result<String, String> {
    let profile: Value = serde_json::from_str(&event.content)
        .map_err(|error| format!("RFQ content is invalid JSON: {error}"))?;
    profile
        .get("mkt_swp")
        .and_then(|profile| profile.get("invoice"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "submarine RFQ has no encrypted invoice payload".to_owned())
}

fn extract_hold_invoice(response: &Value, payment_hash: &str) -> Result<String, String> {
    let invoice = matching_hold_invoice(response, payment_hash)?;
    invoice
        .get("invoice")
        .or_else(|| invoice.get("bolt11"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "CLN has no matching recoverable hold invoice".to_owned())
}

fn exactly_one_kind<'a>(records: &'a [Event], kind: u16, name: &str) -> Result<&'a Event, String> {
    let matches = records
        .iter()
        .filter(|record| record.kind == kind)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!("provider session requires exactly one {name}"));
    }
    matches
        .first()
        .copied()
        .ok_or_else(|| format!("provider session has no {name}"))
}

fn exactly_one_kind_by_author<'a>(
    records: &'a [Event],
    kind: u16,
    author: &str,
    name: &str,
) -> Result<&'a Event, String> {
    let matches = records
        .iter()
        .filter(|record| record.kind == kind && record.pubkey == author)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!("provider session requires exactly one {name}"));
    }
    matches
        .first()
        .copied()
        .ok_or_else(|| format!("provider session has no {name}"))
}

fn provider_status_chain<'a>(records: &'a [Event], author: &str) -> Result<Vec<&'a Event>, String> {
    let mut by_sequence = BTreeMap::new();
    for record in records
        .iter()
        .filter(|record| record.kind == MKT_STATUS_KIND && record.pubkey == author)
    {
        let sequence_tags = record
            .tags
            .iter()
            .filter(|tag| tag.name() == Some("seq"))
            .collect::<Vec<_>>();
        let sequence = match sequence_tags.as_slice() {
            [tag] if tag.as_slice().len() == 2 => tag
                .value()
                .ok_or_else(|| "provider Status sequence tag is empty".to_owned())
                .and_then(canonical_u64)?,
            _ => return Err("provider Status requires exactly one sequence tag".to_owned()),
        };
        if by_sequence.insert(sequence, record).is_some() {
            return Err("provider Status chain contains a sequence fork".to_owned());
        }
    }
    let mut chain = Vec::with_capacity(by_sequence.len());
    let mut previous: Option<&Event> = None;
    for (expected_sequence, (sequence, record)) in (0_u64..).zip(by_sequence.into_iter()) {
        if sequence != expected_sequence {
            return Err("provider Status chain contains a sequence gap".to_owned());
        }
        let previous_tags = record
            .tags
            .iter()
            .filter(|tag| {
                tag.name() == Some("e")
                    && tag.as_slice().get(3).map(String::as_str) == Some("previous")
            })
            .collect::<Vec<_>>();
        match (previous, previous_tags.as_slice()) {
            (None, []) => {}
            (Some(expected), [tag])
                if tag.as_slice().len() == 4 && tag.value() == Some(expected.id.as_str()) => {}
            _ => return Err("provider Status chain has an invalid previous reference".to_owned()),
        }
        chain.push(record);
        previous = Some(record);
    }
    Ok(chain)
}

fn next_provider_status_position(
    session: &ProviderSession,
) -> Result<(u64, Option<String>), String> {
    let chain = provider_status_chain(session.signed_records(), &session.config().provider_pubkey)?;
    let sequence = u64::try_from(chain.len())
        .map_err(|_| "provider status sequence exceeds u64".to_owned())?;
    Ok((sequence, chain.last().map(|record| record.id.clone())))
}

fn latest_status_state(records: &[Event], author: &str) -> Result<Option<String>, String> {
    provider_status_chain(records, author)?
        .last()
        .map(|record| {
            record_profile(record)?
                .get("swp_state")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "provider Status has no swp_state".to_owned())
        })
        .transpose()
}

fn required_chain_confirmations(
    minimum_confirmations: u32,
    reorg_safety_blocks: u32,
) -> Result<u32, String> {
    minimum_confirmations
        .checked_add(reorg_safety_blocks)
        .ok_or_else(|| "chain finality requirement overflowed".to_owned())
}

fn base_state(state: &str) -> Result<&'static str, String> {
    match state {
        "accepted" => Ok("accepted"),
        "lock_terms_ready"
        | "hold_invoice_ready"
        | "provider_lock_terms_ready"
        | "source_lock_terms_ready"
        | "destination_lock_terms_ready" => Ok("awaiting_input"),
        "source_funding_required" => Ok("funding_required"),
        "provider_funding_broadcast"
        | "funding_observed"
        | "funding_zero_conf_accepted"
        | "funding_confirmation_required"
        | "source_funding_observed"
        | "source_funding_zero_conf_accepted"
        | "source_funding_confirmation_required"
        | "provider_destination_broadcast"
        | "destination_funding_observed" => Ok("funding_observed"),
        "lightning_payment_pending"
        | "lightning_htlcs_held"
        | "funding_final"
        | "source_funding_final"
        | "destination_funding_final"
        | "requester_destination_claim_pending"
        | "cooperative_signing_pending"
        | "provider_claim_pending"
        | "provider_claimed"
        | "provider_source_claimed" => Ok("executing"),
        "lightning_settlement_pending" | "provider_source_claim_pending" => {
            Ok("settlement_pending")
        }
        "lightning_paid" | "completed" => Ok("completed"),
        "provider_refund_prepared"
        | "provider_refund_pending"
        | "provider_destination_refund_pending"
        | "invoice_cancel_pending" => Ok("refund_pending"),
        "provider_refunded"
        | "provider_destination_refunded"
        | "invoice_cancelled"
        | "refunded" => Ok("refunded"),
        "expired" => Ok("expired"),
        "unresolved" => Ok("failed"),
        _ => Err("provider state has no MKT-SWP base-state mapping".to_owned()),
    }
}

fn canonical_u64(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err("amount is not canonical decimal".to_owned());
    }
    value
        .parse::<u64>()
        .map_err(|_| "amount exceeds u64".to_owned())
}

fn deterministic_id(label: &str, session_id: &str) -> String {
    lower_hex(&sha256(
        format!("immortal-provider-funded-v1\0{label}\0{session_id}").as_bytes(),
    ))
}

fn rpc_id(label: &str, session_id: &str) -> Result<RpcRequestId, String> {
    RpcRequestId::new(format!("provider:{label}:{}", &session_id[..16]))
        .map_err(|error| error.to_string())
}

fn lightning_id(label: &str, session_id: &str) -> Result<String, String> {
    let prefix = session_id
        .get(..16)
        .ok_or_else(|| "provider session ID is shorter than its request prefix".to_owned())?;
    let value = format!("provider:{label}:{prefix}");
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err("provider Lightning request ID is invalid".to_owned());
    }
    Ok(value)
}

fn network_id(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "bip122:000000000019d6689c085ae165831e93",
        BitcoinNetwork::Testnet => "bip122:000000000933ea01ad0ee984209779ba",
        BitcoinNetwork::Signet => "bip122:00000008819873e925422c1ff0f99f7c",
        BitcoinNetwork::Regtest => "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4",
    }
}

fn network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "mainnet",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}

fn transient_bitcoind_error(error: &BitcoindError) -> bool {
    matches!(
        error,
        BitcoindError::ResolutionFailed
            | BitcoindError::ConnectionFailed
            | BitcoindError::TimedOut(_)
            | BitcoindError::Io(_)
            | BitcoindError::HttpStatus(_)
            | BitcoindError::Rpc { .. }
    )
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "provider clock precedes the Unix epoch".to_owned())
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("provider identity key contains non-hexadecimal data".to_owned()),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
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
    use immortal_client::mkt_swp_client::{
        CooperativeSigningAction, CooperativeSigningContext, CooperativeSigningMessage,
    };
    use immortal_core::domain::{Event, Tag, validate_mkt_swp_evidence_reference};
    use immortal_core::liquid::{LiquidAssetId, LiquidNetworkId, parse_liquid_transaction};
    use immortal_core::mkt_swp_verify::{Transaction, TransactionInput, TransactionOutput};
    use serde_json::{Value, json};

    use crate::{
        bitcoind::{BitcoindAuth, BitcoindEndpoint, BitcoindLimits},
        elementsd::{ElementsdClient, ElementsdWalletName, ElementsdWalletUtxo},
        funding::SignedFundingTransaction,
        liquid::{LiquidFundingObservation, LiquidProviderRail},
        pricing::{
            CapacityBounds, FeerateObservation, PricingConfig, QuoteRequest, QuoteSide,
            ReservationTier, SwapType, funding_feerate_from_priced_vbytes,
        },
        relay_actor::QuoteDisposition,
    };

    use super::{
        ChainRailKind, ChainTerms, CooperativeProviderStep, CooperativeTranscriptPresence,
        HoldStateDecision, LIQUID_CLAIM_VBYTES, LIQUID_REFUND_VBYTES,
        LIQUID_SINGLE_INPUT_FUNDING_VBYTES, ReverseInvoiceCancellationAction, base_state,
        bind_reverse_funding_profile, bitcoin_spend_reference, canonical_json,
        chain_destination_handoff_extra, chain_observation_from_response,
        chain_terminal_evidence_expectations, contract_pricing_swap_type,
        cooperative_provider_step, decode_hex, derive_quote_with_capacity_disposition,
        execute_before_exclusive_deadline, extract_hold_invoice, finalized_from_signed_message,
        funded_cancel_pre_effect, funded_offering, funding_pricing_swap_type, hold_state_decision,
        latest_status_state, liquid_funding_fee_sat, lower_hex, priced_vbytes_for_rails,
        quote_feerate, recover_liquid_reverse_refund_before_claim, require_chain_finality,
        required_chain_confirmations, reverse_invoice_cancellation_action, reverse_spend_decision,
        settlement_destination_path, sha256, status_transaction_id, status_transaction_reference,
        terminal_evidence_expectations, unfunded_destination_reservation_evidence_value,
        validate_cross_domain_held_htlcs, validate_executable_reverse_funding, validate_held_htlcs,
        validate_liquid_chain_observation, validate_liquid_funding_inputs,
        validate_zero_conf_mempool_entry, worst_case_redeem_vbytes, zero_conf_risk_session_id,
    };

    const RUNTIME_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/provider/provider-runtime-v1.json");
    const COOPERATIVE_RUNTIME_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json");
    const LIQUID_RUNTIME_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/provider/liquid-runtime-v1.json");
    const LIQUID_RAIL_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/nipmkt/liquid-rail-v1.json");
    const ZERO_CONF_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/provider/zero-conf-v1.json");

    #[test]
    fn zero_conf_fixture_pins_local_mempool_and_status_policy() {
        let fixture: Value =
            serde_json::from_slice(ZERO_CONF_FIXTURE).expect("zero-conf fixture parses");
        assert_eq!(fixture["enabled_by_default"], false);
        validate_zero_conf_mempool_entry(&fixture["local_admission"]["mempool_entry"])
            .expect("fixture safe mempool entry");
        assert_eq!(
            base_state(
                fixture["statuses"]["submarine"]["accepted"]
                    .as_str()
                    .expect("submarine accepted state")
            ),
            Ok("funding_observed")
        );
        assert_eq!(
            base_state(
                fixture["statuses"]["chain"]["downgraded"]
                    .as_str()
                    .expect("chain downgrade state")
            ),
            Ok("funding_observed")
        );
        let mut replaceable = fixture["local_admission"]["mempool_entry"].clone();
        replaceable["bip125-replaceable"] = Value::Bool(true);
        assert!(validate_zero_conf_mempool_entry(&replaceable).is_err());
        let mut ancestor = fixture["local_admission"]["mempool_entry"].clone();
        ancestor["ancestorcount"] = json!(2);
        ancestor["depends"] = json!(["11".repeat(32)]);
        assert!(validate_zero_conf_mempool_entry(&ancestor).is_err());
        let market_session_id = "22".repeat(32);
        let risk_session_id = zero_conf_risk_session_id(&market_session_id);
        assert_ne!(risk_session_id, market_session_id);
        assert_eq!(risk_session_id.len(), 64);
    }

    #[test]
    fn liquid_fee_weight_fixture_covers_each_direction_and_one_input_bound() {
        let fixture: Value =
            serde_json::from_slice(LIQUID_RUNTIME_FIXTURE).expect("Liquid runtime fixture");
        let weights = &fixture["fee_weights"];
        assert_eq!(weights["single_input_only"], true);
        assert_eq!(
            weights["budgeted_confidential_funding_vbytes"],
            LIQUID_SINGLE_INPUT_FUNDING_VBYTES
        );
        assert!(
            weights["observed_confidential_funding_vbytes"]
                .as_u64()
                .is_some_and(|observed| observed < LIQUID_SINGLE_INPUT_FUNDING_VBYTES)
        );
        assert_eq!(weights["budgeted_claim_vbytes"], LIQUID_CLAIM_VBYTES);
        assert_eq!(weights["budgeted_refund_vbytes"], LIQUID_REFUND_VBYTES);

        let cases = [
            (
                SwapType::Submarine,
                vec![ChainRailKind::Liquid],
                "liquid_submarine_total_vbytes",
            ),
            (
                SwapType::Reverse,
                vec![ChainRailKind::Liquid],
                "liquid_reverse_total_vbytes",
            ),
            (
                SwapType::Chain,
                vec![ChainRailKind::Bitcoin, ChainRailKind::Liquid],
                "btc_to_lbtc_chain_total_vbytes",
            ),
            (
                SwapType::Chain,
                vec![ChainRailKind::Liquid, ChainRailKind::Bitcoin],
                "lbtc_to_btc_chain_total_vbytes",
            ),
        ];
        for (swap_type, rails, fixture_member) in cases {
            let priced = priced_vbytes_for_rails(swap_type, &rails).expect("priced rail shape");
            assert_eq!(weights[fixture_member], priced);
            assert_eq!(
                funding_feerate_from_priced_vbytes(priced, priced * 10)
                    .expect("exact rail fee budget"),
                10
            );
        }

        assert!(funding_feerate_from_priced_vbytes(2_000, 3_999).is_err());
        let pricing = PricingConfig {
            spread_bps: 0,
            fallback_feerate_sat_per_vb: Some(10),
            min_swap_sat: 10_000,
            max_swap_sat: 1_000_000,
            quote_expiry_seconds: 3,
            reservation_tier: ReservationTier::Hard,
            lightning_routing_fee_ppm: 0,
        };
        assert_eq!(
            quote_feerate(&pricing, true, Some(99)),
            Ok(FeerateObservation::Fallback { sat_per_vb: 10 })
        );
        assert_eq!(
            quote_feerate(&pricing, false, Some(99)),
            Ok(FeerateObservation::Live {
                sat_per_vb: 99,
                source: "bitcoind-estimatesmartfee-2".to_owned()
            })
        );
        assert_eq!(
            contract_pricing_swap_type(
                json!({"swap_type":"submarine"})
                    .as_object()
                    .expect("submarine terms")
            ),
            Ok(SwapType::Submarine)
        );
        assert!(
            funding_pricing_swap_type(
                json!({"swap_type":"submarine"})
                    .as_object()
                    .expect("invalid terms")
            )
            .is_err()
        );
    }

    #[test]
    fn liquid_funding_execution_rechecks_reserved_inputs_and_observed_fee() {
        let fixture: Value =
            serde_json::from_slice(LIQUID_RAIL_FIXTURE).expect("Liquid rail fixture");
        let runtime_fixture: Value =
            serde_json::from_slice(LIQUID_RUNTIME_FIXTURE).expect("Liquid runtime fixture");
        assert!(
            runtime_fixture["fail_closed"]
                .as_array()
                .is_some_and(|cases| cases.iter().any(|case| case == "multiple_funding_inputs"))
        );
        let raw = fixture["parser_vectors"][0]["trusted_local_unblind"]
            .as_str()
            .map(decode_hex)
            .transpose()
            .expect("Liquid funding hex")
            .expect("Liquid funding fixture");
        let transaction = parse_liquid_transaction(&raw).expect("Liquid funding transaction");
        let reserved = [ElementsdWalletUtxo {
            transaction_id: "00".repeat(32),
            output_index: 0,
            amount_sat: 101_000,
            script_pubkey: "51".to_owned(),
            confirmations: 6,
        }];
        validate_liquid_funding_inputs(&transaction, &reserved)
            .expect("exact durable Liquid input");
        let multiple = [
            reserved[0].clone(),
            ElementsdWalletUtxo {
                transaction_id: "33".repeat(32),
                output_index: 1,
                ..reserved[0].clone()
            },
        ];
        assert!(validate_liquid_funding_inputs(&transaction, &multiple).is_err());
        let reserved_input = reserved.first().expect("reserved Liquid input").clone();
        let changed = [ElementsdWalletUtxo {
            transaction_id: "22".repeat(32),
            ..reserved_input
        }];
        assert!(validate_liquid_funding_inputs(&transaction, &changed).is_err());
        let mut issued = transaction.clone();
        issued
            .inputs
            .first_mut()
            .expect("Liquid funding input")
            .has_issuance = true;
        assert!(validate_liquid_funding_inputs(&issued, &reserved).is_err());
        let pegged_asset = LiquidAssetId::parse(
            fixture["network"]["pegged_asset"]
                .as_str()
                .expect("pegged asset"),
        )
        .expect("pegged asset ID");
        assert_eq!(
            liquid_funding_fee_sat(&transaction, pegged_asset),
            Ok(1_000)
        );
    }

    #[test]
    fn liquid_chain_fixture_pins_happy_recovery_and_restart_transitions() {
        let fixture: Value =
            serde_json::from_slice(LIQUID_RUNTIME_FIXTURE).expect("Liquid runtime fixture");
        let expected = [
            ("source_lock_terms_ready", "awaiting_input"),
            ("destination_lock_terms_ready", "awaiting_input"),
            ("source_funding_required", "funding_required"),
            ("source_funding_observed", "funding_observed"),
            ("source_funding_final", "executing"),
            ("provider_destination_broadcast", "funding_observed"),
            ("destination_funding_observed", "funding_observed"),
            ("destination_funding_final", "executing"),
            ("requester_destination_claim_pending", "executing"),
            ("provider_source_claim_pending", "settlement_pending"),
            ("provider_source_claimed", "executing"),
            ("completed", "completed"),
        ];
        assert_eq!(
            fixture["chain_lifecycle"],
            Value::Array(
                expected
                    .iter()
                    .map(|(state, _)| Value::String((*state).to_owned()))
                    .collect()
            )
        );
        for (state, expected_base) in expected {
            assert_eq!(base_state(state), Ok(expected_base));
        }
        assert_eq!(
            fixture["chain_preflight"],
            json!({
                "destination_lock_terms_ready_after":"requester_source_verified",
                "source_funding_required_after":"requester_destination_verified",
                "provider_destination_broadcast_after":"source_funding_final"
            })
        );
        assert_eq!(
            fixture["claim_handoff"],
            json!({
                "destination_funding_final_signer":"provider",
                "requester_destination_claim_pending_signer":"requester",
                "requester_destination_claimed_signer":"requester",
                "provider_source_claim_pending_signer":"provider"
            })
        );
        assert_eq!(
            fixture["destination_refund_lifecycle"],
            json!([
                "requester_destination_claim_pending",
                "provider_destination_refund_pending",
                "provider_destination_refunded",
                "requester_source_refund_pending",
                "requester_source_refunded",
                "refunded"
            ])
        );
        assert_eq!(
            fixture["source_only_refund_lifecycle"],
            json!([
                "source_funding_final",
                "requester_source_refund_pending",
                "requester_source_refunded",
                "refunded"
            ])
        );
        assert_eq!(
            fixture["source_only_destination_evidence"],
            json!({
                "state":"refunded",
                "class":"reservation",
                "rung":"verified",
                "finality":"released_unfunded"
            })
        );
        assert_eq!(
            base_state("provider_destination_refund_pending"),
            Ok("refund_pending")
        );
        assert_eq!(base_state("provider_destination_refunded"), Ok("refunded"));
        assert_eq!(
            fixture["durable_operations"]["bitcoin_destination_fund"],
            "chain_fund"
        );
        assert_eq!(
            fixture["durable_operations"]["bitcoin_source_claim"],
            "chain_claim"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_destination_fund"],
            "liquid_chain_fund"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_destination_refund"],
            "liquid_chain_refund"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_source_claim"],
            "liquid_chain_claim"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_submarine_claim"],
            "liquid_submarine_claim"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_reverse_fund"],
            "liquid_reverse_fund"
        );
        assert_eq!(
            fixture["durable_operations"]["liquid_reverse_refund"],
            "liquid_reverse_refund"
        );
        assert_eq!(
            fixture["quote_cases"]
                .as_array()
                .expect("quote cases")
                .iter()
                .map(|case| case["restart"].as_str().expect("restart"))
                .collect::<Vec<_>>(),
            vec![
                "replay_exact_effect_without_second_broadcast",
                "replay_exact_effect_without_second_broadcast"
            ]
        );
        assert_eq!(
            fixture["restart_guards"],
            json!([
                "applied_funding_replays_without_rail_rpc",
                "applied_exit_replays_without_rail_rpc",
                "changed_full_effect_request_conflicts",
                "pending_submarine_claim_retries_exact_effect",
                "pending_reverse_refund_retries_exact_effect",
                "announced_claim_supersedes_unapplied_reverse_refund"
            ])
        );
        let fail_closed = fixture["fail_closed"]
            .as_array()
            .expect("fail-closed cases");
        for case in [
            "confirmation_reorg_below_contract_minimum",
            "destination_refund_reorg_before_close",
            "source_refund_reorg_before_close",
            "source_claim_reorg_before_close",
            "submarine_claim_reorg_before_close",
            "reverse_claim_reorg_before_hold_settlement",
            "reverse_refund_reorg_before_invoice_cancellation",
            "stale_cross_domain_height_observation",
        ] {
            assert!(fail_closed.iter().any(|entry| entry == case));
        }
    }

    #[test]
    fn liquid_reverse_claim_precedes_only_unapplied_refund_recovery() {
        assert!(recover_liquid_reverse_refund_before_claim("pending", false));
        assert!(!recover_liquid_reverse_refund_before_claim("pending", true));
        assert!(!recover_liquid_reverse_refund_before_claim(
            "unresolved",
            true
        ));
        assert!(recover_liquid_reverse_refund_before_claim("applied", true));
    }

    #[test]
    fn chain_destination_handoff_binds_committed_funding_bytes_and_digest() {
        let funding = sample_funding(0);
        let mut terms = sample_chain_terms(funding.raw_transaction.clone());
        let extra = chain_destination_handoff_extra(&terms).expect("bound handoff");
        assert_eq!(extra["funding_transaction"], funding.raw_transaction);
        assert_eq!(
            extra["funding_transaction_sha256"],
            terms.committed_funding_sha256
        );

        terms.committed_funding_sha256 = "ff".repeat(32);
        assert!(chain_destination_handoff_extra(&terms).is_err());
    }

    #[test]
    fn liquid_offering_is_exactly_absent_when_disabled_and_complete_when_enabled() {
        let pricing = PricingConfig {
            spread_bps: 100,
            fallback_feerate_sat_per_vb: Some(2),
            min_swap_sat: 10_000,
            max_swap_sat: 1_000_000,
            quote_expiry_seconds: 30,
            reservation_tier: ReservationTier::Hard,
            lightning_routing_fee_ppm: 1_000,
        };
        let bitcoin_network = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
        let bitcoin_chain = format!("swp:1:{bitcoin_network}:btc:chain");
        let lightning = format!("swp:1:{bitcoin_network}:btc:lightning");
        let disabled = funded_offering(bitcoin_network, 1, 6, &pricing, None, None);
        assert_eq!(
            disabled["mkt_swp"]["swap_types"],
            json!(["submarine", "reverse"])
        );
        assert_eq!(disabled["mkt_swp"]["networks"], json!([bitcoin_network]));
        assert_eq!(
            disabled["mkt_swp"]["sides"]
                .as_array()
                .expect("disabled sides")
                .iter()
                .map(|side| (
                    side["input_asset_id"].as_str().expect("input"),
                    side["output_asset_id"].as_str().expect("output")
                ))
                .collect::<Vec<_>>(),
            vec![
                (bitcoin_chain.as_str(), lightning.as_str()),
                (lightning.as_str(), bitcoin_chain.as_str()),
            ]
        );

        let liquid_network = LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixture Liquid network");
        let liquid_asset = LiquidAssetId::parse(&"11".repeat(32)).expect("fixture asset");
        let elementsd = ElementsdClient::new(
            BitcoindEndpoint::new("127.0.0.1", 18884).expect("fixture endpoint"),
            BitcoindAuth::new("fixture-user", "fixture-password").expect("fixture auth"),
            BitcoindLimits::default(),
            ElementsdWalletName::new("provider-liquid").expect("fixture wallet"),
            liquid_network.clone(),
            liquid_asset,
        )
        .expect("fixture elementsd");
        let liquid = LiquidProviderRail::new(elementsd);
        let liquid_asset = liquid.mkt_asset_id();
        let enabled = funded_offering(bitcoin_network, 1, 6, &pricing, Some(&liquid), None);
        assert_eq!(
            enabled["mkt_swp"]["swap_types"],
            json!(["submarine", "reverse", "chain"])
        );
        assert_eq!(
            enabled["mkt_swp"]["networks"],
            json!([bitcoin_network, liquid_network.as_str()])
        );
        let pairs = enabled["mkt_swp"]["sides"]
            .as_array()
            .expect("enabled sides")
            .iter()
            .map(|side| {
                (
                    side["input_asset_id"].as_str().expect("input"),
                    side["output_asset_id"].as_str().expect("output"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                (bitcoin_chain.as_str(), lightning.as_str()),
                (lightning.as_str(), bitcoin_chain.as_str()),
                (liquid_asset.as_str(), lightning.as_str()),
                (lightning.as_str(), liquid_asset.as_str()),
                (bitcoin_chain.as_str(), liquid_asset.as_str()),
                (liquid_asset.as_str(), bitcoin_chain.as_str()),
            ]
        );
    }

    #[test]
    fn liquid_observation_rejects_changed_bytes_competing_spends_and_reorg_regression() {
        let network = LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixture network");
        let asset = LiquidAssetId::parse(&"11".repeat(32)).expect("fixture asset");
        let script_pubkey = [vec![0x51, 0x20], vec![0x44; 32]].concat();
        let mut raw = Vec::new();
        raw.extend_from_slice(&2_i32.to_le_bytes());
        raw.extend_from_slice(&[0, 1]);
        raw.extend_from_slice(&[0x66; 32]);
        raw.extend_from_slice(&0_u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&0xffff_fffe_u32.to_le_bytes());
        raw.push(2);
        for (amount, script) in [(100_000_u64, script_pubkey.as_slice()), (500_u64, &[])] {
            raw.push(1);
            let mut wire_asset = asset.display_bytes();
            wire_asset.reverse();
            raw.extend_from_slice(&wire_asset);
            raw.push(1);
            raw.extend_from_slice(&amount.to_be_bytes());
            raw.push(0);
            raw.push(u8::try_from(script.len()).expect("fixture script length"));
            raw.extend_from_slice(script);
        }
        raw.extend_from_slice(&0_u32.to_le_bytes());
        let transaction = parse_liquid_transaction(&raw).expect("fixture Liquid funding");
        let mut terms = sample_chain_terms(lower_hex(&raw));
        terms.rail = super::ChainRailKind::Liquid;
        terms.asset_id = asset.mkt_asset_id(&network);
        terms.network_id = network.as_str().to_owned();
        terms.amount_sat = 100_000;
        terms.script_pubkey = script_pubkey;
        terms.committed_funding_transaction = Some(lower_hex(&raw));
        terms.committed_funding_sha256 = lower_hex(&sha256(&raw));
        let observation = LiquidFundingObservation {
            transaction_id: lower_hex(&transaction.transaction_id),
            transaction_sha256: lower_hex(&sha256(&raw)),
            raw_transaction: raw,
            output_index: 0,
            confirmations: 2,
            block_hash: Some("55".repeat(32)),
            unspent: true,
        };
        assert!(validate_liquid_chain_observation(observation.clone(), 0, &terms, true).is_ok());

        let mut changed = observation.clone();
        changed.transaction_sha256 = "00".repeat(32);
        assert!(validate_liquid_chain_observation(changed, 0, &terms, true).is_err());

        let mut spent = observation.clone();
        spent.unspent = false;
        assert!(validate_liquid_chain_observation(spent.clone(), 0, &terms, true).is_err());
        assert!(validate_liquid_chain_observation(spent, 0, &terms, false).is_ok());

        let mut missing_block = observation.clone();
        missing_block.block_hash = None;
        assert!(validate_liquid_chain_observation(missing_block, 0, &terms, true).is_err());

        let mut reorged = observation;
        reorged.confirmations = 1;
        assert!(
            validate_liquid_chain_observation(reorged.clone(), 0, &terms, true).is_ok(),
            "a shallow observation remains measurable"
        );
        assert!(
            reorged.confirmations < required_chain_confirmations(1, 1).expect("finality"),
            "a formerly final observation must not authorize the next external effect"
        );
    }

    #[test]
    fn active_reservations_produce_the_exact_overallocated_disposition() {
        let fixture: Value = serde_json::from_slice(RUNTIME_FIXTURE).expect("runtime fixture");
        let case = fixture["cases"]
            .as_array()
            .and_then(|cases| {
                cases.iter().find(|case| {
                    case["name"] == "provider-v1-hard-reservation-overallocation-disposition"
                })
            })
            .expect("over-allocation fixture case");
        assert_eq!(
            case["durable_session_disposition"],
            "swp_reservation_overallocated"
        );
        assert_eq!(case["wire_refusal"], Value::Null);

        let pricing = PricingConfig {
            spread_bps: 100,
            fallback_feerate_sat_per_vb: Some(2),
            min_swap_sat: 10_000,
            max_swap_sat: 1_000_000,
            quote_expiry_seconds: 3,
            reservation_tier: ReservationTier::Hard,
            lightning_routing_fee_ppm: 2_900,
        };
        let feerate = FeerateObservation::Fallback { sat_per_vb: 2 };
        let request = QuoteRequest {
            swap_type: SwapType::Submarine,
            side: QuoteSide::Input,
            amount: "1000000".to_owned(),
        };
        let reduced = CapacityBounds {
            capacity_bucket_id: "lightning-outbound".to_owned(),
            available_capacity: "500000".to_owned(),
        };
        let error = derive_quote_with_capacity_disposition(
            &pricing,
            &feerate,
            &reduced,
            1_500_000,
            &request,
            1_785_859_200,
            worst_case_redeem_vbytes(request.swap_type),
        )
        .expect_err("active reservation must reject the second quote");
        assert_eq!(
            error.disposition(),
            QuoteDisposition::ReservationOverallocated
        );

        let outside_total = QuoteRequest {
            amount: "2000000".to_owned(),
            ..request
        };
        let error = derive_quote_with_capacity_disposition(
            &pricing,
            &feerate,
            &reduced,
            1_500_000,
            &outside_total,
            1_785_859_200,
            worst_case_redeem_vbytes(outside_total.swap_type),
        )
        .expect_err("request outside total capacity must be rejected");
        assert_eq!(error.disposition(), QuoteDisposition::Rejected);
    }

    #[test]
    fn funded_cancel_consent_is_limited_to_pre_effect_states() {
        assert!(funded_cancel_pre_effect(false, None));
        assert!(funded_cancel_pre_effect(false, Some("accepted")));
        assert!(funded_cancel_pre_effect(false, Some("lock_terms_ready")));
        assert!(!funded_cancel_pre_effect(true, Some("lock_terms_ready")));
        assert!(!funded_cancel_pre_effect(false, Some("funding_observed")));
    }

    #[test]
    fn finalized_signed_status_reconstructs_exact_broadcast_bytes_after_restart() {
        let fixture: Value = serde_json::from_slice(COOPERATIVE_RUNTIME_FIXTURE)
            .expect("cooperative runtime fixture");
        assert_eq!(
            fixture["restart"]["final_signature_recovery"],
            "reconstruct_witness_from_signed_status_then_replay_watch"
        );
        assert_eq!(fixture["restart"]["secret_nonce_recreated"], false);
        assert_eq!(
            fixture["durability_order"],
            json!([
                "public_exit_package",
                "public_cooperative_effect_request",
                "public_chain_claim_effect_request",
                "ephemeral_nonce_allocation",
                "signed_status_routing",
                "public_cooperative_effect_result",
                "durable_broadcast_watch",
                "bitcoind_broadcast",
                "public_chain_claim_effect_result",
            ])
        );
        let unsigned = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [3; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX - 1,
                witness: Vec::new(),
            }],
            vec![TransactionOutput {
                value_sat: 99_000,
                script_pubkey: vec![0x51],
            }],
            0,
        );
        let unsigned_bytes = unsigned.serialize(false).expect("unsigned transaction");
        let signature = [7_u8; 64];
        let message = CooperativeSigningMessage {
            context: CooperativeSigningContext {
                schema: "openagents.mkt-swp.cooperative-signing.v1".to_owned(),
                order_id: "11".repeat(32),
                swap_contract_sha256: "22".repeat(32),
                effect_id: "33".repeat(32),
                leg_id: "source".to_owned(),
                unsigned_transaction: lower_hex(&unsigned_bytes),
                transaction_sha256: lower_hex(&sha256(&unsigned_bytes)),
                input_index: 0,
                prevouts: Vec::new(),
                signature_hash: "44".repeat(32),
                sighash_type: "DEFAULT".to_owned(),
                participant_keys: Vec::new(),
                tweaks: Vec::new(),
                aggregate_key: "55".repeat(32),
                exit_package_sha256: "66".repeat(32),
                latest_safe_height: "200".to_owned(),
            },
            context_sha256: "77".repeat(32),
            participant_index: 1,
            action: CooperativeSigningAction::FinalSignature,
            nonce_commitment: None,
            public_nonce: None,
            public_nonces: None,
            partial_signature: None,
            partial_signatures: None,
            final_signature: Some(lower_hex(&signature)),
            abort_reason: None,
            fallback: None,
        };
        let recovered = finalized_from_signed_message(&message).expect("recovered final bytes");
        let transaction = Transaction::parse(&recovered).expect("recovered transaction");
        assert_eq!(
            transaction
                .inputs
                .first()
                .expect("transaction input")
                .witness,
            vec![signature.to_vec()]
        );
        assert_eq!(
            transaction.serialize(false).expect("stripped transaction"),
            unsigned_bytes
        );
    }

    #[test]
    fn cooperative_runtime_fixture_emits_each_provider_phase_once() {
        let fixture: Value = serde_json::from_slice(COOPERATIVE_RUNTIME_FIXTURE)
            .expect("cooperative runtime fixture");
        let cases = fixture["phase_table"]
            .as_array()
            .expect("cooperative phase table");
        for case in cases {
            let contains = |participant: &str, action: &str| {
                case[participant]
                    .as_array()
                    .is_some_and(|actions| actions.iter().any(|value| value == action))
            };
            let presence = CooperativeTranscriptPresence {
                provider_commitment: contains("provider", "nonce_commitment"),
                requester_commitment: contains("requester", "nonce_commitment"),
                provider_public_nonce: contains("provider", "public_nonce"),
                requester_public_nonce: contains("requester", "public_nonce"),
                provider_partial_signature: contains("provider", "partial_signature"),
                requester_partial_signature: contains("requester", "partial_signature"),
                provider_final_signature: contains("provider", "final_signature"),
                provider_aborted: contains("provider", "aborted"),
                requester_aborted: contains("requester", "aborted"),
            };
            let expected = match case["next"].as_str().expect("next phase") {
                "wait" => CooperativeProviderStep::Wait,
                "nonce_commitment" => CooperativeProviderStep::NonceCommitment,
                "public_nonce" => CooperativeProviderStep::PublicNonce,
                "partial_signature" => CooperativeProviderStep::PartialSignature,
                "final_signature" => CooperativeProviderStep::FinalSignature,
                "aborted" => CooperativeProviderStep::Aborted,
                value => panic!("unsupported fixture phase {value}"),
            };
            assert_eq!(
                cooperative_provider_step(presence),
                expected,
                "{}",
                case["name"].as_str().expect("case name")
            );
        }
    }

    #[test]
    fn every_funded_executor_status_has_the_protocol_base_state() {
        let cases = [
            ("accepted", "accepted"),
            ("lock_terms_ready", "awaiting_input"),
            ("funding_observed", "funding_observed"),
            ("funding_final", "executing"),
            ("lightning_payment_pending", "executing"),
            ("lightning_paid", "completed"),
            ("cooperative_signing_pending", "executing"),
            ("provider_claim_pending", "executing"),
            ("provider_claimed", "executing"),
            ("completed", "completed"),
            ("hold_invoice_ready", "awaiting_input"),
            ("lightning_htlcs_held", "executing"),
            ("provider_lock_terms_ready", "awaiting_input"),
            ("provider_funding_broadcast", "funding_observed"),
            ("lightning_settlement_pending", "settlement_pending"),
            ("provider_refund_prepared", "refund_pending"),
            ("provider_refund_pending", "refund_pending"),
            ("provider_refunded", "refunded"),
            ("invoice_cancel_pending", "refund_pending"),
            ("invoice_cancelled", "refunded"),
            ("refunded", "refunded"),
            ("expired", "expired"),
            ("unresolved", "failed"),
        ];
        for (swp_state, expected) in cases {
            assert_eq!(base_state(swp_state), Ok(expected), "{swp_state}");
        }
    }

    #[test]
    fn latest_provider_status_uses_the_exact_sequence_chain_after_restart() {
        let mut accepted = status_event(json!({"swp_state":"accepted"}));
        accepted.id = "01".repeat(32);
        accepted.created_at = 300;
        let mut funding = status_event(json!({"swp_state":"provider_funding_broadcast"}));
        funding.id = "02".repeat(32);
        funding.created_at = 200;
        funding.tags = vec![
            Tag::new(vec!["seq".to_owned(), "1".to_owned()]),
            Tag::new(vec![
                "e".to_owned(),
                accepted.id.clone(),
                String::new(),
                "previous".to_owned(),
            ]),
        ];
        let mut exit = status_event(json!({"swp_state":"provider_refund_pending"}));
        exit.id = "03".repeat(32);
        exit.created_at = 100;
        exit.tags = vec![
            Tag::new(vec!["seq".to_owned(), "2".to_owned()]),
            Tag::new(vec![
                "e".to_owned(),
                funding.id.clone(),
                String::new(),
                "previous".to_owned(),
            ]),
        ];

        assert_eq!(
            latest_status_state(
                &[exit.clone(), accepted.clone(), funding.clone()],
                &"11".repeat(32),
            ),
            Ok(Some("provider_refund_pending".to_owned()))
        );

        let mut gap = exit.clone();
        gap.tags[0] = Tag::new(vec!["seq".to_owned(), "3".to_owned()]);
        assert!(
            latest_status_state(&[accepted.clone(), funding.clone(), gap], &"11".repeat(32))
                .is_err()
        );

        let mut fork = funding.clone();
        fork.id = "04".repeat(32);
        assert!(
            latest_status_state(&[accepted.clone(), funding.clone(), fork], &"11".repeat(32),)
                .is_err()
        );

        let mut wrong_previous = exit;
        wrong_previous.tags[1] = Tag::new(vec![
            "e".to_owned(),
            "ff".repeat(32),
            String::new(),
            "previous".to_owned(),
        ]);
        assert!(
            latest_status_state(&[accepted, funding, wrong_previous], &"11".repeat(32),).is_err()
        );
    }

    #[test]
    fn terminal_chain_depth_includes_the_reorg_safety_margin() {
        assert_eq!(required_chain_confirmations(1, 6), Ok(7));
        assert!(required_chain_confirmations(u32::MAX, 1).is_err());
    }

    #[test]
    fn bitcoin_spend_evidence_references_the_spent_outpoint() {
        let reference =
            bitcoin_spend_reference(&"11".repeat(32), 7).expect("bounded spent outpoint is valid");
        assert_eq!(reference, format!("{}:7", "11".repeat(32)));
        let evidence = json!({
            "artifact_sha256":"22".repeat(32),
            "class":"bitcoin_spend",
            "observed_at":100,
            "producer_pubkey":"33".repeat(32),
            "rail":"bitcoin",
            "reference":reference,
            "rung":"settled",
            "verifier_policy":"mkt-swp-bitcoin-v1",
            "verifier_pubkey":null,
            "view":"watch:confirmed",
        });
        validate_mkt_swp_evidence_reference(&evidence)
            .expect("spent outpoint is a valid Bitcoin spend reference");

        let mut transaction_only = evidence;
        transaction_only["reference"] = json!("11".repeat(32));
        assert!(validate_mkt_swp_evidence_reference(&transaction_only).is_err());
    }

    #[test]
    fn terminal_close_paths_require_exact_settlement_rungs() {
        for (swap_type, outcome) in [("submarine", "completed"), ("reverse", "completed")] {
            let expectations = terminal_evidence_expectations(swap_type, outcome, "bitcoin")
                .expect("completed funded path has evidence expectations");
            assert!(
                expectations
                    .iter()
                    .all(|expectation| expectation.rung == "settled")
            );
            assert!(
                expectations
                    .iter()
                    .any(|expectation| expectation.class == "bitcoin_spend")
            );
            assert!(
                expectations
                    .iter()
                    .any(|expectation| expectation.class == "lightning_payment")
            );
        }
        let refunded = terminal_evidence_expectations("reverse", "refunded", "bitcoin")
            .expect("refund funded path has evidence expectations");
        assert_eq!(refunded[0].class, "invoice");
        assert_eq!(refunded[0].rung, "verified");
        assert_eq!(refunded[1].class, "refund");
        assert_eq!(refunded[1].rung, "settled");

        let chain_contract = json!({
            "legs":[
                {"leg_id":"source","rail":"bitcoin"},
                {"leg_id":"destination","rail":"liquid"}
            ]
        });
        let source_only = chain_terminal_evidence_expectations(
            chain_contract.as_object().expect("chain contract"),
            "refunded",
            false,
        )
        .expect("source-only refund has exact evidence expectations");
        assert_eq!(source_only[0].state, "requester_source_refunded");
        assert_eq!(source_only[0].class, "bitcoin_spend");
        assert_eq!(source_only[1].state, "refunded");
        assert_eq!(source_only[1].rail, "liquid");
        assert_eq!(source_only[1].class, "reservation");
        assert_eq!(source_only[1].rung, "verified");

        let reservation_id = "12".repeat(32);
        let commitment = json!({
            "reservation_id":reservation_id,
            "reserved_amount":"100000",
            "reserved_asset_id":"swp:1:bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:elements:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:liquid"
        });
        let evidence = unfunded_destination_reservation_evidence_value(
            &"13".repeat(32),
            super::ChainRailKind::Liquid,
            &reservation_id,
            &commitment,
            500,
        )
        .expect("unfunded destination reservation evidence");
        validate_mkt_swp_evidence_reference(&evidence)
            .expect("reservation release evidence follows the common grammar");
        assert_eq!(evidence["class"], "reservation");
        assert_eq!(evidence["rail"], "liquid");
        assert_eq!(evidence["reference"], reservation_id);

        let mut changed = commitment;
        changed["reservation_id"] = json!("14".repeat(32));
        assert!(
            unfunded_destination_reservation_evidence_value(
                &"13".repeat(32),
                super::ChainRailKind::Liquid,
                &reservation_id,
                &changed,
                500,
            )
            .is_err()
        );
    }

    #[test]
    fn reverse_hold_recovery_accepts_the_cln_hold_collection_only_by_hash() {
        let expected_hash = "11".repeat(32);
        let other_hash = "22".repeat(32);
        let response = json!({
            "holdinvoices":[
                {"bolt11":"other", "payment_hash":other_hash},
                {"bolt11":"bound", "payment_hash":expected_hash},
            ]
        });
        assert_eq!(
            extract_hold_invoice(&response, &"11".repeat(32)),
            Ok("bound".to_owned())
        );
    }

    #[test]
    fn funding_status_reference_requires_a_bounded_public_outpoint() {
        let status = status_event(json!({
            "swp_state":"requester_funding_broadcast",
            "transaction_id":"33".repeat(32),
            "output_index":7,
        }));
        assert_eq!(
            status_transaction_reference(&status),
            Ok(("33".repeat(32), 7))
        );

        let malformed = status_event(json!({
            "swp_state":"requester_funding_broadcast",
            "transaction_id":"33".repeat(31),
            "output_index":7,
        }));
        assert!(status_transaction_reference(&malformed).is_err());
    }

    #[test]
    fn requester_claim_reference_does_not_require_a_funding_output_index() {
        let status = status_event(json!({
            "swp_state":"requester_claimed",
            "transaction_id":"44".repeat(32),
        }));
        assert_eq!(status_transaction_id(&status), Ok("44".repeat(32)));
        assert!(status_transaction_reference(&status).is_err());
    }

    #[test]
    fn settlement_destination_remains_inside_the_scanned_wallet_window() {
        let path = settlement_destination_path(&"55".repeat(32)).expect("settlement path");
        assert_eq!(path.account, 0);
        assert!(path.change);
        assert!(path.address_index < 20);
    }

    #[test]
    fn reverse_funding_profile_binds_exact_transaction_and_verifier_digest() {
        let funding = sample_funding(0);
        let profile = json!({
            "terms": {
                "verifier_inputs": [{
                    "leg_id": "destination",
                    "amount": "9000",
                    "script_pubkey": "51"
                }],
                "legs": [{
                    "leg_id": "destination",
                    "verifier_digest": "00".repeat(32)
                }]
            }
        });

        let bound = bind_reverse_funding_profile(profile, &funding).expect("bound profile");
        let verifier = bound["terms"]["verifier_inputs"]
            .as_array()
            .and_then(|verifiers| {
                verifiers
                    .iter()
                    .find(|verifier| verifier["leg_id"] == "destination")
            })
            .and_then(Value::as_object)
            .expect("destination verifier");
        assert_eq!(
            verifier.get("funding_transaction").and_then(Value::as_str),
            Some(funding.raw_transaction.as_str())
        );
        let raw = decode_hex(&funding.raw_transaction).expect("funding bytes");
        assert_eq!(
            verifier
                .get("funding_transaction_sha256")
                .and_then(Value::as_str),
            Some(lower_hex(&sha256(&raw)).as_str())
        );
        assert_eq!(
            verifier.get("output_index").and_then(Value::as_u64),
            Some(0)
        );
        let expected_digest = lower_hex(&sha256(
            &canonical_json(&Value::Object(verifier.clone())).expect("canonical verifier"),
        ));
        assert_eq!(
            bound["terms"]["legs"][0]["verifier_digest"].as_str(),
            Some(expected_digest.as_str())
        );
    }

    #[test]
    fn reverse_execution_and_observation_reject_changed_committed_bytes() {
        let funding = sample_funding(0);
        let changed = sample_funding(1);
        let terms = sample_chain_terms(funding.raw_transaction.clone());

        assert_eq!(
            validate_executable_reverse_funding(&funding, &terms),
            Ok(())
        );
        assert_eq!(
            validate_executable_reverse_funding(&changed, &terms),
            Err("reverse funding changed after the bilateral commitment".to_owned())
        );

        let response = json!({
            "txid": funding.txid,
            "hex": funding.raw_transaction,
            "confirmations": 0
        });
        assert!(chain_observation_from_response(&response, &funding.txid, 0, &terms).is_ok());
        let changed_response = json!({
            "txid": funding.txid,
            "hex": changed.raw_transaction,
            "confirmations": 0
        });
        let Err(error) =
            chain_observation_from_response(&changed_response, &funding.txid, 0, &terms)
        else {
            panic!("changed observed funding must fail closed");
        };
        assert_eq!(
            error,
            "observed funding differs from the bilateral transaction commitment"
        );
    }

    #[test]
    fn provider_runtime_fixture_replays_held_htlc_rejections() {
        let case = runtime_fixture_case("provider-v1-held-htlc-validation");
        assert_eq!(case["runtime_assertion"], "validate_held_htlcs");
        let terms = fixture_chain_terms(&case["terms"]);
        let current_height = fixture_u64(&case, "current_height");
        let invalid_cases = case["invalid_cases"]
            .as_array()
            .expect("held HTLC fixture must contain invalid cases");

        for invalid in invalid_cases {
            let name = fixture_string(invalid, "name");
            let expected_error = fixture_string(invalid, "expected_error");
            assert_eq!(
                validate_held_htlcs(&invalid["invoice"], &terms, current_height)
                    .expect_err("invalid held HTLC fixture must fail"),
                expected_error,
                "{name}"
            );
        }
    }

    #[test]
    fn provider_runtime_fixture_replays_signed_height_deadlines() {
        let case = runtime_fixture_case("provider-v1-signed-height-deadline-boundary");
        assert_eq!(
            case["runtime_assertion"],
            "execute_before_exclusive_deadline"
        );
        let exclusive_deadline = fixture_u32(&case, "exclusive_deadline");
        let irreversible_effects = case["irreversible_effects"]
            .as_array()
            .expect("deadline fixture must name irreversible effects");
        let observations = case["observations"]
            .as_array()
            .expect("deadline fixture must contain observations");

        for effect in irreversible_effects {
            let effect = effect
                .as_str()
                .expect("deadline fixture effect must be a string");
            for observation in observations {
                let current_height = fixture_u32(observation, "current_height");
                let expected = observation["effect_executed"]
                    .as_bool()
                    .expect("deadline fixture outcome must be boolean");
                let mut effect_executed = false;
                let result =
                    execute_before_exclusive_deadline(current_height, exclusive_deadline, || {
                        effect_executed = true;
                        Ok::<_, String>(effect)
                    })
                    .expect("effect spy cannot fail");
                assert_eq!(
                    effect_executed, expected,
                    "{effect} at height {current_height}"
                );
                assert_eq!(
                    result.is_some(),
                    expected,
                    "{effect} at height {current_height}"
                );
            }
        }
    }

    #[test]
    fn provider_runtime_fixture_replays_held_invoice_cancellation() {
        let case = runtime_fixture_case("provider-v1-held-invoice-cancellation");
        assert_eq!(case["runtime_assertion"], "hold_state_decision");
        assert_eq!(fixture_string(&case, "expected_decision"), "cancel");
        let decision = hold_state_decision(fixture_string(&case, "invoice_state"))
            .expect("cancelled invoice state must have a decision");
        let HoldStateDecision::Cancel(failure_code) = decision else {
            panic!("cancelled invoice state must choose cancellation");
        };
        assert_eq!(failure_code, fixture_string(&case, "expected_failure_code"));
    }

    #[test]
    fn provider_runtime_fixture_replays_reverse_invoice_cancellation_recovery() {
        let case = runtime_fixture_case("provider-v1-reverse-invoice-cancellation-recovery");
        assert_eq!(
            case["runtime_assertion"],
            "reverse_invoice_cancellation_action"
        );
        assert_eq!(case["effect_persisted_before_remote_lookup"], true);
        assert_eq!(case["crash_after_remote_apply"], true);
        assert_eq!(fixture_string(&case, "expected_action"), "complete_locally");
        assert_eq!(case["repeat_remote_cancel"], false);
        assert_eq!(
            reverse_invoice_cancellation_action(fixture_string(&case, "remote_state_on_restart")),
            Ok(ReverseInvoiceCancellationAction::CompleteLocally)
        );
    }

    #[test]
    fn reverse_invoice_cancellation_requires_remote_confirmation() {
        for state in ["unpaid", "accepted", "held"] {
            assert_eq!(
                reverse_invoice_cancellation_action(state),
                Ok(ReverseInvoiceCancellationAction::CancelRemotely)
            );
        }
        for state in ["paid", "settled"] {
            assert_eq!(
                reverse_invoice_cancellation_action(state),
                Err(
                    "reverse invoice settled before an unfunded cancellation could complete"
                        .to_owned()
                )
            );
        }
    }

    #[test]
    fn provider_runtime_fixture_replays_cooperative_refund_watch_retirement() {
        let case = runtime_fixture_case("provider-v1-cooperative-reverse-refund-watch-retirement");
        assert_eq!(case["runtime_assertion"], "reverse_spend_decision");
        assert_eq!(
            fixture_string(&case, "expected_decision"),
            "settle_claim_and_retire_refund_watch"
        );
        let decision = reverse_spend_decision(
            Some(fixture_string(&case, "spending_transaction_id")),
            Some(fixture_string(&case, "refund_broadcast_transaction_id")),
            Some(fixture_string(&case, "refund_replacement_transaction_id")),
            case["claim_is_final"]
                .as_bool()
                .expect("reverse claim finality must be boolean"),
        );
        assert_eq!(
            decision,
            super::ReverseSpendDecision::SettleClaimAndRetireRefundWatch
        );
        assert_eq!(
            decision.refund_watch_completion_reason(),
            Some(fixture_string(&case, "expected_watch_completion_reason"))
        );
    }

    #[test]
    fn reverse_funding_requires_every_held_htlc_to_clear_the_recovery_margin() {
        let terms = ChainTerms {
            rail: super::ChainRailKind::Bitcoin,
            asset_id: "swp:1:bip122:00:btc:chain".to_owned(),
            network_id: "bip122:00".to_owned(),
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            taproot_internal_key: "11".repeat(32),
            taproot_merkle_root: "22".repeat(32),
            payment_hash: "11".repeat(32),
            refund_height: 140,
            fee_rate_sat_per_vbyte: 1,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: 10_000,
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(180),
            lightning_settlement_blocks: 18,
            broadcast_safety_blocks: 2,
            chain_current_height: None,
            lightning_current_height: None,
            height_observed_at: None,
            height_observation_max_age_seconds: None,
            chain_block_interval_seconds: None,
            lightning_block_interval_seconds: None,
            cross_domain_safety_seconds: None,
            provider_refund_expected_at: None,
            hold_expiry_expected_at: None,
            committed_funding_transaction: None,
            committed_funding_sha256: "00".repeat(32),
            output_index: 0,
            zero_confirmation: false,
            desired_completion_time: 1_000,
        };
        let safe = json!({
            "state":"accepted",
            "htlcs":[
                {"state":"accepted","msat":6_000_000,"cltv_expiry":181},
                {"state":"accepted","msat":4_000_000,"cltv_expiry":182},
            ],
        });
        assert_eq!(
            validate_held_htlcs(&safe, &terms, 120),
            Ok(super::HeldHtlcSummary {
                state: "accepted".to_owned(),
                htlc_count: 2,
                total_msat: 10_000_000,
                minimum_cltv_expiry: 181,
            })
        );

        let equality = json!({
            "state":"held",
            "htlcs":[{"state":"accepted","msat":10_000_000,"cltv_expiry":180}],
        });
        assert!(validate_held_htlcs(&equality, &terms, 120).is_ok());

        let shallow = json!({
            "state":"accepted",
            "htlcs":[{"state":"accepted","msat":10_000_000,"cltv_expiry":179}],
        });
        assert_eq!(
            validate_held_htlcs(&shallow, &terms, 120),
            Err("held HTLC expires before the signed recovery margin")
        );

        let wrong_state = json!({
            "state":"accepted",
            "htlcs":[{"state":"settled","msat":10_000_000,"cltv_expiry":181}],
        });
        assert_eq!(
            validate_held_htlcs(&wrong_state, &terms, 120),
            Err("reverse invoice contains an HTLC outside the accepted state")
        );

        let wrong_amount = json!({
            "state":"accepted",
            "htlcs":[{"state":"accepted","msat":9_999_999,"cltv_expiry":181}],
        });
        assert_eq!(
            validate_held_htlcs(&wrong_amount, &terms, 120),
            Err("held HTLC amount differs from the bilateral contract")
        );

        let missing_expiry = json!({
            "state":"accepted",
            "htlcs":[{"state":"accepted","msat":10_000_000}],
        });
        assert_eq!(
            validate_held_htlcs(&missing_expiry, &terms, 120),
            Err("held HTLC has no block expiry")
        );

        let too_many = json!({
            "state":"accepted",
            "htlcs":(0..65).map(|_| json!({
                "state":"accepted",
                "msat":1,
                "cltv_expiry":181,
            })).collect::<Vec<_>>(),
        });
        assert_eq!(
            validate_held_htlcs(&too_many, &terms, 120),
            Err("reverse invoice has no bounded held HTLC set")
        );
    }

    #[test]
    fn liquid_reverse_hold_safety_uses_the_signed_cross_domain_conversion() {
        let mut terms = sample_chain_terms(sample_funding(0).raw_transaction);
        terms.rail = super::ChainRailKind::Liquid;
        terms.refund_height = 140;
        terms.hold_expiry_height = Some(180);
        terms.chain_current_height = Some(100);
        terms.lightning_current_height = Some(120);
        terms.height_observed_at = Some(1_000);
        terms.height_observation_max_age_seconds = Some(60);
        terms.chain_block_interval_seconds = Some(60);
        terms.lightning_block_interval_seconds = Some(600);
        terms.cross_domain_safety_seconds = Some(600);
        terms.provider_refund_expected_at = Some(3_520);
        terms.hold_expiry_expected_at = Some(37_000);
        let invoice = json!({
            "state":"accepted",
            "htlcs":[{
                "state":"accepted",
                "msat":terms.lightning_amount_sat * 1_000,
                "cltv_expiry":180,
            }]
        });
        assert!(validate_cross_domain_held_htlcs(&invoice, &terms, 121, 1_010).is_ok());
        assert_eq!(
            validate_cross_domain_held_htlcs(&invoice, &terms, 121, 1_061),
            Err("Liquid reverse height observation is stale")
        );
        terms.provider_refund_expected_at = Some(3_521);
        assert_eq!(
            validate_cross_domain_held_htlcs(&invoice, &terms, 121, 1_010),
            Err("Liquid reverse signed cross-domain timeout conversion is unsafe")
        );
    }

    #[test]
    fn terminal_hold_states_choose_a_session_scoped_disposition() {
        assert_eq!(hold_state_decision("unpaid"), Ok(HoldStateDecision::Wait));
        assert_eq!(
            hold_state_decision("accepted"),
            Ok(HoldStateDecision::Verify)
        );
        assert_eq!(hold_state_decision("held"), Ok(HoldStateDecision::Verify));
        assert_eq!(
            hold_state_decision("cancelled"),
            Ok(HoldStateDecision::Cancel("hold_invoice_cancelled"))
        );
        for state in ["paid", "settled"] {
            assert_eq!(
                hold_state_decision(state),
                Ok(HoldStateDecision::Unresolved(
                    "hold_invoice_settled_before_funding"
                ))
            );
        }
        assert!(hold_state_decision("unknown").is_err());
    }

    #[test]
    fn reverse_claim_must_cross_the_reorg_safe_confirmation_boundary() {
        let mempool = json!({"confirmations":0})
            .as_object()
            .expect("mempool object")
            .clone();
        assert!(require_chain_finality(&mempool, 1, 6).is_err());

        let shallow = json!({"confirmations":6,"blockhash":"44".repeat(32)})
            .as_object()
            .expect("shallow object")
            .clone();
        assert!(require_chain_finality(&shallow, 1, 6).is_err());

        let final_claim = json!({"confirmations":7,"blockhash":"44".repeat(32)})
            .as_object()
            .expect("final object")
            .clone();
        assert_eq!(require_chain_finality(&final_claim, 1, 6), Ok(()));
    }

    fn status_event(profile: serde_json::Value) -> Event {
        Event {
            id: "00".repeat(32),
            pubkey: "11".repeat(32),
            created_at: 1,
            kind: immortal_core::domain::MKT_STATUS_KIND,
            tags: vec![Tag::new(vec!["seq".to_owned(), "0".to_owned()])],
            content: json!({
                "schema":"openagents.mkt.v1",
                "profile":"mkt-swp",
                "profile_version":1,
                "session_id":"22".repeat(32),
                "mkt_swp":profile,
            })
            .to_string(),
            sig: "44".repeat(64),
        }
    }

    fn runtime_fixture_case(name: &str) -> Value {
        let fixture: Value =
            serde_json::from_slice(RUNTIME_FIXTURE).expect("provider runtime fixture must parse");
        fixture["cases"]
            .as_array()
            .expect("provider runtime fixture must contain cases")
            .iter()
            .find(|case| case["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("provider runtime fixture has no {name} case"))
    }

    fn fixture_chain_terms(value: &Value) -> ChainTerms {
        ChainTerms {
            rail: super::ChainRailKind::Bitcoin,
            asset_id: "swp:1:bip122:00:btc:chain".to_owned(),
            network_id: "bip122:00".to_owned(),
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            taproot_internal_key: "11".repeat(32),
            taproot_merkle_root: "22".repeat(32),
            payment_hash: "11".repeat(32),
            refund_height: fixture_u32(value, "refund_height"),
            fee_rate_sat_per_vbyte: 1,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: fixture_u64(value, "lightning_amount_sat"),
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(fixture_u32(value, "hold_expiry_height")),
            lightning_settlement_blocks: fixture_u32(value, "lightning_settlement_blocks"),
            broadcast_safety_blocks: fixture_u32(value, "broadcast_safety_blocks"),
            chain_current_height: None,
            lightning_current_height: None,
            height_observed_at: None,
            height_observation_max_age_seconds: None,
            chain_block_interval_seconds: None,
            lightning_block_interval_seconds: None,
            cross_domain_safety_seconds: None,
            provider_refund_expected_at: None,
            hold_expiry_expected_at: None,
            committed_funding_transaction: None,
            committed_funding_sha256: "00".repeat(32),
            output_index: 0,
            zero_confirmation: false,
            desired_completion_time: 1_000,
        }
    }

    fn sample_funding(lock_time: u32) -> SignedFundingTransaction {
        let transaction = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [0x11; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
                witness: vec![vec![0x01; 64]],
            }],
            vec![TransactionOutput {
                value_sat: 9_000,
                script_pubkey: vec![0x51],
            }],
            lock_time,
        );
        let raw = transaction.serialize(true).expect("serialized funding");
        let txid = lower_hex(&transaction.txid().expect("funding transaction ID"));
        SignedFundingTransaction {
            transaction,
            raw_transaction: lower_hex(&raw),
            txid,
            fee_sat: 500,
            change_sat: None,
        }
    }

    fn sample_chain_terms(committed_funding_transaction: String) -> ChainTerms {
        let committed_funding_sha256 = lower_hex(&sha256(
            &decode_hex(&committed_funding_transaction).expect("fixture funding hex"),
        ));
        ChainTerms {
            rail: super::ChainRailKind::Bitcoin,
            asset_id: "swp:1:bip122:00:btc:chain".to_owned(),
            network_id: "bip122:00".to_owned(),
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            taproot_internal_key: "11".repeat(32),
            taproot_merkle_root: "22".repeat(32),
            payment_hash: "11".repeat(32),
            refund_height: 140,
            fee_rate_sat_per_vbyte: 1,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: 10_000,
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(180),
            lightning_settlement_blocks: 18,
            broadcast_safety_blocks: 2,
            chain_current_height: None,
            lightning_current_height: None,
            height_observed_at: None,
            height_observation_max_age_seconds: None,
            chain_block_interval_seconds: None,
            lightning_block_interval_seconds: None,
            cross_domain_safety_seconds: None,
            provider_refund_expected_at: None,
            hold_expiry_expected_at: None,
            committed_funding_transaction: Some(committed_funding_transaction),
            committed_funding_sha256,
            output_index: 0,
            zero_confirmation: false,
            desired_completion_time: 1_000,
        }
    }

    fn fixture_string<'a>(value: &'a Value, member: &str) -> &'a str {
        value[member]
            .as_str()
            .unwrap_or_else(|| panic!("provider runtime fixture member {member} must be a string"))
    }

    fn fixture_u64(value: &Value, member: &str) -> u64 {
        value[member]
            .as_u64()
            .unwrap_or_else(|| panic!("provider runtime fixture member {member} must be unsigned"))
    }

    fn fixture_u32(value: &Value, member: &str) -> u32 {
        u32::try_from(fixture_u64(value, member))
            .unwrap_or_else(|_| panic!("provider runtime fixture member {member} exceeds u32"))
    }
}
