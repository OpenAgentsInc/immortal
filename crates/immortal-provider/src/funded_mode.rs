use std::{
    collections::BTreeMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{
    Cancellation, CloseOutcome, CooperativePrevout, CooperativeSigningAction,
    CooperativeSigningContext, CooperativeSigningMessage, ExitPackage, MktSigningRequest,
    ParticipantRole, StatusState,
    provider_support::{canonical_json, cooperative_signing_message, effect_id},
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND,
        MKT_STATUS_KIND, MKT_SWP_SWAP_CONTRACT_KIND,
    },
    market::MarketSigner,
    mkt_swp_verify::{
        Transaction, TransactionOutput, musig2_taproot_tweak, sha256, taproot_key_spend_sighash,
        validate_taproot_claim_witness,
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
    cooperative::ProviderCooperativeActor,
    funding::{FundingInput, FundingRequest, SignedFundingTransaction, build_funding_transaction},
    lightning::{LightningPreimage, LightningRail},
    liquidity::{WalletScanPolicy, discover_wallet_utxos},
    pricing::{
        CapacityBounds, DerivedQuote, PricingConfig, QuoteRequest, QuoteSide,
        SwapType as PricingSwapType, derive_quote, feerate_for_quote,
        funding_feerate_from_quote_budget,
    },
    quote::{
        BuiltFundedQuote, FundedQuotePolicy, QuoteWalletAllocation, ReplacementPolicy,
        build_funded_quote,
    },
    relay_actor::{
        DurableRecovery, ProviderMode, RecordOrigin, has_kind_by_author, session_id,
        stalled_session_disposition, tag_value,
    },
    settlement::{
        ClaimPreimage, CooperativeSettlementTemplate, SettlementBridge, SettlementTemplate,
    },
    store::{
        HardReservationRequest, OutPoint, ProviderStore, PublicEffectRequest, PublicEffectResult,
        PublicExitPackage, ReservationOutcome, StoredUtxo, WatchJob, WatchJobRequest,
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
    network: BitcoinNetwork,
    network_id: String,
    minimum_confirmations: u32,
    reorg_safety_blocks: u32,
    pricing: PricingConfig,
    hold_invoice_expiry_seconds: u32,
    cooperative_signing: bool,
    session_invoices: BTreeMap<String, String>,
    reserved_inputs: BTreeMap<String, Vec<FundingInput>>,
    cooperative_actors: BTreeMap<String, FundedCooperativeSession>,
    cooperative_restart_aborts: BTreeMap<String, CooperativeRestartAbort>,
}

pub(crate) struct FundedModePolicy {
    pub network: BitcoinNetwork,
    pub cooperative_signing: bool,
    pub minimum_confirmations: u32,
    pub reorg_safety_blocks: u32,
    pub pricing: PricingConfig,
    pub hold_invoice_expiry_seconds: u32,
}

#[derive(Clone)]
struct ChainTerms {
    amount_sat: u64,
    script_pubkey: Vec<u8>,
    claim_script: Vec<u8>,
    claim_control_block: Vec<u8>,
    refund_script: Vec<u8>,
    refund_control_block: Vec<u8>,
    payment_hash: String,
    refund_height: u32,
    miner_fee_budget_sat: u64,
    lightning_fee_budget_sat: u64,
    lightning_amount_sat: u64,
    fund_last: Option<u32>,
    claim_last: Option<u32>,
    lock_last: Option<u32>,
    hold_expiry_height: Option<u32>,
    lightning_settlement_blocks: u32,
    broadcast_safety_blocks: u32,
    committed_funding_transaction: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeldHtlcSummary {
    state: String,
    htlc_count: usize,
    total_msat: u64,
    minimum_cltv_expiry: u64,
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
        policy: FundedModePolicy,
    ) -> Self {
        Self {
            handle,
            store,
            wallet,
            bitcoind,
            lightning,
            network: policy.network,
            network_id: network_id(policy.network).to_owned(),
            minimum_confirmations: policy.minimum_confirmations,
            reorg_safety_blocks: policy.reorg_safety_blocks,
            pricing: policy.pricing,
            hold_invoice_expiry_seconds: policy.hold_invoice_expiry_seconds,
            cooperative_signing: policy.cooperative_signing,
            session_invoices: BTreeMap::new(),
            reserved_inputs: BTreeMap::new(),
            cooperative_actors: BTreeMap::new(),
            cooperative_restart_aborts: BTreeMap::new(),
        }
    }

    fn quote(&mut self, rfq: &Event, created_at: u64) -> Result<Option<BuiltFundedQuote>, String> {
        let swap_type_name = rfq_swap_type(rfq)?;
        let swap_type = match swap_type_name.as_str() {
            "submarine" => PricingSwapType::Submarine,
            "reverse" => PricingSwapType::Reverse,
            _ => return Err("funded v1 supports submarine and reverse swaps".to_owned()),
        };
        let Some((chain_tip, lightning_current_height)) =
            self.synchronized_quote_heights(session_id(rfq)?)?
        else {
            return Ok(None);
        };
        let pricing = self.derive_pricing(rfq, swap_type, created_at)?;
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
            FundedQuotePolicy {
                network_id: &self.network_id,
                cooperative_signing: self.cooperative_signing,
                lightning_current_height,
                fee_bps: u16::try_from(canonical_u64(&pricing.fee_bps)?)
                    .map_err(|_| "derived spread exceeds the funded Quote range".to_owned())?,
                miner_fee_budget_sat: canonical_u64(&pricing.miner_fee_budget)?,
                lightning_routing_fee_budget_sat: canonical_u64(
                    &pricing.lightning_routing_fee_budget,
                )?,
                minimum_confirmations: self.minimum_confirmations,
                reorg_safety_blocks: self.reorg_safety_blocks,
                zero_confirmation: false,
                rbf: ReplacementPolicy::Reject,
                replacement: ReplacementPolicy::Reject,
                quote_validity_seconds: self.pricing.quote_expiry_seconds,
                funding_window_blocks: 12,
                broadcast_safety_blocks: 2,
                lightning_settlement_blocks: 18,
                expected_block_seconds: 600,
                clock_skew_seconds: 60,
                recovery_target_blocks: 2,
            },
            created_at,
        )
        .map_err(|error| error.to_string())?;
        require_derived_pricing_terms(&quote, &pricing)?;
        Ok(Some(quote))
    }

    fn derive_pricing(
        &self,
        rfq: &Event,
        swap_type: PricingSwapType,
        created_at: u64,
    ) -> Result<DerivedQuote, String> {
        let session = session_id(rfq)?;
        let live = self
            .handle
            .block_on(
                self.bitcoind
                    .estimated_feerate_sat_per_vbyte(&rpc_id("quote-feerate", session)?, 2),
            )
            .map_err(|error| format!("could not estimate the Quote feerate: {error}"))?;
        let feerate = feerate_for_quote(
            &self.pricing,
            live.map(|sat_per_vb| (sat_per_vb, "bitcoind-estimatesmartfee-2")),
        )
        .map_err(|error| error.to_string())?;
        let profile = record_profile(rfq)?;
        let constraints = profile
            .get("constraints")
            .and_then(Value::as_object)
            .ok_or_else(|| "funded RFQ has no constraints".to_owned())?;
        let amount = required_string(constraints, "input_amount")?.to_owned();
        let capacity = self.quote_capacity(session, swap_type, created_at)?;
        derive_quote(
            &self.pricing,
            &feerate,
            &capacity,
            &QuoteRequest {
                swap_type,
                side: QuoteSide::Input,
                amount,
            },
            created_at,
        )
        .map_err(|error| error.to_string())
    }

    fn quote_capacity(
        &self,
        session_id: &str,
        swap_type: PricingSwapType,
        observed_at: u64,
    ) -> Result<CapacityBounds, String> {
        let (bucket_id, asset_id, total_capacity) = match swap_type {
            PricingSwapType::Submarine => (
                "lightning-outbound".to_owned(),
                format!("swp:1:{}:btc:lightning", self.network_id),
                self.lightning_capacity_for_session(session_id)?,
            ),
            PricingSwapType::Reverse => {
                let asset_id = format!("swp:1:{}:btc:chain", self.network_id);
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
            PricingSwapType::Chain => {
                return Err("funded v1 does not price chain swaps".to_owned());
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
        Ok(CapacityBounds {
            capacity_bucket_id: bucket_id,
            available_capacity: available_capacity.to_string(),
        })
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
    ) -> Result<ReservationConfirmation, String> {
        let amount = canonical_u64(&request.reserved_amount)?;
        let now = unix_now()?;
        if now >= request.reservation_expires_at {
            return Err("reservation expired before capacity allocation".to_owned());
        }
        let (proof_class, selected_utxos, committed_capacity) =
            if request.reserved_asset_id.ends_with(":chain") {
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
                    return Err("provider wallet has insufficient confirmed capacity".to_owned());
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
                return Err("reservation asset is not a funded v1 rail".to_owned());
            };
        if committed_capacity < amount {
            return Err("provider rail has insufficient confirmed capacity".to_owned());
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
                    return Err("capacity bucket is fully allocated".to_owned());
                }
                Ok(ReservationOutcome::UtxoUnavailable(_)) => {
                    return Err("selected chain capacity is no longer available".to_owned());
                }
                Err(error) => return Err(format!("capacity reservation failed: {error}")),
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
        let reservation_id = deterministic_id("reservation", session_id);
        let inputs = match self.reserved_inputs.get(session_id) {
            Some(inputs) => inputs.clone(),
            None => self.recover_reserved_inputs(session_id, &reservation_id)?,
        };
        let funding = self.build_reverse_funding(
            session_id,
            &inputs,
            script_pubkey,
            amount_sat,
            miner_fee_budget_sat,
        )?;
        bind_reverse_funding_profile(profile, &funding)
    }

    fn build_reverse_funding(
        &self,
        session_id: &str,
        inputs: &[FundingInput],
        destination_script_pubkey: Vec<u8>,
        amount_sat: u64,
        miner_fee_budget_sat: u64,
    ) -> Result<SignedFundingTransaction, String> {
        let funding_fee_rate_sat_per_vbyte =
            funding_feerate_from_quote_budget(PricingSwapType::Reverse, miner_fee_budget_sat)
                .map_err(|error| error.to_string())?;
        let funding = build_funding_transaction(
            &self.wallet,
            inputs,
            &FundingRequest {
                destination_script_pubkey,
                amount_sat,
                fee_rate_sat_per_vbyte: funding_fee_rate_sat_per_vbyte,
                change_path: funding_change_path(session_id)?,
                lock_time: 0,
            },
        )
        .map_err(|error| format!("could not construct reverse funding: {error}"))?;
        if funding.fee_sat > miner_fee_budget_sat {
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

    fn settlement_template(
        &self,
        session_id: &str,
        observation: &ChainObservation,
        terms: &ChainTerms,
        path: SettlementPath,
    ) -> Result<SettlementTemplate, String> {
        let wallet_path = quote_allocation(session_id)?.unilateral_path;
        let destination_path = settlement_destination_path(session_id)?;
        let destination = self
            .wallet
            .derive_address(destination_path)
            .map_err(|error| format!("could not derive settlement destination: {error}"))?;
        let destination_value_sat = terms
            .amount_sat
            .checked_sub(terms.miner_fee_budget_sat)
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
            maximum_fee_sat: terms.miner_fee_budget_sat,
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
        let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "Quote")?;
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
        let leg = contract_entry(contract, "legs", leg_id, "Bitcoin leg")?;
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
        let confirmation_policy = leg
            .get("confirmation_policy")
            .ok_or_else(|| "cooperative Bitcoin leg has no confirmation policy".to_owned())?;
        let confirmation_policy_sha256 = value_digest(confirmation_policy)?;
        let recovery = verifier
            .get("provider_exit_policy")
            .and_then(Value::as_object)
            .ok_or_else(|| "cooperative verifier has no provider exit policy".to_owned())?;
        let earliest = required_string(recovery, "earliest_broadcast_height")?;
        let latest = required_string(recovery, "latest_safe_broadcast_height")?;
        let verifier_digest = value_digest(&Value::Object(verifier.clone()))?;
        let (taproot_script, taproot_control_block) = if path == "claim" {
            (
                required_string(&verifier, "claim_script")?,
                required_string(&verifier, "taproot_claim_control_block")?,
            )
        } else {
            (
                required_string(&verifier, "refund_script")?,
                required_string(&verifier, "taproot_refund_control_block")?,
            )
        };
        let unilateral_effect_id = effect_id(&order.id, exit_role, leg_id)
            .map_err(|error| format!("cooperative unilateral effect ID failed: {error}"))?;
        let public_package = json!({
            "asset_id":leg.get("asset_id").cloned().ok_or_else(|| "cooperative leg has no asset ID".to_owned())?,
            "contract_sha256":contract_sha256,
            "effect_id":unilateral_effect_id,
            "exit":{
                "destination_script_pubkey":lower_hex(&settlement.destination_script_pubkey),
                "earliest_broadcast_height":earliest,
                "fee_policy":{
                    "bump_mode":required_string(recovery, "bump_mode")?,
                    "maximum_fee":required_string(recovery, "maximum_fee")?,
                    "target_blocks":recovery.get("target_blocks").cloned().ok_or_else(|| "cooperative exit policy has no target blocks".to_owned())?,
                },
                "input_sequence":settlement.input_sequence,
                "latest_safe_broadcast_height":latest,
                "lock_time":settlement.lock_time,
                "mode":"external_signer",
                "path":path,
                "sighash_type":"DEFAULT",
                "signed_transaction":null,
                "signer_ref":provider_exit_signer_ref,
                "transaction_template_sha256":lower_hex(&sha256(&unsigned_bytes)),
                "transaction_version":settlement.transaction_version,
            },
            "funding":{
                "amount":terms.amount_sat.to_string(),
                "confirmation_policy_sha256":confirmation_policy_sha256,
                "output_index":output_index,
                "script_pubkey":lower_hex(&terms.script_pubkey),
                "transaction_id":funding_txid,
                "transaction_template":funding_raw,
                "transaction_template_sha256":lower_hex(&sha256(&funding_bytes)),
            },
            "leg_id":leg_id,
            "network_id":leg.get("network_id").cloned().ok_or_else(|| "cooperative leg has no network ID".to_owned())?,
            "order_id":order.id,
            "participant_role":"provider",
            "profile":"mkt-swp",
            "profile_version":1,
            "schema":"openagents.mkt-swp.exit.v1",
            "secret_commitments":{
                "payment_hash":terms.payment_hash,
                "preimage_recovery_ref":null,
            },
            "swap_contract_ids":[requester_contract.id,provider_contract.id],
            "verification":{
                "quote_id":quote.id,
                "swap_tree_sha256":required_string(&verifier, "swap_tree_sha256")?,
                "taproot_control_block":taproot_control_block,
                "taproot_script":taproot_script,
                "taproot_tree":verifier.get("taproot_tree").cloned().ok_or_else(|| "cooperative verifier has no Taproot tree".to_owned())?,
                "verifier_digest":verifier_digest,
            },
        });
        let package = ExitPackage::parse(public_package)
            .map_err(|error| format!("provider cooperative exit package is invalid: {error}"))?;
        let package_sha256 = package
            .commitment_sha256()
            .map_err(|error| format!("provider cooperative exit package digest failed: {error}"))?;
        require_provider_exit_commitment(contract, leg_id, path, &package_sha256)?;
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
        if has_cooperative_action(
            records,
            provider,
            ParticipantRole::Provider,
            CooperativeSigningAction::FinalSignature,
        )? || has_cooperative_action(
            records,
            provider,
            ParticipantRole::Provider,
            CooperativeSigningAction::Aborted,
        )? {
            return Ok(None);
        }
        if has_cooperative_action(
            records,
            requester,
            ParticipantRole::Requester,
            CooperativeSigningAction::Aborted,
        )? {
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
        if has_cooperative_action(
            records,
            provider,
            ParticipantRole::Provider,
            CooperativeSigningAction::PartialSignature,
        )? && has_cooperative_action(
            records,
            requester,
            ParticipantRole::Requester,
            CooperativeSigningAction::PartialSignature,
        )? {
            return active
                .actor
                .final_signature_status(
                    session,
                    created_at,
                    &SettlementBridge::new(&self.wallet),
                    current_height,
                )
                .map(Some)
                .map_err(|error| format!("could not finalize cooperative signature: {error}"));
        }
        if has_cooperative_action(
            records,
            provider,
            ParticipantRole::Provider,
            CooperativeSigningAction::PublicNonce,
        )? && has_cooperative_action(
            records,
            requester,
            ParticipantRole::Requester,
            CooperativeSigningAction::PublicNonce,
        )? {
            return active
                .actor
                .partial_signature_status(
                    session,
                    created_at,
                    &SettlementBridge::new(&self.wallet),
                    current_height,
                )
                .map(Some)
                .map_err(|error| format!("could not construct cooperative partial: {error}"));
        }
        if has_cooperative_action(
            records,
            provider,
            ParticipantRole::Provider,
            CooperativeSigningAction::NonceCommitment,
        )? && has_cooperative_action(
            records,
            requester,
            ParticipantRole::Requester,
            CooperativeSigningAction::NonceCommitment,
        )? {
            return active
                .actor
                .public_nonce_status(session, created_at, current_height)
                .map(Some)
                .map_err(|error| format!("could not reveal cooperative nonce: {error}"));
        }
        active
            .actor
            .nonce_commitment_status(session, created_at)
            .map(Some)
            .map_err(|error| format!("could not commit cooperative nonce: {error}"))
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
        validate_held_htlcs(invoice, terms, tip.height).map_err(ReverseHoldSafetyError::Invalid)
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
        now: u64,
    ) -> Result<(String, u32, Value), String> {
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
            terms.miner_fee_budget_sat,
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
            .refund(&self.settlement_template(
                session_id,
                &observation,
                terms,
                SettlementPath::Refund,
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
        let public_request = json!({
            "claim_txid":spending_transaction_id,
            "payment_hash":terms.payment_hash,
        });
        let (effect_id, request_sha256) =
            self.persist_effect_request(session_id, "invoice_settle", public_request, now)?;
        let preimage = LightningPreimage::new(
            <[u8; 32]>::try_from(preimage.as_slice())
                .map_err(|_| "reverse claim preimage has another length".to_owned())?,
        );
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
        let announced_claim = status_by_state(
            records,
            &session.config().requester_pubkey,
            "requester_claimed",
        )
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
            return Self::next_status_with_evidence(
                session,
                created_at,
                "lightning_settlement_pending",
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

    fn next_status(
        session: &ProviderSession,
        created_at: u64,
        state: &'static str,
        extra: Map<String, Value>,
    ) -> Result<MktSigningRequest, String> {
        let provider_statuses = session
            .signed_records()
            .iter()
            .filter(|record| {
                record.kind == MKT_STATUS_KIND && record.pubkey == session.config().provider_pubkey
            })
            .collect::<Vec<_>>();
        let sequence = u64::try_from(provider_statuses.len())
            .map_err(|_| "provider status sequence exceeds u64".to_owned())?;
        let previous = provider_statuses.last().map(|record| record.id.as_str());
        let base_state = base_state(state)?;
        session
            .provider_status(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous,
                    base_state,
                    swp_state: state,
                },
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
        let provider_statuses = session
            .signed_records()
            .iter()
            .filter(|record| {
                record.kind == MKT_STATUS_KIND && record.pubkey == session.config().provider_pubkey
            })
            .collect::<Vec<_>>();
        let sequence = u64::try_from(provider_statuses.len())
            .map_err(|_| "provider status sequence exceeds u64".to_owned())?;
        let previous = provider_statuses.last().map(|record| record.id.as_str());
        session
            .provider_status_with_evidence(
                created_at,
                &deterministic_id(state, &session.config().session_id),
                StatusState {
                    sequence,
                    previous,
                    base_state: base_state(state)?,
                    swp_state: state,
                },
                evidence,
                extra,
            )
            .map_err(|error| format!("could not construct provider {state} Status: {error}"))
    }
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
        let proof_class = if confirmation.reserved_asset_id.ends_with(":chain") {
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
        observed_at: u64,
    ) -> Result<(), String> {
        self.dispose_unfunded_session(session, "quote_rejected", observed_at)
    }

    fn construct_quote(
        &mut self,
        session: &mut ProviderSession,
        _requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String> {
        let rfq = exactly_one_kind(session.signed_records(), MKT_RFQ_KIND, "RFQ")?.clone();
        let Some(quote) = self.quote(&rfq, created_at)? else {
            return Ok(None);
        };
        let reservation_id = deterministic_id("reservation", &session.config().session_id);
        let capacity_bucket_id = if quote.reserved_asset_id.ends_with(":chain") {
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
        if rfq_swap_type(&rfq)? == "reverse" {
            return session
                .hard_quote_with_bound_reserve(
                    created_at,
                    &deterministic_id("quote", &session_id),
                    quote.expiration,
                    reservation,
                    quote.profile,
                    |request, existing_confirmation, profile| {
                        let confirmation = match existing_confirmation {
                            Some(confirmation) => confirmation.clone(),
                            None => self.reserve(request)?,
                        };
                        let profile = self.bind_reverse_funding_template(&session_id, profile)?;
                        Ok((confirmation, profile))
                    },
                )
                .map(Some)
                .map_err(|error| format!("could not construct funded hard Quote: {error}"));
        }
        session
            .hard_quote_with_reserve(
                created_at,
                &deterministic_id("quote", &session_id),
                quote.expiration,
                reservation,
                quote.profile,
                |request| self.reserve(request),
            )
            .map(Some)
            .map_err(|error| format!("could not construct funded hard Quote: {error}"))
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
                if deadline_expired(
                    self.chain_height("submarine-fund-deadline", &session.config().session_id)?,
                    fund_last,
                ) {
                    return Self::deadline_failure_status(
                        session,
                        created_at,
                        "funding_deadline_expired",
                    )
                    .map(Some);
                }
                let (transaction_id, output_index) =
                    status_transaction_reference(requester_status)?;
                let observation = self.observe_chain_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                let evidence =
                    bitcoin_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_observed",
                    evidence,
                    transaction_extra(&observation),
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
                let observation = self.observe_chain_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations < self.minimum_confirmations {
                    return Ok(None);
                }
                let evidence =
                    bitcoin_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_final",
                    evidence,
                    transaction_extra(&observation),
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
                if deadline_expired(
                    self.chain_height("submarine-claim-deadline", &session.config().session_id)?,
                    claim_last,
                ) {
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
                let observation = self.observe_chain_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations < self.minimum_confirmations {
                    return Err(
                        "submarine funding lost required confirmation before payment".to_owned(),
                    );
                }
                if self.cooperative_signing {
                    self.prepare_cooperative_session(session)?;
                }
                let invoice = rfq_invoice(exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?)?;
                let effect_height = self.chain_height(
                    "submarine-claim-effect-deadline",
                    &session.config().session_id,
                )?;
                let Some(result) =
                    execute_before_exclusive_deadline(effect_height, claim_last, || {
                        self.execute_submarine_claim(
                            session,
                            &observation,
                            &terms,
                            &invoice,
                            created_at,
                        )
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
                if self.cooperative_signing {
                    return self
                        .begin_cooperative_session(session, created_at)
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
                if status_by_state(records, requester_pubkey, "requester_invoice_verified")
                    .is_none()
                    || status_by_state(records, requester_pubkey, "lightning_payment_pending")
                        .is_none()
                {
                    return Ok(None);
                }
                let lock_last = terms
                    .lock_last
                    .ok_or_else(|| "reverse contract has no lock deadline".to_owned())?;
                if deadline_expired(
                    self.chain_height("reverse-lock-deadline", &session.config().session_id)?,
                    lock_last,
                ) {
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
                let summary = match self
                    .verify_reverse_hold_safety(&session.config().session_id, &terms)
                {
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
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "lightning_htlcs_held",
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
                if status_by_state(records, requester_pubkey, "requester_lock_verified").is_none() {
                    return Ok(None);
                }
                let lock_last = terms
                    .lock_last
                    .ok_or_else(|| "reverse contract has no lock deadline".to_owned())?;
                if deadline_expired(
                    self.chain_height("reverse-fund-deadline", &session.config().session_id)?,
                    lock_last,
                ) {
                    return Self::hold_failure_status(
                        session,
                        created_at,
                        "invoice_cancel_pending",
                        "lock_deadline_expired",
                    )
                    .map(Some);
                }
                match self.verify_reverse_hold_safety(&session.config().session_id, &terms) {
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
                let effect_height = self.chain_height(
                    "reverse-funding-effect-deadline",
                    &session.config().session_id,
                )?;
                let Some((transaction_id, output_index, result)) =
                    execute_before_exclusive_deadline(effect_height, lock_last, || {
                        self.execute_reverse_funding(session, &terms, created_at)
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
                let observation = ChainObservation {
                    transaction: Transaction::new(2, Vec::new(), Vec::new(), 0),
                    transaction_id,
                    output_index,
                    confirmations: 0,
                    block_hash: None,
                };
                let evidence = bitcoin_transaction_evidence(
                    session,
                    &observation.transaction_id,
                    "bitcoin_transaction",
                    "measured",
                    &result,
                    created_at,
                    "provider funding accepted by bitcoind",
                )?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "provider_funding_broadcast",
                    evidence,
                    transaction_extra(&observation),
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
                let observation = self.observe_chain_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                let evidence =
                    bitcoin_output_evidence(session, &observation, "measured", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_observed",
                    evidence,
                    transaction_extra(&observation),
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
                let observation = self.observe_chain_funding(
                    &session.config().session_id,
                    &transaction_id,
                    output_index,
                    &terms,
                )?;
                if observation.confirmations < self.minimum_confirmations {
                    return Ok(None);
                }
                let evidence =
                    bitcoin_output_evidence(session, &observation, "verified", created_at)?;
                Self::next_status_with_evidence(
                    session,
                    created_at,
                    "funding_final",
                    evidence,
                    transaction_extra(&observation),
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
    if terms.committed_funding_transaction.as_deref() != Some(raw) {
        return Err(
            "observed funding differs from the bilateral transaction commitment".to_owned(),
        );
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
    let evidence_expectations = terminal_evidence_expectations(swap_type, outcome)?;
    let evidence_refs = evidence_expectations
        .iter()
        .map(|expectation| status_evidence(records, &session.config().provider_pubkey, expectation))
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
) -> Result<[TerminalEvidenceExpectation; 2], String> {
    let expectation = |state, rail, class, rung| TerminalEvidenceExpectation {
        state,
        rail,
        class,
        rung,
    };
    match (swap_type, outcome) {
        ("submarine", "completed") => Ok([
            expectation("provider_claimed", "bitcoin", "bitcoin_spend", "settled"),
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
            expectation(
                "lightning_settlement_pending",
                "bitcoin",
                "bitcoin_spend",
                "settled",
            ),
        ]),
        ("reverse", "refunded") => Ok([
            expectation("invoice_cancelled", "lightning", "invoice", "verified"),
            expectation("provider_refunded", "bitcoin", "refund", "settled"),
        ]),
        _ => Err("provider Close has no funded-v1 evidence mapping".to_owned()),
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
    let committed_funding_transaction = required_string(verifier, "funding_transaction")?;
    let committed_funding_bytes = decode_hex(committed_funding_transaction)?;
    if required_lower_hex(verifier, "funding_transaction_sha256")?
        != lower_hex(&sha256(&committed_funding_bytes))
        || verifier.get("output_index").and_then(Value::as_u64) != Some(0)
    {
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
    Ok(ChainTerms {
        amount_sat,
        script_pubkey: decode_hex(required_string(verifier, "script_pubkey")?)?,
        claim_script: decode_hex(required_string(verifier, "claim_script")?)?,
        claim_control_block: decode_hex(required_string(verifier, "taproot_claim_control_block")?)?,
        refund_script: decode_hex(required_string(verifier, "refund_script")?)?,
        refund_control_block: decode_hex(required_string(
            verifier,
            "taproot_refund_control_block",
        )?)?,
        payment_hash,
        refund_height,
        miner_fee_budget_sat: canonical_u64(required_string(contract, "miner_fee_budget")?)?,
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
        committed_funding_transaction: Some(committed_funding_transaction.to_owned()),
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

fn require_provider_exit_commitment(
    contract: &Map<String, Value>,
    leg_id: &str,
    path: &str,
    package_sha256: &str,
) -> Result<(), String> {
    if contract
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .is_some_and(|commitments| {
            commitments.iter().any(|commitment| {
                commitment.get("participant_role").and_then(Value::as_str) == Some("provider")
                    && commitment.get("leg_id").and_then(Value::as_str) == Some(leg_id)
                    && commitment.get("path").and_then(Value::as_str) == Some(path)
                    && commitment.get("package_mode").and_then(Value::as_str)
                        == Some("external_signer")
                    && commitment.get("package_sha256").and_then(Value::as_str)
                        == Some(package_sha256)
            })
        })
    {
        Ok(())
    } else {
        Err("cooperative provider exit package is not committed by the contract".to_owned())
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

fn bitcoin_transaction_evidence(
    session: &ProviderSession,
    transaction_id: &str,
    class: &str,
    rung: &str,
    artifact: &Value,
    observed_at: u64,
    view: &str,
) -> Result<Value, String> {
    required_hash(transaction_id, "Bitcoin evidence transaction ID")?;
    Ok(json!({
        "artifact_sha256":value_digest(artifact)?,
        "class":class,
        "observed_at":observed_at,
        "producer_pubkey":session.config().provider_pubkey,
        "rail":"bitcoin",
        "reference":transaction_id,
        "rung":rung,
        "verifier_policy":"mkt-swp-bitcoin-v1",
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
) -> Value {
    let chain = format!("swp:1:{network_id}:btc:chain");
    let lightning = format!("swp:1:{network_id}:btc:lightning");
    json!({
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
    })
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

fn latest_status_state(records: &[Event], author: &str) -> Result<Option<String>, String> {
    records
        .iter()
        .filter(|record| record.kind == MKT_STATUS_KIND && record.pubkey == author)
        .max_by_key(|record| record.created_at)
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
        "lock_terms_ready" | "hold_invoice_ready" | "provider_lock_terms_ready" => {
            Ok("awaiting_input")
        }
        "provider_funding_broadcast" | "funding_observed" => Ok("funding_observed"),
        "lightning_payment_pending"
        | "lightning_htlcs_held"
        | "funding_final"
        | "cooperative_signing_pending"
        | "provider_claim_pending"
        | "provider_claimed" => Ok("executing"),
        "lightning_settlement_pending" => Ok("settlement_pending"),
        "lightning_paid" | "completed" => Ok("completed"),
        "provider_refund_prepared" | "provider_refund_pending" | "invoice_cancel_pending" => {
            Ok("refund_pending")
        }
        "provider_refunded" | "invoice_cancelled" | "refunded" => Ok("refunded"),
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
    use immortal_core::domain::{Event, validate_mkt_swp_evidence_reference};
    use immortal_core::mkt_swp_verify::{Transaction, TransactionInput, TransactionOutput};
    use serde_json::{Value, json};

    use crate::funding::SignedFundingTransaction;

    use super::{
        ChainTerms, HoldStateDecision, ReverseInvoiceCancellationAction, base_state,
        bind_reverse_funding_profile, bitcoin_spend_reference, canonical_json,
        chain_observation_from_response, decode_hex, execute_before_exclusive_deadline,
        extract_hold_invoice, finalized_from_signed_message, funded_cancel_pre_effect,
        hold_state_decision, latest_status_state, lower_hex, require_chain_finality,
        required_chain_confirmations, reverse_invoice_cancellation_action, reverse_spend_decision,
        settlement_destination_path, sha256, status_transaction_id, status_transaction_reference,
        terminal_evidence_expectations, validate_executable_reverse_funding, validate_held_htlcs,
    };

    const RUNTIME_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/provider/provider-runtime-v1.json");
    const COOPERATIVE_RUNTIME_FIXTURE: &[u8] =
        include_bytes!("../../../tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json");

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
    fn latest_provider_status_reads_the_swp_state_member() {
        let mut older = status_event(json!({"swp_state":"accepted"}));
        older.created_at = 1;
        let mut latest = status_event(json!({"swp_state":"funding_final"}));
        latest.created_at = 2;

        assert_eq!(
            latest_status_state(&[older, latest], &"11".repeat(32)),
            Ok(Some("funding_final".to_owned()))
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
            let expectations = terminal_evidence_expectations(swap_type, outcome)
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
        let refunded = terminal_evidence_expectations("reverse", "refunded")
            .expect("refund funded path has evidence expectations");
        assert_eq!(refunded[0].class, "invoice");
        assert_eq!(refunded[0].rung, "verified");
        assert_eq!(refunded[1].class, "refund");
        assert_eq!(refunded[1].rung, "settled");
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
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            payment_hash: "11".repeat(32),
            refund_height: 140,
            miner_fee_budget_sat: 500,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: 10_000,
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(180),
            lightning_settlement_blocks: 18,
            broadcast_safety_blocks: 2,
            committed_funding_transaction: None,
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
            tags: Vec::new(),
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
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            payment_hash: "11".repeat(32),
            refund_height: fixture_u32(value, "refund_height"),
            miner_fee_budget_sat: 500,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: fixture_u64(value, "lightning_amount_sat"),
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(fixture_u32(value, "hold_expiry_height")),
            lightning_settlement_blocks: fixture_u32(value, "lightning_settlement_blocks"),
            broadcast_safety_blocks: fixture_u32(value, "broadcast_safety_blocks"),
            committed_funding_transaction: None,
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
        ChainTerms {
            amount_sat: 9_000,
            script_pubkey: vec![0x51],
            claim_script: vec![0x51],
            claim_control_block: vec![0xc0; 33],
            refund_script: vec![0x51],
            refund_control_block: vec![0xc0; 33],
            payment_hash: "11".repeat(32),
            refund_height: 140,
            miner_fee_budget_sat: 500,
            lightning_fee_budget_sat: 100,
            lightning_amount_sat: 10_000,
            fund_last: None,
            claim_last: None,
            lock_last: Some(112),
            hold_expiry_height: Some(180),
            lightning_settlement_blocks: 18,
            broadcast_safety_blocks: 2,
            committed_funding_transaction: Some(committed_funding_transaction),
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
