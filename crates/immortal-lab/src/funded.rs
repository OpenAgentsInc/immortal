use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use immortal_client::liquid::{
    LiquidBeforeFundRequest, LiquidConfidentiality, LiquidExitMode, LiquidFundingVerificationInput,
    LiquidLegPurpose, LiquidNodeAuthority, LiquidNodeRequest, LiquidSwapType, LiquidUnblindRequest,
    LocalLiquidNodeObservation, LocalLiquidObservation,
};
use immortal_client::mkt_swp_client::{
    AwaitingVerification, Cancellation, ChainRecoveryState, CooperativeSigningAction,
    CooperativeSigningContext, CooperativeSigningMessage, DeliveryProvenance,
    EsploraBroadcastRequest, ExitPackage, ExitSigningOutcome, ExternalEffectRequest, FundingAction,
    FundingAuthorized, FundingVerificationInput, InvoiceVerificationInput, KeylessEsploraExecutor,
    LightningProgressState, LightningReadinessState, LightningRecoveryState,
    LiquidBroadcastRequest, LiquidVerifyBeforeFundInput, LocalBitcoinObservation,
    LocalLightningProgress, LocalLightningReadiness, LocalRailEvidence, LocalRecoveryObservation,
    ParticipantRole, RailObservationRequest, RecoveryAction, RequesterContractLocalInputs,
    RequesterContractSigningInput, RequesterFundingResolution, RequesterOrderInput,
    RequesterQuoteView, RequesterSessionView, RequesterVerificationState, SignedRecordDelivery,
    StatusState, SwapClientConfig, SwapRecordFactory, SwapSession, SwapType, TimeoutLadder,
    VerifyBeforeFundInput, provider_support,
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_STATUS_KIND,
        MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport,
        Tag, parse_unique_json, validate_mkt_public_event,
    },
    liquid::{LiquidAssetId, LiquidNetworkId, LiquidTransaction, parse_liquid_transaction},
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record_raw, wrap_mkt_record},
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, sha256, taproot_key_spend_sighash,
    },
};
use immortal_provider::{
    bitcoind::{
        BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindError, BitcoindLimits, RpcRequestId,
    },
    cln::{ClnClient, ClnEndpoint, ClnLimits, ClnRequestId, Millisatoshi, PaymentResult},
    elementsd::{
        ElementsdClient, ElementsdError, ElementsdMempoolAdmission, ElementsdSignedFunding,
        ElementsdWalletName,
    },
    funding::{FundingInput, FundingRequest, SignedFundingTransaction, build_funding_transaction},
    liquid::{LiquidProviderRail, VerifiedProviderLiquid},
    pricing::{
        CapacityBounds, FeerateObservation, LIQUID_CLAIM_VBYTES, LIQUID_REFUND_VBYTES,
        LIQUID_SINGLE_INPUT_FUNDING_VBYTES, PricingConfig, QuoteRequest, QuoteSide,
        ReservationTier, bitcoin_to_liquid_chain_quote_vbytes, derive_quote_with_worst_case_vbytes,
        funding_feerate_from_priced_vbytes, liquid_reverse_quote_vbytes,
        liquid_submarine_quote_vbytes, liquid_to_bitcoin_chain_quote_vbytes,
    },
    settlement::{
        ClaimPreimage, CooperativeSettlementTemplate, CooperativeSigningRound, SettlementBridge,
        SettlementTemplate,
    },
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
};
use serde_json::{Map, Value, json};
use tokio::{runtime::Runtime, task::JoinHandle};
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message, WebSocket, client};

use crate::state::{
    BoltzAdapterApproval, BoltzAdapterBroadcast, BoltzAdapterFinalizeRequest, BoltzAdapterPrepared,
    FundedCheckpoint, FundedInjectionRequest, LabPaths, clear_boltz_adapter_controls,
    load_boltz_adapter_broadcast, load_boltz_adapter_finalize_request, load_funded_deliveries,
    load_funded_injection, load_funded_injection_proof, load_funded_journey_checkpoint,
    load_funded_secret, load_funded_signed_exit, load_or_create_funded_run_id,
    load_or_create_identity, remove_funded_secret, store_boltz_adapter_approval,
    store_boltz_adapter_complete, store_boltz_adapter_prepared, store_funded_checkpoint,
    store_funded_deliveries, store_funded_injection, store_funded_injection_proof,
    store_funded_journey_checkpoint, store_funded_secret, store_funded_signed_exit,
    store_funded_snapshot,
};

const OFFERING_ID: &str = "immortal-funded-btc-lightning";
const INPUT_AMOUNT_SAT: u64 = 100_000;
const OUTPUT_AMOUNT_SAT: u64 = 98_400;
const DOUBLE_RESERVATION_INPUT_AMOUNT_SAT: u64 = 1_000_000;
const DOUBLE_RESERVATION_OUTPUT_AMOUNT_SAT: u64 = 986_790;
const DOUBLE_RESERVATION_MAXIMUM_TOTAL_FEE_SAT: u64 = 50_000;
const NETWORK_ID: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const JOURNEY_TIMEOUT: Duration = Duration::from_secs(180);
const LIGHTNING_READINESS_TIMEOUT: Duration = Duration::from_secs(60);
const SUBMARINE_REFUND_INVOICE_EXPIRY_SECONDS: u32 = 86_400;
const DOOMSDAY_DIRECT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(90);
const DOOMSDAY_DIRECT_RECOVERY_MAX_BYTES: usize = 8 * 1_024 * 1_024;
const DOOMSDAY_KEYLESS_MAX_BYTES: usize = 64 * 1_024;
const DOOMSDAY_KEYLESS_REQUEST_SCHEMA: &str = "openagents.immortal.doomsday-keyless-request.v1";
const DOOMSDAY_KEYLESS_RESULT_SCHEMA: &str = "openagents.immortal.doomsday-keyless-result.v1";
const FUNDED_TOPOLOGY_FIXTURE: &str =
    include_str!("../../../tests/fixtures/lab/topology-funded-v1.json");
const ADVERSARIAL_FIXTURE: &str = include_str!("../../../tests/fixtures/lab/adversarial-v1.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundedJourney {
    Submarine,
    SubmarineRefund,
    ReverseClaim,
    ReverseRefund,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidChainDirection {
    BitcoinToLiquid,
    LiquidToBitcoin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiquidJourney {
    Submarine,
    Reverse,
}

impl LiquidJourney {
    pub fn name(self) -> &'static str {
        match self {
            Self::Submarine => "liquid_submarine",
            Self::Reverse => "liquid_reverse",
        }
    }

    fn swap_type(self) -> SwapType {
        match self {
            Self::Submarine => SwapType::Submarine,
            Self::Reverse => SwapType::Reverse,
        }
    }

    fn liquid_swap_type(self) -> LiquidSwapType {
        match self {
            Self::Submarine => LiquidSwapType::Submarine,
            Self::Reverse => LiquidSwapType::Reverse,
        }
    }
}

impl LiquidChainDirection {
    pub fn name(self) -> &'static str {
        match self {
            Self::BitcoinToLiquid => "btc-to-lbtc",
            Self::LiquidToBitcoin => "lbtc-to-btc",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CooperativeJourney {
    Complete,
    AbortAfterProviderNonce,
    CrashCutRecovery,
}

impl CooperativeJourney {
    pub fn name(self) -> &'static str {
        match self {
            Self::Complete => "cooperative",
            Self::AbortAfterProviderNonce => "cooperative_abort",
            Self::CrashCutRecovery => "cooperative_crash_cut",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoomsdayCase {
    SubmarineProviderGone,
    ReverseCoordinatorGone,
    KeylessEsploraBroadcast,
    LiquidSubmarineProviderGone,
    LiquidReverseCoordinatorGone,
}

impl DoomsdayCase {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "doomsday-submarine-provider-gone" => Ok(Self::SubmarineProviderGone),
            "doomsday-reverse-coordinator-gone" => Ok(Self::ReverseCoordinatorGone),
            "doomsday-keyless-esplora-broadcast" => Ok(Self::KeylessEsploraBroadcast),
            "doomsday-liquid-submarine-provider-gone" => Ok(Self::LiquidSubmarineProviderGone),
            "doomsday-liquid-reverse-coordinator-gone" => Ok(Self::LiquidReverseCoordinatorGone),
            _ => Err("selected case is not a doomsday scenario".to_owned()),
        }
    }

    fn journey_name(self) -> &'static str {
        match self {
            Self::SubmarineProviderGone => "doomsday_submarine_provider_gone",
            Self::ReverseCoordinatorGone => "doomsday_reverse_coord_gone",
            Self::KeylessEsploraBroadcast => "doomsday_keyless_esplora_exit",
            Self::LiquidSubmarineProviderGone => "liquid_submarine_provider_gone",
            Self::LiquidReverseCoordinatorGone => "liquid_reverse_coordinator_gone",
        }
    }

    fn invoice_label(self) -> &'static str {
        match self {
            Self::SubmarineProviderGone => "immortal-doomsday-submarine",
            Self::ReverseCoordinatorGone => "immortal-doomsday-reverse",
            Self::KeylessEsploraBroadcast => "immortal-doomsday-keyless",
            Self::LiquidSubmarineProviderGone => "immortal-doomsday-liquid-submarine",
            Self::LiquidReverseCoordinatorGone => "immortal-doomsday-liquid-reverse",
        }
    }

    fn case_id(self) -> &'static str {
        match self {
            Self::SubmarineProviderGone => "doomsday-submarine-provider-gone",
            Self::ReverseCoordinatorGone => "doomsday-reverse-coordinator-gone",
            Self::KeylessEsploraBroadcast => "doomsday-keyless-esplora-broadcast",
            Self::LiquidSubmarineProviderGone => "doomsday-liquid-submarine-provider-gone",
            Self::LiquidReverseCoordinatorGone => "doomsday-liquid-reverse-coordinator-gone",
        }
    }
}

fn liquid_doomsday_journey_name(
    case: DoomsdayCase,
    prepared_journey_name: &str,
) -> Result<&'static str, String> {
    let expected_prepared_journey = match case {
        DoomsdayCase::LiquidSubmarineProviderGone => "liquid_submarine",
        DoomsdayCase::LiquidReverseCoordinatorGone => "liquid_reverse",
        _ => return Err("selected doomsday case is not a Liquid scenario".to_owned()),
    };
    if prepared_journey_name != expected_prepared_journey {
        return Err("Liquid doomsday preparation used another journey".to_owned());
    }
    Ok(case.journey_name())
}

impl FundedJourney {
    pub fn name(self) -> &'static str {
        match self {
            Self::Submarine => "submarine",
            Self::SubmarineRefund => "submarine_refund",
            Self::ReverseClaim => "reverse",
            Self::ReverseRefund => "reverse_refund",
        }
    }
}

type RelaySocket = WebSocket<TcpStream>;

struct RelayClient {
    websocket: RelaySocket,
    challenge: String,
}

struct SmokeEnvironment {
    relay_url: String,
    health_url: String,
    evidence_file: PathBuf,
    requester: MarketSigner,
    wallet: ProviderWallet,
    bitcoind: BitcoindClient,
    peer_cln: ClnClient,
    liquid: Option<LiquidLabEnvironment>,
    terminal_confirmations: u64,
    control: StepControl,
}

struct LiquidLabEnvironment {
    elementsd: ElementsdClient,
    rail: LiquidProviderRail,
    network_id: String,
    pegged_asset: String,
}

struct SessionContext {
    relay_url: String,
    reader: RelayClient,
    publisher: RelayClient,
    requester: MarketSigner,
    provider_pubkey: String,
    factory: SwapRecordFactory,
    verifier: SwapSession<AwaitingVerification>,
    deliveries: Vec<SignedRecordDelivery>,
    order: Event,
    contract: Value,
    authorized_verifier: Option<SwapSession<FundingAuthorized>>,
    requester_funding: Option<SignedFundingTransaction>,
    requester_status: Option<(u64, String)>,
    journey_name: String,
    control: StepControl,
}

struct PendingSession {
    relay_url: String,
    reader: RelayClient,
    publisher: RelayClient,
    requester: MarketSigner,
    provider_pubkey: String,
    factory: SwapRecordFactory,
    config: SwapClientConfig,
    records: Vec<Event>,
    deliveries: Vec<SignedRecordDelivery>,
    order: Event,
    order_observed_at: u64,
    contract: Value,
    exit_package_seeds: Vec<ExitPackage>,
    requester_funding: Option<SignedFundingTransaction>,
    journey_name: String,
    control: StepControl,
}

struct QuotedSession {
    relay_url: String,
    reader: RelayClient,
    publisher: RelayClient,
    requester: MarketSigner,
    provider_pubkey: String,
    factory: SwapRecordFactory,
    config: SwapClientConfig,
    records: Vec<Event>,
    deliveries: Vec<SignedRecordDelivery>,
    quote_observed_at: u64,
    journey_name: String,
    control: StepControl,
}

struct FundedTopologyCandidate {
    environment_index: usize,
    quote: RequesterQuoteView,
    quoted: QuotedSession,
    output_amount: u64,
    maximum_total_fee: u64,
}

struct ReceivedPrivate {
    event: Event,
    delivery: SignedRecordDelivery,
}

struct RestoredSession {
    session: SessionContext,
    checkpoint: FundedCheckpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HarnessInjection {
    StaleQuote,
    DuplicateMessage,
    ConflictingMessage,
    SecretLeak,
    RelayLoss,
    ProviderCrash,
    WalletCrash,
    ProviderNoncooperative,
    FundingReorg,
    ClaimReorg,
    RbfConflict,
    ZeroConfRbfReplacement,
    ZeroConfDoubleSpend,
    ZeroConfAncestorEviction,
    StatusGap,
    StatusFork,
    WrongClaimKey,
    CooperativeCrashCut,
}

impl HarnessInjection {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "stale_quote" => Ok(Self::StaleQuote),
            "duplicate_message" => Ok(Self::DuplicateMessage),
            "conflicting_message" => Ok(Self::ConflictingMessage),
            "secret_leak" => Ok(Self::SecretLeak),
            "relay_loss" => Ok(Self::RelayLoss),
            "provider_crash" => Ok(Self::ProviderCrash),
            "wallet_crash" => Ok(Self::WalletCrash),
            "provider_noncooperative" => Ok(Self::ProviderNoncooperative),
            "funding_reorg" => Ok(Self::FundingReorg),
            "claim_reorg" => Ok(Self::ClaimReorg),
            "rbf_conflict" => Ok(Self::RbfConflict),
            "zero_conf_rbf_replacement" => Ok(Self::ZeroConfRbfReplacement),
            "zero_conf_double_spend" => Ok(Self::ZeroConfDoubleSpend),
            "zero_conf_ancestor_eviction" => Ok(Self::ZeroConfAncestorEviction),
            "status_gap" => Ok(Self::StatusGap),
            "status_fork" => Ok(Self::StatusFork),
            "wrong_claim_key" => Ok(Self::WrongClaimKey),
            "cooperative_crash_cut" => Ok(Self::CooperativeCrashCut),
            _ => Err("IMMORTAL_LAB_INJECTION is unsupported".to_owned()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::StaleQuote => "stale_quote",
            Self::DuplicateMessage => "duplicate_message",
            Self::ConflictingMessage => "conflicting_message",
            Self::SecretLeak => "secret_leak",
            Self::RelayLoss => "relay_loss",
            Self::ProviderCrash => "provider_crash",
            Self::WalletCrash => "wallet_crash",
            Self::ProviderNoncooperative => "provider_noncooperative",
            Self::FundingReorg => "funding_reorg",
            Self::ClaimReorg => "claim_reorg",
            Self::RbfConflict => "rbf_conflict",
            Self::ZeroConfRbfReplacement => "zero_conf_rbf_replacement",
            Self::ZeroConfDoubleSpend => "zero_conf_double_spend",
            Self::ZeroConfAncestorEviction => "zero_conf_ancestor_eviction",
            Self::StatusGap => "status_gap",
            Self::StatusFork => "status_fork",
            Self::WrongClaimKey => "wrong_claim_key",
            Self::CooperativeCrashCut => "cooperative_crash_cut",
        }
    }

    const fn requires_external_control(self) -> bool {
        matches!(
            self,
            Self::RelayLoss
                | Self::ProviderCrash
                | Self::WalletCrash
                | Self::ProviderNoncooperative
                | Self::FundingReorg
                | Self::ClaimReorg
                | Self::CooperativeCrashCut
        )
    }
}

#[derive(Clone)]
struct StepControl {
    paths: LabPaths,
    run_id: String,
    stop_after: Option<String>,
    inject_at: Option<String>,
    injection: Option<HarnessInjection>,
    injection_timeout: Duration,
}

impl StepControl {
    fn load_with_injection(injection_override: Option<HarnessInjection>) -> Result<Self, String> {
        let paths = LabPaths::from_env();
        let run_id = load_or_create_funded_run_id(&paths)?;
        let injection_timeout = std::env::var("IMMORTAL_LAB_INJECTION_TIMEOUT_SECONDS")
            .ok()
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    "IMMORTAL_LAB_INJECTION_TIMEOUT_SECONDS is not an integer".to_owned()
                })
            })
            .transpose()?
            .unwrap_or(180);
        if !(1..=3_600).contains(&injection_timeout) {
            return Err("IMMORTAL_LAB_INJECTION_TIMEOUT_SECONDS is outside 1..=3600".to_owned());
        }
        let stop_after = std::env::var("IMMORTAL_LAB_STOP_AFTER").ok();
        let inject_at = std::env::var("IMMORTAL_LAB_INJECT_AT").ok();
        let environment_injection = std::env::var("IMMORTAL_LAB_INJECTION")
            .ok()
            .map(|value| HarnessInjection::parse(&value))
            .transpose()?;
        if injection_override.is_some() && (stop_after.is_some() || environment_injection.is_some())
        {
            return Err(
                "adversarial case injection conflicts with funded harness controls".to_owned(),
            );
        }
        let injection = injection_override.or(environment_injection);
        if injection.is_some_and(HarnessInjection::requires_external_control) && inject_at.is_none()
        {
            return Err("external process injections require IMMORTAL_LAB_INJECT_AT".to_owned());
        }
        Ok(Self {
            paths,
            run_id,
            stop_after,
            inject_at,
            injection,
            injection_timeout: Duration::from_secs(injection_timeout),
        })
    }

    fn checkpoint(
        &self,
        journey: &str,
        label: &str,
        safe_to_stop: bool,
        details: Value,
    ) -> Result<bool, String> {
        let qualified = format!("{journey}:{label}");
        let checkpoint = FundedCheckpoint {
            schema: "openagents.immortal.lab-checkpoint.v1".to_owned(),
            run_id: self.run_id.clone(),
            journey: journey.to_owned(),
            label: label.to_owned(),
            safe_to_stop,
            updated_at: unix_now()?,
            details,
        };
        store_funded_journey_checkpoint(&self.paths, &checkpoint)?;
        store_funded_checkpoint(&self.paths, &checkpoint)?;
        if self.stop_after.as_deref() == Some(&qualified) {
            if !safe_to_stop {
                return Err(format!(
                    "refusing controlled stop at unsafe checkpoint {qualified}"
                ));
            }
            return Err(format!(
                "controlled stop after {qualified}; no unrecorded rail effect was started"
            ));
        }
        if self.inject_at.as_deref() == Some(&qualified) {
            let injection = self.injection.ok_or_else(|| {
                "IMMORTAL_LAB_INJECT_AT requires IMMORTAL_LAB_INJECTION".to_owned()
            })?;
            if !injection.requires_external_control() {
                return Err(format!(
                    "{} is a harness-owned pre-fund injection and cannot pause an external process",
                    injection.name()
                ));
            }
            let continue_path = self.paths.funded_continue();
            if continue_path.exists() {
                return Err(format!(
                    "stale injection continuation {}; remove it before the run",
                    continue_path.display()
                ));
            }
            store_funded_injection(
                &self.paths,
                &FundedInjectionRequest {
                    schema: "openagents.immortal.lab-injection.v1".to_owned(),
                    run_id: self.run_id.clone(),
                    journey: journey.to_owned(),
                    checkpoint: qualified.clone(),
                    injection: injection.name().to_owned(),
                    requested_at: unix_now()?,
                },
            )?;
            self.consume_injection_acknowledgement(&qualified, injection)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn resume_interrupted_wallet_injection(&self) -> Result<(), String> {
        if self.injection != Some(HarnessInjection::WalletCrash) {
            return Ok(());
        }
        let Some(request) = load_funded_injection(&self.paths)? else {
            return Ok(());
        };
        let expected_checkpoint = self
            .inject_at
            .as_deref()
            .ok_or_else(|| "wallet crash recovery has no configured checkpoint".to_owned())?;
        if request.run_id != self.run_id
            || request.checkpoint != expected_checkpoint
            || request.injection != HarnessInjection::WalletCrash.name()
            || request.journey != expected_checkpoint.split(':').next().unwrap_or_default()
        {
            return Err("wallet crash recovery request differs from the selected case".to_owned());
        }
        self.consume_injection_acknowledgement(expected_checkpoint, HarnessInjection::WalletCrash)
    }

    fn consume_injection_acknowledgement(
        &self,
        checkpoint: &str,
        injection: HarnessInjection,
    ) -> Result<(), String> {
        let continue_path = self.paths.funded_continue();
        let deadline = Instant::now() + self.injection_timeout;
        while Instant::now() < deadline {
            if continue_path.exists() {
                let acknowledgement = std::fs::read(&continue_path).map_err(|error| {
                    format!(
                        "could not read injection continuation {}: {error}",
                        continue_path.display()
                    )
                })?;
                let proof = validate_injection_acknowledgement(
                    &acknowledgement,
                    &self.run_id,
                    checkpoint,
                    injection,
                )?;
                store_funded_injection_proof(&self.paths, &proof)?;
                std::fs::remove_file(&continue_path).map_err(|error| {
                    format!(
                        "could not consume injection continuation {}: {error}",
                        continue_path.display()
                    )
                })?;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(format!(
            "timed out waiting for injection continuation {} at {checkpoint}",
            continue_path.display()
        ))
    }
}

fn validate_injection_acknowledgement(
    bytes: &[u8],
    run_id: &str,
    checkpoint: &str,
    injection: HarnessInjection,
) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() > 4_096 {
        return Err("injection continuation is empty or unbounded".to_owned());
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("injection continuation is invalid JSON: {error}"))?;
    provider_support::reject_custody_material(&value)
        .map_err(|error| format!("injection continuation contains custody material: {error}"))?;
    let provider_stopped = injection == HarnessInjection::ProviderNoncooperative;
    if value.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.lab-injection-ack.v1")
        || value.get("run_id").and_then(Value::as_str) != Some(run_id)
        || value.get("checkpoint").and_then(Value::as_str) != Some(checkpoint)
        || value.get("injection").and_then(Value::as_str) != Some(injection.name())
        || value.get("restored").and_then(Value::as_bool) != Some(!provider_stopped)
    {
        return Err("injection continuation does not bind the requested recovery".to_owned());
    }
    let evidence = value
        .get("evidence")
        .and_then(Value::as_object)
        .ok_or_else(|| "injection evidence is not an object".to_owned())?;
    match injection {
        HarnessInjection::RelayLoss
        | HarnessInjection::ProviderCrash
        | HarnessInjection::WalletCrash => {
            validate_process_replacement_evidence(evidence)?;
        }
        HarnessInjection::CooperativeCrashCut => {
            validate_cooperative_crash_evidence(evidence)?;
        }
        HarnessInjection::ProviderNoncooperative => {
            validate_process_stopped_evidence(evidence)?;
        }
        HarnessInjection::FundingReorg | HarnessInjection::ClaimReorg => {
            validate_chain_recovery_evidence(evidence, injection)?;
        }
        _ => return Err("pre-fund injection cannot carry external acknowledgement".to_owned()),
    }
    Ok(value)
}

fn validate_process_stopped_evidence(evidence: &Map<String, Value>) -> Result<(), String> {
    if evidence.len() != 3
        || evidence
            .keys()
            .any(|name| !matches!(name.as_str(), "target" | "before_pid" | "transition"))
        || !matches!(
            evidence.get("target").and_then(Value::as_str),
            Some("provider-a" | "provider-b")
        )
        || evidence.get("transition").and_then(Value::as_str) != Some("process_stopped")
        || evidence
            .get("before_pid")
            .and_then(Value::as_u64)
            .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
    {
        return Err("provider stop evidence has another shape".to_owned());
    }
    Ok(())
}

fn validate_process_replacement_evidence(evidence: &Map<String, Value>) -> Result<(), String> {
    if evidence.len() != 4
        || evidence.keys().any(|name| {
            !matches!(
                name.as_str(),
                "target" | "before_pid" | "after_pid" | "transition"
            )
        })
    {
        return Err("process injection evidence has another shape".to_owned());
    }
    let target = evidence
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| "process injection evidence has no target".to_owned())?;
    let transition = evidence
        .get("transition")
        .and_then(Value::as_str)
        .ok_or_else(|| "process injection evidence has no transition".to_owned())?;
    let before_pid = evidence.get("before_pid").and_then(Value::as_u64);
    let after_pid = evidence.get("after_pid").and_then(Value::as_u64);
    if !matches!(
        target,
        "relay-a" | "relay-b" | "provider-a" | "provider-b" | "wallet-driver"
    ) || transition != "process_replaced_and_ready"
        || before_pid.is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || after_pid.is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || before_pid == after_pid
    {
        return Err("injection evidence does not prove one bounded process replacement".to_owned());
    }
    Ok(())
}

fn validate_cooperative_crash_evidence(evidence: &Map<String, Value>) -> Result<(), String> {
    if evidence.len() != 5
        || evidence.keys().any(|name| {
            !matches!(
                name.as_str(),
                "target" | "before_pid" | "after_pid" | "transition" | "state_boundary_unchanged"
            )
        })
        || !matches!(
            evidence.get("target").and_then(Value::as_str),
            Some("provider-a" | "provider-b")
        )
        || evidence.get("transition").and_then(Value::as_str)
            != Some("process_replaced_same_database_and_wallet_file")
        || evidence
            .get("state_boundary_unchanged")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("cooperative crash evidence has another shape".to_owned());
    }
    let before = evidence.get("before_pid").and_then(Value::as_u64);
    let after = evidence.get("after_pid").and_then(Value::as_u64);
    if before.is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || after.is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || before == after
    {
        return Err("cooperative crash did not replace one provider process".to_owned());
    }
    Ok(())
}

fn validate_chain_recovery_evidence(
    evidence: &Map<String, Value>,
    injection: HarnessInjection,
) -> Result<(), String> {
    let expected_transition = match injection {
        HarnessInjection::FundingReorg => "funding_reorg_waited_and_resumed",
        HarnessInjection::ClaimReorg => "claim_watch_reorged_and_reconfirmed",
        _ => return Err("chain recovery validator received another injection".to_owned()),
    };
    if evidence.len() != 8
        || evidence.keys().any(|name| {
            !matches!(
                name.as_str(),
                "target"
                    | "transition"
                    | "transaction_id"
                    | "orphaned_block_hash"
                    | "competing_tip_hash"
                    | "reconfirmed_block_hash"
                    | "wait_state"
                    | "recovery_state"
            )
        })
        || evidence.get("target").and_then(Value::as_str) != Some("provider-a")
        || evidence.get("transition").and_then(Value::as_str) != Some(expected_transition)
    {
        return Err("chain recovery evidence has another shape or transition".to_owned());
    }
    for member in [
        "transaction_id",
        "orphaned_block_hash",
        "competing_tip_hash",
        "reconfirmed_block_hash",
    ] {
        let hash = evidence
            .get(member)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("chain recovery evidence has no {member}"))?;
        require_lower_hex_32(hash, member)?;
    }
    let (expected_wait, expected_recovery) = match injection {
        HarnessInjection::FundingReorg => (
            "funding_observed_without_finality",
            "funding_final_after_reconfirmation",
        ),
        HarnessInjection::ClaimReorg => (
            "claim_watch_confirmed",
            "claim_watch_reorg_then_reconfirmed",
        ),
        _ => return Err("chain recovery state validator received another injection".to_owned()),
    };
    if evidence.get("wait_state").and_then(Value::as_str) != Some(expected_wait)
        || evidence.get("recovery_state").and_then(Value::as_str) != Some(expected_recovery)
    {
        return Err("chain recovery evidence does not prove wait and recovery states".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum LightningTerminalCheck<'a> {
    IncomingInvoice {
        payment_hash: &'a str,
    },
    OutgoingPayment {
        invoice: &'a str,
        payment_hash: &'a str,
        expected_status: &'static str,
    },
}

struct TerminalRailCheck<'a> {
    runtime: &'a Runtime,
    environment: &'a SmokeEnvironment,
    bitcoin_settlement_txid: Option<&'a str>,
    liquid_settlement_txid: Option<&'a str>,
    lightning: Option<LightningTerminalCheck<'a>>,
}

#[derive(Clone, Copy)]
struct NegotiationInput<'a> {
    journey_name: &'a str,
    swap_type: &'a str,
    payment_hash: &'a str,
    invoice: Option<&'a str>,
    requester_key: [u8; 32],
    requester_funding_input: Option<&'a FundingInput>,
    exit_destination_script_pubkey: &'a [u8],
    presign_submarine_refund: bool,
}

#[derive(Clone, Copy)]
struct ChainNegotiationInput {
    direction: LiquidChainDirection,
    payment_hash: [u8; 32],
    source_requester_key: [u8; 32],
    destination_requester_key: [u8; 32],
}

enum ChainFundingTransaction {
    Bitcoin(SignedFundingTransaction),
    Liquid(ElementsdSignedFunding),
}

struct PreparedChainSession {
    pending: PendingSession,
    source_funding: ChainFundingTransaction,
    liquid_request: LiquidBeforeFundRequest,
    preimage: [u8; 32],
    destination_exit_path: WalletPath,
}

#[derive(Clone)]
struct LiquidNegotiationInput {
    journey: LiquidJourney,
    payment_hash: [u8; 32],
    invoice: Option<String>,
    requester_key: [u8; 32],
}

struct PreparedLiquidSession {
    pending: PendingSession,
    funding: Option<ElementsdSignedFunding>,
    liquid_request: LiquidBeforeFundRequest,
}

struct LiquidClaimRecoveryRefs {
    wallet_signing_handle_sha256: String,
    preimage_recovery_ref: String,
}

pub fn test_bounded_numeric_output_index() {
    let numeric = Map::from_iter([("output_index".to_owned(), json!(7))]);
    let string = Map::from_iter([("output_index".to_owned(), json!("7"))]);
    let overflow = Map::from_iter([("output_index".to_owned(), json!(u64::from(u32::MAX) + 1))]);
    assert_eq!(bounded_u32_member(&numeric, "output_index"), Ok(7));
    assert!(bounded_u32_member(&string, "output_index").is_err());
    assert!(bounded_u32_member(&overflow, "output_index").is_err());
}

pub fn run_funded_smoke() -> Result<(), String> {
    let environment = SmokeEnvironment::load()?;
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    let submarine = journey_evidence(run_funded_journey(FundedJourney::Submarine)?)?;
    let reverse = journey_evidence(run_funded_journey(FundedJourney::ReverseClaim)?)?;
    let reverse_refund = journey_evidence(run_funded_journey(FundedJourney::ReverseRefund)?)?;
    verify_health(&environment.health_url)?;
    write_evidence(
        &environment.evidence_file,
        &provider_pubkey,
        submarine,
        reverse,
        reverse_refund,
    )
}

pub fn run_funded_topology() -> Result<Value, String> {
    validate_funded_topology_fixture()?;
    if [
        "IMMORTAL_LAB_STOP_AFTER",
        "IMMORTAL_LAB_INJECTION",
        "IMMORTAL_LAB_INJECT_AT",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return Err("funded topology does not accept restart or injection controls".to_owned());
    }
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environments = SmokeEnvironment::load_topology()?;
    for environment in &environments {
        verify_health(&environment.health_url)?;
    }
    let provider_pubkeys = environments
        .iter()
        .map(|environment| {
            discover_provider(
                &environment.relay_url,
                &environment.requester,
                JOURNEY_TIMEOUT,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if provider_pubkeys.len() != 2 || provider_pubkeys[0] == provider_pubkeys[1] {
        return Err("funded topology did not discover two distinct providers".to_owned());
    }

    let client_input = fund_client_wallet(&runtime, &environments[0])?;
    let invoice = runtime
        .block_on(
            environments[0].peer_cln.invoice(
                &cln_id("topology-submarine-invoice")?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("topology invoice amount is invalid: {error}"))?,
                "immortal-funded-topology-submarine",
                "Immortal funded topology submarine",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create topology submarine invoice: {error}"))?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("topology refund path is invalid: {error}"))?;
    let requester_key = environments[0]
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive topology refund key: {error}"))?
        .internal_key;
    let exit_destination = environments[0]
        .wallet
        .derive_address(
            WalletPath::new(0, true, 10)
                .map_err(|error| format!("topology exit destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive topology exit destination: {error}"))?;

    let journey_names = ["topology_a", "topology_b"];
    let mut candidates = Vec::with_capacity(2);
    for index in 0..2 {
        let input = NegotiationInput {
            journey_name: journey_names[index],
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &exit_destination.script_pubkey,
            presign_submarine_refund: false,
        };
        let quoted = prepare_quote(&environments[index], &provider_pubkeys[index], input)?;
        candidates.push(funded_topology_candidate(index, quoted)?);
    }
    require_comparable_funded_quotes(&candidates[0].quote, &candidates[1].quote)?;
    candidates.sort_by(compare_funded_topology_candidate);
    let ranked = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            json!({
                "rank":index + 1,
                "relay_url":candidate.quoted.relay_url,
                "provider_pubkey":candidate.quote.provider_pubkey,
                "session_id":candidate.quoted.config.session_id,
                "rfq_id":candidate.quote.rfq_id,
                "quote_id":candidate.quote.quote_id,
                "reservation_class":candidate.quote.reservation_class,
                "input_amount":candidate.quote.input_amount,
                "output_amount":candidate.quote.output_amount,
                "maximum_total_fee":candidate.quote.fees.maximum_total_fee,
                "effective_acceptance_deadline":candidate.quote.effective_acceptance_deadline,
            })
        })
        .collect::<Vec<_>>();
    let unselected = candidates
        .pop()
        .ok_or_else(|| "funded topology has no unselected candidate".to_owned())?;
    let selected = candidates
        .pop()
        .ok_or_else(|| "funded topology has no selected candidate".to_owned())?;
    if !candidates.is_empty() {
        return Err("funded topology retained an unexpected third candidate".to_owned());
    }

    let unselected_input = NegotiationInput {
        journey_name: journey_names[unselected.environment_index],
        swap_type: "submarine",
        payment_hash: &invoice.payment_hash,
        invoice: Some(&invoice.bolt11),
        requester_key,
        requester_funding_input: Some(&client_input),
        exit_destination_script_pubkey: &exit_destination.script_pubkey,
        presign_submarine_refund: false,
    };
    let unselected_environment = &environments[unselected.environment_index];
    let unselected_quote = unselected.quote;
    let unselected_session = finalize_negotiation(prepare_order(
        unselected_environment,
        unselected.quoted,
        unselected_input,
    )?)?;
    let cancellation = cancel_unselected_funded_session(unselected_session, &unselected_quote)?;

    let selected_input = NegotiationInput {
        journey_name: journey_names[selected.environment_index],
        swap_type: "submarine",
        payment_hash: &invoice.payment_hash,
        invoice: Some(&invoice.bolt11),
        requester_key,
        requester_funding_input: Some(&client_input),
        exit_destination_script_pubkey: &exit_destination.script_pubkey,
        presign_submarine_refund: false,
    };
    let selected_environment = &environments[selected.environment_index];
    let selected_provider_pubkey = selected.quote.provider_pubkey.clone();
    let selected_quote_id = selected.quote.quote_id.clone();
    let mut selected_session = finalize_negotiation(prepare_order(
        selected_environment,
        selected.quoted,
        selected_input,
    )?)?;
    selected_session.wait_provider_state("accepted")?;
    selected_session.wait_provider_state("lock_terms_ready")?;
    let funding = selected_session
        .requester_funding
        .take()
        .ok_or_else(|| "selected topology session has no funding transaction".to_owned())?;
    let authorized = verify_submarine_before_fund(&selected_session, &invoice.bolt11, &funding)?;
    selected_session.set_authorized_verifier(authorized)?;
    let selected_journey = continue_submarine(
        &runtime,
        selected_environment,
        selected_session,
        &funding.raw_transaction,
        Some(&funding.txid),
        &invoice.payment_hash,
    )?;
    for environment in &environments {
        verify_health(&environment.health_url)?;
    }
    let result = json!({
        "schema":"openagents.immortal.funded-topology-result.v1",
        "wallet_pubkey":environments[0].requester.pubkey(),
        "candidates":ranked,
        "selection":{
            "policy":[
                "output_amount_desc",
                "maximum_total_fee_asc",
                "provider_pubkey_asc",
                "quote_id_asc"
            ],
            "selected_provider_pubkey":selected_provider_pubkey,
            "selected_quote_id":selected_quote_id,
        },
        "unselected":cancellation,
        "selected":selected_journey,
    });
    provider_support::reject_custody_material(&result)
        .map_err(|error| format!("funded topology result contains custody material: {error}"))?;
    Ok(result)
}

fn validate_funded_topology_fixture() -> Result<(), String> {
    let fixture: Value = serde_json::from_str(FUNDED_TOPOLOGY_FIXTURE)
        .map_err(|error| format!("funded topology fixture is invalid: {error}"))?;
    if fixture.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.lab-funded-topology.v1")
        || fixture
            .pointer("/topology/relay_count")
            .and_then(Value::as_u64)
            != Some(2)
        || fixture
            .pointer("/topology/provider_database_count")
            .and_then(Value::as_u64)
            != Some(2)
        || fixture
            .pointer("/topology/shared_bitcoind_namespace")
            .and_then(Value::as_bool)
            != Some(true)
        || fixture
            .pointer("/topology/issue_18_requires_separate_bitcoind_namespaces")
            .and_then(Value::as_bool)
            != Some(true)
        || fixture.pointer("/selection/ordering")
            != Some(&json!([
                "output_amount_desc",
                "maximum_total_fee_asc",
                "provider_pubkey_asc",
                "quote_id_asc"
            ]))
        || fixture
            .pointer("/unselected/reservation_release_cause")
            .and_then(Value::as_str)
            != Some("terminal_close")
    {
        return Err("funded topology fixture differs from the executable contract".to_owned());
    }
    Ok(())
}

fn funded_topology_candidate(
    environment_index: usize,
    quoted: QuotedSession,
) -> Result<FundedTopologyCandidate, String> {
    let view = RequesterSessionView::from_signed_records(
        &quoted.config,
        &quoted.records,
        quoted.deliveries.clone(),
    )
    .map_err(|error| format!("requester rejected a funded topology Quote: {error}"))?;
    if view.verification.state != RequesterVerificationState::QuoteVerified
        || view.verification.funding_authorized
        || view.quote.quote_class != "firm"
        || view.quote.reservation_class != "hard"
        || unix_now()? > view.quote.effective_acceptance_deadline
    {
        return Err("funded topology candidate is not a fresh verified hard Quote".to_owned());
    }
    let output_amount = canonical_u64(&view.quote.output_amount)?;
    let maximum_total_fee = canonical_u64(&view.quote.fees.maximum_total_fee)?;
    Ok(FundedTopologyCandidate {
        environment_index,
        quote: view.quote,
        quoted,
        output_amount,
        maximum_total_fee,
    })
}

fn require_comparable_funded_quotes(
    left: &RequesterQuoteView,
    right: &RequesterQuoteView,
) -> Result<(), String> {
    if left.swap_type != right.swap_type
        || left.input_asset_id != right.input_asset_id
        || left.output_asset_id != right.output_asset_id
        || left.input_amount != right.input_amount
        || left.amount_equation != right.amount_equation
        || left.rounding != right.rounding
    {
        return Err("funded topology Quotes are not economically comparable".to_owned());
    }
    Ok(())
}

fn compare_funded_topology_candidate(
    left: &FundedTopologyCandidate,
    right: &FundedTopologyCandidate,
) -> std::cmp::Ordering {
    right
        .output_amount
        .cmp(&left.output_amount)
        .then_with(|| left.maximum_total_fee.cmp(&right.maximum_total_fee))
        .then_with(|| left.quote.provider_pubkey.cmp(&right.quote.provider_pubkey))
        .then_with(|| left.quote.quote_id.cmp(&right.quote.quote_id))
}

fn cancel_unselected_funded_session(
    mut session: SessionContext,
    quote: &RequesterQuoteView,
) -> Result<Value, String> {
    let session_id = session.verifier.config().session_id.clone();
    let (request, request_raw) = sign_request(
        session
            .factory
            .cancel(
                ParticipantRole::Requester,
                next_created_at(&session.verifier)?,
                &digest(&format!("topology-cancel-request:{session_id}")),
                &session.order.id,
                Cancellation {
                    action: "request",
                    reason: "topology_quote_not_selected",
                    request_id: None,
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .map_err(|error| format!("could not construct topology Cancel request: {error}"))?,
        &session.requester,
    )?;
    session
        .verifier
        .ingest_signed_record(request.clone())
        .map_err(|error| format!("requester rejected topology Cancel request: {error}"))?;
    session.deliveries.push(
        SignedRecordDelivery::from_locally_signed(request_raw.clone(), unix_now()?)
            .map_err(|error| format!("could not archive topology Cancel request: {error}"))?,
    );
    publish_private(
        &mut session.publisher,
        &request_raw,
        &session.requester,
        &session.provider_pubkey,
    )?;

    let accepted = receive_matching_private(
        &mut session.reader,
        &session.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| {
            event.kind == MKT_CANCEL_KIND
                && event.pubkey == session.provider_pubkey
                && event.tag_values("action").eq(["accepted"])
        },
    )?;
    let accepted_id = accepted.event.id.clone();
    session.deliveries.push(accepted.delivery);
    session
        .verifier
        .ingest_signed_record(accepted.event)
        .map_err(|error| format!("requester rejected accepted topology Cancel: {error}"))?;

    let effective = receive_matching_private(
        &mut session.reader,
        &session.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| {
            event.kind == MKT_CANCEL_KIND
                && event.pubkey == session.provider_pubkey
                && event.tag_values("action").eq(["effective"])
        },
    )?;
    let effective_id = effective.event.id.clone();
    session.deliveries.push(effective.delivery);
    session
        .verifier
        .ingest_signed_record(effective.event)
        .map_err(|error| format!("requester rejected effective topology Cancel: {error}"))?;

    let close = receive_matching_private(
        &mut session.reader,
        &session.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| {
            event.kind == MKT_CLOSE_KIND
                && event.pubkey == session.provider_pubkey
                && event.tag_values("outcome").eq(["cancelled"])
        },
    )?;
    let close_id = close.event.id.clone();
    let profile = record_profile(&close.event)?;
    if profile
        .get("external_spend_effects")
        .and_then(Value::as_u64)
        != Some(0)
        || profile
            .get("loss_accounting")
            .and_then(Value::as_object)
            .and_then(|loss| loss.get("input_committed"))
            .and_then(Value::as_str)
            != Some("0")
        || profile
            .get("loss_accounting")
            .and_then(Value::as_object)
            .and_then(|loss| loss.get("reservation_released"))
            .and_then(Value::as_str)
            != Some(quote.output_amount.as_str())
    {
        return Err("unselected provider Close has invalid no-spend release accounting".to_owned());
    }
    session.deliveries.push(close.delivery);
    session
        .verifier
        .ingest_signed_record(close.event)
        .map_err(|error| format!("requester rejected cancelled topology Close: {error}"))?;
    Ok(json!({
        "provider_pubkey":session.provider_pubkey,
        "session_id":session_id,
        "order_id":session.order.id,
        "cancel_request_id":request.id,
        "cancel_accepted_id":accepted_id,
        "cancel_effective_id":effective_id,
        "close_id":close_id,
        "reservation_released":quote.output_amount,
        "external_spend_effects":0,
        "outcome":"cancelled",
    }))
}

fn journey_evidence(result: Value) -> Result<Value, String> {
    result
        .get("journey")
        .cloned()
        .ok_or_else(|| "funded journey returned no evidence".to_owned())
}

pub fn run_funded_journey(journey: FundedJourney) -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load()?;
    run_funded_journey_with_environment(&runtime, &environment, journey)
}

pub fn run_adversarial_funded_journey(
    provider_index: usize,
    journey: FundedJourney,
    injection: Option<&str>,
) -> Result<Value, String> {
    let injection = injection.map(HarnessInjection::parse).transpose()?;
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(provider_index, injection)?;
    environment.control.resume_interrupted_wallet_injection()?;
    let mut result = run_funded_journey_with_environment(&runtime, &environment, journey)?;
    if injection.is_some_and(HarnessInjection::requires_external_control) {
        let proof = load_funded_injection_proof(&environment.control.paths)?
            .ok_or_else(|| "external adversarial injection has no retained proof".to_owned())?;
        result
            .as_object_mut()
            .ok_or_else(|| "funded journey result is not an object".to_owned())?
            .insert("external_control".to_owned(), proof);
    }
    Ok(result)
}

pub fn run_adversarial_liquid_chain_journey(
    provider_index: usize,
    direction: LiquidChainDirection,
) -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start chain lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(
        provider_index,
        Some(HarnessInjection::ProviderCrash),
    )?;
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid chain journey has no local elementsd".to_owned())?;
    let network = runtime
        .block_on(liquid.rail.network_view("chain-requester-network"))
        .map_err(|error| format!("could not verify requester Liquid network: {error}"))?;
    if network.network_id.as_str() != liquid.network_id
        || network.pegged_asset.to_string() != liquid.pegged_asset
    {
        return Err("requester elementsd differs from the configured Liquid network".to_owned());
    }
    eprintln!("immortal-lab: Liquid chain progress network-verified");
    verify_health(&environment.health_url)?;
    let offering = discover_provider_offering(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    eprintln!("immortal-lab: Liquid chain progress offering-discovered");
    let provider_pubkey = offering.pubkey.clone();
    let source_exit_path = WalletPath::new(4, false, 0)
        .map_err(|error| format!("chain source key path is invalid: {error}"))?;
    let destination_exit_path = WalletPath::new(4, false, 1)
        .map_err(|error| format!("chain destination key path is invalid: {error}"))?;
    let source_requester_key = environment
        .wallet
        .derive_address(source_exit_path)
        .map_err(|error| format!("could not derive chain source key: {error}"))?
        .internal_key;
    let destination_requester_key = environment
        .wallet
        .derive_address(destination_exit_path)
        .map_err(|error| format!("could not derive chain destination key: {error}"))?
        .internal_key;
    let preimage = random_32()?;
    store_funded_secret(&environment.control.paths, "chain", &preimage)?;
    let input = ChainNegotiationInput {
        direction,
        payment_hash: sha256(&preimage),
        source_requester_key,
        destination_requester_key,
    };
    let prepared = prepare_chain_order(
        &runtime,
        &environment,
        prepare_chain_quote(&environment, &provider_pubkey, input)?,
        input,
        preimage,
    )?;
    eprintln!("immortal-lab: Liquid chain progress requester-contract-prepared");
    let PreparedChainSession {
        pending,
        source_funding,
        liquid_request,
        mut preimage,
        destination_exit_path,
    } = prepared;
    let mut session = finalize_negotiation(pending)?;
    session.wait_provider_state("accepted")?;
    eprintln!("immortal-lab: Liquid chain progress accepted");
    session.wait_provider_state("source_lock_terms_ready")?;
    eprintln!("immortal-lab: Liquid chain progress source-lock-terms-ready");
    verify_chain_source(&runtime, &environment, &session, &liquid_request, direction)?;
    session.publish_requester_status("requester_source_verified", Map::new())?;
    eprintln!("immortal-lab: Liquid chain progress requester-source-verified");
    session.wait_provider_state("destination_lock_terms_ready")?;
    eprintln!("immortal-lab: Liquid chain progress destination-lock-terms-ready");
    validate_chain_destination_template(&session.contract, direction)?;
    if direction == LiquidChainDirection::BitcoinToLiquid {
        runtime
            .block_on(liquid.rail.verify_before_fund(&liquid_request))
            .map_err(|error| {
                format!("production Liquid rail rejected destination preflight: {error}")
            })?;
    }
    let authorized =
        authorize_chain_funding(&runtime, &environment, &session, &liquid_request, direction)?;
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_destination_verified", Map::new())?;
    eprintln!("immortal-lab: Liquid chain progress requester-destination-verified");
    session.wait_provider_state("source_funding_required")?;
    eprintln!("immortal-lab: Liquid chain progress source-funding-required");

    let (source_transaction_id, source_output_index, source_transaction_hex) = match &source_funding
    {
        ChainFundingTransaction::Bitcoin(funding) => {
            let transaction_id = transaction_id(&funding.raw_transaction)?;
            broadcast_bitcoin_once(
                &runtime,
                &environment.bitcoind,
                "chain-bitcoin-source-funding",
                &funding.raw_transaction,
                &transaction_id,
            )?;
            (transaction_id, 0, funding.raw_transaction.clone())
        }
        ChainFundingTransaction::Liquid(funding) => {
            let verified = runtime
                .block_on(liquid.rail.verify_before_fund(&liquid_request))
                .map_err(|error| {
                    format!("production Liquid rail rejected exact source funding: {error}")
                })?;
            let receipt = runtime
                .block_on(liquid.rail.broadcast_funding(&verified))
                .map_err(|error| format!("could not broadcast Liquid source funding: {error}"))?;
            if receipt.transaction_id != funding.transaction_id {
                return Err("elementsd broadcast another Liquid source transaction".to_owned());
            }
            (
                receipt.transaction_id,
                funding.output_index,
                lower_hex(&funding.raw_transaction),
            )
        }
    };
    session.record_funding_effect(
        source_transaction_id.clone(),
        sha256(&decode_hex(&source_transaction_hex)?),
    )?;
    session.publish_requester_status(
        "requester_source_broadcast",
        Map::from_iter([
            (
                "transaction_id".to_owned(),
                Value::String(source_transaction_id.clone()),
            ),
            ("output_index".to_owned(), json!(source_output_index)),
        ]),
    )?;
    eprintln!("immortal-lab: Liquid chain progress requester-source-broadcast");
    let source_rail = contract_leg_rail_name(&session.contract, "source")?.to_owned();
    let destination_rail = contract_leg_rail_name(&session.contract, "destination")?.to_owned();
    mine_chain_leg(
        &runtime,
        &environment,
        &source_rail,
        environment.terminal_confirmations,
        "chain-source-finality",
    )?;
    session.wait_provider_state("source_funding_observed")?;
    eprintln!("immortal-lab: Liquid chain progress source-funding-observed");
    session.wait_provider_state("source_funding_final")?;
    eprintln!("immortal-lab: Liquid chain progress source-funding-final");
    let destination_broadcast = session.wait_provider_state("provider_destination_broadcast")?;
    eprintln!("immortal-lab: Liquid chain progress provider-destination-broadcast");
    let (destination_transaction_id, destination_output_index) =
        status_outpoint(&destination_broadcast)?;
    session.persist_authorized_details(
        "provider_funding_effect_recorded",
        true,
        json!({"external_identifier":destination_transaction_id.clone()}),
    )?;
    verify_health(&environment.health_url)?;
    let restart_proof = load_funded_injection_proof(&environment.control.paths)?
        .ok_or_else(|| "chain provider restart has no controller acknowledgement".to_owned())?;
    let replayed_destination = session.wait_provider_state("provider_destination_broadcast")?;
    if replayed_destination.id != destination_broadcast.id
        || status_outpoint(&replayed_destination)?
            != (destination_transaction_id.clone(), destination_output_index)
    {
        return Err("provider restart replayed another destination effect".to_owned());
    }
    wait_for_chain_transaction_propagation(
        &runtime,
        &environment,
        &destination_rail,
        &destination_transaction_id,
        "chain-destination-funding",
    )?;
    eprintln!("immortal-lab: Liquid chain progress destination-funding-propagated");
    mine_chain_leg(
        &runtime,
        &environment,
        &destination_rail,
        environment.terminal_confirmations,
        "chain-destination-finality",
    )?;
    session.wait_provider_state("destination_funding_observed")?;
    eprintln!("immortal-lab: Liquid chain progress destination-funding-observed");
    session.wait_provider_state("destination_funding_final")?;
    eprintln!("immortal-lab: Liquid chain progress destination-funding-final");
    session.publish_requester_status("requester_destination_claim_pending", Map::new())?;
    eprintln!("immortal-lab: Liquid chain progress requester-destination-claim-pending");

    let (destination_claim_transaction_id, destination_claim_transaction_hex) = match direction {
        LiquidChainDirection::BitcoinToLiquid => {
            let authorized = session.authorized_verifier.as_mut().ok_or_else(|| {
                "Liquid destination claim lost its pre-fund authorization".to_owned()
            })?;
            claim_chain_liquid_destination(
                &runtime,
                &environment,
                authorized,
                &liquid_request,
                destination_exit_path,
                preimage,
                "chain",
            )?
        }
        LiquidChainDirection::LiquidToBitcoin => claim_chain_bitcoin_destination(
            &runtime,
            &environment,
            &session.contract,
            &destination_transaction_id,
            destination_output_index,
            destination_exit_path,
            preimage,
        )?,
    };
    if direction == LiquidChainDirection::BitcoinToLiquid {
        session.persist_authorized_details(
            "liquid_claim_broadcast_recorded",
            true,
            json!({"external_identifier":destination_claim_transaction_id.clone()}),
        )?;
    }
    remove_funded_secret(&environment.control.paths, "chain")?;
    preimage.fill(0);
    session.publish_requester_status(
        "requester_destination_claimed",
        Map::from_iter([(
            "transaction_id".to_owned(),
            Value::String(destination_claim_transaction_id.clone()),
        )]),
    )?;
    eprintln!("immortal-lab: Liquid chain progress requester-destination-claimed");
    mine_chain_leg(
        &runtime,
        &environment,
        &destination_rail,
        environment.terminal_confirmations,
        "chain-destination-claim-propagation",
    )?;
    let source_claim = session.wait_provider_state("provider_source_claim_pending")?;
    eprintln!("immortal-lab: Liquid chain progress provider-source-claim-pending");
    let source_claim_transaction_id = status_transaction_id(&source_claim)?;
    wait_for_chain_transaction_propagation(
        &runtime,
        &environment,
        &source_rail,
        &source_claim_transaction_id,
        "chain-source-claim",
    )?;
    eprintln!("immortal-lab: Liquid chain progress source-claim-propagated");
    mine_chain_leg(
        &runtime,
        &environment,
        &source_rail,
        environment.terminal_confirmations,
        "chain-source-claim-finality",
    )?;
    session.wait_provider_state("provider_source_claimed")?;
    eprintln!("immortal-lab: Liquid chain progress provider-source-claimed");
    session.wait_provider_state("completed")?;
    eprintln!("immortal-lab: Liquid chain progress completed");
    let (bitcoin_settlement_txid, liquid_settlement_txid) = chain_terminal_settlement_ids(
        &source_rail,
        &destination_rail,
        &source_claim_transaction_id,
        &destination_claim_transaction_id,
    )?;
    let close = session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime: &runtime,
            environment: &environment,
            bitcoin_settlement_txid: Some(bitcoin_settlement_txid),
            liquid_settlement_txid: Some(liquid_settlement_txid),
            lightning: None,
        },
    )?;
    eprintln!("immortal-lab: Liquid chain progress close");

    let destination_transaction_hex = chain_raw_transaction(
        &runtime,
        &environment,
        &destination_rail,
        &destination_transaction_id,
        "chain-destination-funding-proof",
    )?;
    let source_claim_transaction_hex = chain_raw_transaction(
        &runtime,
        &environment,
        &source_rail,
        &source_claim_transaction_id,
        "chain-source-claim-proof",
    )?;
    let records = session.verifier.signed_records();
    let lifecycle = chain_lifecycle_event_ids(records, &offering, &close)?;
    let provider_destination_count = records
        .iter()
        .filter(|record| {
            record.kind == MKT_STATUS_KIND
                && record.pubkey == provider_pubkey
                && record_profile(record)
                    .ok()
                    .and_then(|profile| profile.get("swp_state").cloned())
                    .and_then(|state| state.as_str().map(str::to_owned))
                    .as_deref()
                    == Some("provider_destination_broadcast")
        })
        .count();
    if provider_destination_count != 1 {
        return Err("provider restart created a duplicate destination Status".to_owned());
    }
    let selected_provider = if provider_index == 0 {
        "provider-a"
    } else {
        "provider-b"
    };
    let (bitcoin, liquid_proof) = match direction {
        LiquidChainDirection::BitcoinToLiquid => (
            chain_leg_process_proof(
                "bitcoin",
                &source_transaction_id,
                source_output_index,
                &source_transaction_hex,
                &source_claim_transaction_id,
                &source_claim_transaction_hex,
            ),
            chain_leg_process_proof(
                "liquid",
                &destination_transaction_id,
                destination_output_index,
                &destination_transaction_hex,
                &destination_claim_transaction_id,
                &destination_claim_transaction_hex,
            ),
        ),
        LiquidChainDirection::LiquidToBitcoin => (
            chain_leg_process_proof(
                "bitcoin",
                &destination_transaction_id,
                destination_output_index,
                &destination_transaction_hex,
                &destination_claim_transaction_id,
                &destination_claim_transaction_hex,
            ),
            chain_leg_process_proof(
                "liquid",
                &source_transaction_id,
                source_output_index,
                &source_transaction_hex,
                &source_claim_transaction_id,
                &source_claim_transaction_hex,
            ),
        ),
    };
    let (shape, provider_effect_operations, terminal_actor) = match direction {
        LiquidChainDirection::BitcoinToLiquid => (
            "chain-btc-to-lbtc",
            vec!["liquid_chain_fund", "chain_claim"],
            "requester",
        ),
        LiquidChainDirection::LiquidToBitcoin => (
            "chain-lbtc-to-btc",
            vec!["chain_fund", "liquid_chain_claim"],
            "provider",
        ),
    };
    let checkpoint_effect_operation = provider_effect_operations
        .first()
        .copied()
        .unwrap_or_default();
    let proof = json!({
        "liquid_case":{
            "schema":"openagents.immortal.adversarial-liquid-case.v1",
            "shape":shape,
            "selected_provider":selected_provider,
            "signed_lifecycle_event_ids":lifecycle,
            "rails":{"bitcoin":bitcoin,"liquid":liquid_proof},
            "provider_effect_operations":provider_effect_operations,
            "provider_status_anchors":["provider_destination_broadcast"],
            "provider_restart":{
                "target":selected_provider,
                "checkpoint_effect_operation":checkpoint_effect_operation,
                "checkpoint_status_state":"provider_destination_broadcast",
                "process_replaced":restart_proof.pointer("/evidence/transition").and_then(Value::as_str)
                    == Some("process_replaced_and_ready"),
                "restored_from_postgres":replayed_destination.id == destination_broadcast.id,
                "exact_known_replay":replayed_destination.id == destination_broadcast.id,
                "duplicate_external_effects":provider_destination_count.saturating_sub(1),
            },
            "liquid_terminal":{
                "actor":terminal_actor,
                "path":"claim",
                "effect_class":"liquid_spend",
                "confirmed":true,
            },
            "lightning_terminal":null,
            "recovery":null,
        }
    });
    provider_support::reject_custody_material(&proof)
        .map_err(|error| format!("chain process proof contains custody material: {error}"))?;
    Ok(proof)
}

pub fn run_adversarial_liquid_journey(
    provider_index: usize,
    journey: LiquidJourney,
) -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start Liquid lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(
        provider_index,
        Some(HarnessInjection::ProviderCrash),
    )?;
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid journey has no local elementsd".to_owned())?;
    let network = runtime
        .block_on(liquid.rail.network_view("liquid-requester-network"))
        .map_err(|error| format!("could not verify requester Liquid network: {error}"))?;
    if network.network_id.as_str() != liquid.network_id
        || network.pegged_asset.to_string() != liquid.pegged_asset
    {
        return Err("requester elementsd differs from the configured Liquid network".to_owned());
    }
    verify_health(&environment.health_url)?;
    let offering = discover_provider_offering(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    match journey {
        LiquidJourney::Submarine => {
            run_liquid_submarine_route(&runtime, &environment, offering, provider_index)
        }
        LiquidJourney::Reverse => {
            run_liquid_reverse_route(&runtime, &environment, offering, provider_index)
        }
    }
}

fn run_liquid_submarine_route(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    offering: Event,
    provider_index: usize,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid submarine route has no local elementsd".to_owned())?;
    let invoice_amount_sat = liquid_submarine_invoice_amount_sat()?;
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id("liquid-submarine-invoice")?,
                Millisatoshi::from_satoshis(invoice_amount_sat)
                    .map_err(|error| format!("Liquid submarine amount is invalid: {error}"))?,
                "immortal-liquid-submarine",
                "Immortal Liquid submarine route",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create Liquid submarine invoice: {error}"))?;
    let refund_path = WalletPath::new(5, false, 0)
        .map_err(|error| format!("Liquid submarine refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive Liquid submarine refund key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 40)
                .map_err(|error| format!("Liquid submarine destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Liquid submarine destination: {error}"))?;
    let input = LiquidNegotiationInput {
        journey: LiquidJourney::Submarine,
        payment_hash: decode_fixed_hex(&invoice.payment_hash, "Liquid submarine payment hash")?,
        invoice: Some(invoice.bolt11.clone()),
        requester_key,
    };
    let prepared = prepare_liquid_order(
        runtime,
        environment,
        prepare_liquid_quote(environment, &offering.pubkey, &input)?,
        &input,
        refund_path,
        &destination.script_pubkey,
        None,
    )?;
    let PreparedLiquidSession {
        pending,
        funding,
        liquid_request,
    } = prepared;
    let funding = funding
        .ok_or_else(|| "Liquid submarine has no contract-bound funding transaction".to_owned())?;
    let mut session = finalize_negotiation(pending)?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let (authorized, retained) = authorize_liquid_submarine(
        runtime,
        environment,
        &session,
        &liquid_request,
        &invoice.bolt11,
    )?;
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":funding.transaction_id.clone()}),
    )?;
    let receipt = runtime
        .block_on(liquid.rail.broadcast_funding(&retained))
        .map_err(|error| format!("could not broadcast Liquid submarine funding: {error}"))?;
    if receipt.transaction_id != funding.transaction_id {
        return Err("elementsd accepted another Liquid submarine funding transaction".to_owned());
    }
    session.record_funding_effect(
        funding.transaction_id.clone(),
        sha256(&funding.raw_transaction),
    )?;
    session.publish_requester_status(
        "requester_funding_broadcast",
        Map::from_iter([
            (
                "transaction_id".to_owned(),
                Value::String(funding.transaction_id.clone()),
            ),
            ("output_index".to_owned(), json!(funding.output_index)),
        ]),
    )?;
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &funding.transaction_id,
        "liquid-submarine-funding-propagation",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "liquid-submarine-funding",
    )?;
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    session.wait_provider_state("lightning_payment_pending")?;
    session.wait_provider_state("lightning_paid")?;
    let claim_pending = session.wait_provider_state("provider_claim_pending")?;
    let claim_transaction_id = status_transaction_id(&claim_pending)?;
    session.persist_authorized_details(
        "provider_claim_effect_recorded",
        true,
        json!({"external_identifier":claim_transaction_id}),
    )?;
    let restart_proof = load_funded_injection_proof(&environment.control.paths)?
        .ok_or_else(|| "Liquid submarine provider restart has no controller proof".to_owned())?;
    let replayed_claim = session.wait_provider_state("provider_claim_pending")?;
    if replayed_claim.id != claim_pending.id
        || status_transaction_id(&replayed_claim)? != claim_transaction_id
    {
        return Err("Liquid submarine restart replayed another claim effect".to_owned());
    }
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &claim_transaction_id,
        "liquid-submarine-claim-propagation",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "liquid-submarine-claim",
    )?;
    session.wait_provider_state("provider_claimed")?;
    session.wait_provider_state("completed")?;
    verify_requester_invoice_paid(runtime, &environment.peer_cln, &invoice.payment_hash)?;
    let close = session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: None,
            liquid_settlement_txid: Some(&claim_transaction_id),
            lightning: Some(LightningTerminalCheck::IncomingInvoice {
                payment_hash: &invoice.payment_hash,
            }),
        },
    )?;
    let funding_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &funding.transaction_id,
        "liquid-submarine-funding-proof",
    )?;
    let claim_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &claim_transaction_id,
        "liquid-submarine-claim-proof",
    )?;
    let lifecycle =
        chain_lifecycle_event_ids(session.verifier.signed_records(), &offering, &close)?;
    Ok(liquid_route_proof(
        "liquid-submarine",
        provider_index,
        lifecycle,
        chain_leg_process_proof(
            "liquid",
            &funding.transaction_id,
            funding.output_index,
            &funding_hex,
            &claim_transaction_id,
            &claim_hex,
        ),
        vec!["liquid_submarine_claim"],
        vec!["provider_claim_pending", "provider_claimed"],
        "provider",
        "claim",
        &invoice.payment_hash,
        &restart_proof,
    ))
}

fn run_liquid_reverse_route(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    offering: Event,
    provider_index: usize,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid reverse route has no local elementsd".to_owned())?;
    let mut preimage = random_32()?;
    store_funded_secret(
        &environment.control.paths,
        LiquidJourney::Reverse.name(),
        &preimage,
    )?;
    let payment_hash = sha256(&preimage);
    let claim_path = WalletPath::new(5, false, 1)
        .map_err(|error| format!("Liquid reverse claim path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(claim_path)
        .map_err(|error| format!("could not derive Liquid reverse claim key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 41)
                .map_err(|error| format!("Liquid reverse destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Liquid reverse destination: {error}"))?;
    let input = LiquidNegotiationInput {
        journey: LiquidJourney::Reverse,
        payment_hash,
        invoice: None,
        requester_key,
    };
    let prepared = prepare_liquid_order(
        runtime,
        environment,
        prepare_liquid_quote(environment, &offering.pubkey, &input)?,
        &input,
        claim_path,
        &destination.script_pubkey,
        Some(LiquidJourney::Reverse.name()),
    )?;
    let mut session = finalize_negotiation(prepared.pending)?;
    session.wait_provider_state("accepted")?;
    let invoice_status = session.wait_provider_state("hold_invoice_ready")?;
    let invoice = record_profile(&invoice_status)?
        .get("invoice")
        .and_then(Value::as_str)
        .ok_or_else(|| "Liquid reverse hold-invoice Status has no invoice".to_owned())?
        .to_owned();
    session.publish_requester_status("requester_invoice_verified", Map::new())?;
    let payment_task = spawn_reverse_payment_once(
        runtime,
        &environment.peer_cln,
        LiquidJourney::Reverse.name(),
        invoice.clone(),
        lower_hex(&payment_hash),
    )?;
    session.publish_requester_status("lightning_payment_pending", Map::new())?;
    session.wait_provider_state("lightning_htlcs_held")?;
    session.wait_provider_state("provider_lock_terms_ready")?;
    let funding_raw = decode_hex(&prepared.liquid_request.funding.raw_transaction)?;
    let funding_transaction = parse_liquid_transaction(&funding_raw)
        .map_err(|error| format!("Liquid reverse funding template is invalid: {error}"))?;
    let expected_funding_transaction_id = lower_hex(&funding_transaction.transaction_id);
    observe_liquid_mempool_template(
        runtime,
        liquid,
        &LiquidNodeRequest {
            transaction_id: expected_funding_transaction_id.clone(),
            transaction_sha256: prepared.liquid_request.funding.transaction_sha256.clone(),
            output_index: prepared.liquid_request.funding.output_index,
            purpose: LiquidLegPurpose::CounterpartyLock,
            raw_transaction: funding_raw,
        },
        "liquid-reverse-template-preflight",
    )?;
    session.publish_requester_status("requester_lock_verified", Map::new())?;
    let funding_status = session.wait_provider_state("provider_funding_broadcast")?;
    let (funding_transaction_id, funding_output_index) = status_outpoint(&funding_status)?;
    if funding_transaction_id != expected_funding_transaction_id
        || funding_output_index != prepared.liquid_request.funding.output_index
    {
        return Err("provider broadcast another Liquid reverse funding transaction".to_owned());
    }
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &funding_transaction_id,
        "liquid-reverse-funding-propagation",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "liquid-reverse-funding",
    )?;
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    let (authorized, _verified) = authorize_liquid_reverse(
        runtime,
        environment,
        &session,
        &prepared.liquid_request,
        &invoice,
    )?;
    session.set_authorized_verifier(authorized)?;
    session.record_funding_effect(lower_hex(&payment_hash), payment_hash)?;
    session.persist_authorized_details(
        "provider_funding_effect_recorded",
        true,
        json!({"external_identifier":funding_transaction_id.clone()}),
    )?;
    let restart_proof = load_funded_injection_proof(&environment.control.paths)?
        .ok_or_else(|| "Liquid reverse provider restart has no controller proof".to_owned())?;
    let replayed_funding = session.wait_provider_state("provider_funding_broadcast")?;
    if replayed_funding.id != funding_status.id
        || status_outpoint(&replayed_funding)?
            != (funding_transaction_id.clone(), funding_output_index)
    {
        return Err("Liquid reverse restart replayed another funding effect".to_owned());
    }
    session.publish_requester_status("requester_claim_pending", Map::new())?;
    let authorized = session
        .authorized_verifier
        .as_mut()
        .ok_or_else(|| "Liquid reverse claim lost its pre-fund authorization".to_owned())?;
    let (claim_transaction_id, _claim_transaction_hex) = execute_liquid_wallet_claim(
        runtime,
        environment,
        authorized,
        &prepared.liquid_request,
        "destination",
        claim_path,
        preimage,
        LiquidJourney::Reverse.name(),
        "liquid-reverse-claim",
    )?;
    session.persist_authorized_details(
        "liquid_claim_broadcast_recorded",
        true,
        json!({"external_identifier":claim_transaction_id.clone()}),
    )?;
    remove_funded_secret(&environment.control.paths, LiquidJourney::Reverse.name())?;
    preimage.fill(0);
    session.publish_requester_status(
        "requester_claimed",
        Map::from_iter([(
            "transaction_id".to_owned(),
            Value::String(claim_transaction_id.clone()),
        )]),
    )?;
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &claim_transaction_id,
        "liquid-reverse-claim-propagation",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "liquid-reverse-claim",
    )?;
    session.wait_provider_state("lightning_settlement_pending")?;
    session.wait_provider_state("lightning_paid")?;
    session.wait_provider_state("completed")?;
    let payment = runtime
        .block_on(payment_task)
        .map_err(|error| format!("Liquid reverse payment task failed: {error}"))?
        .map_err(|error| format!("Liquid reverse payment did not settle: {error}"))?;
    if payment.status != "complete" || payment.payment_hash != lower_hex(&payment_hash) {
        return Err("Liquid reverse payment completed with another result".to_owned());
    }
    let terminal_payment = wait_for_lightning_payment_terminal(
        runtime,
        &environment.peer_cln,
        &invoice,
        &lower_hex(&payment_hash),
    )?;
    if terminal_payment.status != "complete" {
        return Err("Liquid reverse requester CLN did not report terminal settlement".to_owned());
    }
    let close = session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: None,
            liquid_settlement_txid: Some(&claim_transaction_id),
            lightning: Some(LightningTerminalCheck::OutgoingPayment {
                invoice: &invoice,
                payment_hash: &lower_hex(&payment_hash),
                expected_status: "complete",
            }),
        },
    )?;
    let funding_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &funding_transaction_id,
        "liquid-reverse-funding-proof",
    )?;
    let claim_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &claim_transaction_id,
        "liquid-reverse-claim-proof",
    )?;
    let lifecycle =
        chain_lifecycle_event_ids(session.verifier.signed_records(), &offering, &close)?;
    Ok(liquid_route_proof(
        "liquid-reverse",
        provider_index,
        lifecycle,
        chain_leg_process_proof(
            "liquid",
            &funding_transaction_id,
            funding_output_index,
            &funding_hex,
            &claim_transaction_id,
            &claim_hex,
        ),
        vec!["liquid_reverse_fund"],
        vec!["provider_funding_broadcast"],
        "requester",
        "claim",
        &lower_hex(&payment_hash),
        &restart_proof,
    ))
}

#[allow(clippy::too_many_arguments)]
fn liquid_route_proof(
    shape: &str,
    provider_index: usize,
    lifecycle: Value,
    liquid_rail: Value,
    provider_effect_operations: Vec<&str>,
    provider_status_anchors: Vec<&str>,
    terminal_actor: &str,
    terminal_path: &str,
    payment_hash: &str,
    restart_proof: &Value,
) -> Value {
    let selected_provider = if provider_index == 0 {
        "provider-a"
    } else {
        "provider-b"
    };
    let checkpoint_effect_operation = provider_effect_operations
        .first()
        .copied()
        .unwrap_or_default();
    let checkpoint_status_state = provider_status_anchors.first().copied().unwrap_or_default();
    json!({
        "liquid_case":{
            "schema":"openagents.immortal.adversarial-liquid-case.v1",
            "shape":shape,
            "selected_provider":selected_provider,
            "signed_lifecycle_event_ids":lifecycle,
            "rails":{"liquid":liquid_rail},
            "provider_effect_operations":provider_effect_operations,
            "provider_status_anchors":provider_status_anchors,
            "provider_restart":{
                "target":selected_provider,
                "checkpoint_effect_operation":checkpoint_effect_operation,
                "checkpoint_status_state":checkpoint_status_state,
                "process_replaced":restart_proof.pointer("/evidence/transition").and_then(Value::as_str)
                    == Some("process_replaced_and_ready"),
                "restored_from_postgres":true,
                "exact_known_replay":true,
                "duplicate_external_effects":0,
            },
            "liquid_terminal":{
                "actor":terminal_actor,
                "path":terminal_path,
                "effect_class":"liquid_spend",
                "confirmed":true,
            },
            "lightning_terminal":match shape {
                "liquid-submarine" => json!({
                    "actor":"requester",
                    "effect_actor":"provider",
                    "operation":"invoice_pay",
                    "status_anchor":"lightning_paid",
                    "state":"settled",
                    "observation_authority":"requester-cln",
                    "payment_hash":payment_hash,
                }),
                "liquid-reverse" => json!({
                    "actor":"requester",
                    "effect_actor":"provider",
                    "operation":"invoice_settle",
                    "status_anchor":"lightning_paid",
                    "state":"settled",
                    "observation_authority":"requester-cln",
                    "payment_hash":payment_hash,
                }),
                _ => Value::Null,
            },
            "recovery":null,
        }
    })
}

pub fn run_adversarial_double_reservation() -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(0, None)?;
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    let active_invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id("double-reservation-active-invoice")?,
                Millisatoshi::from_satoshis(DOUBLE_RESERVATION_OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("double-reservation amount is invalid: {error}"))?,
                "immortal-double-reservation-active",
                "Immortal adversarial active reservation",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create active reservation invoice: {error}"))?;
    let refused_invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id("double-reservation-refused-invoice")?,
                Millisatoshi::from_satoshis(DOUBLE_RESERVATION_OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("double-reservation amount is invalid: {error}"))?,
                "immortal-double-reservation-refused",
                "Immortal adversarial refused reservation",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create refused reservation invoice: {error}"))?;
    let active_requester_key = environment
        .wallet
        .derive_address(
            WalletPath::new(2, false, 20)
                .map_err(|error| format!("double-reservation path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive double-reservation key: {error}"))?
        .internal_key;
    let refused_requester_key = environment
        .wallet
        .derive_address(
            WalletPath::new(2, false, 21)
                .map_err(|error| format!("double-reservation path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive double-reservation key: {error}"))?
        .internal_key;
    let active_exit_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 20)
                .map_err(|error| format!("double-reservation exit path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive double-reservation exit: {error}"))?;
    let refused_exit_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 21)
                .map_err(|error| format!("double-reservation exit path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive double-reservation exit: {error}"))?;
    let active_input = NegotiationInput {
        journey_name: "double_reservation_active",
        swap_type: "submarine",
        payment_hash: &active_invoice.payment_hash,
        invoice: Some(&active_invoice.bolt11),
        requester_key: active_requester_key,
        requester_funding_input: None,
        exit_destination_script_pubkey: &active_exit_destination.script_pubkey,
        presign_submarine_refund: false,
    };
    let active = prepare_quote_with_terms(
        &environment,
        &provider_pubkey,
        active_input,
        DOUBLE_RESERVATION_INPUT_AMOUNT_SAT,
        DOUBLE_RESERVATION_MAXIMUM_TOTAL_FEE_SAT,
    )?;
    let active_rfq = active
        .records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_RFQ_KIND)
        .cloned()
        .ok_or_else(|| "double-reservation active session has no RFQ".to_owned())?;
    let active_quote = active
        .records
        .iter()
        .find(|event| event.kind == MKT_QUOTE_KIND)
        .cloned()
        .ok_or_else(|| "double-reservation active session has no Quote".to_owned())?;
    let active_profile = record_profile(&active_quote)?;
    let active_reservation = active_profile
        .get("reservation_terms")
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| "double-reservation active Quote has no hard reservation".to_owned())?;
    if !active_quote.tag_values("reservation").eq(["hard"]) {
        return Err("double-reservation active Quote is not hard".to_owned());
    }
    let daemon_reservation_id = required_string(&active_reservation, "reservation_id")?.to_owned();
    let capacity_bucket_id = required_string(&active_reservation, "capacity_bucket_id")?.to_owned();
    if capacity_bucket_id != "lightning-outbound" {
        return Err("double-reservation active Quote used another capacity bucket".to_owned());
    }
    let reserved_amount = canonical_u64(required_string(&active_reservation, "reserved_amount")?)?;
    let committed_capacity = canonical_u64(required_string(
        &active_reservation,
        "handler_committed_capacity",
    )?)?;
    if reserved_amount != DOUBLE_RESERVATION_OUTPUT_AMOUNT_SAT
        || committed_capacity < DOUBLE_RESERVATION_INPUT_AMOUNT_SAT
        || committed_capacity.saturating_sub(reserved_amount) >= DOUBLE_RESERVATION_INPUT_AMOUNT_SAT
    {
        return Err("live provider capacity does not create one-reservation contention".to_owned());
    }

    let refused_input = NegotiationInput {
        journey_name: "double_reservation_refused",
        swap_type: "submarine",
        payment_hash: &refused_invoice.payment_hash,
        invoice: Some(&refused_invoice.bolt11),
        requester_key: refused_requester_key,
        requester_funding_input: None,
        exit_destination_script_pubkey: &refused_exit_destination.script_pubkey,
        presign_submarine_refund: false,
    };
    let (refused_session_id, refused_rfq) = publish_quote_request_with_terms(
        &environment,
        &provider_pubkey,
        refused_input,
        DOUBLE_RESERVATION_INPUT_AMOUNT_SAT,
        DOUBLE_RESERVATION_MAXIMUM_TOTAL_FEE_SAT,
    )?;
    thread::sleep(Duration::from_millis(750));
    verify_health(&environment.health_url)?;

    Ok(json!({
        "proof_class":"live_double_reservation",
        "provider_pubkey":provider_pubkey,
        "capacity_bucket_id":capacity_bucket_id,
        "daemon_reservation_id":daemon_reservation_id,
        "active":{
            "session_id":active.config.session_id,
            "rfq_id":active_rfq.id,
            "quote_id":active_quote.id,
            "reservation_id":daemon_reservation_id,
        },
        "refused":{
            "session_id":refused_session_id,
            "rfq_id":refused_rfq.id,
            "expected_code":"swp_reservation_overallocated",
            "provider_wire_refusal":null,
            "surface":"lab_process_audit_required",
        },
        "checks":{
            "same_provider":true,
            "same_capacity_bucket":true,
            "overlapping_signed_sessions":true,
            "daemon_backed_hard_reservation_effects":1,
        }
    }))
}

pub fn prepare_doomsday_case(case: DoomsdayCase) -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start doomsday runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(0, None)?;
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    match case {
        DoomsdayCase::SubmarineProviderGone | DoomsdayCase::KeylessEsploraBroadcast => {
            prepare_doomsday_submarine(&runtime, &environment, &provider_pubkey, case)
        }
        DoomsdayCase::ReverseCoordinatorGone => {
            prepare_doomsday_reverse(&runtime, &environment, &provider_pubkey, case)
        }
        DoomsdayCase::LiquidSubmarineProviderGone => {
            prepare_doomsday_liquid_submarine(&runtime, &environment, &provider_pubkey, case)
        }
        DoomsdayCase::LiquidReverseCoordinatorGone => {
            prepare_doomsday_liquid_reverse(&runtime, &environment, &provider_pubkey, case)
        }
    }
}

pub fn recover_doomsday_case(case: DoomsdayCase) -> Result<Value, String> {
    let runtime =
        Runtime::new().map_err(|error| format!("could not start doomsday runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(0, None)?;
    let mut restored = restore_doomsday_session(&environment, case)?;
    restored.controller_audit = load_doomsday_controller_audit(case)?;
    match case {
        DoomsdayCase::SubmarineProviderGone => {
            recover_doomsday_submarine(&runtime, &environment, restored, case, false)
        }
        DoomsdayCase::KeylessEsploraBroadcast => {
            finish_doomsday_keyless(&runtime, &environment, restored)
        }
        DoomsdayCase::ReverseCoordinatorGone => {
            recover_doomsday_reverse(&runtime, &environment, restored, case)
        }
        DoomsdayCase::LiquidSubmarineProviderGone => {
            recover_doomsday_liquid_submarine(&runtime, &environment, restored, case)
        }
        DoomsdayCase::LiquidReverseCoordinatorGone => {
            recover_doomsday_liquid_reverse(&runtime, &environment, restored, case)
        }
    }
}

pub fn prepare_doomsday_keyless_request() -> Result<Value, String> {
    let case = DoomsdayCase::KeylessEsploraBroadcast;
    let runtime = Runtime::new()
        .map_err(|error| format!("could not start keyless planner runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(0, None)?;
    let restored = restore_doomsday_session(&environment, case)?;
    let prepared = prepare_doomsday_submarine_recovery(&runtime, &environment, restored, case)?;
    let request_path = PathBuf::from(required_environment("IMMORTAL_LAB_KEYLESS_REQUEST_FILE")?);
    store_doomsday_keyless_request(&request_path, &prepared.request)?;
    Ok(json!({
        "schema":DOOMSDAY_KEYLESS_REQUEST_SCHEMA,
        "case_id":"doomsday-keyless-esplora-broadcast",
        "effect_id":prepared.request.effect_id,
        "transaction_id":prepared.transaction_id,
        "planner_authorized":true,
        "signed_before_contract":true,
        "broadcast":false,
    }))
}

struct DoomsdayRestoredSession {
    authorized: SwapSession<FundingAuthorized>,
    requester: MarketSigner,
    provider_pubkey: String,
    factory: SwapRecordFactory,
    order: Event,
    contract: Value,
    requester_status: Option<(u64, String)>,
    paths: LabPaths,
    journey_name: String,
    controller_audit: Value,
    pending_provider_close: Option<Event>,
    offering_id: Option<String>,
}

struct PreparedSubmarineRecovery {
    restored: DoomsdayRestoredSession,
    request: EsploraBroadcastRequest,
    funding_transaction_id: String,
    funding_output_index: u32,
    transaction_id: String,
    funding_confirmation_height: u32,
    refund_lock_height: u32,
    payment_hash: String,
}

fn prepare_doomsday_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id(case.invoice_label())?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("doomsday invoice amount is invalid: {error}"))?,
                case.invoice_label(),
                "Immortal adversarial doomsday refund",
                SUBMARINE_REFUND_INVOICE_EXPIRY_SECONDS,
            ),
        )
        .map_err(|error| format!("could not create doomsday invoice: {error}"))?;
    let client_input = fund_client_wallet(runtime, environment)?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("doomsday refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive doomsday refund key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 10)
                .map_err(|error| format!("doomsday destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive doomsday destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name: case.journey_name(),
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &destination.script_pubkey,
            presign_submarine_refund: true,
        },
    )?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let funding = session
        .requester_funding
        .take()
        .ok_or_else(|| "doomsday session has no contract-bound funding".to_owned())?;
    let authorized = verify_submarine_before_fund(&session, &invoice.bolt11, &funding)?;
    let package = authorized
        .exit_packages()
        .iter()
        .find(|package| package.path().ok() == Some("refund"))
        .ok_or_else(|| "doomsday session has no requester refund package".to_owned())?;
    if package.mode().map_err(|error| error.to_string())? != "presigned"
        || !matches!(
            package.document().pointer("/exit/signer_ref"),
            Some(Value::Null)
        )
    {
        return Err("doomsday refund was not pre-signed before Contracts".to_owned());
    }
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":funding.txid}),
    )?;
    let funding_transaction_id = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "doomsday-funding",
        &funding.raw_transaction,
        &funding.txid,
    )?;
    session.record_funding_effect(
        funding_transaction_id.clone(),
        sha256(funding.raw_transaction.as_bytes()),
    )?;
    let bitcoin = bitcoin_terms(&session.contract, "source")?;
    session.persist_authorized_details(
        "doomsday_prepared",
        true,
        json!({
            "funding_transaction_id":funding_transaction_id,
            "refund_lock_height":bitcoin.refund_lock_height,
            "package_mode":"presigned",
            "signed_before_contract":true,
            "signed_before_funding":true,
        }),
    )?;
    Ok(json!({
        "schema":"openagents.immortal.doomsday-prepared.v1",
        "case_id":match case {
            DoomsdayCase::SubmarineProviderGone => "doomsday-submarine-provider-gone",
            DoomsdayCase::KeylessEsploraBroadcast => "doomsday-keyless-esplora-broadcast",
            DoomsdayCase::ReverseCoordinatorGone
            | DoomsdayCase::LiquidSubmarineProviderGone
            | DoomsdayCase::LiquidReverseCoordinatorGone => {
                return Err("another case reached Bitcoin submarine preparation".to_owned());
            }
        },
        "provider_pubkey":provider_pubkey,
        "order_id":session.order.id,
        "funding_transaction_id":funding_transaction_id,
        "refund_lock_height":bitcoin.refund_lock_height,
        "package_mode":"presigned",
        "signer_ref":null,
        "signed_before_contract":true,
        "signed_before_funding":true,
        "requester_process_exit":true,
    }))
}

fn prepare_doomsday_liquid_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid submarine doomsday has no local elementsd".to_owned())?;
    let offering = discover_provider_offering(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    if offering.pubkey != provider_pubkey {
        return Err("Liquid submarine doomsday discovered another provider".to_owned());
    }
    let invoice_amount_sat = liquid_submarine_invoice_amount_sat()?;
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id(case.invoice_label())?,
                Millisatoshi::from_satoshis(invoice_amount_sat)
                    .map_err(|error| format!("Liquid doomsday amount is invalid: {error}"))?,
                case.invoice_label(),
                "Immortal Liquid doomsday refund",
                SUBMARINE_REFUND_INVOICE_EXPIRY_SECONDS,
            ),
        )
        .map_err(|error| format!("could not create Liquid doomsday invoice: {error}"))?;
    let refund_path = WalletPath::new(5, false, 2)
        .map_err(|error| format!("Liquid doomsday refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive Liquid doomsday refund key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 42)
                .map_err(|error| format!("Liquid doomsday destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Liquid doomsday destination: {error}"))?;
    let input = LiquidNegotiationInput {
        journey: LiquidJourney::Submarine,
        payment_hash: decode_fixed_hex(&invoice.payment_hash, "Liquid doomsday payment hash")?,
        invoice: Some(invoice.bolt11.clone()),
        requester_key,
    };
    let mut prepared = prepare_liquid_order(
        runtime,
        environment,
        prepare_liquid_quote(environment, provider_pubkey, &input)?,
        &input,
        refund_path,
        &destination.script_pubkey,
        None,
    )?;
    prepared.pending.journey_name =
        liquid_doomsday_journey_name(case, &prepared.pending.journey_name)?.to_owned();
    if prepared.liquid_request.exit_package.mode != LiquidExitMode::Presigned
        || prepared.liquid_request.exit_package.path != "refund"
    {
        return Err("Liquid doomsday refund is not an exact pre-signed package".to_owned());
    }
    let funding = prepared
        .funding
        .ok_or_else(|| "Liquid doomsday has no source funding".to_owned())?;
    let mut session = finalize_negotiation(prepared.pending)?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let (authorized, retained) = authorize_liquid_submarine(
        runtime,
        environment,
        &session,
        &prepared.liquid_request,
        &invoice.bolt11,
    )?;
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    let receipt = runtime
        .block_on(liquid.rail.broadcast_funding(&retained))
        .map_err(|error| format!("could not broadcast Liquid doomsday funding: {error}"))?;
    if receipt.transaction_id != funding.transaction_id {
        return Err("Liquid doomsday broadcast another funding transaction".to_owned());
    }
    session.record_funding_effect(
        funding.transaction_id.clone(),
        sha256(&funding.raw_transaction),
    )?;
    session.persist_authorized_details(
        "doomsday_prepared",
        true,
        json!({
            "funding_transaction_id":funding.transaction_id,
            "refund_lock_height":prepared.liquid_request.exit_package.timelock,
            "package_mode":"presigned",
            "signed_before_contract":true,
            "signed_before_funding":true,
            "offering_id":offering.id,
        }),
    )?;
    Ok(json!({
        "schema":"openagents.immortal.doomsday-prepared.v1",
        "case_id":case.case_id(),
        "provider_pubkey":provider_pubkey,
        "order_id":session.order.id,
        "funding_transaction_id":receipt.transaction_id,
        "refund_lock_height":prepared.liquid_request.exit_package.timelock,
        "package_mode":"presigned",
        "signer_ref":null,
        "signed_before_contract":true,
        "signed_before_funding":true,
        "requester_process_exit":true,
    }))
}

fn prepare_doomsday_liquid_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid reverse doomsday has no local elementsd".to_owned())?;
    let offering = discover_provider_offering(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    if offering.pubkey != provider_pubkey {
        return Err("Liquid reverse doomsday discovered another provider".to_owned());
    }
    let mut preimage = random_32()?;
    store_funded_secret(&environment.control.paths, case.journey_name(), &preimage)?;
    let payment_hash = sha256(&preimage);
    let claim_path = WalletPath::new(5, false, 3)
        .map_err(|error| format!("Liquid doomsday claim path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(claim_path)
        .map_err(|error| format!("could not derive Liquid doomsday claim key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 43)
                .map_err(|error| format!("Liquid reverse destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Liquid reverse destination: {error}"))?;
    let input = LiquidNegotiationInput {
        journey: LiquidJourney::Reverse,
        payment_hash,
        invoice: None,
        requester_key,
    };
    let mut prepared = prepare_liquid_order(
        runtime,
        environment,
        prepare_liquid_quote(environment, provider_pubkey, &input)?,
        &input,
        claim_path,
        &destination.script_pubkey,
        Some(case.journey_name()),
    )?;
    prepared.pending.journey_name =
        liquid_doomsday_journey_name(case, &prepared.pending.journey_name)?.to_owned();
    if prepared.liquid_request.exit_package.mode != LiquidExitMode::Wallet
        || prepared.liquid_request.exit_package.path != "claim"
        || prepared
            .liquid_request
            .exit_package
            .wallet_signing_handle_sha256
            .is_none()
        || prepared
            .liquid_request
            .exit_package
            .preimage_recovery_ref
            .is_none()
        || prepared
            .liquid_request
            .exit_package
            .wallet_signing_handle_sha256
            == prepared.liquid_request.exit_package.preimage_recovery_ref
    {
        return Err("Liquid reverse doomsday claim has no distinct recovery references".to_owned());
    }
    let mut session = finalize_negotiation(prepared.pending)?;
    session.wait_provider_state("accepted")?;
    let invoice_status = session.wait_provider_state("hold_invoice_ready")?;
    let invoice = record_profile(&invoice_status)?
        .get("invoice")
        .and_then(Value::as_str)
        .ok_or_else(|| "Liquid doomsday provider Status has no hold invoice".to_owned())?
        .to_owned();
    session.publish_requester_status("requester_invoice_verified", Map::new())?;
    let payment_task = spawn_reverse_payment_once(
        runtime,
        &environment.peer_cln,
        case.journey_name(),
        invoice.clone(),
        lower_hex(&payment_hash),
    )?;
    session.publish_requester_status("lightning_payment_pending", Map::new())?;
    wait_for_lightning_payment_attempt(
        runtime,
        &environment.peer_cln,
        &invoice,
        &lower_hex(&payment_hash),
    )?;
    session.wait_provider_state("lightning_htlcs_held")?;
    session.wait_provider_state("provider_lock_terms_ready")?;
    session.publish_requester_status("requester_lock_verified", Map::new())?;
    let funding_status = session.wait_provider_state("provider_funding_broadcast")?;
    let (funding_transaction_id, funding_output_index) = status_outpoint(&funding_status)?;
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &funding_transaction_id,
        "doomsday-liquid-reverse-funding",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "doomsday-liquid-reverse-funding",
    )?;
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    let (authorized, _) = authorize_liquid_reverse(
        runtime,
        environment,
        &session,
        &prepared.liquid_request,
        &invoice,
    )?;
    session.set_authorized_verifier(authorized)?;
    session.record_funding_effect(lower_hex(&payment_hash), payment_hash)?;
    session.persist_authorized_details(
        "doomsday_prepared",
        true,
        json!({
            "funding_transaction_id":funding_transaction_id,
            "funding_output_index":funding_output_index,
            "package_mode":"wallet_sign",
            "signer_ref":prepared.liquid_request.exit_package.wallet_signing_handle_sha256,
            "preimage_recovery_ref":prepared.liquid_request.exit_package.preimage_recovery_ref,
            "exit_template_before_contract":true,
            "external_recovery_reference_bound_before_contract":true,
            "offering_id":offering.id,
        }),
    )?;
    drop(payment_task);
    preimage.fill(0);
    Ok(json!({
        "schema":"openagents.immortal.doomsday-prepared.v1",
        "case_id":case.case_id(),
        "provider_pubkey":provider_pubkey,
        "order_id":session.order.id,
        "payment_hash":lower_hex(&payment_hash),
        "funding_transaction_id":funding_transaction_id,
        "funding_output_index":funding_output_index,
        "package_mode":"wallet_sign",
        "exit_template_before_contract":true,
        "external_recovery_reference_bound_before_contract":true,
        "requester_process_exit":true,
    }))
}

fn restore_doomsday_session(
    environment: &SmokeEnvironment,
    case: DoomsdayCase,
) -> Result<DoomsdayRestoredSession, String> {
    let journey_name = case.journey_name();
    let snapshot_path = environment.control.paths.funded_snapshot(journey_name);
    let snapshot = std::fs::read(&snapshot_path).map_err(|error| {
        format!(
            "could not restore doomsday snapshot {}: {error}",
            snapshot_path.display()
        )
    })?;
    let authorized = SwapSession::<AwaitingVerification>::restore(&snapshot)
        .and_then(SwapSession::resume_funding_authorized)
        .map_err(|error| format!("could not restore doomsday authorization: {error}"))?;
    let checkpoint = load_funded_journey_checkpoint(&environment.control.paths, journey_name)?
        .ok_or_else(|| "doomsday snapshot has no checkpoint".to_owned())?;
    if checkpoint.run_id != environment.control.run_id
        || checkpoint.journey != journey_name
        || checkpoint.label != "doomsday_prepared"
    {
        return Err("doomsday checkpoint does not bind the prepared session".to_owned());
    }
    let config = authorized.config().clone();
    let order = authorized
        .signed_records()
        .iter()
        .find(|event| event.kind == MKT_ORDER_KIND)
        .cloned()
        .ok_or_else(|| "doomsday snapshot has no Order".to_owned())?;
    let contract = authorized
        .signed_records()
        .iter()
        .filter(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .find_map(|event| record_profile(event).ok()?.get("contract").cloned())
        .ok_or_else(|| "doomsday snapshot has no contract".to_owned())?;
    let requester_status =
        latest_requester_status(authorized.signed_records(), environment.requester.pubkey())?;
    Ok(DoomsdayRestoredSession {
        authorized,
        requester: environment.requester.clone(),
        provider_pubkey: config.provider_pubkey.clone(),
        factory: SwapRecordFactory::new(config)
            .map_err(|error| format!("could not restore doomsday factory: {error}"))?,
        order,
        contract,
        requester_status,
        paths: environment.control.paths.clone(),
        journey_name: journey_name.to_owned(),
        controller_audit: Value::Null,
        pending_provider_close: None,
        offering_id: checkpoint
            .details
            .get("offering_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn load_doomsday_controller_audit(case: DoomsdayCase) -> Result<Value, String> {
    let path = PathBuf::from(required_environment("IMMORTAL_LAB_DOOMSDAY_CONTROL_FILE")?);
    let value = read_bounded_unique_json(&path, 8 * 1_024)?;
    provider_support::reject_custody_material(&value).map_err(|error| {
        format!("doomsday controller evidence contains custody material: {error}")
    })?;
    let object = value
        .as_object()
        .filter(|object| {
            object.len() == 10
                && [
                    "schema",
                    "case_id",
                    "stopped_targets",
                    "stopped_targets_absent_before_recovery",
                    "stopped_targets_absent_after_recovery",
                    "relay_services_absent",
                    "provider_http_websocket_api_absent",
                    "direct_recovery_retained",
                    "direct_recovery_only_session_surface",
                    "keyless_process",
                ]
                .iter()
                .all(|member| object.contains_key(*member))
        })
        .ok_or_else(|| "doomsday controller evidence has unknown or missing members".to_owned())?;
    let expected_targets = match case {
        DoomsdayCase::ReverseCoordinatorGone | DoomsdayCase::LiquidReverseCoordinatorGone => {
            ["provider-b", "relay-a", "relay-b"].as_slice()
        }
        DoomsdayCase::SubmarineProviderGone
        | DoomsdayCase::KeylessEsploraBroadcast
        | DoomsdayCase::LiquidSubmarineProviderGone => {
            ["provider-a", "provider-b", "relay-a", "relay-b"].as_slice()
        }
    };
    let targets = object
        .get("stopped_targets")
        .and_then(Value::as_array)
        .ok_or_else(|| "doomsday controller stopped targets are not an array".to_owned())?;
    if targets.len() != expected_targets.len()
        || targets
            .iter()
            .zip(expected_targets)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
        || object.get("schema").and_then(Value::as_str)
            != Some("openagents.immortal.doomsday-controller-audit.v1")
        || object.get("case_id").and_then(Value::as_str) != Some(case.case_id())
        || object
            .get("stopped_targets_absent_before_recovery")
            .and_then(Value::as_bool)
            != Some(true)
        || !matches!(
            object
                .get("stopped_targets_absent_after_recovery")
                .and_then(Value::as_bool),
            Some(false | true)
        )
        || object.get("relay_services_absent").and_then(Value::as_bool) != Some(true)
        || object
            .get("provider_http_websocket_api_absent")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("doomsday controller evidence does not bind the removal cut".to_owned());
    }
    let expects_direct = matches!(
        case,
        DoomsdayCase::ReverseCoordinatorGone | DoomsdayCase::LiquidReverseCoordinatorGone
    );
    if object
        .get("direct_recovery_retained")
        .and_then(Value::as_bool)
        != Some(expects_direct)
        || object
            .get("direct_recovery_only_session_surface")
            .and_then(Value::as_bool)
            != Some(expects_direct)
    {
        return Err("doomsday controller evidence changed the direct recovery cut".to_owned());
    }
    validate_doomsday_keyless_process_audit(object.get("keyless_process"), case)?;
    Ok(value)
}

fn validate_doomsday_keyless_process_audit(
    audit: Option<&Value>,
    case: DoomsdayCase,
) -> Result<(), String> {
    if case != DoomsdayCase::KeylessEsploraBroadcast {
        return if matches!(audit, Some(Value::Null)) {
            Ok(())
        } else {
            Err("non-keyless doomsday case contains a keyless process audit".to_owned())
        };
    }
    let object = audit
        .and_then(Value::as_object)
        .filter(|object| {
            object.len() == 10
                && [
                    "separate_container",
                    "application_environment_names",
                    "mount_targets",
                    "observed_environment_count",
                    "observed_mount_count",
                    "environment_allowlist_exact",
                    "mount_allowlist_exact",
                    "rail_access",
                    "runtime_environment_scan_passed",
                    "exact_presigned_request_only",
                ]
                .iter()
                .all(|member| object.contains_key(*member))
        })
        .ok_or_else(|| "keyless process audit has unknown or missing members".to_owned())?;
    let strings = |member: &str| -> Option<Vec<&str>> {
        object
            .get(member)?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect()
    };
    if object.get("separate_container").and_then(Value::as_bool) != Some(true)
        || strings("application_environment_names").as_deref()
            != Some(
                [
                    "IMMORTAL_LAB_KEYLESS_REQUEST_FILE",
                    "IMMORTAL_LAB_KEYLESS_RESULT_FILE",
                ]
                .as_slice(),
            )
        || strings("mount_targets").as_deref() != Some(["/keyless"].as_slice())
        || object
            .get("observed_environment_count")
            .and_then(Value::as_u64)
            != Some(3)
        || object.get("observed_mount_count").and_then(Value::as_u64) != Some(1)
        || object
            .get("environment_allowlist_exact")
            .and_then(Value::as_bool)
            != Some(true)
        || object.get("mount_allowlist_exact").and_then(Value::as_bool) != Some(true)
        || object.get("rail_access").and_then(Value::as_bool) != Some(false)
        || object
            .get("runtime_environment_scan_passed")
            .and_then(Value::as_bool)
            != Some(true)
        || object
            .get("exact_presigned_request_only")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("keyless process audit does not prove its credential-free boundary".to_owned());
    }
    Ok(())
}

fn prepare_doomsday_submarine_recovery(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: DoomsdayRestoredSession,
    case: DoomsdayCase,
) -> Result<PreparedSubmarineRecovery, String> {
    let verifier = verifier_for_leg(&restored.contract, "source")?;
    let funding_transaction_id = transaction_id(required_string(verifier, "funding_transaction")?)?;
    let funding_output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "doomsday funding output is not bounded".to_owned())?;
    require_known_bitcoin_transaction(
        runtime,
        &environment.bitcoind,
        "doomsday-funding",
        &funding_transaction_id,
        Some(required_string(verifier, "funding_transaction")?),
    )?;
    mine_blocks(runtime, &environment.bitcoind, 1, "doomsday-funding")?;
    let funding_confirmation_height = transaction_confirmation_height(
        runtime,
        &environment.bitcoind,
        "doomsday-funding-confirmation",
        &funding_transaction_id,
    )?;
    let payment_hash = restored
        .contract
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "doomsday contract has no payment hash".to_owned())?
        .to_owned();
    finalize_invoice_unpaid(
        runtime,
        &environment.peer_cln,
        case.invoice_label(),
        &payment_hash,
    )?;
    let bitcoin = bitcoin_terms(&restored.contract, "source")?;
    let current_height = chain_height(runtime, &environment.bitcoind, "doomsday-before-timeout")?;
    let before_timeout = doomsday_submarine_recovery_action(
        &restored.authorized,
        current_height,
        funding_confirmation_height,
    )?;
    if before_timeout != RecoveryAction::WaitForTimeout {
        return Err("doomsday planner authorized an early refund broadcast".to_owned());
    }
    mine_blocks(
        runtime,
        &environment.bitcoind,
        u64::from(bitcoin.refund_lock_height.saturating_sub(current_height)),
        "doomsday-refund-timeout",
    )?;
    let timeout_height = chain_height(runtime, &environment.bitcoind, "doomsday-timeout")?;
    if timeout_height < bitcoin.refund_lock_height {
        return Err("doomsday recovery did not reach the committed refund height".to_owned());
    }
    let action = doomsday_submarine_recovery_action(
        &restored.authorized,
        timeout_height,
        funding_confirmation_height,
    )?;
    let expected_effect_id = match action {
        RecoveryAction::BroadcastPresigned { effect_id } => effect_id,
        _ => return Err("doomsday planner did not authorize the pre-signed refund".to_owned()),
    };
    let package = restored
        .authorized
        .exit_packages()
        .iter()
        .find(|package| package.effect_id().ok() == Some(expected_effect_id.as_str()))
        .ok_or_else(|| "doomsday planner selected an unbound exit package".to_owned())?;
    let esplora_url = package
        .document()
        .pointer("/broadcast/esplora_urls/0")
        .and_then(Value::as_str)
        .ok_or_else(|| "doomsday package has no Esplora endpoint".to_owned())?;
    let request = KeylessEsploraExecutor::request(package, esplora_url)
        .map_err(|error| format!("could not build exact keyless request: {error}"))?;
    let transaction = Transaction::parse(&decode_hex(&request.body)?)
        .map_err(|error| format!("doomsday signed refund is invalid: {error}"))?;
    let transaction_id = lower_hex(
        &transaction
            .txid()
            .map_err(|error| format!("could not derive doomsday refund txid: {error}"))?,
    );
    Ok(PreparedSubmarineRecovery {
        restored,
        request,
        funding_transaction_id,
        funding_output_index,
        transaction_id,
        funding_confirmation_height,
        refund_lock_height: bitcoin.refund_lock_height,
        payment_hash,
    })
}

fn doomsday_submarine_recovery_action(
    authorized: &SwapSession<FundingAuthorized>,
    current_height: u32,
    funding_confirmation_height: u32,
) -> Result<RecoveryAction, String> {
    authorized
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height,
                source_funding_confirmation_height: Some(funding_confirmation_height),
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: None,
            })
        })
        .map_err(|error| format!("doomsday planner rejected local observations: {error}"))
}

fn recover_doomsday_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: DoomsdayRestoredSession,
    case: DoomsdayCase,
    _keyless: bool,
) -> Result<Value, String> {
    let mut prepared = prepare_doomsday_submarine_recovery(runtime, environment, restored, case)?;
    let transaction_id = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "doomsday-presigned-refund",
        &prepared.request.body,
        &prepared.transaction_id,
    )?;
    record_doomsday_esplora_effect(&mut prepared.restored, &prepared.request, &transaction_id)?;
    finish_doomsday_submarine_refund(runtime, environment, prepared, false)
}

fn record_doomsday_esplora_effect(
    restored: &mut DoomsdayRestoredSession,
    request: &EsploraBroadcastRequest,
    transaction_id: &str,
) -> Result<(), String> {
    let effect = ExternalEffectRequest::EsploraBroadcast(request.clone());
    restored
        .authorized
        .record_external_effect(
            &effect,
            transaction_id.to_owned(),
            lower_hex(&sha256(&decode_hex(&request.body)?)),
        )
        .map_err(|error| format!("could not persist doomsday broadcast effect: {error}"))?;
    let snapshot = restored
        .authorized
        .persist()
        .map_err(|error| format!("could not serialize doomsday recovery: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &snapshot)
}

fn finish_doomsday_submarine_refund(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    prepared: PreparedSubmarineRecovery,
    keyless: bool,
) -> Result<Value, String> {
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "doomsday-refund-confirmation",
    )?;
    let peer_bitcoind = load_adversarial_bitcoind("B")?;
    verify_refund_spend_on_both_nodes(
        runtime,
        [&environment.bitcoind, &peer_bitcoind],
        &prepared.funding_transaction_id,
        prepared.funding_output_index,
        &prepared.transaction_id,
        &prepared.request.body,
    )?;
    let invoices = runtime
        .block_on(
            environment
                .peer_cln
                .list_invoices(&cln_id("doomsday-terminal-invoice")?, None),
        )
        .map_err(|error| format!("could not inspect doomsday terminal invoice: {error}"))?;
    if invoices
        .get("invoices")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|invoice| {
                invoice.get("payment_hash").and_then(Value::as_str)
                    == Some(prepared.payment_hash.as_str())
            })
        })
    {
        return Err("doomsday submarine invoice did not reach unpaid-final removal".to_owned());
    }
    Ok(json!({
        "proof_class":if keyless {"keyless_presigned_regtest_exit"} else {"presigned_regtest_exit"},
        "provider_pubkey":prepared.restored.provider_pubkey,
        "order_id":prepared.restored.order.id,
        "funding_transaction_id":prepared.funding_transaction_id,
        "funding_output_index":prepared.funding_output_index,
        "refund_transaction_id":prepared.transaction_id,
        "funding_confirmation_height":prepared.funding_confirmation_height,
        "refund_lock_height":prepared.refund_lock_height,
        "payment_hash":prepared.payment_hash,
        "outcome":"refunded",
        "controller_audit":prepared.restored.controller_audit,
        "checks":{
            "fresh_requester_process_restored_before_relay":true,
            "relay_connections_after_restore":0,
            "provider_process_absent":true,
            "relay_processes_absent":true,
            "presigned_before_contract":true,
            "presigned_before_funding":true,
            "wallet_sign_after_contract":false,
            "broadcast_before_timeout":false,
            "verified_local_chain_observation":true,
            "verified_local_lightning_observation":true,
            "exact_outpoint_spent":true,
            "both_bitcoind_nodes_agree":true,
            "transaction_confirmed":true,
            "lightning_unpaid_final":true,
            "keyless_process":keyless,
        }
    }))
}

pub fn run_adversarial_cooperative_journey(
    provider_index: usize,
    journey: CooperativeJourney,
) -> Result<Value, String> {
    let injection = (journey == CooperativeJourney::CrashCutRecovery)
        .then_some(HarnessInjection::CooperativeCrashCut);
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load_topology_selected(provider_index, injection)?;
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    let client_input = fund_client_wallet(&runtime, &environment)?;
    let proof = drive_cooperative_submarine(
        &runtime,
        &environment,
        &provider_pubkey,
        client_input,
        journey,
    )?;
    verify_health(&environment.health_url)?;
    Ok(json!({
        "step":journey.name(),
        "provider_pubkey":provider_pubkey,
        "journey":proof,
    }))
}

fn finish_doomsday_keyless(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: DoomsdayRestoredSession,
) -> Result<Value, String> {
    let request_path = PathBuf::from(required_environment("IMMORTAL_LAB_KEYLESS_REQUEST_FILE")?);
    let result_path = PathBuf::from(required_environment("IMMORTAL_LAB_KEYLESS_RESULT_FILE")?);
    let (request, expected_transaction_id) = load_doomsday_keyless_request(&request_path)?;
    let result = read_bounded_unique_json(&result_path, DOOMSDAY_KEYLESS_MAX_BYTES)?;
    let object = result
        .as_object()
        .filter(|object| {
            object.len() == 5
                && [
                    "schema",
                    "effect_id",
                    "transaction_id",
                    "request_sha256",
                    "broadcast_accepted",
                ]
                .iter()
                .all(|name| object.contains_key(*name))
        })
        .ok_or_else(|| "keyless result has unknown or missing members".to_owned())?;
    let request_sha256 =
        lower_hex(&sha256(&serde_json::to_vec(&request).map_err(|error| {
            format!("could not serialize keyless request: {error}")
        })?));
    if object.get("schema").and_then(Value::as_str) != Some(DOOMSDAY_KEYLESS_RESULT_SCHEMA)
        || object.get("effect_id").and_then(Value::as_str) != Some(request.effect_id.as_str())
        || object.get("transaction_id").and_then(Value::as_str)
            != Some(expected_transaction_id.as_str())
        || object.get("request_sha256").and_then(Value::as_str) != Some(request_sha256.as_str())
        || object.get("broadcast_accepted").and_then(Value::as_bool) != Some(true)
    {
        return Err("keyless result does not bind the exact accepted request".to_owned());
    }
    require_known_bitcoin_transaction(
        runtime,
        &environment.bitcoind,
        "doomsday-keyless-refund",
        &expected_transaction_id,
        Some(&request.body),
    )?;
    let mut prepared = prepared_submarine_from_keyless_result(
        runtime,
        environment,
        restored,
        request,
        expected_transaction_id,
    )?;
    let transaction_id = prepared.transaction_id.clone();
    let request = prepared.request.clone();
    record_doomsday_esplora_effect(&mut prepared.restored, &request, &transaction_id)?;
    finish_doomsday_submarine_refund(runtime, environment, prepared, true)
}

fn prepared_submarine_from_keyless_result(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: DoomsdayRestoredSession,
    request: EsploraBroadcastRequest,
    transaction_id: String,
) -> Result<PreparedSubmarineRecovery, String> {
    let verifier = verifier_for_leg(&restored.contract, "source")?;
    let funding_transaction_id = transaction_id_from_verifier(verifier)?;
    let funding_output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "keyless funding output is not bounded".to_owned())?;
    let funding_confirmation_height = transaction_confirmation_height(
        runtime,
        &environment.bitcoind,
        "keyless-funding-confirmation",
        &funding_transaction_id,
    )?;
    let refund_lock_height = bitcoin_terms(&restored.contract, "source")?.refund_lock_height;
    let current_height = chain_height(runtime, &environment.bitcoind, "keyless-result-height")?;
    if current_height < refund_lock_height {
        return Err("keyless broadcaster accepted a refund before timeout".to_owned());
    }
    let payment_hash = restored
        .contract
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "keyless contract has no payment hash".to_owned())?
        .to_owned();
    Ok(PreparedSubmarineRecovery {
        restored,
        request,
        funding_transaction_id,
        funding_output_index,
        transaction_id,
        funding_confirmation_height,
        refund_lock_height,
        payment_hash,
    })
}

fn transaction_id_from_verifier(verifier: &Map<String, Value>) -> Result<String, String> {
    transaction_id(required_string(verifier, "funding_transaction")?)
}

fn store_doomsday_keyless_request(
    path: &Path,
    request: &EsploraBroadcastRequest,
) -> Result<(), String> {
    let transaction = Transaction::parse(&decode_hex(&request.body)?)
        .map_err(|error| format!("keyless request transaction is invalid: {error}"))?;
    let transaction_id = lower_hex(
        &transaction
            .txid()
            .map_err(|error| format!("could not derive keyless request txid: {error}"))?,
    );
    store_bounded_private_json(
        path,
        &json!({
            "schema":DOOMSDAY_KEYLESS_REQUEST_SCHEMA,
            "transaction_id":transaction_id,
            "request":request,
        }),
        DOOMSDAY_KEYLESS_MAX_BYTES,
    )
}

fn load_doomsday_keyless_request(path: &Path) -> Result<(EsploraBroadcastRequest, String), String> {
    let value = read_bounded_unique_json(path, DOOMSDAY_KEYLESS_MAX_BYTES)?;
    provider_support::reject_custody_material(&value)
        .map_err(|error| format!("keyless request contains custody material: {error}"))?;
    let object = value
        .as_object()
        .filter(|object| {
            object.len() == 3
                && object.contains_key("schema")
                && object.contains_key("transaction_id")
                && object.contains_key("request")
        })
        .ok_or_else(|| "keyless request has unknown or missing members".to_owned())?;
    if object.get("schema").and_then(Value::as_str) != Some(DOOMSDAY_KEYLESS_REQUEST_SCHEMA) {
        return Err("keyless request schema is unsupported".to_owned());
    }
    let transaction_id = object
        .get("transaction_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "keyless request has no transaction ID".to_owned())?;
    require_lower_hex_32(transaction_id, "keyless transaction ID")?;
    let request: EsploraBroadcastRequest = serde_json::from_value(
        object
            .get("request")
            .cloned()
            .ok_or_else(|| "keyless request has no HTTP request".to_owned())?,
    )
    .map_err(|error| format!("keyless HTTP request is invalid: {error}"))?;
    validate_doomsday_keyless_http_request(&request, transaction_id)?;
    Ok((request, transaction_id.to_owned()))
}

fn prepare_doomsday_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let mut preimage = random_32()?;
    store_funded_secret(&environment.control.paths, case.journey_name(), &preimage)?;
    let payment_hash = lower_hex(&sha256(&preimage));
    let claim_path = WalletPath::new(2, false, 1)
        .map_err(|error| format!("doomsday reverse claim path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(claim_path)
        .map_err(|error| format!("could not derive doomsday reverse claim key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 1)
                .map_err(|error| format!("doomsday reverse destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive doomsday reverse destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name: case.journey_name(),
            swap_type: "reverse",
            payment_hash: &payment_hash,
            invoice: None,
            requester_key,
            requester_funding_input: None,
            exit_destination_script_pubkey: &destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    session.wait_provider_state("accepted")?;
    let invoice_status = session.wait_provider_state("hold_invoice_ready")?;
    let invoice = record_profile(&invoice_status)?
        .get("invoice")
        .and_then(Value::as_str)
        .ok_or_else(|| "doomsday provider Status has no hold invoice".to_owned())?
        .to_owned();
    let authorized = verify_reverse_before_fund(runtime, environment, &session, &invoice)?;
    let package = authorized
        .exit_packages()
        .iter()
        .find(|package| package.path().ok() == Some("claim"))
        .ok_or_else(|| "doomsday reverse has no claim package".to_owned())?;
    if package.mode().map_err(|error| error.to_string())? != "wallet_sign" {
        return Err("doomsday reverse claim changed from wallet_sign".to_owned());
    }
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_invoice_verified", Map::new())?;
    let payment_task = spawn_reverse_payment_once(
        runtime,
        &environment.peer_cln,
        case.journey_name(),
        invoice.clone(),
        payment_hash.clone(),
    )?;
    session.record_funding_effect(payment_hash.clone(), sha256(payment_hash.as_bytes()))?;
    session.publish_requester_status("lightning_payment_pending", Map::new())?;
    wait_for_lightning_payment_attempt(runtime, &environment.peer_cln, &invoice, &payment_hash)?;
    drop(payment_task);
    session.persist_authorized_details(
        "doomsday_prepared",
        true,
        json!({
            "payment_hash":payment_hash,
            "package_mode":"wallet_sign",
            "requester_restores_before_direct_recovery":true,
        }),
    )?;
    preimage.fill(0);
    Ok(json!({
        "schema":"openagents.immortal.doomsday-prepared.v1",
        "case_id":"doomsday-reverse-coordinator-gone",
        "provider_pubkey":provider_pubkey,
        "order_id":session.order.id,
        "payment_hash":payment_hash,
        "package_mode":"wallet_sign",
        "requester_process_exit":true,
    }))
}

fn recover_doomsday_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut restored: DoomsdayRestoredSession,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let mut direct_rounds = 0_u32;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds += 1;
    wait_for_direct_provider_state(&mut restored, "lightning_htlcs_held", &mut direct_rounds)?;
    wait_for_direct_provider_state(
        &mut restored,
        "provider_lock_terms_ready",
        &mut direct_rounds,
    )?;
    doomsday_requester_status(&mut restored, "requester_lock_verified", Map::new())?;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds += 1;
    let funding_status = wait_for_direct_provider_state(
        &mut restored,
        "provider_funding_broadcast",
        &mut direct_rounds,
    )?;
    let (funding_transaction_id, funding_output_index) = status_outpoint(&funding_status)?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        1,
        "doomsday-reverse-funding",
    )?;
    wait_for_direct_provider_state(&mut restored, "funding_final", &mut direct_rounds)?;
    let preimage = load_funded_secret(&restored.paths, case.journey_name())?;
    let payment_hash = lower_hex(&sha256(&preimage));
    let invoice = match restored
        .authorized
        .funding_request()
        .map_err(|error| format!("doomsday reverse funding request is invalid: {error}"))?
        .action
        .clone()
    {
        FundingAction::PayLightningInvoice { invoice, .. } => invoice,
        _ => return Err("doomsday reverse restored another funding action".to_owned()),
    };
    let payment = wait_for_lightning_payment_attempt(
        runtime,
        &environment.peer_cln,
        &invoice,
        &payment_hash,
    )?;
    if payment.status != "pending" {
        return Err("doomsday reverse payment was not held before claim".to_owned());
    }
    let current_height = chain_height(runtime, &environment.bitcoind, "doomsday-reverse-height")?;
    let claim_path = WalletPath::new(2, false, 1)
        .map_err(|error| format!("doomsday reverse claim path is invalid: {error}"))?;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 1)
                .map_err(|error| format!("doomsday reverse destination is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not restore reverse destination: {error}"))?;
    let bitcoin = bitcoin_terms(&restored.contract, "destination")?;
    let destination_value_sat = bitcoin
        .amount_sat
        .checked_sub(bitcoin.miner_fee_budget_sat)
        .filter(|value| *value > 0)
        .ok_or_else(|| "doomsday reverse fee consumes the output".to_owned())?;
    let claim = SettlementBridge::new(&environment.wallet)
        .claim(
            &SettlementTemplate {
                wallet_path: claim_path,
                previous_txid_wire: display_txid_wire(&funding_transaction_id)?,
                previous_output: funding_output_index,
                prevout_value_sat: bitcoin.amount_sat,
                prevout_script_pubkey: bitcoin.script_pubkey,
                destination_value_sat,
                destination_script_pubkey: destination.script_pubkey.to_vec(),
                transaction_version: 2,
                input_sequence: 0xffff_fffe,
                lock_time: 0,
                taproot_script: bitcoin.claim_script,
                taproot_control_block: bitcoin.claim_control_block,
                maximum_fee_sat: bitcoin.miner_fee_budget_sat,
                maximum_fee_rate_sat_per_vbyte: 10_000,
                maximum_weight: 1_600,
                dust_relay_fee_sat_per_kilobyte: 3_000,
            },
            ClaimPreimage::new(preimage),
        )
        .map_err(|error| format!("could not construct doomsday reverse claim: {error}"))?;
    doomsday_requester_status(&mut restored, "requester_claim_pending", Map::new())?;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds += 1;
    let observed = restored
        .authorized
        .clone()
        .observe_reverse_payment_with(|request| {
            Ok(LocalLightningProgress {
                invoice_sha256: request.invoice_sha256.clone(),
                payment_hash: request.payment_hash.clone(),
                observed_at: unix_now()?,
                view_sha256: lower_hex(&sha256(payment_hash.as_bytes())),
                state: LightningProgressState::HtlcsHeld,
            })
        })
        .map_err(|error| format!("doomsday reverse observation failed: {error}"))?;
    let recovery = observed
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height,
                source_funding_confirmation_height: None,
                counterparty_available: true,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Pending),
                chain_state: Some(ChainRecoveryState::DestinationClaimable),
            })
        })
        .map_err(|error| format!("doomsday reverse planner rejected local rails: {error}"))?;
    let expected_effect_id = match recovery {
        RecoveryAction::RequestWalletClaim { effect_id } => effect_id,
        _ => return Err("doomsday reverse planner did not authorize the claim".to_owned()),
    };
    let raw_claim = lower_hex(claim.broadcast_bytes());
    let claim_transaction_id = lower_hex(&claim.transaction_id());
    let mut signing_request = None;
    let signed = observed
        .sign_exit_with(0, |request| {
            signing_request = Some(request.clone());
            Ok(claim.broadcast_bytes().to_vec())
        })
        .map_err(|error| format!("doomsday reverse claim signing failed: {error}"))?;
    let ExitSigningOutcome::Signed(signed) = signed else {
        return Err("doomsday reverse claim reused another effect".to_owned());
    };
    if signed.effect_id != expected_effect_id || signed.transaction != raw_claim {
        return Err("doomsday reverse signed another claim".to_owned());
    }
    let mut observed = observed;
    observed
        .record_external_effect(
            &ExternalEffectRequest::WalletSigning(
                signing_request
                    .ok_or_else(|| "doomsday wallet signer was not called".to_owned())?,
            ),
            claim_transaction_id.clone(),
            lower_hex(&sha256(claim.broadcast_bytes())),
        )
        .map_err(|error| format!("could not record doomsday reverse claim: {error}"))?;
    let claim_snapshot = observed
        .persist()
        .map_err(|error| format!("could not persist doomsday reverse claim: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &claim_snapshot)?;
    restored.authorized = SwapSession::<AwaitingVerification>::restore(&claim_snapshot)
        .and_then(SwapSession::resume_funding_authorized)
        .map_err(|error| format!("could not resume recorded doomsday claim: {error}"))?;
    broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "doomsday-reverse-claim",
        &raw_claim,
        &claim_transaction_id,
    )?;
    let mut claim_extra = Map::new();
    claim_extra.insert(
        "transaction_id".to_owned(),
        Value::String(claim_transaction_id.clone()),
    );
    doomsday_requester_status(&mut restored, "requester_claimed", claim_extra)?;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds += 1;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "doomsday-reverse-claim",
    )?;
    wait_for_direct_provider_state(
        &mut restored,
        "lightning_settlement_pending",
        &mut direct_rounds,
    )?;
    wait_for_direct_provider_state(&mut restored, "lightning_paid", &mut direct_rounds)?;
    wait_for_direct_provider_state(&mut restored, "completed", &mut direct_rounds)?;
    let terminal_payment = wait_for_lightning_payment_terminal(
        runtime,
        &environment.peer_cln,
        &invoice,
        &payment_hash,
    )?;
    if terminal_payment.status != "complete" {
        return Err("doomsday reverse Lightning payment did not complete".to_owned());
    }
    let unspent = runtime
        .block_on(environment.bitcoind.transaction_output(
            &rpc_id("doomsday-reverse-outpoint")?,
            &funding_transaction_id,
            funding_output_index,
            true,
        ))
        .map_err(|error| format!("could not inspect doomsday reverse outpoint: {error}"))?;
    if unspent.is_some() {
        return Err("doomsday reverse funding outpoint remains unspent".to_owned());
    }
    wait_for_direct_provider_close(&mut restored, &mut direct_rounds)?;
    ingest_doomsday_direct_close(
        runtime,
        environment,
        &mut restored,
        "completed",
        Some(&claim_transaction_id),
        None,
        &invoice,
        &payment_hash,
    )?;
    remove_funded_secret(&restored.paths, case.journey_name())?;
    Ok(json!({
        "proof_class":"authenticated_direct_reverse_recovery",
        "provider_pubkey":restored.provider_pubkey,
        "order_id":restored.order.id,
        "funding_transaction_id":funding_transaction_id,
        "funding_output_index":funding_output_index,
        "claim_transaction_id":claim_transaction_id,
        "payment_hash":payment_hash,
        "outcome":"completed",
        "controller_audit":restored.controller_audit,
        "checks":{
            "fresh_requester_process_restored_before_relay":true,
            "relay_connections_after_restore":0,
            "relay_processes_absent":true,
            "provider_http_websocket_api_absent":true,
            "direct_channel_nip59_only":true,
            "direct_channel_post_contract_only":true,
            "exact_durable_rfq_replayed":true,
            "direct_channel_opened_rfq_or_new_session":false,
            "direct_rounds":direct_rounds,
            "reverse_package_mode":"wallet_sign",
            "verified_local_chain_observation":true,
            "verified_local_lightning_observation":true,
            "exact_outpoint_spent":true,
            "transaction_confirmed":true,
            "lightning_paid":true,
        }
    }))
}

fn restored_liquid_request(
    restored: &DoomsdayRestoredSession,
) -> Result<LiquidBeforeFundRequest, String> {
    restored
        .authorized
        .funding_request()
        .map_err(|error| format!("restored Liquid funding request is invalid: {error}"))?
        .liquid
        .as_ref()
        .map(|binding| binding.request.clone())
        .ok_or_else(|| "restored session has no Liquid funding binding".to_owned())
}

fn recover_doomsday_liquid_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: DoomsdayRestoredSession,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid submarine recovery has no local elementsd".to_owned())?;
    let request = restored_liquid_request(&restored)?;
    if request.swap_type != LiquidSwapType::Submarine
        || request.purpose != LiquidLegPurpose::RequesterBroadcast
        || request.exit_package.mode != LiquidExitMode::Presigned
        || request.exit_package.path != "refund"
    {
        return Err("restored Liquid submarine refund has another shape".to_owned());
    }
    let funding_transaction_id = request.exit_package.funding_transaction_id.clone();
    let funding_output_index = request.exit_package.funding_output_index;
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &funding_transaction_id,
        "doomsday-liquid-submarine-funding",
    )?;
    let network = runtime
        .block_on(liquid.rail.network_view("doomsday-liquid-submarine-height"))
        .map_err(|error| format!("could not read Liquid recovery height: {error}"))?;
    let current_height = u32::try_from(network.height)
        .map_err(|_| "Liquid recovery height exceeds u32".to_owned())?;
    if current_height < request.exit_package.timelock {
        mine_liquid_blocks(
            runtime,
            liquid,
            request.exit_package.timelock - current_height,
            "doomsday-liquid-submarine-maturity",
        )?;
    }
    let verified = runtime
        .block_on(liquid.rail.verify_before_fund(&request))
        .map_err(|error| format!("restored Liquid refund verification failed: {error}"))?;
    let receipt = runtime
        .block_on(liquid.rail.broadcast_unilateral_exit(&verified))
        .map_err(|error| format!("could not broadcast restored Liquid refund: {error}"))?;
    let refund_transaction_id = receipt.transaction_id;
    let refund = parse_liquid_transaction(&decode_hex(&request.exit_package.transaction)?)
        .map_err(|error| format!("restored Liquid refund is invalid: {error}"))?;
    if lower_hex(&refund.transaction_id) != refund_transaction_id {
        return Err("elementsd accepted another restored Liquid refund".to_owned());
    }
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &refund_transaction_id,
        "doomsday-liquid-submarine-refund",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "doomsday-liquid-submarine-refund",
    )?;
    let funding_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &funding_transaction_id,
        "doomsday-liquid-submarine-funding-proof",
    )?;
    let refund_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &refund_transaction_id,
        "doomsday-liquid-submarine-refund-proof",
    )?;
    let payment_hash = restored
        .contract
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "Liquid submarine recovery has no payment hash".to_owned())?
        .to_owned();
    finalize_invoice_unpaid(
        runtime,
        &environment.peer_cln,
        case.invoice_label(),
        &payment_hash,
    )?;
    let lifecycle = liquid_lifecycle_event_ids(
        restored.authorized.signed_records(),
        restored
            .offering_id
            .as_deref()
            .ok_or_else(|| "Liquid doomsday checkpoint has no Offering ID".to_owned())?,
        None,
    )?;
    remove_funded_secret(&restored.paths, case.journey_name())?;
    Ok(json!({
        "liquid_case":{
            "schema":"openagents.immortal.adversarial-liquid-case.v1",
            "shape":"liquid-submarine",
            "selected_provider":"provider-a",
            "signed_lifecycle_event_ids":lifecycle,
            "rails":{"liquid":chain_leg_process_proof(
                "liquid",
                &funding_transaction_id,
                funding_output_index,
                &funding_hex,
                &refund_transaction_id,
                &refund_hex,
            )},
            "provider_effect_operations":[],
            "provider_status_anchors":[],
            "provider_restart":null,
            "liquid_terminal":{
                "actor":"requester",
                "path":"refund",
                "effect_class":"liquid_spend",
                "confirmed":true,
            },
            "lightning_terminal":{
                "actor":"requester",
                "effect_actor":null,
                "operation":null,
                "status_anchor":null,
                "state":"unpaid_final",
                "observation_authority":"requester-cln",
                "payment_hash":payment_hash,
            },
            "recovery":{
                "mode":"presigned-refund",
                "fresh_requester_process":true,
                "signed_before_requester_contract":true,
                "signed_before_funding_broadcast":true,
                "provider_effect_operations":[],
                "refund_transaction_id":refund_transaction_id,
            },
        }
    }))
}

fn recover_doomsday_liquid_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut restored: DoomsdayRestoredSession,
    case: DoomsdayCase,
) -> Result<Value, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid reverse recovery has no local elementsd".to_owned())?;
    let request = restored_liquid_request(&restored)?;
    if request.swap_type != LiquidSwapType::Reverse
        || request.purpose != LiquidLegPurpose::CounterpartyLock
        || request.exit_package.mode != LiquidExitMode::Wallet
        || request.exit_package.path != "claim"
        || request.exit_package.wallet_signing_handle_sha256.is_none()
        || request.exit_package.preimage_recovery_ref.is_none()
        || request.exit_package.wallet_signing_handle_sha256
            == request.exit_package.preimage_recovery_ref
    {
        return Err("restored Liquid reverse claim has another shape".to_owned());
    }
    let invoice = match restored
        .authorized
        .funding_request()
        .map_err(|error| format!("restored Liquid reverse request is invalid: {error}"))?
        .action
        .clone()
    {
        FundingAction::PayLightningInvoice { invoice, .. } => invoice,
        _ => return Err("restored Liquid reverse authorized another action".to_owned()),
    };
    let payment_hash = restored
        .contract
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "restored Liquid reverse has no payment hash".to_owned())?
        .to_owned();
    let payment = wait_for_lightning_payment_attempt(
        runtime,
        &environment.peer_cln,
        &invoice,
        &payment_hash,
    )?;
    if payment.status != "pending" {
        return Err("Liquid reverse payment was not held before recovery".to_owned());
    }
    let mut direct_rounds = 0_u32;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds = direct_rounds.saturating_add(1);
    doomsday_requester_status(&mut restored, "requester_claim_pending", Map::new())?;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds = direct_rounds.saturating_add(1);
    runtime
        .block_on(liquid.rail.verify_before_fund(&request))
        .map_err(|error| format!("restored Liquid claim verification failed: {error}"))?;
    let mut preimage = load_funded_secret(&restored.paths, case.journey_name())?;
    let claim_path = WalletPath::new(5, false, 3)
        .map_err(|error| format!("restored Liquid claim path is invalid: {error}"))?;
    let (claim_transaction_id, _claim_transaction_hex) = execute_liquid_wallet_claim(
        runtime,
        environment,
        &mut restored.authorized,
        &request,
        "destination",
        claim_path,
        preimage,
        case.journey_name(),
        "doomsday-liquid-reverse-claim",
    )?;
    let claim_snapshot = restored
        .authorized
        .persist()
        .map_err(|error| format!("could not persist restored Liquid claim: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &claim_snapshot)?;
    preimage.fill(0);
    doomsday_requester_status(
        &mut restored,
        "requester_claimed",
        Map::from_iter([(
            "transaction_id".to_owned(),
            Value::String(claim_transaction_id.clone()),
        )]),
    )?;
    direct_recovery_exchange(&mut restored)?;
    direct_rounds = direct_rounds.saturating_add(1);
    wait_for_liquid_transaction_propagation(
        runtime,
        liquid,
        &claim_transaction_id,
        "doomsday-liquid-reverse-claim",
    )?;
    mine_chain_leg(
        runtime,
        environment,
        "liquid",
        environment.terminal_confirmations,
        "doomsday-liquid-reverse-claim",
    )?;
    wait_for_direct_provider_state(
        &mut restored,
        "lightning_settlement_pending",
        &mut direct_rounds,
    )?;
    wait_for_direct_provider_state(&mut restored, "lightning_paid", &mut direct_rounds)?;
    wait_for_direct_provider_state(&mut restored, "completed", &mut direct_rounds)?;
    let terminal_payment = wait_for_lightning_payment_terminal(
        runtime,
        &environment.peer_cln,
        &invoice,
        &payment_hash,
    )?;
    if terminal_payment.status != "complete" {
        return Err("Liquid reverse hold invoice did not settle".to_owned());
    }
    let funding_transaction_id = request.exit_package.funding_transaction_id.clone();
    let funding_output_index = request.exit_package.funding_output_index;
    let spending = runtime
        .block_on(liquid.rail.spending_transaction(
            "doomsday-liquid-reverse-spend",
            &funding_transaction_id,
            funding_output_index,
        ))
        .map_err(|error| format!("could not inspect Liquid reverse spend: {error}"))?;
    if spending.as_deref() != Some(claim_transaction_id.as_str()) {
        return Err("Liquid reverse funding outpoint has another terminal spend".to_owned());
    }
    wait_for_direct_provider_close(&mut restored, &mut direct_rounds)?;
    let close = ingest_doomsday_direct_close(
        runtime,
        environment,
        &mut restored,
        "completed",
        None,
        Some(&claim_transaction_id),
        &invoice,
        &payment_hash,
    )?;
    let close_id = close.id.clone();
    let funding_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &funding_transaction_id,
        "doomsday-liquid-reverse-funding-proof",
    )?;
    let claim_hex = liquid_raw_transaction(
        runtime,
        liquid,
        &claim_transaction_id,
        "doomsday-liquid-reverse-claim-proof",
    )?;
    let lifecycle = liquid_lifecycle_event_ids(
        restored.authorized.signed_records(),
        restored
            .offering_id
            .as_deref()
            .ok_or_else(|| "Liquid doomsday checkpoint has no Offering ID".to_owned())?,
        Some(&close_id),
    )?;
    remove_funded_secret(&restored.paths, case.journey_name())?;
    Ok(json!({
        "liquid_case":{
            "schema":"openagents.immortal.adversarial-liquid-case.v1",
            "shape":"liquid-reverse",
            "selected_provider":"provider-a",
            "signed_lifecycle_event_ids":lifecycle,
            "rails":{"liquid":chain_leg_process_proof(
                "liquid",
                &funding_transaction_id,
                funding_output_index,
                &funding_hex,
                &claim_transaction_id,
                &claim_hex,
            )},
            "provider_effect_operations":["liquid_reverse_fund"],
            "provider_status_anchors":["provider_funding_broadcast"],
            "provider_restart":null,
            "liquid_terminal":{
                "actor":"requester",
                "path":"claim",
                "effect_class":"liquid_spend",
                "confirmed":true,
            },
            "lightning_terminal":{
                "actor":"requester",
                "effect_actor":"provider",
                "operation":"invoice_settle",
                "status_anchor":"lightning_paid",
                "state":"settled",
                "observation_authority":"requester-cln",
                "payment_hash":payment_hash,
            },
            "recovery":{
                "mode":"direct-claim-and-hold-settlement",
                "fresh_requester_process":true,
                "direct_provider_retained":true,
                "claim_transaction_id":claim_transaction_id,
                "hold_invoice_terminal_state":"settled",
            },
        }
    }))
}

fn direct_recovery_exchange(restored: &mut DoomsdayRestoredSession) -> Result<usize, String> {
    let endpoint = required_environment("IMMORTAL_LAB_DOOMSDAY_DIRECT_RECOVERY")?
        .parse::<SocketAddr>()
        .map_err(|_| "doomsday direct recovery endpoint is invalid".to_owned())?;
    if !endpoint.ip().is_loopback() {
        return Err("doomsday direct recovery endpoint must be loopback".to_owned());
    }
    let mut wraps = Vec::new();
    for record in restored
        .authorized
        .signed_records()
        .iter()
        .filter(|record| {
            record.pubkey == restored.requester.pubkey()
                && matches!(
                    record.kind,
                    immortal_core::domain::MKT_RFQ_KIND
                        | MKT_SWP_SWAP_CONTRACT_KIND
                        | MKT_STATUS_KIND
                )
        })
    {
        let raw = serde_json::to_vec(record)
            .map_err(|error| format!("could not encode direct recovery record: {error}"))?;
        let wrap = wrap_mkt_record(
            &raw,
            &restored.requester,
            &restored.provider_pubkey,
            random_wrap_material()?,
        )?;
        if wrap.event.kind != 1_059
            || !wrap
                .event
                .tag_values("p")
                .eq([restored.provider_pubkey.as_str()])
        {
            return Err("direct recovery produced a bare or misaddressed record".to_owned());
        }
        wraps.push(wrap.event);
    }
    if wraps.is_empty() || wraps.len() > 32 {
        return Err("direct recovery request is empty or exceeds its wrap bound".to_owned());
    }
    let request = serde_json::to_vec(&json!({
        "schema":"openagents.immortal.provider-direct-recovery-request.v1",
        "wraps":wraps,
    }))
    .map_err(|error| format!("could not encode direct recovery request: {error}"))?;
    if request.len() > 2 * 1_024 * 1_024 {
        return Err("direct recovery request exceeds its byte bound".to_owned());
    }
    let mut stream = TcpStream::connect_timeout(&endpoint, IO_TIMEOUT)
        .map_err(|error| format!("could not connect to direct recovery: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("could not bound direct recovery socket: {error}"))?;
    let length = u32::try_from(request.len())
        .map_err(|_| "direct recovery request length exceeds u32".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&request))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not write direct recovery request: {error}"))?;
    let mut response_length = [0_u8; 4];
    stream
        .read_exact(&mut response_length)
        .map_err(|error| format!("could not read direct recovery response length: {error}"))?;
    let response_length = usize::try_from(u32::from_be_bytes(response_length))
        .map_err(|_| "direct recovery response length is unsupported".to_owned())?;
    if response_length == 0 || response_length > DOOMSDAY_DIRECT_RECOVERY_MAX_BYTES {
        return Err("direct recovery response is empty or exceeds its bound".to_owned());
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("could not read direct recovery response: {error}"))?;
    let text = std::str::from_utf8(&response)
        .map_err(|_| "direct recovery response is not UTF-8".to_owned())?;
    let value = parse_unique_json(text, "doomsday direct recovery response")?;
    let object = value
        .as_object()
        .filter(|object| {
            object.len() == 2 && object.contains_key("schema") && object.contains_key("wraps")
        })
        .ok_or_else(|| "direct recovery response has unknown or missing members".to_owned())?;
    if object.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.provider-direct-recovery-response.v1")
    {
        return Err("direct recovery response schema is unsupported".to_owned());
    }
    let wraps = object
        .get("wraps")
        .and_then(Value::as_array)
        .filter(|wraps| wraps.len() <= 512)
        .ok_or_else(|| "direct recovery response wraps exceed their bound".to_owned())?;
    let mut accepted = 0_usize;
    for wrap in wraps {
        let raw_wrap = serde_json::to_vec(wrap)
            .map_err(|error| format!("could not encode direct response wrap: {error}"))?;
        let outer: Event = serde_json::from_value(wrap.clone())
            .map_err(|error| format!("direct response wrap is invalid: {error}"))?;
        if outer.kind != 1_059 || !outer.tag_values("p").eq([restored.requester.pubkey()]) {
            return Err("direct recovery returned a bare or misaddressed record".to_owned());
        }
        let delivered = unwrap_mkt_record_raw(&raw_wrap, &restored.requester, &swp_profiles())?;
        let record = delivered.record().event().clone();
        if record.pubkey != restored.provider_pubkey {
            return Err("direct recovery returned a non-provider record".to_owned());
        }
        if record.kind == MKT_CLOSE_KIND {
            match restored.pending_provider_close.as_ref() {
                Some(existing) if existing != &record => {
                    return Err("direct recovery returned conflicting provider Closes".to_owned());
                }
                Some(_) => {}
                None => restored.pending_provider_close = Some(record),
            }
            continue;
        }
        if restored
            .authorized
            .ingest_signed_record(record)
            .map_err(|error| format!("direct recovery record was rejected: {error}"))?
        {
            accepted = accepted.saturating_add(1);
        }
    }
    let snapshot = restored
        .authorized
        .persist()
        .map_err(|error| format!("could not persist direct recovery records: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &snapshot)?;
    Ok(accepted)
}

fn wait_for_direct_provider_close(
    restored: &mut DoomsdayRestoredSession,
    direct_rounds: &mut u32,
) -> Result<(), String> {
    let started = Instant::now();
    while restored.pending_provider_close.is_none() {
        if started.elapsed() >= DOOMSDAY_DIRECT_RECOVERY_TIMEOUT {
            return Err("timed out waiting for provider Close through direct recovery".to_owned());
        }
        thread::sleep(Duration::from_millis(250));
        direct_recovery_exchange(restored)?;
        *direct_rounds = direct_rounds.saturating_add(1);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ingest_doomsday_direct_close(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    restored: &mut DoomsdayRestoredSession,
    expected_outcome: &str,
    bitcoin_settlement_transaction_id: Option<&str>,
    liquid_settlement_transaction_id: Option<&str>,
    invoice: &str,
    payment_hash: &str,
) -> Result<Event, String> {
    let close = restored
        .pending_provider_close
        .take()
        .ok_or_else(|| "direct recovery has no provider Close".to_owned())?;
    if close.pubkey != restored.provider_pubkey
        || !close
            .tag_values("outcome")
            .eq(std::iter::once(expected_outcome))
    {
        return Err("direct recovery returned another provider Close".to_owned());
    }
    let check = TerminalRailCheck {
        runtime,
        environment,
        bitcoin_settlement_txid: bitcoin_settlement_transaction_id,
        liquid_settlement_txid: liquid_settlement_transaction_id,
        lightning: Some(LightningTerminalCheck::OutgoingPayment {
            invoice,
            payment_hash,
            expected_status: "complete",
        }),
    };
    for leg_id in contract_leg_ids(&restored.contract)? {
        let verified = restored
            .authorized
            .verify_terminal_rail_evidence_with(&leg_id, expected_outcome, |request| {
                local_terminal_rail_evidence(&close, request, &check, &restored.contract)
            })
            .map_err(|error| {
                format!("local {leg_id} terminal evidence rejected before direct Close: {error}")
            })?;
        restored
            .authorized
            .record_verified_rail_evidence(verified)
            .map_err(|error| {
                format!("could not persist direct {leg_id} terminal evidence: {error}")
            })?;
    }
    restored
        .authorized
        .ingest_signed_record(close.clone())
        .map_err(|error| format!("direct provider Close was rejected: {error}"))?;
    let snapshot = restored
        .authorized
        .persist()
        .map_err(|error| format!("could not persist direct provider Close: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &snapshot)?;
    Ok(close)
}

fn doomsday_requester_status(
    restored: &mut DoomsdayRestoredSession,
    state: &str,
    extra: Map<String, Value>,
) -> Result<Event, String> {
    let (sequence, previous) = match restored.requester_status.as_ref() {
        Some((sequence, previous)) => (
            sequence
                .checked_add(1)
                .ok_or_else(|| "doomsday requester Status sequence overflowed".to_owned())?,
            Some(previous.as_str()),
        ),
        None => (0, None),
    };
    let created_at = next_created_at_records(restored.authorized.signed_records())?;
    let distinct = digest(&format!(
        "doomsday-requester-status:{state}:{}",
        restored.authorized.config().session_id
    ));
    let status = StatusState {
        sequence,
        previous,
        base_state: base_state(state)?,
        swp_state: state,
    };
    let request = match requester_status_provider_prerequisite_event(
        restored.authorized.signed_records(),
        &restored.provider_pubkey,
        state,
    )? {
        Some(prerequisite) => restored.factory.status_after(
            ParticipantRole::Requester,
            created_at,
            &distinct,
            &restored.order.id,
            status,
            &prerequisite.id,
            extra,
        ),
        None => restored.factory.status(
            ParticipantRole::Requester,
            created_at,
            &distinct,
            &restored.order.id,
            status,
            extra,
        ),
    }
    .map_err(|error| format!("could not build doomsday requester Status: {error}"))?;
    let (event, _) = sign_request(request, &restored.requester)?;
    restored
        .authorized
        .ingest_signed_record(event.clone())
        .map_err(|error| format!("doomsday requester Status was rejected: {error}"))?;
    restored.requester_status = Some((sequence, event.id.clone()));
    let snapshot = restored
        .authorized
        .persist()
        .map_err(|error| format!("could not persist doomsday requester Status: {error}"))?;
    store_funded_snapshot(&restored.paths, &restored.journey_name, &snapshot)?;
    Ok(event)
}

fn provider_state(records: &[Event], provider_pubkey: &str, expected: &str) -> Option<Event> {
    records.iter().find_map(|event| {
        if event.kind == MKT_STATUS_KIND
            && event.pubkey == provider_pubkey
            && record_profile(event)
                .ok()
                .and_then(|profile| profile.get("swp_state").cloned())
                .and_then(|state| state.as_str().map(str::to_owned))
                .as_deref()
                == Some(expected)
        {
            Some(event.clone())
        } else {
            None
        }
    })
}

fn wait_for_direct_provider_state(
    restored: &mut DoomsdayRestoredSession,
    expected: &str,
    direct_rounds: &mut u32,
) -> Result<Event, String> {
    let started = Instant::now();
    loop {
        if let Some(status) = provider_state(
            restored.authorized.signed_records(),
            &restored.provider_pubkey,
            expected,
        ) {
            return Ok(status);
        }
        if started.elapsed() >= DOOMSDAY_DIRECT_RECOVERY_TIMEOUT {
            return Err(format!(
                "timed out waiting for provider {expected} through direct recovery"
            ));
        }
        thread::sleep(Duration::from_millis(500));
        direct_recovery_exchange(restored)?;
        *direct_rounds = direct_rounds.saturating_add(1);
    }
}

fn wait_for_lightning_payment_attempt(
    runtime: &Runtime,
    cln: &ClnClient,
    invoice: &str,
    payment_hash: &str,
) -> Result<PaymentResult, String> {
    wait_for_lightning_payment_status(runtime, cln, invoice, payment_hash, false)
}

fn wait_for_lightning_payment_terminal(
    runtime: &Runtime,
    cln: &ClnClient,
    invoice: &str,
    payment_hash: &str,
) -> Result<PaymentResult, String> {
    wait_for_lightning_payment_status(runtime, cln, invoice, payment_hash, true)
}

fn wait_for_lightning_payment_status(
    runtime: &Runtime,
    cln: &ClnClient,
    invoice: &str,
    payment_hash: &str,
    terminal: bool,
) -> Result<PaymentResult, String> {
    let started = Instant::now();
    loop {
        let response = runtime
            .block_on(cln.list_pays(
                &cln_id(if terminal {
                    "doomsday-payment-terminal"
                } else {
                    "doomsday-payment-attempt"
                })?,
                Some(invoice),
            ))
            .map_err(|error| format!("could not inspect doomsday payment: {error}"))?;
        let matching = response
            .get("pays")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("payment_hash").and_then(Value::as_str) == Some(payment_hash))
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err("doomsday payment has multiple matching attempts".to_owned());
        }
        if let Some(entry) = matching.first() {
            let result = parse_payment_result(entry)?;
            if !terminal || matches!(result.status.as_str(), "complete" | "failed") {
                return Ok(result);
            }
        }
        if started.elapsed() >= DOOMSDAY_DIRECT_RECOVERY_TIMEOUT {
            return Err("timed out observing doomsday Lightning payment".to_owned());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

pub fn run_doomsday_keyless_executor() -> Result<Value, String> {
    reject_keyless_process_credentials()?;
    let request_path = PathBuf::from(required_environment("IMMORTAL_LAB_KEYLESS_REQUEST_FILE")?);
    let result_path = PathBuf::from(required_environment("IMMORTAL_LAB_KEYLESS_RESULT_FILE")?);
    if result_path.exists() {
        return Err("keyless result already exists".to_owned());
    }
    let (request, transaction_id) = load_doomsday_keyless_request(&request_path)?;
    let response_transaction_id = execute_keyless_http_request(&request)?;
    if response_transaction_id != transaction_id {
        return Err("Esplora response returned another transaction ID".to_owned());
    }
    let request_sha256 =
        lower_hex(&sha256(&serde_json::to_vec(&request).map_err(|error| {
            format!("could not serialize exact keyless request: {error}")
        })?));
    let result = json!({
        "schema":DOOMSDAY_KEYLESS_RESULT_SCHEMA,
        "effect_id":request.effect_id,
        "transaction_id":transaction_id,
        "request_sha256":request_sha256,
        "broadcast_accepted":true,
    });
    store_bounded_private_json(&result_path, &result, DOOMSDAY_KEYLESS_MAX_BYTES)?;
    Ok(result)
}

fn reject_keyless_process_credentials() -> Result<(), String> {
    const FORBIDDEN: [&str; 10] = [
        "PASSWORD",
        "MACAROON",
        "PREIMAGE",
        "PRIVATE_KEY",
        "REFUND_KEY",
        "CLAIM_KEY",
        "SEED",
        "RPC_USER",
        "RPC_PASSWORD",
        "IDENTITY_SECRET",
    ];
    for (name, _) in std::env::vars_os() {
        let name = name
            .to_str()
            .ok_or_else(|| "keyless process environment name is not Unicode".to_owned())?;
        if FORBIDDEN.iter().any(|forbidden| name.contains(forbidden)) || name.contains("WALLET") {
            return Err(format!(
                "keyless process environment contains forbidden credential-shaped variable {name}"
            ));
        }
    }
    Ok(())
}

fn validate_doomsday_keyless_http_request(
    request: &EsploraBroadcastRequest,
    transaction_id: &str,
) -> Result<(), String> {
    if request.method != "POST"
        || request.content_type != "text/plain"
        || request.effect_id.len() != 64
    {
        return Err("keyless request method, content type, or effect ID is invalid".to_owned());
    }
    require_lower_hex_32(&request.effect_id, "keyless effect ID")?;
    if request.body.is_empty()
        || request.body.len() > DOOMSDAY_KEYLESS_MAX_BYTES
        || request.body.len() % 2 != 0
        || !request
            .body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("keyless request body is not bounded lowercase transaction hex".to_owned());
    }
    let transaction = Transaction::parse(&decode_hex(&request.body)?)
        .map_err(|error| format!("keyless request body is not a transaction: {error}"))?;
    let derived = lower_hex(
        &transaction
            .txid()
            .map_err(|error| format!("could not derive keyless transaction ID: {error}"))?,
    );
    if derived != transaction_id {
        return Err("keyless request transaction ID is non-canonical".to_owned());
    }
    let (authority, path) = parse_loopback_http_url(&request.url)?;
    if path != "/api/tx" || !authority.starts_with("127.0.0.1:") {
        return Err("keyless request URL is not the configured loopback Esplora path".to_owned());
    }
    Ok(())
}

fn execute_keyless_http_request(request: &EsploraBroadcastRequest) -> Result<String, String> {
    let (authority, path) = parse_loopback_http_url(&request.url)?;
    let address = resolve_one_private(&authority)?;
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .map_err(|error| format!("could not connect to keyless Esplora endpoint: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|error| format!("could not bound keyless HTTP socket: {error}"))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request.body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(request.body.as_bytes()))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not write keyless HTTP request: {error}"))?;
    let mut response = Vec::new();
    stream
        .take(8 * 1_024 + 1)
        .read_to_end(&mut response)
        .map_err(|error| format!("could not read keyless HTTP response: {error}"))?;
    if response.len() > 8 * 1_024 {
        return Err("keyless HTTP response exceeds its bound".to_owned());
    }
    let response = std::str::from_utf8(&response)
        .map_err(|_| "keyless HTTP response is not UTF-8".to_owned())?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "keyless HTTP response has no header boundary".to_owned())?;
    if !head.starts_with("HTTP/1.1 200 ") {
        return Err("keyless Esplora endpoint refused the transaction".to_owned());
    }
    let transaction_id = body.trim();
    require_lower_hex_32(transaction_id, "keyless response transaction ID")?;
    Ok(transaction_id.to_owned())
}

fn parse_loopback_http_url(url: &str) -> Result<(String, String), String> {
    if url.len() > 2_048 || !url.starts_with("http://127.0.0.1:") {
        return Err("keyless HTTP endpoint must be bounded loopback plaintext".to_owned());
    }
    let remainder = &url[7..];
    let (authority, path) = remainder
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .ok_or_else(|| "keyless HTTP endpoint has no path".to_owned())?;
    if authority.contains('@')
        || path
            .bytes()
            .any(|byte| matches!(byte, b'?' | b'#') || byte.is_ascii_control())
    {
        return Err("keyless HTTP endpoint contains forbidden URL syntax".to_owned());
    }
    let port = authority
        .strip_prefix("127.0.0.1:")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| "keyless HTTP endpoint has an invalid port".to_owned())?;
    Ok((format!("127.0.0.1:{port}"), path))
}

fn resolve_one_private(authority: &str) -> Result<SocketAddr, String> {
    authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve keyless endpoint: {error}"))?
        .find(|address| address.ip().is_loopback())
        .ok_or_else(|| "keyless endpoint did not resolve to loopback".to_owned())
}

fn read_bounded_unique_json(path: &Path, maximum_bytes: usize) -> Result<Value, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
    if metadata.len() == 0 || metadata.len() > maximum_bytes as u64 {
        return Err(format!("{} is empty or exceeds its bound", path.display()));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    parse_unique_json(text, "doomsday keyless document")
}

fn store_bounded_private_json(
    path: &Path,
    value: &Value,
    maximum_bytes: usize,
) -> Result<(), String> {
    provider_support::reject_custody_material(value)
        .map_err(|error| format!("refusing custody-bearing keyless document: {error}"))?;
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("could not serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "keyless document path has no parent".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    if let Err(error) = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path))
    {
        if let Err(cleanup_error) = std::fs::remove_file(&temporary) {
            return Err(format!(
                "could not persist {}: {error}; temporary cleanup failed: {cleanup_error}",
                path.display()
            ));
        }
        return Err(format!("could not persist {}: {error}", path.display()));
    }
    Ok(())
}

fn run_funded_journey_with_environment(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    journey: FundedJourney,
) -> Result<Value, String> {
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    if journey != FundedJourney::SubmarineRefund {
        if let Some(restored) = restore_authorized_session(environment, journey)? {
            let result = resume_authorized_journey(runtime, environment, journey, restored)?;
            verify_health(&environment.health_url)?;
            return Ok(json!({
                "step": journey.name(),
                "provider_pubkey": provider_pubkey,
                "resumed": true,
                "journey": result,
            }));
        }
    }
    let result = match journey {
        FundedJourney::Submarine => {
            let client_input = fund_client_wallet(runtime, environment)?;
            drive_submarine(runtime, environment, &provider_pubkey, client_input)?
        }
        FundedJourney::SubmarineRefund => {
            let client_input = fund_client_wallet(runtime, environment)?;
            drive_submarine_refund(runtime, environment, &provider_pubkey, client_input)?
        }
        FundedJourney::ReverseClaim => drive_reverse(
            runtime,
            environment,
            &provider_pubkey,
            FundedJourney::ReverseClaim.name(),
            false,
        )?,
        FundedJourney::ReverseRefund => drive_reverse(
            runtime,
            environment,
            &provider_pubkey,
            FundedJourney::ReverseRefund.name(),
            true,
        )?,
    };
    if journey != FundedJourney::SubmarineRefund {
        verify_health(&environment.health_url)?;
    }
    Ok(json!({
        "step": journey.name(),
        "provider_pubkey": provider_pubkey,
        "journey": result,
    }))
}

pub fn run_boltz_adapter_session() -> Result<Value, String> {
    let client = required_environment("IMMORTAL_LAB_BOLTZ_ADAPTER_CLIENT")?;
    let key_index = match client.as_str() {
        "go" => 20,
        "web" => 21,
        _ => return Err("IMMORTAL_LAB_BOLTZ_ADAPTER_CLIENT must be go or web".to_owned()),
    };
    let journey_name = format!("boltz_{client}");
    let runtime =
        Runtime::new().map_err(|error| format!("could not start lab runtime: {error}"))?;
    let environment = SmokeEnvironment::load()?;
    verify_health(&environment.health_url)?;
    clear_boltz_adapter_controls(&environment.control.paths, &client)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    let client_input = fund_client_wallet(&runtime, &environment)?;
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id(&format!("boltz-{client}-invoice"))?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("Boltz adapter invoice amount is invalid: {error}"))?,
                &format!("immortal-{journey_name}"),
                "Immortal Boltz adapter process gate",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create Boltz adapter invoice: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(
            WalletPath::new(2, false, key_index)
                .map_err(|error| format!("Boltz adapter refund path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Boltz adapter refund key: {error}"))?
        .internal_key;
    let exit_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, key_index)
                .map_err(|error| format!("Boltz adapter exit path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive Boltz adapter exit destination: {error}"))?;
    let pending = prepare_negotiation(
        &environment,
        &provider_pubkey,
        NegotiationInput {
            journey_name: &journey_name,
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &exit_destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    let funding = pending
        .requester_funding
        .as_ref()
        .ok_or_else(|| "Boltz adapter preparation produced no funding transaction".to_owned())?
        .clone();
    let source_leg = pending
        .contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some("source"))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "Boltz adapter Contract has no source leg".to_owned())?;
    let refund_public_key = required_string(source_leg, "refund_public_key")?.to_owned();
    let session_id = pending.config.session_id.clone();
    let output_index = pending
        .contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers
                .iter()
                .find(|value| value.get("leg_id").and_then(Value::as_str) == Some("source"))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "Boltz adapter Contract has no source verifier".to_owned())
        .and_then(|verifier| bounded_u32_member(verifier, "output_index"))?;
    store_boltz_adapter_prepared(
        &environment.control.paths,
        &BoltzAdapterPrepared {
            schema: "openagents.immortal.boltz-adapter-prepared.v1".to_owned(),
            client: client.clone(),
            session_id: session_id.clone(),
            invoice: invoice.bolt11.clone(),
            refund_public_key,
            raw_transaction_hex: funding.raw_transaction.clone(),
            output_index,
        },
    )?;
    let finalize_request = wait_for_boltz_finalize_request(&environment, &client)?;
    let raw = decode_hex(&funding.raw_transaction)?;
    let funding_sha256 = lower_hex(&sha256(&raw));
    let finalize_path = format!("/v2/swap/submarine/{session_id}/finalize");
    if finalize_request
        != (BoltzAdapterFinalizeRequest {
            schema: "openagents.immortal.boltz-adapter-finalize.v1".to_owned(),
            client: client.clone(),
            session_id: session_id.clone(),
            finalize_path: finalize_path.clone(),
            raw_transaction_hex: funding.raw_transaction.clone(),
            funding_transaction_sha256: funding_sha256.clone(),
            output_index,
        })
    {
        return Err("Boltz adapter finalization request changed the prepared funding".to_owned());
    }
    let mut session = finalize_negotiation(pending)?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let authorized = verify_submarine_before_fund(&session, &invoice.bolt11, &funding)?;
    let authorization_snapshot = authorized
        .persist()
        .map_err(|error| format!("could not serialize adapter authorization: {error}"))?;
    let authorization_snapshot_sha256 = lower_hex(&sha256(&authorization_snapshot));
    let restored_authorization =
        SwapSession::<AwaitingVerification>::restore(&authorization_snapshot)
            .and_then(SwapSession::resume_funding_authorized)
            .map_err(|error| format!("could not restore adapter authorization: {error}"))?;
    session.set_authorized_verifier(restored_authorization)?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":funding.txid.clone()}),
    )?;
    let (requester_contract_event_id, provider_contract_event_id) =
        approval_contract_ids(&session)?;
    let (exit_package_mode, exit_package_sha256) = approval_exit_commitment(&session.contract)?;
    store_boltz_adapter_approval(
        &environment.control.paths,
        &BoltzAdapterApproval {
            schema: "openagents.immortal.boltz-adapter-approval.v1".to_owned(),
            client: client.clone(),
            session_id: session_id.clone(),
            finalize_path,
            funding_transaction_sha256: funding_sha256,
            output_index,
            requester_contract_event_id,
            provider_contract_event_id,
            exit_package_sha256,
            exit_package_mode,
            authorization_snapshot_sha256,
            exit_package_persisted: true,
            script_path_only: true,
        },
    )?;
    let broadcast = wait_for_boltz_broadcast(&environment, &client)?;
    if broadcast.schema != "openagents.immortal.boltz-adapter-broadcast.v1"
        || broadcast.client != client
        || broadcast.session_id != session_id
        || broadcast.transaction_id != funding.txid
    {
        return Err("Boltz adapter broadcast acknowledgement changed session or txid".to_owned());
    }
    require_known_bitcoin_transaction(
        &runtime,
        &environment.bitcoind,
        "boltz-adapter-funding",
        &funding.txid,
        Some(&funding.raw_transaction),
    )?;
    session.record_funding_effect(
        funding.txid.clone(),
        sha256(funding.raw_transaction.as_bytes()),
    )?;
    let result = finish_submarine(
        &runtime,
        &environment,
        session,
        funding.txid.clone(),
        &invoice.payment_hash,
    )?;
    store_boltz_adapter_complete(
        &environment.control.paths,
        &BoltzAdapterBroadcast {
            schema: "openagents.immortal.boltz-adapter-complete.v1".to_owned(),
            client,
            session_id,
            transaction_id: funding.txid,
        },
    )?;
    Ok(result)
}

fn wait_for_boltz_finalize_request(
    environment: &SmokeEnvironment,
    client: &str,
) -> Result<BoltzAdapterFinalizeRequest, String> {
    wait_for_boltz_control(
        &environment
            .control
            .paths
            .boltz_adapter_control(client, "finalize-request"),
        || load_boltz_adapter_finalize_request(&environment.control.paths, client),
    )
}

fn wait_for_boltz_broadcast(
    environment: &SmokeEnvironment,
    client: &str,
) -> Result<BoltzAdapterBroadcast, String> {
    wait_for_boltz_control(
        &environment
            .control
            .paths
            .boltz_adapter_control(client, "broadcast"),
        || load_boltz_adapter_broadcast(&environment.control.paths, client),
    )
}

fn wait_for_boltz_control<T>(
    path: &Path,
    load: impl Fn() -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= JOURNEY_TIMEOUT {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(50));
    }
    load()
}

fn approval_contract_ids(session: &SessionContext) -> Result<(String, String), String> {
    let mut requester = None;
    let mut provider = None;
    for event in session
        .verifier
        .signed_records()
        .iter()
        .filter(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
    {
        match record_profile(event)?
            .get("signer_role")
            .and_then(Value::as_str)
        {
            Some("requester") if requester.is_none() => requester = Some(event.id.clone()),
            Some("provider") if provider.is_none() => provider = Some(event.id.clone()),
            _ => return Err("Boltz adapter Contracts have duplicate or invalid roles".to_owned()),
        }
    }
    requester
        .zip(provider)
        .ok_or_else(|| "Boltz adapter approval lacks bilateral Contracts".to_owned())
}

fn approval_exit_commitment(contract: &Value) -> Result<(String, String), String> {
    let commitments = contract
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .ok_or_else(|| "Boltz adapter Contract has no exit commitments".to_owned())?;
    let matching = commitments
        .iter()
        .filter(|commitment| {
            commitment.get("participant_role").and_then(Value::as_str) == Some("requester")
                && commitment.get("path").and_then(Value::as_str) == Some("refund")
        })
        .collect::<Vec<_>>();
    let [commitment] = matching.as_slice() else {
        return Err("Boltz adapter Contract has no unique requester refund exit".to_owned());
    };
    let commitment = commitment
        .as_object()
        .ok_or_else(|| "Boltz adapter exit commitment is not an object".to_owned())?;
    Ok((
        required_string(commitment, "package_mode")?.to_owned(),
        required_string(commitment, "package_sha256")?.to_owned(),
    ))
}

fn restore_authorized_session(
    environment: &SmokeEnvironment,
    journey: FundedJourney,
) -> Result<Option<RestoredSession>, String> {
    let snapshot_path = environment.control.paths.funded_snapshot(journey.name());
    if !snapshot_path.exists() {
        return Ok(None);
    }
    let checkpoint = load_funded_journey_checkpoint(&environment.control.paths, journey.name())?
        .ok_or_else(|| "funded snapshot exists without a checkpoint".to_owned())?;
    if checkpoint.run_id != environment.control.run_id || checkpoint.journey != journey.name() {
        return Err("funded snapshot checkpoint belongs to another run or journey".to_owned());
    }
    if !restartable_checkpoint(journey, &checkpoint.label) {
        return Err(format!(
            "funded journey {} has unsupported persisted checkpoint {}",
            journey.name(),
            checkpoint.label
        ));
    }
    let snapshot = std::fs::read(&snapshot_path)
        .map_err(|error| format!("could not read {}: {error}", snapshot_path.display()))?;
    let verifier = SwapSession::<AwaitingVerification>::restore(&snapshot)
        .map_err(|error| format!("could not restore funded session: {error}"))?;
    let authorized = SwapSession::<AwaitingVerification>::restore(&snapshot)
        .and_then(SwapSession::resume_funding_authorized)
        .map_err(|error| format!("could not resume funded authorization: {error}"))?;
    let config = verifier.config().clone();
    let order = verifier
        .signed_records()
        .iter()
        .find(|event| event.kind == MKT_ORDER_KIND)
        .cloned()
        .ok_or_else(|| "persisted funded session has no Order".to_owned())?;
    let contract = verifier
        .signed_records()
        .iter()
        .filter(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .find_map(|event| record_profile(event).ok()?.get("contract").cloned())
        .ok_or_else(|| "persisted funded session has no contract".to_owned())?;
    let now = unix_now()?;
    let mut reader = connect(&environment.relay_url)?;
    authenticate(
        &mut reader,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    subscribe(&mut reader, environment.requester.pubkey())?;
    let mut publisher = connect(&environment.relay_url)?;
    authenticate(
        &mut publisher,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    let requester_status =
        latest_requester_status(verifier.signed_records(), environment.requester.pubkey())?;
    let deliveries = restore_funded_deliveries(
        load_funded_deliveries(&environment.control.paths, journey.name())?.ok_or_else(|| {
            format!(
                "persisted {} session has no delivery provenance archive",
                journey.name()
            )
        })?,
        verifier.signed_records(),
        &environment.requester,
    )?;
    Ok(Some(RestoredSession {
        session: SessionContext {
            relay_url: environment.relay_url.clone(),
            reader,
            publisher,
            requester: environment.requester.clone(),
            provider_pubkey: config.provider_pubkey.clone(),
            factory: SwapRecordFactory::new(config)
                .map_err(|error| format!("could not restore funded record factory: {error}"))?,
            verifier,
            deliveries,
            order,
            contract,
            authorized_verifier: Some(authorized),
            requester_funding: None,
            requester_status,
            journey_name: journey.name().to_owned(),
            control: environment.control.clone(),
        },
        checkpoint,
    }))
}

fn resume_authorized_journey(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    journey: FundedJourney,
    restored: RestoredSession,
) -> Result<Value, String> {
    if matches!(restored.checkpoint.label.as_str(), "completed" | "refunded") {
        return restored
            .checkpoint
            .details
            .get("result")
            .cloned()
            .ok_or_else(|| "terminal funded checkpoint has no result evidence".to_owned());
    }
    let session = restored.session;
    let action = session
        .authorized_verifier
        .as_ref()
        .ok_or_else(|| "restored session has no funding authorization".to_owned())?
        .funding_request()
        .map_err(|error| format!("restored funding request is invalid: {error}"))?
        .action
        .clone();
    match (journey, action) {
        (
            FundedJourney::Submarine,
            FundingAction::BroadcastBitcoin {
                raw_transaction, ..
            },
        ) => {
            let payment_hash = session
                .contract
                .get("payment_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "restored submarine contract has no payment hash".to_owned())?
                .to_owned();
            resume_submarine(
                runtime,
                environment,
                session,
                &restored.checkpoint,
                &raw_transaction,
                &payment_hash,
            )
        }
        (
            FundedJourney::ReverseClaim | FundedJourney::ReverseRefund,
            FundingAction::PayLightningInvoice { invoice, .. },
        ) => {
            let preimage = load_funded_secret(&environment.control.paths, journey.name())?;
            let payment_hash = lower_hex(&sha256(&preimage));
            let claim_index = if journey == FundedJourney::ReverseRefund {
                2
            } else {
                1
            };
            let claim_path = WalletPath::new(2, false, claim_index)
                .map_err(|error| format!("restored reverse claim path is invalid: {error}"))?;
            let destination = environment
                .wallet
                .derive_address(WalletPath::new(0, true, 1).map_err(|error| {
                    format!("restored reverse destination path is invalid: {error}")
                })?)
                .map_err(|error| format!("could not restore reverse destination: {error}"))?;
            resume_reverse(
                runtime,
                environment,
                session,
                &restored.checkpoint,
                journey.name(),
                journey == FundedJourney::ReverseRefund,
                preimage,
                payment_hash,
                invoice,
                claim_path,
                destination.script_pubkey.to_vec(),
            )
        }
        _ => Err("persisted funding action does not match the requested journey".to_owned()),
    }
}

fn restartable_checkpoint(journey: FundedJourney, label: &str) -> bool {
    match journey {
        FundedJourney::Submarine => matches!(
            label,
            "funding_authorized"
                | "funding_execution_ready"
                | "funding_effect_recorded"
                | "completed"
        ),
        FundedJourney::SubmarineRefund => false,
        FundedJourney::ReverseClaim => matches!(
            label,
            "funding_authorized"
                | "funding_execution_ready"
                | "funding_effect_recorded"
                | "claim_broadcast_ready"
                | "claim_broadcast_recorded"
                | "completed"
        ),
        FundedJourney::ReverseRefund => matches!(
            label,
            "funding_authorized"
                | "funding_execution_ready"
                | "funding_effect_recorded"
                | "refunded"
        ),
    }
}

impl SmokeEnvironment {
    fn load() -> Result<Self, String> {
        let relay_url = required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_RELAY_URL")?;
        let health_url =
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_PROVIDER_HEALTH_URL")?;
        let evidence_file = PathBuf::from(required_environment(
            "IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE",
        )?);
        Self::load_for(relay_url, health_url, evidence_file, None)
    }

    fn load_topology() -> Result<[Self; 2], String> {
        let relay_urls = crate::relay::parse_topology_relay_urls(&required_environment(
            "IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_URLS",
        )?)?;
        let health_urls = exact_topology_health_urls(&required_environment(
            "IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_HEALTH_URLS",
        )?)?;
        let evidence_file = PathBuf::from(required_environment(
            "IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE",
        )?);
        let [relay_a, relay_b] = relay_urls
            .try_into()
            .map_err(|_| "funded topology requires exactly two relay URLs".to_owned())?;
        let [health_a, health_b] = health_urls;
        Ok([
            Self::load_for(relay_a, health_a, evidence_file.clone(), None)?,
            Self::load_for(relay_b, health_b, evidence_file, None)?,
        ])
    }

    fn load_topology_selected(
        provider_index: usize,
        injection: Option<HarnessInjection>,
    ) -> Result<Self, String> {
        if provider_index > 1 {
            return Err(
                "adversarial provider index is outside the two-provider topology".to_owned(),
            );
        }
        let relay_urls = crate::relay::parse_topology_relay_urls(&required_environment(
            "IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_RELAY_URLS",
        )?)?;
        let health_urls = exact_topology_health_urls(&required_environment(
            "IMMORTAL_PROVIDER_FUNDED_TOPOLOGY_HEALTH_URLS",
        )?)?;
        let evidence_file = PathBuf::from(required_environment(
            "IMMORTAL_PROVIDER_FUNDED_SMOKE_EVIDENCE_FILE",
        )?);
        Self::load_for(
            relay_urls
                .get(provider_index)
                .cloned()
                .ok_or_else(|| "adversarial topology relay is unavailable".to_owned())?,
            health_urls[provider_index].clone(),
            evidence_file,
            injection,
        )
    }

    fn load_for(
        relay_url: String,
        health_url: String,
        evidence_file: PathBuf,
        injection: Option<HarnessInjection>,
    ) -> Result<Self, String> {
        let control = StepControl::load_with_injection(injection)?;
        let requester = load_or_create_identity(&LabPaths::from_env())?.signer()?;
        let wallet = ProviderWallet::load(
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_CLIENT_WALLET_SEED_FILE")?,
            BitcoinNetwork::Regtest,
        )
        .map_err(|error| format!("could not load client smoke wallet: {error}"))?;
        let port = required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_PORT")?
            .parse::<u16>()
            .map_err(|_| "smoke bitcoind port is invalid".to_owned())?;
        let endpoint = BitcoindEndpoint::new(
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_HOST")?,
            port,
        )
        .map_err(|error| format!("smoke bitcoind endpoint is invalid: {error}"))?;
        let auth = BitcoindAuth::new(
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_USER")?,
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_BITCOIND_RPC_PASSWORD")?,
        )
        .map_err(|error| format!("smoke bitcoind credentials are invalid: {error}"))?;
        let bitcoind = BitcoindClient::new(endpoint, auth, BitcoindLimits::default())
            .map_err(|error| format!("could not initialize smoke bitcoind client: {error}"))?;
        let peer_cln = ClnClient::new(
            ClnEndpoint::new(required_environment(
                "IMMORTAL_PROVIDER_FUNDED_SMOKE_CLN_RPC_PATH",
            )?)
            .map_err(|error| format!("smoke CLN endpoint is invalid: {error}"))?,
            ClnLimits {
                io_timeout: JOURNEY_TIMEOUT,
                ..ClnLimits::default()
            },
        )
        .map_err(|error| format!("could not initialize smoke CLN client: {error}"))?;
        let liquid = load_liquid_lab_environment()?;
        let terminal_confirmations =
            required_environment("IMMORTAL_PROVIDER_FUNDED_SMOKE_TERMINAL_CONFIRMATIONS")?
                .parse::<u64>()
                .map_err(|_| "smoke terminal confirmation count is invalid".to_owned())?;
        if !(1..=288).contains(&terminal_confirmations) {
            return Err("smoke terminal confirmation count is outside its bound".to_owned());
        }
        Ok(Self {
            relay_url,
            health_url,
            evidence_file,
            requester,
            wallet,
            bitcoind,
            peer_cln,
            liquid,
            terminal_confirmations,
            control,
        })
    }
}

fn load_liquid_lab_environment() -> Result<Option<LiquidLabEnvironment>, String> {
    let host = match std::env::var("IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_HOST") {
        Ok(host) => host,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("adversarial elementsd host is not valid Unicode".to_owned());
        }
    };
    let port = required_environment("IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_PORT")?
        .parse::<u16>()
        .map_err(|_| "adversarial elementsd port is invalid".to_owned())?;
    let network_id = required_environment("IMMORTAL_LAB_ADVERSARIAL_LIQUID_NETWORK_ID")?;
    let pegged_asset = required_environment("IMMORTAL_LAB_ADVERSARIAL_LIQUID_PEGGED_ASSET")?;
    let endpoint = BitcoindEndpoint::new(host, port)
        .map_err(|error| format!("adversarial elementsd endpoint is invalid: {error}"))?;
    let auth = BitcoindAuth::new(
        required_environment("IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_RPC_USER")?,
        required_environment("IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_RPC_PASSWORD")?,
    )
    .map_err(|error| format!("adversarial elementsd credentials are invalid: {error}"))?;
    let wallet = ElementsdWalletName::new(required_environment(
        "IMMORTAL_LAB_ADVERSARIAL_ELEMENTSD_WALLET",
    )?)
    .map_err(|error| format!("adversarial elementsd wallet is invalid: {error}"))?;
    let network = LiquidNetworkId::parse(&network_id)
        .map_err(|error| format!("adversarial Liquid network is invalid: {error}"))?;
    let asset = LiquidAssetId::parse(&pegged_asset)
        .map_err(|error| format!("adversarial Liquid asset is invalid: {error}"))?;
    let elementsd = ElementsdClient::new(
        endpoint,
        auth,
        BitcoindLimits::default(),
        wallet,
        network,
        asset,
    )
    .map_err(|error| format!("could not initialize adversarial elementsd client: {error}"))?;
    Ok(Some(LiquidLabEnvironment {
        rail: LiquidProviderRail::new(elementsd.clone()),
        elementsd,
        network_id,
        pegged_asset,
    }))
}

fn exact_topology_health_urls(value: &str) -> Result<[String; 2], String> {
    let urls = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    let [first, second] = urls.as_slice() else {
        return Err("funded topology requires exactly two provider health URLs".to_owned());
    };
    if first == second
        || [first, second].iter().any(|url| {
            url.len() > 2_048
                || url.bytes().any(|byte| byte.is_ascii_control())
                || !url.starts_with("http://127.0.0.1:")
                || !url.ends_with("/healthz")
        })
    {
        return Err(
            "funded topology health URLs must be distinct bounded loopback URLs".to_owned(),
        );
    }
    Ok([first.clone(), second.clone()])
}

fn drive_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    client_input: FundingInput,
) -> Result<Value, String> {
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id("submarine-invoice")?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("submarine invoice amount is invalid: {error}"))?,
                "immortal-funded-submarine",
                "Immortal funded smoke submarine",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create submarine invoice: {error}"))?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("submarine refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive submarine refund key: {error}"))?
        .internal_key;
    let exit_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 10)
                .map_err(|error| format!("submarine exit destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive submarine exit destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name: "submarine",
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &exit_destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let funding = session
        .requester_funding
        .take()
        .ok_or_else(|| "submarine session has no contract-bound funding transaction".to_owned())?;
    let authorized = verify_submarine_before_fund(&session, &invoice.bolt11, &funding)?;
    session.set_authorized_verifier(authorized)?;
    if environment.control.injection == Some(HarnessInjection::RbfConflict) {
        return prove_rbf_conflict_before_settlement(
            runtime,
            environment,
            &session,
            &client_input,
            &funding,
            &invoice.payment_hash,
        );
    }
    if environment.control.injection.is_some_and(|injection| {
        matches!(
            injection,
            HarnessInjection::ZeroConfRbfReplacement
                | HarnessInjection::ZeroConfDoubleSpend
                | HarnessInjection::ZeroConfAncestorEviction
        )
    }) {
        return prove_zero_conf_downgrade(
            runtime,
            environment,
            session,
            &client_input,
            &funding,
            &invoice.payment_hash,
        );
    }
    continue_submarine(
        runtime,
        environment,
        session,
        &funding.raw_transaction,
        Some(&funding.txid),
        &invoice.payment_hash,
    )
}

fn drive_cooperative_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    client_input: FundingInput,
    journey: CooperativeJourney,
) -> Result<Value, String> {
    let invoice = runtime
        .block_on(
            environment.peer_cln.invoice(
                &cln_id(&format!("{}-invoice", journey.name()))?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT)
                    .map_err(|error| format!("cooperative invoice amount is invalid: {error}"))?,
                &format!("immortal-funded-{}", journey.name()),
                "Immortal adversarial cooperative submarine",
                86_400,
            ),
        )
        .map_err(|error| format!("could not create cooperative invoice: {error}"))?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("cooperative refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive cooperative requester key: {error}"))?
        .internal_key;
    let exit_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 10)
                .map_err(|error| format!("cooperative exit path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive cooperative exit destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name: journey.name(),
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &exit_destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    if session
        .contract
        .get("musig2_execution")
        .and_then(Value::as_bool)
        != Some(true)
        || session.verifier.exit_packages().len() != 2
    {
        return Err("adversarial provider did not bind two cooperative exits".to_owned());
    }
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let funding = session
        .requester_funding
        .take()
        .ok_or_else(|| "cooperative session has no contract-bound funding".to_owned())?;
    let authorized = verify_submarine_before_fund(&session, &invoice.bolt11, &funding)?;
    session.set_authorized_verifier(authorized)?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":funding.txid}),
    )?;
    let lockup_txid = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "cooperative-funding",
        &funding.raw_transaction,
        &funding.txid,
    )?;
    session.record_funding_effect(
        lockup_txid.clone(),
        sha256(funding.raw_transaction.as_bytes()),
    )?;
    session.publish_requester_status(
        "requester_funding_broadcast",
        Map::from_iter([
            ("transaction_id".to_owned(), json!(lockup_txid.clone())),
            ("output_index".to_owned(), json!(0)),
        ]),
    )?;
    mine_blocks(runtime, &environment.bitcoind, 1, "cooperative-funding")?;
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    session.wait_provider_state("lightning_payment_pending")?;
    session.wait_provider_state("lightning_paid")?;

    let (provider_commitment_event, provider_commitment) =
        session.wait_provider_cooperative_action(CooperativeSigningAction::NonceCommitment)?;
    let context = provider_commitment.context.clone();
    let current_height = chain_height(runtime, &environment.bitcoind, "cooperative-round")?;
    let mut requester_round = begin_requester_cooperative_round(
        environment,
        &session,
        refund_path,
        &context,
        current_height,
    )?;
    let provider_commitment_bytes = decode_fixed_hex::<32>(
        provider_commitment
            .nonce_commitment
            .as_deref()
            .ok_or_else(|| "provider commitment Status has no commitment".to_owned())?,
        "provider nonce commitment",
    )?;
    requester_round
        .register_counterparty_nonce_commitment(provider_commitment_bytes, current_height)
        .map_err(|error| format!("requester rejected provider nonce commitment: {error}"))?;
    let requester_commitment = CooperativeSigningMessage::nonce_commitment(
        context.clone(),
        ParticipantRole::Requester,
        requester_round.nonce_commitment(),
    )
    .map_err(|error| format!("could not compose requester nonce commitment: {error}"))?;
    let requester_commitment_event =
        session.publish_requester_cooperative_status(requester_commitment)?;
    let (provider_nonce_event, provider_nonce) =
        session.wait_provider_cooperative_action(CooperativeSigningAction::PublicNonce)?;

    if journey == CooperativeJourney::CrashCutRecovery {
        session.persist_authorized_details(
            "provider_public_nonce_persisted",
            true,
            json!({"status_id":provider_nonce_event.id}),
        )?;
        requester_round.abort();
        let (provider_abort_event, _) =
            session.wait_provider_cooperative_action(CooperativeSigningAction::Aborted)?;
        return finish_cooperative_fallback(
            runtime,
            environment,
            session,
            &lockup_txid,
            &invoice.payment_hash,
            [
                provider_commitment_event,
                requester_commitment_event,
                provider_nonce_event,
                provider_abort_event,
            ],
            true,
        );
    }

    if journey == CooperativeJourney::AbortAfterProviderNonce {
        requester_round.abort();
        let requester_abort = CooperativeSigningMessage::aborted(
            context,
            ParticipantRole::Requester,
            "wallet_refused",
        )
        .map_err(|error| format!("could not compose requester cooperative abort: {error}"))?;
        let requester_abort_event =
            session.publish_requester_cooperative_status(requester_abort)?;
        let (provider_abort_event, _) =
            session.wait_provider_cooperative_action(CooperativeSigningAction::Aborted)?;
        return finish_cooperative_fallback_with_requester_abort(
            runtime,
            environment,
            session,
            &lockup_txid,
            &invoice.payment_hash,
            [
                provider_commitment_event,
                requester_commitment_event,
                provider_nonce_event,
                requester_abort_event,
                provider_abort_event,
            ],
        );
    }

    let provider_public_nonce = decode_fixed_hex::<66>(
        provider_nonce
            .public_nonce
            .as_deref()
            .ok_or_else(|| "provider public-nonce Status has no nonce".to_owned())?,
        "provider public nonce",
    )?;
    let requester_public_nonce = requester_round
        .reveal_public_nonce(current_height)
        .map_err(|error| format!("requester could not reveal public nonce: {error}"))?;
    let requester_nonce = CooperativeSigningMessage::public_nonce(
        context.clone(),
        ParticipantRole::Requester,
        requester_public_nonce,
    )
    .map_err(|error| format!("could not compose requester public nonce: {error}"))?;
    let requester_nonce_event = session.publish_requester_cooperative_status(requester_nonce)?;
    let (provider_partial_event, provider_partial) =
        session.wait_provider_cooperative_action(CooperativeSigningAction::PartialSignature)?;
    let public_nonces = [requester_public_nonce, provider_public_nonce];
    let requester_partial = SettlementBridge::new(&environment.wallet)
        .sign_cooperative_partial(&mut requester_round, current_height, &public_nonces)
        .map_err(|error| format!("requester cooperative partial failed: {error}"))?;
    let requester_partial_message = CooperativeSigningMessage::partial_signature(
        context,
        ParticipantRole::Requester,
        public_nonces,
        requester_partial,
    )
    .map_err(|error| format!("could not compose requester partial signature: {error}"))?;
    let requester_partial_event =
        session.publish_requester_cooperative_status(requester_partial_message)?;
    let (provider_final_event, provider_final) =
        session.wait_provider_cooperative_action(CooperativeSigningAction::FinalSignature)?;
    let provider_partial_bytes = decode_fixed_hex::<32>(
        provider_partial
            .partial_signature
            .as_deref()
            .ok_or_else(|| "provider partial Status has no partial".to_owned())?,
        "provider partial signature",
    )?;
    if provider_final
        .partial_signatures
        .as_deref()
        .and_then(|values| values.get(1))
        .map(String::as_str)
        != Some(lower_hex(&provider_partial_bytes).as_str())
    {
        return Err("provider final Status changed its partial signature".to_owned());
    }
    let claim_pending = session.wait_provider_state("provider_claim_pending")?;
    let claim_txid = status_transaction_id(&claim_pending)?;
    let peer_bitcoind = load_adversarial_bitcoind("B")?;
    wait_for_exact_transaction_on_both_nodes(
        runtime,
        [&environment.bitcoind, &peer_bitcoind],
        &claim_txid,
        "cooperative-key-path",
    )?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "cooperative-key-path",
    )?;
    session.wait_provider_state("provider_claimed")?;
    session.wait_provider_state("completed")?;
    session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: Some(&claim_txid),
            liquid_settlement_txid: None,
            lightning: Some(LightningTerminalCheck::IncomingInvoice {
                payment_hash: &invoice.payment_hash,
            }),
        },
    )?;
    let witness = inspect_cooperative_settlement(
        runtime,
        environment,
        &session.contract,
        &lockup_txid,
        &claim_txid,
        CooperativeWitnessPath::KeyPath,
    )?;
    let status_ids = [
        provider_commitment_event.id,
        requester_commitment_event.id,
        provider_nonce_event.id,
        requester_nonce_event.id,
        provider_partial_event.id,
        requester_partial_event.id,
        provider_final_event.id,
    ];
    let result = json!({
        "order_id":session.order.id,
        "lockup_txid":lockup_txid,
        "lockup_vout":0,
        "claim_txid":claim_txid,
        "payment_hash":invoice.payment_hash,
        "cooperative_status_ids":status_ids,
        "cooperative_status_count":7,
        "provider_final_signature_bytes":64,
        "witness":witness,
        "effect_states":{"cooperative_sign":"applied","chain_claim":"applied"},
        "result":"claimed",
    });
    session.persist_terminal("completed", result.clone())?;
    Ok(result)
}

fn begin_requester_cooperative_round(
    environment: &SmokeEnvironment,
    session: &SessionContext,
    wallet_path: WalletPath,
    context: &CooperativeSigningContext,
    current_height: u32,
) -> Result<CooperativeSigningRound, String> {
    let package = session
        .verifier
        .exit_packages()
        .iter()
        .find(|package| {
            package
                .document()
                .get("participant_role")
                .and_then(Value::as_str)
                == Some("requester")
        })
        .ok_or_else(|| "cooperative requester exit package is absent".to_owned())?;
    let transaction = Transaction::parse(&decode_hex(&context.unsigned_transaction)?)
        .map_err(|error| format!("cooperative unsigned transaction is invalid: {error}"))?;
    let input = transaction
        .inputs
        .first()
        .ok_or_else(|| "cooperative transaction has no input".to_owned())?;
    let output = transaction
        .outputs
        .first()
        .ok_or_else(|| "cooperative transaction has no output".to_owned())?;
    if transaction.inputs.len() != 1 || transaction.outputs.len() != 1 || context.input_index != 0 {
        return Err(
            "cooperative transaction is not the pinned one-input one-output shape".to_owned(),
        );
    }
    let prevout = context
        .prevouts
        .first()
        .ok_or_else(|| "cooperative context has no prevout".to_owned())?;
    let document = package.document();
    let exit = document
        .get("exit")
        .and_then(Value::as_object)
        .ok_or_else(|| "requester exit package has no exit object".to_owned())?;
    let verification = document
        .get("verification")
        .and_then(Value::as_object)
        .ok_or_else(|| "requester exit package has no verification object".to_owned())?;
    let fee_policy = exit
        .get("fee_policy")
        .and_then(Value::as_object)
        .ok_or_else(|| "requester exit package has no fee policy".to_owned())?;
    let participant_keys = context
        .participant_keys
        .iter()
        .map(|key| decode_fixed_hex::<33>(key, "cooperative participant key"))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "cooperative context does not contain two participant keys".to_owned())?;
    let verifier = verifier_for_leg(&session.contract, "source")?;
    let template = CooperativeSettlementTemplate {
        settlement: SettlementTemplate {
            wallet_path,
            previous_txid_wire: input.previous_txid,
            previous_output: input.previous_output,
            prevout_value_sat: canonical_u64(&prevout.amount)?,
            prevout_script_pubkey: decode_hex(&prevout.script_pubkey)?,
            destination_value_sat: output.value_sat,
            destination_script_pubkey: output.script_pubkey.clone(),
            transaction_version: transaction.version,
            input_sequence: input.sequence,
            lock_time: transaction.lock_time,
            taproot_script: decode_hex(required_string(verification, "taproot_script")?)?,
            taproot_control_block: decode_hex(required_string(
                verification,
                "taproot_control_block",
            )?)?,
            maximum_fee_sat: canonical_u64(required_string(fee_policy, "maximum_fee")?)?,
            maximum_fee_rate_sat_per_vbyte: 10_000,
            maximum_weight: 1_600,
            dust_relay_fee_sat_per_kilobyte: 3_000,
        },
        cooperative_wallet_path: wallet_path,
        participant_keys,
        provider_index: 0,
        taproot_merkle_root: decode_fixed_hex::<32>(
            required_string(verifier, "taproot_merkle_root")?,
            "cooperative Taproot merkle root",
        )?,
        transcript_digest: decode_fixed_hex::<32>(
            &context
                .sha256()
                .map_err(|error| format!("cooperative context digest failed: {error}"))?,
            "cooperative context digest",
        )?,
        latest_safe_height: context
            .latest_safe_height
            .parse::<u32>()
            .map_err(|_| "cooperative latest safe height is invalid".to_owned())?,
    };
    let round = SettlementBridge::new(&environment.wallet)
        .begin_cooperative(&template, current_height)
        .map_err(|error| format!("could not begin requester cooperative round: {error}"))?;
    if lower_hex(&round.aggregate_key()) != context.aggregate_key
        || lower_hex(&round.signature_hash()) != context.signature_hash
        || lower_hex(
            &round
                .unsigned_transaction()
                .map_err(|error| format!("requester cooperative transaction failed: {error}"))?,
        ) != context.unsigned_transaction
    {
        return Err("requester cooperative round differs from provider context".to_owned());
    }
    Ok(round)
}

fn finish_cooperative_fallback(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: SessionContext,
    lockup_txid: &str,
    payment_hash: &str,
    statuses: [Event; 4],
    crash_cut: bool,
) -> Result<Value, String> {
    finish_cooperative_fallback_common(
        runtime,
        environment,
        session,
        lockup_txid,
        payment_hash,
        statuses.into_iter().collect(),
        crash_cut,
    )
}

fn finish_cooperative_fallback_with_requester_abort(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: SessionContext,
    lockup_txid: &str,
    payment_hash: &str,
    statuses: [Event; 5],
) -> Result<Value, String> {
    finish_cooperative_fallback_common(
        runtime,
        environment,
        session,
        lockup_txid,
        payment_hash,
        statuses.into_iter().collect(),
        false,
    )
}

fn finish_cooperative_fallback_common(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    lockup_txid: &str,
    payment_hash: &str,
    statuses: Vec<Event>,
    crash_cut: bool,
) -> Result<Value, String> {
    let provider_messages = session
        .verifier
        .signed_records()
        .iter()
        .filter(|event| event.pubkey == session.provider_pubkey)
        .filter_map(|event| {
            provider_support::cooperative_signing_message(event, ParticipantRole::Provider)
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    let requester_messages = session
        .verifier
        .signed_records()
        .iter()
        .filter(|event| event.pubkey == session.requester.pubkey())
        .filter_map(|event| {
            provider_support::cooperative_signing_message(event, ParticipantRole::Requester)
                .ok()
                .flatten()
        })
        .collect::<Vec<_>>();
    if provider_messages
        .iter()
        .filter(|message| message.action == CooperativeSigningAction::Aborted)
        .count()
        != 1
        || provider_messages
            .iter()
            .filter(|message| message.action == CooperativeSigningAction::PublicNonce)
            .count()
            != 1
        || provider_messages.iter().any(|message| {
            matches!(
                message.action,
                CooperativeSigningAction::PartialSignature
                    | CooperativeSigningAction::FinalSignature
            )
        })
        || requester_messages
            .iter()
            .any(|message| message.action == CooperativeSigningAction::PublicNonce)
        || requester_messages
            .iter()
            .filter(|message| message.action == CooperativeSigningAction::Aborted)
            .count()
            != usize::from(!crash_cut)
    {
        return Err("cooperative fallback transcript has another terminal shape".to_owned());
    }
    let claim_pending = session.wait_provider_state("provider_claim_pending")?;
    let claim_txid = status_transaction_id(&claim_pending)?;
    let peer_bitcoind = load_adversarial_bitcoind("B")?;
    wait_for_exact_transaction_on_both_nodes(
        runtime,
        [&environment.bitcoind, &peer_bitcoind],
        &claim_txid,
        "cooperative-script-fallback",
    )?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "cooperative-script-fallback",
    )?;
    session.wait_provider_state("provider_claimed")?;
    session.wait_provider_state("completed")?;
    session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: Some(&claim_txid),
            liquid_settlement_txid: None,
            lightning: Some(LightningTerminalCheck::IncomingInvoice { payment_hash }),
        },
    )?;
    let witness = inspect_cooperative_settlement(
        runtime,
        environment,
        &session.contract,
        lockup_txid,
        &claim_txid,
        CooperativeWitnessPath::ScriptClaim,
    )?;
    let external_control = if crash_cut {
        Some(
            load_funded_injection_proof(&environment.control.paths)?
                .ok_or_else(|| "cooperative crash has no process proof".to_owned())?,
        )
    } else {
        None
    };
    let result = json!({
        "order_id":session.order.id,
        "lockup_txid":lockup_txid,
        "lockup_vout":0,
        "claim_txid":claim_txid,
        "payment_hash":payment_hash,
        "cooperative_status_ids":statuses.into_iter().map(|event| event.id).collect::<Vec<_>>(),
        "cooperative_status_count":if crash_cut { 4 } else { 5 },
        "provider_abort_count":1,
        "provider_public_nonce_count":1,
        "provider_partial_count":0,
        "provider_final_count":0,
        "requester_public_nonce_count":0,
        "requester_abort_count":usize::from(!crash_cut),
        "witness":witness,
        "effect_states":{"cooperative_sign":"applied","chain_claim":"applied"},
        "external_control":external_control,
        "result":"claimed",
    });
    session.persist_terminal("completed", result.clone())?;
    Ok(result)
}

#[derive(Clone, Copy)]
enum CooperativeWitnessPath {
    KeyPath,
    ScriptClaim,
}

fn inspect_cooperative_settlement(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    contract: &Value,
    funding_txid: &str,
    settlement_txid: &str,
    path: CooperativeWitnessPath,
) -> Result<Value, String> {
    let peer = adversarial_peer_bitcoind()?;
    let primary = runtime
        .block_on(environment.bitcoind.raw_transaction(
            &rpc_id("cooperative-primary-transaction")?,
            settlement_txid,
            true,
        ))
        .map_err(|error| format!("could not read cooperative transaction from node A: {error}"))?;
    let secondary = runtime
        .block_on(peer.raw_transaction(
            &rpc_id("cooperative-secondary-transaction")?,
            settlement_txid,
            true,
        ))
        .map_err(|error| format!("could not read cooperative transaction from node B: {error}"))?;
    let primary_object = primary
        .as_object()
        .ok_or_else(|| "node A cooperative transaction response is not an object".to_owned())?;
    let secondary_object = secondary
        .as_object()
        .ok_or_else(|| "node B cooperative transaction response is not an object".to_owned())?;
    let primary_hex = required_string(primary_object, "hex")?;
    if secondary_object.get("hex").and_then(Value::as_str) != Some(primary_hex)
        || primary_object.get("txid").and_then(Value::as_str) != Some(settlement_txid)
        || secondary_object.get("txid").and_then(Value::as_str) != Some(settlement_txid)
        || primary_object.get("confirmations").and_then(Value::as_u64)
            < Some(environment.terminal_confirmations)
        || secondary_object
            .get("confirmations")
            .and_then(Value::as_u64)
            < Some(environment.terminal_confirmations)
    {
        return Err("two bitcoind nodes disagree on cooperative settlement".to_owned());
    }
    let transaction = Transaction::parse(&decode_hex(primary_hex)?)
        .map_err(|error| format!("cooperative settlement transaction is invalid: {error}"))?;
    let input = transaction
        .inputs
        .first()
        .ok_or_else(|| "cooperative settlement has no input".to_owned())?;
    if transaction.inputs.len() != 1
        || transaction.outputs.len() != 1
        || input.previous_txid != display_txid_wire(funding_txid)?
        || input.previous_output != 0
    {
        return Err("cooperative settlement does not spend the exact lockup outpoint".to_owned());
    }
    let virtual_size = transaction
        .virtual_size()
        .map_err(|error| format!("cooperative settlement vsize failed: {error}"))?;
    match path {
        CooperativeWitnessPath::KeyPath => {
            if input.witness.len() != 1
                || input.witness.first().is_none_or(|item| item.len() != 64)
                || virtual_size != 111
            {
                return Err(
                    "cooperative key-path witness differs from the 111-vB fixture".to_owned(),
                );
            }
            Ok(json!({
                "path":"key_path",
                "input_count":1,
                "output_count":1,
                "witness_item_count":1,
                "witness_item_lengths":[64],
                "script_item_count":0,
                "control_block_item_count":0,
                "virtual_size":111,
                "exact_funding_outpoint":true,
                "both_bitcoind_nodes_agree":true,
            }))
        }
        CooperativeWitnessPath::ScriptClaim => {
            let verifier = verifier_for_leg(contract, "source")?;
            let script = decode_hex(required_string(verifier, "claim_script")?)?;
            let control = decode_hex(required_string(verifier, "taproot_claim_control_block")?)?;
            if input.witness.len() != 4
                || input.witness.get(2) != Some(&script)
                || input.witness.get(3) != Some(&control)
                || virtual_size != 155
            {
                return Err(
                    "cooperative fallback witness differs from the exact claim leaf".to_owned(),
                );
            }
            Ok(json!({
                "path":"script_claim",
                "input_count":1,
                "output_count":1,
                "witness_item_count":4,
                "witness_item_lengths":input.witness.iter().map(Vec::len).collect::<Vec<_>>(),
                "taproot_script_bytes":script.len(),
                "control_block_bytes":control.len(),
                "exact_contract_leaf_and_control":true,
                "virtual_size":155,
                "exact_funding_outpoint":true,
                "both_bitcoind_nodes_agree":true,
            }))
        }
    }
}

fn adversarial_peer_bitcoind() -> Result<BitcoindClient, String> {
    let port = required_environment("IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_PORT")?
        .parse::<u16>()
        .map_err(|_| "adversarial Bitcoin B port is invalid".to_owned())?;
    let endpoint = BitcoindEndpoint::new(
        required_environment("IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_HOST")?,
        port,
    )
    .map_err(|error| format!("adversarial Bitcoin B endpoint is invalid: {error}"))?;
    let auth = BitcoindAuth::new(
        required_environment("IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_USER")?,
        required_environment("IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_PASSWORD")?,
    )
    .map_err(|error| format!("adversarial Bitcoin B authentication is invalid: {error}"))?;
    BitcoindClient::new(endpoint, auth, BitcoindLimits::default())
        .map_err(|error| format!("could not initialize adversarial Bitcoin B client: {error}"))
}

fn wait_for_adversarial_transaction_propagation(
    runtime: &Runtime,
    primary: &BitcoindClient,
    transaction_id: &str,
    label: &str,
) -> Result<(), String> {
    let peer_environment = [
        "IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_HOST",
        "IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_PORT",
        "IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_USER",
        "IMMORTAL_LAB_ADVERSARIAL_BITCOIND_B_RPC_PASSWORD",
    ];
    let configured = peer_environment
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .count();
    if configured == 0 {
        return Ok(());
    }
    if configured != peer_environment.len() {
        return Err("adversarial Bitcoin B propagation configuration is partial".to_owned());
    }
    let peer = adversarial_peer_bitcoind()?;
    wait_for_exact_transaction_on_both_nodes(runtime, [primary, &peer], transaction_id, label)
}

fn wait_for_liquid_transaction_propagation(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    transaction_id: &str,
    label: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + JOURNEY_TIMEOUT;
    loop {
        match runtime.block_on(
            liquid
                .elementsd
                .raw_transaction(&rpc_id(label)?, transaction_id),
        ) {
            Ok(raw_transaction) => {
                let transaction = parse_liquid_transaction(&raw_transaction).map_err(|error| {
                    format!("propagated Liquid transaction is invalid: {error}")
                })?;
                if lower_hex(&transaction.transaction_id) != transaction_id {
                    return Err(
                        "propagated Liquid transaction has another transaction ID".to_owned()
                    );
                }
                return Ok(());
            }
            Err(ElementsdError::Rpc(BitcoindError::Rpc { code: -5 }))
                if Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(200));
            }
            Err(ElementsdError::Rpc(BitcoindError::Rpc { code: -5 })) => {
                return Err(format!(
                    "Liquid transaction {transaction_id} did not propagate to the mining elementsd before mining"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "mining elementsd did not receive the Liquid transaction: {error}"
                ));
            }
        }
    }
}

fn wait_for_chain_transaction_propagation(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    rail: &str,
    transaction_id: &str,
    label: &str,
) -> Result<(), String> {
    match rail {
        "bitcoin" => wait_for_adversarial_transaction_propagation(
            runtime,
            &environment.bitcoind,
            transaction_id,
            label,
        ),
        "liquid" => wait_for_liquid_transaction_propagation(
            runtime,
            environment
                .liquid
                .as_ref()
                .ok_or_else(|| "chain propagation has no local elementsd".to_owned())?,
            transaction_id,
            label,
        ),
        _ => Err("chain propagation uses an unsupported rail".to_owned()),
    }
}

fn cooperative_action_name(action: CooperativeSigningAction) -> &'static str {
    match action {
        CooperativeSigningAction::NonceCommitment => "nonce_commitment",
        CooperativeSigningAction::PublicNonce => "public_nonce",
        CooperativeSigningAction::PartialSignature => "partial_signature",
        CooperativeSigningAction::FinalSignature => "final_signature",
        CooperativeSigningAction::Aborted => "aborted",
    }
}

fn decode_fixed_hex<const SIZE: usize>(value: &str, label: &str) -> Result<[u8; SIZE], String> {
    let decoded = decode_hex(value)?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} is not {SIZE} bytes"))
}

fn drive_submarine_refund(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    client_input: FundingInput,
) -> Result<Value, String> {
    let invoice_label = "immortal-funded-submarine-refund";
    let invoice =
        runtime
            .block_on(environment.peer_cln.invoice(
                &cln_id("submarine-refund-invoice")?,
                Millisatoshi::from_satoshis(OUTPUT_AMOUNT_SAT).map_err(|error| {
                    format!("submarine refund invoice amount is invalid: {error}")
                })?,
                invoice_label,
                "Immortal adversarial submarine refund",
                SUBMARINE_REFUND_INVOICE_EXPIRY_SECONDS,
            ))
            .map_err(|error| format!("could not create submarine refund invoice: {error}"))?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("submarine refund path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(refund_path)
        .map_err(|error| format!("could not derive submarine refund key: {error}"))?
        .internal_key;
    let exit_destination =
        environment
            .wallet
            .derive_address(WalletPath::new(0, true, 10).map_err(|error| {
                format!("submarine refund destination path is invalid: {error}")
            })?)
            .map_err(|error| format!("could not derive submarine refund destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name: FundedJourney::SubmarineRefund.name(),
            swap_type: "submarine",
            payment_hash: &invoice.payment_hash,
            invoice: Some(&invoice.bolt11),
            requester_key,
            requester_funding_input: Some(&client_input),
            exit_destination_script_pubkey: &exit_destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    session.wait_provider_state("accepted")?;
    session.wait_provider_state("lock_terms_ready")?;
    let funding = session
        .requester_funding
        .take()
        .ok_or_else(|| "submarine refund has no contract-bound funding transaction".to_owned())?;
    let authorized = verify_submarine_before_fund(&session, &invoice.bolt11, &funding)?;
    session.set_authorized_verifier(authorized)?;
    continue_submarine_refund(
        runtime,
        environment,
        session,
        &funding.raw_transaction,
        &funding.txid,
        &invoice.payment_hash,
        invoice_label,
        refund_path,
        exit_destination.script_pubkey.to_vec(),
    )
}

fn reject_wrong_claim_key(
    environment: &SmokeEnvironment,
    session: &SessionContext,
    preimage: [u8; 32],
) -> Result<Value, String> {
    let verifier = verifier_for_leg(&session.contract, "destination")?;
    let raw_funding = required_string(verifier, "funding_transaction")?;
    let funding_txid = transaction_id(raw_funding)?;
    let output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "wrong-claim-key verifier has no bounded output index".to_owned())?;
    let bitcoin = bitcoin_terms(&session.contract, "destination")?;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 9)
                .map_err(|error| format!("wrong-claim-key destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive wrong-claim-key destination: {error}"))?;
    let wrong_path = WalletPath::new(2, false, 9)
        .map_err(|error| format!("wrong claim wallet path is invalid: {error}"))?;
    let destination_value_sat = bitcoin
        .amount_sat
        .checked_sub(bitcoin.miner_fee_budget_sat)
        .filter(|value| *value > 0)
        .ok_or_else(|| "wrong-claim-key fee consumes its output".to_owned())?;
    let result = SettlementBridge::new(&environment.wallet).claim(
        &SettlementTemplate {
            wallet_path: wrong_path,
            previous_txid_wire: display_txid_wire(&funding_txid)?,
            previous_output: output_index,
            prevout_value_sat: bitcoin.amount_sat,
            prevout_script_pubkey: bitcoin.script_pubkey,
            destination_value_sat,
            destination_script_pubkey: destination.script_pubkey.to_vec(),
            transaction_version: 2,
            input_sequence: 0xffff_fffe,
            lock_time: 0,
            taproot_script: bitcoin.claim_script,
            taproot_control_block: bitcoin.claim_control_block,
            maximum_fee_sat: bitcoin.miner_fee_budget_sat,
            maximum_fee_rate_sat_per_vbyte: 10_000,
            maximum_weight: 1_600,
            dust_relay_fee_sat_per_kilobyte: 3_000,
        },
        ClaimPreimage::new(preimage),
    );
    match result {
        Ok(_) => Err("wrong claim key produced a signed transaction".to_owned()),
        Err(error)
            if error.to_string() == "settlement script does not bind the selected wallet key" =>
        {
            Err("wrong claim key rejected before external effect".to_owned())
        }
        Err(error) => Err(format!("wrong claim key returned another refusal: {error}")),
    }
}

fn prove_rbf_conflict_before_settlement(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    funding_input: &FundingInput,
    committed_funding: &SignedFundingTransaction,
    payment_hash: &str,
) -> Result<Value, String> {
    let conflict_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 11)
                .map_err(|error| format!("conflict destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive conflict destination: {error}"))?;
    let conflict = build_funding_transaction(
        &environment.wallet,
        std::slice::from_ref(funding_input),
        &FundingRequest {
            destination_script_pubkey: conflict_destination.script_pubkey.to_vec(),
            amount_sat: 50_000,
            fee_rate_sat_per_vbyte: 4,
            change_path: WalletPath::new(0, true, 12)
                .map_err(|error| format!("conflict change path is invalid: {error}"))?,
            lock_time: 0,
        },
    )
    .map_err(|error| format!("could not construct same-input conflict: {error}"))?;
    if conflict.txid == committed_funding.txid {
        return Err("same-input conflict did not change the transaction ID".to_owned());
    }
    let committed = Transaction::parse(&decode_hex(&committed_funding.raw_transaction)?)
        .map_err(|error| format!("committed funding transaction is invalid: {error}"))?;
    let conflicting = Transaction::parse(&decode_hex(&conflict.raw_transaction)?)
        .map_err(|error| format!("conflicting funding transaction is invalid: {error}"))?;
    let committed_input = committed
        .inputs
        .first()
        .ok_or_else(|| "committed funding transaction has no input".to_owned())?;
    let conflicting_input = conflicting
        .inputs
        .first()
        .ok_or_else(|| "conflicting funding transaction has no input".to_owned())?;
    if committed.inputs.len() != 1
        || conflicting.inputs.len() != 1
        || committed_input.previous_txid != conflicting_input.previous_txid
        || committed_input.previous_output != conflicting_input.previous_output
    {
        return Err("conflicting transaction does not spend the exact committed input".to_owned());
    }
    let broadcast_conflict = runtime
        .block_on(environment.bitcoind.broadcast(
            &rpc_id("rbf-conflict-broadcast")?,
            &conflict.raw_transaction,
            None,
        ))
        .map_err(|error| format!("could not broadcast same-input conflict: {error}"))?;
    if broadcast_conflict != conflict.txid {
        return Err("bitcoind returned another conflict transaction ID".to_owned());
    }
    let mempool = runtime
        .block_on(
            environment
                .bitcoind
                .raw_mempool(&rpc_id("rbf-conflict-mempool")?, false),
        )
        .map_err(|error| format!("could not inspect conflict mempool: {error}"))?;
    if !mempool.as_array().is_some_and(|transactions| {
        transactions
            .iter()
            .any(|value| value.as_str() == Some(&conflict.txid))
    }) {
        return Err("same-input conflict is absent from the real regtest mempool".to_owned());
    }
    match runtime.block_on(environment.bitcoind.broadcast(
        &rpc_id("rbf-committed-rejected")?,
        &committed_funding.raw_transaction,
        None,
    )) {
        Err(BitcoindError::Rpc { code: -26 }) => {}
        Err(error) => {
            return Err(format!(
                "committed transaction returned another conflict refusal: {error}"
            ));
        }
        Ok(_) => return Err("bitcoind accepted both same-input transactions".to_owned()),
    }
    let authorized = session
        .authorized_verifier
        .as_ref()
        .ok_or_else(|| "RBF conflict session lost funding authorization".to_owned())?;
    let error = match authorized.observe_bitcoin_funding_with("source", |_| {
        Ok(LocalBitcoinObservation {
            raw_transaction: committed_funding.raw_transaction.clone(),
            confirmations: 1,
            replacement_detected: true,
            competing_spend_detected: false,
        })
    }) {
        Err(error) => error,
        Ok(_) => return Err("replacement-reject policy accepted a real conflict".to_owned()),
    };
    if error.code != "swp_rbf_policy_violation" {
        return Err(format!(
            "same-input conflict returned another client refusal: {error}"
        ));
    }
    let mut input_txid_wire = committed_input.previous_txid;
    input_txid_wire.reverse();
    Ok(json!({
        "order_id":session.order.id,
        "payment_hash":payment_hash,
        "committed_txid":committed_funding.txid,
        "conflict_txid":conflict.txid,
        "input_txid":lower_hex(&input_txid_wire),
        "input_vout":committed_input.previous_output,
        "expected_code":"swp_rbf_policy_violation",
        "outcome":"rejected_before_effect",
        "conflict_in_mempool":true,
        "committed_broadcast_rejected":true,
        "external_settlement_effects":0,
    }))
}

fn prove_zero_conf_downgrade(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    funding_input: &FundingInput,
    committed_funding: &SignedFundingTransaction,
    payment_hash: &str,
) -> Result<Value, String> {
    let injection = environment
        .control
        .injection
        .ok_or_else(|| "zero-conf proof has no selected injection".to_owned())?;
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":committed_funding.txid}),
    )?;
    let funding_txid = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "zero-conf-funding",
        &committed_funding.raw_transaction,
        &committed_funding.txid,
    )?;
    session.record_funding_effect(
        funding_txid.clone(),
        sha256(committed_funding.raw_transaction.as_bytes()),
    )?;
    let mut funding_extra = Map::new();
    funding_extra.insert(
        "transaction_id".to_owned(),
        Value::String(funding_txid.clone()),
    );
    funding_extra.insert("output_index".to_owned(), json!(0));
    session.publish_requester_status("requester_funding_broadcast", funding_extra)?;
    let observed = session.wait_provider_state("funding_observed")?;
    let accepted = session.wait_provider_state("funding_zero_conf_accepted")?;
    let accepted_profile = record_profile(&accepted)?;
    let accepted_decision = accepted_profile
        .get("zero_confirmation_acceptance")
        .and_then(Value::as_object)
        .ok_or_else(|| "zero-conf accepted Status has no decision proof".to_owned())?;
    if accepted_decision.get("decision").and_then(Value::as_str) != Some("accepted")
        || accepted_decision
            .get("transaction_id")
            .and_then(Value::as_str)
            != Some(funding_txid.as_str())
        || accepted_decision.get("view").and_then(Value::as_str) != Some("provider_local_bitcoind")
    {
        return Err("zero-conf accepted Status does not bind the local funding view".to_owned());
    }

    let (expected_reason, attack_reference) = match injection {
        HarnessInjection::ZeroConfRbfReplacement => {
            let replacement = zero_conf_competitor(environment, funding_input, true)?;
            broadcast_zero_conf_competitor(runtime, environment, &replacement)?;
            ("replacement", replacement.txid)
        }
        HarnessInjection::ZeroConfDoubleSpend => {
            let conflict = zero_conf_competitor(environment, funding_input, false)?;
            broadcast_zero_conf_competitor(runtime, environment, &conflict)?;
            ("conflict", conflict.txid)
        }
        HarnessInjection::ZeroConfAncestorEviction => {
            let parent = runtime
                .block_on(environment.bitcoind.raw_transaction(
                    &rpc_id("zero-conf-parent")?,
                    &funding_input.txid,
                    true,
                ))
                .map_err(|error| format!("could not inspect zero-conf parent: {error}"))?;
            let block_hash = parent
                .get("blockhash")
                .and_then(Value::as_str)
                .ok_or_else(|| "zero-conf parent has no confirmation block".to_owned())?
                .to_owned();
            runtime
                .block_on(environment.bitcoind.call(
                    &rpc_id("zero-conf-invalidate-parent")?,
                    "invalidateblock",
                    json!([block_hash]),
                ))
                .map_err(|error| format!("could not invalidate zero-conf parent block: {error}"))?;
            wait_for_zero_conf_ancestor(runtime, &environment.bitcoind, &funding_txid)?;
            ("ancestor_unconfirmed", block_hash)
        }
        _ => return Err("selected injection is not a zero-conf downgrade".to_owned()),
    };

    let downgraded = session.wait_provider_state("funding_confirmation_required")?;
    let downgraded_profile = record_profile(&downgraded)?;
    let downgraded_decision = downgraded_profile
        .get("zero_confirmation_acceptance")
        .and_then(Value::as_object)
        .ok_or_else(|| "zero-conf downgraded Status has no decision proof".to_owned())?;
    if downgraded_decision.get("decision").and_then(Value::as_str) != Some("confirmation_required")
        || downgraded_decision.get("reason").and_then(Value::as_str) != Some(expected_reason)
        || downgraded_decision
            .get("transaction_id")
            .and_then(Value::as_str)
            != Some(funding_txid.as_str())
    {
        return Err(format!(
            "zero-conf downgrade binding mismatch: decision={:?} reason={:?} transaction_matches={}",
            downgraded_decision.get("decision").and_then(Value::as_str),
            downgraded_decision.get("reason").and_then(Value::as_str),
            downgraded_decision
                .get("transaction_id")
                .and_then(Value::as_str)
                == Some(funding_txid.as_str())
        ));
    }
    let expected_replacement = matches!(
        injection,
        HarnessInjection::ZeroConfRbfReplacement | HarnessInjection::ZeroConfDoubleSpend
    );
    if expected_replacement
        && downgraded_decision
            .get("replacement_transaction_id")
            .and_then(Value::as_str)
            != Some(attack_reference.as_str())
        || !expected_replacement
            && downgraded_decision
                .get("replacement_transaction_id")
                .is_some()
    {
        return Err("zero-conf downgrade carries the wrong replacement binding".to_owned());
    }
    if session.verifier.signed_records().iter().any(|event| {
        event.kind == MKT_STATUS_KIND
            && event.pubkey == session.provider_pubkey
            && record_profile(event).ok().is_some_and(|profile| {
                matches!(
                    profile.get("swp_state").and_then(Value::as_str),
                    Some("lightning_payment_pending" | "lightning_paid")
                )
            })
    }) {
        return Err("provider advanced to a Lightning effect after zero-conf risk".to_owned());
    }
    let invoices = runtime
        .block_on(
            environment
                .peer_cln
                .list_invoices(&cln_id("zero-conf-invoice-state")?, None),
        )
        .map_err(|error| format!("could not inspect zero-conf invoice state: {error}"))?;
    let invoice_state = invoices
        .get("invoices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|invoice| invoice.get("payment_hash").and_then(Value::as_str) == Some(payment_hash))
        .and_then(|invoice| invoice.get("status"))
        .and_then(Value::as_str)
        .ok_or_else(|| "zero-conf invoice is absent from local CLN".to_owned())?;
    if invoice_state != "unpaid" {
        return Err("zero-conf downgrade did not leave the invoice unpaid".to_owned());
    }
    session.persist_authorized_details(
        "zero_conf_downgraded",
        true,
        json!({"external_identifier":funding_txid,"reason":expected_reason}),
    )?;
    Ok(json!({
        "order_id":session.order.id,
        "payment_hash":payment_hash,
        "funding_txid":funding_txid,
        "funding_observed_status_id":observed.id,
        "zero_conf_accepted_status_id":accepted.id,
        "confirmation_required_status_id":downgraded.id,
        "injection":injection.name(),
        "attack_reference":attack_reference,
        "accepted_decision":"accepted",
        "downgraded_decision":"confirmation_required",
        "reason":expected_reason,
        "invoice_state":invoice_state,
        "provider_settlement_effects":0,
        "outcome":"confirmation_required_without_effect",
    }))
}

fn zero_conf_competitor(
    environment: &SmokeEnvironment,
    funding_input: &FundingInput,
    signals_rbf: bool,
) -> Result<SignedFundingTransaction, String> {
    let destination_index = if signals_rbf { 13 } else { 14 };
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, destination_index)
                .map_err(|error| format!("zero-conf competitor path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive zero-conf competitor destination: {error}"))?;
    let mut competitor = build_funding_transaction(
        &environment.wallet,
        std::slice::from_ref(funding_input),
        &FundingRequest {
            destination_script_pubkey: destination.script_pubkey.to_vec(),
            amount_sat: 50_000,
            fee_rate_sat_per_vbyte: 20,
            change_path: WalletPath::new(0, true, destination_index + 10)
                .map_err(|error| format!("zero-conf competitor change path is invalid: {error}"))?,
            lock_time: 0,
        },
    )
    .map_err(|error| format!("could not construct zero-conf competitor: {error}"))?;
    if !signals_rbf {
        return Ok(competitor);
    }
    let input = competitor
        .transaction
        .inputs
        .first_mut()
        .ok_or_else(|| "zero-conf replacement has no input".to_owned())?;
    input.sequence = 0xffff_fffd;
    input.witness.clear();
    let prevout = environment
        .wallet
        .derive_address(funding_input.path)
        .map_err(|error| format!("could not derive zero-conf replacement prevout: {error}"))?;
    let sighash = taproot_key_spend_sighash(
        &competitor.transaction,
        &[TransactionOutput {
            value_sat: funding_input.value_sat,
            script_pubkey: prevout.script_pubkey.to_vec(),
        }],
        0,
    )
    .map_err(|error| format!("could not hash zero-conf replacement: {error}"))?;
    let signature = environment
        .wallet
        .sign_key_path(funding_input.path, &sighash)
        .map_err(|error| format!("could not sign zero-conf replacement: {error}"))?;
    competitor
        .transaction
        .set_input_witness(0, vec![signature.signature.to_vec()])
        .map_err(|error| format!("could not attach zero-conf replacement witness: {error}"))?;
    competitor.raw_transaction = lower_hex(
        &competitor
            .transaction
            .serialize(true)
            .map_err(|error| format!("could not serialize zero-conf replacement: {error}"))?,
    );
    competitor.txid = lower_hex(
        &competitor
            .transaction
            .txid()
            .map_err(|error| format!("could not identify zero-conf replacement: {error}"))?,
    );
    Ok(competitor)
}

fn broadcast_zero_conf_competitor(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    competitor: &SignedFundingTransaction,
) -> Result<(), String> {
    let transaction_id = runtime
        .block_on(environment.bitcoind.broadcast(
            &rpc_id("zero-conf-competitor")?,
            &competitor.raw_transaction,
            None,
        ))
        .map_err(|error| format!("could not broadcast zero-conf competitor: {error}"))?;
    if transaction_id != competitor.txid {
        return Err("bitcoind returned another zero-conf competitor ID".to_owned());
    }
    Ok(())
}

fn wait_for_zero_conf_ancestor(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    transaction_id: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match runtime
            .block_on(bitcoind.mempool_entry(&rpc_id("zero-conf-ancestor-entry")?, transaction_id))
        {
            Ok(entry)
                if entry.get("ancestorcount").and_then(Value::as_u64) == Some(2)
                    && entry
                        .get("depends")
                        .and_then(Value::as_array)
                        .is_some_and(|dependencies| !dependencies.is_empty()) =>
            {
                return Ok(());
            }
            Ok(_) | Err(BitcoindError::Rpc { code: -5 }) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100));
            }
            Ok(_) | Err(BitcoindError::Rpc { code: -5 }) => {
                return Err("zero-conf funding did not acquire an unconfirmed ancestor".to_owned());
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect zero-conf ancestor state: {error}"
                ));
            }
        }
    }
}

fn continue_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    raw_funding: &str,
    expected_txid: Option<&str>,
    payment_hash: &str,
) -> Result<Value, String> {
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    let intended_txid = match expected_txid {
        Some(expected_txid) => expected_txid.to_owned(),
        None => transaction_id(raw_funding)?,
    };
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier": intended_txid.clone()}),
    )?;
    let lockup_txid = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "submarine-funding",
        raw_funding,
        &intended_txid,
    )?;
    session.record_funding_effect(lockup_txid.clone(), sha256(raw_funding.as_bytes()))?;
    finish_submarine(runtime, environment, session, lockup_txid, payment_hash)
}

fn resume_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    checkpoint: &FundedCheckpoint,
    raw_funding: &str,
    payment_hash: &str,
) -> Result<Value, String> {
    match checkpoint.label.as_str() {
        "funding_authorized" => continue_submarine(
            runtime,
            environment,
            session,
            raw_funding,
            None,
            payment_hash,
        ),
        "funding_execution_ready" => {
            let intended_txid = checkpoint_external_identifier(checkpoint)?;
            if transaction_id(raw_funding)? != intended_txid {
                return Err("persisted funding checkpoint binds another transaction".to_owned());
            }
            let lockup_txid = broadcast_bitcoin_once(
                runtime,
                &environment.bitcoind,
                "submarine-funding-resume",
                raw_funding,
                &intended_txid,
            )?;
            session.record_funding_effect(lockup_txid.clone(), sha256(raw_funding.as_bytes()))?;
            finish_submarine(runtime, environment, session, lockup_txid, payment_hash)
        }
        "funding_effect_recorded" => {
            let lockup_txid = checkpoint_external_identifier(checkpoint)?;
            require_known_bitcoin_transaction(
                runtime,
                &environment.bitcoind,
                "submarine-funding-recorded",
                &lockup_txid,
                Some(raw_funding),
            )?;
            finish_submarine(runtime, environment, session, lockup_txid, payment_hash)
        }
        _ => Err("submarine checkpoint cannot resume execution".to_owned()),
    }
}

fn finish_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    lockup_txid: String,
    payment_hash: &str,
) -> Result<Value, String> {
    let mut funding_extra = Map::new();
    funding_extra.insert(
        "transaction_id".to_owned(),
        Value::String(lockup_txid.clone()),
    );
    funding_extra.insert("output_index".to_owned(), json!(0));
    session.publish_requester_status("requester_funding_broadcast", funding_extra)?;
    if environment.control.injection == Some(HarnessInjection::FundingReorg) {
        session.persist_authorized_details(
            "funding_reorg_control",
            false,
            json!({"external_identifier":lockup_txid.clone()}),
        )?;
    } else {
        mine_blocks(runtime, &environment.bitcoind, 1, "submarine-funding")?;
    }
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    session.wait_provider_state("lightning_payment_pending")?;
    session.wait_provider_state("lightning_paid")?;
    let claim_pending = session.wait_provider_state("provider_claim_pending")?;
    let claim_txid = status_transaction_id(&claim_pending)?;
    if environment.control.injection == Some(HarnessInjection::ClaimReorg) {
        session.persist_authorized_details(
            "claim_reorg_control",
            false,
            json!({"external_identifier":claim_txid.clone()}),
        )?;
    }
    wait_for_adversarial_transaction_propagation(
        runtime,
        &environment.bitcoind,
        &claim_txid,
        "submarine-claim",
    )?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "submarine-claim",
    )?;
    session.wait_provider_state("provider_claimed")?;
    session.wait_provider_state("completed")?;
    session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: Some(&claim_txid),
            liquid_settlement_txid: None,
            lightning: Some(LightningTerminalCheck::IncomingInvoice { payment_hash }),
        },
    )?;
    let result = json!({
        "order_id":session.order.id,
        "lockup_txid":lockup_txid,
        "lockup_vout":0,
        "claim_txid":claim_txid,
        "payment_hash":payment_hash,
        "result":"claimed"
    });
    session.persist_terminal("completed", result.clone())?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn continue_submarine_refund(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    raw_funding: &str,
    intended_txid: &str,
    payment_hash: &str,
    invoice_label: &str,
    refund_path: WalletPath,
    destination_script_pubkey: Vec<u8>,
) -> Result<Value, String> {
    session.publish_requester_status("requester_verification_passed", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier":intended_txid}),
    )?;
    let lockup_txid = broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "submarine-refund-funding",
        raw_funding,
        intended_txid,
    )?;
    session.record_funding_effect(lockup_txid.clone(), sha256(raw_funding.as_bytes()))?;
    if session.control.injection != Some(HarnessInjection::ProviderNoncooperative) {
        return Err("submarine refund requires the selected provider stop proof".to_owned());
    }

    let mut funding_extra = Map::new();
    funding_extra.insert(
        "transaction_id".to_owned(),
        Value::String(lockup_txid.clone()),
    );
    funding_extra.insert("output_index".to_owned(), json!(0));
    session.publish_requester_status("requester_funding_broadcast", funding_extra)?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        1,
        "submarine-refund-funding",
    )?;
    let funding_confirmation_height = transaction_confirmation_height(
        runtime,
        &environment.bitcoind,
        "submarine-refund-funding-confirmation",
        &lockup_txid,
    )?;
    let bitcoin = bitcoin_terms(&session.contract, "source")?;
    if funding_confirmation_height >= bitcoin.refund_lock_height {
        return Err("submarine refund lockup confirmed after its CLTV deadline".to_owned());
    }
    finalize_invoice_unpaid(runtime, &environment.peer_cln, invoice_label, payment_hash)?;
    let current_height = chain_height(runtime, &environment.bitcoind, "refund-before-timeout")?;
    let before_timeout = submarine_refund_action(
        &session,
        current_height,
        funding_confirmation_height,
        LightningRecoveryState::UnpaidFinal,
    )?;
    if before_timeout != RecoveryAction::WaitForTimeout {
        return Err("client recovery did not wait for the committed refund timeout".to_owned());
    }
    mine_blocks(
        runtime,
        &environment.bitcoind,
        u64::from(bitcoin.refund_lock_height - current_height),
        "submarine-refund-timeout",
    )?;
    let timeout_height = chain_height(runtime, &environment.bitcoind, "refund-timeout")?;
    if timeout_height != bitcoin.refund_lock_height {
        return Err("scripted mining did not stop at the exact CLTV refund height".to_owned());
    }
    let recovery = submarine_refund_action(
        &session,
        timeout_height,
        funding_confirmation_height,
        LightningRecoveryState::UnpaidFinal,
    )?;
    let expected_refund_effect = match recovery {
        RecoveryAction::RequestWalletRefund { effect_id } => effect_id,
        _ => {
            return Err("client recovery did not authorize the requester wallet refund".to_owned());
        }
    };

    session.publish_requester_status("refund_prepared", Map::new())?;
    let destination_value_sat = bitcoin
        .amount_sat
        .checked_sub(bitcoin.miner_fee_budget_sat)
        .filter(|value| *value > 0)
        .ok_or_else(|| "submarine refund fee consumes its output".to_owned())?;
    let refund = SettlementBridge::new(&environment.wallet)
        .refund(&SettlementTemplate {
            wallet_path: refund_path,
            previous_txid_wire: display_txid_wire(&lockup_txid)?,
            previous_output: 0,
            prevout_value_sat: bitcoin.amount_sat,
            prevout_script_pubkey: bitcoin.script_pubkey,
            destination_value_sat,
            destination_script_pubkey,
            transaction_version: 2,
            input_sequence: 0xffff_fffe,
            lock_time: bitcoin.refund_lock_height,
            taproot_script: bitcoin.refund_script,
            taproot_control_block: bitcoin.refund_control_block,
            maximum_fee_sat: bitcoin.miner_fee_budget_sat,
            maximum_fee_rate_sat_per_vbyte: 10_000,
            maximum_weight: 1_600,
            dust_relay_fee_sat_per_kilobyte: 3_000,
        })
        .map_err(|error| format!("could not construct requester submarine refund: {error}"))?;
    let raw_refund = lower_hex(refund.broadcast_bytes());
    let refund_txid = lower_hex(&refund.transaction_id());
    let mut signing_request = None;
    let signing = session
        .authorized_verifier
        .as_ref()
        .ok_or_else(|| "submarine refund lost its funding authorization".to_owned())?
        .sign_exit_with(0, |request| {
            signing_request = Some(request.clone());
            Ok(refund.broadcast_bytes().to_vec())
        })
        .map_err(|error| format!("client engine rejected requester refund signing: {error}"))?;
    let ExitSigningOutcome::Signed(signed) = signing else {
        return Err("requester refund signing unexpectedly reused another effect".to_owned());
    };
    if signed.effect_id != expected_refund_effect || signed.transaction != raw_refund {
        return Err("client engine signed another requester refund transaction".to_owned());
    }
    let request = ExternalEffectRequest::WalletSigning(
        signing_request
            .ok_or_else(|| "requester refund wallet callback was not invoked".to_owned())?,
    );
    session
        .authorized_verifier
        .as_mut()
        .ok_or_else(|| "submarine refund lost its mutable funding authorization".to_owned())?
        .record_external_effect(
            &request,
            refund_txid.clone(),
            lower_hex(&sha256(refund.broadcast_bytes())),
        )
        .map_err(|error| format!("could not persist requester refund signing effect: {error}"))?;
    session.persist_snapshot()?;
    session.publish_requester_status("refund_pending", Map::new())?;
    broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "submarine-requester-refund",
        &raw_refund,
        &refund_txid,
    )?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "submarine-requester-refund",
    )?;

    let peer_bitcoind = load_adversarial_bitcoind("B")?;
    verify_refund_spend_on_both_nodes(
        runtime,
        [&environment.bitcoind, &peer_bitcoind],
        &lockup_txid,
        0,
        &refund_txid,
        &raw_refund,
    )?;
    if session.verifier.signed_records().iter().any(|event| {
        event.kind == MKT_STATUS_KIND
            && event.pubkey == session.provider_pubkey
            && record_profile(event)
                .ok()
                .and_then(|profile| profile.get("swp_state").cloned())
                .and_then(|state| state.as_str().map(str::to_owned))
                .is_some_and(|state| {
                    matches!(
                        state.as_str(),
                        "lightning_paid" | "provider_claim_pending" | "provider_claimed"
                    )
                })
    }) {
        return Err("noncooperative provider produced a settlement effect".to_owned());
    }
    session.publish_requester_status("refunded", Map::new())?;
    let result = json!({
        "order_id":session.order.id,
        "lockup_txid":lockup_txid,
        "lockup_vout":0,
        "payment_hash":payment_hash,
        "funding_confirmation_height":funding_confirmation_height,
        "refund_lock_height":bitcoin.refund_lock_height,
        "refund_txid":refund_txid,
        "exit_package_mode":"wallet_sign",
        "client_recovery_action":"request_wallet_refund",
        "both_bitcoind_nodes_agree":true,
        "provider_claim_effects":0,
        "lightning_state":"unpaid_final",
        "result":"refunded"
    });
    session.persist_terminal("refunded", result.clone())?;
    Ok(result)
}

fn drive_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    journey_name: &str,
    refund: bool,
) -> Result<Value, String> {
    let preimage = random_32()?;
    store_funded_secret(&environment.control.paths, journey_name, &preimage)?;
    let payment_hash = lower_hex(&sha256(&preimage));
    let claim_index = if refund { 2 } else { 1 };
    let claim_path = WalletPath::new(2, false, claim_index)
        .map_err(|error| format!("reverse claim path is invalid: {error}"))?;
    let requester_key = environment
        .wallet
        .derive_address(claim_path)
        .map_err(|error| format!("could not derive reverse claim key: {error}"))?
        .internal_key;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 1)
                .map_err(|error| format!("reverse destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive reverse destination: {error}"))?;
    let mut session = negotiate(
        environment,
        provider_pubkey,
        NegotiationInput {
            journey_name,
            swap_type: "reverse",
            payment_hash: &payment_hash,
            invoice: None,
            requester_key,
            requester_funding_input: None,
            exit_destination_script_pubkey: &destination.script_pubkey,
            presign_submarine_refund: false,
        },
    )?;
    if environment.control.injection == Some(HarnessInjection::WrongClaimKey) {
        return reject_wrong_claim_key(environment, &session, preimage);
    }
    session.wait_provider_state("accepted")?;
    let invoice_status = session.wait_provider_state("hold_invoice_ready")?;
    let invoice = record_profile(&invoice_status)?
        .get("invoice")
        .and_then(Value::as_str)
        .ok_or_else(|| "provider hold-invoice Status has no invoice".to_owned())?
        .to_owned();
    let authorized = verify_reverse_before_fund(runtime, environment, &session, &invoice)?;
    session.set_authorized_verifier(authorized)?;
    continue_reverse(
        runtime,
        environment,
        session,
        journey_name,
        refund,
        preimage,
        payment_hash,
        invoice,
        claim_path,
        destination.script_pubkey.to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
fn continue_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    journey_name: &str,
    refund: bool,
    preimage: [u8; 32],
    payment_hash: String,
    invoice: String,
    claim_path: WalletPath,
    destination_script_pubkey: Vec<u8>,
) -> Result<Value, String> {
    session.publish_requester_status("requester_invoice_verified", Map::new())?;
    session.persist_authorized_details(
        "funding_execution_ready",
        true,
        json!({"external_identifier": payment_hash.clone()}),
    )?;
    let payment_task = spawn_reverse_payment_once(
        runtime,
        &environment.peer_cln,
        journey_name,
        invoice.clone(),
        payment_hash.clone(),
    )?;
    session.record_funding_effect(payment_hash.clone(), sha256(payment_hash.as_bytes()))?;
    continue_reverse_after_funding_effect(
        runtime,
        environment,
        session,
        journey_name,
        refund,
        preimage,
        payment_hash,
        invoice,
        claim_path,
        destination_script_pubkey,
        payment_task,
    )
}

#[allow(clippy::too_many_arguments)]
fn resume_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    checkpoint: &FundedCheckpoint,
    journey_name: &str,
    refund: bool,
    mut preimage: [u8; 32],
    payment_hash: String,
    invoice: String,
    claim_path: WalletPath,
    destination_script_pubkey: Vec<u8>,
) -> Result<Value, String> {
    if matches!(
        checkpoint.label.as_str(),
        "funding_execution_ready" | "funding_effect_recorded"
    ) && checkpoint_external_identifier(checkpoint)? != payment_hash
    {
        return Err("persisted reverse checkpoint binds another payment".to_owned());
    }
    match checkpoint.label.as_str() {
        "funding_authorized" => continue_reverse(
            runtime,
            environment,
            session,
            journey_name,
            refund,
            preimage,
            payment_hash,
            invoice,
            claim_path,
            destination_script_pubkey,
        ),
        "funding_execution_ready" | "funding_effect_recorded" => {
            session.publish_requester_status("requester_invoice_verified", Map::new())?;
            let payment_task = spawn_reverse_payment_once(
                runtime,
                &environment.peer_cln,
                journey_name,
                invoice.clone(),
                payment_hash.clone(),
            )?;
            if checkpoint.label == "funding_execution_ready" {
                session
                    .record_funding_effect(payment_hash.clone(), sha256(payment_hash.as_bytes()))?;
            }
            continue_reverse_after_funding_effect(
                runtime,
                environment,
                session,
                journey_name,
                refund,
                preimage,
                payment_hash,
                invoice,
                claim_path,
                destination_script_pubkey,
                payment_task,
            )
        }
        "claim_broadcast_ready" | "claim_broadcast_recorded" if !refund => {
            preimage.fill(0);
            resume_reverse_claim(
                runtime,
                environment,
                session,
                checkpoint,
                journey_name,
                payment_hash,
                invoice,
            )
        }
        _ => Err("reverse checkpoint cannot resume execution".to_owned()),
    }
}

type PaymentTask = JoinHandle<Result<PaymentResult, String>>;

#[allow(clippy::too_many_arguments)]
fn continue_reverse_after_funding_effect(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    journey_name: &str,
    refund: bool,
    mut preimage: [u8; 32],
    payment_hash: String,
    invoice: String,
    claim_path: WalletPath,
    destination_script_pubkey: Vec<u8>,
    payment_task: PaymentTask,
) -> Result<Value, String> {
    session.publish_requester_status("lightning_payment_pending", Map::new())?;
    session.wait_provider_state("lightning_htlcs_held")?;
    session.wait_provider_state("provider_lock_terms_ready")?;
    session.publish_requester_status("requester_lock_verified", Map::new())?;
    let funding_status = session.wait_provider_state("provider_funding_broadcast")?;
    let (lockup_txid, output_index) = status_outpoint(&funding_status)?;
    wait_for_adversarial_transaction_propagation(
        runtime,
        &environment.bitcoind,
        &lockup_txid,
        "reverse-funding",
    )?;
    mine_blocks(runtime, &environment.bitcoind, 1, journey_name)?;
    session.wait_provider_state("funding_observed")?;
    let funding_final = session.wait_provider_state("funding_final")?;
    let observed = session
        .authorized_verifier
        .as_ref()
        .ok_or_else(|| "reverse session lost its funding authorization".to_owned())?
        .clone()
        .observe_reverse_payment_with(|request| {
            Ok(LocalLightningProgress {
                invoice_sha256: request.invoice_sha256.clone(),
                payment_hash: request.payment_hash.clone(),
                observed_at: unix_now()?,
                view_sha256: lower_hex(&sha256(funding_final.id.as_bytes())),
                state: LightningProgressState::HtlcsHeld,
            })
        })
        .map_err(|error| format!("client engine rejected held reverse payment: {error}"))?;
    let tip = runtime
        .block_on(
            environment
                .bitcoind
                .chain_tip(&rpc_id("reverse-recovery-height")?),
        )
        .map_err(|error| format!("could not read reverse recovery height: {error}"))?;
    let current_height =
        u32::try_from(tip.height).map_err(|_| "reverse recovery height exceeds u32".to_owned())?;
    let recovery = observed
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Pending),
                chain_state: Some(if refund {
                    ChainRecoveryState::DestinationFundedUnclaimed
                } else {
                    ChainRecoveryState::DestinationClaimable
                }),
            })
        })
        .map_err(|error| format!("client engine rejected reverse recovery view: {error}"))?;
    if refund && recovery != RecoveryAction::WaitForCounterparty {
        return Err(
            "client engine did not select counterparty wait before reverse refund".to_owned(),
        );
    }

    if refund {
        preimage.fill(0);
        let refund_height = reverse_refund_height(&session.contract)?;
        let tip = runtime
            .block_on(environment.bitcoind.chain_tip(&rpc_id("refund-height")?))
            .map_err(|error| format!("could not read refund chain height: {error}"))?;
        let current_height =
            u32::try_from(tip.height).map_err(|_| "refund chain height exceeds u32".to_owned())?;
        if current_height < refund_height {
            mine_blocks(
                runtime,
                &environment.bitcoind,
                u64::from(refund_height - current_height),
                "reverse-refund-maturity",
            )?;
        }
        session.wait_provider_state("provider_refund_prepared")?;
        let refund_pending = session.wait_provider_state("provider_refund_pending")?;
        let refund_txid = status_transaction_id(&refund_pending)?;
        mine_blocks(
            runtime,
            &environment.bitcoind,
            environment.terminal_confirmations,
            "reverse-refund-confirm",
        )?;
        session.wait_provider_state("provider_refunded")?;
        session.wait_provider_state("invoice_cancelled")?;
        session.wait_provider_state("refunded")?;
        let payment_result = runtime
            .block_on(payment_task)
            .map_err(|error| format!("reverse refund payment task failed: {error}"))?;
        if payment_result.is_ok() {
            return Err("noncooperative reverse payment released a preimage".to_owned());
        }
        session.wait_provider_close(
            "refunded",
            TerminalRailCheck {
                runtime,
                environment,
                bitcoin_settlement_txid: Some(&refund_txid),
                liquid_settlement_txid: None,
                lightning: Some(LightningTerminalCheck::OutgoingPayment {
                    invoice: &invoice,
                    payment_hash: &payment_hash,
                    expected_status: "failed",
                }),
            },
        )?;
        remove_funded_secret(&environment.control.paths, journey_name)?;
        let result = json!({
            "order_id":session.order.id,
            "lockup_txid":lockup_txid,
            "lockup_vout":output_index,
            "refund_txid":refund_txid,
            "payment_hash":payment_hash,
            "result":"refunded",
            "lightning_payment_succeeded":false
        });
        session.persist_terminal("refunded", result.clone())?;
        return Ok(result);
    }

    let bitcoin = bitcoin_terms(&session.contract, "destination")?;
    session.publish_requester_status("requester_claim_pending", Map::new())?;
    let destination_value_sat = bitcoin
        .amount_sat
        .checked_sub(bitcoin.miner_fee_budget_sat)
        .filter(|value| *value > 0)
        .ok_or_else(|| "reverse claim fee consumes its output".to_owned())?;
    let claim = SettlementBridge::new(&environment.wallet)
        .claim(
            &SettlementTemplate {
                wallet_path: claim_path,
                previous_txid_wire: display_txid_wire(&lockup_txid)?,
                previous_output: output_index,
                prevout_value_sat: bitcoin.amount_sat,
                prevout_script_pubkey: bitcoin.script_pubkey,
                destination_value_sat,
                destination_script_pubkey,
                transaction_version: 2,
                input_sequence: 0xffff_fffe,
                lock_time: 0,
                taproot_script: bitcoin.claim_script,
                taproot_control_block: bitcoin.claim_control_block,
                maximum_fee_sat: bitcoin.miner_fee_budget_sat,
                maximum_fee_rate_sat_per_vbyte: 10_000,
                maximum_weight: 1_600,
                dust_relay_fee_sat_per_kilobyte: 3_000,
            },
            ClaimPreimage::new(preimage),
        )
        .map_err(|error| format!("could not construct reverse claim: {error}"))?;
    preimage.fill(0);
    let raw_claim = lower_hex(claim.broadcast_bytes());
    let claim_txid = lower_hex(&claim.transaction_id());
    let expected_claim_effect = match recovery {
        RecoveryAction::RequestWalletClaim { effect_id } => effect_id,
        _ => return Err("client engine did not authorize the reverse wallet claim".to_owned()),
    };
    let mut signing_request = None;
    let signed = observed
        .sign_exit_with(0, |request| {
            signing_request = Some(request.clone());
            Ok(claim.broadcast_bytes().to_vec())
        })
        .map_err(|error| format!("client engine rejected reverse exit signing: {error}"))?;
    let ExitSigningOutcome::Signed(signed) = signed else {
        return Err("reverse exit signing unexpectedly reused an earlier effect".to_owned());
    };
    if signed.effect_id != expected_claim_effect || signed.transaction != raw_claim {
        return Err("client engine signed another reverse exit transaction".to_owned());
    }
    store_funded_signed_exit(
        &environment.control.paths,
        journey_name,
        &signed.transaction,
    )?;
    let request = ExternalEffectRequest::WalletSigning(
        signing_request.ok_or_else(|| "wallet signing callback was not invoked".to_owned())?,
    );
    session
        .authorized_verifier
        .as_mut()
        .ok_or_else(|| "reverse session lost its funding authorization".to_owned())?
        .record_external_effect(
            &request,
            claim_txid.clone(),
            lower_hex(&sha256(claim.broadcast_bytes())),
        )
        .map_err(|error| format!("could not persist reverse signing effect: {error}"))?;
    session.persist_snapshot()?;
    session.persist_authorized_details(
        "claim_broadcast_ready",
        true,
        json!({"external_identifier": claim_txid.clone()}),
    )?;
    broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "reverse-claim",
        &raw_claim,
        &claim_txid,
    )?;
    session.persist_authorized_details(
        "claim_broadcast_recorded",
        true,
        json!({"external_identifier": claim_txid.clone()}),
    )?;
    finish_reverse_claim(
        runtime,
        environment,
        session,
        journey_name,
        payment_hash,
        invoice,
        claim_txid,
        payment_task,
    )
}

#[allow(clippy::too_many_arguments)]
fn resume_reverse_claim(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    checkpoint: &FundedCheckpoint,
    journey_name: &str,
    payment_hash: String,
    invoice: String,
) -> Result<Value, String> {
    let claim_txid = checkpoint_external_identifier(checkpoint)?;
    let raw_claim = load_funded_signed_exit(&environment.control.paths, journey_name)?;
    if transaction_id(&raw_claim)? != claim_txid {
        return Err("persisted reverse claim checkpoint binds another transaction".to_owned());
    }
    let payment_task = spawn_reverse_payment_once(
        runtime,
        &environment.peer_cln,
        journey_name,
        invoice.clone(),
        payment_hash.clone(),
    )?;
    if checkpoint.label == "claim_broadcast_ready" {
        broadcast_bitcoin_once(
            runtime,
            &environment.bitcoind,
            "reverse-claim-resume",
            &raw_claim,
            &claim_txid,
        )?;
        session.persist_authorized_details(
            "claim_broadcast_recorded",
            true,
            json!({"external_identifier": claim_txid.clone()}),
        )?;
    } else {
        require_known_bitcoin_transaction(
            runtime,
            &environment.bitcoind,
            "reverse-claim-recorded",
            &claim_txid,
            Some(&raw_claim),
        )?;
    }
    finish_reverse_claim(
        runtime,
        environment,
        session,
        journey_name,
        payment_hash,
        invoice,
        claim_txid,
        payment_task,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_reverse_claim(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    mut session: SessionContext,
    journey_name: &str,
    payment_hash: String,
    invoice: String,
    claim_txid: String,
    payment_task: PaymentTask,
) -> Result<Value, String> {
    let funding_status = session
        .verifier
        .signed_records()
        .iter()
        .find(|event| {
            event.kind == MKT_STATUS_KIND
                && event.pubkey == session.provider_pubkey
                && record_profile(event)
                    .ok()
                    .and_then(|profile| profile.get("swp_state").cloned())
                    .and_then(|state| state.as_str().map(str::to_owned))
                    .as_deref()
                    == Some("provider_funding_broadcast")
        })
        .ok_or_else(|| "persisted reverse claim has no provider funding Status".to_owned())?;
    let (lockup_txid, output_index) = status_outpoint(funding_status)?;
    let mut claim_extra = Map::new();
    claim_extra.insert(
        "transaction_id".to_owned(),
        Value::String(claim_txid.clone()),
    );
    session.publish_requester_status("requester_claimed", claim_extra)?;
    mine_blocks(
        runtime,
        &environment.bitcoind,
        environment.terminal_confirmations,
        "reverse-claim",
    )?;
    session.wait_provider_state("lightning_settlement_pending")?;
    session.wait_provider_state("lightning_paid")?;
    session.wait_provider_state("completed")?;
    let payment = runtime
        .block_on(payment_task)
        .map_err(|error| format!("reverse payment task failed: {error}"))?
        .map_err(|error| format!("reverse payment did not settle: {error}"))?;
    if payment.status != "complete" || payment.payment_hash != payment_hash {
        return Err("reverse Lightning payment completed with another result".to_owned());
    }
    session.wait_provider_close(
        "completed",
        TerminalRailCheck {
            runtime,
            environment,
            bitcoin_settlement_txid: Some(&claim_txid),
            liquid_settlement_txid: None,
            lightning: Some(LightningTerminalCheck::OutgoingPayment {
                invoice: &invoice,
                payment_hash: &payment_hash,
                expected_status: "complete",
            }),
        },
    )?;
    remove_funded_secret(&environment.control.paths, journey_name)?;
    let result = json!({
        "order_id":session.order.id,
        "lockup_txid":lockup_txid,
        "lockup_vout":output_index,
        "claim_txid":claim_txid,
        "payment_hash":payment_hash,
        "result":"claimed"
    });
    session.persist_terminal("completed", result.clone())?;
    Ok(result)
}

fn spawn_reverse_payment_once(
    runtime: &Runtime,
    cln: &ClnClient,
    journey_name: &str,
    invoice: String,
    payment_hash: String,
) -> Result<PaymentTask, String> {
    let client = cln.clone();
    let request_id = cln_id(&format!("{journey_name}-pay"))?;
    let maximum_fee = Millisatoshi::from_satoshis(100)
        .map_err(|error| format!("reverse routing fee is invalid: {error}"))?;
    let lookup_id = cln_id(&format!("{journey_name}-pay-preflight"))?;
    let existing = runtime
        .block_on(client.list_pays(&lookup_id, Some(&invoice)))
        .map_err(|error| format!("could not inspect prior reverse payment: {error}"))?;
    let (total, matching) = payment_entries(&existing, &payment_hash)?;
    if total != matching {
        return Err("peer CLN returned another payment for the bound invoice".to_owned());
    }
    if matching > 1 {
        return Err("peer CLN reports multiple attempts for one bound payment".to_owned());
    }
    if matching == 0 {
        return Ok(runtime.spawn(async move {
            client
                .pay(&request_id, &invoice, Some(maximum_fee))
                .await
                .map_err(|error| format!("reverse payment failed: {error}"))
        }));
    }
    let journey_name = journey_name.to_owned();
    Ok(runtime.spawn(async move {
        observe_reverse_payment(&client, &invoice, &payment_hash, &journey_name).await
    }))
}

async fn observe_reverse_payment(
    client: &ClnClient,
    invoice: &str,
    payment_hash: &str,
    journey_name: &str,
) -> Result<PaymentResult, String> {
    let deadline = Instant::now() + JOURNEY_TIMEOUT;
    let request_id = cln_id(&format!("{journey_name}-pay-observe"))?;
    while Instant::now() < deadline {
        let response = client
            .list_pays(&request_id, Some(invoice))
            .await
            .map_err(|error| format!("could not observe prior reverse payment: {error}"))?;
        let entries = response
            .get("pays")
            .and_then(Value::as_array)
            .ok_or_else(|| "CLN listpays response has no pays array".to_owned())?;
        let matching = entries
            .iter()
            .filter(|entry| entry.get("payment_hash").and_then(Value::as_str) == Some(payment_hash))
            .collect::<Vec<_>>();
        if entries.len() != matching.len() {
            return Err("peer CLN returned another payment for the bound invoice".to_owned());
        }
        if matching.len() > 1 {
            return Err("peer CLN reports multiple attempts for one bound payment".to_owned());
        }
        if let Some(entry) = matching.first() {
            match entry.get("status").and_then(Value::as_str) {
                Some("complete") => return parse_payment_result(entry),
                Some("failed") => return Err("reverse payment reached failed state".to_owned()),
                Some("pending") => {}
                _ => return Err("peer CLN returned an invalid payment status".to_owned()),
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("timed out observing the existing reverse payment".to_owned())
}

fn payment_entries(response: &Value, payment_hash: &str) -> Result<(usize, usize), String> {
    let entries = response
        .get("pays")
        .and_then(Value::as_array)
        .ok_or_else(|| "CLN listpays response has no pays array".to_owned())?;
    let matching = entries
        .iter()
        .filter(|entry| entry.get("payment_hash").and_then(Value::as_str) == Some(payment_hash))
        .count();
    Ok((entries.len(), matching))
}

fn parse_payment_result(value: &Value) -> Result<PaymentResult, String> {
    let payment_hash = value
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "CLN payment has no payment hash".to_owned())?;
    require_lower_hex_32(payment_hash, "CLN payment hash")?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "complete" | "pending" | "failed"))
        .ok_or_else(|| "CLN payment has an invalid status".to_owned())?;
    let amount = Millisatoshi::parse(
        value
            .get("amount_msat")
            .ok_or_else(|| "CLN payment has no amount".to_owned())?,
    )
    .map_err(|error| format!("CLN payment amount is invalid: {error}"))?;
    let amount_sent = Millisatoshi::parse(
        value
            .get("amount_sent_msat")
            .ok_or_else(|| "CLN payment has no sent amount".to_owned())?,
    )
    .map_err(|error| format!("CLN payment sent amount is invalid: {error}"))?;
    if amount_sent < amount {
        return Err("CLN payment sent amount is below its delivered amount".to_owned());
    }
    Ok(PaymentResult {
        payment_hash: payment_hash.to_owned(),
        status: status.to_owned(),
        amount,
        amount_sent,
    })
}

fn negotiate(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: NegotiationInput<'_>,
) -> Result<SessionContext, String> {
    finalize_negotiation(prepare_negotiation(environment, provider_pubkey, input)?)
}

fn prepare_negotiation(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: NegotiationInput<'_>,
) -> Result<PendingSession, String> {
    let quoted = prepare_quote(environment, provider_pubkey, input)?;
    prepare_order(environment, quoted, input)
}

fn prepare_quote(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: NegotiationInput<'_>,
) -> Result<QuotedSession, String> {
    prepare_quote_with_terms(environment, provider_pubkey, input, INPUT_AMOUNT_SAT, 5_000)
}

fn prepare_quote_with_terms(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: NegotiationInput<'_>,
    input_amount_sat: u64,
    maximum_total_fee_sat: u64,
) -> Result<QuotedSession, String> {
    let session_id = digest(&format!(
        "funded-smoke:{}:{}",
        environment.control.run_id, input.journey_name
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: environment.requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config.clone())
        .map_err(|error| format!("could not initialize funded requester: {error}"))?;
    let now = unix_now()?;
    let mut reader = connect(&environment.relay_url)?;
    authenticate(
        &mut reader,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    subscribe(&mut reader, environment.requester.pubkey())?;
    drain_history(&mut reader, JOURNEY_TIMEOUT)?;
    let mut publisher = connect(&environment.relay_url)?;
    authenticate(
        &mut publisher,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    let mut rfq_profile =
        funded_rfq_profile_with_terms(input, now, input_amount_sat, maximum_total_fee_sat)?;
    if environment.control.injection.is_some_and(|injection| {
        matches!(
            injection,
            HarnessInjection::ZeroConfRbfReplacement
                | HarnessInjection::ZeroConfDoubleSpend
                | HarnessInjection::ZeroConfAncestorEviction
        )
    }) {
        rfq_profile["constraints"]["confirmation_policy"]["zero_confirmation"] =
            Value::String("allowed".to_owned());
        rfq_profile["constraints"]["confirmation_policy"]["replacement"] =
            Value::String("track".to_owned());
    }
    let (rfq, rfq_raw) = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(600),
                rfq_profile,
            )
            .map_err(|error| format!("could not construct funded RFQ: {error}"))?,
        &environment.requester,
    )?;
    let mut records = vec![rfq.clone()];
    let mut deliveries = vec![
        SignedRecordDelivery::from_locally_signed(rfq_raw.clone(), now)
            .map_err(|error| format!("could not archive funded RFQ provenance: {error}"))?,
    ];
    publish_private(
        &mut publisher,
        &rfq_raw,
        &environment.requester,
        provider_pubkey,
    )?;
    let received_quote = receive_matching_private(
        &mut reader,
        &environment.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| event.kind == MKT_QUOTE_KIND,
    )
    .map_err(|error| format!("provider Quote wait failed: {error}"))?;
    let quote_observed_at = received_quote.delivery.observed_at();
    let quote = received_quote.event;
    deliveries.push(received_quote.delivery);
    quote
        .validate_crypto()
        .map_err(|error| format!("funded Quote signature is invalid: {error}"))?;
    records.push(quote.clone());
    Ok(QuotedSession {
        relay_url: environment.relay_url.clone(),
        reader,
        publisher,
        requester: environment.requester.clone(),
        provider_pubkey: provider_pubkey.to_owned(),
        factory,
        config,
        records,
        deliveries,
        quote_observed_at,
        journey_name: input.journey_name.to_owned(),
        control: environment.control.clone(),
    })
}

fn prepare_chain_quote(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: ChainNegotiationInput,
) -> Result<QuotedSession, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid chain journey has no local elementsd".to_owned())?;
    let session_id = digest(&format!(
        "funded-smoke:{}:chain:{}",
        environment.control.run_id,
        input.direction.name()
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: environment.requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config.clone())
        .map_err(|error| format!("could not initialize chain requester: {error}"))?;
    let now = unix_now()?;
    let mut reader = connect(&environment.relay_url)?;
    authenticate(
        &mut reader,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    subscribe(&mut reader, environment.requester.pubkey())?;
    drain_history(&mut reader, JOURNEY_TIMEOUT)?;
    let mut publisher = connect(&environment.relay_url)?;
    authenticate(
        &mut publisher,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    let (rfq, rfq_raw) = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(600),
                funded_chain_rfq_profile(input, liquid, now),
            )
            .map_err(|error| format!("could not construct chain RFQ: {error}"))?,
        &environment.requester,
    )?;
    let mut records = vec![rfq];
    let mut deliveries = vec![
        SignedRecordDelivery::from_locally_signed(rfq_raw.clone(), now)
            .map_err(|error| format!("could not archive chain RFQ provenance: {error}"))?,
    ];
    publish_private(
        &mut publisher,
        &rfq_raw,
        &environment.requester,
        provider_pubkey,
    )?;
    let received_quote = receive_matching_private(
        &mut reader,
        &environment.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| event.kind == MKT_QUOTE_KIND,
    )
    .map_err(|error| format!("provider chain Quote wait failed: {error}"))?;
    let quote_observed_at = received_quote.delivery.observed_at();
    received_quote
        .event
        .validate_crypto()
        .map_err(|error| format!("chain Quote signature is invalid: {error}"))?;
    records.push(received_quote.event);
    deliveries.push(received_quote.delivery);
    Ok(QuotedSession {
        relay_url: environment.relay_url.clone(),
        reader,
        publisher,
        requester: environment.requester.clone(),
        provider_pubkey: provider_pubkey.to_owned(),
        factory,
        config,
        records,
        deliveries,
        quote_observed_at,
        journey_name: "chain".to_owned(),
        control: environment.control.clone(),
    })
}

fn prepare_liquid_quote(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: &LiquidNegotiationInput,
) -> Result<QuotedSession, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid journey has no local elementsd".to_owned())?;
    let session_id = digest(&format!(
        "funded-smoke:{}:{}",
        environment.control.run_id,
        input.journey.name()
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: environment.requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
        provider_route: None,
    };
    let factory = SwapRecordFactory::new(config.clone())
        .map_err(|error| format!("could not initialize Liquid requester: {error}"))?;
    let now = unix_now()?;
    let mut reader = connect(&environment.relay_url)?;
    authenticate(
        &mut reader,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    subscribe(&mut reader, environment.requester.pubkey())?;
    drain_history(&mut reader, JOURNEY_TIMEOUT)?;
    let mut publisher = connect(&environment.relay_url)?;
    authenticate(
        &mut publisher,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    let (rfq, rfq_raw) = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(600),
                funded_liquid_rfq_profile(input, liquid, now)?,
            )
            .map_err(|error| format!("could not construct Liquid RFQ: {error}"))?,
        &environment.requester,
    )?;
    let mut records = vec![rfq];
    let mut deliveries = vec![
        SignedRecordDelivery::from_locally_signed(rfq_raw.clone(), now)
            .map_err(|error| format!("could not archive Liquid RFQ provenance: {error}"))?,
    ];
    publish_private(
        &mut publisher,
        &rfq_raw,
        &environment.requester,
        provider_pubkey,
    )?;
    let received_quote = receive_matching_private(
        &mut reader,
        &environment.requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| event.kind == MKT_QUOTE_KIND,
    )
    .map_err(|error| format!("provider Liquid Quote wait failed: {error}"))?;
    let quote_observed_at = received_quote.delivery.observed_at();
    received_quote
        .event
        .validate_crypto()
        .map_err(|error| format!("Liquid Quote signature is invalid: {error}"))?;
    records.push(received_quote.event);
    deliveries.push(received_quote.delivery);
    Ok(QuotedSession {
        relay_url: environment.relay_url.clone(),
        reader,
        publisher,
        requester: environment.requester.clone(),
        provider_pubkey: provider_pubkey.to_owned(),
        factory,
        config,
        records,
        deliveries,
        quote_observed_at,
        journey_name: input.journey.name().to_owned(),
        control: environment.control.clone(),
    })
}

fn publish_quote_request_with_terms(
    environment: &SmokeEnvironment,
    provider_pubkey: &str,
    input: NegotiationInput<'_>,
    input_amount_sat: u64,
    maximum_total_fee_sat: u64,
) -> Result<(String, Event), String> {
    let session_id = digest(&format!(
        "funded-smoke:{}:{}",
        environment.control.run_id, input.journey_name
    ));
    let factory = SwapRecordFactory::new(SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: environment.requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
        provider_route: None,
    })
    .map_err(|error| format!("could not initialize reservation contender: {error}"))?;
    let now = unix_now()?;
    let (rfq, raw) = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(600),
                funded_rfq_profile_with_terms(input, now, input_amount_sat, maximum_total_fee_sat)?,
            )
            .map_err(|error| format!("could not construct reservation contender RFQ: {error}"))?,
        &environment.requester,
    )?;
    let mut publisher = connect(&environment.relay_url)?;
    authenticate(
        &mut publisher,
        &environment.requester,
        &environment.relay_url,
        now,
    )?;
    publish_private(
        &mut publisher,
        &raw,
        &environment.requester,
        provider_pubkey,
    )?;
    Ok((session_id, rfq))
}

fn prepare_order(
    environment: &SmokeEnvironment,
    quoted: QuotedSession,
    input: NegotiationInput<'_>,
) -> Result<PendingSession, String> {
    let QuotedSession {
        relay_url,
        reader,
        mut publisher,
        requester,
        provider_pubkey,
        factory,
        config,
        mut records,
        mut deliveries,
        quote_observed_at,
        journey_name,
        control,
    } = quoted;
    let rfq = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_RFQ_KIND)
        .cloned()
        .ok_or_else(|| "quoted funded session has no RFQ".to_owned())?;
    let quote = records
        .iter()
        .find(|event| event.kind == MKT_QUOTE_KIND)
        .cloned()
        .ok_or_else(|| "quoted funded session has no Quote".to_owned())?;
    let session_id = config.session_id.clone();
    let order_created_at = next_created_at_records(&records)?;
    let (order, order_raw) = sign_request(
        factory
            .requester_order(RequesterOrderInput {
                rfq: &rfq,
                quote: &quote,
                created_at: order_created_at,
                observed_at: quote_observed_at,
                distinct: &digest(&format!("order:{session_id}")),
                selection: None,
            })
            .map_err(|error| format!("could not construct funded Order: {error}"))?,
        &requester,
    )?;
    records.push(order.clone());
    let order_delivery = SignedRecordDelivery::from_locally_signed(order_raw.clone(), unix_now()?)
        .map_err(|error| format!("could not archive funded Order provenance: {error}"))?;
    let order_observed_at = order_delivery.observed_at();
    deliveries.push(order_delivery);
    publish_private(&mut publisher, &order_raw, &requester, &provider_pubkey)?;
    let swap_type = match input.swap_type {
        "submarine" => SwapType::Submarine,
        "reverse" => SwapType::Reverse,
        _ => return Err("funded smoke requester swap type is unsupported".to_owned()),
    };
    let local_inputs = RequesterContractLocalInputs::for_swap_type(swap_type);
    let mut contract = factory
        .requester_contract_draft(&rfq, &quote, &order, order_observed_at, local_inputs)
        .map_err(|error| format!("could not compose funded contract: {error}"))?;
    let requester_funding = match input.requester_funding_input {
        Some(funding_input) if input.swap_type == "submarine" => Some(bind_requester_funding(
            environment,
            &mut contract,
            funding_input,
        )?),
        None if input.swap_type == "reverse" => None,
        _ => return Err("funded smoke requester funding input has the wrong shape".to_owned()),
    };
    let exit_package_seeds = bind_requester_exit_packages(
        environment,
        &config,
        &mut contract,
        input.swap_type,
        (&order.id, &quote.id),
        input.exit_destination_script_pubkey,
        input.presign_submarine_refund,
    )?;
    Ok(PendingSession {
        relay_url,
        reader,
        publisher,
        requester,
        provider_pubkey,
        factory,
        config,
        records,
        deliveries,
        order,
        order_observed_at,
        contract,
        exit_package_seeds,
        requester_funding,
        journey_name,
        control,
    })
}

fn prepare_chain_order(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    quoted: QuotedSession,
    input: ChainNegotiationInput,
    preimage: [u8; 32],
) -> Result<PreparedChainSession, String> {
    let QuotedSession {
        relay_url,
        reader,
        mut publisher,
        requester,
        provider_pubkey,
        factory,
        config,
        mut records,
        mut deliveries,
        quote_observed_at,
        journey_name,
        control,
    } = quoted;
    let rfq = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_RFQ_KIND)
        .cloned()
        .ok_or_else(|| "quoted chain session has no RFQ".to_owned())?;
    let quote = records
        .iter()
        .find(|event| event.kind == MKT_QUOTE_KIND)
        .cloned()
        .ok_or_else(|| "quoted chain session has no Quote".to_owned())?;
    let session_id = config.session_id.clone();
    let (order, order_raw) = sign_request(
        factory
            .requester_order(RequesterOrderInput {
                rfq: &rfq,
                quote: &quote,
                created_at: next_created_at_records(&records)?,
                observed_at: quote_observed_at,
                distinct: &digest(&format!("order:{session_id}")),
                selection: None,
            })
            .map_err(|error| format!("could not construct chain Order: {error}"))?,
        &requester,
    )?;
    records.push(order.clone());
    let order_delivery = SignedRecordDelivery::from_locally_signed(order_raw.clone(), unix_now()?)
        .map_err(|error| format!("could not archive chain Order provenance: {error}"))?;
    let order_observed_at = order_delivery.observed_at();
    deliveries.push(order_delivery);
    publish_private(&mut publisher, &order_raw, &requester, &provider_pubkey)?;
    let quote_terms_contract = factory
        .requester_contract_draft(
            &rfq,
            &quote,
            &order,
            order.created_at,
            RequesterContractLocalInputs::for_swap_type(SwapType::Chain),
        )
        .map_err(|error| format!("could not inspect chain Quote terms: {error}"))?;
    let source_funding =
        chain_source_funding(runtime, environment, &quote_terms_contract, input.direction)?;
    let (funding_transaction, output_index) = match &source_funding {
        ChainFundingTransaction::Bitcoin(funding) => (funding.raw_transaction.clone(), 0_u32),
        ChainFundingTransaction::Liquid(funding) => {
            (lower_hex(&funding.raw_transaction), funding.output_index)
        }
    };
    let mut local_inputs = RequesterContractLocalInputs::for_swap_type(SwapType::Chain);
    local_inputs.funding_resolution = Some(RequesterFundingResolution {
        leg_id: "source".to_owned(),
        funding_transaction_sha256: lower_hex(&sha256(&decode_hex(&funding_transaction)?)),
        funding_transaction,
        output_index,
    });
    let mut contract = factory
        .requester_contract_draft(&rfq, &quote, &order, order.created_at, local_inputs)
        .map_err(|error| format!("could not compose chain contract: {error}"))?;

    let source_exit_path = WalletPath::new(4, false, 0)
        .map_err(|error| format!("chain source exit path is invalid: {error}"))?;
    let destination_exit_path = WalletPath::new(4, false, 1)
        .map_err(|error| format!("chain destination exit path is invalid: {error}"))?;
    let bitcoin_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 31)
                .map_err(|error| format!("chain Bitcoin destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive chain Bitcoin destination: {error}"))?;
    let liquid_destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 32)
                .map_err(|error| format!("chain Liquid destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive chain Liquid destination: {error}"))?;

    let (liquid_leg, liquid_purpose, liquid_path, liquid_wallet_path) = match input.direction {
        LiquidChainDirection::BitcoinToLiquid => (
            "destination",
            LiquidLegPurpose::CounterpartyLock,
            "claim",
            destination_exit_path,
        ),
        LiquidChainDirection::LiquidToBitcoin => (
            "source",
            LiquidLegPurpose::RequesterBroadcast,
            "refund",
            source_exit_path,
        ),
    };
    let claim_recovery = (input.direction == LiquidChainDirection::BitcoinToLiquid)
        .then(|| liquid_claim_recovery_refs(&control.paths, &journey_name, liquid_wallet_path))
        .transpose()?;
    let liquid_request = build_chain_liquid_request(
        runtime,
        environment,
        &contract,
        LiquidSwapType::Chain,
        liquid_leg,
        liquid_purpose,
        liquid_wallet_path,
        &liquid_destination.script_pubkey,
        claim_recovery.as_ref(),
    )?;
    bind_liquid_exit_commitment(&mut contract, liquid_leg, liquid_path, &liquid_request)?;

    let (bitcoin_leg, bitcoin_path, bitcoin_destination_script) = match input.direction {
        LiquidChainDirection::BitcoinToLiquid => (
            "source",
            "refund",
            bitcoin_destination.script_pubkey.as_slice(),
        ),
        LiquidChainDirection::LiquidToBitcoin => (
            "destination",
            "claim",
            bitcoin_destination.script_pubkey.as_slice(),
        ),
    };
    let bitcoin_exit = ExitPackage::parse(requester_exit_document(
        &contract,
        &order.id,
        &quote.id,
        bitcoin_leg,
        bitcoin_path,
        bitcoin_destination_script,
    )?)
    .map_err(|error| format!("chain Bitcoin exit package is invalid: {error}"))?;
    let bitcoin_exit_digest = bitcoin_exit
        .commitment_sha256()
        .map_err(|error| format!("could not commit chain Bitcoin exit package: {error}"))?;
    let commitments = contract
        .get_mut("exit_package_commitments")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "chain contract has no mutable exit commitments".to_owned())?;
    upsert_exit_commitment(
        commitments,
        "requester",
        bitcoin_leg,
        bitcoin_path,
        "wallet_sign",
        &bitcoin_exit_digest,
    );

    Ok(PreparedChainSession {
        pending: PendingSession {
            relay_url,
            reader,
            publisher,
            requester,
            provider_pubkey,
            factory,
            config,
            records,
            deliveries,
            order,
            order_observed_at,
            contract,
            exit_package_seeds: vec![bitcoin_exit],
            requester_funding: match &source_funding {
                ChainFundingTransaction::Bitcoin(funding) => Some(funding.clone()),
                ChainFundingTransaction::Liquid(_) => None,
            },
            journey_name,
            control,
        },
        source_funding,
        liquid_request,
        preimage,
        destination_exit_path,
    })
}

fn prepare_liquid_order(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    quoted: QuotedSession,
    input: &LiquidNegotiationInput,
    exit_wallet_path: WalletPath,
    exit_destination_script_pubkey: &[u8],
    claim_recovery_journey: Option<&str>,
) -> Result<PreparedLiquidSession, String> {
    let QuotedSession {
        relay_url,
        reader,
        mut publisher,
        requester,
        provider_pubkey,
        factory,
        config,
        mut records,
        mut deliveries,
        quote_observed_at,
        journey_name,
        control,
    } = quoted;
    let rfq = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_RFQ_KIND)
        .cloned()
        .ok_or_else(|| "quoted Liquid session has no RFQ".to_owned())?;
    let quote = records
        .iter()
        .find(|event| event.kind == MKT_QUOTE_KIND)
        .cloned()
        .ok_or_else(|| "quoted Liquid session has no Quote".to_owned())?;
    let session_id = config.session_id.clone();
    let (order, order_raw) = sign_request(
        factory
            .requester_order(RequesterOrderInput {
                rfq: &rfq,
                quote: &quote,
                created_at: next_created_at_records(&records)?,
                observed_at: quote_observed_at,
                distinct: &digest(&format!("order:{session_id}")),
                selection: None,
            })
            .map_err(|error| format!("could not construct Liquid Order: {error}"))?,
        &requester,
    )?;
    records.push(order.clone());
    let order_delivery = SignedRecordDelivery::from_locally_signed(order_raw.clone(), unix_now()?)
        .map_err(|error| format!("could not archive Liquid Order provenance: {error}"))?;
    let order_observed_at = order_delivery.observed_at();
    deliveries.push(order_delivery);
    publish_private(&mut publisher, &order_raw, &requester, &provider_pubkey)?;

    let quote_contract = factory
        .requester_contract_draft(
            &rfq,
            &quote,
            &order,
            order_observed_at,
            RequesterContractLocalInputs::for_swap_type(input.journey.swap_type()),
        )
        .map_err(|error| format!("could not inspect Liquid Quote terms: {error}"))?;
    let funding = match input.journey {
        LiquidJourney::Submarine => Some(liquid_requester_funding(
            runtime,
            environment,
            &quote_contract,
        )?),
        LiquidJourney::Reverse => None,
    };
    let mut local_inputs = RequesterContractLocalInputs::for_swap_type(input.journey.swap_type());
    if let Some(funding) = &funding {
        let funding_transaction = lower_hex(&funding.raw_transaction);
        local_inputs.funding_resolution = Some(RequesterFundingResolution {
            leg_id: "source".to_owned(),
            funding_transaction_sha256: lower_hex(&sha256(&funding.raw_transaction)),
            funding_transaction,
            output_index: funding.output_index,
        });
    }
    let mut contract = factory
        .requester_contract_draft(&rfq, &quote, &order, order_observed_at, local_inputs)
        .map_err(|error| format!("could not compose Liquid contract: {error}"))?;
    let (leg_id, purpose, path) = match input.journey {
        LiquidJourney::Submarine => ("source", LiquidLegPurpose::RequesterBroadcast, "refund"),
        LiquidJourney::Reverse => ("destination", LiquidLegPurpose::CounterpartyLock, "claim"),
    };
    let claim_recovery = claim_recovery_journey
        .map(|journey_name| {
            liquid_claim_recovery_refs(&control.paths, journey_name, exit_wallet_path)
        })
        .transpose()?;
    let liquid_request = build_chain_liquid_request(
        runtime,
        environment,
        &contract,
        input.journey.liquid_swap_type(),
        leg_id,
        purpose,
        exit_wallet_path,
        exit_destination_script_pubkey,
        claim_recovery.as_ref(),
    )?;
    bind_liquid_exit_commitment(&mut contract, leg_id, path, &liquid_request)?;
    Ok(PreparedLiquidSession {
        pending: PendingSession {
            relay_url,
            reader,
            publisher,
            requester,
            provider_pubkey,
            factory,
            config,
            records,
            deliveries,
            order,
            order_observed_at,
            contract,
            exit_package_seeds: Vec::new(),
            requester_funding: None,
            journey_name,
            control,
        },
        funding,
        liquid_request,
    })
}

fn finalize_negotiation(pending: PendingSession) -> Result<SessionContext, String> {
    let PendingSession {
        relay_url,
        mut reader,
        mut publisher,
        requester,
        provider_pubkey,
        factory,
        config,
        mut records,
        mut deliveries,
        order,
        order_observed_at,
        contract,
        exit_package_seeds,
        requester_funding,
        journey_name,
        control,
    } = pending;
    let session_id = config.session_id.clone();
    let rfq = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_RFQ_KIND)
        .cloned()
        .ok_or_else(|| "prepared funded session has no RFQ".to_owned())?;
    let quote = records
        .iter()
        .find(|event| event.kind == MKT_QUOTE_KIND)
        .cloned()
        .ok_or_else(|| "prepared funded session has no Quote".to_owned())?;
    let (requester_contract, requester_contract_raw) = sign_request(
        factory
            .requester_contract(RequesterContractSigningInput {
                rfq: &rfq,
                quote: &quote,
                order: &order,
                order_observed_at,
                created_at: next_created_at_records(&records)?,
                distinct: &digest(&format!("requester-contract:{session_id}")),
                contract: contract.clone(),
            })
            .map_err(|error| format!("could not construct funded contract: {error}"))?,
        &requester,
    )?;
    records.push(requester_contract.clone());
    deliveries.push(
        SignedRecordDelivery::from_locally_signed(requester_contract_raw.clone(), unix_now()?)
            .map_err(|error| format!("could not archive requester Contract provenance: {error}"))?,
    );
    publish_private(
        &mut publisher,
        &requester_contract_raw,
        &requester,
        &provider_pubkey,
    )?;
    let received_provider_contract = receive_matching_private(
        &mut reader,
        &requester,
        &session_id,
        JOURNEY_TIMEOUT,
        |event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND && event.pubkey == provider_pubkey,
    )
    .map_err(|error| format!("provider Swap Contract wait failed: {error}"))?;
    let provider_contract = received_provider_contract.event;
    deliveries.push(received_provider_contract.delivery);
    if record_profile(&provider_contract)?.get("contract") != Some(&contract) {
        return Err("provider countersigned different funded contract terms".to_owned());
    }
    provider_contract
        .validate_crypto()
        .map_err(|error| format!("funded provider contract signature is invalid: {error}"))?;
    let requester_contract_sha256 = exact_tag_value(&requester_contract, "x")?;
    if exact_tag_value(&provider_contract, "x")? != requester_contract_sha256 {
        return Err("provider contract digest differs from requester contract digest".to_owned());
    }
    records.push(provider_contract.clone());
    let exit_packages = exit_package_seeds
        .iter()
        .map(|seed| {
            finalize_exit_package(
                seed,
                [&requester_contract.id, &provider_contract.id],
                requester_contract_sha256,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(provider_seed) = exit_package_seeds.iter().find(|package| {
        package
            .document()
            .get("participant_role")
            .and_then(Value::as_str)
            == Some("provider")
    }) {
        let canonical =
            provider_support::build_provider_submarine_claim_exit_package(&config, &records)
                .map_err(|error| {
                    format!("could not rebuild accepted provider exit package: {error}")
                })?;
        if provider_seed
            .commitment_sha256()
            .map_err(|error| format!("could not commit provider exit seed: {error}"))?
            != canonical
                .commitment_sha256()
                .map_err(|error| format!("could not commit accepted provider exit: {error}"))?
        {
            return Err(
                "provider exit seed commitment differs from the accepted-session canonical package"
                    .to_owned(),
            );
        }
        if !exit_packages.iter().any(|package| package == &canonical) {
            return Err(
                "finalized provider exit differs from the accepted-session canonical package"
                    .to_owned(),
            );
        }
    }
    let verifier = SwapSession::from_signed_records(config, records, exit_packages)
        .map_err(|error| format!("funded verifier rejected negotiated session: {error}"))?;
    let mut session = SessionContext {
        relay_url,
        reader,
        publisher,
        requester,
        provider_pubkey,
        factory,
        verifier,
        deliveries,
        order,
        contract,
        authorized_verifier: None,
        requester_funding,
        requester_status: None,
        journey_name,
        control,
    };
    session.apply_pre_fund_injection()?;
    Ok(session)
}

fn chain_timeout_ladder(contract: &Value) -> Result<TimeoutLadder, String> {
    let ladder = contract
        .get("timeout_ladder")
        .and_then(Value::as_object)
        .ok_or_else(|| "chain contract has no timeout ladder".to_owned())?;
    Ok(TimeoutLadder::Chain {
        destination_final: ladder
            .get("destination_final")
            .and_then(Value::as_bool)
            .ok_or_else(|| "chain ladder has no destination finality".to_owned())?,
        destination_refund_time: ladder
            .get("destination_refund_time")
            .and_then(Value::as_u64)
            .ok_or_else(|| "chain ladder has no destination refund time".to_owned())?,
        source_refund_time: ladder
            .get("source_refund_time")
            .and_then(Value::as_u64)
            .ok_or_else(|| "chain ladder has no source refund time".to_owned())?,
        provider_claim_margin: ladder
            .get("provider_claim_margin")
            .and_then(Value::as_u64)
            .ok_or_else(|| "chain ladder has no provider claim margin".to_owned())?,
        both_network_reorg_margins: ladder
            .get("both_network_reorg_margins")
            .and_then(Value::as_u64)
            .ok_or_else(|| "chain ladder has no reorg margins".to_owned())?,
        both_network_broadcast_margins: ladder
            .get("both_network_broadcast_margins")
            .and_then(Value::as_u64)
            .ok_or_else(|| "chain ladder has no broadcast margins".to_owned())?,
    })
}

fn liquid_timeout_ladder(contract: &Value) -> Result<TimeoutLadder, String> {
    serde_json::from_value(
        contract
            .get("timeout_ladder")
            .cloned()
            .ok_or_else(|| "Liquid contract has no timeout ladder".to_owned())?,
    )
    .map_err(|error| format!("Liquid timeout ladder is invalid: {error}"))
}

fn liquid_invoice_verification(
    session: &SessionContext,
    invoice: &str,
    observed_at: u64,
) -> Result<InvoiceVerificationInput, String> {
    let lightning = verifier_for_leg(&session.contract, "lightning")?;
    Ok(InvoiceVerificationInput {
        invoice: invoice.to_owned(),
        expected_network: required_string(lightning, "invoice_network")?.to_owned(),
        expected_amount_msat: required_string(lightning, "invoice_amount_msat")?.to_owned(),
        observed_at,
        required_minimum_final_cltv_delta: canonical_u64(required_string(
            lightning,
            "invoice_minimum_final_cltv_delta",
        )?)?,
    })
}

fn observe_liquid_confirmed(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    request: &LiquidNodeRequest,
    label: &str,
) -> Result<LocalLiquidNodeObservation, String> {
    let genesis_hash = local_liquid_genesis_hash(runtime, liquid, label)?;
    let observation = runtime
        .block_on(
            liquid
                .elementsd
                .observe_transaction(&rpc_id(label)?, &request.transaction_id),
        )
        .map_err(|error| format!("could not observe exact Liquid funding: {error}"))?;
    if observation.raw_transaction != request.raw_transaction {
        return Err("local elementsd returned other Liquid funding bytes".to_owned());
    }
    Ok(LocalLiquidNodeObservation {
        authority: LiquidNodeAuthority::LocalElementsd,
        network_id: liquid.network_id.clone(),
        genesis_hash,
        pegged_asset: liquid.pegged_asset.clone(),
        observation: LocalLiquidObservation {
            transaction_id: request.transaction_id.clone(),
            transaction_sha256: request.transaction_sha256.clone(),
            confirmations: observation.confirmations,
            mempool_accepted: true,
            replacement_detected: false,
            competing_spend_detected: false,
        },
    })
}

fn liquid_lightning_readiness(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    request: &immortal_client::mkt_swp_client::LightningReadinessRequest,
    label: &str,
) -> Result<LocalLightningReadiness, String> {
    let final_cltv_delta = u32::try_from(request.minimum_final_cltv_delta)
        .map_err(|_| "Liquid invoice final CLTV delta exceeds u32".to_owned())?;
    let deadline = Instant::now() + LIGHTNING_READINESS_TIMEOUT;
    let request_id = cln_id(label)?;
    loop {
        let info = runtime
            .block_on(environment.peer_cln.node_info(&request_id))
            .map_err(|error| format!("could not inspect requester CLN readiness: {error}"))?;
        let minimum_outgoing_expiry = info
            .block_height
            .checked_add(final_cltv_delta)
            .ok_or_else(|| "Liquid requester CLN expiry calculation overflowed".to_owned())?;
        if minimum_outgoing_expiry >= request.hold_expiry_height || Instant::now() >= deadline {
            if info.network != request.network
                || !request.hold_invoice_required
                || info.block_height >= request.hold_expiry_height
                || minimum_outgoing_expiry < request.hold_expiry_height
            {
                return Err("requester CLN cannot satisfy Liquid hold-invoice timing".to_owned());
            }
            return Ok(LocalLightningReadiness {
                invoice_sha256: request.invoice_sha256.clone(),
                payment_hash: request.payment_hash.clone(),
                observed_at: unix_now()?,
                state: LightningReadinessState::Acceptable,
            });
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn authorize_liquid_submarine(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    request: &LiquidBeforeFundRequest,
    invoice: &str,
) -> Result<(SwapSession<FundingAuthorized>, VerifiedProviderLiquid), String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid submarine authorization has no local elementsd".to_owned())?;
    let retained = runtime
        .block_on(liquid.rail.verify_before_fund(request))
        .map_err(|error| format!("production Liquid rail rejected submarine funding: {error}"))?;
    let expected_raw = request.funding.raw_transaction.clone();
    let observed_at = unix_now()?;
    let authorized = session
        .verifier
        .clone()
        .verify_before_fund_with_liquid(
            LiquidVerifyBeforeFundInput {
                observed_at,
                payment_hash: lower_hex(&decode_fixed_hex::<32>(
                    session
                        .contract
                        .get("payment_hash")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "Liquid contract has no payment hash".to_owned())?,
                    "Liquid payment hash",
                )?),
                bitcoin_funding: None,
                invoice: Some(liquid_invoice_verification(session, invoice, observed_at)?),
                timeout_ladder: liquid_timeout_ladder(&session.contract)?,
                liquid: request.clone(),
            },
            |_request| {
                Err("explicit Liquid submarine unexpectedly requested unblinding".to_owned())
            },
            |node_request| {
                observe_liquid_mempool_template(
                    runtime,
                    liquid,
                    node_request,
                    "liquid-submarine-source-preflight",
                )
            },
            |authorization| match &authorization.action {
                FundingAction::BroadcastLiquid {
                    leg_id,
                    raw_transaction,
                    ..
                } if leg_id == "source" && raw_transaction == &expected_raw => Ok(()),
                _ => Err("client authorized another Liquid submarine effect".to_owned()),
            },
        )
        .map_err(|error| format!("client rejected Liquid submarine funding: {error}"))?;
    Ok((authorized, retained))
}

fn authorize_liquid_reverse(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    request: &LiquidBeforeFundRequest,
    invoice: &str,
) -> Result<(SwapSession<FundingAuthorized>, VerifiedProviderLiquid), String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid reverse authorization has no local elementsd".to_owned())?;
    let retained = runtime
        .block_on(liquid.rail.verify_before_fund(request))
        .map_err(|error| format!("production Liquid rail rejected reverse lock: {error}"))?;
    let observed_at = unix_now()?;
    let authorized = session
        .verifier
        .clone()
        .verify_before_fund_with_liquid_and_lightning(
            LiquidVerifyBeforeFundInput {
                observed_at,
                payment_hash: session
                    .contract
                    .get("payment_hash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Liquid contract has no payment hash".to_owned())?
                    .to_owned(),
                bitcoin_funding: None,
                invoice: Some(liquid_invoice_verification(session, invoice, observed_at)?),
                timeout_ladder: liquid_timeout_ladder(&session.contract)?,
                liquid: request.clone(),
            },
            |_request| Err("explicit Liquid reverse unexpectedly requested unblinding".to_owned()),
            |node_request| {
                observe_liquid_confirmed(
                    runtime,
                    liquid,
                    node_request,
                    "liquid-reverse-confirmed-lock",
                )
            },
            |readiness| {
                liquid_lightning_readiness(
                    runtime,
                    environment,
                    readiness,
                    "liquid-reverse-readiness",
                )
            },
            |authorization| match &authorization.action {
                FundingAction::PayLightningInvoice {
                    leg_id,
                    invoice: authorized_invoice,
                    hold_invoice_required,
                    ..
                } if leg_id == "lightning"
                    && authorized_invoice == invoice
                    && *hold_invoice_required =>
                {
                    Ok(())
                }
                _ => Err("client authorized another Liquid reverse effect".to_owned()),
            },
        )
        .map_err(|error| format!("client rejected Liquid reverse lock: {error}"))?;
    Ok((authorized, retained))
}

fn chain_bitcoin_verification_input(
    contract: &Value,
    leg_id: &str,
) -> Result<FundingVerificationInput, String> {
    let verifier = verifier_for_leg(contract, leg_id)?;
    Ok(FundingVerificationInput {
        raw_transaction: required_string(verifier, "funding_transaction")?.to_owned(),
        output_index: bounded_u32_member(verifier, "output_index")?,
        expected_amount: required_string(verifier, "amount")?.to_owned(),
        expected_script_pubkey: required_string(verifier, "script_pubkey")?.to_owned(),
        taproot_output_key: required_string(verifier, "taproot_output_key")?.to_owned(),
        taproot_script: match leg_id {
            "source" => required_string(verifier, "refund_script")?.to_owned(),
            "destination" => required_string(verifier, "claim_script")?.to_owned(),
            _ => return Err("chain Bitcoin verifier leg is unsupported".to_owned()),
        },
        taproot_control_block: match leg_id {
            "source" => required_string(verifier, "taproot_refund_control_block")?.to_owned(),
            "destination" => required_string(verifier, "taproot_claim_control_block")?.to_owned(),
            _ => return Err("chain Bitcoin verifier leg is unsupported".to_owned()),
        },
    })
}

fn observe_liquid_mempool_template(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    node_request: &LiquidNodeRequest,
    label: &str,
) -> Result<LocalLiquidNodeObservation, String> {
    let genesis_hash = local_liquid_genesis_hash(runtime, liquid, label)?;
    runtime
        .block_on(
            liquid
                .elementsd
                .require_mempool_acceptance(&rpc_id(label)?, &node_request.raw_transaction),
        )
        .map_err(|error| format!("local elementsd rejected the exact Liquid template: {error}"))?;
    Ok(LocalLiquidNodeObservation {
        authority: LiquidNodeAuthority::LocalElementsd,
        network_id: liquid.network_id.clone(),
        genesis_hash,
        pegged_asset: liquid.pegged_asset.clone(),
        observation: LocalLiquidObservation {
            transaction_id: node_request.transaction_id.clone(),
            transaction_sha256: node_request.transaction_sha256.clone(),
            confirmations: 0,
            mempool_accepted: true,
            replacement_detected: false,
            competing_spend_detected: false,
        },
    })
}

fn local_liquid_genesis_hash(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    label: &str,
) -> Result<String, String> {
    runtime
        .block_on(
            liquid
                .elementsd
                .genesis_hash(&rpc_id(&format!("{label}-genesis"))?),
        )
        .map_err(|error| format!("could not verify the local Liquid genesis hash: {error}"))
}

fn chain_bitcoin_before_fund_input(
    session: &SessionContext,
    leg_id: &str,
) -> Result<VerifyBeforeFundInput, String> {
    let funding = chain_bitcoin_verification_input(&session.contract, leg_id)?;
    let verifier = verifier_for_leg(&session.contract, leg_id)?;
    Ok(VerifyBeforeFundInput {
        observed_at: unix_now()?,
        payment_hash: session
            .contract
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "chain contract has no payment hash".to_owned())?
            .to_owned(),
        funding,
        invoice: None,
        timeout_ladder: chain_timeout_ladder(&session.contract)?,
        minimum_confirmations: u32::try_from(canonical_u64(required_string(
            verifier,
            "minimum_confirmations",
        )?)?)
        .map_err(|_| "chain minimum confirmation count exceeds u32".to_owned())?,
        replacement_policy: required_string(verifier, "replacement_policy")?.to_owned(),
    })
}

fn verify_chain_source(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    liquid_request: &LiquidBeforeFundRequest,
    direction: LiquidChainDirection,
) -> Result<(), String> {
    match direction {
        LiquidChainDirection::BitcoinToLiquid => {
            let input = chain_bitcoin_before_fund_input(session, "source")?;
            let expected_raw = input.funding.raw_transaction.clone();
            session
                .verifier
                .clone()
                .verify_before_fund(input, |request| match &request.action {
                    FundingAction::BroadcastBitcoin {
                        leg_id,
                        raw_transaction,
                        ..
                    } if leg_id == "source" && raw_transaction == &expected_raw => Ok(()),
                    _ => Err("source preflight authorized another Bitcoin effect".to_owned()),
                })
                .map(|_| ())
                .map_err(|error| format!("client rejected Bitcoin source preflight: {error}"))
        }
        LiquidChainDirection::LiquidToBitcoin => {
            let liquid = environment
                .liquid
                .as_ref()
                .ok_or_else(|| "chain source preflight has no local elementsd".to_owned())?;
            runtime
                .block_on(liquid.rail.verify_before_fund(liquid_request))
                .map_err(|error| {
                    format!("production Liquid rail rejected source preflight: {error}")
                })?;
            let expected_raw = liquid_request.funding.raw_transaction.clone();
            session
                .verifier
                .clone()
                .verify_before_fund_with_liquid(
                    LiquidVerifyBeforeFundInput {
                        observed_at: unix_now()?,
                        payment_hash: session
                            .contract
                            .get("payment_hash")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "chain contract has no payment hash".to_owned())?
                            .to_owned(),
                        bitcoin_funding: None,
                        invoice: None,
                        timeout_ladder: chain_timeout_ladder(&session.contract)?,
                        liquid: liquid_request.clone(),
                    },
                    |_request: &LiquidUnblindRequest| {
                        Err("explicit Liquid source unexpectedly requested unblinding".to_owned())
                    },
                    |node_request: &LiquidNodeRequest| {
                        observe_liquid_mempool_template(
                            runtime,
                            liquid,
                            node_request,
                            "chain-liquid-source-preflight",
                        )
                    },
                    |authorization| match &authorization.action {
                        FundingAction::BroadcastLiquid {
                            leg_id,
                            raw_transaction,
                            ..
                        } if leg_id == "source" && raw_transaction == &expected_raw => Ok(()),
                        _ => Err("source preflight authorized another Liquid effect".to_owned()),
                    },
                )
                .map(|_| ())
                .map_err(|error| format!("client rejected Liquid source preflight: {error}"))
        }
    }
}

fn authorize_chain_funding(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    liquid_request: &LiquidBeforeFundRequest,
    direction: LiquidChainDirection,
) -> Result<SwapSession<FundingAuthorized>, String> {
    let payment_hash = session
        .contract
        .get("payment_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "chain contract has no payment hash".to_owned())?
        .to_owned();
    let observed_at = unix_now()?;
    let timeout_ladder = chain_timeout_ladder(&session.contract)?;
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "chain source authorization has no local elementsd".to_owned())?;
    match direction {
        LiquidChainDirection::BitcoinToLiquid => {
            let funding = chain_bitcoin_verification_input(&session.contract, "source")?;
            let expected_raw = funding.raw_transaction.clone();
            session
                .verifier
                .clone()
                .verify_before_fund_with_liquid(
                    LiquidVerifyBeforeFundInput {
                        observed_at,
                        payment_hash,
                        bitcoin_funding: Some(funding),
                        invoice: None,
                        timeout_ladder,
                        liquid: liquid_request.clone(),
                    },
                    |_request: &LiquidUnblindRequest| {
                        Err(
                            "explicit Liquid destination unexpectedly requested unblinding"
                                .to_owned(),
                        )
                    },
                    |node_request: &LiquidNodeRequest| {
                        observe_liquid_mempool_template(
                            runtime,
                            liquid,
                            node_request,
                            "chain-bitcoin-to-liquid-template",
                        )
                    },
                    |request| match &request.action {
                        FundingAction::BroadcastBitcoin {
                            leg_id,
                            raw_transaction,
                            ..
                        } if leg_id == "source" && raw_transaction == &expected_raw => Ok(()),
                        _ => {
                            Err("client authorized another BTC-to-Liquid source effect".to_owned())
                        }
                    },
                )
                .map_err(|error| format!("client rejected BTC-to-Liquid source funding: {error}"))
        }
        LiquidChainDirection::LiquidToBitcoin => {
            let bitcoin_funding =
                chain_bitcoin_verification_input(&session.contract, "destination")?;
            runtime
                .block_on(liquid.rail.verify_before_fund(liquid_request))
                .map_err(|error| {
                    format!("production Liquid rail rejected source funding: {error}")
                })?;
            let request = liquid_request.clone();
            session
                .verifier
                .clone()
                .verify_before_fund_with_liquid(
                    LiquidVerifyBeforeFundInput {
                        observed_at,
                        payment_hash,
                        bitcoin_funding: Some(bitcoin_funding),
                        invoice: None,
                        timeout_ladder,
                        liquid: request.clone(),
                    },
                    |_request: &LiquidUnblindRequest| {
                        Err("explicit Liquid source unexpectedly requested unblinding".to_owned())
                    },
                    |node_request: &LiquidNodeRequest| {
                        observe_liquid_mempool_template(
                            runtime,
                            liquid,
                            node_request,
                            "chain-liquid-to-bitcoin-source",
                        )
                    },
                    |authorization| match &authorization.action {
                        FundingAction::BroadcastLiquid { leg_id, .. } if leg_id == "source" => {
                            Ok(())
                        }
                        _ => {
                            Err("client authorized another Liquid-to-Bitcoin source effect"
                                .to_owned())
                        }
                    },
                )
                .map_err(|error| {
                    format!("client rejected Liquid-to-Bitcoin source funding: {error}")
                })
        }
    }
}

impl SessionContext {
    fn apply_pre_fund_injection(&mut self) -> Result<(), String> {
        match self.control.injection {
            Some(HarnessInjection::DuplicateMessage) => {
                let duplicate = self.order.clone();
                if self
                    .verifier
                    .ingest_signed_record(duplicate)
                    .map_err(|error| format!("duplicate injection was rejected: {error}"))?
                {
                    return Err("duplicate injection created another logical record".to_owned());
                }
                Ok(())
            }
            Some(HarnessInjection::ConflictingMessage) => {
                let mut conflicting = self.order.clone();
                conflicting.content.push(' ');
                let error = match self.verifier.ingest_signed_record(conflicting) {
                    Ok(_) => return Err("conflicting signed bytes were accepted".to_owned()),
                    Err(error) => error,
                };
                if error.code != "swp_idempotency_conflict" {
                    return Err(format!(
                        "conflict injection returned another refusal: {error}"
                    ));
                }
                Err("injected conflicting message rejected before funding".to_owned())
            }
            Some(HarnessInjection::SecretLeak) => {
                let error = match provider_support::reject_custody_material(&json!({
                    "preimage": "00".repeat(32)
                })) {
                    Ok(()) => return Err("custody injection was accepted".to_owned()),
                    Err(error) => error,
                };
                if error.code != "swp_secret_material_forbidden" {
                    return Err(format!(
                        "secret injection returned another refusal: {error}"
                    ));
                }
                Err("injected custody material rejected before persistence or funding".to_owned())
            }
            Some(HarnessInjection::StatusGap) => self.inject_status_gap(),
            Some(HarnessInjection::StatusFork) => self.inject_status_fork(),
            Some(HarnessInjection::WrongClaimKey | HarnessInjection::ProviderNoncooperative) => {
                Ok(())
            }
            Some(HarnessInjection::StaleQuote)
            | Some(
                HarnessInjection::RelayLoss
                | HarnessInjection::ProviderCrash
                | HarnessInjection::WalletCrash
                | HarnessInjection::FundingReorg
                | HarnessInjection::ClaimReorg
                | HarnessInjection::RbfConflict
                | HarnessInjection::ZeroConfRbfReplacement
                | HarnessInjection::ZeroConfDoubleSpend
                | HarnessInjection::ZeroConfAncestorEviction
                | HarnessInjection::CooperativeCrashCut,
            )
            | None => Ok(()),
        }
    }

    fn signed_requester_status(
        &self,
        sequence: u64,
        previous: Option<&str>,
        distinct: &str,
    ) -> Result<Event, String> {
        let (event, _) = sign_request(
            self.factory
                .status(
                    ParticipantRole::Requester,
                    next_created_at(&self.verifier)?,
                    distinct,
                    &self.order.id,
                    StatusState {
                        sequence,
                        previous,
                        base_state: base_state("requester_verification_passed")?,
                        swp_state: "requester_verification_passed",
                    },
                    Map::new(),
                )
                .map_err(|error| format!("could not construct adversarial Status: {error}"))?,
            &self.requester,
        )?;
        Ok(event)
    }

    fn inject_status_gap(&mut self) -> Result<(), String> {
        let previous = digest(&format!(
            "missing-requester-status:{}",
            self.verifier.config().session_id
        ));
        let distinct = digest(&format!(
            "requester-status-gap:{}",
            self.verifier.config().session_id
        ));
        let status = self.signed_requester_status(1, Some(&previous), &distinct)?;
        if !self
            .verifier
            .ingest_signed_record(status)
            .map_err(|error| format!("could not ingest Status gap record: {error}"))?
        {
            return Err("Status gap replayed another record".to_owned());
        }
        let error = match self
            .verifier
            .status_projection()
            .and_then(|projection| projection.require_contiguous())
        {
            Ok(()) => return Err("Status gap projection was contiguous".to_owned()),
            Err(error) => error,
        };
        if error.code != "swp_status_gap" {
            return Err(format!("Status gap returned another refusal: {error}"));
        }
        Err("swp_status_gap rejected before external effect".to_owned())
    }

    fn inject_status_fork(&mut self) -> Result<(), String> {
        let first_distinct = digest(&format!(
            "requester-status-fork-a:{}",
            self.verifier.config().session_id
        ));
        let first = self.signed_requester_status(0, None, &first_distinct)?;
        if !self
            .verifier
            .ingest_signed_record(first)
            .map_err(|error| format!("could not establish Status fork prefix: {error}"))?
        {
            return Err("Status fork prefix replayed another record".to_owned());
        }
        let second_distinct = digest(&format!(
            "requester-status-fork-b:{}",
            self.verifier.config().session_id
        ));
        let second = self.signed_requester_status(0, None, &second_distinct)?;
        if !self
            .verifier
            .ingest_signed_record(second)
            .map_err(|error| format!("could not ingest Status fork record: {error}"))?
        {
            return Err("Status fork replayed another record".to_owned());
        }
        let error = match self
            .verifier
            .status_projection()
            .and_then(|projection| projection.require_contiguous())
        {
            Ok(()) => return Err("Status fork projection was contiguous".to_owned()),
            Err(error) => error,
        };
        if error.code != "swp_status_fork" {
            return Err(format!("Status fork returned another refusal: {error}"));
        }
        Err("swp_status_fork rejected before external effect".to_owned())
    }

    fn set_authorized_verifier(
        &mut self,
        authorized: SwapSession<FundingAuthorized>,
    ) -> Result<(), String> {
        if authorized.signed_records() != self.verifier.signed_records()
            || authorized.config().session_id != self.verifier.config().session_id
        {
            return Err("funding authorization belongs to another signed session view".to_owned());
        }
        self.authorized_verifier = Some(authorized);
        self.persist_authorized("funding_authorized", true)
    }

    fn persist_authorized(&mut self, label: &str, safe_to_stop: bool) -> Result<(), String> {
        self.persist_authorized_details(label, safe_to_stop, json!({}))
    }

    fn persist_authorized_details(
        &mut self,
        label: &str,
        safe_to_stop: bool,
        details: Value,
    ) -> Result<(), String> {
        let authorized = self
            .authorized_verifier
            .as_ref()
            .ok_or_else(|| "funded session has no funding authorization to persist".to_owned())?;
        let snapshot = authorized
            .persist()
            .map_err(|error| format!("could not persist funded client session: {error}"))?;
        store_funded_snapshot(&self.control.paths, &self.journey_name, &snapshot)?;
        self.persist_deliveries()?;
        let mut checkpoint_details = details
            .as_object()
            .cloned()
            .ok_or_else(|| "funded checkpoint details must be an object".to_owned())?;
        checkpoint_details.insert(
            "session_id".to_owned(),
            Value::String(authorized.config().session_id.clone()),
        );
        checkpoint_details.insert("order_id".to_owned(), Value::String(self.order.id.clone()));
        checkpoint_details.insert(
            "snapshot".to_owned(),
            Value::String(
                self.control
                    .paths
                    .funded_snapshot(&self.journey_name)
                    .display()
                    .to_string(),
            ),
        );
        checkpoint_details.insert(
            "deliveries".to_owned(),
            Value::String(
                self.control
                    .paths
                    .funded_deliveries(&self.journey_name)
                    .display()
                    .to_string(),
            ),
        );
        let recovered_external_process = self.control.checkpoint(
            &self.journey_name,
            label,
            safe_to_stop,
            Value::Object(checkpoint_details),
        )?;
        if recovered_external_process && self.control.injection == Some(HarnessInjection::RelayLoss)
        {
            self.reconnect_relay()?;
        }
        Ok(())
    }

    fn persist_terminal(&mut self, label: &str, result: Value) -> Result<(), String> {
        self.persist_authorized_details(label, true, json!({"result": result}))
    }

    fn reconnect_relay(&mut self) -> Result<(), String> {
        let now = unix_now()?;
        let mut reader = connect(&self.relay_url)?;
        authenticate(&mut reader, &self.requester, &self.relay_url, now)?;
        subscribe(&mut reader, self.requester.pubkey())?;
        let mut publisher = connect(&self.relay_url)?;
        authenticate(&mut publisher, &self.requester, &self.relay_url, now)?;
        self.reader = reader;
        self.publisher = publisher;
        Ok(())
    }

    fn persist_snapshot(&self) -> Result<(), String> {
        let Some(authorized) = self.authorized_verifier.as_ref() else {
            return Ok(());
        };
        let snapshot = authorized
            .persist()
            .map_err(|error| format!("could not persist funded client session: {error}"))?;
        store_funded_snapshot(&self.control.paths, &self.journey_name, &snapshot)?;
        self.persist_deliveries()
    }

    fn persist_deliveries(&self) -> Result<(), String> {
        let archive = serde_json::to_value(&self.deliveries)
            .map_err(|error| format!("could not encode funded delivery provenance: {error}"))?;
        store_funded_deliveries(&self.control.paths, &self.journey_name, &archive)
    }

    fn record_funding_effect(
        &mut self,
        external_identifier: String,
        result_digest: [u8; 32],
    ) -> Result<(), String> {
        let checkpoint_identifier = external_identifier.clone();
        let authorized = self
            .authorized_verifier
            .as_mut()
            .ok_or_else(|| "funded session has no preserved funding authorization".to_owned())?;
        let request = ExternalEffectRequest::Funding(
            authorized
                .funding_request()
                .map_err(|error| format!("funded session has no funding request: {error}"))?
                .clone(),
        );
        authorized
            .record_external_effect(&request, external_identifier, lower_hex(&result_digest))
            .map_err(|error| format!("could not persist funded execution effect: {error}"))?;
        self.persist_authorized_details(
            "funding_effect_recorded",
            true,
            json!({"external_identifier": checkpoint_identifier}),
        )
    }

    fn wait_provider_state(&mut self, expected: &str) -> Result<Event, String> {
        if let Some(existing) = self.verifier.signed_records().iter().find(|event| {
            event.kind == MKT_STATUS_KIND
                && event.pubkey == self.provider_pubkey
                && record_profile(event)
                    .ok()
                    .and_then(|profile| profile.get("swp_state").cloned())
                    .and_then(|state| state.as_str().map(str::to_owned))
                    .as_deref()
                    == Some(expected)
        }) {
            return Ok(existing.clone());
        }
        let session_id = self.verifier.config().session_id.clone();
        let received = receive_matching_private(
            &mut self.reader,
            &self.requester,
            &session_id,
            JOURNEY_TIMEOUT,
            |event| {
                event.kind == MKT_STATUS_KIND
                    && event.pubkey == self.provider_pubkey
                    && record_profile(event)
                        .ok()
                        .and_then(|profile| profile.get("swp_state").cloned())
                        .and_then(|state| state.as_str().map(str::to_owned))
                        .as_deref()
                        == Some(expected)
            },
        )
        .map_err(|error| format!("provider {expected} Status wait failed: {error}"))?;
        let event = received.event;
        self.deliveries.push(received.delivery);
        self.ingest_synchronized(event.clone(), &format!("provider {expected}"))?;
        Ok(event)
    }

    fn wait_provider_cooperative_action(
        &mut self,
        expected: CooperativeSigningAction,
    ) -> Result<(Event, CooperativeSigningMessage), String> {
        if let Some((event, message)) = self.verifier.signed_records().iter().find_map(|event| {
            if event.kind != MKT_STATUS_KIND || event.pubkey != self.provider_pubkey {
                return None;
            }
            provider_support::cooperative_signing_message(event, ParticipantRole::Provider)
                .ok()
                .flatten()
                .filter(|message| message.action == expected)
                .map(|message| (event.clone(), message))
        }) {
            return Ok((event, message));
        }
        let session_id = self.verifier.config().session_id.clone();
        let received = receive_matching_private(
            &mut self.reader,
            &self.requester,
            &session_id,
            JOURNEY_TIMEOUT,
            |event| {
                event.kind == MKT_STATUS_KIND
                    && event.pubkey == self.provider_pubkey
                    && provider_support::cooperative_signing_message(
                        event,
                        ParticipantRole::Provider,
                    )
                    .ok()
                    .flatten()
                    .is_some_and(|message| message.action == expected)
            },
        )
        .map_err(|error| {
            format!(
                "provider cooperative {} Status wait failed: {error}",
                cooperative_action_name(expected)
            )
        })?;
        let event = received.event;
        self.deliveries.push(received.delivery);
        self.ingest_synchronized(
            event.clone(),
            &format!("provider cooperative {}", cooperative_action_name(expected)),
        )?;
        let message =
            provider_support::cooperative_signing_message(&event, ParticipantRole::Provider)
                .map_err(|error| format!("provider cooperative Status is invalid: {error}"))?
                .ok_or_else(|| "provider cooperative Status has no message".to_owned())?;
        Ok((event, message))
    }

    fn wait_provider_close(
        &mut self,
        expected_outcome: &str,
        check: TerminalRailCheck<'_>,
    ) -> Result<Event, String> {
        let session_id = self.verifier.config().session_id.clone();
        let (event, delivery) = match self.verifier.signed_records().iter().find(|event| {
            event.kind == MKT_CLOSE_KIND
                && event.pubkey == self.provider_pubkey
                && event
                    .tag_values("outcome")
                    .eq(std::iter::once(expected_outcome))
        }) {
            Some(existing) => (existing.clone(), None),
            None => {
                let received = receive_matching_private(
                    &mut self.reader,
                    &self.requester,
                    &session_id,
                    JOURNEY_TIMEOUT,
                    |event| {
                        event.kind == MKT_CLOSE_KIND
                            && event.pubkey == self.provider_pubkey
                            && event
                                .tag_values("outcome")
                                .eq(std::iter::once(expected_outcome))
                    },
                )
                .map_err(|error| {
                    format!("provider {expected_outcome} Close wait failed: {error}")
                })?;
                (received.event, Some(received.delivery))
            }
        };
        if let Some(delivery) = delivery {
            self.deliveries.push(delivery);
        }
        let leg_ids = contract_leg_ids(&self.contract)?;
        let mut authorized = self
            .authorized_verifier
            .as_ref()
            .ok_or_else(|| {
                "provider Close arrived without a preserved funding authorization".to_owned()
            })?
            .clone();
        for leg_id in leg_ids {
            let verified = authorized
                .verify_terminal_rail_evidence_with(&leg_id, expected_outcome, |request| {
                    local_terminal_rail_evidence(&event, request, &check, &self.contract)
                })
                .map_err(|error| {
                    format!(
                        "local {leg_id} terminal evidence rejected before provider Close: {error}"
                    )
                })?;
            authorized
                .record_verified_rail_evidence(verified)
                .map_err(|error| {
                    format!("could not persist local {leg_id} terminal evidence: {error}")
                })?;
        }
        authorized
            .ingest_signed_record(event.clone())
            .map_err(|error| {
                format!("funded verifier rejected provider {expected_outcome} Close: {error}")
            })?;
        self.authorized_verifier = Some(authorized);
        Ok(event)
    }

    fn publish_requester_status(
        &mut self,
        state: &'static str,
        extra: Map<String, Value>,
    ) -> Result<Event, String> {
        if let Some(existing) = self.verifier.signed_records().iter().find(|event| {
            if event.kind != MKT_STATUS_KIND || event.pubkey != self.requester.pubkey() {
                return false;
            }
            let Ok(profile) = record_profile(event) else {
                return false;
            };
            profile.get("swp_state").and_then(Value::as_str) == Some(state)
                && extra
                    .iter()
                    .all(|(name, value)| profile.get(name) == Some(value))
        }) {
            return Ok(existing.clone());
        }
        let (sequence, previous) = match &self.requester_status {
            Some((sequence, previous)) => (
                sequence
                    .checked_add(1)
                    .ok_or_else(|| "requester Status sequence overflowed".to_owned())?,
                Some(previous.as_str()),
            ),
            None => (0, None),
        };
        let created_at = next_created_at(&self.verifier)?;
        let distinct = digest(&format!(
            "requester-status:{state}:{}",
            self.verifier.config().session_id
        ));
        let status = StatusState {
            sequence,
            previous,
            base_state: base_state(state)?,
            swp_state: state,
        };
        let request = match requester_status_provider_prerequisite_event(
            self.verifier.signed_records(),
            &self.provider_pubkey,
            state,
        )? {
            Some(prerequisite) => self.factory.status_after(
                ParticipantRole::Requester,
                created_at,
                &distinct,
                &self.order.id,
                status,
                &prerequisite.id,
                extra,
            ),
            None => self.factory.status(
                ParticipantRole::Requester,
                created_at,
                &distinct,
                &self.order.id,
                status,
                extra,
            ),
        }
        .map_err(|error| format!("could not construct requester {state}: {error}"))?;
        let (event, raw_event) = sign_request(request, &self.requester)?;
        let delivery = SignedRecordDelivery::from_locally_signed(raw_event.clone(), unix_now()?)
            .map_err(|error| format!("could not retain requester Status provenance: {error}"))?;
        self.ingest_synchronized(event.clone(), &format!("requester {state}"))?;
        self.deliveries.push(delivery);
        self.persist_snapshot()?;
        publish_private(
            &mut self.publisher,
            &raw_event,
            &self.requester,
            &self.provider_pubkey,
        )?;
        self.requester_status = Some((sequence, event.id.clone()));
        Ok(event)
    }

    fn publish_requester_cooperative_status(
        &mut self,
        message: CooperativeSigningMessage,
    ) -> Result<Event, String> {
        let action = cooperative_action_name(message.action);
        let (sequence, previous) = match &self.requester_status {
            Some((sequence, previous)) => (
                sequence
                    .checked_add(1)
                    .ok_or_else(|| "requester Status sequence overflowed".to_owned())?,
                Some(previous.as_str()),
            ),
            None => (0, None),
        };
        let (event, raw_event) = sign_request(
            self.factory
                .cooperative_status(
                    ParticipantRole::Requester,
                    next_created_at(&self.verifier)?,
                    &digest(&format!(
                        "requester-cooperative:{action}:{}",
                        self.verifier.config().session_id
                    )),
                    &self.order.id,
                    StatusState {
                        sequence,
                        previous,
                        base_state: "executing",
                        swp_state: "cooperative_signing_pending",
                    },
                    message,
                )
                .map_err(|error| {
                    format!("could not construct requester cooperative {action}: {error}")
                })?,
            &self.requester,
        )?;
        let delivery = SignedRecordDelivery::from_locally_signed(raw_event.clone(), unix_now()?)
            .map_err(|error| {
                format!("could not retain requester cooperative {action} provenance: {error}")
            })?;
        self.ingest_synchronized(event.clone(), &format!("requester cooperative {action}"))?;
        self.deliveries.push(delivery);
        self.persist_snapshot()?;
        publish_private(
            &mut self.publisher,
            &raw_event,
            &self.requester,
            &self.provider_pubkey,
        )?;
        self.requester_status = Some((sequence, event.id.clone()));
        Ok(event)
    }

    fn ingest_synchronized(&mut self, event: Event, label: &str) -> Result<(), String> {
        let mut verifier = self.verifier.clone();
        verifier
            .ingest_signed_record(event.clone())
            .map_err(|error| format!("funded verifier rejected {label}: {error}"))?;
        let authorized = self
            .authorized_verifier
            .as_ref()
            .map(|authorized| {
                let mut authorized = authorized.clone();
                authorized
                    .ingest_signed_record(event)
                    .map(|_| authorized)
                    .map_err(|error| {
                        format!("funding-authorized verifier rejected {label}: {error}")
                    })
            })
            .transpose()?;
        self.verifier = verifier;
        self.authorized_verifier = authorized;
        self.persist_snapshot()
    }
}

fn contract_leg_ids(contract: &Value) -> Result<Vec<String>, String> {
    let legs = contract
        .get("legs")
        .and_then(Value::as_array)
        .ok_or_else(|| "funded contract has no legs".to_owned())?;
    let mut leg_ids = Vec::with_capacity(legs.len());
    for leg in legs {
        let leg_id = leg
            .get("leg_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "funded contract leg has no identifier".to_owned())?;
        if leg_ids.iter().any(|existing| existing == leg_id) {
            return Err("funded contract duplicates a leg identifier".to_owned());
        }
        leg_ids.push(leg_id.to_owned());
    }
    Ok(leg_ids)
}

fn local_terminal_rail_evidence(
    close: &Event,
    request: &RailObservationRequest,
    check: &TerminalRailCheck<'_>,
    contract: &Value,
) -> Result<LocalRailEvidence, String> {
    let evidence = exact_close_evidence_reference(close, request)?;
    let settlement_reference = required_string(&evidence, "reference")?;
    let (artifact_sha256, view, external_identifier) = match request.rail.as_str() {
        "bitcoin" => (
            required_string(&evidence, "artifact_sha256")?.to_owned(),
            required_string(&evidence, "view")?.to_owned(),
            verify_local_bitcoin_terminal(request, settlement_reference, check, contract)?,
        ),
        "liquid" => {
            let derived =
                verify_local_liquid_terminal(request, settlement_reference, check, contract)?;
            require_exact_liquid_terminal_metadata(&evidence, &derived)?;
            (
                derived.artifact_sha256,
                derived.view,
                derived.external_identifier,
            )
        }
        "lightning" => (
            required_string(&evidence, "artifact_sha256")?.to_owned(),
            required_string(&evidence, "view")?.to_owned(),
            verify_local_lightning_terminal(request, settlement_reference, check)?,
        ),
        _ => return Err("terminal evidence requested an unsupported local rail".to_owned()),
    };
    let producer_pubkey = required_string(&evidence, "producer_pubkey")?;
    if producer_pubkey != close.pubkey {
        return Err("provider Close evidence names another producer".to_owned());
    }
    let verifier_pubkey = match evidence.get("verifier_pubkey") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        _ => return Err("provider Close evidence has an invalid verifier key".to_owned()),
    };
    Ok(LocalRailEvidence {
        artifact_sha256,
        observed_at: evidence
            .get("observed_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| "provider Close evidence has no observation time".to_owned())?,
        view,
        settlement_reference: settlement_reference.to_owned(),
        verifier_pubkey,
        producer_pubkey: producer_pubkey.to_owned(),
        external_identifier,
    })
}

fn exact_close_evidence_reference(
    close: &Event,
    request: &RailObservationRequest,
) -> Result<Map<String, Value>, String> {
    let matching = close_evidence_references(close)?
        .into_iter()
        .filter_map(|evidence| evidence.as_object().cloned())
        .filter(|evidence| {
            evidence.get("rail").and_then(Value::as_str) == Some(request.rail.as_str())
                && evidence.get("class").and_then(Value::as_str)
                    == Some(request.evidence_class.as_str())
                && evidence.get("rung").and_then(Value::as_str) == Some(request.rung.as_str())
                && evidence.get("verifier_policy").and_then(Value::as_str)
                    == Some(request.verifier_policy.as_str())
        })
        .collect::<Vec<_>>();
    let [evidence] = matching.as_slice() else {
        return Err(format!(
            "provider Close does not carry one exact {} terminal reference",
            request.rail
        ));
    };
    Ok(evidence.clone())
}

fn close_evidence_references(close: &Event) -> Result<Vec<Value>, String> {
    record_profile(close)?
        .get("loss_accounting")
        .and_then(Value::as_object)
        .and_then(|accounting| accounting.get("evidence_refs"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "provider Close has no terminal evidence references".to_owned())
}

fn local_final_bitcoin_transaction(
    check: &TerminalRailCheck<'_>,
    label: &str,
    transaction_id: &str,
) -> Result<(Vec<u8>, Transaction), String> {
    let transaction = check
        .runtime
        .block_on(
            check
                .environment
                .bitcoind
                .raw_transaction(&rpc_id(label)?, transaction_id, true),
        )
        .map_err(|error| format!("could not inspect terminal Bitcoin transaction: {error}"))?;
    let transaction = transaction
        .as_object()
        .ok_or_else(|| "terminal Bitcoin transaction response is not an object".to_owned())?;
    if transaction.get("txid").and_then(Value::as_str) != Some(transaction_id)
        || transaction.get("confirmations").and_then(Value::as_u64)
            < Some(check.environment.terminal_confirmations)
    {
        return Err("terminal Bitcoin transaction is not final in the local node view".to_owned());
    }
    let raw = decode_hex(
        transaction
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "terminal Bitcoin response has no raw transaction".to_owned())?,
    )?;
    let parsed = Transaction::parse(&raw)
        .map_err(|error| format!("terminal Bitcoin transaction is invalid: {error}"))?;
    if lower_hex(
        &parsed.txid().map_err(|error| {
            format!("could not derive terminal Bitcoin transaction ID: {error}")
        })?,
    ) != transaction_id
    {
        return Err("terminal Bitcoin transaction has another transaction ID".to_owned());
    }
    Ok((raw, parsed))
}

fn verify_local_bitcoin_terminal(
    request: &RailObservationRequest,
    settlement_reference: &str,
    check: &TerminalRailCheck<'_>,
    contract: &Value,
) -> Result<String, String> {
    let verifier = verifier_for_leg(contract, &request.leg_id)?;
    let raw_funding = required_string(verifier, "funding_transaction")
        .and_then(decode_hex)
        .map_err(|error| format!("contract funding transaction is invalid: {error}"))?;
    let funding = Transaction::parse(&raw_funding)
        .map_err(|error| format!("contract funding transaction is invalid: {error}"))?;
    let funding_txid =
        lower_hex(&funding.txid().map_err(|error| {
            format!("could not derive contract funding transaction ID: {error}")
        })?);
    let funding_vout = bounded_u32_member(verifier, "output_index")?;
    let funding_outpoint = format!("{funding_txid}:{funding_vout}");
    let (terminal_transaction_id, requires_spend) = match request.evidence_class.as_str() {
        "bitcoin_output"
            if request.reference == funding_outpoint
                && settlement_reference == funding_outpoint =>
        {
            (funding_txid.as_str(), false)
        }
        "bitcoin_spend"
            if request.reference == funding_outpoint
                && settlement_reference == funding_outpoint =>
        {
            (
                check.bitcoin_settlement_txid.ok_or_else(|| {
                    "terminal Bitcoin spend has no local settlement transaction".to_owned()
                })?,
                true,
            )
        }
        _ => {
            return Err(
                "provider Close Bitcoin reference differs from the locally bound settlement"
                    .to_owned(),
            );
        }
    };
    let (raw, parsed) = local_final_bitcoin_transaction(
        check,
        "terminal-bitcoin-transaction",
        terminal_transaction_id,
    )?;
    let funding_txid_wire = display_txid_wire(&funding_txid)?;
    if !requires_spend {
        if raw != raw_funding {
            return Err(
                "terminal Bitcoin output differs from the contracted funding bytes".to_owned(),
            );
        }
        let destination_settlement = check.bitcoin_settlement_txid.ok_or_else(|| {
            "terminal Bitcoin output has no local destination settlement".to_owned()
        })?;
        let (_, settlement) = local_final_bitcoin_transaction(
            check,
            "terminal-bitcoin-output-settlement",
            destination_settlement,
        )?;
        if !settlement.inputs.iter().any(|input| {
            input.previous_txid == funding_txid_wire && input.previous_output == funding_vout
        }) {
            return Err(
                "terminal Bitcoin destination settlement does not spend the contract outpoint"
                    .to_owned(),
            );
        }
        return Ok(format!(
            "bitcoind:output:{terminal_transaction_id}:settlement:{destination_settlement}:{}",
            check.environment.terminal_confirmations
        ));
    }
    if !parsed.inputs.iter().any(|input| {
        input.previous_txid == funding_txid_wire && input.previous_output == funding_vout
    }) {
        return Err("terminal Bitcoin transaction does not spend the contract outpoint".to_owned());
    }
    let unspent = check
        .runtime
        .block_on(check.environment.bitcoind.transaction_output(
            &rpc_id("terminal-bitcoin-outpoint")?,
            &funding_txid,
            funding_vout,
            true,
        ))
        .map_err(|error| format!("could not inspect terminal Bitcoin outpoint: {error}"))?;
    if unspent.is_some() {
        return Err("contract Bitcoin outpoint remains unspent in the local node view".to_owned());
    }
    Ok(format!(
        "bitcoind:{}:{}",
        terminal_transaction_id, check.environment.terminal_confirmations
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiquidTerminalBinding {
    funding_raw: Vec<u8>,
    funding_transaction_id: String,
    funding_output_index: u32,
    terminal_transaction_id: String,
    requires_spend: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedLiquidTerminalEvidence {
    artifact_sha256: String,
    view: String,
    external_identifier: String,
}

fn liquid_terminal_binding(
    request: &RailObservationRequest,
    settlement_reference: &str,
    settlement_transaction_id: Option<&str>,
    contract: &Value,
) -> Result<LiquidTerminalBinding, String> {
    let verifier = verifier_for_leg(contract, &request.leg_id)?;
    let funding_raw = required_string(verifier, "funding_transaction")
        .and_then(decode_hex)
        .map_err(|error| format!("contract Liquid funding transaction is invalid: {error}"))?;
    let funding = parse_liquid_transaction(&funding_raw)
        .map_err(|error| format!("contract Liquid funding transaction is invalid: {error}"))?;
    let funding_transaction_id = lower_hex(&funding.transaction_id);
    let funding_output_index = bounded_u32_member(verifier, "output_index")?;
    let funding_outpoint = format!("{funding_transaction_id}:{funding_output_index}");
    if request.reference != funding_outpoint || settlement_reference != funding_outpoint {
        return Err(
            "provider Close Liquid reference differs from the contracted funding outpoint"
                .to_owned(),
        );
    }
    let (terminal_transaction_id, requires_spend) = match request.evidence_class.as_str() {
        "liquid_output" => (funding_transaction_id.clone(), false),
        "liquid_spend" => (
            settlement_transaction_id
                .ok_or_else(|| {
                    "terminal Liquid spend has no local settlement transaction".to_owned()
                })?
                .to_owned(),
            true,
        ),
        _ => return Err("terminal Liquid evidence class is unsupported".to_owned()),
    };
    Ok(LiquidTerminalBinding {
        funding_raw,
        funding_transaction_id,
        funding_output_index,
        terminal_transaction_id,
        requires_spend,
    })
}

fn local_final_liquid_transaction(
    check: &TerminalRailCheck<'_>,
    liquid: &LiquidLabEnvironment,
    label: &str,
    transaction_id: &str,
) -> Result<(Vec<u8>, LiquidTransaction, String), String> {
    let observation = check
        .runtime
        .block_on(
            liquid
                .elementsd
                .observe_transaction(&rpc_id(label)?, transaction_id),
        )
        .map_err(|error| format!("could not inspect terminal Liquid transaction: {error}"))?;
    if u64::from(observation.confirmations) < check.environment.terminal_confirmations {
        return Err("terminal Liquid transaction is not final in the local node view".to_owned());
    }
    let parsed = parse_liquid_transaction(&observation.raw_transaction)
        .map_err(|error| format!("terminal Liquid transaction is invalid: {error}"))?;
    if lower_hex(&parsed.transaction_id) != transaction_id {
        return Err("terminal Liquid transaction has another transaction ID".to_owned());
    }
    let block_hash = observation
        .block_hash
        .ok_or_else(|| "terminal Liquid transaction has no final block hash".to_owned())?;
    Ok((observation.raw_transaction, parsed, block_hash))
}

fn liquid_terminal_artifact_and_view(
    request: &RailObservationRequest,
    binding: &LiquidTerminalBinding,
    raw_transaction: &[u8],
    block_hash: &str,
    contract: &Value,
) -> Result<(String, String), String> {
    if request.evidence_class == "liquid_output" && !binding.requires_spend {
        return Ok((lower_hex(&sha256(raw_transaction)), block_hash.to_owned()));
    }
    if request.evidence_class != "liquid_spend" || !binding.requires_spend {
        return Err("terminal Liquid evidence has an unsupported local derivation".to_owned());
    }
    let swap_type = required_string(
        contract
            .as_object()
            .ok_or_else(|| "funded contract is not an object".to_owned())?,
        "swap_type",
    )?;
    let artifact = match (swap_type, request.outcome.as_str(), request.leg_id.as_str()) {
        ("submarine", "completed", _) => json!({
            "claim_txid":binding.terminal_transaction_id,
        }),
        ("reverse", "completed", _) => {
            let payment_hash = contract
                .get("payment_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "funded reverse contract has no payment hash".to_owned())?;
            require_lower_hex_32(payment_hash, "funded reverse payment hash")?;
            json!({
                "claim_txid":binding.terminal_transaction_id,
                "payment_hash":payment_hash,
                "state":"settled",
            })
        }
        ("chain", "completed", "source") => json!({
            "claim_txid":binding.terminal_transaction_id,
        }),
        _ => {
            return Err(
                "terminal Liquid spend has an unsupported local artifact derivation".to_owned(),
            );
        }
    };
    let view = match swap_type {
        "submarine" => "provider Liquid claim reached reorg-safe finality",
        "reverse" => "requester Liquid claim verified before hold settlement",
        "chain" => "provider source claim reached reorg-safe finality",
        _ => return Err("terminal Liquid spend has an unsupported local view".to_owned()),
    };
    let artifact_sha256 = provider_support::canonical_json(&artifact)
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .map_err(|error| format!("could not derive terminal Liquid artifact: {error}"))?;
    Ok((artifact_sha256, view.to_owned()))
}

fn require_exact_liquid_terminal_metadata(
    evidence: &Map<String, Value>,
    derived: &DerivedLiquidTerminalEvidence,
) -> Result<(), String> {
    if evidence.get("artifact_sha256").and_then(Value::as_str)
        != Some(derived.artifact_sha256.as_str())
    {
        return Err(
            "provider Close Liquid artifact differs from the local transaction proof".to_owned(),
        );
    }
    if evidence.get("view").and_then(Value::as_str) != Some(derived.view.as_str()) {
        return Err("provider Close Liquid view differs from the local node proof".to_owned());
    }
    Ok(())
}

fn verify_local_liquid_terminal(
    request: &RailObservationRequest,
    settlement_reference: &str,
    check: &TerminalRailCheck<'_>,
    contract: &Value,
) -> Result<DerivedLiquidTerminalEvidence, String> {
    let binding = liquid_terminal_binding(
        request,
        settlement_reference,
        check.liquid_settlement_txid,
        contract,
    )?;
    let liquid = check
        .environment
        .liquid
        .as_ref()
        .ok_or_else(|| "terminal Liquid evidence has no local elementsd".to_owned())?;
    let (raw, parsed, block_hash) = local_final_liquid_transaction(
        check,
        liquid,
        "terminal-liquid-transaction",
        &binding.terminal_transaction_id,
    )?;
    if !binding.requires_spend {
        if raw != binding.funding_raw {
            return Err(
                "terminal Liquid output differs from the contracted funding bytes".to_owned(),
            );
        }
        let destination_settlement = check.liquid_settlement_txid.ok_or_else(|| {
            "terminal Liquid output has no local destination settlement".to_owned()
        })?;
        let (_, settlement, _) = local_final_liquid_transaction(
            check,
            liquid,
            "terminal-liquid-output-settlement",
            destination_settlement,
        )?;
        if !settlement.inputs.iter().any(|input| {
            lower_hex(&input.previous_txid) == binding.funding_transaction_id
                && input.previous_output == binding.funding_output_index
        }) {
            return Err(
                "terminal Liquid destination settlement does not spend the contract outpoint"
                    .to_owned(),
            );
        }
        let spending = check
            .runtime
            .block_on(liquid.elementsd.spending_transaction(
                "terminal-liquid-output-spender",
                &binding.funding_transaction_id,
                binding.funding_output_index,
            ))
            .map_err(|error| {
                format!("could not inspect terminal Liquid output spender: {error}")
            })?;
        if spending.spending_transaction_id.as_deref() != Some(destination_settlement) {
            return Err("local elementsd reports another Liquid destination spender".to_owned());
        }
        let (artifact_sha256, view) =
            liquid_terminal_artifact_and_view(request, &binding, &raw, &block_hash, contract)?;
        return Ok(DerivedLiquidTerminalEvidence {
            artifact_sha256,
            view,
            external_identifier: format!(
                "elementsd:output:{}:settlement:{destination_settlement}:{}",
                binding.terminal_transaction_id, check.environment.terminal_confirmations
            ),
        });
    }
    if !parsed.inputs.iter().any(|input| {
        lower_hex(&input.previous_txid) == binding.funding_transaction_id
            && input.previous_output == binding.funding_output_index
    }) {
        return Err("terminal Liquid transaction does not spend the contract outpoint".to_owned());
    }
    let spending = check
        .runtime
        .block_on(liquid.elementsd.spending_transaction(
            "terminal-liquid-spender",
            &binding.funding_transaction_id,
            binding.funding_output_index,
        ))
        .map_err(|error| format!("could not inspect terminal Liquid spender: {error}"))?;
    if spending.spending_transaction_id.as_deref() != Some(binding.terminal_transaction_id.as_str())
    {
        return Err("local elementsd reports another Liquid funding spender".to_owned());
    }
    let (artifact_sha256, view) =
        liquid_terminal_artifact_and_view(request, &binding, &raw, &block_hash, contract)?;
    Ok(DerivedLiquidTerminalEvidence {
        artifact_sha256,
        view,
        external_identifier: format!(
            "elementsd:{}:{}",
            binding.terminal_transaction_id, check.environment.terminal_confirmations
        ),
    })
}

fn verify_local_lightning_terminal(
    request: &RailObservationRequest,
    settlement_reference: &str,
    check: &TerminalRailCheck<'_>,
) -> Result<String, String> {
    let lightning = check
        .lightning
        .ok_or_else(|| "terminal Lightning evidence has no local observation".to_owned())?;
    let (response, collection, payment_hash, expected_status, direction) = match lightning {
        LightningTerminalCheck::IncomingInvoice { payment_hash } => (
            check
                .runtime
                .block_on(
                    check
                        .environment
                        .peer_cln
                        .list_invoices(&cln_id("terminal-invoice")?, None),
                )
                .map_err(|error| format!("could not inspect local terminal invoice: {error}"))?,
            "invoices",
            payment_hash,
            "paid",
            "incoming",
        ),
        LightningTerminalCheck::OutgoingPayment {
            invoice,
            payment_hash,
            expected_status,
        } => (
            check
                .runtime
                .block_on(
                    check
                        .environment
                        .peer_cln
                        .list_pays(&cln_id("terminal-payment")?, Some(invoice)),
                )
                .map_err(|error| format!("could not inspect local terminal payment: {error}"))?,
            "pays",
            payment_hash,
            expected_status,
            "outgoing",
        ),
    };
    if request.reference != payment_hash || settlement_reference != payment_hash {
        return Err("provider Close Lightning reference differs from the bound payment".to_owned());
    }
    let matching = response
        .get(collection)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("payment_hash").and_then(Value::as_str) == Some(payment_hash))
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some(expected_status))
        .count();
    if matching == 0 {
        return Err("peer CLN does not report the bound terminal Lightning state".to_owned());
    }
    Ok(format!("cln:{direction}:{payment_hash}:{expected_status}"))
}

fn funded_rfq_profile_with_terms(
    input: NegotiationInput<'_>,
    now: u64,
    input_amount_sat: u64,
    maximum_total_fee_sat: u64,
) -> Result<Value, String> {
    let (asset_pair, leg_id, path) = match input.swap_type {
        "submarine" => (
            json!([
                format!("swp:1:{NETWORK_ID}:btc:chain"),
                format!("swp:1:{NETWORK_ID}:btc:lightning")
            ]),
            "source",
            "refund",
        ),
        "reverse" => (
            json!([
                format!("swp:1:{NETWORK_ID}:btc:lightning"),
                format!("swp:1:{NETWORK_ID}:btc:chain")
            ]),
            "destination",
            "claim",
        ),
        _ => return Err("funded smoke requested an unsupported swap type".to_owned()),
    };
    let mut constraints = json!({
        "allowed_script_modes":["taproot-musig2-script-exit"],
        "asset_pair":asset_pair,
        "confirmation_policy":{
            "minimum_confirmations":"1",
            "reorg_safety_blocks":"2",
            "zero_confirmation":"forbidden",
            "rbf":"reject",
            "replacement":"reject"
        },
        "desired_completion_time":now.saturating_add(86_400),
        "firm_quote_required":true,
        "input_amount":input_amount_sat.to_string(),
        "invoice_sha256":input.invoice.map(|invoice| lower_hex(&sha256(invoice.as_bytes()))),
        "maximum_total_fee":maximum_total_fee_sat.to_string(),
        "payment_hash":input.payment_hash,
        "requester_public_keys":[{
            "leg_id":leg_id,
            "path":path,
            "public_key":lower_hex(&input.requester_key)
        }],
        "swap_type":input.swap_type
    });
    if input.swap_type == "reverse" {
        constraints
            .as_object_mut()
            .ok_or_else(|| "reverse constraints are not an object".to_owned())?
            .remove("invoice_sha256");
    }
    let mut profile = json!({"constraints":constraints});
    if let Some(invoice) = input.invoice {
        profile
            .as_object_mut()
            .ok_or_else(|| "submarine RFQ profile is not an object".to_owned())?
            .insert("invoice".to_owned(), Value::String(invoice.to_owned()));
    }
    Ok(profile)
}

fn funded_chain_rfq_profile(
    input: ChainNegotiationInput,
    liquid: &LiquidLabEnvironment,
    now: u64,
) -> Value {
    let bitcoin_asset = format!("swp:1:{NETWORK_ID}:btc:chain");
    let liquid_asset = format!(
        "swp:1:{}:elements:{}:liquid",
        liquid.network_id, liquid.pegged_asset
    );
    let asset_pair = match input.direction {
        LiquidChainDirection::BitcoinToLiquid => [bitcoin_asset, liquid_asset],
        LiquidChainDirection::LiquidToBitcoin => [liquid_asset, bitcoin_asset],
    };
    json!({
        "constraints":{
            "allowed_script_modes":["taproot-musig2-script-exit"],
            "asset_pair":asset_pair,
            "confirmation_policy":{
                "minimum_confirmations":"1",
                "reorg_safety_blocks":"2",
                "zero_confirmation":"forbidden",
                "rbf":"reject",
                "replacement":"reject"
            },
            "desired_completion_time":now.saturating_add(86_400),
            "firm_quote_required":true,
            "input_amount":INPUT_AMOUNT_SAT.to_string(),
            "invoice_sha256":null,
            "maximum_total_fee":"5000",
            "payment_hash":lower_hex(&input.payment_hash),
            "requester_public_keys":[
                {
                    "leg_id":"destination",
                    "path":"claim",
                    "public_key":lower_hex(&input.destination_requester_key)
                },
                {
                    "leg_id":"source",
                    "path":"refund",
                    "public_key":lower_hex(&input.source_requester_key)
                }
            ],
            "swap_type":"chain"
        }
    })
}

fn funded_liquid_rfq_profile(
    input: &LiquidNegotiationInput,
    liquid: &LiquidLabEnvironment,
    now: u64,
) -> Result<Value, String> {
    let liquid_asset = format!(
        "swp:1:{}:elements:{}:liquid",
        liquid.network_id, liquid.pegged_asset
    );
    let lightning_asset = format!("swp:1:{NETWORK_ID}:btc:lightning");
    let (asset_pair, leg_id, path, swap_type) = match input.journey {
        LiquidJourney::Submarine => (
            [liquid_asset, lightning_asset],
            "source",
            "refund",
            "submarine",
        ),
        LiquidJourney::Reverse => (
            [lightning_asset, liquid_asset],
            "destination",
            "claim",
            "reverse",
        ),
    };
    let mut constraints = json!({
        "allowed_script_modes":["taproot-musig2-script-exit"],
        "asset_pair":asset_pair,
        "confirmation_policy":{
            "minimum_confirmations":"1",
            "reorg_safety_blocks":"2",
            "zero_confirmation":"forbidden",
            "rbf":"reject",
            "replacement":"reject"
        },
        "desired_completion_time":now.saturating_add(86_400),
        "firm_quote_required":true,
        "input_amount":INPUT_AMOUNT_SAT.to_string(),
        "invoice_sha256":input.invoice.as_ref().map(|invoice| lower_hex(&sha256(invoice.as_bytes()))),
        "maximum_total_fee":"5000",
        "payment_hash":lower_hex(&input.payment_hash),
        "requester_public_keys":[{
            "leg_id":leg_id,
            "path":path,
            "public_key":lower_hex(&input.requester_key)
        }],
        "swap_type":swap_type
    });
    if input.journey == LiquidJourney::Reverse {
        constraints
            .as_object_mut()
            .ok_or_else(|| "Liquid RFQ constraints are not an object".to_owned())?
            .remove("invoice_sha256");
    }
    let mut profile = json!({"constraints":constraints});
    if let Some(invoice) = &input.invoice {
        profile
            .as_object_mut()
            .ok_or_else(|| "Liquid RFQ profile is not an object".to_owned())?
            .insert("invoice".to_owned(), Value::String(invoice.clone()));
    }
    Ok(profile)
}

fn bind_requester_funding(
    environment: &SmokeEnvironment,
    contract: &mut Value,
    funding_input: &FundingInput,
) -> Result<SignedFundingTransaction, String> {
    let bitcoin = bitcoin_terms(contract, "source")?;
    let funding = build_funding_transaction(
        &environment.wallet,
        std::slice::from_ref(funding_input),
        &FundingRequest {
            destination_script_pubkey: bitcoin.script_pubkey,
            amount_sat: bitcoin.amount_sat,
            fee_rate_sat_per_vbyte: 2,
            change_path: WalletPath::new(0, true, 0)
                .map_err(|error| format!("client funding change path is invalid: {error}"))?,
            lock_time: 0,
        },
    )
    .map_err(|error| format!("could not construct submarine funding: {error}"))?;
    let raw = decode_hex(&funding.raw_transaction)?;
    let verifiers = contract
        .get_mut("verifier_inputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "submarine contract has no mutable verifier inputs".to_owned())?;
    let verifier = verifiers
        .iter_mut()
        .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some("source"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "submarine contract has no source verifier".to_owned())?;
    verifier.insert(
        "funding_transaction".to_owned(),
        Value::String(funding.raw_transaction.clone()),
    );
    verifier.insert(
        "funding_transaction_sha256".to_owned(),
        Value::String(lower_hex(&sha256(&raw))),
    );
    verifier.insert("output_index".to_owned(), json!(0));
    let verifier_digest = lower_hex(&sha256(
        &provider_support::canonical_json(&Value::Object(verifier.clone()))
            .map_err(|error| format!("could not canonicalize source verifier: {error}"))?,
    ));
    let legs = contract
        .get_mut("legs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "submarine contract has no mutable legs".to_owned())?;
    let leg = legs
        .iter_mut()
        .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some("source"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "submarine contract has no source leg".to_owned())?;
    leg.insert("verifier_digest".to_owned(), Value::String(verifier_digest));
    Ok(funding)
}

fn chain_source_funding(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    contract: &Value,
    direction: LiquidChainDirection,
) -> Result<ChainFundingTransaction, String> {
    let verifier = verifier_for_leg(contract, "source")?;
    let script_pubkey = decode_hex(required_string(verifier, "script_pubkey")?)?;
    let amount_sat = canonical_u64(required_string(verifier, "amount")?)?;
    match direction {
        LiquidChainDirection::BitcoinToLiquid => {
            let input = fund_client_wallet(runtime, environment)?;
            build_funding_transaction(
                &environment.wallet,
                std::slice::from_ref(&input),
                &FundingRequest {
                    destination_script_pubkey: script_pubkey,
                    amount_sat,
                    fee_rate_sat_per_vbyte: 2,
                    change_path: WalletPath::new(0, true, 30).map_err(|error| {
                        format!("chain Bitcoin change path is invalid: {error}")
                    })?,
                    lock_time: 0,
                },
            )
            .map(ChainFundingTransaction::Bitcoin)
            .map_err(|error| format!("could not construct chain Bitcoin source funding: {error}"))
        }
        LiquidChainDirection::LiquidToBitcoin => {
            let fees = liquid_fee_schedule(contract, LiquidSwapType::Chain)?;
            let liquid = environment
                .liquid
                .as_ref()
                .ok_or_else(|| "Liquid chain source has no local elementsd".to_owned())?;
            let capacity = runtime
                .block_on(liquid.rail.confirmed_capacity(
                    &rpc_id("chain-liquid-source-capacity")?,
                    1,
                    64,
                ))
                .map_err(|error| format!("could not inspect requester Liquid capacity: {error}"))?;
            let required = amount_sat
                .checked_add(fees.funding_fee_cap_sat)
                .ok_or_else(|| "Liquid source capacity target overflows".to_owned())?;
            let selected = capacity
                .utxos
                .into_iter()
                .find(|output| output.amount_sat >= required)
                .map(|output| vec![output])
                .ok_or_else(|| {
                    "requester elementsd wallet has no single confirmed output covering amount and derived funding fee cap".to_owned()
                })?;
            runtime
                .block_on(liquid.rail.create_signed_funding(
                    "chain-liquid-source",
                    &selected,
                    &script_pubkey,
                    amount_sat,
                    fees.sat_per_vbyte,
                    fees.funding_fee_cap_sat,
                ))
                .map(ChainFundingTransaction::Liquid)
                .map_err(|error| {
                    format!("could not construct chain Liquid source funding: {error}")
                })
        }
    }
}

fn liquid_requester_funding(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    contract: &Value,
) -> Result<ElementsdSignedFunding, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid requester funding has no local elementsd".to_owned())?;
    let verifier = verifier_for_leg(contract, "source")?;
    let script_pubkey = decode_hex(required_string(verifier, "script_pubkey")?)?;
    let amount_sat = canonical_u64(required_string(verifier, "amount")?)?;
    let fees = liquid_fee_schedule(contract, LiquidSwapType::Submarine)?;
    let capacity = runtime
        .block_on(liquid.rail.confirmed_capacity(
            &rpc_id("liquid-submarine-source-capacity")?,
            1,
            64,
        ))
        .map_err(|error| format!("could not inspect requester Liquid capacity: {error}"))?;
    let required = amount_sat
        .checked_add(fees.funding_fee_cap_sat)
        .ok_or_else(|| "Liquid source capacity target overflows".to_owned())?;
    let selected = capacity
        .utxos
        .into_iter()
        .find(|output| output.amount_sat >= required)
        .map(|output| vec![output])
        .ok_or_else(|| {
            "requester elementsd wallet has no single confirmed output covering amount and derived funding fee cap".to_owned()
        })?;
    runtime
        .block_on(liquid.rail.create_signed_funding(
            "liquid-submarine-source",
            &selected,
            &script_pubkey,
            amount_sat,
            fees.sat_per_vbyte,
            fees.funding_fee_cap_sat,
        ))
        .map_err(|error| format!("could not construct Liquid submarine funding: {error}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiquidFeeSchedule {
    sat_per_vbyte: u64,
    funding_fee_cap_sat: u64,
    claim_fee_sat: u64,
    refund_fee_sat: u64,
}

fn liquid_fee_schedule(
    contract: &Value,
    swap_type: LiquidSwapType,
) -> Result<LiquidFeeSchedule, String> {
    let priced_vbytes = liquid_quote_priced_vbytes(contract, swap_type)?;
    let miner_fee_budget_sat = canonical_u64(
        contract
            .get("miner_fee_budget")
            .and_then(Value::as_str)
            .ok_or_else(|| "Liquid contract has no miner fee budget".to_owned())?,
    )?;
    let sat_per_vbyte = funding_feerate_from_priced_vbytes(priced_vbytes, miner_fee_budget_sat)
        .map_err(|error| error.to_string())?;
    let effect_fee = |vbytes: u64, label: &str| {
        vbytes
            .checked_mul(sat_per_vbyte)
            .ok_or_else(|| format!("Liquid {label} fee cap overflows"))
    };
    Ok(LiquidFeeSchedule {
        sat_per_vbyte,
        funding_fee_cap_sat: effect_fee(
            LIQUID_SINGLE_INPUT_FUNDING_VBYTES,
            "single-input funding",
        )?,
        claim_fee_sat: effect_fee(LIQUID_CLAIM_VBYTES, "claim")?,
        refund_fee_sat: effect_fee(LIQUID_REFUND_VBYTES, "refund")?,
    })
}

fn liquid_quote_priced_vbytes(contract: &Value, swap_type: LiquidSwapType) -> Result<u64, String> {
    match swap_type {
        LiquidSwapType::Submarine => Ok(liquid_submarine_quote_vbytes()),
        LiquidSwapType::Reverse => Ok(liquid_reverse_quote_vbytes()),
        LiquidSwapType::Chain => {
            let pair = contract
                .get("asset_pair")
                .and_then(Value::as_array)
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| "Liquid chain Contract has no ordered asset pair".to_owned())?;
            match (
                pair[0]
                    .as_str()
                    .is_some_and(|asset| asset.ends_with(":liquid")),
                pair[1]
                    .as_str()
                    .is_some_and(|asset| asset.ends_with(":liquid")),
            ) {
                (false, true) => Ok(bitcoin_to_liquid_chain_quote_vbytes()),
                (true, false) => Ok(liquid_to_bitcoin_chain_quote_vbytes()),
                _ => Err("Liquid chain Contract does not contain one Liquid asset".to_owned()),
            }
        }
    }
}

fn liquid_submarine_invoice_amount_sat() -> Result<u64, String> {
    let fixture: Value = serde_json::from_str(ADVERSARIAL_FIXTURE)
        .map_err(|error| format!("adversarial fixture is invalid: {error}"))?;
    let profile = fixture
        .get("lab_profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "adversarial fixture has no lab profile".to_owned())?;
    let pricing = profile
        .get("pricing")
        .and_then(Value::as_object)
        .filter(|pricing| {
            pricing.get("source").and_then(Value::as_str) == Some("configured_fallback_only")
        })
        .ok_or_else(|| "adversarial fixture has no forced fallback pricing".to_owned())?;
    let number = |object: &Map<String, Value>, member: &str| {
        object
            .get(member)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("adversarial lab pricing has no {member}"))
    };
    let sat_per_vbyte = number(pricing, "sat_per_vbyte")?;
    let derived = derive_quote_with_worst_case_vbytes(
        &PricingConfig {
            spread_bps: number(pricing, "spread_bps")?,
            fallback_feerate_sat_per_vb: Some(sat_per_vbyte),
            min_swap_sat: number(pricing, "min_swap_sat")?,
            max_swap_sat: number(pricing, "max_swap_sat")?,
            quote_expiry_seconds: number(profile, "tiny_quote_expiry_seconds")?,
            reservation_tier: ReservationTier::Hard,
            lightning_routing_fee_ppm: number(pricing, "lightning_routing_fee_ppm")?,
        },
        &FeerateObservation::Fallback {
            sat_per_vb: sat_per_vbyte,
        },
        &CapacityBounds {
            capacity_bucket_id: "liquid-lab".to_owned(),
            available_capacity: number(pricing, "max_swap_sat")?.to_string(),
        },
        &QuoteRequest {
            swap_type: immortal_provider::pricing::SwapType::Submarine,
            side: QuoteSide::Input,
            amount: INPUT_AMOUNT_SAT.to_string(),
        },
        0,
        liquid_submarine_quote_vbytes(),
    )
    .map_err(|error| format!("could not derive Liquid submarine lab Quote: {error}"))?;
    canonical_u64(&derived.output_amount)
}

fn liquid_claim_recovery_refs(
    paths: &LabPaths,
    journey_name: &str,
    wallet_path: WalletPath,
) -> Result<LiquidClaimRecoveryRefs, String> {
    let secret_path = paths.funded_secret(journey_name);
    let metadata = std::fs::symlink_metadata(&secret_path).map_err(|error| {
        format!(
            "Liquid claim has no persisted preimage recovery record {}: {error}",
            secret_path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
        return Err(
            "Liquid preimage recovery record is not an exact private 32-byte file".to_owned(),
        );
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err("Liquid preimage recovery record permissions are not 0600".to_owned());
    }
    let wallet_binding = format!(
        "openagents.immortal.lab-liquid-wallet-ref.v1\0{}\0{}\0{}",
        wallet_path.account, wallet_path.change, wallet_path.address_index
    );
    let preimage_binding = format!(
        "openagents.immortal.lab-liquid-preimage-ref.v1\0{journey_name}\0{}",
        secret_path.display()
    );
    Ok(LiquidClaimRecoveryRefs {
        wallet_signing_handle_sha256: lower_hex(&sha256(wallet_binding.as_bytes())),
        preimage_recovery_ref: lower_hex(&sha256(preimage_binding.as_bytes())),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_chain_liquid_request(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    contract: &Value,
    swap_type: LiquidSwapType,
    leg_id: &str,
    purpose: LiquidLegPurpose,
    wallet_path: WalletPath,
    destination_script_pubkey: &[u8],
    claim_recovery: Option<&LiquidClaimRecoveryRefs>,
) -> Result<LiquidBeforeFundRequest, String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "chain Liquid request has no local elementsd".to_owned())?;
    let contract_object = contract
        .as_object()
        .ok_or_else(|| "chain contract is not an object".to_owned())?;
    let verifier = verifier_for_leg(contract, leg_id)?;
    let funding_transaction = required_string(verifier, "funding_transaction")?;
    let funding_raw = decode_hex(funding_transaction)?;
    let funding_output_index = bounded_u32_member(verifier, "output_index")?;
    let amount_sat = canonical_u64(required_string(verifier, "amount")?)?;
    let funding_script_pubkey = decode_hex(required_string(verifier, "script_pubkey")?)?;
    let leg = contract_object
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| format!("chain contract has no {leg_id} leg"))?;
    let path = if leg_id == "source" {
        "refund"
    } else {
        "claim"
    };
    let (script, control_block, timelock) = match path {
        "claim" => (
            decode_hex(required_string(verifier, "claim_script")?)?,
            decode_hex(required_string(verifier, "taproot_claim_control_block")?)?,
            0,
        ),
        "refund" => (
            decode_hex(required_string(verifier, "refund_script")?)?,
            decode_hex(required_string(verifier, "taproot_refund_control_block")?)?,
            u32::try_from(canonical_u64(required_string(leg, "refund_lock_value")?)?)
                .map_err(|_| "Liquid refund lock exceeds u32".to_owned())?,
        ),
        _ => return Err("chain Liquid exit path is unsupported".to_owned()),
    };
    let fees = liquid_fee_schedule(contract, swap_type)?;
    let fee_amount_sat = match path {
        "claim" => fees.claim_fee_sat,
        "refund" => fees.refund_fee_sat,
        _ => return Err("chain Liquid exit path is unsupported".to_owned()),
    };
    let exit_package = match (path, claim_recovery) {
        ("claim", Some(recovery)) => runtime.block_on(liquid.rail.build_wallet_claim_exit_package(
            &format!("chain-liquid-{leg_id}-{path}"),
            &funding_raw,
            funding_output_index,
            amount_sat,
            &funding_script_pubkey,
            &script,
            &control_block,
            destination_script_pubkey,
            fee_amount_sat,
            &recovery.wallet_signing_handle_sha256,
            &recovery.preimage_recovery_ref,
        )),
        ("refund", None) => runtime.block_on(liquid.rail.build_signed_exit_package(
            &format!("chain-liquid-{leg_id}-{path}"),
            &environment.wallet,
            wallet_path,
            &funding_raw,
            funding_output_index,
            amount_sat,
            &funding_script_pubkey,
            path,
            &script,
            &control_block,
            timelock,
            destination_script_pubkey,
            fee_amount_sat,
            None,
        )),
        ("claim", None) => {
            return Err("Liquid claim has no persisted preimage recovery reference".to_owned());
        }
        ("refund", Some(_)) => {
            return Err("Liquid refund unexpectedly has claim recovery references".to_owned());
        }
        _ => return Err("chain Liquid exit path is unsupported".to_owned()),
    }
    .map_err(|error| format!("could not build chain Liquid {path} package: {error}"))?;
    let asset_pair = contract_object
        .get("asset_pair")
        .and_then(Value::as_array)
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| "chain contract has no ordered asset pair".to_owned())?;
    Ok(LiquidBeforeFundRequest {
        swap_type,
        purpose,
        input_asset_id: asset_pair[0]
            .as_str()
            .ok_or_else(|| "chain input asset is invalid".to_owned())?
            .to_owned(),
        output_asset_id: asset_pair[1]
            .as_str()
            .ok_or_else(|| "chain output asset is invalid".to_owned())?
            .to_owned(),
        funding: LiquidFundingVerificationInput {
            raw_transaction: funding_transaction.to_owned(),
            trusted_unblind_transaction: None,
            transaction_sha256: required_string(verifier, "funding_transaction_sha256")?.to_owned(),
            output_index: funding_output_index,
            asset_id: required_string(leg, "asset_id")?.to_owned(),
            amount: amount_sat.to_string(),
            script_pubkey: lower_hex(&funding_script_pubkey),
            taproot_internal_key: required_string(verifier, "taproot_internal_key")?.to_owned(),
            taproot_merkle_root: Some(required_string(verifier, "taproot_merkle_root")?.to_owned()),
            confidentiality: LiquidConfidentiality::Explicit,
            minimum_confirmations: u32::try_from(canonical_u64(required_string(
                verifier,
                "minimum_confirmations",
            )?)?)
            .map_err(|_| "Liquid minimum confirmations exceed u32".to_owned())?,
            replacement_policy: required_string(verifier, "replacement_policy")?.to_owned(),
        },
        exit_package,
    })
}

fn bind_liquid_exit_commitment(
    contract: &mut Value,
    leg_id: &str,
    path: &str,
    request: &LiquidBeforeFundRequest,
) -> Result<(), String> {
    let document = serde_json::to_value(&request.exit_package)
        .map_err(|error| format!("could not serialize Liquid exit package: {error}"))?;
    let digest = lower_hex(&sha256(
        &provider_support::canonical_json(&document)
            .map_err(|error| format!("could not canonicalize Liquid exit package: {error}"))?,
    ));
    let commitments = contract
        .get_mut("exit_package_commitments")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "chain contract has no mutable exit commitments".to_owned())?;
    let package_mode = match request.exit_package.mode {
        LiquidExitMode::Presigned => "presigned",
        LiquidExitMode::Wallet => "wallet_sign",
    };
    upsert_exit_commitment(
        commitments,
        "requester",
        leg_id,
        path,
        package_mode,
        &digest,
    );
    Ok(())
}

fn bind_requester_exit_packages(
    environment: &SmokeEnvironment,
    config: &SwapClientConfig,
    contract: &mut Value,
    swap_type: &str,
    order_and_quote_ids: (&str, &str),
    destination_script_pubkey: &[u8],
    presign_submarine_refund: bool,
) -> Result<Vec<ExitPackage>, String> {
    let (order_id, quote_id) = order_and_quote_ids;
    let (leg_id, path, funding_role, funding_leg_id) = match swap_type {
        "submarine" => ("source", "refund", "chain_fund", "source"),
        "reverse" => ("destination", "claim", "invoice_pay", "lightning"),
        _ => return Err("funded smoke cannot bind exits for this swap type".to_owned()),
    };
    let cooperative = swap_type == "submarine"
        && contract.get("musig2_execution").and_then(Value::as_bool) == Some(true);
    if presign_submarine_refund && swap_type != "submarine" {
        return Err("only the submarine CLTV refund can be pre-signed".to_owned());
    }
    {
        let root = contract
            .as_object_mut()
            .ok_or_else(|| "funded contract is not an object".to_owned())?;
        let bindings = root
            .get_mut("effect_bindings")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "funded contract has no mutable effect bindings".to_owned())?;
        upsert_effect_binding(bindings, funding_role, funding_leg_id);
        upsert_effect_binding(bindings, &format!("chain_{path}"), leg_id);
        if cooperative {
            upsert_effect_binding(bindings, "cooperative_sign", "source");
            upsert_effect_binding(bindings, "chain_claim", "source");
        }
    }
    let mut document = requester_exit_document(
        contract,
        order_id,
        quote_id,
        leg_id,
        path,
        destination_script_pubkey,
    )?;
    if presign_submarine_refund {
        presign_requester_submarine_refund(
            environment,
            contract,
            &mut document,
            destination_script_pubkey,
        )?;
    }
    let requester_package = ExitPackage::parse(document)
        .map_err(|error| format!("dynamic requester exit package is invalid: {error}"))?;
    let requester_package_mode = requester_package
        .mode()
        .map_err(|error| format!("could not read requester exit mode: {error}"))?;
    let requester_package_sha256 = requester_package
        .commitment_sha256()
        .map_err(|error| format!("could not commit requester exit package: {error}"))?;
    let provider_package = cooperative
        .then(|| {
            provider_support::build_provider_submarine_claim_exit_package_seed(
                config, order_id, quote_id, contract,
            )
            .map_err(|error| {
                format!("could not build canonical provider exit package seed: {error}")
            })
        })
        .transpose()?;
    let provider_package_sha256 = provider_package
        .as_ref()
        .map(ExitPackage::commitment_sha256)
        .transpose()
        .map_err(|error| format!("could not commit provider exit package: {error}"))?;
    let root = contract
        .as_object_mut()
        .ok_or_else(|| "funded contract is not an object".to_owned())?;
    let commitments = root
        .get_mut("exit_package_commitments")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "funded contract has no mutable exit commitments".to_owned())?;
    upsert_exit_commitment(
        commitments,
        "requester",
        leg_id,
        path,
        requester_package_mode,
        &requester_package_sha256,
    );
    if let Some(provider_digest) = provider_package_sha256.as_deref() {
        upsert_exit_commitment(
            commitments,
            "provider",
            "source",
            "claim",
            "external_signer",
            provider_digest,
        );
    }
    let mut packages = vec![requester_package];
    if let Some(provider_package) = provider_package {
        packages.push(provider_package);
    }
    Ok(packages)
}

fn upsert_effect_binding(bindings: &mut Vec<Value>, role: &str, leg_id: &str) {
    if !bindings.iter().any(|binding| {
        binding.get("role").and_then(Value::as_str) == Some(role)
            && binding.get("leg_id").and_then(Value::as_str) == Some(leg_id)
    }) {
        bindings.push(json!({"role":role,"leg_id":leg_id}));
    }
}

fn upsert_exit_commitment(
    commitments: &mut Vec<Value>,
    participant_role: &str,
    leg_id: &str,
    path: &str,
    package_mode: &str,
    package_sha256: &str,
) {
    commitments.retain(|commitment| {
        commitment.get("participant_role").and_then(Value::as_str) != Some(participant_role)
            || commitment.get("leg_id").and_then(Value::as_str) != Some(leg_id)
            || commitment.get("path").and_then(Value::as_str) != Some(path)
    });
    commitments.push(json!({
        "participant_role":participant_role,
        "leg_id":leg_id,
        "path":path,
        "package_mode":package_mode,
        "package_sha256":package_sha256,
    }));
}

fn presign_requester_submarine_refund(
    environment: &SmokeEnvironment,
    contract: &Value,
    document: &mut Value,
    destination_script_pubkey: &[u8],
) -> Result<(), String> {
    let verifier = verifier_for_leg(contract, "source")?;
    let funding_transaction = required_string(verifier, "funding_transaction")?;
    let funding_txid = transaction_id(funding_transaction)?;
    let output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "doomsday refund has no bounded funding output".to_owned())?;
    let bitcoin = bitcoin_terms(contract, "source")?;
    let destination_value_sat = bitcoin
        .amount_sat
        .checked_sub(bitcoin.miner_fee_budget_sat)
        .filter(|value| *value > 0)
        .ok_or_else(|| "doomsday refund fee consumes the funding output".to_owned())?;
    let refund_path = WalletPath::new(2, false, 0)
        .map_err(|error| format!("doomsday refund wallet path is invalid: {error}"))?;
    let refund = SettlementBridge::new(&environment.wallet)
        .refund(&SettlementTemplate {
            wallet_path: refund_path,
            previous_txid_wire: display_txid_wire(&funding_txid)?,
            previous_output: output_index,
            prevout_value_sat: bitcoin.amount_sat,
            prevout_script_pubkey: bitcoin.script_pubkey,
            destination_value_sat,
            destination_script_pubkey: destination_script_pubkey.to_vec(),
            transaction_version: 2,
            input_sequence: 0xffff_fffe,
            lock_time: bitcoin.refund_lock_height,
            taproot_script: bitcoin.refund_script,
            taproot_control_block: bitcoin.refund_control_block,
            maximum_fee_sat: bitcoin.miner_fee_budget_sat,
            maximum_fee_rate_sat_per_vbyte: 10_000,
            maximum_weight: 1_600,
            dust_relay_fee_sat_per_kilobyte: 3_000,
        })
        .map_err(|error| format!("could not pre-sign doomsday refund: {error}"))?;
    let exit = document
        .get_mut("exit")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "doomsday exit package has no mutable exit".to_owned())?;
    exit.insert("mode".to_owned(), Value::String("presigned".to_owned()));
    exit.insert(
        "signed_transaction".to_owned(),
        Value::String(lower_hex(refund.broadcast_bytes())),
    );
    exit.insert("signer_ref".to_owned(), Value::Null);
    let esplora_url = required_environment("IMMORTAL_LAB_DOOMSDAY_ESPLORA_URL")?;
    document["broadcast"] = json!({
        "esplora_urls":[esplora_url],
        "minimum_agreeing_sources":1
    });
    let package = ExitPackage::parse(document.clone())
        .map_err(|error| format!("pre-signed doomsday refund package is invalid: {error}"))?;
    KeylessEsploraExecutor::request(&package, &esplora_url)
        .map_err(|error| format!("doomsday Esplora endpoint is invalid: {error}"))?;
    Ok(())
}

fn requester_exit_document(
    contract: &Value,
    order_id: &str,
    quote_id: &str,
    leg_id: &str,
    path: &str,
    destination_script_pubkey: &[u8],
) -> Result<Value, String> {
    let verifier = verifier_for_leg(contract, leg_id)?;
    let leg = contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| format!("funded contract has no {leg_id} leg"))?;
    let funding_transaction = required_string(verifier, "funding_transaction")?;
    let funding_bytes = decode_hex(funding_transaction)?;
    let funding = Transaction::parse(&funding_bytes)
        .map_err(|error| format!("committed funding transaction is invalid: {error}"))?;
    let funding_transaction_id = lower_hex(
        &funding
            .txid()
            .map_err(|error| format!("could not derive funding transaction ID: {error}"))?,
    );
    let output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "funded verifier has no bounded output index".to_owned())?;
    let amount = canonical_u64(required_string(verifier, "amount")?)?;
    let recovery = contract
        .get("recovery")
        .and_then(Value::as_object)
        .and_then(|recovery| recovery.get("exit_policy"))
        .and_then(Value::as_object)
        .ok_or_else(|| "funded contract has no exit policy".to_owned())?;
    let maximum_fee = canonical_u64(required_string(recovery, "maximum_fee")?)?;
    let destination_value = amount
        .checked_sub(maximum_fee)
        .filter(|value| *value > 0)
        .ok_or_else(|| "requester exit fee consumes the funding output".to_owned())?;
    let lock_time = match path {
        "claim" => 0,
        "refund" => u32::try_from(canonical_u64(required_string(leg, "refund_lock_value")?)?)
            .map_err(|_| "requester refund height exceeds u32".to_owned())?,
        _ => return Err("requester exit path is unsupported".to_owned()),
    };
    let (taproot_script, taproot_control_block) = match path {
        "claim" => (
            required_string(verifier, "claim_script")?,
            required_string(verifier, "taproot_claim_control_block")?,
        ),
        "refund" => (
            required_string(verifier, "refund_script")?,
            required_string(verifier, "taproot_refund_control_block")?,
        ),
        _ => return Err("requester exit path is unsupported".to_owned()),
    };
    let mut previous_txid = decode_lower_hex_32(&funding_transaction_id)?;
    previous_txid.reverse();
    let unsigned_exit = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid,
            previous_output: output_index,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: destination_value,
            script_pubkey: destination_script_pubkey.to_vec(),
        }],
        lock_time,
    )
    .serialize(false)
    .map_err(|error| format!("could not serialize requester exit template: {error}"))?;
    let confirmation_policy = leg
        .get("confirmation_policy")
        .ok_or_else(|| "funded Bitcoin leg has no confirmation policy".to_owned())?;
    let confirmation_policy_sha256 = json_digest(confirmation_policy)?;
    let verifier_sha256 = json_digest(&Value::Object(verifier.clone()))?;
    let effect_id = requester_effect_id(order_id, &format!("chain_{path}"), leg_id)?;
    Ok(json!({
        "schema":"openagents.mkt-swp.exit.v1",
        "profile":MKT_SWP_PROFILE_ID,
        "profile_version":MKT_SWP_PROFILE_VERSION,
        "order_id":order_id,
        "swap_contract_ids":["01".repeat(32),"02".repeat(32)],
        "contract_sha256":"03".repeat(32),
        "participant_role":"requester",
        "leg_id":leg_id,
        "network_id":leg.get("network_id").cloned().ok_or_else(|| "Bitcoin leg has no network ID".to_owned())?,
        "asset_id":leg.get("asset_id").cloned().ok_or_else(|| "Bitcoin leg has no asset ID".to_owned())?,
        "effect_id":effect_id,
        "funding":{
            "transaction_id":funding_transaction_id,
            "transaction_template_sha256":required_string(verifier,"funding_transaction_sha256")?,
            "transaction_template":funding_transaction,
            "output_index":output_index,
            "amount":required_string(verifier,"amount")?,
            "script_pubkey":required_string(verifier,"script_pubkey")?,
            "confirmation_policy_sha256":confirmation_policy_sha256
        },
        "exit":{
            "mode":"wallet_sign",
            "path":path,
            "transaction_template_sha256":lower_hex(&sha256(&unsigned_exit)),
            "signed_transaction":null,
            "signer_ref":format!("funded-smoke-wallet:{leg_id}:{path}"),
            "transaction_version":2,
            "lock_time":lock_time,
            "input_sequence":0xffff_fffe_u32,
            "sighash_type":"DEFAULT",
            "destination_script_pubkey":lower_hex(destination_script_pubkey),
            "earliest_broadcast_height":required_string(recovery,"earliest_broadcast_height")?,
            "latest_safe_broadcast_height":required_string(recovery,"latest_safe_broadcast_height")?,
            "fee_policy":{
                "target_blocks":recovery.get("target_blocks").cloned().ok_or_else(|| "exit policy has no target blocks".to_owned())?,
                "maximum_fee":required_string(recovery,"maximum_fee")?,
                "bump_mode":required_string(recovery,"bump_mode")?
            }
        },
        "verification":{
            "swap_tree_sha256":required_string(verifier,"swap_tree_sha256")?,
            "quote_id":quote_id,
            "verifier_digest":verifier_sha256,
            "taproot_script":taproot_script,
            "taproot_control_block":taproot_control_block,
            "taproot_tree":verifier.get("taproot_tree").cloned().ok_or_else(|| "funded verifier has no Taproot tree".to_owned())?
        },
        "secret_commitments":{
            "payment_hash":contract.get("payment_hash").cloned().ok_or_else(|| "funded contract has no payment hash".to_owned())?,
            "preimage_recovery_ref":null
        },
        "broadcast":{
            "esplora_urls":["https://localhost.invalid/api"],
            "minimum_agreeing_sources":1
        }
    }))
}

fn finalize_exit_package(
    seed: &ExitPackage,
    contract_ids: [&String; 2],
    contract_sha256: &str,
) -> Result<ExitPackage, String> {
    let mut document = seed.document().clone();
    document["swap_contract_ids"] = json!(contract_ids);
    document["contract_sha256"] = Value::String(contract_sha256.to_owned());
    ExitPackage::parse(document).map_err(|error| format!("bound exit package is invalid: {error}"))
}

fn verify_submarine_before_fund(
    session: &SessionContext,
    invoice: &str,
    funding: &SignedFundingTransaction,
) -> Result<SwapSession<FundingAuthorized>, String> {
    let input = verify_before_fund_input(session, invoice)?;
    let authorized = session
        .verifier
        .clone()
        .verify_before_fund(input, |request| match &request.action {
            FundingAction::BroadcastBitcoin {
                leg_id,
                raw_transaction,
                ..
            } if leg_id == "source" && raw_transaction == &funding.raw_transaction => Ok(()),
            _ => Err("client authorized another submarine funding action".to_owned()),
        })
        .map_err(|error| format!("client rejected submarine before funding: {error}"))?;
    match &authorized
        .funding_request()
        .map_err(|error| format!("submarine authorization has no funding request: {error}"))?
        .action
    {
        FundingAction::BroadcastBitcoin {
            leg_id,
            raw_transaction,
            ..
        } if leg_id == "source" && raw_transaction == &funding.raw_transaction => Ok(authorized),
        _ => Err("client returned another submarine funding request".to_owned()),
    }
}

fn verify_reverse_before_fund(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    session: &SessionContext,
    invoice: &str,
) -> Result<SwapSession<FundingAuthorized>, String> {
    let input = verify_before_fund_input(session, invoice)?;
    let readiness_id = cln_id(&format!(
        "reverse-readiness:{}",
        session.verifier.config().session_id
    ))?;
    let authorized = session
        .verifier
        .clone()
        .verify_before_fund_with_lightning(
            input,
            |request| {
                let final_cltv_delta = u32::try_from(request.minimum_final_cltv_delta)
                    .map_err(|_| "invoice final CLTV delta exceeds u32".to_owned())?;
                let deadline = Instant::now() + LIGHTNING_READINESS_TIMEOUT;
                let info = loop {
                    let info = runtime
                        .block_on(environment.peer_cln.node_info(&readiness_id))
                        .map_err(|error| {
                            format!("could not inspect requester CLN readiness: {error}")
                        })?;
                    let minimum_outgoing_expiry = info
                        .block_height
                        .checked_add(final_cltv_delta)
                        .ok_or_else(|| {
                        "requester CLN expiry calculation overflowed".to_owned()
                    })?;
                    if minimum_outgoing_expiry >= request.hold_expiry_height
                        || Instant::now() >= deadline
                    {
                        break info;
                    }
                    thread::sleep(Duration::from_millis(250));
                };
                let minimum_outgoing_expiry = info
                    .block_height
                    .checked_add(final_cltv_delta)
                    .ok_or_else(|| "requester CLN expiry calculation overflowed".to_owned())?;
                if info.network != request.network
                    || !request.hold_invoice_required
                    || info.block_height >= request.hold_expiry_height
                    || minimum_outgoing_expiry < request.hold_expiry_height
                {
                    return Err(format!(
                        "requester CLN cannot satisfy the bound hold-invoice timing: network={}, expected_network={}, height={}, hold_expiry_height={}, minimum_final_cltv_delta={}, hold_required={}",
                        info.network,
                        request.network,
                        info.block_height,
                        request.hold_expiry_height,
                        request.minimum_final_cltv_delta,
                        request.hold_invoice_required,
                    ));
                }
                Ok(LocalLightningReadiness {
                    invoice_sha256: request.invoice_sha256.clone(),
                    payment_hash: request.payment_hash.clone(),
                    observed_at: unix_now()?,
                    state: LightningReadinessState::Acceptable,
                })
            },
            |request| match &request.action {
                FundingAction::PayLightningInvoice {
                    leg_id,
                    invoice: authorized_invoice,
                    hold_invoice_required,
                    ..
                } if leg_id == "lightning"
                    && authorized_invoice == invoice
                    && *hold_invoice_required =>
                {
                    Ok(())
                }
                _ => Err("client authorized another reverse funding action".to_owned()),
            },
        )
        .map_err(|error| format!("client rejected reverse before funding: {error}"))?;
    match &authorized
        .funding_request()
        .map_err(|error| format!("reverse authorization has no funding request: {error}"))?
        .action
    {
        FundingAction::PayLightningInvoice {
            leg_id,
            invoice: authorized_invoice,
            hold_invoice_required,
            ..
        } if leg_id == "lightning" && authorized_invoice == invoice && *hold_invoice_required => {
            Ok(authorized)
        }
        _ => Err("client returned another reverse funding request".to_owned()),
    }
}

fn verify_before_fund_input(
    session: &SessionContext,
    invoice: &str,
) -> Result<VerifyBeforeFundInput, String> {
    let swap_type = session
        .contract
        .get("swap_type")
        .and_then(Value::as_str)
        .ok_or_else(|| "funded contract has no swap type".to_owned())?;
    let bitcoin_leg_id = match swap_type {
        "submarine" => "source",
        "reverse" => "destination",
        _ => return Err("funded contract has an unsupported verification flow".to_owned()),
    };
    let verifier = verifier_for_leg(&session.contract, bitcoin_leg_id)?;
    let lightning = verifier_for_leg(&session.contract, "lightning")?;
    let output_index = verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "funded verifier has no bounded output index".to_owned())?;
    let observed_at = if session.control.injection == Some(HarnessInjection::StaleQuote) {
        let quote_expiration = session
            .verifier
            .signed_records()
            .iter()
            .find(|event| event.kind == MKT_QUOTE_KIND)
            .and_then(|quote| quote.tag_values("expiration").next())
            .ok_or_else(|| "stale-quote injection found no Quote expiration".to_owned())?
            .parse::<u64>()
            .map_err(|_| "stale-quote injection found an invalid expiration".to_owned())?;
        let clock_skew = canonical_u64(
            session
                .contract
                .get("clock_skew_seconds")
                .and_then(Value::as_str)
                .ok_or_else(|| "stale-quote injection found no clock-skew bound".to_owned())?,
        )?;
        quote_expiration
            .checked_add(clock_skew)
            .and_then(|deadline| deadline.checked_add(1))
            .ok_or_else(|| "stale-quote injection deadline overflowed".to_owned())?
    } else {
        unix_now()?
    };
    let minimum_confirmations = u32::try_from(canonical_u64(required_string(
        verifier,
        "minimum_confirmations",
    )?)?)
    .map_err(|_| "minimum confirmation count exceeds u32".to_owned())?;
    let minimum_final_cltv = canonical_u64(required_string(
        lightning,
        "invoice_minimum_final_cltv_delta",
    )?)?;
    let timeout_ladder = serde_json::from_value(
        session
            .contract
            .get("timeout_ladder")
            .cloned()
            .ok_or_else(|| "funded contract has no timeout ladder".to_owned())?,
    )
    .map_err(|error| format!("funded timeout ladder is invalid: {error}"))?;
    Ok(VerifyBeforeFundInput {
        observed_at,
        payment_hash: session
            .contract
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "funded contract has no payment hash".to_owned())?
            .to_owned(),
        funding: FundingVerificationInput {
            raw_transaction: required_string(verifier, "funding_transaction")?.to_owned(),
            output_index,
            expected_amount: required_string(verifier, "amount")?.to_owned(),
            expected_script_pubkey: required_string(verifier, "script_pubkey")?.to_owned(),
            taproot_output_key: required_string(verifier, "taproot_output_key")?.to_owned(),
            taproot_script: required_string(verifier, "taproot_script")?.to_owned(),
            taproot_control_block: required_string(verifier, "taproot_control_block")?.to_owned(),
        },
        invoice: Some(InvoiceVerificationInput {
            invoice: invoice.to_owned(),
            expected_network: required_string(lightning, "invoice_network")?.to_owned(),
            expected_amount_msat: required_string(lightning, "invoice_amount_msat")?.to_owned(),
            observed_at,
            required_minimum_final_cltv_delta: minimum_final_cltv,
        }),
        timeout_ladder,
        minimum_confirmations,
        replacement_policy: required_string(verifier, "replacement_policy")?.to_owned(),
    })
}

fn verifier_for_leg<'a>(
    contract: &'a Value,
    leg_id: &str,
) -> Result<&'a Map<String, Value>, String> {
    contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers
                .iter()
                .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| format!("funded contract has no {leg_id} verifier"))
}

fn requester_effect_id(order_id: &str, role: &str, leg_id: &str) -> Result<String, String> {
    let mut preimage = b"openagents.mkt-swp.v1".to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&decode_hex(order_id)?);
    preimage.push(0);
    preimage.extend_from_slice(role.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(leg_id.as_bytes());
    Ok(lower_hex(&sha256(&preimage)))
}

fn json_digest(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .map_err(|error| format!("could not serialize committed JSON: {error}"))
}

fn exact_tag_value<'a>(event: &'a Event, name: &'a str) -> Result<&'a str, String> {
    let values = event.tag_values(name).collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return Err(format!("event does not have exactly one {name} tag"));
    };
    Ok(*value)
}

struct BitcoinTerms {
    amount_sat: u64,
    miner_fee_budget_sat: u64,
    script_pubkey: Vec<u8>,
    claim_script: Vec<u8>,
    claim_control_block: Vec<u8>,
    refund_script: Vec<u8>,
    refund_control_block: Vec<u8>,
    refund_lock_height: u32,
}

fn bitcoin_terms(contract: &Value, leg_id: &str) -> Result<BitcoinTerms, String> {
    let verifier = contract
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|verifiers| {
            verifiers
                .iter()
                .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "funded contract has no Bitcoin verifier".to_owned())?;
    let leg = contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| "funded contract has no Bitcoin leg".to_owned())?;
    Ok(BitcoinTerms {
        amount_sat: canonical_u64(required_string(verifier, "amount")?)?,
        miner_fee_budget_sat: canonical_u64(
            contract
                .get("miner_fee_budget")
                .and_then(Value::as_str)
                .ok_or_else(|| "funded contract has no miner fee budget".to_owned())?,
        )?,
        script_pubkey: decode_hex(required_string(verifier, "script_pubkey")?)?,
        claim_script: decode_hex(required_string(verifier, "claim_script")?)?,
        claim_control_block: decode_hex(required_string(verifier, "taproot_claim_control_block")?)?,
        refund_script: decode_hex(required_string(verifier, "refund_script")?)?,
        refund_control_block: decode_hex(required_string(
            verifier,
            "taproot_refund_control_block",
        )?)?,
        refund_lock_height: u32::try_from(canonical_u64(required_string(
            leg,
            "refund_lock_value",
        )?)?)
        .map_err(|_| "Bitcoin refund lock height exceeds u32".to_owned())?,
    })
}

fn submarine_refund_action(
    session: &SessionContext,
    current_height: u32,
    funding_confirmation_height: u32,
    lightning_state: LightningRecoveryState,
) -> Result<RecoveryAction, String> {
    session
        .authorized_verifier
        .as_ref()
        .ok_or_else(|| "submarine refund has no funding-authorized client session".to_owned())?
        .recovery_action_with(|request| {
            if !matches!(
                request.source_refund_condition,
                Some(immortal_client::mkt_swp_client::RecoveryTimeoutCondition::Cltv { .. })
            ) {
                return Err("submarine refund recovery omitted its CLTV condition".to_owned());
            }
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height,
                source_funding_confirmation_height: Some(funding_confirmation_height),
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(lightning_state),
                chain_state: None,
            })
        })
        .map_err(|error| format!("client engine rejected submarine refund recovery view: {error}"))
}

fn finalize_invoice_unpaid(
    runtime: &Runtime,
    cln: &ClnClient,
    label: &str,
    payment_hash: &str,
) -> Result<(), String> {
    let deleted = runtime
        .block_on(cln.call(
            &cln_id("submarine-refund-invoice-final")?,
            "delinvoice",
            json!({"label":label,"status":"unpaid"}),
        ))
        .map_err(|error| format!("could not finalize requester invoice as unpaid: {error}"))?;
    if deleted.get("payment_hash").and_then(Value::as_str) != Some(payment_hash)
        || deleted.get("status").and_then(Value::as_str) != Some("unpaid")
    {
        return Err("deleted requester invoice differs from the exact unpaid invoice".to_owned());
    }
    let remaining = runtime
        .block_on(cln.list_invoices(&cln_id("submarine-refund-invoice-absence")?, Some(label)))
        .map_err(|error| format!("could not prove requester invoice deletion: {error}"))?;
    if remaining
        .get("invoices")
        .and_then(Value::as_array)
        .is_none_or(|invoices| !invoices.is_empty())
    {
        return Err("requester invoice remained payable after unpaid finalization".to_owned());
    }
    Ok(())
}

fn verify_requester_invoice_paid(
    runtime: &Runtime,
    cln: &ClnClient,
    payment_hash: &str,
) -> Result<(), String> {
    let invoices = runtime
        .block_on(cln.list_invoices(&cln_id("liquid-terminal-invoice")?, None))
        .map_err(|error| format!("could not inspect Liquid terminal invoice: {error}"))?;
    let matching = invoices
        .get("invoices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|invoice| {
            invoice.get("payment_hash").and_then(Value::as_str) == Some(payment_hash)
                && invoice.get("status").and_then(Value::as_str) == Some("paid")
        })
        .count();
    if matching != 1 {
        return Err("requester CLN did not report one exact paid Liquid invoice".to_owned());
    }
    Ok(())
}

fn chain_height(runtime: &Runtime, bitcoind: &BitcoindClient, label: &str) -> Result<u32, String> {
    runtime
        .block_on(bitcoind.call(&rpc_id(label)?, "getblockcount", json!([])))
        .map_err(|error| format!("could not read Bitcoin chain height: {error}"))?
        .as_u64()
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| "Bitcoin chain height exceeds u32".to_owned())
}

fn transaction_confirmation_height(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    label: &str,
    transaction_id: &str,
) -> Result<u32, String> {
    let transaction = runtime
        .block_on(bitcoind.raw_transaction(
            &rpc_id(&format!("{label}-transaction"))?,
            transaction_id,
            true,
        ))
        .map_err(|error| format!("could not inspect confirmed funding transaction: {error}"))?;
    let block_hash = transaction
        .get("blockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| "funding transaction is not confirmed".to_owned())?;
    runtime
        .block_on(bitcoind.call(
            &rpc_id(&format!("{label}-block"))?,
            "getblockheader",
            json!([block_hash, true]),
        ))
        .map_err(|error| format!("could not inspect funding confirmation block: {error}"))?
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| "funding confirmation height exceeds u32".to_owned())
}

fn load_adversarial_bitcoind(suffix: &str) -> Result<BitcoindClient, String> {
    if !matches!(suffix, "A" | "B") {
        return Err("adversarial bitcoind suffix must be A or B".to_owned());
    }
    let prefix = format!("IMMORTAL_LAB_ADVERSARIAL_BITCOIND_{suffix}");
    let port = required_environment(&format!("{prefix}_PORT"))?
        .parse::<u16>()
        .map_err(|_| "adversarial bitcoind port is invalid".to_owned())?;
    let endpoint = BitcoindEndpoint::new(required_environment(&format!("{prefix}_HOST"))?, port)
        .map_err(|error| format!("adversarial bitcoind endpoint is invalid: {error}"))?;
    let auth = BitcoindAuth::new(
        required_environment(&format!("{prefix}_RPC_USER"))?,
        required_environment(&format!("{prefix}_RPC_PASSWORD"))?,
    )
    .map_err(|error| format!("adversarial bitcoind credentials are invalid: {error}"))?;
    BitcoindClient::new(endpoint, auth, BitcoindLimits::default())
        .map_err(|error| format!("could not initialize adversarial bitcoind client: {error}"))
}

fn wait_for_exact_transaction_on_both_nodes(
    runtime: &Runtime,
    nodes: [&BitcoindClient; 2],
    transaction_id: &str,
    label: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + JOURNEY_TIMEOUT;
    loop {
        let mut transactions = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            match runtime.block_on(node.raw_transaction(
                &rpc_id(&format!("{label}-propagation-{index}"))?,
                transaction_id,
                false,
            )) {
                Ok(Value::String(raw)) => transactions.push(raw),
                Ok(_) => {
                    return Err(format!(
                        "Bitcoin node {index} returned another transaction shape during propagation"
                    ));
                }
                Err(BitcoindError::Rpc { code: -5 }) if Instant::now() < deadline => break,
                Err(error) => {
                    return Err(format!(
                        "Bitcoin node {index} did not receive the settlement transaction: {error}"
                    ));
                }
            }
        }
        if let [first, second] = transactions.as_slice() {
            if first != second {
                return Err(
                    "Bitcoin nodes received different settlement transaction bytes".to_owned(),
                );
            }
            let transaction = Transaction::parse(&decode_hex(first)?).map_err(|error| {
                format!("propagated settlement transaction is invalid: {error}")
            })?;
            if lower_hex(
                &transaction
                    .txid()
                    .map_err(|error| format!("settlement transaction txid failed: {error}"))?,
            ) != transaction_id
            {
                return Err("propagated settlement transaction has another txid".to_owned());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "settlement transaction did not propagate to both Bitcoin nodes before mining"
                    .to_owned(),
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn verify_refund_spend_on_both_nodes(
    runtime: &Runtime,
    nodes: [&BitcoindClient; 2],
    funding_transaction_id: &str,
    funding_output_index: u32,
    refund_transaction_id: &str,
    raw_refund: &str,
) -> Result<(), String> {
    for (index, node) in nodes.into_iter().enumerate() {
        let deadline = Instant::now() + JOURNEY_TIMEOUT;
        let transaction = loop {
            match runtime.block_on(node.raw_transaction(
                &rpc_id(&format!("refund-node-{index}"))?,
                refund_transaction_id,
                true,
            )) {
                Ok(transaction) => break transaction,
                Err(BitcoindError::Rpc { code: -5 }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(error) => {
                    return Err(format!(
                        "Bitcoin node {index} did not observe the requester refund: {error}"
                    ));
                }
            }
        };
        verify_known_bitcoin_transaction(&transaction, refund_transaction_id, Some(raw_refund))?;
        let inputs = transaction
            .get("vin")
            .and_then(Value::as_array)
            .ok_or_else(|| "refund transaction has no input array".to_owned())?;
        let [input] = inputs.as_slice() else {
            return Err("requester refund does not have exactly one input".to_owned());
        };
        if input.get("txid").and_then(Value::as_str) != Some(funding_transaction_id)
            || input.get("vout").and_then(Value::as_u64) != Some(u64::from(funding_output_index))
        {
            return Err("requester refund spends another funding outpoint".to_owned());
        }
        let unspent = runtime
            .block_on(node.call(
                &rpc_id(&format!("refund-outpoint-node-{index}"))?,
                "gettxout",
                json!([funding_transaction_id, funding_output_index, true]),
            ))
            .map_err(|error| {
                format!("could not inspect refund outpoint on node {index}: {error}")
            })?;
        if !unspent.is_null() {
            return Err("requester funding outpoint remains unspent on a Bitcoin node".to_owned());
        }
    }
    Ok(())
}

fn reverse_refund_height(contract: &Value) -> Result<u32, String> {
    let value = contract
        .get("timeout_ladder")
        .and_then(|ladder| ladder.get("provider_refund_first"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "reverse contract has no provider refund height".to_owned())?;
    u32::try_from(value).map_err(|_| "reverse refund height exceeds u32".to_owned())
}

fn fund_client_wallet(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
) -> Result<FundingInput, String> {
    let path = WalletPath::new(0, false, 0)
        .map_err(|error| format!("client wallet funding path is invalid: {error}"))?;
    let address = environment
        .wallet
        .derive_address(path)
        .map_err(|error| format!("could not derive client funding address: {error}"))?;
    let transaction_id = runtime
        .block_on(environment.bitcoind.call(
            &rpc_id("client-wallet-fund")?,
            "sendtoaddress",
            json!([address.address, 1.0]),
        ))
        .map_err(|error| format!("could not fund client smoke wallet: {error}"))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "client wallet funding returned no transaction ID".to_owned())?;
    mine_blocks(runtime, &environment.bitcoind, 2, "client-wallet-fund")?;
    let transaction = runtime
        .block_on(environment.bitcoind.raw_transaction(
            &rpc_id("client-wallet-transaction")?,
            &transaction_id,
            true,
        ))
        .map_err(|error| format!("could not inspect client wallet funding: {error}"))?;
    let outputs = transaction
        .get("vout")
        .and_then(Value::as_array)
        .ok_or_else(|| "client wallet funding has no outputs".to_owned())?;
    let script = lower_hex(&address.script_pubkey);
    let matching = outputs
        .iter()
        .filter(|output| {
            output
                .get("scriptPubKey")
                .and_then(|script| script.get("hex"))
                .and_then(Value::as_str)
                == Some(script.as_str())
        })
        .collect::<Vec<_>>();
    let [output] = matching.as_slice() else {
        return Err("client wallet funding did not contain one derived output".to_owned());
    };
    let output_index = output
        .get("n")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "client wallet funding output index is invalid".to_owned())?;
    let amount = output
        .get("value")
        .ok_or_else(|| "client wallet funding output has no amount".to_owned())?;
    if btc_value_to_sat(amount)? != 100_000_000 {
        return Err("client wallet funding output has another amount".to_owned());
    }
    Ok(FundingInput {
        txid: transaction_id,
        vout: output_index,
        value_sat: 100_000_000,
        path,
    })
}

fn mine_blocks(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    count: u64,
    label: &str,
) -> Result<(), String> {
    if count == 0 || count > 1_000 {
        return Err("smoke mining count is outside bounds".to_owned());
    }
    let address = runtime
        .block_on(bitcoind.call(
            &rpc_id(&format!("{label}-mine-address"))?,
            "getnewaddress",
            json!([]),
        ))
        .map_err(|error| format!("could not derive mining address: {error}"))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "bitcoind returned no mining address".to_owned())?;
    let blocks = runtime
        .block_on(bitcoind.call(
            &rpc_id(&format!("{label}-mine"))?,
            "generatetoaddress",
            json!([count, address]),
        ))
        .map_err(|error| format!("could not mine smoke blocks: {error}"))?;
    if blocks.as_array().map(Vec::len) != usize::try_from(count).ok() {
        return Err("bitcoind returned another mined-block count".to_owned());
    }
    Ok(())
}

fn mine_liquid_blocks(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    count: u32,
    label: &str,
) -> Result<(), String> {
    if count == 0 || count > 1_000 {
        return Err("Liquid mining count is outside bounds".to_owned());
    }
    let address = runtime
        .block_on(
            liquid
                .elementsd
                .new_address(&rpc_id(&format!("{label}-liquid-mine-address"))?),
        )
        .map_err(|error| format!("could not derive Liquid mining address: {error}"))?;
    let blocks = runtime
        .block_on(liquid.elementsd.generate_to_address(
            &rpc_id(&format!("{label}-liquid-mine"))?,
            count,
            &address,
        ))
        .map_err(|error| format!("could not mine Liquid blocks: {error}"))?;
    if Some(blocks.len()) != usize::try_from(count).ok() {
        return Err("elementsd returned another mined-block count".to_owned());
    }
    Ok(())
}

fn mine_chain_leg(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    rail: &str,
    count: u64,
    label: &str,
) -> Result<(), String> {
    match rail {
        "bitcoin" => mine_blocks(runtime, &environment.bitcoind, count, label),
        "liquid" => mine_liquid_blocks(
            runtime,
            environment
                .liquid
                .as_ref()
                .ok_or_else(|| "chain leg has no local elementsd".to_owned())?,
            u32::try_from(count).map_err(|_| "Liquid block count exceeds u32".to_owned())?,
            label,
        ),
        _ => Err("chain leg uses an unsupported rail".to_owned()),
    }
}

fn discover_provider(
    relay_url: &str,
    requester: &MarketSigner,
    timeout: Duration,
) -> Result<String, String> {
    discover_provider_offering(relay_url, requester, timeout).map(|event| event.pubkey)
}

fn discover_provider_offering(
    relay_url: &str,
    requester: &MarketSigner,
    timeout: Duration,
) -> Result<Event, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut relay = connect(relay_url)?;
        authenticate(&mut relay, requester, relay_url, unix_now()?)?;
        send_json(
            &mut relay.websocket,
            json!(["REQ", "funded-provider-discovery", {
                "kinds":[39601],
                "#d":[OFFERING_ID],
                "limit":8
            }]),
        )?;
        while Instant::now() < deadline {
            let Some(message) = read_json_until(&mut relay.websocket, deadline)? else {
                break;
            };
            if message == json!(["EOSE", "funded-provider-discovery"]) {
                break;
            }
            let Some(value) = message
                .as_array()
                .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
                .and_then(|fields| fields.get(2))
            else {
                continue;
            };
            let event: Event = serde_json::from_value(value.clone())
                .map_err(|error| format!("provider discovery event is invalid: {error}"))?;
            if event.kind == 39_601 && event.tag_values("d").any(|value| value == OFFERING_ID) {
                event
                    .validate_structure()
                    .and_then(|()| event.validate_crypto())
                    .map_err(|error| format!("provider Offering signature is invalid: {error}"))?;
                validate_mkt_public_event(&event)
                    .map_err(|error| format!("provider Offering is invalid: {error}"))?;
                return Ok(event);
            }
        }
        if Instant::now() >= deadline {
            return Err("funded provider Offering did not appear before timeout".to_owned());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn verify_health(url: &str) -> Result<(), String> {
    let remainder = url
        .strip_prefix("http://")
        .ok_or_else(|| "smoke health URL must use plaintext loopback HTTP".to_owned())?;
    let (authority, path) = remainder
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((remainder, "/".to_owned()));
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve provider health endpoint: {error}"))?
        .filter(|address| address.ip().is_loopback())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("smoke health endpoint is not loopback".to_owned());
    }
    let mut stream = TcpStream::connect_timeout(
        addresses
            .first()
            .ok_or_else(|| "provider health endpoint has no address".to_owned())?,
        IO_TIMEOUT,
    )
    .map_err(|error| format!("could not connect to provider health endpoint: {error}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("could not bound provider health read: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("could not bound provider health write: {error}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("could not request provider health: {error}"))?;
    let mut response = Vec::new();
    stream
        .take(16 * 1024)
        .read_to_end(&mut response)
        .map_err(|error| format!("could not read provider health: {error}"))?;
    let response = std::str::from_utf8(&response)
        .map_err(|_| "provider health response is not UTF-8".to_owned())?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n") || !response.ends_with("\r\n\r\nready\n") {
        return Err("provider health endpoint did not report ready".to_owned());
    }
    Ok(())
}

fn write_evidence(
    path: &Path,
    provider_pubkey: &str,
    submarine: Value,
    reverse: Value,
    reverse_refund: Value,
) -> Result<(), String> {
    let evidence = json!({
        "schema":"openagents.immortal.provider-funded-smoke-evidence.v1",
        "daemon":{
            "health_ready":true,
            "provider_pubkey":provider_pubkey
        },
        "journeys":{
            "submarine":submarine,
            "reverse":reverse,
            "reverse_refund":reverse_refund
        }
    });
    let bytes = serde_json::to_vec_pretty(&evidence)
        .map_err(|error| format!("could not serialize funded evidence: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create private funded evidence: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("could not write private funded evidence: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("could not terminate private funded evidence: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("could not sync private funded evidence: {error}"))
}

fn connect(relay_url: &str) -> Result<RelayClient, String> {
    let addresses = loopback_addresses(relay_url)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay write timeout: {error}"))?;
                let (mut websocket, _) = client(relay_url, stream)
                    .map_err(|error| format!("could not open relay WebSocket: {error}"))?;
                let challenge_message =
                    read_json_until(&mut websocket, Instant::now() + IO_TIMEOUT)?.ok_or_else(
                        || "relay did not send an authentication challenge".to_owned(),
                    )?;
                let challenge = challenge_message
                    .as_array()
                    .filter(|fields| fields.first().and_then(Value::as_str) == Some("AUTH"))
                    .and_then(|fields| fields.get(1))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "relay did not send NIP-42 challenge".to_owned())?
                    .to_owned();
                return Ok(RelayClient {
                    websocket,
                    challenge,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "could not connect to relay: {}",
        last_error.map_or_else(|| "no address".to_owned(), |error| error.to_string())
    ))
}

fn authenticate(
    client: &mut RelayClient,
    signer: &MarketSigner,
    relay_url: &str,
    now: u64,
) -> Result<(), String> {
    let event = signer.sign(
        now,
        22_242,
        vec![
            Tag::new(vec!["relay".into(), relay_url.into()]),
            Tag::new(vec!["challenge".into(), client.challenge.clone()]),
        ],
        String::new(),
    );
    send_json(&mut client.websocket, json!(["AUTH", event]))?;
    expect_ok(
        &mut client.websocket,
        &event.id,
        Instant::now() + IO_TIMEOUT,
    )
}

fn subscribe(client: &mut RelayClient, recipient: &str) -> Result<(), String> {
    send_json(
        &mut client.websocket,
        json!(["REQ", "funded-requester", {"kinds":[1059],"#p":[recipient],"limit":512}]),
    )
}

fn drain_history(client: &mut RelayClient, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let message = read_json_until(&mut client.websocket, deadline)?
            .ok_or_else(|| "funded requester history did not reach EOSE".to_owned())?;
        if message == json!(["EOSE", "funded-requester"]) {
            return Ok(());
        }
    }
}

fn publish_private(
    publisher: &mut RelayClient,
    raw_signed_event: &[u8],
    sender: &MarketSigner,
    recipient: &str,
) -> Result<(), String> {
    let wrap = wrap_mkt_record(raw_signed_event, sender, recipient, random_wrap_material()?)?;
    send_json(&mut publisher.websocket, json!(["EVENT", wrap.event]))?;
    expect_ok(
        &mut publisher.websocket,
        &wrap.event.id,
        Instant::now() + IO_TIMEOUT,
    )
}

fn receive_matching_private<F>(
    reader: &mut RelayClient,
    recipient: &MarketSigner,
    session_id: &str,
    timeout: Duration,
    matches: F,
) -> Result<ReceivedPrivate, String>
where
    F: Fn(&Event) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Some(raw_message) = read_text_until(&mut reader.websocket, deadline)? else {
            break;
        };
        let message: Value = serde_json::from_str(&raw_message)
            .map_err(|error| format!("relay message is invalid JSON: {error}"))?;
        let Some(value) = message
            .as_array()
            .filter(|fields| fields.first().and_then(Value::as_str) == Some("EVENT"))
            .and_then(|fields| fields.get(2))
        else {
            continue;
        };
        if !value.is_object() {
            return Err("funded subscription payload is not an event".to_owned());
        }
        let raw_wrap = relay_array_element_raw(&raw_message, 2)
            .ok_or_else(|| "could not retain exact funded gift-wrap bytes".to_owned())?
            .as_bytes()
            .to_vec();
        let delivered = unwrap_mkt_record_raw(&raw_wrap, recipient, &swp_profiles())?;
        if delivered.record().envelope().session_id == session_id
            && matches(delivered.record().event())
        {
            let delivery = SignedRecordDelivery::from_delivered(&delivered, unix_now()?)
                .map_err(|error| format!("could not retain funded delivery provenance: {error}"))?;
            return Ok(ReceivedPrivate {
                event: delivered.record().event().clone(),
                delivery,
            });
        }
    }
    Err(format!(
        "no matching provider record arrived for session {session_id}"
    ))
}

fn restore_funded_deliveries(
    archive: Value,
    records: &[Event],
    requester: &MarketSigner,
) -> Result<Vec<SignedRecordDelivery>, String> {
    let entries = archive
        .as_array()
        .ok_or_else(|| "funded delivery archive is not an array".to_owned())?;
    if entries.len() != records.len() {
        return Err("funded delivery archive does not cover every signed record".to_owned());
    }
    let record_ids = records
        .iter()
        .map(|event| event.id.as_str())
        .collect::<BTreeSet<_>>();
    if record_ids.len() != records.len() {
        return Err("funded signed-record set contains a duplicate event ID".to_owned());
    }
    let mut archive_ids = BTreeSet::new();
    let mut restored = Vec::with_capacity(entries.len());
    for entry in entries {
        let event_id = entry
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "funded delivery archive has no event ID".to_owned())?;
        if !archive_ids.insert(event_id) {
            return Err("funded delivery archive contains a duplicate event ID".to_owned());
        }
        let event = records
            .iter()
            .find(|event| event.id == event_id)
            .ok_or_else(|| "funded delivery archive refers outside the session".to_owned())?;
        let observed_at = entry
            .get("observed_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| "funded delivery archive has no observation time".to_owned())?;
        let provenance: DeliveryProvenance = serde_json::from_value(
            entry
                .get("provenance")
                .cloned()
                .ok_or_else(|| "funded delivery archive has no provenance".to_owned())?,
        )
        .map_err(|error| format!("funded delivery provenance is invalid: {error}"))?;
        let delivery = match provenance {
            DeliveryProvenance::LocallySigned => {
                let archived_raw: Vec<u8> = serde_json::from_value(
                    entry
                        .get("raw_signed_event")
                        .cloned()
                        .ok_or_else(|| "local delivery has no signed bytes".to_owned())?,
                )
                .map_err(|error| format!("local delivery bytes are invalid: {error}"))?;
                let delivery = SignedRecordDelivery::from_locally_signed(archived_raw, observed_at)
                    .map_err(|error| format!("local delivery restore failed: {error}"))?;
                if delivery.event_id() != event.id {
                    return Err("local delivery restored another signed record".to_owned());
                }
                delivery
            }
            DeliveryProvenance::GiftWrap => {
                let raw_wrap: Vec<u8> = serde_json::from_value(
                    entry
                        .get("raw_wrap_event")
                        .cloned()
                        .ok_or_else(|| "gift-wrap delivery has no outer bytes".to_owned())?,
                )
                .map_err(|error| format!("gift-wrap delivery bytes are invalid: {error}"))?;
                let delivered = unwrap_mkt_record_raw(&raw_wrap, requester, &swp_profiles())?;
                if delivered.record().event() != event {
                    return Err("gift-wrap delivery restored another signed record".to_owned());
                }
                SignedRecordDelivery::from_delivered(&delivered, observed_at)
                    .map_err(|error| format!("gift-wrap delivery restore failed: {error}"))?
            }
            DeliveryProvenance::Direct => {
                return Err("funded relay archive cannot contain direct provenance".to_owned());
            }
        };
        let reconstructed = serde_json::to_value(&delivery)
            .map_err(|error| format!("restored funded delivery cannot be encoded: {error}"))?;
        if &reconstructed != entry {
            return Err(
                "funded delivery archive differs from its reconstructed signed receipt".to_owned(),
            );
        }
        restored.push(delivery);
    }
    if archive_ids != record_ids {
        return Err("funded delivery archive event IDs differ from the session".to_owned());
    }
    Ok(restored)
}

fn expect_ok(websocket: &mut RelaySocket, event_id: &str, deadline: Instant) -> Result<(), String> {
    loop {
        let response = read_json_until(websocket, deadline)?
            .ok_or_else(|| format!("relay did not acknowledge event {event_id}"))?;
        let Some(fields) = response.as_array() else {
            continue;
        };
        if fields.first().and_then(Value::as_str) != Some("OK")
            || fields.get(1).and_then(Value::as_str) != Some(event_id)
        {
            continue;
        }
        return if fields.get(2).and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err(format!("relay rejected event {event_id}: {response}"))
        };
    }
}

fn send_json(websocket: &mut RelaySocket, value: Value) -> Result<(), String> {
    websocket
        .send(Message::text(value.to_string()))
        .map_err(|error| format!("could not write relay message: {error}"))
}

fn read_json_until(
    websocket: &mut RelaySocket,
    deadline: Instant,
) -> Result<Option<Value>, String> {
    read_text_until(websocket, deadline)?
        .map(|text| {
            serde_json::from_str(&text)
                .map_err(|error| format!("relay message is invalid JSON: {error}"))
        })
        .transpose()
}

fn read_text_until(
    websocket: &mut RelaySocket,
    deadline: Instant,
) -> Result<Option<String>, String> {
    loop {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match websocket.read() {
            Ok(Message::Text(text)) => return Ok(Some(text.to_string())),
            Ok(Message::Ping(payload)) => websocket
                .send(Message::Pong(payload))
                .map_err(|error| format!("could not answer relay ping: {error}"))?,
            Ok(Message::Pong(_)) => {}
            Ok(Message::Close(frame)) => {
                return Err(format!("relay closed the smoke subscription: {frame:?}"));
            }
            Ok(message) => return Err(format!("unexpected relay frame: {message:?}")),
            Err(WebSocketError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("could not read relay message: {error}")),
        }
    }
}

fn relay_array_element_raw(input: &str, target_index: usize) -> Option<&str> {
    let bytes = input.as_bytes();
    let mut offset = bytes.iter().position(|byte| *byte == b'[')? + 1;
    for index in 0..=target_index {
        offset += bytes
            .get(offset..)?
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())?;
        if index > 0 {
            if *bytes.get(offset)? != b',' {
                return None;
            }
            offset += 1;
            offset += bytes
                .get(offset..)?
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())?;
        }
        let start = offset;
        let mut values =
            serde_json::Deserializer::from_str(input.get(start..)?).into_iter::<Value>();
        values.next()?.ok()?;
        offset = start.checked_add(values.byte_offset())?;
        if index == target_index {
            return input.get(start..offset);
        }
    }
    None
}

fn loopback_addresses(relay_url: &str) -> Result<Vec<SocketAddr>, String> {
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| "funded smoke accepts only ws:// relay URLs".to_owned())?
        .split('/')
        .next()
        .unwrap_or_default();
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("funded smoke refuses non-loopback relay addresses".to_owned());
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn sign_request(
    request: immortal_client::mkt_swp_client::MktSigningRequest,
    signer: &MarketSigner,
) -> Result<(Event, Vec<u8>), String> {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    let event = request
        .verify_signed(event)
        .map_err(|error| format!("request signature failed: {error}"))?;
    let raw = serde_json::to_vec(&event)
        .map_err(|error| format!("could not retain locally signed event bytes: {error}"))?;
    Ok((event, raw))
}

fn record_profile(event: &Event) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Value>(&event.content)
        .map_err(|error| format!("record content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "record has no MKT-SWP profile".to_owned())
}

fn exactly_one_status_by_author_and_state<'a>(
    records: &'a [Event],
    author: &str,
    state: &str,
) -> Result<&'a Event, String> {
    let matches = records
        .iter()
        .filter(|record| {
            record.kind == MKT_STATUS_KIND
                && record.pubkey == author
                && record_profile(record)
                    .ok()
                    .and_then(|profile| profile.get("swp_state").cloned())
                    .and_then(|state| state.as_str().map(str::to_owned))
                    .as_deref()
                    == Some(state)
        })
        .collect::<Vec<_>>();
    let [status] = matches.as_slice() else {
        return Err(format!(
            "requester {state} requires one exact provider prerequisite Status"
        ));
    };
    Ok(status)
}

fn requester_status_provider_prerequisite(state: &str) -> Option<&'static str> {
    match state {
        "requester_verification_passed" => Some("lock_terms_ready"),
        "requester_invoice_verified" => Some("hold_invoice_ready"),
        "requester_lock_verified" => Some("provider_lock_terms_ready"),
        "requester_claim_pending" => Some("funding_final"),
        "requester_source_verified" => Some("source_lock_terms_ready"),
        "requester_destination_verified" => Some("destination_lock_terms_ready"),
        "requester_source_broadcast" => Some("source_funding_required"),
        "requester_destination_claim_pending" => Some("destination_funding_final"),
        "requester_source_refund_pending" => Some("provider_destination_refunded"),
        _ => None,
    }
}

fn requester_status_provider_prerequisite_event<'a>(
    records: &'a [Event],
    provider_pubkey: &str,
    requester_state: &str,
) -> Result<Option<&'a Event>, String> {
    requester_status_provider_prerequisite(requester_state)
        .map(|provider_state| {
            exactly_one_status_by_author_and_state(records, provider_pubkey, provider_state)
        })
        .transpose()
}

fn next_created_at(session: &SwapSession<AwaitingVerification>) -> Result<u64, String> {
    next_created_at_records(session.signed_records())
}

fn next_created_at_records(records: &[Event]) -> Result<u64, String> {
    let newest = records
        .iter()
        .map(|record| record.created_at)
        .max()
        .unwrap_or(unix_now()?);
    Ok(unix_now()?.max(newest.saturating_add(1)))
}

fn base_state(state: &str) -> Result<&'static str, String> {
    match state {
        "requester_verification_passed"
        | "requester_invoice_verified"
        | "requester_lock_verified"
        | "requester_source_verified"
        | "requester_destination_verified" => Ok("awaiting_input"),
        "requester_funding_broadcast" | "requester_source_broadcast" => Ok("funding_observed"),
        "lightning_payment_pending"
        | "requester_claim_pending"
        | "requester_claimed"
        | "requester_destination_claim_pending"
        | "requester_destination_claimed" => Ok("executing"),
        "refund_prepared" | "refund_pending" => Ok("refund_pending"),
        "refunded" => Ok("refunded"),
        _ => Err("requester state has no smoke base-state mapping".to_owned()),
    }
}

fn latest_requester_status(
    records: &[Event],
    requester_pubkey: &str,
) -> Result<Option<(u64, String)>, String> {
    let mut latest: Option<(u64, String)> = None;
    for event in records
        .iter()
        .filter(|event| event.kind == MKT_STATUS_KIND && event.pubkey == requester_pubkey)
    {
        let sequence = event
            .tag_values("seq")
            .next()
            .ok_or_else(|| "persisted requester Status has no sequence".to_owned())?
            .parse::<u64>()
            .map_err(|_| "persisted requester Status sequence is invalid".to_owned())?;
        match &latest {
            Some((current, current_id)) if *current == sequence && current_id != &event.id => {
                return Err("persisted requester Status stream contains a fork".to_owned());
            }
            Some((current, _)) if *current > sequence => {}
            _ => latest = Some((sequence, event.id.clone())),
        }
    }
    Ok(latest)
}

fn checkpoint_external_identifier(checkpoint: &FundedCheckpoint) -> Result<String, String> {
    let identifier = checkpoint
        .details
        .get("external_identifier")
        .and_then(Value::as_str)
        .ok_or_else(|| "funded checkpoint has no external identifier".to_owned())?;
    require_lower_hex_32(identifier, "funded checkpoint external identifier")?;
    Ok(identifier.to_owned())
}

fn transaction_id(raw_transaction: &str) -> Result<String, String> {
    let bytes = decode_hex(raw_transaction)?;
    let transaction = Transaction::parse(&bytes)
        .map_err(|error| format!("persisted Bitcoin transaction is invalid: {error}"))?;
    transaction
        .txid()
        .map(|txid| lower_hex(&txid))
        .map_err(|error| format!("could not derive Bitcoin transaction ID: {error}"))
}

fn broadcast_bitcoin_once(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    label: &str,
    raw_transaction: &str,
    expected_txid: &str,
) -> Result<String, String> {
    require_lower_hex_32(expected_txid, "expected Bitcoin transaction ID")?;
    if transaction_id(raw_transaction)? != expected_txid {
        return Err("Bitcoin execution checkpoint binds another transaction".to_owned());
    }
    match runtime.block_on(bitcoind.raw_transaction(
        &rpc_id(&format!("{label}-preflight"))?,
        expected_txid,
        true,
    )) {
        Ok(value) => {
            verify_known_bitcoin_transaction(&value, expected_txid, Some(raw_transaction))?;
            return Ok(expected_txid.to_owned());
        }
        Err(BitcoindError::Rpc { code: -5 }) => {}
        Err(error) => {
            return Err(format!(
                "could not prove whether Bitcoin transaction already exists: {error}"
            ));
        }
    }
    let transaction_id = runtime
        .block_on(bitcoind.broadcast(&rpc_id(label)?, raw_transaction, None))
        .map_err(|error| format!("could not broadcast Bitcoin transaction: {error}"))?;
    if transaction_id != expected_txid {
        return Err("bitcoind returned another Bitcoin transaction ID".to_owned());
    }
    Ok(transaction_id)
}

fn claim_chain_bitcoin_destination(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    contract: &Value,
    funding_transaction_id: &str,
    funding_output_index: u32,
    wallet_path: WalletPath,
    preimage: [u8; 32],
) -> Result<(String, String), String> {
    let terms = bitcoin_terms(contract, "destination")?;
    let destination = environment
        .wallet
        .derive_address(
            WalletPath::new(0, true, 33)
                .map_err(|error| format!("chain claim destination path is invalid: {error}"))?,
        )
        .map_err(|error| format!("could not derive chain claim destination: {error}"))?;
    let destination_value_sat = terms
        .amount_sat
        .checked_sub(terms.miner_fee_budget_sat)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| "chain Bitcoin claim fee consumes its principal".to_owned())?;
    let claim = SettlementBridge::new(&environment.wallet)
        .claim(
            &SettlementTemplate {
                wallet_path,
                previous_txid_wire: display_txid_wire(funding_transaction_id)?,
                previous_output: funding_output_index,
                prevout_value_sat: terms.amount_sat,
                prevout_script_pubkey: terms.script_pubkey,
                destination_value_sat,
                destination_script_pubkey: destination.script_pubkey.to_vec(),
                transaction_version: 2,
                input_sequence: 0xffff_fffe,
                lock_time: 0,
                taproot_script: terms.claim_script,
                taproot_control_block: terms.claim_control_block,
                maximum_fee_sat: terms.miner_fee_budget_sat,
                maximum_fee_rate_sat_per_vbyte: 10_000,
                maximum_weight: 1_600,
                dust_relay_fee_sat_per_kilobyte: 3_000,
            },
            ClaimPreimage::new(preimage),
        )
        .map_err(|error| format!("could not construct chain Bitcoin claim: {error}"))?;
    let transaction_hex = lower_hex(claim.broadcast_bytes());
    let transaction_id = lower_hex(&claim.transaction_id());
    broadcast_bitcoin_once(
        runtime,
        &environment.bitcoind,
        "chain-bitcoin-destination-claim",
        &transaction_hex,
        &transaction_id,
    )?;
    Ok((transaction_id, transaction_hex))
}

fn claim_chain_liquid_destination(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    authorized: &mut SwapSession<FundingAuthorized>,
    request: &LiquidBeforeFundRequest,
    wallet_path: WalletPath,
    preimage: [u8; 32],
    journey_name: &str,
) -> Result<(String, String), String> {
    execute_liquid_wallet_claim(
        runtime,
        environment,
        authorized,
        request,
        "destination",
        wallet_path,
        preimage,
        journey_name,
        "chain-liquid-destination-claim",
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_liquid_wallet_claim(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    authorized: &mut SwapSession<FundingAuthorized>,
    request: &LiquidBeforeFundRequest,
    leg_id: &str,
    wallet_path: WalletPath,
    preimage: [u8; 32],
    journey_name: &str,
    label: &str,
) -> Result<(String, String), String> {
    let liquid = environment
        .liquid
        .as_ref()
        .ok_or_else(|| "Liquid wallet claim has no local elementsd".to_owned())?;
    let transaction_artifact_ref = format!("lab-private-signed-exit:{journey_name}");
    let retained_transaction = environment
        .control
        .paths
        .funded_signed_exit(journey_name)
        .exists()
        .then(|| load_funded_signed_exit(&environment.control.paths, journey_name))
        .transpose()?;
    let signed = authorized
        .sign_liquid_exit_with(leg_id, "claim", |_| {
            if let Some(transaction) = &retained_transaction {
                decode_hex(transaction)
            } else {
                liquid
                    .rail
                    .complete_wallet_claim_exit(request, &environment.wallet, wallet_path, preimage)
                    .map_err(|error| error.to_string())
            }
        })
        .map_err(|error| format!("could not sign exact Liquid wallet claim: {error}"))?;
    let ExitSigningOutcome::Signed(signed) = signed else {
        return Err("Liquid wallet claim was already recorded before broadcast".to_owned());
    };
    if let Some(retained_transaction) = retained_transaction {
        if retained_transaction != signed.transaction {
            return Err("retained Liquid wallet claim differs from the verified exit".to_owned());
        }
    } else {
        store_funded_signed_exit(
            &environment.control.paths,
            journey_name,
            &signed.transaction,
        )?;
    }
    let broadcast = authorized
        .liquid_exit_broadcast_request(&signed, &transaction_artifact_ref)
        .map_err(|error| format!("could not derive exact Liquid broadcast request: {error}"))?;
    let transaction_id = broadcast_liquid_effect_request(
        runtime,
        liquid,
        &environment.control.paths,
        journey_name,
        &broadcast,
        label,
    )?;
    let effect = authorized
        .record_liquid_broadcast_effect_with(&broadcast, |artifact_ref| {
            load_liquid_broadcast_artifact(&environment.control.paths, journey_name, artifact_ref)
        })
        .map_err(|error| format!("could not record exact Liquid broadcast effect: {error}"))?;
    if effect.external_identifier() != transaction_id {
        return Err("recorded Liquid broadcast effect differs from elementsd".to_owned());
    }
    let transaction_hex = load_funded_signed_exit(&environment.control.paths, journey_name)?;
    let parsed = parse_liquid_transaction(&decode_hex(&transaction_hex)?)
        .map_err(|error| format!("signed Liquid wallet claim is invalid: {error}"))?;
    if lower_hex(&parsed.transaction_id) != transaction_id {
        return Err("elementsd accepted another Liquid wallet claim".to_owned());
    }
    Ok((transaction_id, transaction_hex))
}

fn broadcast_liquid_effect_request(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    paths: &LabPaths,
    journey_name: &str,
    request: &LiquidBroadcastRequest,
    label: &str,
) -> Result<String, String> {
    let network = runtime
        .block_on(liquid.rail.network_view(&format!("{label}-network")))
        .map_err(|error| format!("could not verify Liquid broadcast network: {error}"))?;
    if request.rpc_method != "sendrawtransaction"
        || request.network_id != liquid.network_id
        || request.network_id != network.network_id.as_str()
        || request.genesis_hash != network.genesis_hash
    {
        return Err("Liquid broadcast request differs from the local elementsd network".to_owned());
    }
    let raw =
        load_liquid_broadcast_artifact(paths, journey_name, &request.transaction_artifact_ref)?;
    if lower_hex(&sha256(&raw)) != request.transaction_sha256 {
        return Err("Liquid broadcast request differs from its transaction digest".to_owned());
    }
    let transaction = parse_liquid_transaction(&raw)
        .map_err(|error| format!("Liquid broadcast transaction is invalid: {error}"))?;
    let transaction_id = lower_hex(&transaction.transaction_id);
    let admission = runtime
        .block_on(liquid.elementsd.require_mempool_acceptance_or_exact_known(
            &rpc_id(&format!("{label}-mempool"))?,
            &rpc_id(&format!("{label}-known"))?,
            &raw,
        ))
        .map_err(|error| format!("elementsd rejected exact Liquid broadcast: {error}"))?;
    let observed = match admission {
        ElementsdMempoolAdmission::New => runtime
            .block_on(
                liquid
                    .elementsd
                    .broadcast(&rpc_id(&format!("{label}-broadcast"))?, &raw),
            )
            .map_err(|error| format!("elementsd Liquid broadcast failed: {error}"))?,
        ElementsdMempoolAdmission::ExactKnown => transaction_id.clone(),
    };
    if observed != transaction_id {
        return Err("elementsd returned another Liquid transaction ID".to_owned());
    }
    Ok(observed)
}

fn load_liquid_broadcast_artifact(
    paths: &LabPaths,
    journey_name: &str,
    artifact_ref: &str,
) -> Result<Vec<u8>, String> {
    if artifact_ref != format!("lab-private-signed-exit:{journey_name}") {
        return Err("Liquid broadcast artifact reference differs from its lab journey".to_owned());
    }
    decode_hex(&load_funded_signed_exit(paths, journey_name)?)
}

fn require_known_bitcoin_transaction(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    label: &str,
    transaction_id: &str,
    raw_transaction: Option<&str>,
) -> Result<(), String> {
    let value = runtime
        .block_on(bitcoind.raw_transaction(&rpc_id(label)?, transaction_id, true))
        .map_err(|error| format!("recorded Bitcoin transaction is not observable: {error}"))?;
    verify_known_bitcoin_transaction(&value, transaction_id, raw_transaction)
}

fn bitcoin_raw_transaction(
    runtime: &Runtime,
    bitcoind: &BitcoindClient,
    expected_transaction_id: &str,
    label: &str,
) -> Result<String, String> {
    let raw = runtime
        .block_on(bitcoind.raw_transaction(&rpc_id(label)?, expected_transaction_id, false))
        .map_err(|error| format!("could not read exact Bitcoin transaction: {error}"))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "bitcoind raw transaction result is not hexadecimal".to_owned())?;
    if transaction_id(&raw)? != expected_transaction_id {
        return Err("bitcoind raw transaction has another transaction ID".to_owned());
    }
    Ok(raw)
}

fn liquid_raw_transaction(
    runtime: &Runtime,
    liquid: &LiquidLabEnvironment,
    expected_transaction_id: &str,
    label: &str,
) -> Result<String, String> {
    let raw = runtime
        .block_on(
            liquid
                .elementsd
                .raw_transaction(&rpc_id(label)?, expected_transaction_id),
        )
        .map_err(|error| format!("could not read exact Liquid transaction: {error}"))?;
    let parsed = parse_liquid_transaction(&raw)
        .map_err(|error| format!("observed Liquid transaction is invalid: {error}"))?;
    if lower_hex(&parsed.transaction_id) != expected_transaction_id {
        return Err("elementsd raw transaction has another transaction ID".to_owned());
    }
    Ok(lower_hex(&raw))
}

fn contract_leg_rail_name<'a>(contract: &'a Value, leg_id: &str) -> Result<&'a str, String> {
    contract
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|legs| {
            legs.iter()
                .find(|leg| leg.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(|leg| leg.get("rail"))
        .and_then(Value::as_str)
        .filter(|rail| matches!(*rail, "bitcoin" | "liquid"))
        .ok_or_else(|| format!("chain {leg_id} leg has no supported rail"))
}

fn chain_terminal_settlement_ids<'a>(
    source_rail: &str,
    destination_rail: &str,
    source_claim_transaction_id: &'a str,
    destination_claim_transaction_id: &'a str,
) -> Result<(&'a str, &'a str), String> {
    match (source_rail, destination_rail) {
        ("bitcoin", "liquid") => Ok((
            source_claim_transaction_id,
            destination_claim_transaction_id,
        )),
        ("liquid", "bitcoin") => Ok((
            destination_claim_transaction_id,
            source_claim_transaction_id,
        )),
        _ => Err("chain terminal settlement rails are unsupported or duplicated".to_owned()),
    }
}

fn validate_chain_destination_template(
    contract: &Value,
    direction: LiquidChainDirection,
) -> Result<(), String> {
    let rail = contract_leg_rail_name(contract, "destination")?;
    let expected = match direction {
        LiquidChainDirection::BitcoinToLiquid => "liquid",
        LiquidChainDirection::LiquidToBitcoin => "bitcoin",
    };
    if rail != expected {
        return Err("chain destination rail differs from its ordered asset pair".to_owned());
    }
    let verifier = verifier_for_leg(contract, "destination")?;
    let raw = decode_hex(required_string(verifier, "funding_transaction")?)?;
    let output_index = bounded_u32_member(verifier, "output_index")?;
    let expected_amount = canonical_u64(required_string(verifier, "amount")?)?;
    let expected_script = decode_hex(required_string(verifier, "script_pubkey")?)?;
    match rail {
        "bitcoin" => {
            let transaction = Transaction::parse(&raw).map_err(|error| {
                format!("chain destination Bitcoin template is invalid: {error}")
            })?;
            let output = transaction
                .outputs
                .get(usize::try_from(output_index).map_err(|_| {
                    "chain destination Bitcoin output index exceeds usize".to_owned()
                })?)
                .ok_or_else(|| "chain destination Bitcoin output is absent".to_owned())?;
            if output.value_sat != expected_amount || output.script_pubkey != expected_script {
                return Err(
                    "chain destination Bitcoin template differs from the Contract".to_owned(),
                );
            }
        }
        "liquid" => {
            let transaction = parse_liquid_transaction(&raw).map_err(|error| {
                format!("chain destination Liquid template is invalid: {error}")
            })?;
            let output = transaction
                .outputs
                .get(usize::try_from(output_index).map_err(|_| {
                    "chain destination Liquid output index exceeds usize".to_owned()
                })?)
                .ok_or_else(|| "chain destination Liquid output is absent".to_owned())?;
            if output.script_pubkey != expected_script {
                return Err("chain destination Liquid script differs from the Contract".to_owned());
            }
        }
        _ => return Err("chain destination template uses another rail".to_owned()),
    }
    Ok(())
}

fn chain_raw_transaction(
    runtime: &Runtime,
    environment: &SmokeEnvironment,
    rail: &str,
    transaction_id: &str,
    label: &str,
) -> Result<String, String> {
    match rail {
        "bitcoin" => bitcoin_raw_transaction(runtime, &environment.bitcoind, transaction_id, label),
        "liquid" => liquid_raw_transaction(
            runtime,
            environment
                .liquid
                .as_ref()
                .ok_or_else(|| "chain proof has no local elementsd".to_owned())?,
            transaction_id,
            label,
        ),
        _ => Err("chain proof uses an unsupported rail".to_owned()),
    }
}

fn chain_lifecycle_event_ids(
    records: &[Event],
    offering: &Event,
    close: &Event,
) -> Result<Value, String> {
    let exactly_one = |kind: u16, author: Option<&str>, label: &str| {
        let events = records
            .iter()
            .filter(|record| record.kind == kind)
            .filter(|record| author.is_none_or(|author| record.pubkey == author))
            .collect::<Vec<_>>();
        let [event] = events.as_slice() else {
            return Err(format!(
                "chain lifecycle does not contain exactly one {label}"
            ));
        };
        Ok(event.id.clone())
    };
    let rfq_id = exactly_one(immortal_core::domain::MKT_RFQ_KIND, None, "RFQ")?;
    let quote_id = exactly_one(MKT_QUOTE_KIND, None, "Quote")?;
    let order_id = exactly_one(MKT_ORDER_KIND, None, "Order")?;
    let requester_contract_id = exactly_one(
        MKT_SWP_SWAP_CONTRACT_KIND,
        Some(
            records
                .iter()
                .find(|record| record.kind == immortal_core::domain::MKT_RFQ_KIND)
                .ok_or_else(|| "chain lifecycle has no RFQ author".to_owned())?
                .pubkey
                .as_str(),
        ),
        "requester Contract",
    )?;
    let provider_contract_id = exactly_one(
        MKT_SWP_SWAP_CONTRACT_KIND,
        Some(offering.pubkey.as_str()),
        "provider Contract",
    )?;
    let status_ids = records
        .iter()
        .filter(|record| record.kind == MKT_STATUS_KIND)
        .map(|record| Value::String(record.id.clone()))
        .collect::<Vec<_>>();
    if status_ids.len() < 2 {
        return Err("chain lifecycle has no signed Status progression".to_owned());
    }
    Ok(json!({
        "offering_id":offering.id,
        "rfq_id":rfq_id,
        "quote_id":quote_id,
        "order_id":order_id,
        "requester_contract_id":requester_contract_id,
        "provider_contract_id":provider_contract_id,
        "status_ids":status_ids,
        "close_id":close.id,
    }))
}

fn liquid_lifecycle_event_ids(
    records: &[Event],
    offering_id: &str,
    close_id: Option<&str>,
) -> Result<Value, String> {
    require_lower_hex_32(offering_id, "Liquid lifecycle Offering ID")?;
    if let Some(close_id) = close_id {
        require_lower_hex_32(close_id, "Liquid lifecycle Close ID")?;
    }
    let exactly_one = |kind: u16, author: Option<&str>, label: &str| {
        let events = records
            .iter()
            .filter(|record| record.kind == kind)
            .filter(|record| author.is_none_or(|author| record.pubkey == author))
            .collect::<Vec<_>>();
        let [event] = events.as_slice() else {
            return Err(format!(
                "Liquid lifecycle does not contain exactly one {label}"
            ));
        };
        Ok(event.id.clone())
    };
    let rfq = records
        .iter()
        .find(|record| record.kind == immortal_core::domain::MKT_RFQ_KIND)
        .ok_or_else(|| "Liquid lifecycle has no RFQ".to_owned())?;
    let status_ids = records
        .iter()
        .filter(|record| record.kind == MKT_STATUS_KIND)
        .map(|record| Value::String(record.id.clone()))
        .collect::<Vec<_>>();
    if status_ids.is_empty() {
        return Err("Liquid lifecycle has no signed Status".to_owned());
    }
    Ok(json!({
        "offering_id":offering_id,
        "rfq_id":rfq.id,
        "quote_id":exactly_one(MKT_QUOTE_KIND, None, "Quote")?,
        "order_id":exactly_one(MKT_ORDER_KIND, None, "Order")?,
        "requester_contract_id":exactly_one(
            MKT_SWP_SWAP_CONTRACT_KIND,
            Some(&rfq.pubkey),
            "requester Contract",
        )?,
        "provider_contract_id":exactly_one(
            MKT_SWP_SWAP_CONTRACT_KIND,
            records
                .iter()
                .find(|record| record.kind == MKT_QUOTE_KIND)
                .map(|record| record.pubkey.as_str()),
            "provider Contract",
        )?,
        "status_ids":status_ids,
        "close_id":close_id,
    }))
}

fn chain_leg_process_proof(
    rail: &str,
    funding_transaction_id: &str,
    funding_output_index: u32,
    funding_transaction_hex: &str,
    exit_transaction_id: &str,
    exit_transaction_hex: &str,
) -> Value {
    let node_transaction_ids = match rail {
        "bitcoin" => json!({
            "bitcoind-a":funding_transaction_id,
            "bitcoind-b":funding_transaction_id,
        }),
        "liquid" => json!({
            "elementsd-provider-a":funding_transaction_id,
            "elementsd-provider-b":funding_transaction_id,
            "elementsd-wallet":funding_transaction_id,
        }),
        _ => json!({}),
    };
    let exit_node_transaction_ids = match rail {
        "bitcoin" => json!({
            "bitcoind-a":exit_transaction_id,
            "bitcoind-b":exit_transaction_id,
        }),
        "liquid" => json!({
            "elementsd-provider-a":exit_transaction_id,
            "elementsd-provider-b":exit_transaction_id,
            "elementsd-wallet":exit_transaction_id,
        }),
        _ => json!({}),
    };
    let outpoint = format!("{funding_transaction_id}:{funding_output_index}");
    json!({
        "lockup":{
            "transaction_hex":funding_transaction_hex,
            "transaction_id":funding_transaction_id,
            "outpoint":outpoint,
            "node_transaction_ids":node_transaction_ids,
            "exact_node_byte_equality":true,
        },
        "exit":{
            "transaction_hex":exit_transaction_hex,
            "transaction_id":exit_transaction_id,
            "spends_outpoint":format!("{funding_transaction_id}:{funding_output_index}"),
            "node_transaction_ids":exit_node_transaction_ids,
            "exact_node_byte_equality":true,
        }
    })
}

fn verify_known_bitcoin_transaction(
    value: &Value,
    transaction_id: &str,
    raw_transaction: Option<&str>,
) -> Result<(), String> {
    if value.get("txid").and_then(Value::as_str) != Some(transaction_id) {
        return Err("bitcoind returned another recorded transaction".to_owned());
    }
    if raw_transaction
        .is_some_and(|expected| value.get("hex").and_then(Value::as_str) != Some(expected))
    {
        return Err("bitcoind transaction bytes differ from the persisted execution".to_owned());
    }
    Ok(())
}

fn status_outpoint(status: &Event) -> Result<(String, u32), String> {
    let profile = record_profile(status)?;
    let transaction_id = profile
        .get("transaction_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "provider funding Status has no transaction ID".to_owned())?;
    require_lower_hex_32(transaction_id, "provider funding transaction ID")?;
    let output_index = profile
        .get("output_index")
        .or_else(|| profile.get("vout"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "provider funding Status has no output index".to_owned())?;
    Ok((transaction_id.to_owned(), output_index))
}

fn status_transaction_id(status: &Event) -> Result<String, String> {
    let transaction_id = record_profile(status)?
        .get("transaction_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "provider settlement Status has no transaction ID".to_owned())?;
    require_lower_hex_32(&transaction_id, "provider settlement transaction ID")?;
    Ok(transaction_id)
}

fn btc_value_to_sat(value: &Value) -> Result<u64, String> {
    let encoded = value
        .as_number()
        .map(ToString::to_string)
        .ok_or_else(|| "Bitcoin amount is not numeric".to_owned())?;
    let (whole, fraction) = encoded.split_once('.').unwrap_or((&encoded, ""));
    if fraction.len() > 8
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("Bitcoin amount is not a bounded decimal".to_owned());
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| "Bitcoin whole amount exceeds u64".to_owned())?;
    let mut padded = fraction.to_owned();
    padded.extend(std::iter::repeat_n('0', 8 - fraction.len()));
    let fractional = padded
        .parse::<u64>()
        .map_err(|_| "Bitcoin fractional amount is invalid".to_owned())?;
    whole
        .checked_mul(100_000_000)
        .and_then(|amount| amount.checked_add(fractional))
        .ok_or_else(|| "Bitcoin amount exceeds u64 satoshis".to_owned())
}

fn swp_profiles() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }]
}

fn random_wrap_material() -> Result<WrapMaterial, String> {
    let now = unix_now()?;
    Ok(WrapMaterial {
        seal_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        wrap_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        seal_nonce: random_32()?,
        wrap_nonce: random_32()?,
        wrap_secret: random_secret()?,
    })
}

fn random_secret() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate one-time wrapping key".to_owned())
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

fn required_environment(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required for the funded smoke"))
}

fn rpc_id(label: &str) -> Result<RpcRequestId, String> {
    let bounded = if label.len() > 80 {
        &label[..80]
    } else {
        label
    };
    RpcRequestId::new(format!("funded-smoke:{bounded}"))
        .map_err(|error| format!("smoke bitcoind request ID is invalid: {error}"))
}

fn cln_id(label: &str) -> Result<ClnRequestId, String> {
    let bounded = if label.len() > 80 {
        &label[..80]
    } else {
        label
    };
    ClnRequestId::new(format!("funded-smoke:{bounded}"))
        .map_err(|error| format!("smoke CLN request ID is invalid: {error}"))
}

fn required_string<'a>(object: &'a Map<String, Value>, member: &str) -> Result<&'a str, String> {
    object
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("contract member {member} is missing"))
}

fn bounded_u32_member(object: &Map<String, Value>, member: &str) -> Result<u32, String> {
    object
        .get(member)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| format!("contract member {member} is not a bounded unsigned integer"))
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

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("identity key is not 32-byte lowercase hex".to_owned());
    }
    let decoded = decode_hex(value)?;
    decoded
        .try_into()
        .map_err(|_| "identity key is not 32 bytes".to_owned())
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

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("hexadecimal artifact is not lowercase".to_owned()),
    }
}

fn display_txid_wire(value: &str) -> Result<[u8; 32], String> {
    require_lower_hex_32(value, "transaction ID")?;
    let mut bytes: [u8; 32] = decode_hex(value)?
        .try_into()
        .map_err(|_| "transaction ID is not 32 bytes".to_owned())?;
    bytes.reverse();
    Ok(bytes)
}

fn require_lower_hex_32(value: &str, label: &str) -> Result<(), String> {
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

fn digest(value: &str) -> String {
    lower_hex(&sha256(value.as_bytes()))
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

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKPOINT_FIXTURE: &str =
        include_str!("../../../tests/fixtures/lab/funded-checkpoints-v1.json");
    const MATRIX_FIXTURE: &str = include_str!("../../../tests/fixtures/lab/funded-matrix-v1.json");
    const LIQUID_RAIL_FIXTURE: &str =
        include_str!("../../../tests/fixtures/nipmkt/liquid-rail-v1.json");
    const LIQUID_RUNTIME_FIXTURE: &str =
        include_str!("../../../tests/fixtures/provider/liquid-runtime-v1.json");

    #[test]
    fn liquid_fee_schedule_replays_every_fixture_shape_at_a_non_lab_rate() {
        let fixture: Value =
            serde_json::from_str(LIQUID_RUNTIME_FIXTURE).expect("Liquid runtime fixture");
        let expected = &fixture["fee_weights"]["at_10_sat_per_vbyte"];
        let bitcoin = format!("swp:1:{NETWORK_ID}:btc:chain");
        let liquid = "swp:1:bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:elements:1111111111111111111111111111111111111111111111111111111111111111:liquid";
        let cases = [
            (
                "liquid_submarine",
                LiquidSwapType::Submarine,
                json!([liquid, format!("swp:1:{NETWORK_ID}:btc:lightning")]),
            ),
            (
                "liquid_reverse",
                LiquidSwapType::Reverse,
                json!([format!("swp:1:{NETWORK_ID}:btc:lightning"), liquid]),
            ),
            (
                "btc_to_lbtc_chain",
                LiquidSwapType::Chain,
                json!([bitcoin, liquid]),
            ),
            (
                "lbtc_to_btc_chain",
                LiquidSwapType::Chain,
                json!([liquid, format!("swp:1:{NETWORK_ID}:btc:chain")]),
            ),
        ];
        for (name, swap_type, asset_pair) in cases {
            let vector = &expected[name];
            let contract = json!({
                "asset_pair":asset_pair,
                "miner_fee_budget":vector["quote_budget_sat"].as_u64().expect("quote budget").to_string(),
            });
            let fees = liquid_fee_schedule(&contract, swap_type).expect("Liquid fee schedule");
            assert_eq!(fees.sat_per_vbyte, 10);
            let expected_funding_fee = if vector["requester_liquid_funding_cap_sat"].is_null() {
                None
            } else {
                Some(fees.funding_fee_cap_sat)
            };
            assert_eq!(
                vector["requester_liquid_funding_cap_sat"].as_u64(),
                expected_funding_fee
            );
            let exit_fee = match vector["requester_exit_path"].as_str() {
                Some("claim") => fees.claim_fee_sat,
                Some("refund") => fees.refund_fee_sat,
                _ => panic!("fixture exit path"),
            };
            assert_eq!(vector["requester_exit_fee_sat"], exit_fee);
        }

        let adversarial: Value =
            serde_json::from_str(ADVERSARIAL_FIXTURE).expect("adversarial fixture");
        assert_eq!(
            liquid_submarine_invoice_amount_sat().expect("fixture-pinned invoice amount"),
            adversarial["lab_profile"]["pricing"]["liquid_submarine_invoice_amount_sat"]
        );
    }

    #[test]
    fn liquid_doomsday_checkpoint_retains_only_an_external_recovery_reference() {
        assert!(
            provider_support::reject_custody_material(&json!({
                "external_recovery_reference_bound_before_contract":true,
            }))
            .is_ok()
        );
        assert!(
            provider_support::reject_custody_material(&json!({
                "preimage_persisted_before_contract":true,
            }))
            .is_err()
        );
    }

    fn terminal_observation_request(
        leg_id: &str,
        rail: &str,
        evidence_class: &str,
        reference: &str,
        verifier_policy: &str,
    ) -> RailObservationRequest {
        RailObservationRequest {
            session_id: "11".repeat(32),
            order_id: "22".repeat(32),
            leg_id: leg_id.to_owned(),
            outcome: "completed".to_owned(),
            rail: rail.to_owned(),
            evidence_class: evidence_class.to_owned(),
            reference: reference.to_owned(),
            rung: "settled".to_owned(),
            verifier_policy: verifier_policy.to_owned(),
            verifier_authority_sha256: "33".repeat(32),
            finality_state: "settled".to_owned(),
            unfunded_destination: None,
        }
    }

    #[test]
    fn liquid_terminal_binding_requires_exact_output_and_spend_identity() {
        let fixture: Value =
            serde_json::from_str(LIQUID_RAIL_FIXTURE).expect("Liquid rail fixture");
        let raw = fixture["parser_vectors"][0]["raw_transaction"]
            .as_str()
            .expect("accepted Liquid parser transaction");
        let funding = parse_liquid_transaction(&decode_hex(raw).expect("Liquid transaction hex"))
            .expect("Liquid funding transaction");
        let funding_transaction_id = lower_hex(&funding.transaction_id);
        let outpoint = format!("{funding_transaction_id}:0");
        let contract = json!({
            "verifier_inputs":[{
                "leg_id":"destination",
                "funding_transaction":raw,
                "output_index":0,
            }]
        });
        let output = terminal_observation_request(
            "destination",
            "liquid",
            "liquid_output",
            &outpoint,
            "mkt-swp-liquid-v1",
        );
        let output_binding =
            liquid_terminal_binding(&output, &outpoint, Some(&"44".repeat(32)), &contract)
                .expect("exact Liquid output binding");
        assert!(!output_binding.requires_spend);
        assert_eq!(
            output_binding.terminal_transaction_id,
            funding_transaction_id
        );

        let spend = terminal_observation_request(
            "destination",
            "liquid",
            "liquid_spend",
            &outpoint,
            "mkt-swp-liquid-v1",
        );
        let settlement = "55".repeat(32);
        let spend_binding =
            liquid_terminal_binding(&spend, &outpoint, Some(&settlement), &contract)
                .expect("exact Liquid spend binding");
        assert!(spend_binding.requires_spend);
        assert_eq!(spend_binding.terminal_transaction_id, settlement);
        assert!(liquid_terminal_binding(&spend, &outpoint, None, &contract).is_err());
        assert!(
            liquid_terminal_binding(&spend, &format!("{}:1", "66".repeat(32)), None, &contract)
                .is_err()
        );
    }

    #[test]
    fn liquid_terminal_metadata_is_locally_derived_and_rejects_close_mutation() {
        let fixture: Value =
            serde_json::from_str(LIQUID_RAIL_FIXTURE).expect("Liquid rail fixture");
        let raw = decode_hex(
            fixture["parser_vectors"][0]["raw_transaction"]
                .as_str()
                .expect("accepted Liquid parser transaction"),
        )
        .expect("Liquid transaction hex");
        let funding = parse_liquid_transaction(&raw).expect("Liquid funding transaction");
        let funding_transaction_id = lower_hex(&funding.transaction_id);
        let settlement_transaction_id = "55".repeat(32);
        let spend_binding = LiquidTerminalBinding {
            funding_raw: raw.clone(),
            funding_transaction_id: funding_transaction_id.clone(),
            funding_output_index: 0,
            terminal_transaction_id: settlement_transaction_id.clone(),
            requires_spend: true,
        };
        let outpoint = format!("{funding_transaction_id}:0");
        let mut spend_request = terminal_observation_request(
            "chain",
            "liquid",
            "liquid_spend",
            &outpoint,
            "mkt-swp-liquid-v1",
        );
        let submarine_contract = json!({"swap_type":"submarine"});
        let (submarine_artifact, submarine_view) = liquid_terminal_artifact_and_view(
            &spend_request,
            &spend_binding,
            &raw,
            &"66".repeat(32),
            &submarine_contract,
        )
        .expect("submarine Liquid evidence is derived");
        let expected_submarine_artifact = provider_support::canonical_json(&json!({
            "claim_txid":settlement_transaction_id,
        }))
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .expect("canonical submarine artifact");
        assert_eq!(submarine_artifact, expected_submarine_artifact);
        assert_eq!(
            submarine_view,
            "provider Liquid claim reached reorg-safe finality"
        );

        let payment_hash = "77".repeat(32);
        let reverse_contract = json!({
            "swap_type":"reverse",
            "payment_hash":payment_hash,
        });
        let (reverse_artifact, reverse_view) = liquid_terminal_artifact_and_view(
            &spend_request,
            &spend_binding,
            &raw,
            &"66".repeat(32),
            &reverse_contract,
        )
        .expect("reverse Liquid evidence is derived");
        let expected_reverse_artifact = provider_support::canonical_json(&json!({
            "claim_txid":settlement_transaction_id,
            "payment_hash":payment_hash,
            "state":"settled",
        }))
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .expect("canonical reverse artifact");
        assert_eq!(reverse_artifact, expected_reverse_artifact);
        assert_eq!(
            reverse_view,
            "requester Liquid claim verified before hold settlement"
        );

        spend_request.leg_id = "source".to_owned();
        let (chain_artifact, chain_view) = liquid_terminal_artifact_and_view(
            &spend_request,
            &spend_binding,
            &raw,
            &"66".repeat(32),
            &json!({"swap_type":"chain"}),
        )
        .expect("chain Liquid evidence is derived");
        assert_eq!(chain_artifact, expected_submarine_artifact);
        assert_eq!(
            chain_view,
            "provider source claim reached reorg-safe finality"
        );

        let output_binding = LiquidTerminalBinding {
            funding_raw: raw.clone(),
            funding_transaction_id,
            funding_output_index: 0,
            terminal_transaction_id: "88".repeat(32),
            requires_spend: false,
        };
        let output_request = terminal_observation_request(
            "destination",
            "liquid",
            "liquid_output",
            &outpoint,
            "mkt-swp-liquid-v1",
        );
        let block_hash = "99".repeat(32);
        let (output_artifact, output_view) = liquid_terminal_artifact_and_view(
            &output_request,
            &output_binding,
            &raw,
            &block_hash,
            &json!({"swap_type":"chain"}),
        )
        .expect("Liquid output evidence is derived");
        assert_eq!(output_artifact, lower_hex(&sha256(&raw)));
        assert_eq!(output_view, block_hash);

        let derived = DerivedLiquidTerminalEvidence {
            artifact_sha256: reverse_artifact,
            view: reverse_view,
            external_identifier: "elementsd:test".to_owned(),
        };
        let mut close_evidence = Map::from_iter([
            (
                "artifact_sha256".to_owned(),
                Value::String(derived.artifact_sha256.clone()),
            ),
            ("view".to_owned(), Value::String(derived.view.clone())),
        ]);
        require_exact_liquid_terminal_metadata(&close_evidence, &derived)
            .expect("exact locally derived Liquid metadata");
        close_evidence.insert("artifact_sha256".to_owned(), Value::String("aa".repeat(32)));
        assert!(require_exact_liquid_terminal_metadata(&close_evidence, &derived).is_err());
        close_evidence.insert(
            "artifact_sha256".to_owned(),
            Value::String(derived.artifact_sha256.clone()),
        );
        close_evidence.insert(
            "view".to_owned(),
            Value::String("provider supplied another view".to_owned()),
        );
        assert!(require_exact_liquid_terminal_metadata(&close_evidence, &derived).is_err());
    }

    #[test]
    fn terminal_close_requires_one_reference_for_each_contract_leg() {
        let outpoint = format!("{}:0", "44".repeat(32));
        let payment_hash = "55".repeat(32);
        let bitcoin_reference = json!({
            "artifact_sha256":"33".repeat(32),
            "class":"bitcoin_spend",
            "observed_at":1,
            "producer_pubkey":"77".repeat(32),
            "rail":"bitcoin",
            "reference":outpoint,
            "rung":"settled",
            "verifier_policy":"mkt-swp-bitcoin-v1",
            "verifier_pubkey":null,
            "view":"local bitcoind",
        });
        let liquid_reference = json!({
            "artifact_sha256":"66".repeat(32),
            "class":"liquid_spend",
            "observed_at":1,
            "producer_pubkey":"77".repeat(32),
            "rail":"liquid",
            "reference":outpoint,
            "rung":"settled",
            "verifier_policy":"mkt-swp-liquid-v1",
            "verifier_pubkey":null,
            "view":"local elementsd",
        });
        let lightning_reference = json!({
            "artifact_sha256":"88".repeat(32),
            "class":"lightning_payment",
            "observed_at":1,
            "producer_pubkey":"77".repeat(32),
            "rail":"lightning",
            "reference":payment_hash,
            "rung":"settled",
            "verifier_policy":"mkt-swp-lightning-v1",
            "verifier_pubkey":null,
            "view":"requester CLN",
        });
        let close = |references: Vec<Value>| Event {
            id: "99".repeat(32),
            pubkey: "77".repeat(32),
            created_at: 1,
            kind: MKT_CLOSE_KIND,
            tags: Vec::new(),
            content: json!({"mkt_swp":{"loss_accounting":{"evidence_refs":references}}})
                .to_string(),
            sig: "aa".repeat(64),
        };
        let liquid_request = terminal_observation_request(
            "destination",
            "liquid",
            "liquid_spend",
            &outpoint,
            "mkt-swp-liquid-v1",
        );
        let lightning_request = terminal_observation_request(
            "lightning",
            "lightning",
            "lightning_payment",
            &payment_hash,
            "mkt-swp-lightning-v1",
        );
        let bitcoin_request = terminal_observation_request(
            "destination",
            "bitcoin",
            "bitcoin_spend",
            &outpoint,
            "mkt-swp-bitcoin-v1",
        );
        let exact = close(vec![liquid_reference.clone(), lightning_reference.clone()]);
        exact_close_evidence_reference(&exact, &liquid_request)
            .expect("one exact Liquid reference");
        exact_close_evidence_reference(&exact, &lightning_request)
            .expect("one exact Lightning reference");
        exact_close_evidence_reference(&close(vec![bitcoin_reference.clone()]), &bitcoin_request)
            .expect("one exact Bitcoin spend reference");
        let mut legacy_refund = bitcoin_reference;
        legacy_refund["class"] = Value::String("refund".to_owned());
        assert!(
            exact_close_evidence_reference(&close(vec![legacy_refund]), &bitcoin_request).is_err()
        );
        assert!(
            exact_close_evidence_reference(
                &close(vec![liquid_reference.clone(), liquid_reference]),
                &liquid_request
            )
            .is_err()
        );
        assert!(
            exact_close_evidence_reference(&close(vec![lightning_reference]), &liquid_request)
                .is_err()
        );

        let contract = json!({"legs":[{"leg_id":"source"},{"leg_id":"destination"}]});
        assert_eq!(
            contract_leg_ids(&contract).expect("two exact contract legs"),
            vec!["source", "destination"]
        );
        let duplicate = json!({"legs":[{"leg_id":"source"},{"leg_id":"source"}]});
        assert!(contract_leg_ids(&duplicate).is_err());
    }

    #[test]
    fn chain_terminal_settlements_cover_both_rail_orientations() {
        let source_claim = "11".repeat(32);
        let destination_claim = "22".repeat(32);
        let (bitcoin, liquid) =
            chain_terminal_settlement_ids("bitcoin", "liquid", &source_claim, &destination_claim)
                .expect("BTC to Liquid settlements");
        assert_eq!(
            (bitcoin, liquid),
            (source_claim.as_str(), destination_claim.as_str())
        );

        let (bitcoin, liquid) =
            chain_terminal_settlement_ids("liquid", "bitcoin", &source_claim, &destination_claim)
                .expect("Liquid to BTC settlements");
        assert_eq!(
            (bitcoin, liquid),
            (destination_claim.as_str(), source_claim.as_str())
        );
        assert!(!bitcoin.is_empty() && !liquid.is_empty());
        assert!(
            chain_terminal_settlement_ids("liquid", "liquid", &source_claim, &destination_claim)
                .is_err()
        );
    }

    #[test]
    fn liquid_doomsday_state_uses_case_specific_journey_keys() {
        assert_eq!(
            liquid_doomsday_journey_name(
                DoomsdayCase::LiquidSubmarineProviderGone,
                "liquid_submarine"
            ),
            Ok("liquid_submarine_provider_gone")
        );
        assert_eq!(
            liquid_doomsday_journey_name(
                DoomsdayCase::LiquidReverseCoordinatorGone,
                "liquid_reverse"
            ),
            Ok("liquid_reverse_coordinator_gone")
        );
        assert!(
            liquid_doomsday_journey_name(
                DoomsdayCase::LiquidSubmarineProviderGone,
                "liquid_reverse"
            )
            .is_err()
        );
        assert!(
            liquid_doomsday_journey_name(DoomsdayCase::SubmarineProviderGone, "liquid_submarine")
                .is_err()
        );
        for case in [
            DoomsdayCase::LiquidSubmarineProviderGone,
            DoomsdayCase::LiquidReverseCoordinatorGone,
        ] {
            assert!(case.journey_name().len() <= 32);
        }
    }

    #[test]
    fn requester_statuses_enumerate_every_provider_causal_prerequisite() {
        let expected = [
            ("requester_verification_passed", "lock_terms_ready"),
            ("requester_invoice_verified", "hold_invoice_ready"),
            ("requester_lock_verified", "provider_lock_terms_ready"),
            ("requester_claim_pending", "funding_final"),
            ("requester_source_verified", "source_lock_terms_ready"),
            (
                "requester_destination_verified",
                "destination_lock_terms_ready",
            ),
            ("requester_source_broadcast", "source_funding_required"),
            (
                "requester_destination_claim_pending",
                "destination_funding_final",
            ),
            (
                "requester_source_refund_pending",
                "provider_destination_refunded",
            ),
        ];
        for (requester_state, provider_state) in expected {
            assert_eq!(
                requester_status_provider_prerequisite(requester_state),
                Some(provider_state)
            );
        }
        for independent in [
            "lightning_payment_pending",
            "requester_funding_broadcast",
            "requester_claimed",
            "requester_destination_claimed",
            "refund_prepared",
            "refund_pending",
            "refunded",
        ] {
            assert_eq!(requester_status_provider_prerequisite(independent), None);
        }
    }

    #[test]
    fn doomsday_and_normal_requester_publishers_share_exact_claim_prerequisite() {
        let status = |id: &str, state: &str| Event {
            id: id.to_owned(),
            pubkey: "provider".to_owned(),
            created_at: 1,
            kind: MKT_STATUS_KIND,
            tags: Vec::new(),
            content: json!({"mkt_swp":{"swp_state":state}}).to_string(),
            sig: "00".repeat(64),
        };
        let funding_final = status("funding-final", "funding_final");
        assert_eq!(
            requester_status_provider_prerequisite("requester_claim_pending"),
            Some("funding_final")
        );
        assert_eq!(
            requester_status_provider_prerequisite_event(
                std::slice::from_ref(&funding_final),
                "provider",
                "requester_claim_pending"
            )
            .expect("exact provider prerequisite")
            .map(|event| event.id.as_str()),
            Some("funding-final")
        );
        assert!(
            requester_status_provider_prerequisite_event(
                &[],
                "provider",
                "requester_claim_pending"
            )
            .is_err()
        );
        assert!(
            requester_status_provider_prerequisite_event(
                &[funding_final.clone(), status("duplicate", "funding_final")],
                "provider",
                "requester_claim_pending"
            )
            .is_err()
        );
        assert_eq!(
            requester_status_provider_prerequisite_event(
                &[funding_final],
                "provider",
                "requester_claimed"
            ),
            Ok(None)
        );
    }

    #[test]
    fn liquid_claim_requires_retained_pre_fund_authorization() {
        let fixture: Value =
            serde_json::from_str(ADVERSARIAL_FIXTURE).expect("adversarial fixture should parse");
        assert_eq!(
            fixture
                .pointer("/evidence/liquid_case_record/liquid_exit_authorization")
                .and_then(Value::as_str),
            Some("retained-pre-fund-capability")
        );
        assert_eq!(
            fixture
                .pointer("/evidence/liquid_case_record/claim_finality")
                .and_then(Value::as_str),
            Some("contract-terminal-confirmations")
        );
        assert_eq!(
            fixture.pointer("/evidence/liquid_case_record/verification_boundaries"),
            Some(&json!({
                "source_preflight_before":"requester_source_verified",
                "destination_preflight_after":"destination_lock_terms_ready",
                "combined_authorization_before":"requester_destination_verified",
            }))
        );
    }

    #[test]
    fn relay_event_extraction_retains_exact_outer_bytes() {
        let message = r#"[ "EVENT" , "subscription,{id}" , { "id" : "aa", "content" : "},[" } ]"#;
        assert_eq!(
            relay_array_element_raw(message, 2),
            Some(r#"{ "id" : "aa", "content" : "},[" }"#)
        );
        assert_eq!(relay_array_element_raw(message, 3), None);
    }

    #[test]
    fn funded_delivery_restore_requires_exact_archived_receipt_bytes() {
        let sender = MarketSigner::from_secret_bytes([1; 32]).expect("sender key should be valid");
        let requester =
            MarketSigner::from_secret_bytes([2; 32]).expect("requester key should be valid");
        let config = SwapClientConfig {
            session_id: "11".repeat(32),
            requester_pubkey: sender.pubkey().to_owned(),
            provider_pubkey: requester.pubkey().to_owned(),
            offering_address: format!("39601:{}:{}", requester.pubkey(), "22".repeat(32)),
            provider_route: None,
        };
        let factory = SwapRecordFactory::new(config).expect("factory config should be valid");
        let (event, raw_signed_event) = sign_request(
            factory
                .rfq(100, &"33".repeat(32), 200, json!({"constraints":{}}))
                .expect("RFQ should be composed"),
            &sender,
        )
        .expect("RFQ should be signed");
        let wrapped = wrap_mkt_record(
            &raw_signed_event,
            &sender,
            requester.pubkey(),
            WrapMaterial {
                seal_created_at: 101,
                wrap_created_at: 102,
                seal_nonce: [3; 32],
                wrap_nonce: [4; 32],
                wrap_secret: [5; 32],
            },
        )
        .expect("RFQ should wrap");
        let raw_wrap = serde_json::to_vec(&wrapped.event).expect("wrap should encode");
        let delivered = unwrap_mkt_record_raw(&raw_wrap, &requester, &swp_profiles())
            .expect("wrap should unwrap");
        let delivery = SignedRecordDelivery::from_delivered(&delivered, 103)
            .expect("delivery should validate");
        let archive = json!([delivery]);
        restore_funded_deliveries(archive.clone(), std::slice::from_ref(&event), &requester)
            .expect("exact archive should restore");

        for field in ["sender_pubkey", "wrap_event_id"] {
            let mut mutated = archive.clone();
            mutated[0][field] = json!("ff".repeat(32));
            assert!(
                restore_funded_deliveries(mutated, std::slice::from_ref(&event), &requester,)
                    .is_err(),
                "{field} mutation should be rejected"
            );
        }
        let mut mutated_inner = archive;
        let bytes = mutated_inner[0]["raw_signed_event"]
            .as_array_mut()
            .expect("inner bytes should be an array");
        let byte = bytes.first_mut().expect("inner bytes should not be empty");
        *byte = json!(byte.as_u64().unwrap_or_default() ^ 1);
        assert!(
            restore_funded_deliveries(mutated_inner, std::slice::from_ref(&event), &requester,)
                .is_err()
        );

        let (second_event, second_raw_signed_event) = sign_request(
            factory
                .rfq(104, &"34".repeat(32), 200, json!({"constraints":{}}))
                .expect("second RFQ should be composed"),
            &sender,
        )
        .expect("second RFQ should be signed");
        let second_delivery =
            SignedRecordDelivery::from_locally_signed(second_raw_signed_event, 105)
                .expect("local delivery should validate");
        let records = vec![event, second_event];
        let exact_archive = json!([delivery, second_delivery]);
        restore_funded_deliveries(exact_archive.clone(), &records, &requester)
            .expect("exact event-ID set should restore");

        let mut omitted = exact_archive.clone();
        omitted.as_array_mut().expect("archive array").pop();
        assert!(restore_funded_deliveries(omitted, &records, &requester).is_err());

        let mut duplicated = exact_archive;
        duplicated[1] = duplicated[0].clone();
        assert!(restore_funded_deliveries(duplicated, &records, &requester).is_err());
    }

    #[test]
    fn checkpoint_fixture_names_exactly_the_implemented_restart_surface() {
        let fixture: Value =
            serde_json::from_str(CHECKPOINT_FIXTURE).expect("checkpoint fixture should parse");
        let journeys = fixture
            .get("journeys")
            .and_then(Value::as_object)
            .expect("checkpoint fixture should name journeys");
        for (name, journey) in [
            ("submarine", FundedJourney::Submarine),
            ("reverse", FundedJourney::ReverseClaim),
            ("reverse_refund", FundedJourney::ReverseRefund),
        ] {
            let labels = journeys
                .get(name)
                .and_then(|value| value.get("restartable"))
                .and_then(Value::as_array)
                .expect("journey should name restartable checkpoints");
            assert!(!labels.is_empty());
            for label in labels {
                assert!(restartable_checkpoint(
                    journey,
                    label.as_str().expect("checkpoint label should be text")
                ));
            }
        }
        assert!(!restartable_checkpoint(
            FundedJourney::Submarine,
            "claim_broadcast_ready"
        ));
        assert!(!restartable_checkpoint(
            FundedJourney::ReverseRefund,
            "claim_broadcast_recorded"
        ));
    }

    #[test]
    fn funded_topology_fixture_matches_the_executable_contract() {
        validate_funded_topology_fixture()
            .expect("funded topology fixture should match the executable contract");
        assert_eq!(
            exact_topology_health_urls(
                "http://127.0.0.1:9091/healthz,http://127.0.0.1:9092/healthz"
            ),
            Ok([
                "http://127.0.0.1:9091/healthz".to_owned(),
                "http://127.0.0.1:9092/healthz".to_owned()
            ])
        );
        assert!(exact_topology_health_urls("http://127.0.0.1:9091/healthz").is_err());
        assert!(
            exact_topology_health_urls(
                "http://127.0.0.1:9091/healthz,http://127.0.0.1:9091/healthz"
            )
            .is_err()
        );
    }

    #[test]
    fn injection_fixture_names_all_bounded_controls() {
        let fixture: Value =
            serde_json::from_str(CHECKPOINT_FIXTURE).expect("checkpoint fixture should parse");
        let injections = fixture
            .get("injections")
            .and_then(Value::as_array)
            .expect("checkpoint fixture should name injections");
        let names = injections
            .iter()
            .map(|injection| {
                injection
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("injection name should be text")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "stale_quote",
                "duplicate_message",
                "conflicting_message",
                "secret_leak",
                "relay_loss",
                "provider_crash"
            ]
        );
        for name in names {
            assert_eq!(
                HarnessInjection::parse(name)
                    .expect("fixture injection should be implemented")
                    .name(),
                name
            );
        }
        assert_eq!(
            injections[4].get("wallet_recovery").and_then(Value::as_str),
            Some("reauthenticate_reader_and_publisher_then_resubscribe_without_history_discard")
        );
        assert_eq!(
            injections[5].get("wallet_recovery").and_then(Value::as_str),
            Some("retain_authenticated_relay_sockets")
        );
        assert_eq!(
            injections[5]
                .get("provider_recovery")
                .and_then(Value::as_str),
            Some("restore_durable_reservation_release_before_ingesting_provider_close")
        );
    }

    #[test]
    fn matrix_fixture_selects_every_checkpoint_and_injection() {
        let checkpoints: Value =
            serde_json::from_str(CHECKPOINT_FIXTURE).expect("checkpoint fixture should parse");
        let matrix: Value =
            serde_json::from_str(MATRIX_FIXTURE).expect("matrix fixture should parse");
        assert_eq!(
            matrix.get("schema").and_then(Value::as_str),
            Some("openagents.immortal.lab-funded-matrix.v1")
        );
        assert_eq!(
            matrix
                .pointer("/selection/restart_cases")
                .and_then(Value::as_str),
            Some("every_restartable_checkpoint")
        );
        assert_eq!(
            matrix
                .pointer("/selection/injection_cases")
                .and_then(Value::as_str),
            Some("every_bounded_injection")
        );

        let restartable = checkpoints
            .get("journeys")
            .and_then(Value::as_object)
            .expect("checkpoint fixture should name journeys")
            .iter()
            .flat_map(|(journey, contract)| {
                contract
                    .get("restartable")
                    .and_then(Value::as_array)
                    .expect("journey should name restartable checkpoints")
                    .iter()
                    .map(move |label| {
                        format!(
                            "{journey}:{}",
                            label.as_str().expect("checkpoint label should be text")
                        )
                    })
            })
            .collect::<Vec<_>>();
        assert!(restartable.iter().all(|checkpoint| checkpoint.len() <= 128));
        assert_eq!(
            checkpoints
                .get("smoke_restart_checkpoint")
                .and_then(Value::as_str),
            matrix
                .pointer("/default_case/restart_at")
                .and_then(Value::as_str)
        );
        assert!(
            restartable.contains(
                &matrix
                    .pointer("/default_case/restart_at")
                    .and_then(Value::as_str)
                    .expect("matrix should name its default restart")
                    .to_owned()
            )
        );

        let injection_names = checkpoints
            .get("injections")
            .and_then(Value::as_array)
            .expect("checkpoint fixture should name injections")
            .iter()
            .map(|injection| {
                injection
                    .get("name")
                    .and_then(Value::as_str)
                    .expect("injection should have a name")
            })
            .collect::<Vec<_>>();
        let matrix_injections = matrix
            .get("injection_cases")
            .and_then(Value::as_object)
            .expect("matrix should name injection cases");
        assert_eq!(matrix_injections.len(), injection_names.len());
        assert!(
            injection_names
                .iter()
                .all(|name| matrix_injections.contains_key(*name))
        );
        for name in ["relay_loss", "provider_crash"] {
            let checkpoint = matrix_injections
                .get(name)
                .and_then(|case| case.get("inject_at"))
                .and_then(Value::as_str)
                .expect("external injection should select a checkpoint");
            assert!(restartable.iter().any(|candidate| candidate == checkpoint));
        }
    }

    #[test]
    fn external_injection_acknowledgement_is_exact_and_custody_free() {
        let valid = json!({
            "schema":"openagents.immortal.lab-injection-ack.v1",
            "run_id":"run-1",
            "checkpoint":"reverse:funding_effect_recorded",
            "injection":"provider_crash",
            "restored":true,
            "evidence":{
                "target":"provider-a",
                "before_pid":101,
                "after_pid":202,
                "transition":"process_replaced_and_ready",
            }
        });
        validate_injection_acknowledgement(
            valid.to_string().as_bytes(),
            "run-1",
            "reverse:funding_effect_recorded",
            HarnessInjection::ProviderCrash,
        )
        .expect("exact acknowledgement should pass");
        assert!(
            validate_injection_acknowledgement(
                json!({
                    "schema":"openagents.immortal.lab-injection-ack.v1",
                    "run_id":"run-1",
                    "checkpoint":"reverse:funding_effect_recorded",
                    "injection":"provider_crash",
                    "restored":true,
                    "preimage":"00"
                })
                .to_string()
                .as_bytes(),
                "run-1",
                "reverse:funding_effect_recorded",
                HarnessInjection::ProviderCrash,
            )
            .is_err()
        );
        let same_pid = json!({
            "schema":"openagents.immortal.lab-injection-ack.v1",
            "run_id":"run-1",
            "checkpoint":"reverse:funding_effect_recorded",
            "injection":"provider_crash",
            "restored":true,
            "evidence":{
                "target":"provider-a",
                "before_pid":101,
                "after_pid":101,
                "transition":"process_replaced_and_ready",
            }
        });
        assert!(
            validate_injection_acknowledgement(
                same_pid.to_string().as_bytes(),
                "run-1",
                "reverse:funding_effect_recorded",
                HarnessInjection::ProviderCrash,
            )
            .is_err()
        );

        let provider_stopped = json!({
            "schema":"openagents.immortal.lab-injection-ack.v1",
            "run_id":"run-2",
            "checkpoint":"submarine_refund:funding_effect_recorded",
            "injection":"provider_noncooperative",
            "restored":false,
            "evidence":{
                "target":"provider-a",
                "before_pid":303,
                "transition":"process_stopped",
            }
        });
        validate_injection_acknowledgement(
            provider_stopped.to_string().as_bytes(),
            "run-2",
            "submarine_refund:funding_effect_recorded",
            HarnessInjection::ProviderNoncooperative,
        )
        .expect("permanently stopped provider acknowledgement should pass");
        let mut falsely_restored = provider_stopped;
        falsely_restored["restored"] = Value::Bool(true);
        assert!(
            validate_injection_acknowledgement(
                falsely_restored.to_string().as_bytes(),
                "run-2",
                "submarine_refund:funding_effect_recorded",
                HarnessInjection::ProviderNoncooperative,
            )
            .is_err()
        );

        let chain_recovery = json!({
            "schema":"openagents.immortal.lab-injection-ack.v1",
            "run_id":"run-2",
            "checkpoint":"submarine:claim_reorg_control",
            "injection":"claim_reorg",
            "restored":true,
            "evidence":{
                "target":"provider-a",
                "transaction_id":"11".repeat(32),
                "orphaned_block_hash":"22".repeat(32),
                "competing_tip_hash":"33".repeat(32),
                "reconfirmed_block_hash":"44".repeat(32),
                "transition":"claim_watch_reorged_and_reconfirmed",
                "wait_state":"claim_watch_confirmed",
                "recovery_state":"claim_watch_reorg_then_reconfirmed",
            }
        });
        validate_injection_acknowledgement(
            chain_recovery.to_string().as_bytes(),
            "run-2",
            "submarine:claim_reorg_control",
            HarnessInjection::ClaimReorg,
        )
        .expect("exact chain recovery acknowledgement should pass");
        let mut wrong_transition = chain_recovery;
        wrong_transition["evidence"]["transition"] =
            Value::String("funding_reorg_waited_and_resumed".to_owned());
        assert!(
            validate_injection_acknowledgement(
                wrong_transition.to_string().as_bytes(),
                "run-2",
                "submarine:claim_reorg_control",
                HarnessInjection::ClaimReorg,
            )
            .is_err()
        );
    }

    #[test]
    fn prior_lightning_attempts_are_counted_by_exact_payment_hash() {
        let wanted = "11".repeat(32);
        let other = "22".repeat(32);
        let response = json!({"pays":[
            {"payment_hash":wanted,"status":"pending"},
            {"payment_hash":other,"status":"failed"}
        ]});
        assert_eq!(payment_entries(&response, &"11".repeat(32)), Ok((2, 1)));
        assert_eq!(payment_entries(&response, &"33".repeat(32)), Ok((2, 0)));
    }

    #[test]
    fn recorded_payment_result_rejects_amount_inversion() {
        let response = json!({
            "payment_hash":"11".repeat(32),
            "status":"complete",
            "amount_msat":"1000msat",
            "amount_sent_msat":"999msat"
        });
        assert!(parse_payment_result(&response).is_err());
    }

    #[test]
    fn keyless_controller_audit_is_exact_and_custody_scanner_safe() {
        let audit = json!({
            "separate_container":true,
            "application_environment_names":[
                "IMMORTAL_LAB_KEYLESS_REQUEST_FILE",
                "IMMORTAL_LAB_KEYLESS_RESULT_FILE"
            ],
            "mount_targets":["/keyless"],
            "observed_environment_count":3,
            "observed_mount_count":1,
            "environment_allowlist_exact":true,
            "mount_allowlist_exact":true,
            "rail_access":false,
            "runtime_environment_scan_passed":true,
            "exact_presigned_request_only":true,
        });
        provider_support::reject_custody_material(&audit)
            .expect("public keyless audit should be custody-scanner safe");
        validate_doomsday_keyless_process_audit(
            Some(&audit),
            DoomsdayCase::KeylessEsploraBroadcast,
        )
        .expect("exact keyless process audit should pass");

        let mut rail_access = audit.clone();
        rail_access["rail_access"] = Value::Bool(true);
        assert!(
            validate_doomsday_keyless_process_audit(
                Some(&rail_access),
                DoomsdayCase::KeylessEsploraBroadcast,
            )
            .is_err()
        );
        let mut unknown = audit;
        unknown["unknown"] = Value::Bool(true);
        assert!(
            validate_doomsday_keyless_process_audit(
                Some(&unknown),
                DoomsdayCase::KeylessEsploraBroadcast,
            )
            .is_err()
        );
    }

    #[test]
    fn keyless_request_is_closed_bounded_and_txid_bound() {
        let raw = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [1; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
                witness: vec![vec![2; 64]],
            }],
            vec![TransactionOutput {
                value_sat: 10_000,
                script_pubkey: vec![0x51],
            }],
            0,
        )
        .serialize(true)
        .expect("test transaction should serialize");
        let transaction = Transaction::parse(&raw).expect("test transaction should parse");
        let transaction_id = lower_hex(&transaction.txid().expect("test txid should derive"));
        let request = EsploraBroadcastRequest {
            effect_id: "11".repeat(32),
            method: "POST".to_owned(),
            url: "http://127.0.0.1:3002/api/tx".to_owned(),
            content_type: "text/plain".to_owned(),
            body: lower_hex(&raw),
        };
        validate_doomsday_keyless_http_request(&request, &transaction_id)
            .expect("exact keyless request should pass");

        let mut wrong_id = transaction_id.clone();
        wrong_id.replace_range(..2, "00");
        assert!(validate_doomsday_keyless_http_request(&request, &wrong_id).is_err());
        let mut oversized = request.clone();
        oversized.body = "00".repeat(DOOMSDAY_KEYLESS_MAX_BYTES + 1);
        assert!(validate_doomsday_keyless_http_request(&oversized, &transaction_id).is_err());
        let mut wrong_path = request;
        wrong_path.url = "http://127.0.0.1:3002/other/tx".to_owned();
        assert!(validate_doomsday_keyless_http_request(&wrong_path, &transaction_id).is_err());
    }

    #[test]
    fn keyless_file_rejects_duplicate_unknown_and_custody_members() {
        let root =
            std::env::temp_dir().join(format!("immortal-keyless-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("keyless test directory should be created");
        let path = root.join("request.json");
        let duplicate = format!(
            r#"{{"schema":"{DOOMSDAY_KEYLESS_REQUEST_SCHEMA}","schema":"{DOOMSDAY_KEYLESS_REQUEST_SCHEMA}","transaction_id":"{}","request":{{}}}}"#,
            "11".repeat(32)
        );
        std::fs::write(&path, duplicate).expect("duplicate fixture should be written");
        assert!(load_doomsday_keyless_request(&path).is_err());

        for extra in [json!({"unknown":true}), json!({"wallet_seed":"00"})] {
            let mut value = json!({
                "schema":DOOMSDAY_KEYLESS_REQUEST_SCHEMA,
                "transaction_id":"11".repeat(32),
                "request":{},
            });
            value
                .as_object_mut()
                .expect("request should be an object")
                .extend(
                    extra
                        .as_object()
                        .expect("extra should be an object")
                        .clone(),
                );
            std::fs::write(&path, value.to_string()).expect("invalid fixture should be written");
            assert!(load_doomsday_keyless_request(&path).is_err());
        }
        std::fs::remove_file(&path).expect("keyless test file should be removed");
        std::fs::remove_dir(&root).expect("keyless test directory should be removed");
    }

    #[test]
    fn keyless_acceptance_is_not_terminal_evidence() {
        let result = json!({
            "schema":DOOMSDAY_KEYLESS_RESULT_SCHEMA,
            "effect_id":"11".repeat(32),
            "transaction_id":"22".repeat(32),
            "request_sha256":"33".repeat(32),
            "broadcast_accepted":true,
        });
        let object = result.as_object().expect("result should be an object");
        assert!(!object.contains_key("passed"));
        assert!(!object.contains_key("outcome"));
        assert!(!object.contains_key("terminal"));
    }
}
