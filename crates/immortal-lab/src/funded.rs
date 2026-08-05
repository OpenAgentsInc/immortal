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

use immortal_client::mkt_swp_client::{
    AwaitingVerification, Cancellation, ChainRecoveryState, DeliveryProvenance, ExitPackage,
    ExitSigningOutcome, ExternalEffectRequest, FundingAction, FundingAuthorized,
    FundingVerificationInput, InvoiceVerificationInput, LightningProgressState,
    LightningReadinessState, LightningRecoveryState, LocalLightningProgress,
    LocalLightningReadiness, LocalRailEvidence, LocalRecoveryObservation, ParticipantRole,
    RailObservationRequest, RecoveryAction, RequesterContractLocalInputs,
    RequesterContractSigningInput, RequesterOrderInput, RequesterQuoteView, RequesterSessionView,
    RequesterVerificationState, SignedRecordDelivery, StatusState, SwapClientConfig,
    SwapRecordFactory, SwapSession, SwapType, VerifyBeforeFundInput, provider_support,
};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_STATUS_KIND,
        MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND, MktProfileSupport,
        Tag, validate_mkt_public_event,
    },
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record_raw, wrap_mkt_record},
    mkt_swp_verify::{Transaction, TransactionInput, TransactionOutput, sha256},
};
use immortal_provider::{
    bitcoind::{
        BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindError, BitcoindLimits, RpcRequestId,
    },
    cln::{ClnClient, ClnEndpoint, ClnLimits, ClnRequestId, Millisatoshi, PaymentResult},
    funding::{FundingInput, FundingRequest, SignedFundingTransaction, build_funding_transaction},
    settlement::{ClaimPreimage, SettlementBridge, SettlementTemplate},
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
};
use serde_json::{Map, Value, json};
use tokio::{runtime::Runtime, task::JoinHandle};
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message, WebSocket, client};

use crate::state::{
    BoltzAdapterApproval, BoltzAdapterBroadcast, BoltzAdapterFinalizeRequest, BoltzAdapterPrepared,
    FundedCheckpoint, FundedInjectionRequest, LabPaths, clear_boltz_adapter_controls,
    load_boltz_adapter_broadcast, load_boltz_adapter_finalize_request, load_funded_deliveries,
    load_funded_journey_checkpoint, load_funded_secret, load_funded_signed_exit,
    load_or_create_funded_run_id, load_or_create_identity, remove_funded_secret,
    store_boltz_adapter_approval, store_boltz_adapter_complete, store_boltz_adapter_prepared,
    store_funded_checkpoint, store_funded_deliveries, store_funded_injection,
    store_funded_journey_checkpoint, store_funded_secret, store_funded_signed_exit,
    store_funded_snapshot,
};

const OFFERING_ID: &str = "immortal-funded-btc-lightning";
const INPUT_AMOUNT_SAT: u64 = 100_000;
const OUTPUT_AMOUNT_SAT: u64 = 98_400;
const NETWORK_ID: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const JOURNEY_TIMEOUT: Duration = Duration::from_secs(180);
const LIGHTNING_READINESS_TIMEOUT: Duration = Duration::from_secs(60);
const FUNDED_TOPOLOGY_FIXTURE: &str =
    include_str!("../../../tests/fixtures/lab/topology-funded-v1.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundedJourney {
    Submarine,
    ReverseClaim,
    ReverseRefund,
}

impl FundedJourney {
    pub fn name(self) -> &'static str {
        match self {
            Self::Submarine => "submarine",
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
    terminal_confirmations: u64,
    control: StepControl,
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
    exit_package_seed: ExitPackage,
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
        }
    }

    const fn requires_external_control(self) -> bool {
        matches!(self, Self::RelayLoss | Self::ProviderCrash)
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
    fn load() -> Result<Self, String> {
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
        let inject_at = std::env::var("IMMORTAL_LAB_INJECT_AT").ok();
        let injection = std::env::var("IMMORTAL_LAB_INJECTION")
            .ok()
            .map(|value| HarnessInjection::parse(&value))
            .transpose()?;
        if injection.is_some_and(HarnessInjection::requires_external_control) && inject_at.is_none()
        {
            return Err("relay_loss and provider_crash require IMMORTAL_LAB_INJECT_AT".to_owned());
        }
        Ok(Self {
            paths,
            run_id,
            stop_after: std::env::var("IMMORTAL_LAB_STOP_AFTER").ok(),
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
            let deadline = Instant::now() + self.injection_timeout;
            while Instant::now() < deadline {
                if continue_path.exists() {
                    let acknowledgement = std::fs::read(&continue_path).map_err(|error| {
                        format!(
                            "could not read injection continuation {}: {error}",
                            continue_path.display()
                        )
                    })?;
                    validate_injection_acknowledgement(
                        &acknowledgement,
                        &self.run_id,
                        &qualified,
                        injection,
                    )?;
                    std::fs::remove_file(&continue_path).map_err(|error| {
                        format!(
                            "could not consume injection continuation {}: {error}",
                            continue_path.display()
                        )
                    })?;
                    return Ok(true);
                }
                thread::sleep(Duration::from_millis(200));
            }
            return Err(format!(
                "timed out waiting for injection continuation {} at {qualified}",
                continue_path.display()
            ));
        }
        Ok(false)
    }
}

fn validate_injection_acknowledgement(
    bytes: &[u8],
    run_id: &str,
    checkpoint: &str,
    injection: HarnessInjection,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > 4_096 {
        return Err("injection continuation is empty or unbounded".to_owned());
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("injection continuation is invalid JSON: {error}"))?;
    provider_support::reject_custody_material(&value)
        .map_err(|error| format!("injection continuation contains custody material: {error}"))?;
    if value.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.lab-injection-ack.v1")
        || value.get("run_id").and_then(Value::as_str) != Some(run_id)
        || value.get("checkpoint").and_then(Value::as_str) != Some(checkpoint)
        || value.get("injection").and_then(Value::as_str) != Some(injection.name())
        || value.get("restored").and_then(Value::as_bool) != Some(true)
    {
        return Err("injection continuation does not bind the requested recovery".to_owned());
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
    bitcoin_settlement_txid: &'a str,
    lightning: LightningTerminalCheck<'a>,
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
    verify_health(&environment.health_url)?;
    let provider_pubkey = discover_provider(
        &environment.relay_url,
        &environment.requester,
        JOURNEY_TIMEOUT,
    )?;
    if let Some(restored) = restore_authorized_session(&environment, journey)? {
        let result = resume_authorized_journey(&runtime, &environment, journey, restored)?;
        verify_health(&environment.health_url)?;
        return Ok(json!({
            "step": journey.name(),
            "provider_pubkey": provider_pubkey,
            "resumed": true,
            "journey": result,
        }));
    }
    let result = match journey {
        FundedJourney::Submarine => {
            let client_input = fund_client_wallet(&runtime, &environment)?;
            drive_submarine(&runtime, &environment, &provider_pubkey, client_input)?
        }
        FundedJourney::ReverseClaim => drive_reverse(
            &runtime,
            &environment,
            &provider_pubkey,
            FundedJourney::ReverseClaim.name(),
            false,
        )?,
        FundedJourney::ReverseRefund => drive_reverse(
            &runtime,
            &environment,
            &provider_pubkey,
            FundedJourney::ReverseRefund.name(),
            true,
        )?,
    };
    verify_health(&environment.health_url)?;
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
        Self::load_for(relay_url, health_url, evidence_file)
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
            Self::load_for(relay_a, health_a, evidence_file.clone())?,
            Self::load_for(relay_b, health_b, evidence_file)?,
        ])
    }

    fn load_for(
        relay_url: String,
        health_url: String,
        evidence_file: PathBuf,
    ) -> Result<Self, String> {
        let control = StepControl::load()?;
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
            terminal_confirmations,
            control,
        })
    }
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
    continue_submarine(
        runtime,
        environment,
        session,
        &funding.raw_transaction,
        Some(&funding.txid),
        &invoice.payment_hash,
    )
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
    mine_blocks(runtime, &environment.bitcoind, 1, "submarine-funding")?;
    session.wait_provider_state("funding_observed")?;
    session.wait_provider_state("funding_final")?;
    session.wait_provider_state("lightning_payment_pending")?;
    session.wait_provider_state("lightning_paid")?;
    let claim_pending = session.wait_provider_state("provider_claim_pending")?;
    let claim_txid = status_transaction_id(&claim_pending)?;
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
            bitcoin_settlement_txid: &claim_txid,
            lightning: LightningTerminalCheck::IncomingInvoice { payment_hash },
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
        },
    )?;
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
                bitcoin_settlement_txid: &refund_txid,
                lightning: LightningTerminalCheck::OutgoingPayment {
                    invoice: &invoice,
                    payment_hash: &payment_hash,
                    expected_status: "failed",
                },
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
            bitcoin_settlement_txid: &claim_txid,
            lightning: LightningTerminalCheck::OutgoingPayment {
                invoice: &invoice,
                payment_hash: &payment_hash,
                expected_status: "complete",
            },
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
    let session_id = digest(&format!(
        "funded-smoke:{}:{}",
        environment.control.run_id, input.journey_name
    ));
    let config = SwapClientConfig {
        session_id: session_id.clone(),
        requester_pubkey: environment.requester.pubkey().to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        offering_address: format!("39601:{provider_pubkey}:{OFFERING_ID}"),
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
    let (rfq, rfq_raw) = sign_request(
        factory
            .rfq(
                now,
                &digest(&format!("rfq:{session_id}")),
                now.saturating_add(600),
                funded_rfq_profile(input, now)?,
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
    )?;
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
    let exit_package_seed = bind_requester_exit_package(
        &mut contract,
        input.swap_type,
        &order.id,
        &quote.id,
        input.exit_destination_script_pubkey,
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
        exit_package_seed,
        requester_funding,
        journey_name,
        control,
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
        exit_package_seed,
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
    )?;
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
    let exit_package = finalize_requester_exit_package(
        &exit_package_seed,
        [&requester_contract.id, &provider_contract.id],
        requester_contract_sha256,
    )?;
    records.push(provider_contract);
    let verifier = SwapSession::from_signed_records(config, records, vec![exit_package])
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

impl SessionContext {
    fn apply_pre_fund_injection(&mut self) -> Result<(), String> {
        match self.control.injection {
            Some(HarnessInjection::DuplicateMessage) => {
                let duplicate = self
                    .verifier
                    .signed_records()
                    .last()
                    .cloned()
                    .ok_or_else(|| "cannot inject a duplicate into an empty session".to_owned())?;
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
                let mut conflicting = self
                    .verifier
                    .signed_records()
                    .last()
                    .cloned()
                    .ok_or_else(|| "cannot inject a conflict into an empty session".to_owned())?;
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
            Some(HarnessInjection::StaleQuote)
            | Some(HarnessInjection::RelayLoss | HarnessInjection::ProviderCrash)
            | None => Ok(()),
        }
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
        )?;
        let event = received.event;
        self.deliveries.push(received.delivery);
        self.ingest_synchronized(event.clone(), &format!("provider {expected}"))?;
        Ok(event)
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
                )?;
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
        let (event, raw_event) = sign_request(
            self.factory
                .status(
                    ParticipantRole::Requester,
                    next_created_at(&self.verifier)?,
                    &digest(&format!(
                        "requester-status:{state}:{}",
                        self.verifier.config().session_id
                    )),
                    &self.order.id,
                    StatusState {
                        sequence,
                        previous,
                        base_state: base_state(state)?,
                        swp_state: state,
                    },
                    extra,
                )
                .map_err(|error| format!("could not construct requester {state}: {error}"))?,
            &self.requester,
        )?;
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
    let references = close_evidence_references(close)?;
    let matching = references
        .iter()
        .filter_map(Value::as_object)
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
    let settlement_reference = required_string(evidence, "reference")?;
    let external_identifier = match request.rail.as_str() {
        "bitcoin" => verify_local_bitcoin_terminal(request, settlement_reference, check, contract)?,
        "lightning" => verify_local_lightning_terminal(request, settlement_reference, check)?,
        _ => return Err("terminal evidence requested an unsupported local rail".to_owned()),
    };
    let producer_pubkey = required_string(evidence, "producer_pubkey")?;
    if producer_pubkey != close.pubkey {
        return Err("provider Close evidence names another producer".to_owned());
    }
    let verifier_pubkey = match evidence.get("verifier_pubkey") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        _ => return Err("provider Close evidence has an invalid verifier key".to_owned()),
    };
    Ok(LocalRailEvidence {
        artifact_sha256: required_string(evidence, "artifact_sha256")?.to_owned(),
        observed_at: evidence
            .get("observed_at")
            .and_then(Value::as_u64)
            .ok_or_else(|| "provider Close evidence has no observation time".to_owned())?,
        view: required_string(evidence, "view")?.to_owned(),
        settlement_reference: settlement_reference.to_owned(),
        verifier_pubkey,
        producer_pubkey: producer_pubkey.to_owned(),
        external_identifier,
    })
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
    match request.evidence_class.as_str() {
        "bitcoin_spend"
            if request.reference == funding_outpoint
                && settlement_reference == funding_outpoint => {}
        "refund" if settlement_reference == check.bitcoin_settlement_txid => {}
        _ => {
            return Err(
                "provider Close Bitcoin reference differs from the locally bound settlement"
                    .to_owned(),
            );
        }
    }
    let transaction = check
        .runtime
        .block_on(check.environment.bitcoind.raw_transaction(
            &rpc_id("terminal-bitcoin-transaction")?,
            check.bitcoin_settlement_txid,
            true,
        ))
        .map_err(|error| format!("could not inspect terminal Bitcoin transaction: {error}"))?;
    let transaction = transaction
        .as_object()
        .ok_or_else(|| "terminal Bitcoin transaction response is not an object".to_owned())?;
    if transaction.get("txid").and_then(Value::as_str) != Some(check.bitcoin_settlement_txid)
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
    let funding_txid_wire = display_txid_wire(&funding_txid)?;
    if lower_hex(
        &parsed.txid().map_err(|error| {
            format!("could not derive terminal Bitcoin transaction ID: {error}")
        })?,
    ) != check.bitcoin_settlement_txid
        || !parsed.inputs.iter().any(|input| {
            input.previous_txid == funding_txid_wire && input.previous_output == funding_vout
        })
    {
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
        check.bitcoin_settlement_txid, check.environment.terminal_confirmations
    ))
}

fn verify_local_lightning_terminal(
    request: &RailObservationRequest,
    settlement_reference: &str,
    check: &TerminalRailCheck<'_>,
) -> Result<String, String> {
    let (response, collection, payment_hash, expected_status, direction) = match check.lightning {
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

fn funded_rfq_profile(input: NegotiationInput<'_>, now: u64) -> Result<Value, String> {
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
        "input_amount":INPUT_AMOUNT_SAT.to_string(),
        "invoice_sha256":input.invoice.map(|invoice| lower_hex(&sha256(invoice.as_bytes()))),
        "maximum_total_fee":"5000",
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

fn bind_requester_exit_package(
    contract: &mut Value,
    swap_type: &str,
    order_id: &str,
    quote_id: &str,
    destination_script_pubkey: &[u8],
) -> Result<ExitPackage, String> {
    let (leg_id, path, funding_role, funding_leg_id) = match swap_type {
        "submarine" => ("source", "refund", "chain_fund", "source"),
        "reverse" => ("destination", "claim", "invoice_pay", "lightning"),
        _ => return Err("funded smoke cannot bind exits for this swap type".to_owned()),
    };
    let document = requester_exit_document(
        contract,
        order_id,
        quote_id,
        leg_id,
        path,
        destination_script_pubkey,
    )?;
    let package = ExitPackage::parse(document)
        .map_err(|error| format!("dynamic requester exit package is invalid: {error}"))?;
    let package_sha256 = package
        .commitment_sha256()
        .map_err(|error| format!("could not commit requester exit package: {error}"))?;
    let root = contract
        .as_object_mut()
        .ok_or_else(|| "funded contract is not an object".to_owned())?;
    root.insert(
        "effect_bindings".to_owned(),
        json!([
            {"role":funding_role,"leg_id":funding_leg_id},
            {"role":format!("chain_{path}"),"leg_id":leg_id}
        ]),
    );
    root.insert(
        "exit_package_commitments".to_owned(),
        json!([{
            "participant_role":"requester",
            "leg_id":leg_id,
            "path":path,
            "package_mode":"wallet_sign",
            "package_sha256":package_sha256
        }]),
    );
    Ok(package)
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
        "refund" => u32::try_from(canonical_u64(required_string(
            verifier,
            "exit_lock_value",
        )?)?)
        .map_err(|_| "requester refund height exceeds u32".to_owned())?,
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
            "taproot_script":required_string(verifier,"taproot_script")?,
            "taproot_control_block":required_string(verifier,"taproot_control_block")?,
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

fn finalize_requester_exit_package(
    seed: &ExitPackage,
    contract_ids: [&String; 2],
    contract_sha256: &str,
) -> Result<ExitPackage, String> {
    let mut document = seed.document().clone();
    document["swap_contract_ids"] = json!(contract_ids);
    document["contract_sha256"] = Value::String(contract_sha256.to_owned());
    ExitPackage::parse(document)
        .map_err(|error| format!("bound requester exit package is invalid: {error}"))
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
    })
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

fn discover_provider(
    relay_url: &str,
    requester: &MarketSigner,
    timeout: Duration,
) -> Result<String, String> {
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
                return Ok(event.pubkey);
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
        | "requester_lock_verified" => Ok("awaiting_input"),
        "requester_funding_broadcast" => Ok("funding_observed"),
        "lightning_payment_pending" | "requester_claim_pending" | "requester_claimed" => {
            Ok("executing")
        }
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
            "restored":true
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
}
