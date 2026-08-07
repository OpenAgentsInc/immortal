//! Capability-scoped public-regtest boundary.
//!
//! The gateway owns no wallet or rail credential. It persists only bounded,
//! public-safe session metadata, capability digests, admitted redacted effect
//! requests, and public-safe receipts. The funded lab worker remains the only
//! process that can compare an admission with the complete requester-engine
//! authorization and touch a rail.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use immortal_core::domain::{Event, RelaySigner, Tag, parse_json_without_duplicate_members};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CONTRACT: &str = include_str!("../../../tests/fixtures/lab/public-regtest-gateway-v1.json");
const SERVICE_CONTRACT: &str =
    include_str!("../../../tests/fixtures/lab/public-regtest-service-v1.json");
const CONTRACT_SCHEMA: &str = "openagents.immortal.public-regtest-gateway-contract.v1";
const CREATE_SCHEMA: &str = "openagents.immortal.public-regtest-session-create.v1";
const SESSION_SCHEMA: &str = "openagents.immortal.public-regtest-session.v1";
const MANIFEST_SCHEMA: &str = "openagents.immortal.public-regtest-session-manifest.v1";
const RESPONSE_SCHEMA: &str = "openagents.immortal.public-regtest-session-response.v1";
const AUTHORIZATION_SCHEMA: &str = "openagents.immortal.public-regtest-authorization.v1";
const EFFECT_SCHEMA: &str = "openagents.immortal.public-regtest-effect.v1";
const RECEIPT_SCHEMA: &str = "openagents.immortal.public-regtest-effect-receipt.v1";
const DYNAMIC_SUBMISSION_SCHEMA: &str = "openagents.immortal.public-regtest-dynamic-submission.v1";
const DEMO_INPUT_REQUEST_SCHEMA: &str = "openagents.immortal.public-regtest-demo-input-request.v1";
const DEMO_INPUT_RESPONSE_SCHEMA: &str = "openagents.immortal.public-regtest-demo-input.v1";
const DYNAMIC_VIEW_SCHEMA: &str = "openagents.immortal.dynamic-public-regtest-request.v1";
const JOURNEY_SCHEMA: &str = "openagents.immortal.public-regtest-journey.v1";
const ERROR_SCHEMA: &str = "openagents.immortal.public-regtest-error.v1";
const REGTEST_NETWORK: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
const MANIFEST_EVENT_KIND: u16 = 27_236;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_STATE_BYTES: usize = 64 * 1024;
const MAX_EFFECTS_PER_SESSION: u16 = 2;
const MAX_CONCURRENT_EFFECTS_PER_SESSION: u16 = 1;
const MAX_REQUESTS_PER_SESSION: u16 = 64;
const MAX_SESSIONS_PER_IP_WINDOW: u16 = 8;
const MAX_EFFECTS_PER_WINDOW: u16 = 32;
const MAX_ACTIVE_SESSIONS: usize = 16;
const MAX_CONNECTIONS: usize = 32;
const MAX_RETAINED_SESSION_DIRS: usize = 1_024;
const MAX_OUTSTANDING_SAT: u64 = 5_000_000;
const READINESS_MAXIMUM_AGE_SECONDS: u64 = 30;
const RATE_WINDOW_SECONDS: u64 = 60;
const MAX_AMOUNT_SAT: u64 = 1_000_000;
const LOCK_ATTEMPTS: usize = 200;
const SERVICE_CONTRACT_SCHEMA: &str = "openagents.immortal.public-regtest-service-contract.v1";
const SERVICE_READINESS_SCHEMA: &str = "openagents.immortal.public-regtest-service-readiness.v1";

#[derive(Debug, Default)]
struct GatewayMetrics {
    active_connections: AtomicUsize,
    requests_total: AtomicU64,
    request_errors_total: AtomicU64,
    sessions_created_total: AtomicU64,
    receipts_replayed_total: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayEffectRequest {
    pub schema: String,
    pub network: String,
    pub journey: String,
    pub session_id: String,
    pub order_id: String,
    pub effect_id: String,
    pub idempotency_digest: String,
    pub method: String,
    pub amount_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEffectReceipt {
    pub schema: String,
    pub request: GatewayEffectRequest,
    pub external_identifier: String,
    pub result_digest: String,
    pub state: String,
    pub admitted_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    schema: String,
    requester_identity: String,
    client_nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSession {
    schema: String,
    sandbox_session_id: String,
    requester_identity: String,
    client_ip: String,
    origin: String,
    capability_digest: String,
    issued_at: u64,
    expires_at: u64,
    revoked_at: Option<u64>,
    request_window_started_at: u64,
    request_count: u16,
    authorizations: Vec<PublicAuthorization>,
    #[serde(default)]
    dynamic_request: Option<PublicDynamicRequestView>,
    #[serde(default)]
    requester_engine_identity: Option<String>,
    #[serde(default)]
    journey: Option<PublicJourney>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicRequestSubmission {
    schema: String,
    sandbox_session_id: String,
    request: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoInputRequest {
    pub schema: String,
    pub sandbox_session_id: String,
    pub swap_type: String,
    pub amount_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoInputResponse {
    pub schema: String,
    pub sandbox_session_id: String,
    pub swap_type: String,
    pub amount_sat: u64,
    pub destination: String,
    pub expires_at: u64,
}

/// Redacted, signed projection of a private dynamic request. The destination
/// itself never enters a manifest or HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDynamicRequestView {
    pub schema: String,
    pub request_id: String,
    pub network: String,
    pub swap_type: String,
    pub input_amount_sat: u64,
    pub maximum_total_fee_sat: u64,
    pub destination_kind: String,
    pub destination_commitment_sha256: String,
    pub destination_amount_sat: Option<u64>,
    pub payment_hash: Option<String>,
    pub expires_at: u64,
}

/// Public-safe, monotonic worker projection. Provider claims remain distinct
/// from requester-admitted rail evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJourney {
    pub schema: String,
    pub request_id: String,
    pub stage: String,
    pub quote_provider_pubkeys: Vec<String>,
    pub selected_provider_pubkey: Option<String>,
    pub unselected_provider_pubkey: Option<String>,
    pub unselected_released: bool,
    pub provider_status: Option<String>,
    pub requester_evidence: Vec<PublicRailEvidence>,
    pub error_code: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRailEvidence {
    pub rail: String,
    pub reference: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAuthorization {
    pub schema: String,
    pub sandbox_session_id: String,
    pub provider_pubkey: String,
    pub effect: GatewayEffectRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicEffectSubmission {
    schema: String,
    sandbox_session_id: String,
    provider_pubkey: String,
    effect: GatewayEffectRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEffectReceipt {
    pub schema: String,
    pub sandbox_session_id: String,
    pub provider_pubkey: String,
    pub effect_id: String,
    pub idempotency_digest: String,
    pub external_identifier: String,
    pub result_digest: String,
    pub state: String,
    pub admitted_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionManifest {
    schema: String,
    mode: String,
    network: String,
    origin: String,
    sandbox_session_id: String,
    requester_identity: String,
    requester_engine_identity: Option<String>,
    issued_at: u64,
    expires_at: u64,
    revoked: bool,
    source_revision: String,
    requester_contract_digest: String,
    browser_abi_version: u16,
    providers: Vec<String>,
    quotas: ManifestQuotas,
    allowed_operations: Vec<String>,
    dynamic_request: Option<PublicDynamicRequestView>,
    journey: Option<PublicJourney>,
    effects: Vec<ManifestEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestQuotas {
    maximum_amount_sat: u64,
    maximum_effects: u16,
    maximum_concurrent_effects: u16,
    maximum_requests: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEffect {
    provider_pubkey: String,
    network: String,
    session_id: String,
    order_id: String,
    effect_id: String,
    idempotency_digest: String,
    method: String,
    amount_sat: u64,
    state: String,
    receipt: Option<PublicEffectReceipt>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    manifest: SessionManifest,
    signature_event: Event,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionResponse {
    schema: String,
    capability: String,
    signed_manifest: SignedManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IpRateState {
    schema: String,
    client_ip: String,
    window_started_at: u64,
    sessions_created: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectRateState {
    schema: String,
    window_started_at: u64,
    effects_authorized: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceReadiness {
    schema: String,
    ready: bool,
    checked_at: u64,
    revision: String,
    failures: Vec<String>,
    active_sessions: u64,
    outstanding_sat: u64,
    provider_pubkeys: Vec<String>,
    lightning_node_ids: Vec<String>,
    bitcoin_height: u64,
    receipt_store_writable: bool,
}

#[derive(Clone)]
struct GatewayConfig {
    root: PathBuf,
    bind: SocketAddr,
    origin: String,
    signer: RelaySigner,
    lifetime_seconds: u64,
    effect_timeout: Duration,
    source_revision: String,
    requester_contract_digest: String,
    provider_set: Vec<String>,
    metrics: Arc<GatewayMetrics>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    origin: Option<String>,
    authorization: Option<String>,
    client_ip: IpAddr,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpError {
    status: u16,
    code: &'static str,
    retry_after_seconds: Option<u64>,
}

impl HttpError {
    fn new(status: u16, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after_seconds: None,
        }
    }

    fn retry(seconds: u64) -> Self {
        Self {
            status: 429,
            code: "rate_limited",
            retry_after_seconds: Some(seconds),
        }
    }
}

pub fn run_server() -> Result<Value, String> {
    validate_contract()?;
    validate_service_contract()?;
    let config = Arc::new(GatewayConfig::from_env()?);
    prepare_root(&config.root)?;
    let listener = TcpListener::bind(config.bind)
        .map_err(|error| format!("could not bind public regtest gateway: {error}"))?;
    recover_gateway_locks(&config.root)?;
    eprintln!(
        "{}",
        json!({
            "schema":"openagents.immortal.public-regtest-audit.v1",
            "event":"gateway_started",
            "bind":config.bind.to_string(),
            "origin":config.origin,
        })
    );
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|error| format!("gateway accept failed: {error}"))?;
        let active = config
            .metrics
            .active_connections
            .fetch_add(1, Ordering::AcqRel)
            + 1;
        if active > MAX_CONNECTIONS {
            config
                .metrics
                .active_connections
                .fetch_sub(1, Ordering::AcqRel);
            let _ = write_error(
                &mut stream,
                &config.origin,
                HttpError::new(503, "connection_capacity_exhausted"),
            );
            continue;
        }
        let peer = stream
            .peer_addr()
            .map_err(|error| format!("gateway could not identify peer: {error}"))?;
        let thread_config = Arc::clone(&config);
        thread::spawn(move || {
            if let Err(error) = handle_connection(&mut stream, peer, &thread_config) {
                thread_config
                    .metrics
                    .request_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                let _ = write_error(&mut stream, &thread_config.origin, error);
            }
            thread_config
                .metrics
                .active_connections
                .fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(json!({"schema":"openagents.immortal.public-regtest-gateway.v1","stopped":true}))
}

fn handle_connection(
    stream: &mut TcpStream,
    peer: SocketAddr,
    config: &GatewayConfig,
) -> Result<(), HttpError> {
    config
        .metrics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| HttpError::new(500, "internal_error"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| HttpError::new(500, "internal_error"))?;
    let request = read_http_request(stream, peer)?;
    let started = Instant::now();
    let outcome = route_request(stream, &request, config);
    let (session, effect, code) = match &outcome {
        Ok(meta) => (meta.0.as_deref(), meta.1.as_deref(), meta.2),
        Err(error) => (None, None, error.code),
    };
    let capability_digest = request
        .authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("ImmortalRegtest "))
        .filter(|value| value.len() == 64)
        .map(digest_text);
    eprintln!(
        "{}",
        json!({
            "schema":"openagents.immortal.public-regtest-audit.v1",
            "event":"request",
            "client_ip_digest":digest_text(&request.client_ip.to_string()),
            "capability_digest":capability_digest,
            "session_id":session,
            "effect_id":effect,
            "outcome":code,
            "latency_ms":started.elapsed().as_millis().min(u128::from(u32::MAX)),
        })
    );
    outcome.map(|_| ())
}

fn route_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    config: &GatewayConfig,
) -> Result<(Option<String>, Option<String>, &'static str), HttpError> {
    if request.method == "GET"
        && matches!(request.path.as_str(), "/healthz" | "/readyz" | "/metrics")
    {
        if request
            .origin
            .as_deref()
            .is_some_and(|origin| origin != config.origin)
        {
            return Err(HttpError::new(403, "origin_refused"));
        }
        return route_operational_request(stream, request, config);
    }
    if request.origin.as_deref() != Some(config.origin.as_str()) {
        return Err(HttpError::new(403, "origin_refused"));
    }
    if request.method == "OPTIONS" {
        if request.path == "/v1/public-regtest/sessions"
            || parse_session_path(&request.path).is_some()
        {
            write_json_response(stream, 204, &config.origin, &Value::Null)?;
            return Ok((None, None, "preflight"));
        }
        return Err(HttpError::new(404, "unknown_endpoint"));
    }
    if request.method == "POST" && request.path == "/v1/public-regtest/sessions" {
        require_json(request)?;
        let input: CreateSessionRequest = parse_closed_json(&request.body, "session create")?;
        let response = create_session(config, request.client_ip, input)?;
        config
            .metrics
            .sessions_created_total
            .fetch_add(1, Ordering::Relaxed);
        let session_id = response.signed_manifest.manifest.sandbox_session_id.clone();
        write_serialized_response(stream, 201, &config.origin, &response)?;
        return Ok((Some(session_id), None, "session_created"));
    }
    let Some((session_id, suffix)) = parse_session_path(&request.path) else {
        return Err(HttpError::new(404, "unknown_endpoint"));
    };
    let capability = require_capability(request)?;
    let mut lock = SessionLock::acquire(&config.root, session_id)
        .map_err(|_| HttpError::new(503, "session_busy"))?;
    let mut session = load_session(&config.root, session_id)
        .map_err(|_| HttpError::new(500, "session_state_unavailable"))?
        .ok_or_else(|| HttpError::new(404, "session_not_found"))?;
    authorize_session(
        &mut session,
        capability,
        request.client_ip,
        unix_now_http()?,
    )?;
    charge_session(&mut session, unix_now_http()?)?;
    store_session(&config.root, &session)
        .map_err(|_| HttpError::new(500, "session_state_unavailable"))?;

    match (request.method.as_str(), suffix) {
        ("GET", "") => {
            let signed = signed_manifest(config, &session)
                .map_err(|_| HttpError::new(500, "manifest_unavailable"))?;
            lock.release();
            write_serialized_response(stream, 200, &config.origin, &signed)?;
            Ok((Some(session_id.to_owned()), None, "session_read"))
        }
        ("DELETE", "") => {
            session.revoked_at = Some(unix_now_http()?);
            store_session(&config.root, &session)
                .map_err(|_| HttpError::new(500, "session_state_unavailable"))?;
            lock.release();
            write_json_response(stream, 200, &config.origin, &json!({"revoked":true}))?;
            Ok((Some(session_id.to_owned()), None, "session_revoked"))
        }
        ("POST", "/effects") => {
            require_json(request)?;
            let submission: PublicEffectSubmission =
                parse_closed_json(&request.body, "effect submission")?;
            validate_submission(&session, session_id, &submission)?;
            let effect_id = submission.effect.effect_id.clone();
            if let Some(receipt) = load_receipt(&config.root, session_id, &effect_id)
                .map_err(|_| HttpError::new(500, "receipt_unavailable"))?
            {
                config
                    .metrics
                    .receipts_replayed_total
                    .fetch_add(1, Ordering::Relaxed);
                lock.release();
                write_serialized_response(stream, 200, &config.origin, &receipt)?;
                return Ok((
                    Some(session_id.to_owned()),
                    Some(effect_id),
                    "receipt_replayed",
                ));
            }
            let admitted = admission_path(&config.root, session_id, &effect_id);
            if let Some(existing) = load_optional_json::<PublicEffectSubmission>(&admitted)
                .map_err(|_| HttpError::new(500, "admission_unavailable"))?
            {
                if existing != submission {
                    return Err(HttpError::new(409, "effect_conflict"));
                }
            } else {
                write_json(&admitted, &submission)
                    .map_err(|_| HttpError::new(500, "admission_unavailable"))?;
            }
            lock.release();
            let deadline = Instant::now() + config.effect_timeout;
            loop {
                if let Some(receipt) = load_receipt(&config.root, session_id, &effect_id)
                    .map_err(|_| HttpError::new(500, "receipt_unavailable"))?
                {
                    write_serialized_response(stream, 200, &config.origin, &receipt)?;
                    return Ok((
                        Some(session_id.to_owned()),
                        Some(effect_id),
                        "effect_admitted",
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(HttpError::new(504, "effect_timeout"));
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
        ("POST", "/requests") => {
            require_json(request)?;
            let submission: DynamicRequestSubmission =
                parse_closed_json(&request.body, "dynamic request submission")?;
            validate_dynamic_submission(session_id, &submission)?;
            let path = dynamic_request_path(&config.root, session_id);
            if session.dynamic_request.is_some() && !path.exists() {
                return Err(HttpError::new(409, "dynamic_request_terminal"));
            }
            if let Some(existing) = load_optional_json::<DynamicRequestSubmission>(&path)
                .map_err(|_| HttpError::new(500, "dynamic_request_unavailable"))?
            {
                if existing != submission {
                    return Err(HttpError::new(409, "dynamic_request_conflict"));
                }
            } else {
                write_json_create_new(&path, &submission)
                    .map_err(|_| HttpError::new(500, "dynamic_request_unavailable"))?;
            }
            lock.release();
            write_json_response(
                stream,
                202,
                &config.origin,
                &json!({
                    "schema":DYNAMIC_SUBMISSION_SCHEMA,
                    "sandbox_session_id":session_id,
                    "accepted":true,
                }),
            )?;
            Ok((
                Some(session_id.to_owned()),
                None,
                "dynamic_request_accepted",
            ))
        }
        ("POST", "/inputs") => {
            require_json(request)?;
            if session.dynamic_request.is_some() {
                return Err(HttpError::new(409, "demo_input_terminal"));
            }
            let input: DemoInputRequest = parse_closed_json(&request.body, "demo input request")?;
            validate_demo_input_request(session_id, &input)?;
            let path = demo_input_request_path(&config.root, session_id);
            if let Some(existing) = load_optional_json::<DemoInputRequest>(&path)
                .map_err(|_| HttpError::new(500, "demo_input_unavailable"))?
            {
                if existing != input {
                    return Err(HttpError::new(409, "demo_input_conflict"));
                }
            } else {
                write_json_create_new(&path, &input)
                    .map_err(|_| HttpError::new(500, "demo_input_unavailable"))?;
            }
            lock.release();
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(output) = load_optional_json::<DemoInputResponse>(
                    &demo_input_response_path(&config.root, session_id),
                )
                .map_err(|_| HttpError::new(500, "demo_input_unavailable"))?
                {
                    validate_demo_input_response(&input, &output)
                        .map_err(|_| HttpError::new(500, "demo_input_unavailable"))?;
                    write_serialized_response(stream, 200, &config.origin, &output)?;
                    return Ok((Some(session_id.to_owned()), None, "demo_input_issued"));
                }
                if Instant::now() >= deadline {
                    return Err(HttpError::new(504, "demo_input_timeout"));
                }
                thread::sleep(Duration::from_millis(25));
            }
        }
        _ => Err(HttpError::new(404, "unknown_endpoint")),
    }
}

fn route_operational_request(
    stream: &mut TcpStream,
    request: &HttpRequest,
    config: &GatewayConfig,
) -> Result<(Option<String>, Option<String>, &'static str), HttpError> {
    match request.path.as_str() {
        "/healthz" => {
            probe_state_root(&config.root)
                .map_err(|_| HttpError::new(503, "receipt_store_unwritable"))?;
            write_json_response(
                stream,
                200,
                &config.origin,
                &json!({"schema":"openagents.immortal.public-regtest-health.v1","status":"live"}),
            )?;
            Ok((None, None, "health_live"))
        }
        "/readyz" => {
            let readiness = require_service_ready(config, unix_now_http()?)?;
            write_serialized_response(stream, 200, &config.origin, &readiness)?;
            Ok((None, None, "service_ready"))
        }
        "/metrics" => {
            let now = unix_now_http()?;
            let (active_sessions, outstanding_sat) = service_counts(&config.root, now)
                .map_err(|_| HttpError::new(503, "service_state_unavailable"))?;
            write_json_response(
                stream,
                200,
                &config.origin,
                &json!({
                    "schema":"openagents.immortal.public-regtest-metrics.v1",
                    "active_connections":config.metrics.active_connections.load(Ordering::Relaxed),
                    "active_sessions":active_sessions,
                    "outstanding_sat":outstanding_sat,
                    "requests_total":config.metrics.requests_total.load(Ordering::Relaxed),
                    "request_errors_total":config.metrics.request_errors_total.load(Ordering::Relaxed),
                    "sessions_created_total":config.metrics.sessions_created_total.load(Ordering::Relaxed),
                    "receipts_replayed_total":config.metrics.receipts_replayed_total.load(Ordering::Relaxed),
                }),
            )?;
            Ok((None, None, "metrics_read"))
        }
        _ => Err(HttpError::new(404, "unknown_endpoint")),
    }
}

fn probe_state_root(root: &Path) -> Result<(), String> {
    let probe = root
        .join("locks")
        .join(format!("health-{}", lower_hex(&random_32()?)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)
        .map_err(|error| format!("could not write receipt-store probe: {error}"))?;
    file.write_all(b"ready\n")
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not sync receipt-store probe: {error}"))?;
    fs::remove_file(&probe)
        .map_err(|error| format!("could not remove receipt-store probe: {error}"))
}

fn require_service_ready(config: &GatewayConfig, now: u64) -> Result<ServiceReadiness, HttpError> {
    if config.root.join("maintenance").exists() {
        return Err(HttpError::new(503, "maintenance"));
    }
    let readiness = load_optional_json::<ServiceReadiness>(&config.root.join("readiness.json"))
        .map_err(|_| HttpError::new(503, "readiness_unavailable"))?
        .ok_or_else(|| HttpError::new(503, "readiness_unavailable"))?;
    if readiness.schema != SERVICE_READINESS_SCHEMA
        || !readiness.ready
        || !readiness.failures.is_empty()
        || readiness.checked_at > now.saturating_add(5)
        || now.saturating_sub(readiness.checked_at) > READINESS_MAXIMUM_AGE_SECONDS
        || readiness.revision != config.source_revision
        || readiness.provider_pubkeys != config.provider_set
        || readiness.lightning_node_ids.len() != 3
        || readiness.lightning_node_ids.iter().any(|id| {
            id.len() != 66
                || !(id.starts_with("02") || id.starts_with("03"))
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || readiness.bitcoin_height == 0
        || !readiness.receipt_store_writable
    {
        return Err(HttpError::new(503, "service_unready"));
    }
    let (active_sessions, outstanding_sat) = service_counts(&config.root, now)
        .map_err(|_| HttpError::new(503, "service_state_unavailable"))?;
    if active_sessions > MAX_ACTIVE_SESSIONS
        || outstanding_sat > MAX_OUTSTANDING_SAT
        || readiness.active_sessions > u64::try_from(MAX_ACTIVE_SESSIONS).unwrap_or(u64::MAX)
        || readiness.outstanding_sat > MAX_OUTSTANDING_SAT
    {
        return Err(HttpError::new(503, "service_capacity_unavailable"));
    }
    Ok(readiness)
}

fn service_counts(root: &Path, now: u64) -> Result<(usize, u64), String> {
    let mut active = 0_usize;
    let mut outstanding = 0_u64;
    let mut retained = 0_usize;
    for entry in fs::read_dir(root.join("sessions"))
        .map_err(|error| format!("could not inspect public sessions: {error}"))?
    {
        let entry = entry.map_err(|error| format!("could not inspect public session: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("could not inspect public session type: {error}"))?
            .is_dir()
        {
            return Err("public session root contains a non-directory".to_owned());
        }
        retained = retained.saturating_add(1);
        if retained > MAX_RETAINED_SESSION_DIRS {
            return Err("public retained-session bound exceeded".to_owned());
        }
        let session_id = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "public session name is not UTF-8".to_owned())?
            .to_owned();
        validate_lower_hex_32(&session_id, "retained session")?;
        let session = load_session(root, &session_id)?
            .ok_or_else(|| "public session directory has no state".to_owned())?;
        if session.revoked_at.is_none() && now < session.expires_at {
            active = active.saturating_add(1);
            for authorization in &session.authorizations {
                if load_receipt(root, &session_id, &authorization.effect.effect_id)?.is_none() {
                    outstanding = outstanding
                        .checked_add(authorization.effect.amount_sat)
                        .ok_or_else(|| "public outstanding exposure overflowed".to_owned())?;
                }
            }
        }
    }
    Ok((active, outstanding))
}

fn create_session(
    config: &GatewayConfig,
    client_ip: IpAddr,
    input: CreateSessionRequest,
) -> Result<CreateSessionResponse, HttpError> {
    validate_create(&input)?;
    let now = unix_now_http()?;
    require_service_ready(config, now)?;
    let mut global = SessionLock::acquire_named(&config.root, "global-sessions")
        .map_err(|_| HttpError::new(503, "service_state_busy"))?;
    let (active, _) = service_counts(&config.root, now)
        .map_err(|_| HttpError::new(503, "service_state_unavailable"))?;
    if active >= MAX_ACTIVE_SESSIONS {
        return Err(HttpError::new(503, "session_capacity_exhausted"));
    }
    charge_ip(config, client_ip, now)?;
    let capability = lower_hex(&random_32().map_err(|_| HttpError::new(500, "entropy_failed"))?);
    let sandbox_session_id = lower_hex(&Sha256::digest(
        [
            capability.as_bytes(),
            input.client_nonce.as_bytes(),
            &now.to_be_bytes(),
        ]
        .concat(),
    ));
    let session = StoredSession {
        schema: SESSION_SCHEMA.to_owned(),
        sandbox_session_id: sandbox_session_id.clone(),
        requester_identity: input.requester_identity,
        client_ip: client_ip.to_string(),
        origin: config.origin.clone(),
        capability_digest: digest_text(&capability),
        issued_at: now,
        expires_at: now + config.lifetime_seconds,
        revoked_at: None,
        request_window_started_at: now,
        request_count: 0,
        authorizations: Vec::new(),
        dynamic_request: None,
        requester_engine_identity: None,
        journey: None,
    };
    store_session_create_new(&config.root, &session)
        .map_err(|_| HttpError::new(500, "session_state_unavailable"))?;
    global.release();
    let signed_manifest = signed_manifest(config, &session)
        .map_err(|_| HttpError::new(500, "manifest_unavailable"))?;
    Ok(CreateSessionResponse {
        schema: RESPONSE_SCHEMA.to_owned(),
        capability,
        signed_manifest,
    })
}

pub fn bind_authorization(
    sandbox_session_id: &str,
    requester_pubkey: &str,
    provider_pubkey: &str,
    effect: &GatewayEffectRequest,
) -> Result<(), String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    validate_lower_hex_32(requester_pubkey, "requester pubkey")?;
    validate_lower_hex_32(provider_pubkey, "provider pubkey")?;
    validate_browser_effect(effect)?;
    let root = state_root()?;
    prepare_root(&root)?;
    let mut global = SessionLock::acquire_named(&root, "global-exposure")?;
    let mut lock = SessionLock::acquire(&root, sandbox_session_id)?;
    let mut session = load_session(&root, sandbox_session_id)?
        .ok_or_else(|| "public regtest session does not exist".to_owned())?;
    let now = unix_now()?;
    if session.revoked_at.is_some() || now >= session.expires_at {
        return Err("public regtest session cannot accept a new effect".to_owned());
    }
    let expected_requester = session
        .requester_engine_identity
        .as_deref()
        .unwrap_or(&session.requester_identity);
    if expected_requester != requester_pubkey {
        return Err("public regtest requester identity differs from the engine signer".to_owned());
    }
    let candidate = PublicAuthorization {
        schema: AUTHORIZATION_SCHEMA.to_owned(),
        sandbox_session_id: sandbox_session_id.to_owned(),
        provider_pubkey: provider_pubkey.to_owned(),
        effect: effect.clone(),
    };
    if let Some(existing) = session
        .authorizations
        .iter()
        .find(|authorization| authorization.effect.effect_id == effect.effect_id)
    {
        if existing != &candidate {
            return Err("public regtest authorization conflicts with durable state".to_owned());
        }
        lock.release();
        return Ok(());
    }
    if session.authorizations.len() >= usize::from(MAX_EFFECTS_PER_SESSION) {
        return Err("public regtest session effect quota is exhausted".to_owned());
    }
    let (_, outstanding) = service_counts(&root, now)?;
    if outstanding
        .checked_add(effect.amount_sat)
        .is_none_or(|total| total > MAX_OUTSTANDING_SAT)
    {
        return Err("public regtest outstanding exposure is exhausted".to_owned());
    }
    charge_effect_rate(&root, now)?;
    session.authorizations.push(candidate);
    store_session(&root, &session)?;
    lock.release();
    global.release();
    Ok(())
}

pub fn await_admission(
    sandbox_session_id: &str,
    requester_pubkey: &str,
    provider_pubkey: &str,
    effect: &GatewayEffectRequest,
) -> Result<(), String> {
    bind_authorization(
        sandbox_session_id,
        requester_pubkey,
        provider_pubkey,
        effect,
    )?;
    let root = state_root()?;
    let deadline = Instant::now()
        + Duration::from_secs(bounded_env(
            "IMMORTAL_PUBLIC_REGTEST_EFFECT_TIMEOUT_SECONDS",
            180,
            1,
            900,
        )?);
    loop {
        if let Some(submission) = load_optional_json::<PublicEffectSubmission>(&admission_path(
            &root,
            sandbox_session_id,
            &effect.effect_id,
        ))? {
            let expected = PublicEffectSubmission {
                schema: EFFECT_SCHEMA.to_owned(),
                sandbox_session_id: sandbox_session_id.to_owned(),
                provider_pubkey: provider_pubkey.to_owned(),
                effect: effect.clone(),
            };
            if submission != expected {
                return Err("public regtest admission changed the engine authorization".to_owned());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "public regtest browser did not admit the effect before timeout".to_owned(),
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub fn record_receipt(
    sandbox_session_id: &str,
    receipt: &WorkerEffectReceipt,
) -> Result<PublicEffectReceipt, String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    if receipt.schema != "openagents.immortal.browser-demo-effect-receipt.v1"
        || receipt.state != "admitted"
    {
        return Err("private worker receipt has another schema or state".to_owned());
    }
    validate_browser_effect(&receipt.request)?;
    let root = state_root()?;
    let admitted: PublicEffectSubmission = load_optional_json(&admission_path(
        &root,
        sandbox_session_id,
        &receipt.request.effect_id,
    ))?
    .ok_or_else(|| "public regtest receipt has no admitted request".to_owned())?;
    if admitted.effect != receipt.request {
        return Err("public regtest receipt conflicts with its admission".to_owned());
    }
    let public = PublicEffectReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        sandbox_session_id: sandbox_session_id.to_owned(),
        provider_pubkey: admitted.provider_pubkey,
        effect_id: receipt.request.effect_id.clone(),
        idempotency_digest: receipt.request.idempotency_digest.clone(),
        external_identifier: receipt.external_identifier.clone(),
        result_digest: receipt.result_digest.clone(),
        state: receipt.state.clone(),
        admitted_at: receipt.admitted_at,
    };
    validate_public_receipt(&public)?;
    let path = receipt_path(&root, sandbox_session_id, &public.effect_id);
    if let Some(existing) = load_optional_json::<PublicEffectReceipt>(&path)? {
        if existing.sandbox_session_id != public.sandbox_session_id
            || existing.provider_pubkey != public.provider_pubkey
            || existing.effect_id != public.effect_id
            || existing.idempotency_digest != public.idempotency_digest
            || existing.external_identifier != public.external_identifier
            || existing.result_digest != public.result_digest
            || existing.state != public.state
        {
            return Err("public regtest receipt conflicts with durable replay".to_owned());
        }
        return Ok(existing);
    }
    write_json_create_new(&path, &public)?;
    Ok(public)
}

/// Load the one capability-bound private request for the sandbox worker. The
/// caller is the fixed local worker process; this is deliberately not an HTTP
/// read endpoint.
pub fn claim_dynamic_request(sandbox_session_id: &str) -> Result<Option<Value>, String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    let root = state_root()?;
    let submission = load_optional_json::<DynamicRequestSubmission>(&dynamic_request_path(
        &root,
        sandbox_session_id,
    ))?;
    let Some(submission) = submission else {
        return Ok(None);
    };
    if submission.schema != DYNAMIC_SUBMISSION_SCHEMA
        || submission.sandbox_session_id != sandbox_session_id
    {
        return Err("private dynamic request changed its session binding".to_owned());
    }
    Ok(Some(submission.request))
}

/// Claim one capability-bound demo-input allocation request from the private
/// rail worker. The destination is returned only to that capability over HTTP;
/// it is never copied into a signed public manifest or audit event.
pub fn claim_demo_input_request(
    sandbox_session_id: &str,
) -> Result<Option<DemoInputRequest>, String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    let root = state_root()?;
    let request = load_optional_json::<DemoInputRequest>(&demo_input_request_path(
        &root,
        sandbox_session_id,
    ))?;
    if let Some(request) = &request {
        validate_demo_input_request_value(sandbox_session_id, request)?;
    }
    Ok(request)
}

/// Publish the one-time demo destination generated by the private requester
/// rail worker. Exact replay is allowed; any changed response is refused.
pub fn record_demo_input_response(response: &DemoInputResponse) -> Result<(), String> {
    validate_lower_hex_32(&response.sandbox_session_id, "sandbox session ID")?;
    let root = state_root()?;
    let request = load_optional_json::<DemoInputRequest>(&demo_input_request_path(
        &root,
        &response.sandbox_session_id,
    ))?
    .ok_or_else(|| "demo input response has no request".to_owned())?;
    validate_demo_input_response(&request, response)?;
    let path = demo_input_response_path(&root, &response.sandbox_session_id);
    if let Some(existing) = load_optional_json::<DemoInputResponse>(&path)? {
        if existing != *response {
            return Err("demo input response conflicts with durable replay".to_owned());
        }
        return Ok(());
    }
    write_json_create_new(&path, response)
}

/// Publish the semantic validator's redacted request projection. This is the
/// only request material copied into the signed public manifest.
pub fn record_dynamic_request_view(
    sandbox_session_id: &str,
    requester_engine_identity: &str,
    view: &PublicDynamicRequestView,
) -> Result<(), String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    validate_lower_hex_32(requester_engine_identity, "requester engine identity")?;
    validate_dynamic_view(view)?;
    let root = state_root()?;
    let mut lock = SessionLock::acquire(&root, sandbox_session_id)?;
    let mut session = load_session(&root, sandbox_session_id)?
        .ok_or_else(|| "public regtest session does not exist".to_owned())?;
    if session
        .dynamic_request
        .as_ref()
        .is_some_and(|current| current != view)
    {
        return Err("public dynamic request conflicts with durable replay".to_owned());
    }
    if session
        .requester_engine_identity
        .as_deref()
        .is_some_and(|current| current != requester_engine_identity)
    {
        return Err("public requester engine identity conflicts with durable replay".to_owned());
    }
    session.dynamic_request = Some(view.clone());
    session.requester_engine_identity = Some(requester_engine_identity.to_owned());
    store_session(&root, &session)?;
    lock.release();
    Ok(())
}

/// Publish a monotonic, public-safe journey update from the private worker.
pub fn record_journey(sandbox_session_id: &str, journey: &PublicJourney) -> Result<(), String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    validate_public_journey(journey)?;
    let root = state_root()?;
    let mut lock = SessionLock::acquire(&root, sandbox_session_id)?;
    let mut session = load_session(&root, sandbox_session_id)?
        .ok_or_else(|| "public regtest session does not exist".to_owned())?;
    let view = session
        .dynamic_request
        .as_ref()
        .ok_or_else(|| "public journey has no validated dynamic request".to_owned())?;
    if journey.request_id != view.request_id {
        return Err("public journey changed the dynamic request ID".to_owned());
    }
    if let Some(current) = &session.journey {
        if journey_rank(&journey.stage)? < journey_rank(&current.stage)? {
            return Err("public journey cannot move backward".to_owned());
        }
        if journey.updated_at < current.updated_at {
            return Err("public journey timestamp cannot move backward".to_owned());
        }
    }
    session.journey = Some(journey.clone());
    store_session(&root, &session)?;
    lock.release();
    Ok(())
}

/// Delete the private destination/invoice after a terminal public projection
/// is durable. The redacted commitment remains signed in the manifest.
pub fn retire_dynamic_request(sandbox_session_id: &str) -> Result<(), String> {
    validate_lower_hex_32(sandbox_session_id, "sandbox session ID")?;
    let root = state_root()?;
    let mut lock = SessionLock::acquire(&root, sandbox_session_id)?;
    let session = load_session(&root, sandbox_session_id)?
        .ok_or_else(|| "public regtest session does not exist".to_owned())?;
    if !session.journey.as_ref().is_some_and(|journey| {
        matches!(
            journey.stage.as_str(),
            "completed" | "failed" | "recoverable"
        )
    }) {
        return Err("private dynamic request cannot retire before terminal state".to_owned());
    }
    let path = dynamic_request_path(&root, sandbox_session_id);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("could not retire private dynamic request: {error}"))?;
    }
    lock.release();
    Ok(())
}

fn validate_dynamic_submission(
    session_id: &str,
    submission: &DynamicRequestSubmission,
) -> Result<(), HttpError> {
    if submission.schema != DYNAMIC_SUBMISSION_SCHEMA
        || submission.sandbox_session_id != session_id
        || !submission.request.is_object()
    {
        return Err(HttpError::new(400, "dynamic_request_refused"));
    }
    let encoded = serde_json::to_vec(&submission.request)
        .map_err(|_| HttpError::new(400, "dynamic_request_refused"))?;
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_BYTES {
        return Err(HttpError::new(413, "dynamic_request_too_large"));
    }
    Ok(())
}

fn validate_demo_input_request(
    session_id: &str,
    request: &DemoInputRequest,
) -> Result<(), HttpError> {
    validate_demo_input_request_value(session_id, request)
        .map_err(|_| HttpError::new(400, "demo_input_refused"))
}

fn validate_demo_input_request_value(
    session_id: &str,
    request: &DemoInputRequest,
) -> Result<(), String> {
    if request.schema != DEMO_INPUT_REQUEST_SCHEMA
        || request.sandbox_session_id != session_id
        || !matches!(request.swap_type.as_str(), "reverse" | "submarine")
        || !(10_000..=MAX_AMOUNT_SAT).contains(&request.amount_sat)
    {
        return Err("demo input request is outside the closed contract".to_owned());
    }
    Ok(())
}

fn validate_demo_input_response(
    request: &DemoInputRequest,
    response: &DemoInputResponse,
) -> Result<(), String> {
    if response.schema != DEMO_INPUT_RESPONSE_SCHEMA
        || response.sandbox_session_id != request.sandbox_session_id
        || response.swap_type != request.swap_type
        || response.amount_sat != request.amount_sat
        || response.destination.is_empty()
        || response.destination.len() > 8_192
        || response
            .destination
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || (response.swap_type == "reverse" && !response.destination.starts_with("bcrt1"))
        || (response.swap_type == "submarine" && !response.destination.starts_with("lnbcrt"))
    {
        return Err("demo input response is outside the closed contract".to_owned());
    }
    let now = unix_now()?;
    if response.expires_at <= now || response.expires_at > now.saturating_add(600) {
        return Err("demo input response expiry is outside the closed contract".to_owned());
    }
    Ok(())
}

fn validate_dynamic_view(view: &PublicDynamicRequestView) -> Result<(), String> {
    if view.schema != DYNAMIC_VIEW_SCHEMA
        || view.network != REGTEST_NETWORK
        || !matches!(view.swap_type.as_str(), "reverse" | "submarine")
        || !matches!(
            view.destination_kind.as_str(),
            "bitcoin_address" | "bolt11_invoice"
        )
        || view.input_amount_sat < 10_000
        || view.input_amount_sat > MAX_AMOUNT_SAT
        || view.maximum_total_fee_sat == 0
        || view.maximum_total_fee_sat >= view.input_amount_sat
    {
        return Err("public dynamic request view is outside the closed contract".to_owned());
    }
    validate_lower_hex_32(&view.request_id, "dynamic request ID")?;
    validate_lower_hex_32(
        &view.destination_commitment_sha256,
        "destination commitment",
    )?;
    if let Some(payment_hash) = &view.payment_hash {
        validate_lower_hex_32(payment_hash, "payment hash")?;
    }
    reject_custody_material(&serde_json::to_value(view).map_err(|error| error.to_string())?)
}

fn validate_public_journey(journey: &PublicJourney) -> Result<(), String> {
    if journey.schema != JOURNEY_SCHEMA || journey.quote_provider_pubkeys.len() > 8 {
        return Err("public journey is outside the closed contract".to_owned());
    }
    validate_lower_hex_32(&journey.request_id, "journey request ID")?;
    journey_rank(&journey.stage)?;
    for provider in journey
        .quote_provider_pubkeys
        .iter()
        .chain(journey.selected_provider_pubkey.iter())
        .chain(journey.unselected_provider_pubkey.iter())
    {
        validate_lower_hex_32(provider, "journey provider")?;
    }
    if journey.requester_evidence.len() > 4 {
        return Err("public journey has too much rail evidence".to_owned());
    }
    for evidence in &journey.requester_evidence {
        if !matches!(evidence.rail.as_str(), "bitcoin" | "lightning")
            || !matches!(evidence.state.as_str(), "admitted" | "verified")
        {
            return Err("public journey rail evidence is invalid".to_owned());
        }
        validate_lower_hex_32(&evidence.reference, "rail evidence reference")?;
    }
    reject_custody_material(&serde_json::to_value(journey).map_err(|error| error.to_string())?)
}

fn journey_rank(stage: &str) -> Result<u8, String> {
    match stage {
        "accepted" => Ok(0),
        "quotes_verified" => Ok(1),
        "provider_selected" => Ok(2),
        "effect_authorized" => Ok(3),
        "effect_admitted" => Ok(4),
        "completed" | "recoverable" | "failed" => Ok(5),
        _ => Err("public journey stage is unsupported".to_owned()),
    }
}

pub fn run_fixture_worker_once() -> Result<Value, String> {
    if std::env::var("IMMORTAL_PUBLIC_REGTEST_FIXTURE_WORKER").as_deref() != Ok("1") {
        return Err("fixture worker requires its explicit regtest-only gate".to_owned());
    }
    let root = state_root()?;
    let session_id = required_env("IMMORTAL_PUBLIC_REGTEST_SESSION_ID")?;
    let effect_id = required_env("IMMORTAL_PUBLIC_REGTEST_EFFECT_ID")?;
    let admission: PublicEffectSubmission =
        load_optional_json(&admission_path(&root, &session_id, &effect_id))?
            .ok_or_else(|| "fixture worker has no admitted effect".to_owned())?;
    let receipt = PublicEffectReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        sandbox_session_id: session_id.clone(),
        provider_pubkey: admission.provider_pubkey,
        effect_id: effect_id.clone(),
        idempotency_digest: admission.effect.idempotency_digest,
        external_identifier: digest_text(&format!("external:{effect_id}")),
        result_digest: digest_text(&format!("result:{effect_id}")),
        state: "admitted".to_owned(),
        admitted_at: unix_now()?,
    };
    validate_public_receipt(&receipt)?;
    let path = receipt_path(&root, &session_id, &effect_id);
    if let Some(existing) = load_optional_json::<PublicEffectReceipt>(&path)? {
        if existing.sandbox_session_id != receipt.sandbox_session_id
            || existing.provider_pubkey != receipt.provider_pubkey
            || existing.effect_id != receipt.effect_id
            || existing.idempotency_digest != receipt.idempotency_digest
            || existing.external_identifier != receipt.external_identifier
            || existing.result_digest != receipt.result_digest
            || existing.state != receipt.state
        {
            return Err("fixture worker receipt conflicts with durable replay".to_owned());
        }
        return serde_json::to_value(existing).map_err(|error| error.to_string());
    } else {
        write_json_create_new(&path, &receipt)?;
    }
    serde_json::to_value(receipt).map_err(|error| error.to_string())
}

pub fn bind_fixture_authorization() -> Result<Value, String> {
    if std::env::var("IMMORTAL_PUBLIC_REGTEST_FIXTURE_WORKER").as_deref() != Ok("1") {
        return Err("fixture authorization requires its explicit regtest-only gate".to_owned());
    }
    let sandbox_session_id = required_env("IMMORTAL_PUBLIC_REGTEST_SESSION_ID")?;
    let requester_pubkey = required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_REQUESTER")?;
    let provider_pubkey = required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_PROVIDER")?;
    let effect = GatewayEffectRequest {
        schema: "openagents.immortal.browser-demo-effect.v1".to_owned(),
        network: REGTEST_NETWORK.to_owned(),
        journey: required_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_JOURNEY")?,
        session_id: required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_ENGINE_SESSION")?,
        order_id: required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_ORDER")?,
        effect_id: required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_EFFECT_ID")?,
        idempotency_digest: required_lower_hex_env(
            "IMMORTAL_PUBLIC_REGTEST_FIXTURE_IDEMPOTENCY_DIGEST",
        )?,
        method: required_env("IMMORTAL_PUBLIC_REGTEST_FIXTURE_METHOD")?,
        amount_sat: bounded_env(
            "IMMORTAL_PUBLIC_REGTEST_FIXTURE_AMOUNT_SAT",
            100_000,
            1,
            MAX_AMOUNT_SAT,
        )?,
    };
    bind_authorization(
        &sandbox_session_id,
        &requester_pubkey,
        &provider_pubkey,
        &effect,
    )?;
    Ok(json!({
        "schema":AUTHORIZATION_SCHEMA,
        "sandbox_session_id":sandbox_session_id,
        "provider_pubkey":provider_pubkey,
        "effect":effect,
    }))
}

fn signed_manifest(
    config: &GatewayConfig,
    session: &StoredSession,
) -> Result<SignedManifest, String> {
    let mut providers = config.provider_set.clone();
    for authorization in &session.authorizations {
        if !providers.contains(&authorization.provider_pubkey) {
            providers.push(authorization.provider_pubkey.clone());
        }
    }
    providers.sort();
    providers.dedup();
    let effects = session
        .authorizations
        .iter()
        .map(|authorization| {
            let receipt = load_receipt(
                &config.root,
                &session.sandbox_session_id,
                &authorization.effect.effect_id,
            )?;
            Ok(ManifestEffect {
                provider_pubkey: authorization.provider_pubkey.clone(),
                network: authorization.effect.network.clone(),
                session_id: authorization.effect.session_id.clone(),
                order_id: authorization.effect.order_id.clone(),
                effect_id: authorization.effect.effect_id.clone(),
                idempotency_digest: authorization.effect.idempotency_digest.clone(),
                method: authorization.effect.method.clone(),
                amount_sat: authorization.effect.amount_sat,
                state: if receipt.is_some() {
                    "admitted".to_owned()
                } else {
                    "authorized".to_owned()
                },
                receipt,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let manifest = SessionManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        mode: "public_regtest_capability_v1".to_owned(),
        network: REGTEST_NETWORK.to_owned(),
        origin: session.origin.clone(),
        sandbox_session_id: session.sandbox_session_id.clone(),
        requester_identity: session.requester_identity.clone(),
        requester_engine_identity: session.requester_engine_identity.clone(),
        issued_at: session.issued_at,
        expires_at: session.expires_at,
        revoked: session.revoked_at.is_some(),
        source_revision: config.source_revision.clone(),
        requester_contract_digest: config.requester_contract_digest.clone(),
        browser_abi_version: 1,
        providers,
        quotas: ManifestQuotas {
            maximum_amount_sat: MAX_AMOUNT_SAT,
            maximum_effects: MAX_EFFECTS_PER_SESSION,
            maximum_concurrent_effects: MAX_CONCURRENT_EFFECTS_PER_SESSION,
            maximum_requests: MAX_REQUESTS_PER_SESSION,
        },
        allowed_operations: vec![
            "allocate_demo_input".to_owned(),
            "submit_dynamic_request".to_owned(),
            "broadcast_bitcoin_funding".to_owned(),
            "pay_lightning_invoice".to_owned(),
        ],
        dynamic_request: session.dynamic_request.clone(),
        journey: session.journey.clone(),
        effects,
    };
    let manifest_value = serde_json::to_value(&manifest).map_err(|error| error.to_string())?;
    reject_custody_material(&manifest_value)?;
    let content = serde_json::to_string(&manifest).map_err(|error| error.to_string())?;
    let signature_event = config.signer.sign(
        unix_now()?,
        MANIFEST_EVENT_KIND,
        vec![
            Tag(vec!["d".to_owned(), session.sandbox_session_id.clone()]),
            Tag(vec!["network".to_owned(), REGTEST_NETWORK.to_owned()]),
        ],
        content,
    );
    Ok(SignedManifest {
        manifest,
        signature_event,
    })
}

fn validate_create(input: &CreateSessionRequest) -> Result<(), HttpError> {
    if input.schema != CREATE_SCHEMA {
        return Err(HttpError::new(400, "invalid_session_request"));
    }
    validate_lower_hex_32(&input.requester_identity, "requester identity")
        .map_err(|_| HttpError::new(400, "invalid_session_request"))?;
    validate_lower_hex_32(&input.client_nonce, "client nonce")
        .map_err(|_| HttpError::new(400, "invalid_session_request"))?;
    Ok(())
}

fn validate_submission(
    session: &StoredSession,
    session_id: &str,
    submission: &PublicEffectSubmission,
) -> Result<(), HttpError> {
    if submission.schema != EFFECT_SCHEMA || submission.sandbox_session_id != session_id {
        return Err(HttpError::new(409, "effect_conflict"));
    }
    validate_browser_effect(&submission.effect)
        .map_err(|_| HttpError::new(400, "invalid_effect"))?;
    if session.authorizations.iter().any(|authorization| {
        authorization.sandbox_session_id == session_id
            && authorization.provider_pubkey == submission.provider_pubkey
            && authorization.effect == submission.effect
    }) {
        Ok(())
    } else {
        Err(HttpError::new(409, "effect_conflict"))
    }
}

fn validate_browser_effect(effect: &GatewayEffectRequest) -> Result<(), String> {
    if effect.schema != "openagents.immortal.browser-demo-effect.v1"
        || effect.network != REGTEST_NETWORK
        || !matches!(effect.journey.as_str(), "submarine" | "reverse")
        || !matches!(
            effect.method.as_str(),
            "broadcast_bitcoin_funding" | "pay_lightning_invoice"
        )
        || effect.amount_sat == 0
        || effect.amount_sat > MAX_AMOUNT_SAT
        || (effect.journey == "submarine" && effect.method != "broadcast_bitcoin_funding")
        || (effect.journey == "reverse" && effect.method != "pay_lightning_invoice")
    {
        return Err("effect is outside the public regtest contract".to_owned());
    }
    for (value, label) in [
        (&effect.session_id, "requester session ID"),
        (&effect.order_id, "Order ID"),
        (&effect.effect_id, "effect ID"),
        (&effect.idempotency_digest, "idempotency digest"),
    ] {
        validate_lower_hex_32(value, label)?;
    }
    Ok(())
}

fn validate_public_receipt(receipt: &PublicEffectReceipt) -> Result<(), String> {
    if receipt.schema != RECEIPT_SCHEMA || receipt.state != "admitted" {
        return Err("public receipt has another schema or state".to_owned());
    }
    for (value, label) in [
        (&receipt.sandbox_session_id, "receipt sandbox session"),
        (&receipt.provider_pubkey, "receipt provider"),
        (&receipt.effect_id, "receipt effect"),
        (&receipt.idempotency_digest, "receipt idempotency digest"),
        (&receipt.external_identifier, "receipt external identifier"),
        (&receipt.result_digest, "receipt result digest"),
    ] {
        validate_lower_hex_32(value, label)?;
    }
    Ok(())
}

fn authorize_session(
    session: &mut StoredSession,
    capability: &str,
    client_ip: IpAddr,
    now: u64,
) -> Result<(), HttpError> {
    if capability.len() != 64 || digest_text(capability) != session.capability_digest {
        return Err(HttpError::new(401, "capability_refused"));
    }
    if session.client_ip != client_ip.to_string() {
        return Err(HttpError::new(403, "client_ip_refused"));
    }
    if session.revoked_at.is_some() {
        return Err(HttpError::new(410, "session_revoked"));
    }
    if now >= session.expires_at {
        return Err(HttpError::new(410, "session_expired"));
    }
    Ok(())
}

fn charge_session(session: &mut StoredSession, now: u64) -> Result<(), HttpError> {
    if now.saturating_sub(session.request_window_started_at) >= RATE_WINDOW_SECONDS {
        session.request_window_started_at = now;
        session.request_count = 0;
    }
    if session.request_count >= MAX_REQUESTS_PER_SESSION {
        return Err(HttpError::retry(
            RATE_WINDOW_SECONDS.saturating_sub(now - session.request_window_started_at),
        ));
    }
    session.request_count += 1;
    Ok(())
}

fn charge_ip(config: &GatewayConfig, client_ip: IpAddr, now: u64) -> Result<(), HttpError> {
    let key = digest_text(&client_ip.to_string());
    let mut lock = SessionLock::acquire_named(&config.root, &format!("ip-{key}"))
        .map_err(|_| HttpError::new(503, "rate_state_busy"))?;
    let path = config.root.join("rates").join(format!("{key}.json"));
    let mut state = load_optional_json::<IpRateState>(&path)
        .map_err(|_| HttpError::new(500, "rate_state_unavailable"))?
        .unwrap_or(IpRateState {
            schema: "openagents.immortal.public-regtest-ip-rate.v1".to_owned(),
            client_ip: client_ip.to_string(),
            window_started_at: now,
            sessions_created: 0,
        });
    if state.client_ip != client_ip.to_string() {
        return Err(HttpError::new(500, "rate_state_unavailable"));
    }
    if now.saturating_sub(state.window_started_at) >= RATE_WINDOW_SECONDS {
        state.window_started_at = now;
        state.sessions_created = 0;
    }
    if state.sessions_created >= MAX_SESSIONS_PER_IP_WINDOW {
        return Err(HttpError::retry(
            RATE_WINDOW_SECONDS.saturating_sub(now - state.window_started_at),
        ));
    }
    state.sessions_created += 1;
    write_json(&path, &state).map_err(|_| HttpError::new(500, "rate_state_unavailable"))?;
    lock.release();
    Ok(())
}

fn charge_effect_rate(root: &Path, now: u64) -> Result<(), String> {
    let path = root.join("effect-rate.json");
    let mut state = load_optional_json::<EffectRateState>(&path)?.unwrap_or(EffectRateState {
        schema: "openagents.immortal.public-regtest-effect-rate.v1".to_owned(),
        window_started_at: now,
        effects_authorized: 0,
    });
    if state.schema != "openagents.immortal.public-regtest-effect-rate.v1" {
        return Err("public regtest effect-rate schema changed".to_owned());
    }
    if now.saturating_sub(state.window_started_at) >= RATE_WINDOW_SECONDS {
        state.window_started_at = now;
        state.effects_authorized = 0;
    }
    if state.effects_authorized >= MAX_EFFECTS_PER_WINDOW {
        return Err("public regtest global effect rate is exhausted".to_owned());
    }
    state.effects_authorized += 1;
    write_json(&path, &state)
}

fn read_http_request(stream: &mut TcpStream, peer: SocketAddr) -> Result<HttpRequest, HttpError> {
    let bytes = read_bounded_request(stream)?;
    let split =
        find_subsequence(&bytes, b"\r\n\r\n").ok_or_else(|| HttpError::new(400, "invalid_http"))?;
    let head =
        std::str::from_utf8(&bytes[..split]).map_err(|_| HttpError::new(400, "invalid_utf8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpError::new(400, "invalid_http"))?;
    let parts = request_line.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" || !parts[1].starts_with('/') {
        return Err(HttpError::new(400, "invalid_http"));
    }
    let mut headers = BTreeMap::<String, String>::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpError::new(400, "invalid_http"))?;
        let name = name.to_ascii_lowercase();
        if headers.insert(name, value.trim().to_owned()).is_some() {
            return Err(HttpError::new(400, "duplicate_header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(HttpError::new(400, "transfer_encoding_refused"));
    }
    let declared = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| HttpError::new(400, "invalid_body_length"))?
        .unwrap_or(0);
    let body = bytes[split + 4..].to_vec();
    if declared != body.len() || declared > MAX_REQUEST_BYTES {
        return Err(HttpError::new(400, "invalid_body_length"));
    }
    if !peer.ip().is_loopback() {
        return Err(HttpError::new(403, "untrusted_proxy"));
    }
    let client_ip = headers
        .get("x-immortal-client-ip")
        .ok_or_else(|| HttpError::new(400, "client_ip_required"))?
        .parse::<IpAddr>()
        .map_err(|_| HttpError::new(400, "invalid_client_ip"))?;
    if client_ip.is_unspecified() || client_ip.is_multicast() {
        return Err(HttpError::new(400, "invalid_client_ip"));
    }
    Ok(HttpRequest {
        method: parts[0].to_owned(),
        path: parts[1].to_owned(),
        origin: headers.get("origin").cloned(),
        authorization: headers.get("authorization").cloned(),
        client_ip,
        content_type: headers.get("content-type").cloned(),
        body,
    })
}

fn read_bounded_request(stream: &mut TcpStream) -> Result<Vec<u8>, HttpError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| HttpError::new(408, "request_timeout"))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(HttpError::new(413, "request_too_large"));
        }
        if let Some(split) = find_subsequence(&bytes, b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..split])
                .map_err(|_| HttpError::new(400, "invalid_utf8"))?;
            let length = head
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .transpose()
                .map_err(|_| HttpError::new(400, "invalid_body_length"))?
                .unwrap_or(0);
            if bytes.len() == split + 4 + length {
                break;
            }
            if bytes.len() > split + 4 + length {
                return Err(HttpError::new(400, "invalid_body_length"));
            }
        }
    }
    Ok(bytes)
}

fn write_error(stream: &mut TcpStream, origin: &str, error: HttpError) -> Result<(), String> {
    let body = json!({
        "schema":ERROR_SCHEMA,
        "code":error.code,
        "retryable":error.status == 429 || error.status == 503 || error.status == 504,
        "retry_after_seconds":error.retry_after_seconds,
    });
    write_json_response_string(stream, error.status, origin, &body)
        .map_err(|_| "write failed".to_owned())
}

fn write_serialized_response<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    value: &T,
) -> Result<(), HttpError> {
    let body = serde_json::to_vec(value).map_err(|_| HttpError::new(500, "internal_error"))?;
    write_bytes_response(stream, status, origin, &body)
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    value: &Value,
) -> Result<(), HttpError> {
    let body = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(value).map_err(|_| HttpError::new(500, "internal_error"))?
    };
    write_bytes_response(stream, status, origin, &body)
}

fn write_json_response_string(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    value: &Value,
) -> Result<(), HttpError> {
    write_json_response(stream, status, origin, value)
}

fn write_bytes_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    body: &[u8],
) -> Result<(), HttpError> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => return Err(HttpError::new(500, "internal_error")),
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, X-Immortal-Client-IP\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|_| HttpError::new(500, "internal_error"))
}

fn require_json(request: &HttpRequest) -> Result<(), HttpError> {
    if request.content_type.as_deref() == Some("application/json") {
        Ok(())
    } else {
        Err(HttpError::new(415, "content_type_refused"))
    }
}

fn require_capability(request: &HttpRequest) -> Result<&str, HttpError> {
    let value = request
        .authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("ImmortalRegtest "))
        .ok_or_else(|| HttpError::new(401, "capability_required"))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HttpError::new(401, "capability_refused"));
    }
    Ok(value)
}

fn parse_closed_json<T: DeserializeOwned>(bytes: &[u8], subject: &str) -> Result<T, HttpError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpError::new(400, "invalid_utf8"))?;
    let value = parse_json_without_duplicate_members(text, subject)
        .map_err(|_| HttpError::new(400, "invalid_json"))?;
    serde_json::from_value(value).map_err(|_| HttpError::new(400, "invalid_json"))
}

fn parse_session_path(path: &str) -> Option<(&str, &str)> {
    let remainder = path.strip_prefix("/v1/public-regtest/sessions/")?;
    if let Some(session) = remainder.strip_suffix("/effects") {
        validate_lower_hex_32(session, "path session").ok()?;
        return Some((session, "/effects"));
    }
    if let Some(session) = remainder.strip_suffix("/requests") {
        validate_lower_hex_32(session, "path session").ok()?;
        return Some((session, "/requests"));
    }
    if let Some(session) = remainder.strip_suffix("/inputs") {
        validate_lower_hex_32(session, "path session").ok()?;
        return Some((session, "/inputs"));
    }
    validate_lower_hex_32(remainder, "path session").ok()?;
    Some((remainder, ""))
}

fn unix_now_http() -> Result<u64, HttpError> {
    unix_now().map_err(|_| HttpError::new(500, "clock_unavailable"))
}

impl GatewayConfig {
    fn from_env() -> Result<Self, String> {
        let root = state_root()?;
        let bind = std::env::var("IMMORTAL_PUBLIC_REGTEST_GATEWAY_BIND")
            .unwrap_or_else(|_| "127.0.0.1:19337".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| "public regtest gateway bind must be numeric".to_owned())?;
        if !bind.ip().is_loopback() || !matches!(bind.ip(), IpAddr::V4(_)) {
            return Err("public regtest gateway must bind IPv4 loopback behind TLS".to_owned());
        }
        let origin = required_env("IMMORTAL_PUBLIC_REGTEST_ORIGIN")?;
        validate_https_origin(&origin)?;
        let key_path = PathBuf::from(required_env("IMMORTAL_PUBLIC_REGTEST_SIGNING_KEY_FILE")?);
        let signer = load_signer(&key_path)?;
        let lifetime_seconds = bounded_env(
            "IMMORTAL_PUBLIC_REGTEST_SESSION_LIFETIME_SECONDS",
            900,
            1,
            3_600,
        )?;
        let effect_timeout = Duration::from_secs(bounded_env(
            "IMMORTAL_PUBLIC_REGTEST_EFFECT_TIMEOUT_SECONDS",
            180,
            1,
            900,
        )?);
        let source_revision = required_env("IMMORTAL_PUBLIC_REGTEST_SOURCE_REVISION")?;
        if source_revision.len() != 40
            || !source_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("public regtest source revision is not lower hex-20".to_owned());
        }
        let requester_contract_digest =
            required_lower_hex_env("IMMORTAL_PUBLIC_REGTEST_REQUESTER_CONTRACT_DIGEST")?;
        let mut provider_set = required_env("IMMORTAL_PUBLIC_REGTEST_PROVIDER_SET")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if provider_set.is_empty() || provider_set.len() > 8 {
            return Err("public regtest provider set is outside 1..=8".to_owned());
        }
        for provider in &provider_set {
            validate_lower_hex_32(provider, "configured provider")?;
        }
        provider_set.sort();
        provider_set.dedup();
        Ok(Self {
            root,
            bind,
            origin,
            signer,
            lifetime_seconds,
            effect_timeout,
            source_revision,
            requester_contract_digest,
            provider_set,
            metrics: Arc::new(GatewayMetrics::default()),
        })
    }
}

fn state_root() -> Result<PathBuf, String> {
    let root = PathBuf::from(required_env("IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR")?);
    if !root.is_absolute() {
        return Err("public regtest gateway state path must be absolute".to_owned());
    }
    Ok(root)
}

fn prepare_root(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|error| format!("could not create gateway state: {error}"))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect gateway state: {error}"))?;
    for child in ["sessions", "rates", "locks"] {
        let path = root.join(child);
        fs::create_dir_all(&path)
            .map_err(|error| format!("could not create gateway {child}: {error}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not protect gateway {child}: {error}"))?;
    }
    Ok(())
}

fn recover_gateway_locks(root: &Path) -> Result<(), String> {
    let locks = root.join("locks");
    for _ in 0..LOCK_ATTEMPTS {
        if fs::read_dir(&locks)
            .map_err(|error| format!("could not inspect gateway locks: {error}"))?
            .next()
            .is_none()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    for entry in fs::read_dir(&locks)
        .map_err(|error| format!("could not inspect stale gateway locks: {error}"))?
    {
        let entry = entry.map_err(|error| format!("could not inspect stale lock: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("could not inspect stale lock type: {error}"))?
            .is_dir()
        {
            return Err("gateway lock directory contains a non-directory".to_owned());
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| "gateway lock name is not UTF-8".to_owned())?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("gateway lock name is outside the owned grammar".to_owned());
        }
        fs::remove_dir(entry.path())
            .map_err(|error| format!("could not recover stale gateway lock: {error}"))?;
    }
    Ok(())
}

fn load_signer(path: &Path) -> Result<RelaySigner, String> {
    if !path.is_absolute() {
        return Err("public regtest signing key path must be absolute".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect gateway signing key: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
    {
        return Err("public regtest signing key must be a private regular file".to_owned());
    }
    let secret = fs::read_to_string(path)
        .map_err(|error| format!("could not read gateway signing key: {error}"))?;
    RelaySigner::from_secret_hex(secret.trim())
        .map_err(|_| "public regtest signing key is invalid".to_owned())
}

fn validate_https_origin(origin: &str) -> Result<(), String> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or_else(|| "public regtest origin must use HTTPS".to_owned())?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return Err("public regtest origin must be one exact HTTPS authority".to_owned());
    }
    Ok(())
}

fn bounded_env(name: &str, default: u64, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| format!("{name} must be an integer"))?
        .unwrap_or(default);
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} is outside {minimum}..={maximum}"));
    }
    Ok(value)
}

fn required_env(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() || value.len() > 4_096 || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!("{name} is empty or unbounded"));
    }
    Ok(value)
}

fn required_lower_hex_env(name: &str) -> Result<String, String> {
    let value = required_env(name)?;
    validate_lower_hex_32(&value, name)?;
    Ok(value)
}

fn validate_lower_hex_32(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("public regtest {label} is not lower hex-32"));
    }
    Ok(())
}

fn digest_text(value: &str) -> String {
    lower_hex(&Sha256::digest(value.as_bytes()))
}

fn session_dir(root: &Path, session_id: &str) -> PathBuf {
    root.join("sessions").join(session_id)
}

fn session_path(root: &Path, session_id: &str) -> PathBuf {
    session_dir(root, session_id).join("session.json")
}

fn admission_path(root: &Path, session_id: &str, effect_id: &str) -> PathBuf {
    session_dir(root, session_id).join(format!("admission-{effect_id}.json"))
}

fn receipt_path(root: &Path, session_id: &str, effect_id: &str) -> PathBuf {
    session_dir(root, session_id).join(format!("receipt-{effect_id}.json"))
}

fn dynamic_request_path(root: &Path, session_id: &str) -> PathBuf {
    session_dir(root, session_id).join("private-dynamic-request.json")
}

fn demo_input_request_path(root: &Path, session_id: &str) -> PathBuf {
    session_dir(root, session_id).join("demo-input-request.json")
}

fn demo_input_response_path(root: &Path, session_id: &str) -> PathBuf {
    session_dir(root, session_id).join("demo-input-response.json")
}

fn load_session(root: &Path, session_id: &str) -> Result<Option<StoredSession>, String> {
    let value = load_optional_json::<StoredSession>(&session_path(root, session_id))?;
    if let Some(session) = &value {
        if session.schema != SESSION_SCHEMA || session.sandbox_session_id != session_id {
            return Err("public regtest session state is invalid".to_owned());
        }
    }
    Ok(value)
}

fn store_session_create_new(root: &Path, session: &StoredSession) -> Result<(), String> {
    let directory = session_dir(root, &session.sandbox_session_id);
    fs::create_dir(&directory)
        .map_err(|error| format!("could not create public session: {error}"))?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect public session: {error}"))?;
    write_json_create_new(&session_path(root, &session.sandbox_session_id), session)
}

fn store_session(root: &Path, session: &StoredSession) -> Result<(), String> {
    write_json(&session_path(root, &session.sandbox_session_id), session)
}

fn load_receipt(
    root: &Path,
    session_id: &str,
    effect_id: &str,
) -> Result<Option<PublicEffectReceipt>, String> {
    let receipt =
        load_optional_json::<PublicEffectReceipt>(&receipt_path(root, session_id, effect_id))?;
    if let Some(receipt) = &receipt {
        validate_public_receipt(receipt)?;
        if receipt.sandbox_session_id != session_id || receipt.effect_id != effect_id {
            return Err("public receipt path binding changed".to_owned());
        }
    }
    Ok(receipt)
}

fn load_optional_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err(format!("{} is empty or unbounded", path.display()));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let value = parse_json_without_duplicate_members(text, "public regtest state")?;
    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| format!("{} is invalid: {error}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = encoded_json(path, value)?;
    let parent = path
        .parent()
        .ok_or_else(|| "state path has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create state parent: {error}"))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not persist {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("could not install {}: {error}", path.display()))
}

fn write_json_create_new<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = encoded_json(path, value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not persist {}: {error}", path.display()))
}

fn encoded_json<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("could not encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STATE_BYTES {
        return Err(format!("{} would exceed its state bound", path.display()));
    }
    Ok(bytes)
}

struct SessionLock {
    path: PathBuf,
    held: bool,
}

impl SessionLock {
    fn acquire(root: &Path, session_id: &str) -> Result<Self, String> {
        validate_lower_hex_32(session_id, "lock session")?;
        Self::acquire_named(root, session_id)
    }

    fn acquire_named(root: &Path, name: &str) -> Result<Self, String> {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("public regtest lock name is invalid".to_owned());
        }
        let path = root.join("locks").join(name);
        for _ in 0..LOCK_ATTEMPTS {
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .map_err(|error| format!("could not protect session lock: {error}"))?;
                    return Ok(Self { path, held: true });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(format!("could not acquire session lock: {error}")),
            }
        }
        Err("public regtest session lock timed out".to_owned())
    }

    fn release(&mut self) {
        if self.held {
            let _ = fs::remove_dir(&self.path);
            self.held = false;
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        self.release();
    }
}

fn validate_contract() -> Result<(), String> {
    let contract: Value = serde_json::from_str(CONTRACT)
        .map_err(|error| format!("public gateway contract is invalid: {error}"))?;
    if contract.get("schema").and_then(Value::as_str) != Some(CONTRACT_SCHEMA)
        || contract.get("network").and_then(Value::as_str) != Some(REGTEST_NETWORK)
        || contract
            .pointer("/gateway/default_bind")
            .and_then(Value::as_str)
            != Some("127.0.0.1:19337")
        || contract
            .pointer("/gateway/maximum_request_bytes")
            .and_then(Value::as_u64)
            != Some(MAX_REQUEST_BYTES as u64)
        || contract
            .pointer("/session/maximum_effects")
            .and_then(Value::as_u64)
            != Some(u64::from(MAX_EFFECTS_PER_SESSION))
        || contract
            .pointer("/session/maximum_concurrent_effects")
            .and_then(Value::as_u64)
            != Some(u64::from(MAX_CONCURRENT_EFFECTS_PER_SESSION))
        || contract
            .pointer("/session/maximum_amount_sat")
            .and_then(Value::as_u64)
            != Some(MAX_AMOUNT_SAT)
        || contract
            .pointer("/claims/dynamic_inputs")
            .and_then(Value::as_bool)
            != Some(true)
        || !contract
            .pointer("/gateway/endpoints")
            .and_then(Value::as_array)
            .is_some_and(|endpoints| {
                endpoints.iter().any(|endpoint| {
                    endpoint.as_str()
                        == Some("POST /v1/public-regtest/sessions/{session_id}/requests")
                })
            })
        || !contract
            .pointer("/gateway/endpoints")
            .and_then(Value::as_array)
            .is_some_and(|endpoints| {
                endpoints.iter().any(|endpoint| {
                    endpoint.as_str()
                        == Some("POST /v1/public-regtest/sessions/{session_id}/inputs")
                })
            })
    {
        return Err("public gateway fixture differs from executable limits".to_owned());
    }
    Ok(())
}

fn validate_service_contract() -> Result<(), String> {
    let contract: Value = serde_json::from_str(SERVICE_CONTRACT)
        .map_err(|error| format!("public service contract is invalid: {error}"))?;
    if contract.get("schema").and_then(Value::as_str) != Some(SERVICE_CONTRACT_SCHEMA)
        || contract.get("network").and_then(Value::as_str) != Some(REGTEST_NETWORK)
        || contract
            .pointer("/concurrency/maximum_active_sessions")
            .and_then(Value::as_u64)
            != u64::try_from(MAX_ACTIVE_SESSIONS).ok()
        || contract
            .pointer("/concurrency/maximum_connections")
            .and_then(Value::as_u64)
            != u64::try_from(MAX_CONNECTIONS).ok()
        || contract
            .pointer("/concurrency/maximum_outstanding_sat")
            .and_then(Value::as_u64)
            != Some(MAX_OUTSTANDING_SAT)
        || contract
            .pointer("/concurrency/maximum_effects_per_minute")
            .and_then(Value::as_u64)
            != Some(u64::from(MAX_EFFECTS_PER_WINDOW))
        || contract
            .pointer("/operator/readiness_maximum_age_seconds")
            .and_then(Value::as_u64)
            != Some(READINESS_MAXIMUM_AGE_SECONDS)
    {
        return Err("public service fixture differs from executable limits".to_owned());
    }
    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

fn reject_custody_material(value: &Value) -> Result<(), String> {
    fn walk(value: &Value) -> Result<(), String> {
        match value {
            Value::Object(object) => {
                for (key, nested) in object {
                    let normalized = key
                        .chars()
                        .filter(|character| character.is_ascii_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect::<String>();
                    if [
                        "rawtransaction",
                        "invoice",
                        "preimage",
                        "walletseed",
                        "privatekey",
                        "secret",
                        "macaroon",
                        "rpcpassword",
                        "credential",
                    ]
                    .iter()
                    .any(|forbidden| normalized.contains(forbidden))
                    {
                        return Err(format!(
                            "public manifest contains forbidden custody key {key:?}"
                        ));
                    }
                    walk(nested)?;
                }
            }
            Value::Array(values) => {
                for nested in values {
                    walk(nested)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_config() -> GatewayConfig {
        let root = std::env::temp_dir().join(format!(
            "immortal-public-regtest-service-test-{}",
            lower_hex(&random_32().expect("test entropy"))
        ));
        prepare_root(&root).expect("prepare service root");
        GatewayConfig {
            root,
            bind: "127.0.0.1:19337".parse().unwrap(),
            origin: "https://demo.example".to_owned(),
            signer: RelaySigner::from_secret_hex(&"01".repeat(32)).unwrap(),
            lifetime_seconds: 300,
            effect_timeout: Duration::from_secs(1),
            source_revision: "ab".repeat(20),
            requester_contract_digest: "cd".repeat(32),
            provider_set: vec!["ef".repeat(32)],
            metrics: Arc::new(GatewayMetrics::default()),
        }
    }

    fn publish_test_readiness(config: &GatewayConfig, checked_at: u64) {
        write_json(
            &config.root.join("readiness.json"),
            &ServiceReadiness {
                schema: SERVICE_READINESS_SCHEMA.to_owned(),
                ready: true,
                checked_at,
                revision: config.source_revision.clone(),
                failures: vec![],
                active_sessions: 0,
                outstanding_sat: 0,
                provider_pubkeys: config.provider_set.clone(),
                lightning_node_ids: vec![
                    "02".repeat(33),
                    "03".repeat(33),
                    format!("02{}", "44".repeat(32)),
                ],
                bitcoin_height: 101,
                receipt_store_writable: true,
            },
        )
        .expect("write readiness");
    }

    fn effect() -> GatewayEffectRequest {
        GatewayEffectRequest {
            schema: "openagents.immortal.browser-demo-effect.v1".to_owned(),
            network: REGTEST_NETWORK.to_owned(),
            journey: "submarine".to_owned(),
            session_id: "11".repeat(32),
            order_id: "22".repeat(32),
            effect_id: "33".repeat(32),
            idempotency_digest: "44".repeat(32),
            method: "broadcast_bitcoin_funding".to_owned(),
            amount_sat: 100_000,
        }
    }

    #[test]
    fn contract_origin_and_effect_bounds_are_closed() {
        validate_contract().expect("contract");
        validate_service_contract().expect("service contract");
        assert!(validate_https_origin("https://demo.example").is_ok());
        assert!(validate_https_origin("http://demo.example").is_err());
        assert!(validate_https_origin("https://user@demo.example").is_err());
        let mut changed = effect();
        assert!(validate_browser_effect(&changed).is_ok());
        changed.network = "mainnet".to_owned();
        assert!(validate_browser_effect(&changed).is_err());
        changed = effect();
        changed.method = "bitcoin_rpc".to_owned();
        assert!(validate_browser_effect(&changed).is_err());
    }

    #[test]
    fn duplicate_json_and_unknown_members_fail() {
        let duplicate =
            br#"{"schema":"a","schema":"b","requester_identity":"00","client_nonce":"00"}"#;
        assert!(parse_closed_json::<CreateSessionRequest>(duplicate, "test").is_err());
        let unknown = br#"{"schema":"openagents.immortal.public-regtest-session-create.v1","requester_identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","client_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","extra":true}"#;
        assert!(parse_closed_json::<CreateSessionRequest>(unknown, "test").is_err());
    }

    #[test]
    fn demo_input_allocation_is_session_amount_direction_and_expiry_bound() {
        let session_id = "aa".repeat(32);
        let request = DemoInputRequest {
            schema: DEMO_INPUT_REQUEST_SCHEMA.to_owned(),
            sandbox_session_id: session_id.clone(),
            swap_type: "reverse".to_owned(),
            amount_sat: 100_000,
        };
        validate_demo_input_request_value(&session_id, &request).expect("demo input request");
        let response = DemoInputResponse {
            schema: DEMO_INPUT_RESPONSE_SCHEMA.to_owned(),
            sandbox_session_id: session_id.clone(),
            swap_type: "reverse".to_owned(),
            amount_sat: 100_000,
            destination: "bcrt1ptestdestination".to_owned(),
            expires_at: unix_now().unwrap() + 300,
        };
        validate_demo_input_response(&request, &response).expect("demo input response");
        let mut changed = response.clone();
        changed.amount_sat += 1;
        assert!(validate_demo_input_response(&request, &changed).is_err());
        changed = response.clone();
        changed.destination = "lnbcrt1wrongdirection".to_owned();
        assert!(validate_demo_input_response(&request, &changed).is_err());
        changed = response;
        changed.expires_at = unix_now().unwrap() + 601;
        assert!(validate_demo_input_response(&request, &changed).is_err());
    }

    #[test]
    fn dynamic_projection_is_closed_public_safe_and_monotonic() {
        let view = PublicDynamicRequestView {
            schema: DYNAMIC_VIEW_SCHEMA.to_owned(),
            request_id: "11".repeat(32),
            network: REGTEST_NETWORK.to_owned(),
            swap_type: "reverse".to_owned(),
            input_amount_sat: 100_000,
            maximum_total_fee_sat: 5_000,
            destination_kind: "bitcoin_address".to_owned(),
            destination_commitment_sha256: "22".repeat(32),
            destination_amount_sat: None,
            payment_hash: None,
            expires_at: 100,
        };
        validate_dynamic_view(&view).expect("redacted dynamic view");
        let journey = PublicJourney {
            schema: JOURNEY_SCHEMA.to_owned(),
            request_id: view.request_id,
            stage: "completed".to_owned(),
            quote_provider_pubkeys: vec!["33".repeat(32), "44".repeat(32)],
            selected_provider_pubkey: Some("33".repeat(32)),
            unselected_provider_pubkey: Some("44".repeat(32)),
            unselected_released: true,
            provider_status: Some("completed_unverified_claim".to_owned()),
            requester_evidence: vec![
                PublicRailEvidence {
                    rail: "bitcoin".to_owned(),
                    reference: "55".repeat(32),
                    state: "verified".to_owned(),
                },
                PublicRailEvidence {
                    rail: "lightning".to_owned(),
                    reference: "66".repeat(32),
                    state: "verified".to_owned(),
                },
            ],
            error_code: None,
            updated_at: 99,
        };
        validate_public_journey(&journey).expect("public terminal journey");
        assert!(journey_rank("completed").unwrap() > journey_rank("accepted").unwrap());
        let mut changed = journey;
        changed.requester_evidence[0].rail = "wallet_rpc".to_owned();
        assert!(validate_public_journey(&changed).is_err());
    }

    #[test]
    fn capability_is_session_ip_expiry_and_revocation_bound() {
        let capability = "aa".repeat(32);
        let mut session = StoredSession {
            schema: SESSION_SCHEMA.to_owned(),
            sandbox_session_id: "bb".repeat(32),
            requester_identity: "cc".repeat(32),
            client_ip: "198.51.100.10".to_owned(),
            origin: "https://demo.example".to_owned(),
            capability_digest: digest_text(&capability),
            issued_at: 10,
            expires_at: 20,
            revoked_at: None,
            request_window_started_at: 10,
            request_count: 0,
            authorizations: vec![],
            dynamic_request: None,
            requester_engine_identity: None,
            journey: None,
        };
        let ip = "198.51.100.10".parse().unwrap();
        assert!(authorize_session(&mut session, &capability, ip, 19).is_ok());
        assert!(authorize_session(&mut session, &"dd".repeat(32), ip, 19).is_err());
        assert!(
            authorize_session(
                &mut session,
                &capability,
                "198.51.100.11".parse().unwrap(),
                19
            )
            .is_err()
        );
        assert!(authorize_session(&mut session, &capability, ip, 20).is_err());
        session.expires_at = 30;
        session.revoked_at = Some(19);
        assert!(authorize_session(&mut session, &capability, ip, 20).is_err());
    }

    #[test]
    fn manifest_signature_is_canonical_and_public_safe() {
        let root = std::env::temp_dir().join(format!(
            "immortal-public-regtest-manifest-test-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove prior owned test root");
        }
        prepare_root(&root).expect("prepare root");
        let config = GatewayConfig {
            root: root.clone(),
            bind: "127.0.0.1:19337".parse().unwrap(),
            origin: "https://demo.example".to_owned(),
            signer: RelaySigner::from_secret_hex(&"01".repeat(32)).unwrap(),
            lifetime_seconds: 300,
            effect_timeout: Duration::from_secs(1),
            source_revision: "ab".repeat(20),
            requester_contract_digest: "cd".repeat(32),
            provider_set: vec!["ef".repeat(32)],
            metrics: Arc::new(GatewayMetrics::default()),
        };
        let session = StoredSession {
            schema: SESSION_SCHEMA.to_owned(),
            sandbox_session_id: "12".repeat(32),
            requester_identity: "34".repeat(32),
            client_ip: "198.51.100.10".to_owned(),
            origin: config.origin.clone(),
            capability_digest: "56".repeat(32),
            issued_at: 10,
            expires_at: 310,
            revoked_at: None,
            request_window_started_at: 10,
            request_count: 0,
            authorizations: vec![],
            dynamic_request: None,
            requester_engine_identity: None,
            journey: None,
        };
        let signed = signed_manifest(&config, &session).expect("signed manifest");
        signed
            .signature_event
            .validate_crypto()
            .expect("valid signature");
        let decoded: SessionManifest =
            serde_json::from_str(&signed.signature_event.content).expect("manifest content");
        assert_eq!(decoded, signed.manifest);
        fs::remove_dir_all(root).expect("remove owned test root");
    }

    #[test]
    fn readiness_fails_closed_and_service_sustains_qualification_counts() {
        let config = service_config();
        let now = unix_now().expect("clock");
        assert_eq!(
            require_service_ready(&config, now).unwrap_err().code,
            "readiness_unavailable"
        );
        publish_test_readiness(&config, now.saturating_sub(31));
        assert_eq!(
            require_service_ready(&config, now).unwrap_err().code,
            "service_unready"
        );
        publish_test_readiness(&config, now);
        require_service_ready(&config, now).expect("fresh readiness");

        let mut active = Vec::new();
        for number in 1..=5_u8 {
            active.push(
                create_session(
                    &config,
                    format!("198.51.100.{number}").parse().unwrap(),
                    CreateSessionRequest {
                        schema: CREATE_SCHEMA.to_owned(),
                        requester_identity: "11".repeat(32),
                        client_nonce: format!("{number:064x}"),
                    },
                )
                .expect("simultaneous active session"),
            );
        }
        assert_eq!(service_counts(&config.root, now).unwrap().0, 5);
        for response in active {
            let id = response.signed_manifest.manifest.sandbox_session_id;
            let mut state = load_session(&config.root, &id).unwrap().unwrap();
            state.revoked_at = Some(now);
            store_session(&config.root, &state).unwrap();
        }

        for number in 0..50_u8 {
            let response = create_session(
                &config,
                format!("203.0.113.{}", number.saturating_add(1))
                    .parse()
                    .unwrap(),
                CreateSessionRequest {
                    schema: CREATE_SCHEMA.to_owned(),
                    requester_identity: "22".repeat(32),
                    client_nonce: format!("{:064x}", u16::from(number) + 100),
                },
            )
            .expect("sequential qualification session");
            let id = response.signed_manifest.manifest.sandbox_session_id;
            let mut state = load_session(&config.root, &id).unwrap().unwrap();
            state.revoked_at = Some(now);
            store_session(&config.root, &state).unwrap();
        }
        assert_eq!(service_counts(&config.root, now).unwrap(), (0, 0));

        write_json(&config.root.join("maintenance"), &json!({"enabled":true})).unwrap();
        assert_eq!(
            require_service_ready(&config, now).unwrap_err().code,
            "maintenance"
        );
        fs::remove_dir_all(config.root).expect("remove service test root");
    }
}
