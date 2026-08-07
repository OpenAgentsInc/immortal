//! Loopback-only, regtest-only browser bridge for the funded lab.
//!
//! The HTTP process has no node or wallet credentials. It can only copy one
//! exact engine-issued effect request into the private lab state directory;
//! the existing funded harness remains the sole rail executor.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{
    ExternalEffectRequest, FundingAction, FundingAuthorizationRequest, provider_support,
};
use immortal_public_regtest_gateway::{
    self as public_regtest_gateway, GatewayEffectRequest, WorkerEffectReceipt,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::state::LabPaths;

const MANIFEST_SCHEMA: &str = "openagents.immortal.browser-demo-manifest.v1";
const EFFECT_SCHEMA: &str = "openagents.immortal.browser-demo-effect.v1";
const RECEIPT_SCHEMA: &str = "openagents.immortal.browser-demo-effect-receipt.v1";
const REGTEST_NETWORK: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
const MAX_HTTP_BYTES: usize = 16 * 1024;
const MAX_AMOUNT_SAT: u64 = 1_000_000;
const CONTRACT: &str = include_str!("../../../tests/fixtures/lab/browser-demo-v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserEffectRequest {
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
pub struct BrowserEffectReceipt {
    pub schema: String,
    pub request: BrowserEffectRequest,
    pub external_identifier: String,
    pub result_digest: String,
    pub state: String,
    pub admitted_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserJourney {
    swap_type: String,
    session_id: String,
    order_id: String,
    provider_pubkey: String,
    relay_url: String,
    provider_status_claim: Value,
    requester_verification: Value,
    pending_effect: Option<BrowserEffectRequest>,
    effect_receipt: Option<BrowserEffectReceipt>,
    presentation: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserManifest {
    schema: String,
    mode: String,
    warning: String,
    network: String,
    allowed_origin: String,
    active_journey: String,
    requester_pubkey: String,
    journeys: BTreeMap<String, BrowserJourney>,
}

pub struct BrowserSession<'a> {
    pub journey: &'a str,
    pub swap_type: &'a str,
    pub requester_pubkey: &'a str,
    pub provider_pubkey: &'a str,
    pub relay_url: &'a str,
    pub amount_sat: u64,
}

pub fn enabled_for(journey: &str) -> bool {
    std::env::var("IMMORTAL_LAB_BROWSER_DEMO_MODE").as_deref() == Ok("1")
        && matches!(journey, "submarine" | "reverse")
}

pub fn await_engine_effect(
    paths: &LabPaths,
    session: BrowserSession<'_>,
    request: &FundingAuthorizationRequest,
) -> Result<BrowserEffectRequest, String> {
    validate_contract()?;
    if !enabled_for(session.journey) {
        return Err("browser demo effect requested while browser-demo mode is disabled".to_owned());
    }
    if session.amount_sat == 0 || session.amount_sat > MAX_AMOUNT_SAT {
        return Err("browser demo amount is outside the funded-regtest bound".to_owned());
    }
    if request.session_id.is_empty() || request.order_id.is_empty() {
        return Err("browser demo received an unbound engine request".to_owned());
    }
    let method = match &request.action {
        FundingAction::BroadcastBitcoin { .. } => "broadcast_bitcoin_funding",
        FundingAction::PayLightningInvoice { .. } => "pay_lightning_invoice",
        FundingAction::BroadcastLiquid { .. } => {
            return Err("browser demo does not expose Liquid effects".to_owned());
        }
    };
    let effect = BrowserEffectRequest {
        schema: EFFECT_SCHEMA.to_owned(),
        network: REGTEST_NETWORK.to_owned(),
        journey: session.journey.to_owned(),
        session_id: request.session_id.clone(),
        order_id: request.order_id.clone(),
        effect_id: request.action.effect_id().to_owned(),
        idempotency_digest: ExternalEffectRequest::Funding(request.clone())
            .sha256()
            .map_err(|error| format!("could not bind browser effect digest: {error}"))?,
        method: method.to_owned(),
        amount_sat: session.amount_sat,
    };
    validate_effect(&effect)?;
    if let Ok(sandbox_session_id) = std::env::var("IMMORTAL_PUBLIC_REGTEST_SESSION_ID") {
        public_regtest_gateway::await_admission(
            &sandbox_session_id,
            session.requester_pubkey,
            session.provider_pubkey,
            &gateway_effect(&effect),
        )?;
        return Ok(effect);
    }
    let allowed_origin = allowed_origin()?;
    let mut manifest = load_manifest(paths)?.unwrap_or(BrowserManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        mode: "unsafe_local_funded_regtest_demo".to_owned(),
        warning: "disposable loopback regtest only; never expose or reuse this adapter".to_owned(),
        network: REGTEST_NETWORK.to_owned(),
        allowed_origin: allowed_origin.clone(),
        active_journey: session.journey.to_owned(),
        requester_pubkey: session.requester_pubkey.to_owned(),
        journeys: BTreeMap::new(),
    });
    if manifest.allowed_origin != allowed_origin
        || manifest.network != REGTEST_NETWORK
        || manifest.requester_pubkey != session.requester_pubkey
    {
        return Err("browser demo manifest changed origin, network, or requester".to_owned());
    }
    manifest.active_journey = session.journey.to_owned();
    manifest.journeys.insert(
        session.journey.to_owned(),
        BrowserJourney {
            swap_type: session.swap_type.to_owned(),
            session_id: request.session_id.clone(),
            order_id: request.order_id.clone(),
            provider_pubkey: session.provider_pubkey.to_owned(),
            relay_url: session.relay_url.to_owned(),
            provider_status_claim: json!({"state":"funding_requested","verified":false}),
            requester_verification: json!({
                "state":"effect_authorized",
                "engine":"immortal-client",
                "independent_rail_evidence":[],
            }),
            pending_effect: Some(effect.clone()),
            effect_receipt: load_receipt(paths, &effect.effect_id)?,
            presentation: json!({"settled_allowed":false}),
        },
    );
    store_manifest(paths, &manifest)?;

    if let Some(receipt) = load_receipt(paths, &effect.effect_id)? {
        if receipt.request != effect {
            return Err(
                "persisted browser effect receipt conflicts with the engine request".to_owned(),
            );
        }
        return Ok(effect);
    }
    let deadline = Instant::now() + request_timeout()?;
    loop {
        if let Some(submitted) = load_request(paths, &effect.effect_id)? {
            if submitted != effect {
                return Err("browser submitted a changed engine effect".to_owned());
            }
            return Ok(effect);
        }
        if Instant::now() >= deadline {
            return Err("browser did not authorize the bounded effect before timeout".to_owned());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn record_engine_effect(
    paths: &LabPaths,
    request: &BrowserEffectRequest,
    external_identifier: &str,
    result_digest: &str,
) -> Result<(), String> {
    validate_effect(request)?;
    validate_lower_hex_32(external_identifier, "external identifier")?;
    validate_lower_hex_32(result_digest, "result digest")?;
    let candidate = BrowserEffectReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        request: request.clone(),
        external_identifier: external_identifier.to_owned(),
        result_digest: result_digest.to_owned(),
        state: "admitted".to_owned(),
        admitted_at: unix_now()?,
    };
    if let Ok(sandbox_session_id) = std::env::var("IMMORTAL_PUBLIC_REGTEST_SESSION_ID") {
        public_regtest_gateway::record_receipt(
            &sandbox_session_id,
            &WorkerEffectReceipt {
                schema: candidate.schema.clone(),
                request: gateway_effect(&candidate.request),
                external_identifier: candidate.external_identifier.clone(),
                result_digest: candidate.result_digest.clone(),
                state: candidate.state.clone(),
                admitted_at: candidate.admitted_at,
            },
        )?;
        return Ok(());
    }
    let receipt = if let Some(existing) = load_receipt(paths, &request.effect_id)? {
        if existing != candidate
            && (existing.request != candidate.request
                || existing.external_identifier != candidate.external_identifier
                || existing.result_digest != candidate.result_digest
                || existing.state != candidate.state)
        {
            return Err("browser effect receipt conflicts with its durable replay".to_owned());
        }
        existing
    } else {
        write_json(&receipt_path(paths, &request.effect_id), &candidate)?;
        candidate
    };
    let mut manifest = load_manifest(paths)?
        .ok_or_else(|| "browser demo has no public manifest for its receipt".to_owned())?;
    let journey = manifest
        .journeys
        .get_mut(&request.journey)
        .ok_or_else(|| "browser demo receipt belongs to an unknown journey".to_owned())?;
    if journey.pending_effect.as_ref() != Some(request) {
        return Err("browser demo receipt differs from the active effect".to_owned());
    }
    journey.effect_receipt = Some(receipt);
    journey.requester_verification = json!({
        "state":"effect_admitted",
        "engine":"immortal-client",
        "independent_rail_evidence":[],
    });
    store_manifest(paths, &manifest)
}

pub fn record_terminal(paths: &LabPaths, journey_name: &str, result: &Value) -> Result<(), String> {
    if !enabled_for(journey_name) {
        return Ok(());
    }
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("browser terminal evidence contains custody material: {error}"))?;
    let mut manifest = load_manifest(paths)?
        .ok_or_else(|| "browser demo has no manifest at terminal state".to_owned())?;
    let journey = manifest
        .journeys
        .get_mut(journey_name)
        .ok_or_else(|| "browser terminal evidence belongs to an unknown journey".to_owned())?;
    if journey.effect_receipt.is_none() {
        return Err("browser demo cannot present settlement before the effect receipt".to_owned());
    }
    journey.pending_effect = None;
    journey.provider_status_claim = json!({"state":"completed","verified":false});
    journey.requester_verification = json!({
        "state":"terminal_rail_evidence_verified",
        "engine":"immortal-client",
        "independent_rail_evidence":[
            {"rail":"bitcoin","lockup_txid":required_result(result,"lockup_txid")?,"claim_txid":required_result(result,"claim_txid")?},
            {"rail":"lightning","payment_hash":required_result(result,"payment_hash")?,"state":"paid"}
        ],
    });
    journey.presentation = json!({"settled_allowed":true});
    store_manifest(paths, &manifest)
}

pub fn run_server() -> Result<Value, String> {
    validate_contract()?;
    let address = bind_address()?;
    let origin = allowed_origin()?;
    let paths = LabPaths::from_env();
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("could not bind browser demo adapter: {error}"))?;
    eprintln!("immortal-lab: browser demo adapter listening on http://{address}");
    for incoming in listener.incoming() {
        let mut stream =
            incoming.map_err(|error| format!("browser demo accept failed: {error}"))?;
        if let Err(error) = handle_request(&mut stream, &paths, &origin) {
            let _ = write_response(&mut stream, 500, &origin, &json!({"error":error}));
        }
    }
    Ok(json!({"schema":"openagents.immortal.browser-demo-server.v1","stopped":true}))
}

fn handle_request(stream: &mut TcpStream, paths: &LabPaths, origin: &str) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("could not bound browser request: {error}"))?;
    let bytes = read_request(stream)?;
    let split = find_subsequence(&bytes, b"\r\n\r\n")
        .ok_or_else(|| "browser request has no header terminator".to_owned())?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "browser request headers are not UTF-8".to_owned())?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "browser request is empty".to_owned())?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return write_response(
            stream,
            400,
            origin,
            &json!({"error":"invalid_request_line"}),
        );
    }
    let mut request_origin = None;
    let mut content_length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "browser request has a malformed header".to_owned())?;
        match name.to_ascii_lowercase().as_str() {
            "origin" if request_origin.replace(value.trim()).is_some() => {
                return write_response(stream, 400, origin, &json!({"error":"ambiguous_origin"}));
            }
            "origin" => {}
            "content-length" if content_length.replace(value.trim()).is_some() => {
                return write_response(stream, 400, origin, &json!({"error":"ambiguous_length"}));
            }
            "content-length" => {}
            "content-type" => content_type = Some(value.trim()),
            "transfer-encoding" => {
                return write_response(
                    stream,
                    400,
                    origin,
                    &json!({"error":"transfer_encoding_refused"}),
                );
            }
            _ => {}
        }
    }
    if request_origin != Some(origin) {
        return write_response(stream, 403, origin, &json!({"error":"origin_refused"}));
    }
    if method == "OPTIONS" && matches!(path, "/v1/session" | "/v1/effects") {
        return write_response(stream, 204, origin, &Value::Null);
    }
    if method == "GET" && path == "/v1/session" {
        let Some(manifest) = load_manifest(paths)? else {
            return write_response(stream, 404, origin, &json!({"error":"session_not_ready"}));
        };
        return write_response(
            stream,
            200,
            origin,
            &serde_json::to_value(manifest)
                .map_err(|error| format!("could not encode browser manifest: {error}"))?,
        );
    }
    if method != "POST" || path != "/v1/effects" {
        return write_response(stream, 404, origin, &json!({"error":"unknown_method"}));
    }
    if content_type != Some("application/json") {
        return write_response(
            stream,
            415,
            origin,
            &json!({"error":"content_type_refused"}),
        );
    }
    let declared = content_length
        .ok_or_else(|| "browser effect request has no Content-Length".to_owned())?
        .parse::<usize>()
        .map_err(|_| "browser effect Content-Length is invalid".to_owned())?;
    let body = &bytes[split + 4..];
    if declared != body.len() || declared > MAX_HTTP_BYTES {
        return write_response(stream, 400, origin, &json!({"error":"invalid_body_length"}));
    }
    let effect: BrowserEffectRequest = match serde_json::from_slice(body) {
        Ok(effect) => effect,
        Err(_) => return write_response(stream, 400, origin, &json!({"error":"invalid_effect"})),
    };
    if validate_effect(&effect).is_err() {
        return write_response(stream, 400, origin, &json!({"error":"invalid_effect"}));
    }
    if let Some(receipt) = load_receipt(paths, &effect.effect_id)? {
        if receipt.request != effect {
            return write_response(stream, 409, origin, &json!({"error":"receipt_conflict"}));
        }
        return write_response(
            stream,
            200,
            origin,
            &serde_json::to_value(receipt)
                .map_err(|error| format!("could not encode browser receipt: {error}"))?,
        );
    }
    let manifest = load_manifest(paths)?
        .ok_or_else(|| "browser effect arrived before the session manifest".to_owned())?;
    let expected = manifest
        .journeys
        .get(&manifest.active_journey)
        .and_then(|journey| journey.pending_effect.as_ref());
    if expected != Some(&effect) {
        return write_response(stream, 409, origin, &json!({"error":"effect_conflict"}));
    }
    if let Some(previous) = load_request(paths, &effect.effect_id)? {
        if previous != effect {
            return write_response(stream, 409, origin, &json!({"error":"effect_conflict"}));
        }
    } else {
        write_json(&request_path(paths, &effect.effect_id), &effect)?;
    }
    let deadline = Instant::now() + request_timeout()?;
    loop {
        if let Some(receipt) = load_receipt(paths, &effect.effect_id)? {
            if receipt.request != effect {
                return write_response(stream, 409, origin, &json!({"error":"receipt_conflict"}));
            }
            return write_response(
                stream,
                200,
                origin,
                &serde_json::to_value(receipt)
                    .map_err(|error| format!("could not encode browser receipt: {error}"))?,
            );
        }
        if Instant::now() >= deadline {
            return write_response(stream, 504, origin, &json!({"error":"effect_timeout"}));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("could not read browser request: {error}"))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_HTTP_BYTES {
            return Err("browser request exceeds its byte bound".to_owned());
        }
        if let Some(split) = find_subsequence(&bytes, b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..split])
                .map_err(|_| "browser request headers are not UTF-8".to_owned())?;
            let length = head
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
                .transpose()
                .map_err(|_| "browser Content-Length is invalid".to_owned())?
                .unwrap_or(0);
            if bytes.len() == split + 4 + length {
                break;
            }
            if bytes.len() > split + 4 + length {
                return Err("browser request exceeds its declared body".to_owned());
            }
        }
    }
    Ok(bytes)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    value: &Value,
) -> Result<(), String> {
    let reason = match status {
        204 => "No Content",
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        504 => "Gateway Timeout",
        _ => return Err("browser adapter attempted an unsupported response".to_owned()),
    };
    let body = if status == 204 {
        Vec::new()
    } else {
        serde_json::to_vec(value)
            .map_err(|error| format!("could not encode browser response: {error}"))?
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .map_err(|error| format!("could not write browser response: {error}"))
}

fn bind_address() -> Result<SocketAddr, String> {
    let value = std::env::var("IMMORTAL_LAB_BROWSER_DEMO_BIND")
        .unwrap_or_else(|_| "127.0.0.1:19336".to_owned());
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "browser demo bind must be a numeric socket address".to_owned())?;
    if !address.ip().is_loopback() || !matches!(address.ip(), IpAddr::V4(_)) {
        return Err("browser demo bind must be IPv4 loopback".to_owned());
    }
    Ok(address)
}

fn allowed_origin() -> Result<String, String> {
    let origin = std::env::var("IMMORTAL_LAB_BROWSER_DEMO_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned());
    let authority = origin
        .strip_prefix("http://")
        .ok_or_else(|| "browser demo origin must use loopback HTTP".to_owned())?;
    if authority.contains('/')
        || authority.contains('@')
        || authority.contains('#')
        || authority.contains('?')
    {
        return Err(
            "browser demo origin must be an exact origin without path or credentials".to_owned(),
        );
    }
    let address = authority.parse::<SocketAddr>().map_err(|_| {
        "browser demo origin must use a numeric loopback address and port".to_owned()
    })?;
    if !address.ip().is_loopback() || !matches!(address.ip(), IpAddr::V4(_)) {
        return Err("browser demo origin must be IPv4 loopback".to_owned());
    }
    Ok(origin)
}

fn request_timeout() -> Result<Duration, String> {
    let seconds = std::env::var("IMMORTAL_LAB_BROWSER_DEMO_TIMEOUT_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| "browser demo timeout must be an integer".to_owned())?
        .unwrap_or(180);
    if !(1..=900).contains(&seconds) {
        return Err("browser demo timeout is outside 1..=900 seconds".to_owned());
    }
    Ok(Duration::from_secs(seconds))
}

fn validate_effect(effect: &BrowserEffectRequest) -> Result<(), String> {
    if effect.schema != EFFECT_SCHEMA
        || effect.network != REGTEST_NETWORK
        || !matches!(effect.journey.as_str(), "submarine" | "reverse")
        || !matches!(
            effect.method.as_str(),
            "broadcast_bitcoin_funding" | "pay_lightning_invoice"
        )
        || effect.amount_sat == 0
        || effect.amount_sat > MAX_AMOUNT_SAT
    {
        return Err("browser effect is outside the closed regtest method set".to_owned());
    }
    for (value, label) in [
        (&effect.session_id, "session ID"),
        (&effect.order_id, "order ID"),
        (&effect.effect_id, "effect ID"),
        (&effect.idempotency_digest, "idempotency digest"),
    ] {
        validate_lower_hex_32(value, label)?;
    }
    if (effect.journey == "submarine" && effect.method != "broadcast_bitcoin_funding")
        || (effect.journey == "reverse" && effect.method != "pay_lightning_invoice")
    {
        return Err("browser effect method differs from its swap journey".to_owned());
    }
    Ok(())
}

fn gateway_effect(effect: &BrowserEffectRequest) -> GatewayEffectRequest {
    GatewayEffectRequest {
        schema: effect.schema.clone(),
        network: effect.network.clone(),
        journey: effect.journey.clone(),
        session_id: effect.session_id.clone(),
        order_id: effect.order_id.clone(),
        effect_id: effect.effect_id.clone(),
        idempotency_digest: effect.idempotency_digest.clone(),
        method: effect.method.clone(),
        amount_sat: effect.amount_sat,
    }
}

fn validate_contract() -> Result<(), String> {
    let contract: Value = serde_json::from_str(CONTRACT)
        .map_err(|error| format!("browser demo contract is invalid: {error}"))?;
    if contract.get("schema").and_then(Value::as_str)
        != Some("openagents.immortal.browser-demo-contract.v1")
        || contract.get("launcher").and_then(Value::as_str)
            != Some("scripts/dev-funded-browser-demo.sh")
        || contract.get("network").and_then(Value::as_str) != Some(REGTEST_NETWORK)
        || contract
            .pointer("/adapter/default_bind")
            .and_then(Value::as_str)
            != Some("127.0.0.1:19336")
        || contract
            .pointer("/adapter/default_origin")
            .and_then(Value::as_str)
            != Some("http://127.0.0.1:3000")
        || contract
            .pointer("/adapter/maximum_amount_sat")
            .and_then(Value::as_u64)
            != Some(MAX_AMOUNT_SAT)
        || contract
            .pointer("/adapter/maximum_request_bytes")
            .and_then(Value::as_u64)
            != Some(MAX_HTTP_BYTES as u64)
        || contract.pointer("/adapter/effect_methods")
            != Some(&json!([
                "broadcast_bitcoin_funding",
                "pay_lightning_invoice"
            ]))
    {
        return Err("browser demo fixture differs from the executable contract".to_owned());
    }
    Ok(())
}

fn validate_lower_hex_32(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("browser demo {label} is not lower hex-32"));
    }
    Ok(())
}

fn required_result<'a>(result: &'a Value, name: &str) -> Result<&'a str, String> {
    let value = result
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("browser terminal result has no {name}"))?;
    validate_lower_hex_32(value, name)?;
    Ok(value)
}

fn manifest_path(paths: &LabPaths) -> PathBuf {
    paths.root().join("browser-demo-manifest.json")
}

fn request_path(paths: &LabPaths, effect_id: &str) -> PathBuf {
    paths
        .root()
        .join(format!("browser-demo-{effect_id}-request.json"))
}

fn receipt_path(paths: &LabPaths, effect_id: &str) -> PathBuf {
    paths
        .root()
        .join(format!("browser-demo-{effect_id}-receipt.json"))
}

fn load_manifest(paths: &LabPaths) -> Result<Option<BrowserManifest>, String> {
    load_optional_json(&manifest_path(paths))
}

fn store_manifest(paths: &LabPaths, manifest: &BrowserManifest) -> Result<(), String> {
    provider_support::reject_custody_material(
        &serde_json::to_value(manifest)
            .map_err(|error| format!("could not inspect browser manifest: {error}"))?,
    )
    .map_err(|error| format!("browser manifest contains custody material: {error}"))?;
    write_json(&manifest_path(paths), manifest)
}

fn load_request(paths: &LabPaths, effect_id: &str) -> Result<Option<BrowserEffectRequest>, String> {
    load_optional_json(&request_path(paths, effect_id))
}

fn load_receipt(paths: &LabPaths, effect_id: &str) -> Result<Option<BrowserEffectReceipt>, String> {
    let receipt: Option<BrowserEffectReceipt> =
        load_optional_json(&receipt_path(paths, effect_id))?;
    if let Some(receipt) = &receipt {
        if receipt.schema != RECEIPT_SCHEMA || receipt.state != "admitted" {
            return Err("browser effect receipt has another schema or state".to_owned());
        }
        validate_effect(&receipt.request)?;
        validate_lower_hex_32(&receipt.external_identifier, "receipt external identifier")?;
        validate_lower_hex_32(&receipt.result_digest, "receipt result digest")?;
    }
    Ok(receipt)
}

fn load_optional_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > MAX_HTTP_BYTES {
        return Err(format!("{} is empty or unbounded", path.display()));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{} is invalid: {error}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > MAX_HTTP_BYTES {
        return Err(format!("{} would be empty or unbounded", path.display()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "browser state path has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not persist {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("could not install {}: {error}", path.display()))
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "system time is before the Unix epoch".to_owned())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect() -> BrowserEffectRequest {
        BrowserEffectRequest {
            schema: EFFECT_SCHEMA.to_owned(),
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
    fn closed_effect_contract_rejects_mainnet_unknown_methods_and_unbounded_amounts() {
        let mut candidate = effect();
        assert!(validate_effect(&candidate).is_ok());
        candidate.network = "mainnet".to_owned();
        assert!(validate_effect(&candidate).is_err());
        candidate = effect();
        candidate.method = "bitcoin_rpc".to_owned();
        assert!(validate_effect(&candidate).is_err());
        candidate = effect();
        candidate.amount_sat = MAX_AMOUNT_SAT + 1;
        assert!(validate_effect(&candidate).is_err());
    }

    #[test]
    fn bind_and_origin_contracts_refuse_remote_authority() {
        assert!(!"0.0.0.0".parse::<IpAddr>().unwrap().is_loopback());
        assert!(!"192.0.2.1".parse::<IpAddr>().unwrap().is_loopback());
        assert!("127.0.0.1".parse::<IpAddr>().unwrap().is_loopback());
    }

    #[test]
    fn fixture_matches_the_executable_contract() {
        validate_contract().expect("browser demo contract should match");
    }
}
