use crate::{
    bitcoind::{BitcoindClient, RpcRequestId},
    contract::boltz_provider_conformance_sha256,
    health::private_or_loopback,
    lightning::LightningRail,
    pricing::{PricingConfig, claim_spend_vbytes, lockup_vbytes},
    store::{MAX_SESSION_RECORDS, ProviderStore},
    wallet::{BitcoinNetwork, encode_segwit_v1_address},
};
use immortal_core::{
    boltz_compat::{BOLTZ_MAPPING_REVISION, classify_boltz_handoff, safe_origin_form},
    domain::{
        Event, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND,
        MKT_SWP_SWAP_CONTRACT_KIND, parse_unique_json,
    },
    mkt_swp_verify::{Transaction, parse_bolt11},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, watch},
    time::{sleep, timeout},
};

pub const BOLTZ_BIND_ENV: &str = "IMMORTAL_PROVIDER_BOLTZ_BIND";
pub const BOLTZ_CONFORMANCE_ENV: &str = "IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256";
pub const BOLTZ_ALLOWED_ORIGIN_ENV: &str = "IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN";

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_REQUESTS_PER_MINUTE: u32 = 120;
const MAX_RATE_IDENTITIES: usize = 4_096;
pub const MAX_HTTP_HEAD_BYTES: usize = 16 * 1024;
pub const MAX_JSON_BODY_BYTES: usize = 2_000_128;
pub const MAX_RAW_TRANSACTION_BYTES: usize = 1_000_000;
pub const MAX_STATUS_IDS: usize = 64;
pub const MAX_WS_SUBSCRIPTIONS: usize = 64;
pub const MAX_WS_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_WS_MESSAGES_PER_MINUTE: u32 = 120;
pub const MAX_WS_STATUS_QUERY_BATCHES_PER_MINUTE: u32 = 60;
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const WS_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoltzConfig {
    pub bind: SocketAddr,
    pub allowed_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoltzConfigError {
    Partial,
    Digest,
    Bind,
    Origin,
}

impl fmt::Display for BoltzConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Partial => write!(
                formatter,
                "{BOLTZ_BIND_ENV}, {BOLTZ_CONFORMANCE_ENV}, and {BOLTZ_ALLOWED_ORIGIN_ENV} must be configured together"
            ),
            Self::Digest => write!(
                formatter,
                "{BOLTZ_CONFORMANCE_ENV} does not match the compiled provider compatibility corpus"
            ),
            Self::Bind => write!(
                formatter,
                "{BOLTZ_BIND_ENV} must be a private or loopback numeric socket address"
            ),
            Self::Origin => write!(
                formatter,
                "{BOLTZ_ALLOWED_ORIGIN_ENV} must be one bounded http(s) origin without wildcard, path, credentials, query, or fragment"
            ),
        }
    }
}

impl std::error::Error for BoltzConfigError {}

impl BoltzConfig {
    pub fn from_environment() -> Result<Option<Self>, BoltzConfigError> {
        let bind = optional_environment(BOLTZ_BIND_ENV);
        let digest = optional_environment(BOLTZ_CONFORMANCE_ENV);
        let origin = optional_environment(BOLTZ_ALLOWED_ORIGIN_ENV);
        match (bind, digest, origin) {
            (None, None, None) => Ok(None),
            (Some(bind), Some(digest), Some(allowed_origin)) => {
                if digest != boltz_provider_conformance_sha256() {
                    return Err(BoltzConfigError::Digest);
                }
                let bind = bind
                    .parse::<SocketAddr>()
                    .map_err(|_| BoltzConfigError::Bind)?;
                if !private_or_loopback(bind.ip()) {
                    return Err(BoltzConfigError::Bind);
                }
                validate_origin(&allowed_origin)?;
                Ok(Some(Self {
                    bind,
                    allowed_origin,
                }))
            }
            _ => Err(BoltzConfigError::Partial),
        }
    }
}

fn optional_environment(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| {
        !value.is_empty()
            && !value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    })
}

fn validate_origin(value: &str) -> Result<(), BoltzConfigError> {
    if value.len() > 2_048 || value.ends_with('/') || value.contains(['@', '?', '#', '\\', '*']) {
        return Err(BoltzConfigError::Origin);
    }
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or(BoltzConfigError::Origin)?;
    if authority.is_empty() || authority.contains('/') {
        return Err(BoltzConfigError::Origin);
    }
    Ok(())
}

#[derive(Clone)]
pub struct BoltzApi {
    store: Arc<Mutex<ProviderStore>>,
    bitcoind: BitcoindClient,
    lightning: Arc<dyn LightningRail>,
    pricing: PricingConfig,
    network: BitcoinNetwork,
    allowed_origin: Arc<str>,
    rates: Arc<Mutex<BTreeMap<IpAddr, RateWindow>>>,
}

impl BoltzApi {
    pub fn new(
        store: ProviderStore,
        bitcoind: BitcoindClient,
        lightning: Arc<dyn LightningRail>,
        pricing: PricingConfig,
        network: BitcoinNetwork,
        allowed_origin: String,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            bitcoind,
            lightning,
            pricing,
            network,
            allowed_origin: Arc::from(allowed_origin),
            rates: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn admit(&self, address: IpAddr) -> bool {
        let now = Instant::now();
        let mut rates = self.rates.lock().await;
        rates.retain(|_, rate| now.duration_since(rate.started) < Duration::from_secs(120));
        if rates.len() >= MAX_RATE_IDENTITIES && !rates.contains_key(&address) {
            return false;
        }
        rates
            .entry(address)
            .or_insert_with(|| RateWindow::new(now))
            .admit(now, MAX_REQUESTS_PER_MINUTE)
    }
}

struct RateWindow {
    started: Instant,
    requests: u32,
}

impl RateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            requests: 0,
        }
    }

    fn admit(&mut self, now: Instant, limit: u32) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(60) {
            self.started = now;
            self.requests = 0;
        }
        if self.requests >= limit {
            return false;
        }
        self.requests += 1;
        true
    }
}

#[derive(Debug)]
pub enum BoltzServerError {
    Bind,
    Accept,
}

impl fmt::Display for BoltzServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind => formatter.write_str("provider Boltz listener could not bind"),
            Self::Accept => formatter.write_str("provider Boltz listener could not accept"),
        }
    }
}

impl std::error::Error for BoltzServerError {}

pub async fn serve_boltz(
    bind: SocketAddr,
    api: BoltzApi,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BoltzServerError> {
    if !private_or_loopback(bind.ip()) {
        return Err(BoltzServerError::Bind);
    }
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| BoltzServerError::Bind)?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|_| BoltzServerError::Accept)?;
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let api = api.clone();
                let shutdown = shutdown.clone();
                drop(tokio::spawn(async move {
                    let _permit = permit;
                    if !api.admit(peer.ip()).await {
                        let mut stream = stream;
                        if let Err(error) =
                            write_error(&mut stream, &api, 429, "rate_limited").await
                        {
                            eprintln!(
                                "immortal-provider: Boltz rate-limit response failed: {error}"
                            );
                        }
                        return;
                    }
                    if let Err(error) = handle_connection(stream, api, shutdown).await {
                        eprintln!("immortal-provider: Boltz request failed: {error}");
                    }
                }));
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    api: BoltzApi,
    shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let preview = preview_http_head(&stream).await?;
    if websocket_request(&preview, &api)? {
        return handle_websocket(stream, api, shutdown).await;
    }
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            write_error(&mut stream, &api, 400, &error).await?;
            return Ok(());
        }
    };
    let response = route_request(&api, request).await;
    write_response(&mut stream, &api, response).await
}

async fn preview_http_head(stream: &TcpStream) -> Result<String, String> {
    timeout(REQUEST_TIMEOUT, preview_http_head_inner(stream))
        .await
        .map_err(|_| "request head timed out".to_owned())?
}

async fn preview_http_head_inner(stream: &TcpStream) -> Result<String, String> {
    let mut preview = Box::new([0_u8; MAX_HTTP_HEAD_BYTES]);
    loop {
        let read = stream
            .peek(preview.as_mut())
            .await
            .map_err(|_| "request head could not be read".to_owned())?;
        if read == 0 {
            return Err("request head is incomplete".to_owned());
        }
        if let Some(position) = preview[..read]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let head = std::str::from_utf8(&preview[..position + 4])
                .map_err(|_| "request head is not UTF-8".to_owned())?;
            return Ok(head.to_owned());
        }
        if read == MAX_HTTP_HEAD_BYTES {
            return Err("request head is too large".to_owned());
        }
        sleep(Duration::from_millis(1)).await;
    }
}

fn websocket_request(head: &str, api: &BoltzApi) -> Result<bool, String> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    if request_line != "GET /v2/ws HTTP/1.1" {
        return Ok(false);
    }
    let headers = parse_headers(lines)?;
    let upgrade = headers
        .get("upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if !upgrade {
        return Ok(false);
    }
    validate_browser_origin(&headers, api)?;
    Ok(true)
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    timeout(REQUEST_TIMEOUT, read_request_inner(stream))
        .await
        .map_err(|_| "request_timeout".to_owned())?
}

async fn read_request_inner(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::with_capacity(1_024);
    let head_end = loop {
        if bytes.len() >= MAX_HTTP_HEAD_BYTES {
            return Err("request_head_too_large".to_owned());
        }
        let mut chunk = [0_u8; 1_024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "request_read_failed".to_owned())?;
        if read == 0 {
            return Err("request_incomplete".to_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head =
        std::str::from_utf8(&bytes[..head_end]).map_err(|_| "request_head_invalid".to_owned())?;
    let mut lines = head[..head.len() - 4].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "request_line_missing".to_owned())?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let version = parts.next().unwrap_or("");
    if parts.next().is_some()
        || !matches!(method.as_str(), "GET" | "POST" | "OPTIONS")
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !safe_origin_form(&target)
    {
        return Err("request_line_invalid".to_owned());
    }
    let headers = parse_headers(lines)?;
    if headers.contains_key("transfer-encoding") {
        return Err("transfer_encoding_refused".to_owned());
    }
    let length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|length| *length <= MAX_JSON_BODY_BYTES)
            .ok_or_else(|| "content_length_invalid".to_owned())?,
        None => 0,
    };
    if method == "POST"
        && headers.get("content-type").map(String::as_str) != Some("application/json")
    {
        return Err("content_type_invalid".to_owned());
    }
    let existing_body = bytes.len() - head_end;
    if existing_body > length {
        return Err("request_body_overrun".to_owned());
    }
    while bytes.len() - head_end < length {
        let remaining = length - (bytes.len() - head_end);
        let mut chunk = vec![0_u8; remaining.min(8 * 1024)];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| "request_read_failed".to_owned())?;
        if read == 0 {
            return Err("request_incomplete".to_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body: bytes[head_end..].to_vec(),
    })
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "request_header_invalid".to_owned())?;
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || headers.contains_key(&name)
        {
            return Err("request_header_invalid".to_owned());
        }
        let value = value.trim();
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("request_header_invalid".to_owned());
        }
        headers.insert(name, value.to_owned());
    }
    Ok(headers)
}

fn validate_browser_origin(
    headers: &BTreeMap<String, String>,
    api: &BoltzApi,
) -> Result<(), String> {
    if !origin_allowed(
        headers.get("origin").map(String::as_str),
        api.allowed_origin.as_ref(),
    ) {
        return Err("origin_refused".to_owned());
    }
    Ok(())
}

fn origin_allowed(origin: Option<&str>, allowed_origin: &str) -> bool {
    origin.is_none_or(|origin| origin == allowed_origin)
}

struct HttpResponse {
    status: u16,
    body: Value,
}

impl HttpResponse {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    fn created(body: Value) -> Self {
        Self { status: 201, body }
    }

    fn error(status: u16, code: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({"error":code.into()}),
        }
    }
}

async fn route_request(api: &BoltzApi, request: HttpRequest) -> HttpResponse {
    if let Err(error) = validate_browser_origin(&request.headers, api) {
        return HttpResponse::error(403, error);
    }
    if request.method == "OPTIONS" {
        let Some(requested_method) = request
            .headers
            .get("access-control-request-method")
            .filter(|method| matches!(method.as_str(), "GET" | "POST"))
        else {
            return HttpResponse::error(400, "preflight_method_invalid");
        };
        if classify_boltz_handoff(requested_method, &request.target).is_none() {
            return HttpResponse::error(404, "outside_released_profile");
        }
        return HttpResponse::ok(json!({}));
    }
    if classify_boltz_handoff(&request.method, &request.target).is_none() {
        return HttpResponse::error(404, "outside_released_profile");
    }
    match route_request_inner(api, &request).await {
        Ok(response) => response,
        Err(ApiError { status, code }) => HttpResponse::error(status, code),
    }
}

#[derive(Debug)]
struct ApiError {
    status: u16,
    code: String,
}

impl ApiError {
    fn bad(code: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: code.into(),
        }
    }

    fn missing(code: impl Into<String>) -> Self {
        Self {
            status: 404,
            code: code.into(),
        }
    }

    fn conflict(code: impl Into<String>) -> Self {
        Self {
            status: 409,
            code: code.into(),
        }
    }

    fn upstream(code: impl Into<String>) -> Self {
        Self {
            status: 503,
            code: code.into(),
        }
    }
}

async fn route_request_inner(
    api: &BoltzApi,
    request: &HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let path = request.target.split('?').next().unwrap_or(&request.target);
    match (request.method.as_str(), path) {
        ("GET", "/v2/version") => Ok(HttpResponse::ok(json!({
            "version":env!("CARGO_PKG_VERSION"),
            "mappingRevision":BOLTZ_MAPPING_REVISION,
            "profile":"bitcoin-lightning-script-path-v1",
        }))),
        ("GET", "/v2/swap/submarine") => pair_response(api, "submarine").await,
        ("GET", "/v2/swap/reverse") => pair_response(api, "reverse").await,
        ("POST", "/v2/swap/submarine") => create_response(api, request, "submarine").await,
        ("POST", "/v2/swap/reverse") => create_response(api, request, "reverse").await,
        ("GET", "/v2/chain/fees") => {
            let fee = current_fee(api, "fees").await?;
            Ok(HttpResponse::ok(json!({"BTC":fee})))
        }
        ("GET", "/v2/chain/BTC/fee") => {
            let fee = current_fee(api, "fee").await?;
            Ok(HttpResponse::ok(json!({"fee":fee})))
        }
        ("GET", "/v2/chain/BTC/height") => {
            let tip = api
                .bitcoind
                .chain_tip(&rpc_id("boltz-height", "public")?)
                .await
                .map_err(|_| ApiError::upstream("chain_unavailable"))?;
            Ok(HttpResponse::ok(json!({"height":tip.height})))
        }
        ("GET", "/v2/nodes/stats") => {
            let capacity = api
                .lightning
                .channel_capacity_sat("boltz-node-stats")
                .await
                .map_err(|_| ApiError::upstream("lightning_unavailable"))?;
            Ok(HttpResponse::ok(json!({
                "BTC":{
                    "Immortal":{
                        "capacity":capacity,
                        "channels":0,
                        "peers":0
                    },
                    "total":{
                        "capacity":capacity,
                        "channels":0,
                        "peers":0
                    }
                }
            })))
        }
        ("GET", "/v2/swap/status") => status_batch(api, &request.target).await,
        ("POST", "/v2/chain/BTC/transaction") => broadcast(api, request).await,
        _ => dynamic_route(api, request, path).await,
    }
}

async fn pair_response(api: &BoltzApi, swap_type: &str) -> Result<HttpResponse, ApiError> {
    let fee = current_fee(api, "pairs").await?;
    let capacity = api
        .lightning
        .channel_capacity_sat("boltz-pairs")
        .await
        .map_err(|_| ApiError::upstream("lightning_unavailable"))?;
    let maximum = api.pricing.max_swap_sat.min(capacity);
    if maximum < api.pricing.min_swap_sat {
        return Err(ApiError::upstream("provider_capacity_below_minimum"));
    }
    let hash = pair_hash(&api.pricing, swap_type, fee, maximum);
    let percentage = api.pricing.spread_bps as f64 / 100.0;
    let body = if swap_type == "submarine" {
        json!({
            "BTC":{"BTC":{
                "hash":hash,
                "rate":1.0,
                "limits":{
                    "minimal":api.pricing.min_swap_sat,
                    "minimalBatched":api.pricing.min_swap_sat,
                    "maximal":maximum,
                    "maximalZeroConf":0
                },
                "fees":{
                    "percentage":percentage,
                    "minerFees":claim_spend_vbytes().saturating_mul(fee)
                }
            }}
        })
    } else {
        json!({
            "BTC":{"BTC":{
                "hash":hash,
                "rate":1.0,
                "limits":{
                    "minimal":api.pricing.min_swap_sat,
                    "maximal":maximum
                },
                "fees":{
                    "percentage":percentage,
                    "minerFees":{
                        "lockup":lockup_vbytes().saturating_mul(fee),
                        "claim":claim_spend_vbytes().saturating_mul(fee)
                    }
                }
            }}
        })
    };
    Ok(HttpResponse::ok(body))
}

async fn current_fee(api: &BoltzApi, context: &str) -> Result<u64, ApiError> {
    api.bitcoind
        .estimated_feerate_sat_per_vbyte(&rpc_id("boltz-fee", context)?, 2)
        .await
        .map_err(|_| ApiError::upstream("fee_estimate_unavailable"))?
        .or(api.pricing.fallback_feerate_sat_per_vb)
        .ok_or_else(|| ApiError::upstream("fee_estimate_unavailable"))
}

fn pair_hash(pricing: &PricingConfig, swap_type: &str, fee: u64, maximum: u64) -> String {
    lower_hex(&Sha256::digest(
        format!(
            "immortal-boltz-pair-v1\0{swap_type}\0{}\0{}\0{}\0{}\0{fee}\0{maximum}",
            pricing.spread_bps,
            pricing.min_swap_sat,
            pricing.max_swap_sat,
            pricing.lightning_routing_fee_ppm,
        )
        .as_bytes(),
    ))
}

fn rpc_id(label: &str, context: &str) -> Result<RpcRequestId, ApiError> {
    RpcRequestId::new(format!("{label}:{context}"))
        .map_err(|_| ApiError::bad("request_context_invalid"))
}

fn request_object(request: &HttpRequest) -> Result<Map<String, Value>, ApiError> {
    let text =
        std::str::from_utf8(&request.body).map_err(|_| ApiError::bad("request_body_invalid"))?;
    parse_unique_json(text, "Boltz provider request")
        .map_err(|_| ApiError::bad("request_body_invalid"))?
        .as_object()
        .cloned()
        .ok_or_else(|| ApiError::bad("request_body_invalid"))
}

fn exact_members(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), ApiError> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err(ApiError::bad("request_member_outside_profile"));
    }
    Ok(())
}

async fn create_response(
    api: &BoltzApi,
    request: &HttpRequest,
    swap_type: &str,
) -> Result<HttpResponse, ApiError> {
    let body = request_object(request)?;
    if swap_type == "submarine" {
        exact_members(
            &body,
            &[
                "from",
                "to",
                "invoice",
                "pairHash",
                "refundPublicKey",
                "mktSessionId",
            ],
        )?;
    } else {
        exact_members(
            &body,
            &[
                "from",
                "to",
                "invoiceAmount",
                "preimageHash",
                "claimPublicKey",
                "pairHash",
                "mktSessionId",
            ],
        )?;
    }
    if body.get("from").and_then(Value::as_str) != Some("BTC")
        || body.get("to").and_then(Value::as_str) != Some("BTC")
    {
        return Err(ApiError::bad("bitcoin_lightning_pair_required"));
    }
    let session_id = body
        .get("mktSessionId")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::bad("mkt_session_id_required"))?;
    let records = session_records(api, session_id).await?;
    let rfq = exactly_one_kind(&records, MKT_RFQ_KIND, "rfq_missing")?;
    let quote = exactly_one_kind(&records, MKT_QUOTE_KIND, "quote_missing")?;
    let quote_terms = profile_object(quote)?
        .get("terms")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::conflict("quote_terms_missing"))?;
    if quote_terms.get("swap_type").and_then(Value::as_str) != Some(swap_type) {
        return Err(ApiError::conflict("session_swap_type_mismatch"));
    }
    validate_pair_hash(api, &body, swap_type).await?;
    validate_creation_against_native(&body, rfq, &quote_terms, swap_type)?;
    let terms = if swap_type == "reverse" {
        bilateral_contract(&records)?
    } else {
        quote_terms
    };
    let bitcoin = bitcoin_terms(&terms, swap_type)?;
    let address = taproot_address(api.network, bitcoin.script_pubkey)?;
    let swap_tree = json!({
        "claimLeaf":{"output":bitcoin.claim_script,"version":192},
        "refundLeaf":{"output":bitcoin.refund_script,"version":192},
    });
    if swap_type == "submarine" {
        let expected_amount = canonical_u64(
            terms
                .get("input_amount")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::conflict("quote_input_amount_missing"))?,
        )?;
        let claim_public_key = bitcoin
            .leg
            .get("claim_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("quote_claim_key_missing"))?;
        Ok(HttpResponse::created(json!({
            "id":session_id,
            "address":address,
            "bip21":bitcoin_bip21(&address, expected_amount, None),
            "swapTree":swap_tree,
            "claimPublicKey":claim_public_key,
            "timeoutBlockHeight":bitcoin.refund_height,
            "acceptZeroConf":false,
            "expectedAmount":expected_amount,
        })))
    } else {
        let invoice = reverse_invoice(&records)?;
        let onchain_amount = canonical_u64(
            bitcoin
                .verifier
                .get("amount")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::conflict("contract_amount_missing"))?,
        )?;
        let refund_public_key = bitcoin
            .leg
            .get("refund_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("contract_refund_key_missing"))?;
        Ok(HttpResponse::created(json!({
            "id":session_id,
            "invoice":invoice,
            "swapTree":swap_tree,
            "refundPublicKey":refund_public_key,
            "lockupAddress":address,
            "timeoutBlockHeight":bitcoin.refund_height,
            "onchainAmount":onchain_amount,
        })))
    }
}

async fn validate_pair_hash(
    api: &BoltzApi,
    body: &Map<String, Value>,
    swap_type: &str,
) -> Result<(), ApiError> {
    let supplied = body
        .get("pairHash")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("pair_hash_required"))?;
    let fee = current_fee(api, "create").await?;
    let capacity = api
        .lightning
        .channel_capacity_sat("boltz-create")
        .await
        .map_err(|_| ApiError::upstream("lightning_unavailable"))?;
    let expected = pair_hash(
        &api.pricing,
        swap_type,
        fee,
        api.pricing.max_swap_sat.min(capacity),
    );
    if supplied != expected {
        return Err(ApiError::conflict("pair_hash_stale"));
    }
    Ok(())
}

fn validate_creation_against_native(
    body: &Map<String, Value>,
    rfq: &Event,
    terms: &Map<String, Value>,
    swap_type: &str,
) -> Result<(), ApiError> {
    let constraints = profile_object(rfq)?
        .get("constraints")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::conflict("rfq_constraints_missing"))?;
    if swap_type == "submarine" {
        let invoice = body
            .get("invoice")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("invoice_required"))?;
        let parsed = parse_bolt11(invoice).map_err(|_| ApiError::bad("invoice_invalid"))?;
        let invoice_digest = lower_hex(&Sha256::digest(invoice.as_bytes()));
        if constraints.get("invoice_sha256").and_then(Value::as_str)
            != Some(invoice_digest.as_str())
            || constraints.get("payment_hash").and_then(Value::as_str)
                != Some(lower_hex(&parsed.payment_hash).as_str())
        {
            return Err(ApiError::conflict("invoice_differs_from_signed_rfq"));
        }
        let refund_key = body
            .get("refundPublicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("refund_public_key_required"))?;
        let bitcoin = bitcoin_terms(terms, swap_type)?;
        if bitcoin.leg.get("refund_public_key").and_then(Value::as_str) != Some(refund_key) {
            return Err(ApiError::conflict("refund_key_differs_from_signed_quote"));
        }
    } else {
        let payment_hash = body
            .get("preimageHash")
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .ok_or_else(|| ApiError::bad("preimage_hash_required"))?;
        if constraints.get("payment_hash").and_then(Value::as_str) != Some(payment_hash) {
            return Err(ApiError::conflict("payment_hash_differs_from_signed_rfq"));
        }
        let claim_key = body
            .get("claimPublicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("claim_public_key_required"))?;
        let bitcoin = bitcoin_terms(terms, swap_type)?;
        if bitcoin.leg.get("claim_public_key").and_then(Value::as_str) != Some(claim_key) {
            return Err(ApiError::conflict("claim_key_differs_from_signed_contract"));
        }
        let amount = body
            .get("invoiceAmount")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::bad("reverse_amount_required"))?;
        if constraints.get("input_amount").and_then(Value::as_str)
            != Some(amount.to_string().as_str())
        {
            return Err(ApiError::conflict("amount_differs_from_signed_rfq"));
        }
    }
    Ok(())
}

struct BitcoinTerms<'a> {
    verifier: &'a Map<String, Value>,
    leg: &'a Map<String, Value>,
    script_pubkey: [u8; 34],
    claim_script: &'a str,
    refund_script: &'a str,
    claim_control_block: &'a str,
    refund_height: u32,
}

fn bitcoin_terms<'a>(
    terms: &'a Map<String, Value>,
    swap_type: &str,
) -> Result<BitcoinTerms<'a>, ApiError> {
    let leg_id = if swap_type == "submarine" {
        "source"
    } else {
        "destination"
    };
    let verifier = terms
        .get("verifier_inputs")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .find(|value| value.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("bitcoin_verifier_missing"))?;
    let leg = terms
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .find(|value| value.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("bitcoin_leg_missing"))?;
    let script = decode_hex_exact::<34>(
        verifier
            .get("script_pubkey")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("script_pubkey_missing"))?,
    )?;
    if script[..2] != [0x51, 0x20] {
        return Err(ApiError::conflict("script_pubkey_not_taproot"));
    }
    let claim_script = verifier
        .get("claim_script")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("claim_script_missing"))?;
    let refund_script = verifier
        .get("refund_script")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("refund_script_missing"))?;
    let claim_control_block = verifier
        .get("taproot_claim_control_block")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("claim_control_block_missing"))?;
    let refund_height = leg
        .get("refund_lock_value")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("refund_height_missing"))?
        .parse::<u32>()
        .map_err(|_| ApiError::conflict("refund_height_invalid"))?;
    Ok(BitcoinTerms {
        verifier,
        leg,
        script_pubkey: script,
        claim_script,
        refund_script,
        claim_control_block,
        refund_height,
    })
}

fn taproot_address(network: BitcoinNetwork, script: [u8; 34]) -> Result<String, ApiError> {
    let program = <[u8; 32]>::try_from(&script[2..])
        .map_err(|_| ApiError::conflict("script_pubkey_invalid"))?;
    encode_segwit_v1_address(network.human_readable_part(), &program)
        .map_err(|_| ApiError::conflict("address_encoding_failed"))
}

fn bitcoin_bip21(address: &str, amount_sat: u64, invoice: Option<&str>) -> String {
    let whole = amount_sat / 100_000_000;
    let fraction = amount_sat % 100_000_000;
    let mut value = format!("bitcoin:{address}?amount={whole}.{fraction:08}");
    if let Some(invoice) = invoice {
        value.push_str("&lightning=");
        value.push_str(invoice);
    }
    value
}

async fn session_records(api: &BoltzApi, session_id: &str) -> Result<Vec<Event>, ApiError> {
    if !valid_hash(session_id) {
        return Err(ApiError::bad("session_id_invalid"));
    }
    let store = api.store.lock().await;
    let records = store
        .session_records(session_id, MAX_SESSION_RECORDS)
        .await
        .map_err(|_| ApiError::upstream("provider_store_unavailable"))?;
    if records.is_empty() {
        return Err(ApiError::missing("swap_not_found"));
    }
    Ok(records)
}

fn exactly_one_kind<'a>(
    records: &'a [Event],
    kind: u16,
    code: &str,
) -> Result<&'a Event, ApiError> {
    let values = records
        .iter()
        .filter(|record| record.kind == kind)
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        [] => Err(ApiError::conflict(code)),
        _ => Err(ApiError::conflict("signed_session_fork")),
    }
}

fn profile_object(event: &Event) -> Result<Map<String, Value>, ApiError> {
    parse_unique_json(&event.content, "signed MKT-SWP record")
        .map_err(|_| ApiError::conflict("signed_session_record_invalid"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::conflict("signed_session_profile_missing"))
}

fn bilateral_contract(records: &[Event]) -> Result<Map<String, Value>, ApiError> {
    let contracts = records
        .iter()
        .filter(|record| record.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .collect::<Vec<_>>();
    if contracts.len() != 2 || contracts[0].pubkey == contracts[1].pubkey {
        return Err(ApiError::conflict("bilateral_contracts_missing"));
    }
    let first = profile_object(contracts[0])?;
    let second = profile_object(contracts[1])?;
    let first_contract = first
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("requester_contract_invalid"))?;
    let second_contract = second
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("provider_contract_invalid"))?;
    if first_contract != second_contract {
        return Err(ApiError::conflict("bilateral_contract_conflict"));
    }
    Ok(first_contract.clone())
}

fn reverse_invoice(records: &[Event]) -> Result<String, ApiError> {
    let provider = exactly_one_kind(records, MKT_QUOTE_KIND, "quote_missing")?
        .pubkey
        .as_str();
    let invoices = dense_statuses(records)?
        .into_iter()
        .filter(|status| status.event.pubkey == provider)
        .filter_map(|status| {
            status
                .profile
                .get("invoice")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    match invoices.iter().collect::<Vec<_>>().as_slice() {
        [invoice] => Ok((*invoice).clone()),
        [] => Err(ApiError::conflict("reverse_invoice_not_released")),
        _ => Err(ApiError::conflict("reverse_invoice_conflict")),
    }
}

async fn dynamic_route(
    api: &BoltzApi,
    request: &HttpRequest,
    path: &str,
) -> Result<HttpResponse, ApiError> {
    if request.method == "GET" {
        if let Some(id) = path
            .strip_prefix("/v2/swap/")
            .filter(|value| valid_hash(value))
        {
            return status_response(api, id).await;
        }
        if let Some(id) = session_action(path, "submarine", "transaction") {
            return session_transaction(api, id, "submarine").await;
        }
        if let Some(id) = session_action(path, "reverse", "transaction") {
            return session_transaction(api, id, "reverse").await;
        }
        if let Some(id) = session_action(path, "submarine", "preimage") {
            return released_preimage(api, id).await;
        }
        if let Some(invoice) = path
            .strip_prefix("/v2/swap/reverse/")
            .and_then(|value| value.strip_suffix("/bip21"))
        {
            return reverse_bip21(api, invoice).await;
        }
        if let Some(txid) = path.strip_prefix("/v2/chain/BTC/transaction/") {
            return public_transaction(api, txid).await;
        }
    }
    if request.method == "POST" {
        if let Some(id) = session_action(path, "submarine", "finalize") {
            return finalize_submarine(api, request, id).await;
        }
    }
    Err(ApiError::missing("outside_released_profile"))
}

fn session_action<'a>(path: &'a str, swap_type: &str, action: &str) -> Option<&'a str> {
    path.strip_prefix(&format!("/v2/swap/{swap_type}/"))
        .and_then(|value| value.strip_suffix(&format!("/{action}")))
        .filter(|value| valid_hash(value))
}

async fn finalize_submarine(
    api: &BoltzApi,
    request: &HttpRequest,
    session_id: &str,
) -> Result<HttpResponse, ApiError> {
    let body = request_object(request)?;
    exact_members(
        &body,
        &[
            "sessionId",
            "finalizePath",
            "rawTransactionHex",
            "fundingTransactionSha256",
            "outputIndex",
        ],
    )?;
    if body.get("sessionId").and_then(Value::as_str) != Some(session_id)
        || body.get("finalizePath").and_then(Value::as_str)
            != Some(format!("/v2/swap/submarine/{session_id}/finalize").as_str())
    {
        return Err(ApiError::conflict("finalize_session_binding_mismatch"));
    }
    let raw = body
        .get("rawTransactionHex")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("raw_transaction_required"))?;
    let raw_bytes = decode_hex_bounded(raw, MAX_RAW_TRANSACTION_BYTES)?;
    let digest = lower_hex(&Sha256::digest(&raw_bytes));
    if body.get("fundingTransactionSha256").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(ApiError::conflict("funding_transaction_digest_mismatch"));
    }
    let output_index = body
        .get("outputIndex")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ApiError::bad("output_index_invalid"))?;
    let records = session_records(api, session_id).await?;
    exactly_one_kind(&records, MKT_ORDER_KIND, "order_missing")?;
    let terms = bilateral_contract(&records)?;
    if terms.get("swap_type").and_then(Value::as_str) != Some("submarine") {
        return Err(ApiError::conflict("session_swap_type_mismatch"));
    }
    let bitcoin = bitcoin_terms(&terms, "submarine")?;
    if bitcoin
        .verifier
        .get("funding_transaction")
        .and_then(Value::as_str)
        != Some(raw)
        || bitcoin
            .verifier
            .get("funding_transaction_sha256")
            .and_then(Value::as_str)
            != Some(digest.as_str())
        || bitcoin.verifier.get("output_index").and_then(Value::as_u64)
            != Some(u64::from(output_index))
    {
        return Err(ApiError::conflict(
            "funding_differs_from_bilateral_contract",
        ));
    }
    let transaction =
        Transaction::parse(&raw_bytes).map_err(|_| ApiError::bad("raw_transaction_invalid"))?;
    let output = transaction
        .outputs
        .get(usize::try_from(output_index).map_err(|_| ApiError::bad("output_index_invalid"))?)
        .ok_or_else(|| ApiError::conflict("funding_output_missing"))?;
    let amount = canonical_u64(
        bitcoin
            .verifier
            .get("amount")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("contract_amount_missing"))?,
    )?;
    if output.value_sat != amount || output.script_pubkey.as_slice() != bitcoin.script_pubkey {
        return Err(ApiError::conflict("funding_output_differs_from_contract"));
    }
    let contract_records = records
        .iter()
        .filter(|record| record.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .collect::<Vec<_>>();
    let requester_pubkey = exactly_one_kind(&records, MKT_RFQ_KIND, "rfq_missing")?
        .pubkey
        .as_str();
    let requester_contract = contract_records
        .iter()
        .find(|record| record.pubkey == requester_pubkey)
        .ok_or_else(|| ApiError::conflict("requester_contract_missing"))?;
    let provider_contract = contract_records
        .iter()
        .find(|record| record.pubkey != requester_pubkey)
        .ok_or_else(|| ApiError::conflict("provider_contract_missing"))?;
    let exit_commitment = terms
        .get("exit_package_commitments")
        .and_then(Value::as_array)
        .and_then(|values| {
            values.iter().find(|value| {
                value.get("participant_role").and_then(Value::as_str) == Some("requester")
                    && value.get("path").and_then(Value::as_str) == Some("refund")
                    && matches!(
                        value.get("package_mode").and_then(Value::as_str),
                        Some("presigned" | "wallet_sign")
                    )
            })
        })
        .ok_or_else(|| ApiError::conflict("script_path_exit_commitment_missing"))?;
    let exit_mode = exit_commitment
        .get("package_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("script_path_exit_commitment_missing"))?;
    let exit = exit_commitment
        .get("package_sha256")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::conflict("script_path_exit_commitment_missing"))?;
    Ok(HttpResponse::ok(json!({
        "sessionId":session_id,
        "finalizePath":format!("/v2/swap/submarine/{session_id}/finalize"),
        "fundingTransactionSha256":digest,
        "outputIndex":output_index,
        "requesterContractEventId":requester_contract.id,
        "providerContractEventId":provider_contract.id,
        "exitPackageSha256":exit,
        "exitPackageMode":exit_mode,
        "scriptPathOnly":true,
    })))
}

async fn session_transaction(
    api: &BoltzApi,
    session_id: &str,
    swap_type: &str,
) -> Result<HttpResponse, ApiError> {
    let records = session_records(api, session_id).await?;
    let terms = bilateral_contract(&records)?;
    if terms.get("swap_type").and_then(Value::as_str) != Some(swap_type) {
        return Err(ApiError::conflict("session_swap_type_mismatch"));
    }
    let bitcoin = bitcoin_terms(&terms, swap_type)?;
    let raw = bitcoin
        .verifier
        .get("funding_transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("funding_transaction_not_finalized"))?;
    let transaction = Transaction::parse(&decode_hex_bounded(raw, MAX_RAW_TRANSACTION_BYTES)?)
        .map_err(|_| ApiError::conflict("funding_transaction_invalid"))?;
    let txid = lower_hex(
        &transaction
            .txid()
            .map_err(|_| ApiError::conflict("funding_transaction_invalid"))?,
    );
    Ok(HttpResponse::ok(json!({
        "id":txid,
        "hex":raw,
        "timeoutBlockHeight":bitcoin.refund_height,
    })))
}

async fn status_response(api: &BoltzApi, session_id: &str) -> Result<HttpResponse, ApiError> {
    let records = session_records(api, session_id).await?;
    Ok(HttpResponse::ok(project_status(session_id, &records)?))
}

async fn status_batch(api: &BoltzApi, target: &str) -> Result<HttpResponse, ApiError> {
    let query = target
        .strip_prefix("/v2/swap/status?")
        .ok_or_else(|| ApiError::bad("status_query_invalid"))?;
    let mut ids = Vec::new();
    for part in query.split('&') {
        let id = part
            .strip_prefix("ids=")
            .filter(|value| valid_hash(value))
            .ok_or_else(|| ApiError::bad("status_query_invalid"))?;
        ids.push(id);
        if ids.len() > MAX_STATUS_IDS {
            return Err(ApiError::bad("status_query_too_large"));
        }
    }
    if ids.is_empty() {
        return Err(ApiError::bad("status_query_invalid"));
    }
    let owned_ids = ids.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
    let grouped = session_record_batch(api, &owned_ids)
        .await
        .map_err(|_| ApiError::upstream("provider_store_unavailable"))?;
    let mut result = Map::new();
    for id in ids {
        let records = grouped
            .get(id)
            .ok_or_else(|| ApiError::missing("swap_not_found"))?;
        result.insert(id.to_owned(), project_status(id, records)?);
    }
    Ok(HttpResponse::ok(Value::Object(result)))
}

fn project_status(session_id: &str, records: &[Event]) -> Result<Value, ApiError> {
    let statuses = dense_statuses(records)?;
    let Some(status) = statuses.iter().max_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then_with(|| left.event.id.cmp(&right.event.id))
    }) else {
        return Ok(json!({"id":session_id,"status":"swap.created"}));
    };
    let mut result = Map::new();
    result.insert("id".to_owned(), Value::String(session_id.to_owned()));
    result.insert(
        "status".to_owned(),
        Value::String(status.boltz_status.to_owned()),
    );
    if let Some(reason) = status.profile.get("failure_code").and_then(Value::as_str) {
        result.insert("failureReason".to_owned(), Value::String(reason.to_owned()));
    }
    if let Some(transaction_id) = status.profile.get("transaction_id").and_then(Value::as_str) {
        result.insert("transaction".to_owned(), json!({"id":transaction_id}));
    }
    Ok(Value::Object(result))
}

#[derive(Debug)]
struct DenseStatus<'a> {
    event: &'a Event,
    profile: Map<String, Value>,
    rank: u16,
    boltz_status: &'static str,
}

fn dense_statuses(records: &[Event]) -> Result<Vec<DenseStatus<'_>>, ApiError> {
    let requester = exactly_one_kind(records, MKT_RFQ_KIND, "rfq_missing")?
        .pubkey
        .as_str();
    let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "quote_missing")?;
    let provider = quote.pubkey.as_str();
    if requester == provider {
        return Err(ApiError::conflict("session_participants_invalid"));
    }
    let quote_profile = profile_object(quote)?;
    let swap_type = quote_profile
        .get("terms")
        .and_then(Value::as_object)
        .and_then(|terms| terms.get("swap_type"))
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "submarine" | "reverse"))
        .ok_or_else(|| ApiError::conflict("session_swap_type_mismatch"))?;
    let mut streams = BTreeMap::<&str, BTreeMap<u64, Vec<&Event>>>::new();
    for event in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
        if event.pubkey != requester && event.pubkey != provider {
            return Err(ApiError::conflict("status_signer_invalid"));
        }
        let sequence = tag_value(event, "seq")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| ApiError::conflict("status_sequence_invalid"))?;
        streams
            .entry(event.pubkey.as_str())
            .or_default()
            .entry(sequence)
            .or_default()
            .push(event);
    }
    let mut dense = Vec::new();
    for (author, stream) in streams {
        let mut previous: Option<&Event> = None;
        let mut previous_state: Option<(String, u16)> = None;
        for (expected, (sequence, events)) in (0_u64..).zip(stream) {
            if sequence != expected || events.len() != 1 {
                return Err(ApiError::conflict("status_stream_not_dense"));
            }
            let event = events[0];
            let previous_reference = previous_status_reference(event)?;
            match previous {
                None if previous_reference.is_some() => {
                    return Err(ApiError::conflict("status_previous_invalid"));
                }
                Some(previous) if previous_reference != Some(previous.id.as_str()) => {
                    return Err(ApiError::conflict("status_previous_invalid"));
                }
                _ => {}
            }
            let profile = profile_object(event)?;
            let state = profile
                .get("swp_state")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::conflict("status_state_missing"))?
                .to_owned();
            let role = if author == requester {
                StatusSigner::Requester
            } else {
                StatusSigner::Provider
            };
            if !status_signer_allowed(swap_type, &state, role) {
                return Err(ApiError::conflict("status_signer_invalid"));
            }
            let (rank, boltz_status) = boltz_status(swap_type, &state)
                .ok_or_else(|| ApiError::conflict("status_state_unrepresentable"))?;
            if previous_state
                .as_ref()
                .is_some_and(|(previous_state, previous_rank)| {
                    rank < *previous_rank
                        || rank == *previous_rank
                            && (state != "cooperative_signing_pending"
                                || previous_state != "cooperative_signing_pending")
                })
            {
                return Err(ApiError::conflict("status_transition_invalid"));
            }
            dense.push(DenseStatus {
                event,
                profile,
                rank,
                boltz_status,
            });
            previous = Some(event);
            previous_state = Some((state, rank));
        }
    }
    Ok(dense)
}

fn previous_status_reference(event: &Event) -> Result<Option<&str>, ApiError> {
    let mut references = event.tags.iter().filter(|tag| {
        tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some("previous")
    });
    let Some(first) = references.next() else {
        return Ok(None);
    };
    let value = first
        .value()
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::conflict("status_previous_invalid"))?;
    if references.next().is_some() {
        return Err(ApiError::conflict("status_previous_invalid"));
    }
    Ok(Some(value))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusSigner {
    Requester,
    Provider,
}

fn status_signer_allowed(swap_type: &str, state: &str, signer: StatusSigner) -> bool {
    if matches!(
        state,
        "funding_observed"
            | "funding_final"
            | "cooperative_signing_pending"
            | "cancelled"
            | "expired"
            | "completed"
            | "refunded"
            | "disputed"
            | "failed"
            | "unresolved"
    ) {
        return true;
    }
    match (swap_type, signer) {
        ("submarine", StatusSigner::Requester) => matches!(
            state,
            "requester_verification_passed"
                | "funding_required"
                | "requester_funding_broadcast"
                | "refund_prepared"
                | "refund_pending"
        ),
        ("submarine", StatusSigner::Provider) => matches!(
            state,
            "accepted"
                | "lock_terms_ready"
                | "lightning_payment_pending"
                | "lightning_paid"
                | "provider_claim_pending"
                | "provider_claimed"
        ),
        ("reverse", StatusSigner::Requester) => matches!(
            state,
            "requester_invoice_verified"
                | "lightning_payment_pending"
                | "requester_lock_verified"
                | "requester_claim_pending"
                | "requester_claimed"
        ),
        ("reverse", StatusSigner::Provider) => matches!(
            state,
            "accepted"
                | "hold_invoice_ready"
                | "lightning_htlcs_held"
                | "provider_lock_terms_ready"
                | "provider_funding_broadcast"
                | "lightning_settlement_pending"
                | "lightning_paid"
                | "provider_refund_prepared"
                | "provider_refund_pending"
                | "provider_refunded"
                | "invoice_cancel_pending"
                | "invoice_cancelled"
        ),
        _ => false,
    }
}

fn boltz_status(swap_type: &str, state: &str) -> Option<(u16, &'static str)> {
    let states: &[&str] = match swap_type {
        "submarine" => &[
            "accepted",
            "lock_terms_ready",
            "requester_verification_passed",
            "funding_required",
            "requester_funding_broadcast",
            "funding_observed",
            "funding_final",
            "lightning_payment_pending",
            "lightning_paid",
            "cooperative_signing_pending",
            "provider_claim_pending",
            "provider_claimed",
            "refund_prepared",
            "refund_pending",
            "refunded",
            "cancelled",
            "expired",
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
        "reverse" => &[
            "accepted",
            "hold_invoice_ready",
            "requester_invoice_verified",
            "lightning_payment_pending",
            "lightning_htlcs_held",
            "provider_lock_terms_ready",
            "requester_lock_verified",
            "provider_funding_broadcast",
            "funding_observed",
            "funding_final",
            "cooperative_signing_pending",
            "requester_claim_pending",
            "requester_claimed",
            "lightning_settlement_pending",
            "lightning_paid",
            "provider_refund_prepared",
            "provider_refund_pending",
            "provider_refunded",
            "invoice_cancel_pending",
            "invoice_cancelled",
            "refunded",
            "cancelled",
            "expired",
            "completed",
            "disputed",
            "failed",
            "unresolved",
        ],
        _ => return None,
    };
    let rank = states
        .iter()
        .position(|candidate| *candidate == state)
        .and_then(|position| u16::try_from(position).ok())?;
    let status = match (swap_type, state) {
        (_, "accepted" | "lock_terms_ready" | "requester_verification_passed")
        | ("submarine", "funding_required" | "requester_funding_broadcast")
        | (
            "reverse",
            "hold_invoice_ready" | "requester_invoice_verified" | "provider_lock_terms_ready",
        )
        | ("reverse", "invoice_cancel_pending") => "swap.created",
        (_, "funding_observed") | ("reverse", "provider_funding_broadcast") => {
            "transaction.mempool"
        }
        (_, "funding_final")
        | ("submarine", "refund_prepared")
        | (
            "reverse",
            "requester_claim_pending" | "requester_claimed" | "provider_refund_prepared",
        ) => "transaction.confirmed",
        (_, "lightning_payment_pending")
        | ("reverse", "lightning_htlcs_held" | "requester_lock_verified") => "invoice.pending",
        (_, "lightning_paid") => "invoice.settled",
        (_, "cooperative_signing_pending")
        | ("submarine", "provider_claim_pending")
        | ("reverse", "lightning_settlement_pending") => "transaction.claim.pending",
        ("submarine", "provider_claimed" | "completed") | ("reverse", "completed") => {
            "transaction.claimed"
        }
        ("submarine", "refund_pending") | ("reverse", "provider_refund_pending") => {
            "transaction.mempool"
        }
        ("submarine", "refunded") | ("reverse", "provider_refunded" | "refunded") => {
            "transaction.refunded"
        }
        (_, "cancelled" | "expired") | ("reverse", "invoice_cancelled") => "swap.expired",
        (_, "disputed" | "failed" | "unresolved") => "transaction.failed",
        _ => return None,
    };
    Some((rank, status))
}

async fn public_transaction(
    api: &BoltzApi,
    transaction_id: &str,
) -> Result<HttpResponse, ApiError> {
    if !valid_hash(transaction_id) {
        return Err(ApiError::bad("transaction_id_invalid"));
    }
    let response = api
        .bitcoind
        .raw_transaction(
            &rpc_id("boltz-transaction", transaction_id)?,
            transaction_id,
            true,
        )
        .await
        .map_err(|_| ApiError::missing("transaction_not_found"))?;
    let object = response
        .as_object()
        .ok_or_else(|| ApiError::upstream("transaction_response_invalid"))?;
    let raw = object
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::upstream("transaction_response_invalid"))?;
    let confirmations = object
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(HttpResponse::ok(json!({
        "hex":raw,
        "confirmations":confirmations,
    })))
}

async fn released_preimage(api: &BoltzApi, session_id: &str) -> Result<HttpResponse, ApiError> {
    let records = session_records(api, session_id).await?;
    let terms = bilateral_contract(&records)?;
    if terms.get("swap_type").and_then(Value::as_str) != Some("submarine") {
        return Err(ApiError::conflict("session_swap_type_mismatch"));
    }
    let payment_hash = terms
        .get("payment_hash")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::conflict("payment_hash_missing"))?;
    let status = public_claim_transaction_id(&records)?;
    let response = api
        .bitcoind
        .raw_transaction(&rpc_id("boltz-preimage", session_id)?, &status, true)
        .await
        .map_err(|_| ApiError::conflict("claim_transaction_not_public"))?;
    let raw = response
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::upstream("claim_transaction_invalid"))?;
    let transaction = Transaction::parse(&decode_hex_bounded(raw, MAX_RAW_TRANSACTION_BYTES)?)
        .map_err(|_| ApiError::upstream("claim_transaction_invalid"))?;
    let preimage = transaction
        .inputs
        .iter()
        .flat_map(|input| input.witness.iter())
        .find(|item| item.len() == 32 && lower_hex(&Sha256::digest(item)) == payment_hash)
        .ok_or_else(|| ApiError::conflict("preimage_not_public"))?;
    Ok(HttpResponse::ok(json!({"preimage":lower_hex(preimage)})))
}

fn public_claim_transaction_id(records: &[Event]) -> Result<String, ApiError> {
    dense_statuses(records)?
        .into_iter()
        .filter_map(|status| {
            let state = status.profile.get("swp_state").and_then(Value::as_str)?;
            if !matches!(state, "provider_claim_pending" | "provider_claimed") {
                return None;
            }
            status
                .profile
                .get("transaction_id")
                .and_then(Value::as_str)
                .map(|transaction_id| (status.rank, transaction_id.to_owned()))
        })
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, transaction_id)| transaction_id)
        .ok_or_else(|| ApiError::conflict("preimage_not_public"))
}

async fn reverse_bip21(api: &BoltzApi, invoice: &str) -> Result<HttpResponse, ApiError> {
    let parsed = parse_bolt11(invoice).map_err(|_| ApiError::bad("invoice_invalid"))?;
    let session_id = {
        let store = api.store.lock().await;
        store
            .reverse_invoice_session(invoice)
            .await
            .map_err(|_| ApiError::upstream("provider_store_unavailable"))?
            .ok_or_else(|| ApiError::missing("reverse_invoice_not_found"))?
    };
    let records = session_records(api, &session_id).await?;
    if reverse_invoice(&records)? != invoice {
        return Err(ApiError::conflict("reverse_invoice_binding_mismatch"));
    }
    let terms = bilateral_contract(&records)?;
    if terms.get("payment_hash").and_then(Value::as_str)
        != Some(lower_hex(&parsed.payment_hash).as_str())
    {
        return Err(ApiError::conflict("reverse_invoice_binding_mismatch"));
    }
    let bitcoin = bitcoin_terms(&terms, "reverse")?;
    let address = taproot_address(api.network, bitcoin.script_pubkey)?;
    let amount = canonical_u64(
        bitcoin
            .verifier
            .get("amount")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("contract_amount_missing"))?,
    )?;
    let provider = exactly_one_kind(&records, MKT_QUOTE_KIND, "quote_missing")?
        .pubkey
        .as_str();
    let signature = records
        .iter()
        .find(|record| {
            record.kind == MKT_STATUS_KIND
                && record.pubkey == provider
                && profile_object(record)
                    .ok()
                    .and_then(|profile| {
                        profile
                            .get("invoice")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(invoice)
        })
        .map(|record| record.sig.clone())
        .ok_or_else(|| ApiError::conflict("invoice_status_missing"))?;
    Ok(HttpResponse::ok(json!({
        "bip21":bitcoin_bip21(&address, amount, Some(invoice)),
        "signature":signature,
    })))
}

async fn broadcast(api: &BoltzApi, request: &HttpRequest) -> Result<HttpResponse, ApiError> {
    let body = request_object(request)?;
    exact_members(&body, &["hex", "mktSessionId"])?;
    let session_id = body
        .get("mktSessionId")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::bad("mkt_session_id_required"))?;
    let raw = body
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("raw_transaction_required"))?;
    let raw_bytes = decode_hex_bounded(raw, MAX_RAW_TRANSACTION_BYTES)?;
    let records = session_records(api, session_id).await?;
    let terms = bilateral_contract(&records)?;
    let swap_type = terms
        .get("swap_type")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("contract_swap_type_missing"))?;
    let bitcoin = bitcoin_terms(&terms, swap_type)?;
    let committed = bitcoin
        .verifier
        .get("funding_transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("funding_transaction_not_finalized"))?;
    let candidate =
        Transaction::parse(&raw_bytes).map_err(|_| ApiError::bad("raw_transaction_invalid"))?;
    if raw != committed {
        verify_script_path_spend(&candidate, committed, &bitcoin, &terms, swap_type)?;
    }
    let expected_txid = lower_hex(
        &candidate
            .txid()
            .map_err(|_| ApiError::bad("raw_transaction_invalid"))?,
    );
    let result = api
        .bitcoind
        .broadcast(&rpc_id("boltz-broadcast", session_id)?, raw, None)
        .await;
    match result {
        Ok(transaction_id) if transaction_id == expected_txid => {
            Ok(HttpResponse::ok(json!({"id":transaction_id})))
        }
        Ok(_) => Err(ApiError::upstream("broadcast_transaction_id_mismatch")),
        Err(_) => {
            let replay = api
                .bitcoind
                .raw_transaction(
                    &rpc_id("boltz-broadcast-replay", session_id)?,
                    &expected_txid,
                    false,
                )
                .await;
            if replay
                .as_ref()
                .is_ok_and(|observed| exact_transaction_replay(observed, raw))
            {
                Ok(HttpResponse::ok(json!({"id":expected_txid})))
            } else {
                Err(ApiError::upstream("broadcast_failed"))
            }
        }
    }
}

fn exact_transaction_replay(observed: &Value, submitted: &str) -> bool {
    observed.as_str() == Some(submitted)
}

fn verify_script_path_spend(
    candidate: &Transaction,
    committed: &str,
    bitcoin: &BitcoinTerms<'_>,
    terms: &Map<String, Value>,
    swap_type: &str,
) -> Result<(), ApiError> {
    if swap_type != "reverse" {
        return Err(ApiError::conflict("transaction_not_session_bound"));
    }
    let funding = Transaction::parse(&decode_hex_bounded(committed, MAX_RAW_TRANSACTION_BYTES)?)
        .map_err(|_| ApiError::conflict("committed_funding_invalid"))?;
    let mut funding_txid_wire = funding
        .txid()
        .map_err(|_| ApiError::conflict("committed_funding_invalid"))?;
    // Transaction inputs serialize outpoints in wire order, while txid() returns display order.
    funding_txid_wire.reverse();
    let output_index = bitcoin
        .verifier
        .get("output_index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ApiError::conflict("funding_output_index_missing"))?;
    let input = candidate
        .inputs
        .iter()
        .find(|input| {
            input.previous_txid == funding_txid_wire && input.previous_output == output_index
        })
        .ok_or_else(|| ApiError::conflict("transaction_not_session_bound"))?;
    if input.witness.len() < 3 {
        return Err(ApiError::conflict("claim_witness_invalid"));
    }
    let script = decode_hex_bounded(bitcoin.claim_script, MAX_WS_FRAME_BYTES)?;
    let control = decode_hex_bounded(bitcoin.claim_control_block, MAX_WS_FRAME_BYTES)?;
    if input.witness.get(input.witness.len() - 2) != Some(&script)
        || input.witness.last() != Some(&control)
    {
        return Err(ApiError::conflict("claim_path_differs_from_contract"));
    }
    let payment_hash = terms
        .get("payment_hash")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::conflict("payment_hash_missing"))?;
    if !input
        .witness
        .iter()
        .any(|item| item.len() == 32 && lower_hex(&Sha256::digest(item)) == payment_hash)
    {
        return Err(ApiError::conflict("claim_preimage_differs_from_contract"));
    }
    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    api: &BoltzApi,
    response: HttpResponse,
) -> Result<(), String> {
    let body = serde_json::to_vec(&response.body)
        .map_err(|_| "response serialization failed".to_owned())?;
    let status = match response.status {
        200 => "200 OK",
        201 => "201 Created",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        409 => "409 Conflict",
        429 => "429 Too Many Requests",
        _ => "503 Service Unavailable",
    };
    let head = format!(
        concat!(
            "HTTP/1.1 {}\r\n",
            "Content-Type: application/json\r\n",
            "Content-Length: {}\r\n",
            "Access-Control-Allow-Origin: {}\r\n",
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n",
            "Access-Control-Allow-Headers: Content-Type\r\n",
            "Vary: Origin\r\n",
            "Cache-Control: no-store\r\n",
            "Connection: close\r\n\r\n"
        ),
        status,
        body.len(),
        api.allowed_origin,
    );
    timeout(REQUEST_TIMEOUT, async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| "response write timed out".to_owned())?
    .map_err(|_| "response write failed".to_owned())
}

async fn write_error(
    stream: &mut TcpStream,
    api: &BoltzApi,
    status: u16,
    code: &str,
) -> Result<(), String> {
    write_response(stream, api, HttpResponse::error(status, code)).await
}

async fn handle_websocket(
    stream: TcpStream,
    api: BoltzApi,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut websocket = timeout(REQUEST_TIMEOUT, tokio_tungstenite::accept_async(stream))
        .await
        .map_err(|_| "WebSocket handshake timed out".to_owned())?
        .map_err(|_| "WebSocket handshake failed".to_owned())?;
    let stream = websocket.get_mut();
    let mut subscriptions = BTreeSet::<String>::new();
    let mut last_statuses = BTreeMap::<String, Value>::new();
    let mut missing_sessions = BTreeSet::<String>::new();
    let mut message_budget = RateWindow::new(Instant::now());
    let mut query_budget = RateWindow::new(Instant::now());
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    write_ws_frame(stream, 0x8, &[]).await?;
                    return Ok(());
                }
            }
            frame = read_ws_frame(stream) => {
                let frame = frame?;
                if !message_budget.admit(Instant::now(), MAX_WS_MESSAGES_PER_MINUTE) {
                    write_ws_json(stream, &json!({"error":"rate_limited"})).await?;
                    return Err("WebSocket message rate limit reached".to_owned());
                }
                match frame.opcode {
                    0x1 => {
                        let request = std::str::from_utf8(&frame.payload)
                            .map_err(|_| "WebSocket text is not UTF-8".to_owned())?;
                        let message = parse_unique_json(request, "Boltz WebSocket request")
                            .map_err(|_| "WebSocket JSON is invalid".to_owned())?;
                        let object = message.as_object().ok_or_else(|| "WebSocket request is not an object".to_owned())?;
                        exact_ws_members(object, &["op", "channel", "args"])?;
                        let operation = object.get("op").and_then(Value::as_str)
                            .ok_or_else(|| "WebSocket operation is missing".to_owned())?;
                        if object.get("channel").and_then(Value::as_str) != Some("swap.update") {
                            return Err("WebSocket channel is outside the released profile".to_owned());
                        }
                        let ids = object.get("args").and_then(Value::as_array)
                            .ok_or_else(|| "WebSocket subscription args are missing".to_owned())?;
                        if ids.len() > MAX_WS_SUBSCRIPTIONS {
                            return Err("WebSocket subscription bound reached".to_owned());
                        }
                        for id in ids {
                            let id = id.as_str().filter(|value| valid_hash(value))
                                .ok_or_else(|| "WebSocket session ID is invalid".to_owned())?;
                            match operation {
                                "subscribe" => {
                                    if subscriptions.len() >= MAX_WS_SUBSCRIPTIONS && !subscriptions.contains(id) {
                                        return Err("WebSocket subscription bound reached".to_owned());
                                    }
                                    subscriptions.insert(id.to_owned());
                                }
                                "unsubscribe" => {
                                    subscriptions.remove(id);
                                    last_statuses.remove(id);
                                    missing_sessions.remove(id);
                                }
                                _ => return Err("WebSocket operation is unsupported".to_owned()),
                            }
                        }
                        write_ws_json(stream, &json!({
                            "event":operation,
                            "channel":"swap.update",
                            "args":ids,
                        })).await?;
                    }
                    0x8 => return Ok(()),
                    0x9 => write_ws_frame(stream, 0xA, &frame.payload).await?,
                    0xA => {}
                    _ => return Err("WebSocket frame type is unsupported".to_owned()),
                }
            }
            _ = sleep(WS_POLL_INTERVAL) => {
                let ids = subscriptions.iter().cloned().collect::<Vec<_>>();
                if ids.is_empty() {
                    continue;
                }
                if !query_budget.admit(
                    Instant::now(),
                    MAX_WS_STATUS_QUERY_BATCHES_PER_MINUTE,
                ) {
                    write_ws_json(stream, &json!({"error":"status_query_rate_limited"})).await?;
                    return Err("WebSocket status query budget reached".to_owned());
                }
                let grouped = session_record_batch(&api, &ids).await?;
                for id in ids {
                    let Some(records) = grouped.get(&id) else {
                        last_statuses.remove(&id);
                        if missing_sessions.insert(id.clone()) {
                            write_ws_json(stream, &json!({"error":"swap_not_found","id":id})).await?;
                        }
                        continue;
                    };
                    missing_sessions.remove(&id);
                    let status = project_status(&id, records)
                        .map_err(|error| format!("status projection failed: {}", error.code))?;
                    if last_statuses.get(&id) == Some(&status) {
                        continue;
                    }
                    last_statuses.insert(id, status.clone());
                    write_ws_json(stream, &json!({
                        "event":"update",
                        "channel":"swap.update",
                        "args":[status],
                    })).await?;
                }
            }
        }
    }
}

fn exact_ws_members(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err("WebSocket request member is outside the released profile".to_owned());
    }
    Ok(())
}

async fn session_record_batch(
    api: &BoltzApi,
    session_ids: &[String],
) -> Result<BTreeMap<String, Vec<Event>>, String> {
    let store = api.store.lock().await;
    store
        .session_records_for_sessions(session_ids, MAX_SESSION_RECORDS)
        .await
        .map_err(|_| "provider store is unavailable".to_owned())
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn read_ws_frame(stream: &mut TcpStream) -> Result<WebSocketFrame, String> {
    timeout(REQUEST_TIMEOUT, read_ws_frame_inner(stream))
        .await
        .map_err(|_| "WebSocket frame timed out".to_owned())?
}

async fn read_ws_frame_inner(stream: &mut TcpStream) -> Result<WebSocketFrame, String> {
    let mut head = [0_u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| "WebSocket closed".to_owned())?;
    if head[0] & 0x80 == 0 || head[0] & 0x70 != 0 || head[1] & 0x80 == 0 {
        return Err("WebSocket frame flags are invalid".to_owned());
    }
    let opcode = head[0] & 0x0f;
    let short = usize::from(head[1] & 0x7f);
    let length = match short {
        126 => {
            let mut bytes = [0_u8; 2];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| "WebSocket length is incomplete".to_owned())?;
            let length = usize::from(u16::from_be_bytes(bytes));
            if length < 126 {
                return Err("WebSocket length encoding is not canonical".to_owned());
            }
            length
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| "WebSocket length is incomplete".to_owned())?;
            let encoded = u64::from_be_bytes(bytes);
            if encoded < 65_536 || encoded & (1_u64 << 63) != 0 {
                return Err("WebSocket length encoding is not canonical".to_owned());
            }
            usize::try_from(encoded).map_err(|_| "WebSocket length overflows".to_owned())?
        }
        value => value,
    };
    if length > MAX_WS_FRAME_BYTES {
        return Err("WebSocket frame bound reached".to_owned());
    }
    if matches!(opcode, 0x8..=0xA) && length > 125 {
        return Err("WebSocket control frame bound reached".to_owned());
    }
    let mut mask = [0_u8; 4];
    stream
        .read_exact(&mut mask)
        .await
        .map_err(|_| "WebSocket mask is incomplete".to_owned())?;
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|_| "WebSocket payload is incomplete".to_owned())?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    if opcode == 0x8 {
        if payload.len() == 1 {
            return Err("WebSocket close payload is invalid".to_owned());
        }
        if payload.len() > 2 && std::str::from_utf8(&payload[2..]).is_err() {
            return Err("WebSocket close reason is not UTF-8".to_owned());
        }
    }
    Ok(WebSocketFrame { opcode, payload })
}

async fn write_ws_json(stream: &mut TcpStream, value: &Value) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| "WebSocket response is invalid".to_owned())?;
    write_ws_frame(stream, 0x1, &bytes).await
}

async fn write_ws_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_WS_FRAME_BYTES {
        return Err("WebSocket response bound reached".to_owned());
    }
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    match payload.len() {
        length @ 0..=125 => {
            frame.push(u8::try_from(length).map_err(|_| "WebSocket length failed".to_owned())?)
        }
        length @ 126..=65535 => {
            frame.push(126);
            frame.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| "WebSocket length failed".to_owned())?
                    .to_be_bytes(),
            );
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(
                &u64::try_from(length)
                    .map_err(|_| "WebSocket length failed".to_owned())?
                    .to_be_bytes(),
            );
        }
    }
    frame.extend_from_slice(payload);
    timeout(REQUEST_TIMEOUT, stream.write_all(&frame))
        .await
        .map_err(|_| "WebSocket write timed out".to_owned())?
        .map_err(|_| "WebSocket write failed".to_owned())
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    let mut values = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .filter_map(|tag| tag.value());
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn canonical_u64(value: &str) -> Result<u64, ApiError> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0') && value != "0"
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::conflict("canonical_amount_invalid"));
    }
    value
        .parse::<u64>()
        .map_err(|_| ApiError::conflict("canonical_amount_invalid"))
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], ApiError> {
    let bytes = decode_hex_bounded(value, N)?;
    <[u8; N]>::try_from(bytes).map_err(|_| ApiError::conflict("hex_length_invalid"))
}

fn decode_hex_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() / 2 > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("hex_invalid"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or_else(|| ApiError::bad("hex_invalid"))?;
        let low = hex_value(pair[1]).ok_or_else(|| ApiError::bad("hex_invalid"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_core::domain::Tag;
    use immortal_core::mkt_swp_verify::{TransactionInput, TransactionOutput};

    #[test]
    fn fixture_pins_full_dependent_coverage_and_honest_surface_count() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json"
        ))
        .expect("provider API fixture");
        assert_eq!(fixture["coverage"]["dependent_call_emulated_routes"], 19);
        assert_eq!(fixture["coverage"]["dependent_call_route_denominator"], 19);
        assert_eq!(fixture["coverage"]["endpoint_surface_emulated_routes"], 17);
        assert_eq!(fixture["coverage"]["backend_v2_route_denominator"], 53);
        assert_eq!(fixture["activation"]["nip11_advertised"], false);
        assert_eq!(
            fixture["process_gate"]["dependent_call_union"],
            fixture["coverage"]["dependent_call_route_denominator"]
        );
        assert_eq!(
            fixture["process_gate"]["adapted_clients"],
            json!(["go", "web"])
        );
        assert_eq!(
            fixture["native_session_binding"]["requester_script_path_exit_package_modes"],
            json!(["presigned", "wallet_sign"])
        );
        assert_eq!(fixture["limits"]["request_timeout_seconds"], 10);
        assert_eq!(
            fixture["limits"]["websocket_status_query_batches_per_minute"],
            60
        );
        assert_eq!(fixture["projection_law"]["created_at_orders_status"], false);
        assert_eq!(
            fixture["broadcast_law"]["duplicate_bitcoind_broadcast"],
            "idempotent only when getrawtransaction returns exact submitted raw bytes"
        );
        assert_eq!(
            fixture["broadcast_law"]["outpoint_comparison"],
            "transaction input wire order is compared with the reversed display-order funding transaction id"
        );
        assert_eq!(
            fixture["public_preimage_law"]["later_terminal_status_without_transaction_reference"],
            "does_not_hide_public_claim"
        );
        assert_eq!(
            fixture["process_gate"]["reverse_claim_evidence"],
            "both adapted clients resubmit the public script-path claim"
        );

        let funded_gate = include_str!("../../../scripts/test-provider-funded.sh");
        assert!(funded_gate.contains("compose exec -T bitcoin cat /etc/hosts"));
        assert!(funded_gate.contains("wait_for \"Boltz provider compatibility listener\""));
        assert!(!funded_gate.contains("IMMORTAL_PROVIDER_BOLTZ_BIND=127.0.0.1:19093"));
    }

    #[test]
    fn activation_digest_and_origin_are_fail_closed() {
        assert_eq!(boltz_provider_conformance_sha256().len(), 64);
        assert!(validate_origin("https://provider.example").is_ok());
        assert!(validate_origin("http://127.0.0.1:8081").is_ok());
        assert!(validate_origin("*").is_err());
        assert!(validate_origin("https://user@provider.example").is_err());
        assert!(validate_origin("https://provider.example/path").is_err());
        assert!(origin_allowed(None, "https://wallet.example"));
        assert!(origin_allowed(
            Some("https://wallet.example"),
            "https://wallet.example"
        ));
        assert!(!origin_allowed(
            Some("https://other.example"),
            "https://wallet.example"
        ));
    }

    #[test]
    fn status_mapping_is_explicit_and_refuses_unknown_states() {
        assert_eq!(
            boltz_status("submarine", "funding_final"),
            Some((6, "transaction.confirmed"))
        );
        assert_eq!(
            boltz_status("reverse", "provider_refunded"),
            Some((17, "transaction.refunded"))
        );
        assert_eq!(
            boltz_status("reverse", "provider_refund_prepared"),
            Some((15, "transaction.confirmed"))
        );
        assert_eq!(boltz_status("reverse", "future_state"), None);
    }

    #[test]
    fn status_projection_uses_dense_signer_streams_not_timestamps() {
        let mut records = session_records_fixture("submarine");
        records.push(status_fixture('c', '2', 100, 0, None, "accepted"));
        records.push(status_fixture(
            'd',
            '2',
            1,
            1,
            Some('c'),
            "funding_observed",
        ));
        assert_eq!(
            project_status(&"a".repeat(64), &records).expect("dense status projection")["status"],
            "transaction.mempool"
        );
    }

    #[test]
    fn prepared_refund_and_wrong_signer_fail_closed() {
        let mut records = session_records_fixture("reverse");
        records.push(status_fixture('c', '2', 1, 0, None, "accepted"));
        records.push(status_fixture(
            'd',
            '2',
            2,
            1,
            Some('c'),
            "provider_refund_prepared",
        ));
        assert_eq!(
            project_status(&"a".repeat(64), &records).expect("prepared projection")["status"],
            "transaction.confirmed"
        );
        records.pop();
        records.push(status_fixture(
            'e',
            '1',
            2,
            0,
            None,
            "provider_refund_prepared",
        ));
        assert_eq!(
            project_status(&"a".repeat(64), &records)
                .expect_err("wrong signer must fail")
                .code,
            "status_signer_invalid"
        );
    }

    #[test]
    fn completed_status_does_not_hide_public_claim_transaction() {
        let transaction_id = "f".repeat(64);
        let mut records = session_records_fixture("submarine");
        let mut claimed = status_fixture('c', '2', 1, 0, None, "provider_claimed");
        claimed.content = json!({
            "mkt_swp":{
                "swp_state":"provider_claimed",
                "transaction_id":transaction_id,
            }
        })
        .to_string();
        records.push(claimed);
        records.push(status_fixture('d', '2', 2, 1, Some('c'), "completed"));

        assert_eq!(
            public_claim_transaction_id(&records).expect("public claim transaction"),
            transaction_id
        );
    }

    #[test]
    fn broadcast_replay_requires_exact_witness_bytes() {
        let mut transaction = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [0; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![vec![1]],
            }],
            vec![TransactionOutput {
                value_sat: 1,
                script_pubkey: Vec::new(),
            }],
            0,
        );
        let first_txid = transaction.txid().expect("first txid");
        let first = lower_hex(&transaction.serialize(true).expect("first transaction"));
        transaction
            .set_input_witness(0, vec![vec![2]])
            .expect("witness mutation");
        let mutated = lower_hex(&transaction.serialize(true).expect("mutated transaction"));
        assert_eq!(first_txid, transaction.txid().expect("mutated txid"));
        assert!(exact_transaction_replay(
            &Value::String(first.clone()),
            &first
        ));
        assert!(!exact_transaction_replay(&Value::String(mutated), &first));
    }

    #[test]
    fn reverse_claim_binding_compares_outpoints_in_wire_order() {
        let funding = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [0x11; 32],
                previous_output: 3,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            vec![
                TransactionOutput {
                    value_sat: 1,
                    script_pubkey: vec![0x51],
                },
                TransactionOutput {
                    value_sat: 2,
                    script_pubkey: vec![0x51],
                },
            ],
            0,
        );
        let mut funding_txid_wire = funding.txid().expect("funding txid");
        funding_txid_wire.reverse();
        assert_ne!(funding_txid_wire, funding.txid().expect("display txid"));

        let preimage = [0x22; 32];
        let candidate = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: funding_txid_wire,
                previous_output: 1,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: vec![vec![0x30], preimage.to_vec(), vec![0x51], vec![0xc0, 0x01]],
            }],
            vec![TransactionOutput {
                value_sat: 1,
                script_pubkey: vec![0x51],
            }],
            0,
        );
        let verifier = json!({"output_index":1})
            .as_object()
            .expect("verifier object")
            .clone();
        let leg = Map::new();
        let bitcoin = BitcoinTerms {
            verifier: &verifier,
            leg: &leg,
            script_pubkey: [0; 34],
            claim_script: "51",
            refund_script: "",
            claim_control_block: "c001",
            refund_height: 0,
        };
        let terms = json!({"payment_hash":lower_hex(&Sha256::digest(preimage))})
            .as_object()
            .expect("terms object")
            .clone();
        let committed = lower_hex(&funding.serialize(true).expect("funding transaction"));

        verify_script_path_spend(&candidate, &committed, &bitcoin, &terms, "reverse")
            .expect("wire-order claim binding");
    }

    #[test]
    fn script_path_broadcast_costs_are_nonzero() {
        assert!(claim_spend_vbytes() > 0);
        assert!(crate::pricing::refund_spend_vbytes() > 0);
        assert!(lockup_vbytes() > 0);
    }

    fn session_records_fixture(swap_type: &str) -> Vec<Event> {
        vec![
            event_fixture(
                'a',
                '1',
                10,
                MKT_RFQ_KIND,
                Vec::new(),
                json!({"mkt_swp":{"constraints":{}}}),
            ),
            event_fixture(
                'b',
                '2',
                11,
                MKT_QUOTE_KIND,
                Vec::new(),
                json!({"mkt_swp":{"terms":{"swap_type":swap_type}}}),
            ),
        ]
    }

    fn status_fixture(
        id: char,
        author: char,
        created_at: u64,
        sequence: u64,
        previous: Option<char>,
        state: &str,
    ) -> Event {
        let mut tags = vec![Tag::new(vec!["seq".to_owned(), sequence.to_string()])];
        if let Some(previous) = previous {
            tags.push(Tag::new(vec![
                "e".to_owned(),
                previous.to_string().repeat(64),
                String::new(),
                "previous".to_owned(),
            ]));
        }
        event_fixture(
            id,
            author,
            created_at,
            MKT_STATUS_KIND,
            tags,
            json!({"mkt_swp":{"swp_state":state}}),
        )
    }

    fn event_fixture(
        id: char,
        author: char,
        created_at: u64,
        kind: u16,
        tags: Vec<Tag>,
        content: Value,
    ) -> Event {
        Event {
            id: id.to_string().repeat(64),
            pubkey: author.to_string().repeat(64),
            created_at,
            kind,
            tags,
            content: content.to_string(),
            sig: "0".repeat(128),
        }
    }
}
