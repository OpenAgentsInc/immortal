use crate::{
    bitcoind::{BitcoindClient, RpcRequestId},
    contract::boltz_provider_conformance_sha256,
    health::private_or_loopback,
    lightning::LightningRail,
    pricing::{PricingConfig, claim_spend_vbytes, lockup_vbytes},
    store::{InvoiceBinding, MAX_SESSION_RECORDS, ProviderStore},
    wallet::{BitcoinNetwork, encode_segwit_v1_address},
};
use immortal_client::mkt_swp_client::{
    SwapClientConfig,
    provider_support::{self, ValidatedSession},
};
use immortal_core::{
    boltz_compat::{BOLTZ_MAPPING_REVISION, classify_boltz_handoff, safe_origin_form},
    domain::{
        Event, MKT_QUOTE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_SWP_SWAP_CONTRACT_KIND,
        parse_unique_json,
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc, watch},
    time::{Instant as TokioInstant, sleep, timeout, timeout_at},
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
pub const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
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
    rates: Arc<Mutex<BTreeMap<IpAddr, RateBudgets>>>,
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

    async fn admit(&self, address: IpAddr, budget: RateBudget) -> bool {
        let now = Instant::now();
        let mut rates = self.rates.lock().await;
        admit_rate(&mut rates, address, budget, now)
    }

    async fn admit_connection(&self, address: IpAddr) -> bool {
        self.admit(address, RateBudget::Connection).await
    }

    async fn admit_websocket_message(&self, address: IpAddr) -> bool {
        self.admit(address, RateBudget::WebSocketMessage).await
    }

    async fn admit_websocket_query(&self, address: IpAddr) -> bool {
        self.admit(address, RateBudget::WebSocketQuery).await
    }
}

fn admit_rate(
    rates: &mut BTreeMap<IpAddr, RateBudgets>,
    address: IpAddr,
    budget: RateBudget,
    now: Instant,
) -> bool {
    rates.retain(|_, rate| now.duration_since(rate.last_seen) < Duration::from_secs(120));
    if rates.len() >= MAX_RATE_IDENTITIES && !rates.contains_key(&address) {
        return false;
    }
    let rates = rates
        .entry(address)
        .or_insert_with(|| RateBudgets::new(now));
    rates.last_seen = now;
    match budget {
        RateBudget::Connection => rates.connections.admit(now, MAX_REQUESTS_PER_MINUTE),
        RateBudget::WebSocketMessage => rates
            .websocket_messages
            .admit(now, MAX_WS_MESSAGES_PER_MINUTE),
        RateBudget::WebSocketQuery => rates
            .websocket_queries
            .admit(now, MAX_WS_STATUS_QUERY_BATCHES_PER_MINUTE),
    }
}

#[derive(Clone, Copy)]
enum RateBudget {
    Connection,
    WebSocketMessage,
    WebSocketQuery,
}

struct RateBudgets {
    last_seen: Instant,
    connections: RateWindow,
    websocket_messages: RateWindow,
    websocket_queries: RateWindow,
}

impl RateBudgets {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            connections: RateWindow::new(now),
            websocket_messages: RateWindow::new(now),
            websocket_queries: RateWindow::new(now),
        }
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
                let connection_deadline = TokioInstant::now() + REQUEST_TIMEOUT;
                drop(tokio::spawn(async move {
                    let _permit = permit;
                    let admitted = timeout_at(
                        connection_deadline,
                        api.admit_connection(peer.ip()),
                    )
                    .await
                    .unwrap_or(false);
                    if !admitted {
                        let mut stream = stream;
                        let response = HttpResponse::error(429, "rate_limited");
                        if let Err(error) = timeout_at(
                            connection_deadline,
                            write_response_inner(&mut stream, &api, response),
                        )
                        .await
                        .map_err(|_| "connection_deadline_reached".to_owned())
                        .and_then(|result| result)
                        {
                            eprintln!(
                                "immortal-provider: Boltz rate-limit response failed: {error}"
                            );
                        }
                        return;
                    }
                    if let Err(error) = handle_connection(
                        stream,
                        peer.ip(),
                        api,
                        shutdown,
                        connection_deadline,
                    )
                    .await
                    {
                        eprintln!("immortal-provider: Boltz request failed: {error}");
                    }
                }));
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: IpAddr,
    api: BoltzApi,
    shutdown: watch::Receiver<bool>,
    deadline: TokioInstant,
) -> Result<(), String> {
    let preview = timeout_at(deadline, preview_http_head_inner(&stream))
        .await
        .map_err(|_| "connection_deadline_reached".to_owned())??;
    if websocket_request(&preview, &api)? {
        return handle_websocket(stream, peer, api, shutdown, deadline).await;
    }
    timeout_at(deadline, async {
        let request = match read_request_inner(&mut stream).await {
            Ok(request) => request,
            Err(error) => {
                write_response_inner(&mut stream, &api, HttpResponse::error(400, &error)).await?;
                return Ok(());
            }
        };
        let response = route_request(&api, request).await;
        write_response_inner(&mut stream, &api, response).await
    })
    .await
    .map_err(|_| "connection_deadline_reached".to_owned())?
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
    let config = provider_support::session_config(&records)
        .map_err(|error| ApiError::conflict(error.code))?;
    if config.session_id != session_id {
        return Err(ApiError::conflict("session_id_mismatch"));
    }
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
    let terms = if swap_type == "submarine" {
        validated_ordered_submarine_terms(&config, &records)?
    } else {
        validated_bilateral_session(&records)?
            .1
            .contract
            .as_object()
            .cloned()
            .ok_or_else(|| ApiError::conflict("bilateral_contract_invalid"))?
    };
    validate_creation_against_native(&body, rfq, &quote_terms, &terms, swap_type)?;
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
        let invoice_binding = reverse_invoice_binding(api, session_id).await?;
        exact_reverse_invoice_status(&records, &invoice_binding)?;
        let invoice = invoice_binding.invoice;
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
    quote_terms: &Map<String, Value>,
    contract_terms: &Map<String, Value>,
    swap_type: &str,
) -> Result<(), ApiError> {
    let constraints = profile_object(rfq)?
        .get("constraints")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| ApiError::conflict("rfq_constraints_missing"))?;
    let input_amount = constraints
        .get("input_amount")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::conflict("rfq_input_amount_missing"))?;
    if quote_terms.get("input_amount").and_then(Value::as_str) != Some(input_amount)
        || contract_terms.get("input_amount").and_then(Value::as_str) != Some(input_amount)
    {
        return Err(ApiError::conflict("amount_differs_across_signed_session"));
    }
    let payment_hash = constraints
        .get("payment_hash")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| ApiError::conflict("rfq_payment_hash_missing"))?;
    if quote_terms.get("payment_hash").and_then(Value::as_str) != Some(payment_hash)
        || contract_terms.get("payment_hash").and_then(Value::as_str) != Some(payment_hash)
    {
        return Err(ApiError::conflict(
            "payment_hash_differs_across_signed_session",
        ));
    }
    if swap_type == "submarine" {
        let invoice = body
            .get("invoice")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("invoice_required"))?;
        let parsed = parse_bolt11(invoice).map_err(|_| ApiError::bad("invoice_invalid"))?;
        let invoice_digest = lower_hex(&Sha256::digest(invoice.as_bytes()));
        if constraints.get("invoice_sha256").and_then(Value::as_str)
            != Some(invoice_digest.as_str())
            || payment_hash != lower_hex(&parsed.payment_hash)
        {
            return Err(ApiError::conflict("invoice_differs_from_signed_rfq"));
        }
        let refund_key = body
            .get("refundPublicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("refund_public_key_required"))?;
        let quote_bitcoin = bitcoin_leg(quote_terms, swap_type)?;
        let contract_bitcoin = bitcoin_leg(contract_terms, swap_type)?;
        if quote_bitcoin
            .get("refund_public_key")
            .and_then(Value::as_str)
            != Some(refund_key)
            || contract_bitcoin
                .get("refund_public_key")
                .and_then(Value::as_str)
                != Some(refund_key)
        {
            return Err(ApiError::conflict("refund_key_differs_from_signed_quote"));
        }
    } else {
        let supplied_payment_hash = body
            .get("preimageHash")
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .ok_or_else(|| ApiError::bad("preimage_hash_required"))?;
        if supplied_payment_hash != payment_hash {
            return Err(ApiError::conflict("payment_hash_differs_from_signed_rfq"));
        }
        let claim_key = body
            .get("claimPublicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::bad("claim_public_key_required"))?;
        let quote_bitcoin = bitcoin_leg(quote_terms, swap_type)?;
        let contract_bitcoin = bitcoin_leg(contract_terms, swap_type)?;
        if quote_bitcoin
            .get("claim_public_key")
            .and_then(Value::as_str)
            != Some(claim_key)
            || contract_bitcoin
                .get("claim_public_key")
                .and_then(Value::as_str)
                != Some(claim_key)
        {
            return Err(ApiError::conflict("claim_key_differs_from_signed_contract"));
        }
        let amount = body
            .get("invoiceAmount")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::bad("reverse_amount_required"))?;
        if input_amount != amount.to_string() {
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

fn bitcoin_leg<'a>(
    terms: &'a Map<String, Value>,
    swap_type: &str,
) -> Result<&'a Map<String, Value>, ApiError> {
    let leg_id = if swap_type == "submarine" {
        "source"
    } else {
        "destination"
    };
    terms
        .get("legs")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .find(|value| value.get("leg_id").and_then(Value::as_str) == Some(leg_id))
        })
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("bitcoin_leg_missing"))
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
    let leg = bitcoin_leg(terms, swap_type)?;
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

fn exact_tag_value<'a>(event: &'a Event, name: &str) -> Result<&'a str, ApiError> {
    let values = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .filter_map(|tag| tag.value())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(value),
        _ => Err(ApiError::conflict("signed_session_record_invalid")),
    }
}

fn validated_bilateral_session(
    records: &[Event],
) -> Result<(SwapClientConfig, ValidatedSession), ApiError> {
    let config = provider_support::session_config(records)
        .map_err(|error| ApiError::conflict(error.code))?;
    let session = provider_support::validate_bound_session(&config, records)
        .map_err(|error| ApiError::conflict(error.code))?;
    Ok((config, session))
}

fn validated_ordered_submarine_terms(
    config: &SwapClientConfig,
    records: &[Event],
) -> Result<Map<String, Value>, ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::upstream("system_clock_invalid"))?
        .as_secs();
    validated_ordered_submarine_terms_at(config, records, now)
}

fn validated_ordered_submarine_terms_at(
    config: &SwapClientConfig,
    records: &[Event],
    now: u64,
) -> Result<Map<String, Value>, ApiError> {
    let precontract = provider_support::validate_precontract_session(config, records)
        .map_err(|error| ApiError::conflict(error.code))?;
    let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "quote_missing")?;
    if exact_tag_value(quote, "reservation")? != "hard" {
        return Err(ApiError::conflict("firm_reservation_required"));
    }
    let expiration = exact_tag_value(quote, "expiration")?
        .parse::<u64>()
        .map_err(|_| ApiError::conflict("quote_expiration_invalid"))?;
    if expiration <= now {
        return Err(ApiError::conflict("quote_expired"));
    }
    let quote_profile = profile_object(quote)?;
    let reservation = quote_profile
        .get("reservation_terms")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::conflict("firm_reservation_required"))?;
    if reservation
        .get("reservation_expires_at")
        .and_then(Value::as_u64)
        != Some(expiration)
        || !matches!(
            reservation.get("proof_class").and_then(Value::as_str),
            Some(
                "provider_signed"
                    | "utxo_control"
                    | "lightning_liquidity"
                    | "covenant_reserve"
                    | "third_party_guarantee"
            )
        )
    {
        return Err(ApiError::conflict("firm_reservation_required"));
    }
    let contract_count = records
        .iter()
        .filter(|event| event.kind == MKT_SWP_SWAP_CONTRACT_KIND)
        .count();
    match contract_count {
        0 => precontract
            .quote_terms
            .as_object()
            .cloned()
            .ok_or_else(|| ApiError::conflict("quote_terms_missing")),
        1 => Err(ApiError::conflict("bilateral_contract_incomplete")),
        2 => validated_bilateral_session(records)?
            .1
            .contract
            .as_object()
            .cloned()
            .ok_or_else(|| ApiError::conflict("bilateral_contract_invalid")),
        _ => Err(ApiError::conflict("signed_session_fork")),
    }
}

fn bilateral_contract(records: &[Event]) -> Result<Map<String, Value>, ApiError> {
    validated_bilateral_session(records)?
        .1
        .contract
        .as_object()
        .cloned()
        .ok_or_else(|| ApiError::conflict("bilateral_contract_invalid"))
}

async fn reverse_invoice_binding(
    api: &BoltzApi,
    session_id: &str,
) -> Result<InvoiceBinding, ApiError> {
    let store = api.store.lock().await;
    store
        .reverse_invoice_binding_for_session(session_id)
        .await
        .map_err(|_| ApiError::upstream("provider_store_unavailable"))?
        .ok_or_else(|| ApiError::conflict("reverse_invoice_not_released"))
}

fn exact_reverse_invoice_status<'a>(
    records: &'a [Event],
    binding: &InvoiceBinding,
) -> Result<&'a Event, ApiError> {
    let provider = exactly_one_kind(records, MKT_QUOTE_KIND, "quote_missing")?
        .pubkey
        .as_str();
    let matching = records
        .iter()
        .filter(|record| record.id == binding.status_event_id)
        .collect::<Vec<_>>();
    let [status] = matching.as_slice() else {
        return Err(ApiError::conflict("invoice_status_missing"));
    };
    let profile = profile_object(status)?;
    if binding.session_id != exact_tag_value(status, "session")?
        || status.kind != MKT_STATUS_KIND
        || status.pubkey != provider
        || profile.get("swp_state").and_then(Value::as_str) != Some("hold_invoice_ready")
        || profile.get("invoice").and_then(Value::as_str) != Some(binding.invoice.as_str())
    {
        return Err(ApiError::conflict("reverse_invoice_binding_mismatch"));
    }
    let parsed = parse_bolt11(&binding.invoice)
        .map_err(|_| ApiError::conflict("reverse_invoice_binding_mismatch"))?;
    if lower_hex(&parsed.payment_hash) != binding.payment_hash {
        return Err(ApiError::conflict("reverse_invoice_binding_mismatch"));
    }
    Ok(status)
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
    let (config, session) = validated_bilateral_session(&records)?;
    if config.session_id != session_id {
        return Err(ApiError::conflict("session_id_mismatch"));
    }
    let terms = session
        .contract
        .as_object()
        .cloned()
        .ok_or_else(|| ApiError::conflict("bilateral_contract_invalid"))?;
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
        "requesterContractEventId":session.requester_contract_id,
        "providerContractEventId":session.provider_contract_id,
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
    let (config, session) = validated_bilateral_session(records)?;
    provider_support::validate_status_history(&config, records, &session.contract)
        .map_err(|error| ApiError::conflict(error.code))?;
    let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "quote_missing")?;
    let quote_profile = profile_object(quote)?;
    let swap_type = quote_profile
        .get("terms")
        .and_then(Value::as_object)
        .and_then(|terms| terms.get("swap_type"))
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "submarine" | "reverse"))
        .ok_or_else(|| ApiError::conflict("session_swap_type_mismatch"))?;
    let mut dense = Vec::new();
    for event in records.iter().filter(|event| event.kind == MKT_STATUS_KIND) {
        let profile = profile_object(event)?;
        let state = profile
            .get("swp_state")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::conflict("status_state_missing"))?;
        let (rank, boltz_status) = boltz_status(swap_type, state)
            .ok_or_else(|| ApiError::conflict("status_state_unrepresentable"))?;
        dense.push(DenseStatus {
            event,
            profile,
            rank,
            boltz_status,
        });
    }
    validate_cross_signer_outcome(swap_type, &dense)?;
    Ok(dense)
}

fn validate_cross_signer_outcome(
    swap_type: &str,
    statuses: &[DenseStatus<'_>],
) -> Result<(), ApiError> {
    let has_state = |states: &[&str]| {
        statuses.iter().any(|status| {
            status
                .profile
                .get("swp_state")
                .and_then(Value::as_str)
                .is_some_and(|state| states.contains(&state))
        })
    };
    let (claim_states, refund_states): (&[&str], &[&str]) = match swap_type {
        "submarine" => (
            &["provider_claim_pending", "provider_claimed"],
            &["refund_pending", "refunded"],
        ),
        "reverse" => (
            &[
                "requester_claim_pending",
                "requester_claimed",
                "lightning_settlement_pending",
                "lightning_paid",
            ],
            &[
                "provider_refund_pending",
                "provider_refunded",
                "invoice_cancel_pending",
                "invoice_cancelled",
                "refunded",
            ],
        ),
        _ => return Err(ApiError::conflict("session_swap_type_mismatch")),
    };
    if has_state(claim_states) && has_state(refund_states) {
        return Err(ApiError::conflict("cross_signer_terminal_conflict"));
    }
    Ok(())
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
        ("reverse", "provider_funding_broadcast") => "swap.created",
        (_, "funding_observed") => "transaction.mempool",
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
    let binding = {
        let store = api.store.lock().await;
        let session_id = store
            .reverse_invoice_session(invoice)
            .await
            .map_err(|_| ApiError::upstream("provider_store_unavailable"))?
            .ok_or_else(|| ApiError::missing("reverse_invoice_not_found"))?;
        store
            .reverse_invoice_binding_for_session(&session_id)
            .await
            .map_err(|_| ApiError::upstream("provider_store_unavailable"))?
            .ok_or_else(|| ApiError::conflict("reverse_invoice_binding_mismatch"))?
    };
    let records = session_records(api, &binding.session_id).await?;
    if binding.invoice != invoice || lower_hex(&parsed.payment_hash) != binding.payment_hash {
        return Err(ApiError::conflict("reverse_invoice_binding_mismatch"));
    }
    let invoice_status = exact_reverse_invoice_status(&records, &binding)?;
    let terms = bilateral_contract(&records)?;
    if terms.get("payment_hash").and_then(Value::as_str) != Some(binding.payment_hash.as_str()) {
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
    Ok(HttpResponse::ok(json!({
        "bip21":bitcoin_bip21(&address, amount, Some(invoice)),
        "signature":invoice_status.sig,
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

async fn write_response_inner<W: AsyncWrite + Unpin>(
    stream: &mut W,
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
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|_| "response write failed".to_owned())?;
    stream
        .write_all(&body)
        .await
        .map_err(|_| "response write failed".to_owned())?;
    stream
        .shutdown()
        .await
        .map_err(|_| "response write failed".to_owned())
}

async fn handle_websocket(
    stream: TcpStream,
    peer: IpAddr,
    api: BoltzApi,
    mut shutdown: watch::Receiver<bool>,
    connection_deadline: TokioInstant,
) -> Result<(), String> {
    let websocket = timeout_at(connection_deadline, tokio_tungstenite::accept_async(stream))
        .await
        .map_err(|_| "connection_deadline_reached".to_owned())?
        .map_err(|_| "WebSocket handshake failed".to_owned())?;
    let stream = websocket.into_inner();
    let (reader, mut writer) = stream.into_split();
    let (frame_sender, mut frame_receiver) = mpsc::channel(1);
    let reader_task = tokio::spawn(forward_ws_frames(
        reader,
        frame_sender,
        WS_IDLE_TIMEOUT,
        REQUEST_TIMEOUT,
    ));
    let mut subscriptions = BTreeSet::<String>::new();
    let mut last_statuses = BTreeMap::<String, Value>::new();
    let mut missing_sessions = BTreeSet::<String>::new();
    let result = async {
        loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    write_ws_frame(&mut writer, 0x8, &[]).await?;
                    return Ok(());
                }
            }
            frame = frame_receiver.recv() => {
                let frame = frame
                    .ok_or_else(|| "WebSocket frame reader stopped".to_owned())??;
                if !api.admit_websocket_message(peer).await {
                    write_ws_json(&mut writer, &json!({"error":"rate_limited"})).await?;
                    return Err("WebSocket message rate limit reached".to_owned());
                }
                match frame.opcode {
                    0x1 => {
                        let request = std::str::from_utf8(&frame.payload)
                            .map_err(|_| "WebSocket text is not UTF-8".to_owned())?;
                        let message = parse_unique_json(request, "Boltz WebSocket request")
                            .map_err(|_| "WebSocket JSON is invalid".to_owned())?;
                        let object = message.as_object().ok_or_else(|| "WebSocket request is not an object".to_owned())?;
                        let operation = object.get("op").and_then(Value::as_str)
                            .ok_or_else(|| "WebSocket operation is missing".to_owned())?;
                        if operation == "ping" {
                            exact_ws_members(object, &["op"])?;
                            write_ws_json(&mut writer, &websocket_pong_response()).await?;
                            continue;
                        }
                        exact_ws_members(object, &["op", "channel", "args"])?;
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
                        write_ws_json(&mut writer, &json!({
                            "event":operation,
                            "channel":"swap.update",
                            "args":ids,
                        })).await?;
                    }
                    0x8 => return Ok(()),
                    0x9 => write_ws_frame(&mut writer, 0xA, &frame.payload).await?,
                    0xA => {}
                    _ => return Err("WebSocket frame type is unsupported".to_owned()),
                }
            }
            _ = sleep(WS_POLL_INTERVAL) => {
                let ids = subscriptions.iter().cloned().collect::<Vec<_>>();
                if ids.is_empty() {
                    continue;
                }
                if !api.admit_websocket_query(peer).await {
                    write_ws_json(&mut writer, &json!({"error":"status_query_rate_limited"})).await?;
                    return Err("WebSocket status query budget reached".to_owned());
                }
                let grouped = session_record_batch(&api, &ids).await?;
                for id in ids {
                    let Some(records) = grouped.get(&id) else {
                        last_statuses.remove(&id);
                        if missing_sessions.insert(id.clone()) {
                            write_ws_json(&mut writer, &json!({"error":"swap_not_found","id":id})).await?;
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
                    write_ws_json(&mut writer, &json!({
                        "event":"update",
                        "channel":"swap.update",
                        "args":[status],
                    })).await?;
                }
            }
        }
        }
    }
    .await;
    reader_task.abort();
    match reader_task.await {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {}
        Err(_) if result.is_err() => {}
        Err(_) => return Err("WebSocket frame reader failed".to_owned()),
    }
    result
}

fn exact_ws_members(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().any(|name| !allowed.contains(name.as_str())) {
        return Err("WebSocket request member is outside the released profile".to_owned());
    }
    Ok(())
}

fn websocket_pong_response() -> Value {
    json!({"event":"pong"})
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

#[derive(Debug)]
struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

#[cfg(test)]
async fn read_ws_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<WebSocketFrame, String> {
    read_ws_frame_with_timeout(stream, REQUEST_TIMEOUT).await
}

#[cfg(test)]
async fn read_ws_frame_with_timeout<R: AsyncRead + Unpin>(
    stream: &mut R,
    frame_deadline: Duration,
) -> Result<WebSocketFrame, String> {
    read_ws_frame_with_timeouts(stream, frame_deadline, frame_deadline).await
}

async fn read_ws_frame_with_timeouts<R: AsyncRead + Unpin>(
    stream: &mut R,
    idle_deadline: Duration,
    frame_deadline: Duration,
) -> Result<WebSocketFrame, String> {
    let mut first = [0_u8; 1];
    timeout(idle_deadline, stream.read_exact(&mut first))
        .await
        .map_err(|_| "WebSocket idle deadline reached".to_owned())?
        .map_err(|_| "WebSocket closed".to_owned())?;
    timeout(
        frame_deadline,
        read_ws_frame_after_first_byte(stream, first[0]),
    )
    .await
    .map_err(|_| "WebSocket partial frame timed out".to_owned())?
}

async fn forward_ws_frames<R: AsyncRead + Unpin>(
    mut reader: R,
    sender: mpsc::Sender<Result<WebSocketFrame, String>>,
    idle_deadline: Duration,
    frame_deadline: Duration,
) {
    loop {
        let frame = read_ws_frame_with_timeouts(&mut reader, idle_deadline, frame_deadline).await;
        let terminal = frame.is_err();
        if sender.send(frame).await.is_err() || terminal {
            return;
        }
    }
}

async fn read_ws_frame_after_first_byte<R: AsyncRead + Unpin>(
    stream: &mut R,
    first: u8,
) -> Result<WebSocketFrame, String> {
    let mut head = [first, 0_u8];
    stream
        .read_exact(&mut head[1..])
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

async fn write_ws_json<W: AsyncWrite + Unpin>(stream: &mut W, value: &Value) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| "WebSocket response is invalid".to_owned())?;
    write_ws_frame(stream, 0x1, &bytes).await
}

async fn write_ws_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    opcode: u8,
    payload: &[u8],
) -> Result<(), String> {
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
    use crate::{ProviderSession, ReservationConfirmation, ReservationRequest};
    use immortal_client::mkt_swp_client::{
        ParticipantRole, StatusState, SwapClientConfig, SwapContractReferences, SwapRecordFactory,
    };
    use immortal_core::domain::{MKT_ORDER_KIND, Tag};
    use immortal_core::market::MarketSigner;
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
            fixture["process_gate"]["clean_room_client_seams"],
            json!(["go", "web"])
        );
        assert_eq!(
            fixture["process_gate"]["pinned_upstream_client_builds"],
            false
        );
        assert_eq!(
            fixture["native_session_binding"]["requester_script_path_exit_package_modes"],
            json!(["presigned", "wallet_sign"])
        );
        assert_eq!(fixture["limits"]["connection_deadline_seconds"], 10);
        assert_eq!(
            fixture["limits"]["websocket_frame_completion_deadline_seconds"],
            10
        );
        assert_eq!(fixture["limits"]["websocket_idle_deadline_seconds"], 90);
        assert_eq!(
            fixture["network_failure_cases"].as_array().map(Vec::len),
            Some(14)
        );
        assert_eq!(
            fixture["semantic_failure_cases"].as_array().map(Vec::len),
            Some(37)
        );
        assert_eq!(
            fixture["limits"]["websocket_status_query_batches_per_minute_per_ip"],
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
        let go_process_gate =
            include_str!("../../../adapters/boltz-client-go/provider_process_test.go");
        assert!(funded_gate.contains("compose exec -T bitcoin cat /etc/hosts"));
        assert!(funded_gate.contains("wait_for \"Boltz provider compatibility listener\""));
        assert!(funded_gate.contains("TestAdaptedGoClientAgainstProviderProcess"));
        assert!(go_process_gate.contains("websocketUpdate(t, baseURL, prepared.SessionID, true)"));
        assert!(!funded_gate.contains("IMMORTAL_PROVIDER_BOLTZ_BIND=127.0.0.1:19093"));
    }

    #[test]
    fn submarine_contract_admission_fixture_cases_are_executable() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json"
        ))
        .expect("provider API fixture");
        let cases = fixture["submarine_contract_admission_cases"]
            .as_array()
            .expect("submarine Contract admission cases");
        assert_eq!(cases.len(), 12);
        let foreign = MarketSigner::from_secret_bytes([0x42; 32]).expect("foreign signer");

        for case in cases {
            let name = case["name"].as_str().expect("admission case name");
            let contract_count = case["contract_count"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .expect("admission Contract count");
            let mutation = case["mutation"].as_str().expect("admission mutation");
            let expected = case["expected"].as_str().expect("admission result");
            let mut records = submarine_admission_records_fixture();
            let mut retained_contracts = 0_usize;
            records.retain(|event| {
                if event.kind != MKT_SWP_SWAP_CONTRACT_KIND {
                    return true;
                }
                retained_contracts = retained_contracts.saturating_add(1);
                retained_contracts <= contract_count
            });

            match mutation {
                "none" => {}
                "invalid_rfq" => resign_admission_record(
                    &mut records,
                    MKT_RFQ_KIND,
                    &fixture_signer(ParticipantRole::Requester),
                    |_, content| *content = "{}".to_owned(),
                ),
                "foreign_rfq_author" => {
                    resign_admission_record(&mut records, MKT_RFQ_KIND, &foreign, |_, _| {})
                }
                "invalid_quote" => resign_admission_record(
                    &mut records,
                    MKT_QUOTE_KIND,
                    &fixture_signer(ParticipantRole::Provider),
                    |_, content| *content = "{}".to_owned(),
                ),
                "foreign_quote_author" => {
                    resign_admission_record(&mut records, MKT_QUOTE_KIND, &foreign, |_, _| {})
                }
                "misbound_quote_rfq" => resign_admission_record(
                    &mut records,
                    MKT_QUOTE_KIND,
                    &fixture_signer(ParticipantRole::Provider),
                    |tags, _| replace_marked_reference(tags, "rfq", &"f1".repeat(32)),
                ),
                "invalid_order" => resign_admission_record(
                    &mut records,
                    MKT_ORDER_KIND,
                    &fixture_signer(ParticipantRole::Requester),
                    |_, content| *content = "{}".to_owned(),
                ),
                "foreign_order_author" => {
                    resign_admission_record(&mut records, MKT_ORDER_KIND, &foreign, |_, _| {})
                }
                "misbound_order_quote" => resign_admission_record(
                    &mut records,
                    MKT_ORDER_KIND,
                    &fixture_signer(ParticipantRole::Requester),
                    |tags, _| replace_marked_reference(tags, "quote", &"f2".repeat(32)),
                ),
                "misbound_offering_authority" => resign_admission_record(
                    &mut records,
                    MKT_RFQ_KIND,
                    &fixture_signer(ParticipantRole::Requester),
                    |tags, _| {
                        replace_tag_value(
                            tags,
                            "a",
                            &format!("39601:{}:btc-lightning-regtest", foreign.pubkey()),
                        )
                    },
                ),
                _ => panic!("unknown admission mutation {mutation}"),
            }

            let result = provider_support::session_config(&records)
                .map_err(|error| ApiError::conflict(error.code))
                .and_then(|config| validated_ordered_submarine_terms_at(&config, &records, 150));
            match expected {
                "accepted" => assert!(result.is_ok(), "{name}: {result:?}"),
                "refused" => assert!(result.is_err(), "{name} unexpectedly passed"),
                _ => panic!("unknown admission expectation {expected}"),
            }
        }
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

    #[tokio::test]
    async fn network_failure_fixture_cases_are_executable() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json"
        ))
        .expect("provider API fixture");
        let cases = fixture["network_failure_cases"]
            .as_array()
            .expect("network cases")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            cases,
            BTreeSet::from([
                "http-idle-before-first-byte-times-out",
                "http-64-idle-connections-expire-under-one-deadline",
                "http-body-slow-drip-total-deadline",
                "websocket-handshake-total-deadline",
                "websocket-length-stall-persistent-deadline",
                "websocket-mask-stall-persistent-deadline",
                "websocket-payload-stall-persistent-deadline",
                "websocket-idle-allows-pinned-heartbeat-cadence",
                "websocket-application-ping-gets-pong",
                "websocket-control-payload-over-125-refused",
                "websocket-noncanonical-extended-length-refused",
                "websocket-unknown-request-member-refused",
                "websocket-message-rate-shared-across-peer-connections",
                "websocket-query-rate-shared-across-peer-connections",
            ])
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let mut idle_clients = Vec::new();
        let mut idle_servers = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let connecting = TcpStream::connect(address);
            let (client, accepted) = tokio::join!(connecting, listener.accept());
            idle_clients.push(client.expect("idle client"));
            let (server, _) = accepted.expect("idle server");
            idle_servers.push(tokio::spawn(async move {
                timeout(Duration::from_millis(25), preview_http_head_inner(&server))
                    .await
                    .is_err()
            }));
        }
        for server in idle_servers {
            assert!(server.await.expect("idle deadline task"));
        }
        drop(idle_clients);

        let (mut client, mut server) = tcp_pair().await;
        client
            .write_all(
                b"POST /v2/swap/reverse HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{",
            )
            .await
            .expect("slow body prefix");
        let deadline = TokioInstant::now() + Duration::from_millis(40);
        timeout_at(deadline, preview_http_head_inner(&server))
            .await
            .expect("head before deadline")
            .expect("HTTP head");
        let drip = tokio::spawn(async move {
            for byte in b"1234567" {
                sleep(Duration::from_millis(15)).await;
                if client.write_all(&[*byte]).await.is_err() {
                    return;
                }
            }
        });
        assert!(
            timeout_at(deadline, read_request_inner(&mut server))
                .await
                .is_err()
        );
        drip.abort();

        let (mut handshake_client, handshake_server) = tcp_pair().await;
        handshake_client
            .write_all(b"G")
            .await
            .expect("handshake prefix");
        assert!(
            timeout(
                Duration::from_millis(25),
                tokio_tungstenite::accept_async(handshake_server),
            )
            .await
            .is_err()
        );

        assert_persistent_frame_stall(&[0x81, 0xfe]).await;
        assert_persistent_frame_stall(&[0x81, 0x81, 0x00, 0x01]).await;
        assert_persistent_frame_stall(&[0x81, 0x81, 0x00, 0x01, 0x02, 0x03]).await;
        let (mut heartbeat_client, mut heartbeat_server) = tcp_pair().await;
        let delayed_heartbeat = tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            write_masked_frame(&mut heartbeat_client, br#"{"op":"ping"}"#).await;
        });
        let heartbeat = read_ws_frame_with_timeouts(
            &mut heartbeat_server,
            Duration::from_millis(100),
            Duration::from_millis(20),
        )
        .await
        .expect("idle connection accepts a later complete heartbeat");
        delayed_heartbeat.await.expect("delayed heartbeat");
        let heartbeat_json = parse_unique_json(
            std::str::from_utf8(&heartbeat.payload).expect("heartbeat UTF-8"),
            "test heartbeat",
        )
        .expect("heartbeat JSON");
        let heartbeat_object = heartbeat_json.as_object().expect("heartbeat object");
        assert_eq!(
            heartbeat_object.get("op").and_then(Value::as_str),
            Some("ping")
        );
        exact_ws_members(heartbeat_object, &["op"]).expect("exact application ping");
        assert_eq!(websocket_pong_response(), json!({"event":"pong"}));
        assert_frame_rejected(&[0x88, 0xfe, 0x00, 0x7e], "control frame").await;
        assert_frame_rejected(&[0x81, 0xfe, 0x00, 0x01], "not canonical").await;

        let payload = br#"{"op":"subscribe","channel":"swap.update","args":[],"extra":true}"#;
        let (mut unknown_client, mut unknown_server) = tcp_pair().await;
        write_masked_frame(&mut unknown_client, payload).await;
        let frame = read_ws_frame(&mut unknown_server)
            .await
            .expect("bounded WebSocket frame");
        let value = parse_unique_json(
            std::str::from_utf8(&frame.payload).expect("UTF-8 frame"),
            "test WebSocket request",
        )
        .expect("unique JSON");
        assert!(
            exact_ws_members(
                value.as_object().expect("request object"),
                &["op", "channel", "args"]
            )
            .is_err()
        );

        let peer = "127.0.0.1".parse::<IpAddr>().expect("loopback IP");
        let now = Instant::now();
        let mut rates = BTreeMap::new();
        for _connection in 0..2 {
            for _ in 0..(MAX_WS_MESSAGES_PER_MINUTE / 2) {
                assert!(admit_rate(
                    &mut rates,
                    peer,
                    RateBudget::WebSocketMessage,
                    now
                ));
            }
        }
        assert!(!admit_rate(
            &mut rates,
            peer,
            RateBudget::WebSocketMessage,
            now
        ));
        for _connection in 0..2 {
            for _ in 0..(MAX_WS_STATUS_QUERY_BATCHES_PER_MINUTE / 2) {
                assert!(admit_rate(
                    &mut rates,
                    peer,
                    RateBudget::WebSocketQuery,
                    now
                ));
            }
        }
        assert!(!admit_rate(
            &mut rates,
            peer,
            RateBudget::WebSocketQuery,
            now
        ));
    }

    #[test]
    fn semantic_failure_fixture_cases_are_bound_to_fail_closed_checks() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/boltz-provider-api-v1.json"
        ))
        .expect("provider API fixture");
        let cases = fixture["semantic_failure_cases"]
            .as_array()
            .expect("semantic cases")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(cases.len(), 37);

        let mut oversized_sequence = session_records_fixture("submarine");
        append_mutated_status(
            &mut oversized_sequence,
            ParticipantRole::Provider,
            "accepted",
            Map::new(),
            |tags| replace_tag_value(tags, "seq", &u64::MAX.to_string()),
        );
        assert!(dense_statuses(&oversized_sequence).is_err());

        for terminal in ["completed", "refunded"] {
            let mut records = session_records_fixture("submarine");
            append_status(
                &mut records,
                ParticipantRole::Provider,
                0,
                terminal,
                Map::new(),
            );
            assert!(dense_statuses(&records).is_err());
        }

        for (swap_type, successful, terminal) in [
            ("submarine", "provider_claimed", "completed"),
            ("reverse", "provider_refunded", "refunded"),
        ] {
            let mut records = session_records_fixture(swap_type);
            append_status(
                &mut records,
                ParticipantRole::Provider,
                0,
                "accepted",
                Map::new(),
            );
            append_status(
                &mut records,
                ParticipantRole::Provider,
                1,
                successful,
                Map::new(),
            );
            append_status(
                &mut records,
                ParticipantRole::Provider,
                2,
                terminal,
                Map::new(),
            );
            assert!(dense_statuses(&records).is_err());
        }

        for mutation in ["artifact", "policy", "verifier"] {
            let mut records = session_records_fixture("submarine");
            append_status(
                &mut records,
                ParticipantRole::Provider,
                0,
                "accepted",
                Map::new(),
            );
            let mut extra = evidence_extra("submarine", "measured", "bitcoin_output");
            let evidence = extra
                .get_mut("evidence")
                .and_then(Value::as_object_mut)
                .expect("fixture evidence");
            match mutation {
                "artifact" => {
                    evidence.insert("artifact_sha256".to_owned(), Value::String("99".repeat(32)));
                }
                "policy" => {
                    evidence.insert(
                        "verifier_policy".to_owned(),
                        Value::String("mkt-swp-lightning-v1".to_owned()),
                    );
                }
                "verifier" => {
                    evidence.insert("verifier_pubkey".to_owned(), Value::String("88".repeat(32)));
                }
                _ => unreachable!("bounded mutation"),
            }
            append_status(
                &mut records,
                ParticipantRole::Provider,
                1,
                "funding_observed",
                extra,
            );
            assert!(dense_statuses(&records).is_err());
        }

        let mut conflicting_outcomes = session_records_fixture("submarine");
        for (index, state) in [
            "accepted",
            "funding_observed",
            "funding_final",
            "lightning_paid",
            "provider_claim_pending",
            "provider_claimed",
        ]
        .into_iter()
        .enumerate()
        {
            let mut extra = match state {
                "funding_observed" => evidence_extra("submarine", "measured", "bitcoin_output"),
                "funding_final" => evidence_extra("submarine", "verified", "bitcoin_output"),
                "lightning_paid" => evidence_extra("submarine", "settled", "lightning_payment"),
                "provider_claim_pending" => evidence_extra("submarine", "measured", "claim"),
                "provider_claimed" => evidence_extra("submarine", "settled", "bitcoin_spend"),
                _ => Map::new(),
            };
            if matches!(state, "provider_claim_pending" | "provider_claimed") {
                extra.insert("transaction_id".to_owned(), Value::String("f".repeat(64)));
            }
            append_status(
                &mut conflicting_outcomes,
                ParticipantRole::Provider,
                u64::try_from(index).expect("provider state index"),
                state,
                extra,
            );
        }
        for (index, state) in [
            "requester_verification_passed",
            "requester_funding_broadcast",
            "refund_prepared",
            "refund_pending",
            "refunded",
        ]
        .into_iter()
        .enumerate()
        {
            let mut extra = if state == "refund_pending" {
                let mut extra = evidence_extra("submarine", "settled", "claim");
                let evidence = extra
                    .get_mut("evidence")
                    .and_then(Value::as_object_mut)
                    .expect("requester refund evidence");
                evidence.insert("class".to_owned(), Value::String("refund".to_owned()));
                evidence.insert(
                    "producer_pubkey".to_owned(),
                    Value::String(
                        fixture_signer(ParticipantRole::Requester)
                            .pubkey()
                            .to_owned(),
                    ),
                );
                extra
            } else {
                Map::new()
            };
            if state == "refund_pending" {
                extra.insert("transaction_id".to_owned(), Value::String("f".repeat(64)));
            }
            append_status(
                &mut conflicting_outcomes,
                ParticipantRole::Requester,
                u64::try_from(index).expect("requester state index"),
                state,
                extra,
            );
        }
        assert!(dense_statuses(&conflicting_outcomes).is_err());

        let mut completed_before_claim = session_records_fixture("submarine");
        for (index, state) in [
            "accepted",
            "lock_terms_ready",
            "funding_observed",
            "funding_final",
            "lightning_payment_pending",
            "lightning_paid",
            "completed",
        ]
        .into_iter()
        .enumerate()
        {
            let extra = match state {
                "funding_observed" => evidence_extra("submarine", "measured", "bitcoin_output"),
                "funding_final" => evidence_extra("submarine", "verified", "bitcoin_output"),
                "lightning_paid" => evidence_extra("submarine", "settled", "lightning_payment"),
                _ => Map::new(),
            };
            append_status(
                &mut completed_before_claim,
                ParticipantRole::Provider,
                u64::try_from(index).expect("premature completion index"),
                state,
                extra,
            );
        }
        assert!(dense_statuses(&completed_before_claim).is_err());

        let mut under_evidenced_refund = session_records_fixture("submarine");
        for (index, state) in [
            "requester_verification_passed",
            "requester_funding_broadcast",
            "refund_prepared",
            "refund_pending",
            "refunded",
        ]
        .into_iter()
        .enumerate()
        {
            let mut extra = if matches!(state, "refund_pending" | "refunded") {
                requester_refund_extra("measured")
            } else {
                Map::new()
            };
            if matches!(state, "refund_pending" | "refunded") {
                extra.insert("transaction_id".to_owned(), Value::String("f".repeat(64)));
            }
            append_status(
                &mut under_evidenced_refund,
                ParticipantRole::Requester,
                u64::try_from(index).expect("refund evidence index"),
                state,
                extra,
            );
        }
        assert!(dense_statuses(&under_evidenced_refund).is_err());

        let mut cancelled_after_claim = session_records_fixture("submarine");
        for (index, state) in [
            "accepted",
            "lock_terms_ready",
            "funding_observed",
            "funding_final",
            "lightning_payment_pending",
            "lightning_paid",
            "provider_claim_pending",
            "provider_claimed",
        ]
        .into_iter()
        .enumerate()
        {
            let mut extra = match state {
                "funding_observed" => evidence_extra("submarine", "measured", "bitcoin_output"),
                "funding_final" => evidence_extra("submarine", "verified", "bitcoin_output"),
                "lightning_paid" => evidence_extra("submarine", "settled", "lightning_payment"),
                "provider_claim_pending" => evidence_extra("submarine", "measured", "claim"),
                "provider_claimed" => evidence_extra("submarine", "settled", "bitcoin_spend"),
                _ => Map::new(),
            };
            if matches!(state, "provider_claim_pending" | "provider_claimed") {
                extra.insert("transaction_id".to_owned(), Value::String("f".repeat(64)));
            }
            append_status(
                &mut cancelled_after_claim,
                ParticipantRole::Provider,
                u64::try_from(index).expect("cancelled claim index"),
                state,
                extra,
            );
        }
        append_status(
            &mut cancelled_after_claim,
            ParticipantRole::Requester,
            0,
            "cancelled",
            Map::new(),
        );
        assert!(dense_statuses(&cancelled_after_claim).is_err());

        let mut base_mismatch = session_records_fixture("submarine");
        append_mutated_status(
            &mut base_mismatch,
            ParticipantRole::Provider,
            "accepted",
            Map::new(),
            |tags| replace_tag_value(tags, "state", "awaiting_input"),
        );
        assert!(dense_statuses(&base_mismatch).is_err());

        let mut order_mismatch = session_records_fixture("submarine");
        append_mutated_status(
            &mut order_mismatch,
            ParticipantRole::Provider,
            "accepted",
            Map::new(),
            |tags| replace_marked_reference(tags, "order", &"ff".repeat(32)),
        );
        assert!(dense_statuses(&order_mismatch).is_err());

        let mut predecessor_mismatch = session_records_fixture("submarine");
        append_status(
            &mut predecessor_mismatch,
            ParticipantRole::Provider,
            0,
            "accepted",
            Map::new(),
        );
        append_mutated_status(
            &mut predecessor_mismatch,
            ParticipantRole::Provider,
            "lock_terms_ready",
            Map::new(),
            |tags| replace_marked_reference(tags, "previous", &"ee".repeat(32)),
        );
        assert!(dense_statuses(&predecessor_mismatch).is_err());

        let mut evidence_missing = session_records_fixture("submarine");
        append_status(
            &mut evidence_missing,
            ParticipantRole::Provider,
            0,
            "accepted",
            Map::new(),
        );
        append_status(
            &mut evidence_missing,
            ParticipantRole::Provider,
            1,
            "lock_terms_ready",
            Map::new(),
        );
        append_status(
            &mut evidence_missing,
            ParticipantRole::Provider,
            2,
            "funding_observed",
            Map::new(),
        );
        assert!(dense_statuses(&evidence_missing).is_err());

        let mut out_of_order = session_records_fixture("reverse");
        append_status(
            &mut out_of_order,
            ParticipantRole::Provider,
            200,
            "hold_invoice_ready",
            Map::new(),
        );
        let hold_invoice_status_id = out_of_order
            .last()
            .map(|event| event.id.clone())
            .expect("hold-invoice Status");
        append_status(
            &mut out_of_order,
            ParticipantRole::Provider,
            201,
            "lightning_htlcs_held",
            Map::new(),
        );
        let missing_predecessor_id = out_of_order
            .last()
            .map(|event| event.id.clone())
            .expect("intermediate Status");
        append_status(
            &mut out_of_order,
            ParticipantRole::Provider,
            202,
            "provider_lock_terms_ready",
            Map::new(),
        );
        out_of_order.retain(|event| event.id != missing_predecessor_id);
        let (config, session) =
            validated_bilateral_session(&out_of_order).expect("out-of-order bilateral session");
        assert!(
            provider_support::validate_status_history(&config, &out_of_order, &session.contract,)
                .is_err()
        );
        provider_support::validate_status_prefix(
            &config,
            &out_of_order,
            &session.contract,
            &hold_invoice_status_id,
        )
        .expect("immutable invoice prefix ignores an unrelated later Status gap");

        let mut optional_state_skip = session_records_fixture("submarine");
        append_status(
            &mut optional_state_skip,
            ParticipantRole::Requester,
            300,
            "requester_verification_passed",
            Map::new(),
        );
        append_status(
            &mut optional_state_skip,
            ParticipantRole::Requester,
            301,
            "requester_funding_broadcast",
            Map::new(),
        );
        dense_statuses(&optional_state_skip)
            .expect("requester may skip an optional funding-required Status");

        assert_eq!(
            boltz_status("reverse", "provider_funding_broadcast"),
            Some((7, "swap.created"))
        );
        assert_eq!(
            boltz_status("reverse", "funding_observed"),
            Some((8, "transaction.mempool"))
        );

        let mut foreign_contract = session_records_fixture("reverse");
        let contract = foreign_contract
            .iter_mut()
            .find(|event| event.kind == 39610)
            .expect("Swap Contract");
        let foreign = MarketSigner::from_secret_bytes([0x42; 32]).expect("foreign signer");
        *contract = foreign.sign(
            contract.created_at,
            contract.kind,
            contract.tags.clone(),
            contract.content.clone(),
        );
        assert!(validated_bilateral_session(&foreign_contract).is_err());

        let records = session_records_fixture("reverse");
        let rfq = exactly_one_kind(&records, MKT_RFQ_KIND, "rfq").expect("RFQ");
        let quote = exactly_one_kind(&records, MKT_QUOTE_KIND, "quote").expect("Quote");
        let quote_terms = profile_object(quote)
            .expect("Quote profile")
            .get("terms")
            .and_then(Value::as_object)
            .cloned()
            .expect("Quote terms");
        let contract = bilateral_contract(&records).expect("bilateral Contract");
        let claim_public_key = contract
            .get("legs")
            .and_then(Value::as_array)
            .and_then(|legs| {
                legs.iter().find_map(|leg| {
                    (leg.get("rail").and_then(Value::as_str) == Some("bitcoin"))
                        .then(|| leg.get("claim_public_key").cloned())
                        .flatten()
                })
            })
            .expect("reverse claim public key");
        let constraints = profile_object(rfq)
            .expect("RFQ profile")
            .get("constraints")
            .and_then(Value::as_object)
            .cloned()
            .expect("RFQ constraints");
        let mut body = json!({
            "preimageHash":constraints["payment_hash"],
            "claimPublicKey":claim_public_key,
            "invoiceAmount":canonical_u64(constraints["input_amount"].as_str().expect("amount")).expect("canonical amount"),
        })
        .as_object()
        .expect("creation body")
        .clone();
        validate_creation_against_native(&body, rfq, &quote_terms, &contract, "reverse")
            .expect("bound reverse creation");
        body.insert("claimPublicKey".to_owned(), Value::String("02".repeat(32)));
        assert!(
            validate_creation_against_native(&body, rfq, &quote_terms, &contract, "reverse")
                .is_err()
        );
        body.insert("claimPublicKey".to_owned(), claim_public_key);
        body.insert("invoiceAmount".to_owned(), json!(1));
        assert!(
            validate_creation_against_native(&body, rfq, &quote_terms, &contract, "reverse")
                .is_err()
        );

        assert!(!exact_transaction_replay(
            &Value::String("00".to_owned()),
            "01"
        ));
        assert_eq!(
            cases,
            BTreeSet::from([
                "admission-one-contract-incomplete-refused",
                "admission-invalid-rfq-refused",
                "admission-foreign-rfq-author-refused",
                "admission-invalid-quote-refused",
                "admission-foreign-quote-author-refused",
                "admission-quote-rfq-reference-misbound-refused",
                "admission-invalid-order-refused",
                "admission-foreign-order-author-refused",
                "admission-order-quote-reference-misbound-refused",
                "admission-offering-authority-misbound-refused",
                "status-created-at-skew-does-not-reorder-sequences",
                "status-base-state-mismatch-refused",
                "status-order-reference-mismatch-refused",
                "status-predecessor-mismatch-refused",
                "status-required-evidence-missing-refused",
                "status-sequence-over-record-bound-refused",
                "status-terminal-completed-seq0-refused",
                "status-terminal-refunded-seq0-refused",
                "status-evidence-artifact-contract-mismatch-refused",
                "status-evidence-policy-contract-mismatch-refused",
                "status-evidence-verifier-authority-mismatch-refused",
                "status-cross-signer-claim-refund-conflict-refused",
                "status-completed-before-swap-claim-refused",
                "status-refunded-without-settled-evidence-refused",
                "status-cancelled-after-claim-settlement-refused",
                "status-funding-observed-projects-mempool",
                "status-prepared-does-not-project-mempool",
                "status-provider-funding-broadcast-does-not-project-mempool",
                "foreign-contract-signer-refused",
                "reverse-claim-key-mismatch-refused",
                "reverse-conflicting-amount-fields-refused",
                "reverse-requester-or-foreign-invoice-index-poison-refused",
                "reverse-invoice-contract-payment-hash-mismatch-refused",
                "reverse-invoice-index-ignores-unrelated-later-status-gap",
                "reverse-invoice-read-ignores-later-provider-invoice-poison",
                "broadcast-replay-same-txid-different-witness-refused",
                "reverse-invoice-index-survives-more-than-6144-history-records",
            ])
        );
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
    fn reverse_invoice_reads_use_the_exact_indexed_status() {
        const INVOICE: &str = "lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0";
        let mut records = session_records_fixture("reverse");
        append_status(
            &mut records,
            ParticipantRole::Provider,
            100,
            "hold_invoice_ready",
            Map::from_iter([("invoice".to_owned(), Value::String(INVOICE.to_owned()))]),
        );
        let indexed = records.last().expect("indexed invoice Status");
        let indexed_signature = indexed.sig.clone();
        let binding = InvoiceBinding {
            payment_hash: lower_hex(&parse_bolt11(INVOICE).expect("fixture BOLT11").payment_hash),
            invoice: INVOICE.to_owned(),
            session_id: exact_tag_value(indexed, "session")
                .expect("invoice session")
                .to_owned(),
            status_event_id: indexed.id.clone(),
        };
        append_status(
            &mut records,
            ParticipantRole::Provider,
            101,
            "lightning_htlcs_held",
            Map::from_iter([(
                "invoice".to_owned(),
                Value::String("later-provider-poison".to_owned()),
            )]),
        );
        let status = exact_reverse_invoice_status(&records, &binding)
            .expect("exact immutable invoice Status");
        assert_eq!(status.id, binding.status_event_id);
        assert_eq!(status.sig, indexed_signature);
    }

    #[test]
    fn status_projection_uses_dense_signer_streams_not_timestamps() {
        let mut records = session_records_fixture("submarine");
        append_status(
            &mut records,
            ParticipantRole::Provider,
            100,
            "accepted",
            Map::new(),
        );
        append_status(
            &mut records,
            ParticipantRole::Provider,
            50,
            "lock_terms_ready",
            Map::new(),
        );
        append_status(
            &mut records,
            ParticipantRole::Provider,
            1,
            "funding_observed",
            evidence_extra("submarine", "measured", "bitcoin_output"),
        );
        assert_eq!(
            project_status(&"a".repeat(64), &records).expect("dense status projection")["status"],
            "transaction.mempool"
        );
    }

    #[test]
    fn prepared_refund_and_wrong_signer_fail_closed() {
        let mut records = session_records_fixture("reverse");
        for (index, state) in [
            "accepted",
            "hold_invoice_ready",
            "lightning_htlcs_held",
            "provider_lock_terms_ready",
            "provider_funding_broadcast",
        ]
        .into_iter()
        .enumerate()
        {
            append_status(
                &mut records,
                ParticipantRole::Provider,
                u64::try_from(index).expect("test index"),
                state,
                Map::new(),
            );
        }
        append_status(
            &mut records,
            ParticipantRole::Provider,
            5,
            "funding_observed",
            evidence_extra("reverse", "measured", "bitcoin_output"),
        );
        append_status(
            &mut records,
            ParticipantRole::Provider,
            6,
            "funding_final",
            evidence_extra("reverse", "verified", "bitcoin_output"),
        );
        append_status(
            &mut records,
            ParticipantRole::Provider,
            7,
            "provider_refund_prepared",
            Map::new(),
        );
        assert_eq!(
            project_status(&"a".repeat(64), &records).expect("prepared projection")["status"],
            "transaction.confirmed"
        );
        let mut wrong_signer = session_records_fixture("reverse");
        append_status_signed_by(
            &mut wrong_signer,
            ParticipantRole::Provider,
            ParticipantRole::Requester,
            1,
            "accepted",
            Map::new(),
        );
        assert!(project_status(&"a".repeat(64), &wrong_signer).is_err());
    }

    #[test]
    fn completed_status_does_not_hide_public_claim_transaction() {
        let transaction_id = "f".repeat(64);
        let mut records = session_records_fixture("submarine");
        for (index, state) in [
            "accepted",
            "lock_terms_ready",
            "funding_observed",
            "funding_final",
            "lightning_payment_pending",
            "lightning_paid",
            "provider_claim_pending",
            "provider_claimed",
            "completed",
        ]
        .into_iter()
        .enumerate()
        {
            let mut extra = match state {
                "funding_observed" => evidence_extra("submarine", "measured", "bitcoin_output"),
                "funding_final" => evidence_extra("submarine", "verified", "bitcoin_output"),
                "lightning_paid" => evidence_extra("submarine", "settled", "lightning_payment"),
                "provider_claim_pending" => evidence_extra("submarine", "measured", "claim"),
                "provider_claimed" => evidence_extra("submarine", "settled", "bitcoin_spend"),
                _ => Map::new(),
            };
            if matches!(state, "provider_claim_pending" | "provider_claimed") {
                extra.insert(
                    "transaction_id".to_owned(),
                    Value::String(transaction_id.clone()),
                );
            }
            append_status(
                &mut records,
                ParticipantRole::Provider,
                u64::try_from(index).expect("test index"),
                state,
                extra,
            );
        }

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

    fn submarine_admission_records_fixture() -> Vec<Event> {
        let source = session_records_fixture("submarine");
        let config = provider_support::session_config(&source).expect("fixture session config");
        let factory = SwapRecordFactory::new(config.clone()).expect("fixture record factory");
        let requester = fixture_signer(ParticipantRole::Requester);
        let provider = fixture_signer(ParticipantRole::Provider);

        let source_rfq = exactly_one_kind(&source, MKT_RFQ_KIND, "rfq").expect("fixture RFQ");
        let rfq_request = factory
            .rfq(
                100,
                &"a1".repeat(32),
                300,
                Value::Object(profile_object(source_rfq).expect("fixture RFQ profile")),
            )
            .expect("admission RFQ request");
        let rfq = requester.sign(
            rfq_request.created_at,
            rfq_request.kind,
            rfq_request.tags,
            rfq_request.content,
        );

        let source_quote =
            exactly_one_kind(&source, MKT_QUOTE_KIND, "quote").expect("fixture Quote");
        let mut quote_profile = profile_object(source_quote).expect("fixture Quote profile");
        quote_profile.remove("reservation_terms");
        let mut provider_session =
            ProviderSession::new(config.clone()).expect("admission provider session");
        assert!(
            provider_session
                .ingest_signed(rfq.clone())
                .expect("ingest admission RFQ")
        );
        let quote_request = provider_session
            .hard_quote_with_reserve(
                101,
                &"a2".repeat(32),
                200,
                ReservationRequest {
                    reservation_id: "b1".repeat(32),
                    capacity_bucket_id: "boltz-admission".to_owned(),
                    reserved_asset_id:
                        "swp:1:bip122:00000000000000000000000000000000:btc:lightning".to_owned(),
                    reserved_amount: "1000".to_owned(),
                    reservation_expires_at: 200,
                },
                Value::Object(quote_profile),
                |request| {
                    Ok(ReservationConfirmation {
                        reservation_id: request.reservation_id.clone(),
                        capacity_bucket_id: request.capacity_bucket_id.clone(),
                        reserved_asset_id: request.reserved_asset_id.clone(),
                        reserved_amount: request.reserved_amount.clone(),
                        committed_capacity: request.reserved_amount.clone(),
                        reservation_expires_at: request.reservation_expires_at,
                        allocation_sequence: "1".to_owned(),
                        proof_class: "lightning_liquidity".to_owned(),
                        proof_ref: "boltz-admission:cln:1".to_owned(),
                        capacity_commitment_sha256: lower_hex(&Sha256::digest(
                            b"boltz-admission-capacity",
                        )),
                    })
                },
            )
            .expect("admission hard Quote request");
        let quote = provider.sign(
            quote_request.created_at,
            quote_request.kind,
            quote_request.tags,
            quote_request.content,
        );
        let order_request = factory
            .order(
                102,
                &"a3".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .expect("admission Order request");
        let order = requester.sign(
            order_request.created_at,
            order_request.kind,
            order_request.tags,
            order_request.content,
        );

        let mut contract = bilateral_contract(&source).expect("fixture bilateral Contract");
        contract.insert("order_id".to_owned(), Value::String(order.id.clone()));
        contract.insert("quote_id".to_owned(), Value::String(quote.id.clone()));
        let signed_quote_profile = profile_object(&quote).expect("signed hard Quote profile");
        let reservation = signed_quote_profile
            .get("reservation_terms")
            .and_then(Value::as_object)
            .expect("signed hard Quote reservation");
        let proof_ref = reservation
            .get("proof_ref")
            .and_then(Value::as_str)
            .expect("signed hard Quote proof reference");
        contract.insert(
            "reservation_commitment".to_owned(),
            json!({
                "session_id":config.session_id,
                "rfq_id":rfq.id,
                "quote_id":quote.id,
                "reservation_id":reservation["reservation_id"],
                "reservation_class":"hard",
                "capacity_bucket_id":reservation["capacity_bucket_id"],
                "reserved_asset_id":reservation["reserved_asset_id"],
                "reserved_amount":reservation["reserved_amount"],
                "handler_committed_capacity":reservation["handler_committed_capacity"],
                "allocation_sequence":reservation["allocation_sequence"],
                "proof_class":reservation["proof_class"],
                "proof_strength":50,
                "proof_ref_sha256":lower_hex(&Sha256::digest(proof_ref.as_bytes())),
                "capacity_commitment_sha256":reservation["capacity_commitment_sha256"],
                "reservation_expires_at":reservation["reservation_expires_at"],
                "profile_timeout_at":null,
                "covenant_commitment":null
            }),
        );
        let references = SwapContractReferences {
            order_id: &order.id,
            quote_id: &quote.id,
            accepted_status_id: None,
        };
        let requester_contract_request = factory
            .swap_contract(
                ParticipantRole::Requester,
                103,
                &"a4".repeat(32),
                references,
                Value::Object(contract.clone()),
            )
            .expect("requester admission Contract request");
        let requester_contract = requester.sign(
            requester_contract_request.created_at,
            requester_contract_request.kind,
            requester_contract_request.tags,
            requester_contract_request.content,
        );
        let provider_contract_request = factory
            .swap_contract(
                ParticipantRole::Provider,
                104,
                &"a5".repeat(32),
                references,
                Value::Object(contract),
            )
            .expect("provider admission Contract request");
        let provider_contract = provider.sign(
            provider_contract_request.created_at,
            provider_contract_request.kind,
            provider_contract_request.tags,
            provider_contract_request.content,
        );
        vec![rfq, quote, order, requester_contract, provider_contract]
    }

    fn resign_admission_record(
        records: &mut [Event],
        kind: u16,
        signer: &MarketSigner,
        mutate: impl FnOnce(&mut [Tag], &mut String),
    ) {
        let event = records
            .iter_mut()
            .find(|event| event.kind == kind)
            .expect("admission record");
        let mut tags = event.tags.clone();
        let mut content = event.content.clone();
        mutate(&mut tags, &mut content);
        *event = signer.sign(event.created_at, event.kind, tags, content);
    }

    fn session_records_fixture(swap_type: &str) -> Vec<Event> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
        ))
        .expect("full session fixture");
        serde_json::from_value(fixture["flows"][swap_type]["snapshot"]["signed_records"].clone())
            .expect("signed session records")
    }

    fn append_status(
        records: &mut Vec<Event>,
        role: ParticipantRole,
        created_at: u64,
        state: &str,
        extra: Map<String, Value>,
    ) {
        append_status_signed_by(records, role, role, created_at, state, extra);
    }

    fn append_status_signed_by(
        records: &mut Vec<Event>,
        role: ParticipantRole,
        signer_role: ParticipantRole,
        created_at: u64,
        state: &str,
        extra: Map<String, Value>,
    ) {
        let config = provider_support::session_config(records).expect("session config");
        let factory = SwapRecordFactory::new(config.clone()).expect("record factory");
        let signer = fixture_signer(signer_role);
        assert_eq!(signer.pubkey(), config_pubkey(&config, signer_role));
        let statuses = records
            .iter()
            .filter(|event| event.kind == MKT_STATUS_KIND && event.pubkey == signer.pubkey())
            .collect::<Vec<_>>();
        let sequence = u64::try_from(statuses.len()).expect("status count");
        let previous = statuses.last().map(|event| event.id.as_str());
        let order_id = records
            .iter()
            .find(|event| event.kind == 39606)
            .map(|event| event.id.as_str())
            .expect("Order");
        let request = factory
            .status(
                role,
                created_at,
                &lower_hex(&Sha256::digest(
                    format!("boltz-status:{signer_role:?}:{sequence}:{state}").as_bytes(),
                )),
                order_id,
                StatusState {
                    sequence,
                    previous,
                    base_state: test_base_state(state),
                    swp_state: state,
                },
                extra,
            )
            .expect("Status request");
        records.push(signer.sign(
            request.created_at,
            request.kind,
            request.tags,
            request.content,
        ));
    }

    fn append_mutated_status(
        records: &mut Vec<Event>,
        role: ParticipantRole,
        state: &str,
        extra: Map<String, Value>,
        mutate: impl FnOnce(&mut [Tag]),
    ) {
        let config = provider_support::session_config(records).expect("session config");
        let factory = SwapRecordFactory::new(config.clone()).expect("record factory");
        let signer = fixture_signer(role);
        let statuses = records
            .iter()
            .filter(|event| event.kind == MKT_STATUS_KIND && event.pubkey == signer.pubkey())
            .collect::<Vec<_>>();
        let sequence = u64::try_from(statuses.len()).expect("status count");
        let previous = statuses.last().map(|event| event.id.as_str());
        let order_id = records
            .iter()
            .find(|event| event.kind == 39606)
            .map(|event| event.id.as_str())
            .expect("Order");
        let request = factory
            .status(
                role,
                100 + sequence,
                &lower_hex(&Sha256::digest(
                    format!("boltz-mutated-status:{role:?}:{sequence}:{state}").as_bytes(),
                )),
                order_id,
                StatusState {
                    sequence,
                    previous,
                    base_state: test_base_state(state),
                    swp_state: state,
                },
                extra,
            )
            .expect("Status request");
        let mut tags = request.tags;
        mutate(&mut tags);
        records.push(signer.sign(request.created_at, request.kind, tags, request.content));
    }

    fn replace_tag_value(tags: &mut [Tag], name: &str, value: &str) {
        let member = tags
            .iter_mut()
            .find(|tag| tag.name() == Some(name))
            .and_then(|tag| tag.0.get_mut(1))
            .expect("test tag");
        *member = value.to_owned();
    }

    fn replace_marked_reference(tags: &mut [Tag], marker: &str, value: &str) {
        let member = tags
            .iter_mut()
            .find(|tag| {
                tag.name() == Some("e") && tag.as_slice().get(3).map(String::as_str) == Some(marker)
            })
            .and_then(|tag| tag.0.get_mut(1))
            .expect("test marked reference");
        *member = value.to_owned();
    }

    fn fixture_signer(role: ParticipantRole) -> MarketSigner {
        let label = match role {
            ParticipantRole::Requester => b"requester".as_slice(),
            ParticipantRole::Provider => b"provider".as_slice(),
        };
        let key: [u8; 32] =
            Sha256::digest([b"immortal-mkt-swp-test-only:".as_slice(), label].concat()).into();
        MarketSigner::from_secret_bytes(key).expect("fixture signer")
    }

    fn config_pubkey(config: &SwapClientConfig, role: ParticipantRole) -> &str {
        match role {
            ParticipantRole::Requester => &config.requester_pubkey,
            ParticipantRole::Provider => &config.provider_pubkey,
        }
    }

    fn evidence_extra(swap_type: &str, rung: &str, class: &str) -> Map<String, Value> {
        let records = session_records_fixture(swap_type);
        let contract = bilateral_contract(&records).expect("fixture bilateral Contract");
        let leg_id = if class == "lightning_payment" {
            "lightning"
        } else if swap_type == "submarine" {
            "source"
        } else {
            "destination"
        };
        let verifier = contract
            .get("verifier_inputs")
            .and_then(Value::as_array)
            .and_then(|verifiers| {
                verifiers
                    .iter()
                    .find(|verifier| verifier.get("leg_id").and_then(Value::as_str) == Some(leg_id))
            })
            .and_then(Value::as_object)
            .expect("fixture Bitcoin verifier");
        let (rail, verifier_policy, reference) = if class == "lightning_payment" {
            (
                "lightning",
                "mkt-swp-lightning-v1",
                contract
                    .get("payment_hash")
                    .and_then(Value::as_str)
                    .expect("fixture payment hash")
                    .to_owned(),
            )
        } else {
            let raw = verifier
                .get("funding_transaction")
                .and_then(Value::as_str)
                .and_then(|raw| decode_hex_bounded(raw, MAX_RAW_TRANSACTION_BYTES).ok())
                .expect("fixture funding transaction");
            let transaction = Transaction::parse(&raw).expect("parsed fixture funding transaction");
            let output_index = verifier
                .get("output_index")
                .and_then(Value::as_u64)
                .expect("fixture output index");
            let reference = if class == "claim" {
                "f".repeat(64)
            } else {
                format!(
                    "{}:{output_index}",
                    lower_hex(&transaction.txid().expect("fixture funding txid"))
                )
            };
            ("bitcoin", "mkt-swp-bitcoin-v1", reference)
        };
        let artifact_sha256 = if class == "bitcoin_output" {
            verifier
                .get("funding_transaction_sha256")
                .and_then(Value::as_str)
                .expect("fixture funding digest")
                .to_owned()
        } else {
            "22".repeat(32)
        };
        Map::from_iter([(
            "evidence".to_owned(),
            json!({
                "artifact_sha256":artifact_sha256,
                "class":class,
                "observed_at":100,
                "producer_pubkey":fixture_signer(ParticipantRole::Provider).pubkey(),
                "rail":rail,
                "reference":reference,
                "rung":rung,
                "verifier_policy":verifier_policy,
                "verifier_pubkey":null,
                "view":"regtest:100",
            }),
        )])
    }

    fn requester_refund_extra(rung: &str) -> Map<String, Value> {
        let mut extra = evidence_extra("submarine", rung, "claim");
        let evidence = extra
            .get_mut("evidence")
            .and_then(Value::as_object_mut)
            .expect("requester refund evidence");
        evidence.insert("class".to_owned(), Value::String("refund".to_owned()));
        evidence.insert(
            "producer_pubkey".to_owned(),
            Value::String(
                fixture_signer(ParticipantRole::Requester)
                    .pubkey()
                    .to_owned(),
            ),
        );
        extra
    }

    fn test_base_state(state: &str) -> &'static str {
        match state {
            "accepted" => "accepted",
            "requester_verification_passed" => "awaiting_input",
            "requester_funding_broadcast" => "funding_observed",
            "lock_terms_ready" | "hold_invoice_ready" | "provider_lock_terms_ready" => {
                "awaiting_input"
            }
            "provider_funding_broadcast" | "funding_observed" => "funding_observed",
            "funding_final"
            | "lightning_payment_pending"
            | "lightning_htlcs_held"
            | "provider_claim_pending"
            | "provider_claimed" => "executing",
            "lightning_paid" | "completed" => "completed",
            "provider_refund_prepared" | "refund_prepared" | "refund_pending" => "refund_pending",
            "provider_refunded" | "refunded" => "refunded",
            "cancelled" => "cancelled",
            _ => panic!("test state has no base-state mapping"),
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let connecting = TcpStream::connect(address);
        let (client, accepted) = tokio::join!(connecting, listener.accept());
        (
            client.expect("client connection"),
            accepted.expect("server connection").0,
        )
    }

    async fn assert_persistent_frame_stall(prefix: &[u8]) {
        let (mut client, server) = tcp_pair().await;
        client.write_all(prefix).await.expect("frame prefix");
        let (sender, mut receiver) = mpsc::channel(1);
        let reader = tokio::spawn(forward_ws_frames(
            server,
            sender,
            Duration::from_millis(200),
            Duration::from_millis(40),
        ));
        let mut poll_ticks = 0_u8;
        let frame = timeout(Duration::from_millis(200), async {
            loop {
                tokio::select! {
                    frame = receiver.recv() => return frame,
                    _ = sleep(Duration::from_millis(5)) => {
                        poll_ticks = poll_ticks.saturating_add(1);
                    }
                }
            }
        })
        .await
        .expect("persistent frame deadline")
        .expect("persistent frame result");
        assert!(poll_ticks > 0);
        assert_eq!(
            frame.expect_err("stalled frame must fail"),
            "WebSocket partial frame timed out"
        );
        reader.await.expect("persistent frame reader");
    }

    async fn assert_frame_rejected(frame: &[u8], label: &str) {
        let (mut client, mut server) = tcp_pair().await;
        client.write_all(frame).await.expect("invalid frame");
        client.shutdown().await.expect("invalid frame shutdown");
        let first = server.read_u8().await.expect("invalid frame first byte");
        assert!(
            read_ws_frame_after_first_byte(&mut server, first)
                .await
                .expect_err(label)
                .contains(label)
        );
    }

    async fn write_masked_frame(stream: &mut TcpStream, payload: &[u8]) {
        assert!(payload.len() < 126);
        let mask = [0x11, 0x22, 0x33, 0x44];
        let mut frame = vec![
            0x81,
            0x80 | u8::try_from(payload.len()).expect("test payload"),
        ];
        frame.extend(mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        stream.write_all(&frame).await.expect("masked frame");
    }
}
