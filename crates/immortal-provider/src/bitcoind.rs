use std::{fmt, net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};

pub(crate) const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_RESOLVED_ADDRESSES: usize = 8;
const MAX_RPC_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoindError {
    InvalidConfiguration(&'static str),
    ResolutionFailed,
    NonLoopbackEndpoint,
    ConnectionFailed,
    TimedOut(&'static str),
    Io(&'static str),
    Protocol(&'static str),
    HttpStatus(u16),
    Json(&'static str),
    WrongResponseId,
    Rpc { code: i64 },
}

impl fmt::Display for BitcoindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid bitcoind configuration: {detail}")
            }
            Self::ResolutionFailed => formatter.write_str("bitcoind address resolution failed"),
            Self::NonLoopbackEndpoint => {
                formatter.write_str("bitcoind endpoint did not resolve and connect to loopback")
            }
            Self::ConnectionFailed => formatter.write_str("bitcoind connection failed"),
            Self::TimedOut(operation) => write!(formatter, "bitcoind {operation} timed out"),
            Self::Io(operation) => write!(formatter, "bitcoind {operation} failed"),
            Self::Protocol(detail) => write!(formatter, "invalid bitcoind HTTP response: {detail}"),
            Self::HttpStatus(status) => write!(formatter, "bitcoind returned HTTP status {status}"),
            Self::Json(detail) => write!(formatter, "invalid bitcoind JSON-RPC response: {detail}"),
            Self::WrongResponseId => formatter.write_str("bitcoind response ID did not match"),
            Self::Rpc { code } => write!(formatter, "bitcoind JSON-RPC failed with code {code}"),
        }
    }
}

impl std::error::Error for BitcoindError {}

#[derive(Clone, PartialEq, Eq)]
pub struct BitcoindAuth {
    username: String,
    password: String,
}

impl BitcoindAuth {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, BitcoindError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty()
            || username.len() > 256
            || username.contains(':')
            || !safe_credential_part(&username)
        {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC username is empty, too long, or contains a forbidden byte",
            ));
        }
        if password.is_empty() || password.len() > 1024 || !safe_credential_part(&password) {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC password is empty, too long, or contains a forbidden byte",
            ));
        }
        Ok(Self { username, password })
    }

    fn authorization_value(&self) -> String {
        let mut credential = Vec::with_capacity(self.username.len() + self.password.len() + 1);
        credential.extend_from_slice(self.username.as_bytes());
        credential.push(b':');
        credential.extend_from_slice(self.password.as_bytes());
        format!("Basic {}", encode_base64(&credential))
    }
}

impl fmt::Debug for BitcoindAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoindAuth")
            .field("username", &"[redacted]")
            .field("password", &"[redacted]")
            .finish()
    }
}

fn safe_credential_part(value: &str) -> bool {
    value.as_bytes().iter().all(|byte| !byte.is_ascii_control())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoindEndpoint {
    pub host: String,
    pub port: u16,
}

impl BitcoindEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, BitcoindError> {
        let host = host.into();
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || host.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b' ' | b'/' | b'\\' | b'@' | b'#')
            })
        {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC host or port is invalid",
            ));
        }
        Ok(Self { host, port })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoindLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_response_bytes: usize,
    pub max_request_bytes: usize,
}

impl Default for BitcoindLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(10),
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
        }
    }
}

impl BitcoindLimits {
    fn validate(self) -> Result<Self, BitcoindError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || !(1024..=64 * 1024).contains(&self.max_header_bytes)
            || !(1024..=64 * 1024 * 1024).contains(&self.max_response_bytes)
            || !(1024..=16 * 1024 * 1024).contains(&self.max_request_bytes)
        {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC timeouts or byte limits are outside supported bounds",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpcRequestId(String);

impl RpcRequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, BitcoindError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RPC_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC request ID is invalid",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone)]
pub struct BitcoindClient {
    endpoint: BitcoindEndpoint,
    auth: BitcoindAuth,
    limits: BitcoindLimits,
}

impl fmt::Debug for BitcoindClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoindClient")
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("limits", &self.limits)
            .finish()
    }
}

impl BitcoindClient {
    pub fn new(
        endpoint: BitcoindEndpoint,
        auth: BitcoindAuth,
        limits: BitcoindLimits,
    ) -> Result<Self, BitcoindError> {
        Ok(Self {
            endpoint,
            auth,
            limits: limits.validate()?,
        })
    }

    pub async fn call(
        &self,
        request_id: &RpcRequestId,
        method: &'static str,
        params: Value,
    ) -> Result<Value, BitcoindError> {
        if method.is_empty()
            || method.len() > 64
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !params.is_array()
        {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC method or params are invalid",
            ));
        }
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"1.0",
            "id":request_id.as_str(),
            "method":method,
            "params":params,
        }))
        .map_err(|_| BitcoindError::InvalidConfiguration("RPC request is not serializable"))?;
        if body.len() > self.limits.max_request_bytes {
            return Err(BitcoindError::InvalidConfiguration(
                "RPC request exceeds the configured byte limit",
            ));
        }

        let mut stream = self.connect().await?;
        let host = if self.endpoint.host.contains(':') {
            format!("[{}]:{}", self.endpoint.host, self.endpoint.port)
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        };
        let request_head = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.auth.authorization_value(),
            body.len()
        );
        timeout(self.limits.io_timeout, async {
            stream.write_all(request_head.as_bytes()).await?;
            stream.write_all(&body).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| BitcoindError::TimedOut("request write"))?
        .map_err(|_| BitcoindError::Io("request write"))?;

        let response = timeout(
            self.limits.io_timeout,
            read_http_response(&mut stream, self.limits),
        )
        .await
        .map_err(|_| BitcoindError::TimedOut("response read"))??;
        decode_rpc_response(&response, request_id)
    }

    pub async fn chain_tip(&self, request_id: &RpcRequestId) -> Result<ChainTip, BitcoindError> {
        let result = self
            .call(request_id, "getblockchaininfo", json!([]))
            .await?;
        let object = result
            .as_object()
            .ok_or(BitcoindError::Json("chain info result is not an object"))?;
        let hash = object
            .get("bestblockhash")
            .and_then(Value::as_str)
            .ok_or(BitcoindError::Json("chain info has no best block hash"))?;
        validate_hash(hash)?;
        let height = object
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or(BitcoindError::Json("chain info has no block height"))?;
        Ok(ChainTip {
            hash: hash.to_owned(),
            height,
        })
    }

    pub async fn best_block_hash(
        &self,
        request_id: &RpcRequestId,
    ) -> Result<String, BitcoindError> {
        let result = self.call(request_id, "getbestblockhash", json!([])).await?;
        parse_hash_result(result, "best-block result is not a hash")
    }

    pub async fn block_header(
        &self,
        request_id: &RpcRequestId,
        block_hash: &str,
        verbose: bool,
    ) -> Result<Value, BitcoindError> {
        validate_hash(block_hash)?;
        self.call(request_id, "getblockheader", json!([block_hash, verbose]))
            .await
    }

    pub async fn block(
        &self,
        request_id: &RpcRequestId,
        block_hash: &str,
        verbosity: u8,
    ) -> Result<Value, BitcoindError> {
        validate_hash(block_hash)?;
        if verbosity > 2 {
            return Err(BitcoindError::InvalidConfiguration(
                "block verbosity must be 0, 1, or 2",
            ));
        }
        self.call(request_id, "getblock", json!([block_hash, verbosity]))
            .await
    }

    pub async fn raw_transaction(
        &self,
        request_id: &RpcRequestId,
        transaction_id: &str,
        verbose: bool,
    ) -> Result<Value, BitcoindError> {
        validate_hash(transaction_id)?;
        self.call(
            request_id,
            "getrawtransaction",
            json!([transaction_id, verbose]),
        )
        .await
    }

    pub async fn raw_mempool(
        &self,
        request_id: &RpcRequestId,
        verbose: bool,
    ) -> Result<Value, BitcoindError> {
        self.call(request_id, "getrawmempool", json!([verbose]))
            .await
    }

    pub async fn transaction_output(
        &self,
        request_id: &RpcRequestId,
        transaction_id: &str,
        output_index: u32,
        include_mempool: bool,
    ) -> Result<Option<Value>, BitcoindError> {
        validate_hash(transaction_id)?;
        let result = self
            .call(
                request_id,
                "gettxout",
                json!([transaction_id, output_index, include_mempool]),
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else if result.is_object() {
            Ok(Some(result))
        } else {
            Err(BitcoindError::Json("gettxout result has invalid shape"))
        }
    }

    pub async fn broadcast(
        &self,
        request_id: &RpcRequestId,
        raw_transaction: &str,
        max_fee_rate: Option<f64>,
    ) -> Result<String, BitcoindError> {
        validate_hex(
            raw_transaction,
            "raw transaction is not bounded hexadecimal",
        )?;
        let params = match max_fee_rate {
            Some(rate) if rate.is_finite() && rate >= 0.0 => json!([raw_transaction, rate]),
            Some(_) => {
                return Err(BitcoindError::InvalidConfiguration(
                    "maximum fee rate is invalid",
                ));
            }
            None => json!([raw_transaction]),
        };
        let result = self.call(request_id, "sendrawtransaction", params).await?;
        parse_hash_result(result, "broadcast result is not a transaction ID")
    }

    async fn connect(&self) -> Result<TcpStream, BitcoindError> {
        let endpoint = (self.endpoint.host.as_str(), self.endpoint.port);
        let addresses = timeout(self.limits.connect_timeout, lookup_host(endpoint))
            .await
            .map_err(|_| BitcoindError::TimedOut("address resolution"))?
            .map_err(|_| BitcoindError::ResolutionFailed)?
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(BitcoindError::ResolutionFailed);
        }
        if addresses.iter().any(|address| !address.ip().is_loopback()) {
            return Err(BitcoindError::NonLoopbackEndpoint);
        }
        let stream = timeout(self.limits.connect_timeout, connect_first(&addresses))
            .await
            .map_err(|_| BitcoindError::TimedOut("connection"))??;
        let peer = stream
            .peer_addr()
            .map_err(|_| BitcoindError::ConnectionFailed)?;
        if !peer.ip().is_loopback() || !addresses.contains(&peer) {
            return Err(BitcoindError::NonLoopbackEndpoint);
        }
        Ok(stream)
    }
}

async fn connect_first(addresses: &[SocketAddr]) -> Result<TcpStream, BitcoindError> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(BitcoindError::ConnectionFailed)
}

async fn read_http_response(
    stream: &mut TcpStream,
    limits: BitcoindLimits,
) -> Result<Vec<u8>, BitcoindError> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| BitcoindError::Io("response read"))?;
        if read == 0 {
            return Err(BitcoindError::Protocol("truncated response headers"));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_header_end(&bytes) {
            if position > limits.max_header_bytes {
                return Err(BitcoindError::Protocol("response headers are too large"));
            }
            break position;
        }
        if bytes.len() > limits.max_header_bytes {
            return Err(BitcoindError::Protocol("response headers are too large"));
        }
    };

    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| BitcoindError::Protocol("response headers are not ASCII"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(BitcoindError::Protocol("response has no status line"))?;
    let status = parse_status(status_line)?;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(BitcoindError::Protocol("malformed response header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() || value.contains(',') {
                return Err(BitcoindError::Protocol("ambiguous Content-Length header"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| BitcoindError::Protocol("invalid Content-Length header"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = true;
        }
    }
    if transfer_encoding {
        return Err(BitcoindError::Protocol(
            "Transfer-Encoding responses are unsupported",
        ));
    }
    let content_length = content_length.ok_or(BitcoindError::Protocol(
        "response has no Content-Length header",
    ))?;
    if content_length > limits.max_response_bytes {
        return Err(BitcoindError::Protocol("response body is too large"));
    }
    let body_start = header_end + 4;
    let available = bytes.len().saturating_sub(body_start);
    if available > content_length {
        return Err(BitcoindError::Protocol(
            "response exceeds declared Content-Length",
        ));
    }
    let remaining = content_length - available;
    if remaining > 0 {
        bytes.resize(bytes.len() + remaining, 0);
        stream
            .read_exact(&mut bytes[body_start + available..])
            .await
            .map_err(|_| BitcoindError::Protocol("truncated response body"))?;
    }
    if status != 200 {
        return Err(BitcoindError::HttpStatus(status));
    }
    Ok(bytes[body_start..].to_vec())
}

fn parse_status(status_line: &str) -> Result<u16, BitcoindError> {
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts
        .next()
        .ok_or(BitcoindError::Protocol("status line is incomplete"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(BitcoindError::Protocol("unsupported HTTP version"));
    }
    parts
        .next()
        .ok_or(BitcoindError::Protocol("status line has no status"))?
        .parse::<u16>()
        .map_err(|_| BitcoindError::Protocol("HTTP status is invalid"))
}

fn decode_rpc_response(body: &[u8], request_id: &RpcRequestId) -> Result<Value, BitcoindError> {
    let response: Value =
        serde_json::from_slice(body).map_err(|_| BitcoindError::Json("body is not JSON"))?;
    let object = response
        .as_object()
        .ok_or(BitcoindError::Json("response is not an object"))?;
    if object.get("id").and_then(Value::as_str) != Some(request_id.as_str()) {
        return Err(BitcoindError::WrongResponseId);
    }
    match object.get("error") {
        Some(Value::Null) => {}
        Some(Value::Object(error)) => {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(BitcoindError::Json("RPC error has no numeric code"))?;
            return Err(BitcoindError::Rpc { code });
        }
        _ => return Err(BitcoindError::Json("response has invalid error member")),
    }
    object
        .get("result")
        .cloned()
        .ok_or(BitcoindError::Json("response has no result member"))
}

fn parse_hash_result(result: Value, detail: &'static str) -> Result<String, BitcoindError> {
    let hash = result.as_str().ok_or(BitcoindError::Json(detail))?;
    validate_hash(hash)?;
    Ok(hash.to_owned())
}

fn validate_hash(value: &str) -> Result<(), BitcoindError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BitcoindError::InvalidConfiguration(
            "hash is not 64-character lowercase hexadecimal",
        ))
    }
}

fn validate_hex(value: &str, detail: &'static str) -> Result<(), BitcoindError> {
    if !value.is_empty()
        && value.len() % 2 == 0
        && value.len() <= DEFAULT_MAX_REQUEST_BYTES * 2
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(BitcoindError::InvalidConfiguration(detail))
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    pub hash: String,
    pub height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    ClockRegression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    max_age: Duration,
}

impl FreshnessPolicy {
    pub fn new(max_age: Duration) -> Result<Self, BitcoindError> {
        if max_age.is_zero() || max_age > Duration::from_secs(3600) {
            return Err(BitcoindError::InvalidConfiguration(
                "freshness age must be between one second and one hour",
            ));
        }
        Ok(Self { max_age })
    }

    pub fn evaluate(&self, observed_at: Duration, now: Duration) -> Freshness {
        match now.checked_sub(observed_at) {
            None => Freshness::ClockRegression,
            Some(age) if age <= self.max_age => Freshness::Fresh,
            Some(_) => Freshness::Stale,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollBackoff {
    initial: Duration,
    maximum: Duration,
    current: Duration,
    consecutive_failures: u32,
    maximum_failures: u32,
}

impl PollBackoff {
    pub fn new(
        initial: Duration,
        maximum: Duration,
        maximum_failures: u32,
    ) -> Result<Self, BitcoindError> {
        if initial.is_zero()
            || initial > maximum
            || maximum > Duration::from_secs(300)
            || maximum_failures == 0
            || maximum_failures > 1_000
        {
            return Err(BitcoindError::InvalidConfiguration(
                "poll backoff bounds are invalid",
            ));
        }
        Ok(Self {
            initial,
            maximum,
            current: initial,
            consecutive_failures: 0,
            maximum_failures,
        })
    }

    pub fn record_failure(&mut self) -> Option<Duration> {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures > self.maximum_failures {
            return None;
        }
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(self.maximum);
        Some(delay)
    }

    pub fn record_success(&mut self) {
        self.current = self.initial;
        self.consecutive_failures = 0;
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}
