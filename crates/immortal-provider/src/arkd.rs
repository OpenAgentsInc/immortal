use std::{fmt, fs::File, io::Read, net::SocketAddr, path::Path, time::Duration};

use immortal_core::{
    ark::{
        ArkOperatorDescriptor, ArkOperatorPolicy, ArkOutpoint, ArkProtocolFamily, encode_hex,
        verify_operator_binding,
    },
    domain::parse_json_without_duplicate_members,
    mkt_swp_verify::Transaction,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};

const MAX_PATH_BYTES: usize = 2_048;
const MAX_RESOLVED_ADDRESSES: usize = 8;
const MAX_OPERATOR_STATUS_ENTRIES: usize = 32;
const MAX_OPERATOR_STATUS_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 128;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_TRANSACTION_BYTES: usize = 1_000_000;
const MAX_CHECKPOINT_TRANSACTIONS: usize = 64;
const MAX_COMMITMENT_TRANSACTION_IDS: usize = 64;
const MAX_OPERATOR_DOCUMENT_BYTES: usize = 64 * 1024;
pub const ARKD_SOURCE_REVISION: &str = "8b34e352859595cc03ba22ffa35088ab88b87fd9";
pub const ARKD_OPERATOR_DOCUMENT_SCHEMA: &str = "openagents.immortal.arkd-operator.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkdError {
    InvalidConfiguration(&'static str),
    ResolutionFailed,
    NonLoopbackEndpoint,
    ConnectionFailed,
    TimedOut(&'static str),
    Io(&'static str),
    Protocol(&'static str),
    HttpRedirect,
    HttpStatus(u16),
    Json(&'static str),
    OperatorMismatch(&'static str),
    VtxoInvalid(&'static str),
    ExternalEffectConflict(&'static str),
}

impl ArkdError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration(_) => "arkd_invalid_configuration",
            Self::ResolutionFailed => "arkd_resolution_failed",
            Self::NonLoopbackEndpoint => "arkd_non_loopback_endpoint",
            Self::ConnectionFailed => "arkd_connection_failed",
            Self::TimedOut(_) => "arkd_timeout",
            Self::Io(_) => "arkd_io",
            Self::Protocol(_) => "arkd_protocol",
            Self::HttpRedirect => "arkd_http_redirect",
            Self::HttpStatus(_) => "arkd_http_status",
            Self::Json(detail) if *detail == "duplicate JSON member" => "arkd_duplicate_json",
            Self::Json(_) => "arkd_json",
            Self::OperatorMismatch(_) => "swp_ark_operator_mismatch",
            Self::VtxoInvalid(_) => "swp_ark_vtxo_invalid",
            Self::ExternalEffectConflict(_) => "swp_external_effect_conflict",
        }
    }
}

impl fmt::Display for ArkdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid arkd configuration: {detail}")
            }
            Self::ResolutionFailed => formatter.write_str("arkd address resolution failed"),
            Self::NonLoopbackEndpoint => {
                formatter.write_str("arkd endpoint did not resolve and connect to loopback")
            }
            Self::ConnectionFailed => formatter.write_str("arkd connection failed"),
            Self::TimedOut(operation) => write!(formatter, "arkd {operation} timed out"),
            Self::Io(operation) => write!(formatter, "arkd {operation} failed"),
            Self::Protocol(detail) => write!(formatter, "invalid arkd HTTP response: {detail}"),
            Self::HttpRedirect => formatter.write_str("arkd redirects are forbidden"),
            Self::HttpStatus(status) => write!(formatter, "arkd returned HTTP status {status}"),
            Self::Json(detail) => write!(formatter, "invalid arkd JSON response: {detail}"),
            Self::OperatorMismatch(detail) => write!(formatter, "arkd operator mismatch: {detail}"),
            Self::VtxoInvalid(detail) => write!(formatter, "invalid arkd VTXO: {detail}"),
            Self::ExternalEffectConflict(detail) => {
                write!(formatter, "arkd external effect conflict: {detail}")
            }
        }
    }
}

impl std::error::Error for ArkdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkdEndpoint {
    pub host: String,
    pub port: u16,
}

impl ArkdEndpoint {
    pub fn plaintext_regtest(host: impl Into<String>, port: u16) -> Result<Self, ArkdError> {
        let host = host.into();
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || host.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b' ' | b'/' | b'\\' | b'@' | b'#')
            })
        {
            return Err(ArkdError::InvalidConfiguration(
                "plaintext regtest host or port is invalid",
            ));
        }
        Ok(Self { host, port })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArkdLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for ArkdLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(10),
            max_header_bytes: 16 * 1024,
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 4 * 1024 * 1024,
        }
    }
}

impl ArkdLimits {
    fn validate(self) -> Result<Self, ArkdError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || !(1_024..=64 * 1_024).contains(&self.max_header_bytes)
            || !(1_024..=4 * 1_024 * 1_024).contains(&self.max_request_bytes)
            || !(1_024..=16 * 1_024 * 1_024).contains(&self.max_response_bytes)
        {
            return Err(ArkdError::InvalidConfiguration(
                "timeouts or byte limits are outside supported bounds",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkdExpectedOperator {
    descriptor: ArkOperatorDescriptor,
    policy: ArkOperatorPolicy,
    identity_sha256: String,
    policy_sha256: String,
}

impl ArkdExpectedOperator {
    pub fn new(
        descriptor: ArkOperatorDescriptor,
        policy: ArkOperatorPolicy,
    ) -> Result<Self, ArkdError> {
        descriptor
            .validate()
            .map_err(|_| ArkdError::InvalidConfiguration("operator descriptor"))?;
        policy
            .validate()
            .map_err(|_| ArkdError::InvalidConfiguration("operator policy"))?;
        if descriptor.protocol_family != ArkProtocolFamily::Arkade
            || descriptor.network_id.as_str() != "bip122:0f9188f13cb7b2c9e5c30f844f792506"
            || policy.expiry_domain != "block_height"
            || policy.unilateral_exit_domain != "blocks"
        {
            return Err(ArkdError::InvalidConfiguration(
                "arkd adapter is structurally limited to Arkade regtest",
            ));
        }
        let identity_sha256 = descriptor
            .identity_hex()
            .map_err(|_| ArkdError::InvalidConfiguration("operator identity"))?;
        verify_operator_binding(&descriptor, &policy, &identity_sha256)
            .map_err(|_| ArkdError::InvalidConfiguration("operator descriptor or policy"))?;
        let policy_sha256 = policy
            .digest_hex()
            .map_err(|_| ArkdError::InvalidConfiguration("operator policy digest"))?;
        Ok(Self {
            descriptor,
            policy,
            identity_sha256,
            policy_sha256,
        })
    }

    pub fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn from_document_bytes(bytes: &[u8]) -> Result<Self, ArkdError> {
        if bytes.is_empty() || bytes.len() > MAX_OPERATOR_DOCUMENT_BYTES {
            return Err(ArkdError::InvalidConfiguration(
                "operator document size is invalid",
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ArkdError::InvalidConfiguration("operator document is not UTF-8"))?;
        let value = parse_json_without_duplicate_members(text, "arkd operator document")
            .map_err(|_| ArkdError::InvalidConfiguration("operator document JSON"))?;
        let object = value.as_object().ok_or(ArkdError::InvalidConfiguration(
            "operator document is not an object",
        ))?;
        if object.len() != 6
            || object.keys().any(|name| {
                !matches!(
                    name.as_str(),
                    "schema"
                        | "source_commit"
                        | "descriptor"
                        | "policy"
                        | "operator_identity_sha256"
                        | "operator_policy_sha256"
                )
            })
            || object.get("schema").and_then(Value::as_str) != Some(ARKD_OPERATOR_DOCUMENT_SCHEMA)
            || object.get("source_commit").and_then(Value::as_str) != Some(ARKD_SOURCE_REVISION)
        {
            return Err(ArkdError::InvalidConfiguration(
                "operator document member set, schema, or source revision",
            ));
        }
        let descriptor = serde_json::from_value::<ArkOperatorDescriptor>(
            object
                .get("descriptor")
                .ok_or(ArkdError::InvalidConfiguration("operator descriptor"))?
                .clone(),
        )
        .map_err(|_| ArkdError::InvalidConfiguration("operator descriptor"))?;
        let policy = serde_json::from_value::<ArkOperatorPolicy>(
            object
                .get("policy")
                .ok_or(ArkdError::InvalidConfiguration("operator policy"))?
                .clone(),
        )
        .map_err(|_| ArkdError::InvalidConfiguration("operator policy"))?;
        let expected = Self::new(descriptor, policy)?;
        if object
            .get("operator_identity_sha256")
            .and_then(Value::as_str)
            != Some(expected.identity_sha256())
            || object.get("operator_policy_sha256").and_then(Value::as_str)
                != Some(expected.policy_sha256())
        {
            return Err(ArkdError::InvalidConfiguration(
                "operator document digest binding",
            ));
        }
        Ok(expected)
    }

    pub fn load_document(path: &Path) -> Result<Self, ArkdError> {
        if !path.is_absolute() {
            return Err(ArkdError::InvalidConfiguration(
                "operator document path is not absolute",
            ));
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| {
            ArkdError::InvalidConfiguration("operator document metadata is unavailable")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ArkdError::InvalidConfiguration(
                "operator document is not a regular file",
            ));
        }
        let length = usize::try_from(metadata.len())
            .map_err(|_| ArkdError::InvalidConfiguration("operator document size is invalid"))?;
        if length == 0 || length > MAX_OPERATOR_DOCUMENT_BYTES {
            return Err(ArkdError::InvalidConfiguration(
                "operator document size is invalid",
            ));
        }
        let mut file = File::open(path).map_err(|_| {
            ArkdError::InvalidConfiguration("operator document could not be opened")
        })?;
        let opened = file.metadata().map_err(|_| {
            ArkdError::InvalidConfiguration("operator document metadata is unavailable")
        })?;
        if !opened.is_file() || opened.len() != metadata.len() || !same_file(&metadata, &opened) {
            return Err(ArkdError::InvalidConfiguration(
                "operator document changed before opening",
            ));
        }
        let mut bytes = Vec::with_capacity(length);
        file.by_ref()
            .take(
                u64::try_from(MAX_OPERATOR_DOCUMENT_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)
            .map_err(|_| ArkdError::InvalidConfiguration("operator document could not be read"))?;
        if bytes.len() != length {
            return Err(ArkdError::InvalidConfiguration(
                "operator document changed while reading",
            ));
        }
        Self::from_document_bytes(&bytes)
    }
}

#[cfg(unix)]
fn same_file(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(not(unix))]
fn same_file(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    first.len() == second.len()
        && first
            .modified()
            .ok()
            .zip(second.modified().ok())
            .is_some_and(|(first_modified, second_modified)| first_modified == second_modified)
}

#[derive(Clone)]
pub struct ArkdClient {
    endpoint: ArkdEndpoint,
    expected: ArkdExpectedOperator,
    limits: ArkdLimits,
}

impl fmt::Debug for ArkdClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArkdClient")
            .field("endpoint", &self.endpoint)
            .field("operator_identity_sha256", &self.expected.identity_sha256)
            .field("operator_policy_sha256", &self.expected.policy_sha256)
            .field("limits", &self.limits)
            .finish()
    }
}

impl ArkdClient {
    pub fn new(
        endpoint: ArkdEndpoint,
        expected: ArkdExpectedOperator,
        limits: ArkdLimits,
    ) -> Result<Self, ArkdError> {
        Ok(Self {
            endpoint,
            expected,
            limits: limits.validate()?,
        })
    }

    pub fn operator_identity_sha256(&self) -> &str {
        self.expected.identity_sha256()
    }

    pub fn operator_policy_sha256(&self) -> &str {
        self.expected.policy_sha256()
    }

    pub async fn info(&self) -> Result<ArkdInfo, ArkdError> {
        let value = self.request("GET", "/v1/info", None).await?;
        let info = parse_info(&value)?;
        validate_info(&info, &self.expected)?;
        Ok(info)
    }

    pub async fn vtxo(&self, outpoint: &ArkOutpoint) -> Result<ArkdVtxo, ArkdError> {
        let path = format!(
            "/v1/indexer/vtxos?outpoints={}%3A{}&page.size=1&page.index=0",
            encode_hex(&outpoint.transaction_id()),
            outpoint.output_index()
        );
        let value = self.request("GET", &path, None).await?;
        parse_exact_vtxo(&value, outpoint)
    }

    pub async fn submit_transaction(
        &self,
        signed_ark_transaction: &str,
        checkpoint_transactions: &[String],
    ) -> Result<ArkdSubmission, ArkdError> {
        let requested_transaction_id =
            validate_transaction_hex(signed_ark_transaction, "submitted Ark transaction")?;
        validate_transaction_set(checkpoint_transactions, "checkpoint transaction")?;
        let value = self
            .request(
                "POST",
                "/v1/tx/submit",
                Some(&json!({
                    "signedArkTx":signed_ark_transaction,
                    "checkpointTxs":checkpoint_transactions,
                })),
            )
            .await?;
        parse_submission(&value, &requested_transaction_id)
    }

    pub async fn finalize_transaction(
        &self,
        ark_transaction_id: &str,
        final_checkpoint_transactions: &[String],
    ) -> Result<(), ArkdError> {
        require_lower_hex(ark_transaction_id, 64, "Ark transaction ID")?;
        validate_transaction_set(
            final_checkpoint_transactions,
            "final checkpoint transaction",
        )?;
        let value = self
            .request(
                "POST",
                "/v1/tx/finalize",
                Some(&json!({
                    "arkTxid":ark_transaction_id,
                    "finalCheckpointTxs":final_checkpoint_transactions,
                })),
            )
            .await?;
        let object = value
            .as_object()
            .ok_or(ArkdError::Json("finalize response is not an object"))?;
        if !object.is_empty() {
            return Err(ArkdError::ExternalEffectConflict(
                "finalize response is not empty",
            ));
        }
        Ok(())
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ArkdError> {
        let request = encode_request(&self.endpoint, method, path, body, self.limits)?;
        let mut stream = self.connect().await?;
        timeout(self.limits.io_timeout, async {
            stream.write_all(&request).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| ArkdError::TimedOut("request write"))?
        .map_err(|_| ArkdError::Io("request write"))?;
        let response = timeout(
            self.limits.io_timeout,
            read_http_response(&mut stream, self.limits),
        )
        .await
        .map_err(|_| ArkdError::TimedOut("response read"))??;
        if (300..400).contains(&response.status) {
            return Err(ArkdError::HttpRedirect);
        }
        if response.status != 200 {
            return Err(ArkdError::HttpStatus(response.status));
        }
        parse_json_response(&response.body)
    }

    async fn connect(&self) -> Result<TcpStream, ArkdError> {
        let endpoint = (self.endpoint.host.as_str(), self.endpoint.port);
        let addresses = timeout(self.limits.connect_timeout, lookup_host(endpoint))
            .await
            .map_err(|_| ArkdError::TimedOut("address resolution"))?
            .map_err(|_| ArkdError::ResolutionFailed)?
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(ArkdError::ResolutionFailed);
        }
        if addresses.iter().any(|address| !address.ip().is_loopback()) {
            return Err(ArkdError::NonLoopbackEndpoint);
        }
        let stream = timeout(self.limits.connect_timeout, connect_first(&addresses))
            .await
            .map_err(|_| ArkdError::TimedOut("connection"))??;
        let peer = stream
            .peer_addr()
            .map_err(|_| ArkdError::ConnectionFailed)?;
        if !peer.ip().is_loopback() || !addresses.contains(&peer) {
            return Err(ArkdError::NonLoopbackEndpoint);
        }
        Ok(stream)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkdInfo {
    pub version: String,
    pub signer_pubkey: String,
    pub forfeit_pubkey: String,
    pub checkpoint_tapscript: String,
    pub network: String,
    pub unilateral_exit_delay: u64,
    pub vtxo_min_amount: u64,
    pub vtxo_max_amount: u64,
    pub digest: String,
    pub maximum_transaction_weight: u64,
    pub service_status: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkdVtxo {
    pub outpoint: ArkOutpoint,
    pub amount: u64,
    pub script_pubkey: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub preconfirmed: bool,
    pub spent: bool,
    pub swept: bool,
    pub unrolled: bool,
    pub spent_by: Option<String>,
    pub settled_by: Option<String>,
    pub ark_transaction_id: String,
    pub commitment_transaction_ids: Vec<String>,
    pub depth: u32,
}

impl ArkdVtxo {
    pub const fn is_available(&self) -> bool {
        !self.spent && !self.swept && !self.unrolled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkdSubmission {
    pub ark_transaction_id: String,
    pub final_ark_transaction: String,
    pub signed_checkpoint_transactions: Vec<String>,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn connect_first(addresses: &[SocketAddr]) -> Result<TcpStream, ArkdError> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(ArkdError::ConnectionFailed)
}

fn encode_request(
    endpoint: &ArkdEndpoint,
    method: &str,
    path: &str,
    body: Option<&Value>,
    limits: ArkdLimits,
) -> Result<Vec<u8>, ArkdError> {
    if !matches!(method, "GET" | "POST")
        || !safe_path(path)
        || path.len() > MAX_PATH_BYTES
        || (method == "GET" && body.is_some())
    {
        return Err(ArkdError::InvalidConfiguration(
            "REST method, path, or body is invalid",
        ));
    }
    let body = body
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| ArkdError::InvalidConfiguration("REST body is not serializable"))?
        .unwrap_or_default();
    if body.len() > limits.max_request_bytes {
        return Err(ArkdError::InvalidConfiguration(
            "REST request exceeds the configured byte limit",
        ));
    }
    let host = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
    )
    .into_bytes();
    if method == "POST" {
        request.extend_from_slice(
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
            .as_bytes(),
        );
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&body);
    if request.len() > limits.max_request_bytes + limits.max_header_bytes {
        return Err(ArkdError::InvalidConfiguration(
            "encoded REST request exceeds the configured byte limit",
        ));
    }
    Ok(request)
}

fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('#')
        && !path.contains('\\')
        && !path.contains("..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b' ')
}

async fn read_http_response(
    stream: &mut TcpStream,
    limits: ArkdLimits,
) -> Result<HttpResponse, ArkdError> {
    let maximum = limits
        .max_header_bytes
        .checked_add(limits.max_response_bytes)
        .ok_or(ArkdError::Protocol("response byte limit overflow"))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| ArkdError::Io("response read"))?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > maximum {
            return Err(ArkdError::Protocol("response exceeds configured bound"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    parse_http_response(&bytes, limits)
}

fn parse_http_response(bytes: &[u8], limits: ArkdLimits) -> Result<HttpResponse, ArkdError> {
    let header_end = find_bytes(bytes, b"\r\n\r\n")
        .ok_or(ArkdError::Protocol("header terminator is missing"))?;
    if header_end + 4 > limits.max_header_bytes {
        return Err(ArkdError::Protocol("header exceeds configured bound"));
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ArkdError::Protocol("header is not ASCII"))?;
    if !header.is_ascii() {
        return Err(ArkdError::Protocol("header is not ASCII"));
    }
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(ArkdError::Protocol("status line is missing"))?;
    let mut status_parts = status_line.split_ascii_whitespace();
    let version = status_parts
        .next()
        .ok_or(ArkdError::Protocol("HTTP version is missing"))?;
    let status = status_parts
        .next()
        .ok_or(ArkdError::Protocol("HTTP status is missing"))?
        .parse::<u16>()
        .map_err(|_| ArkdError::Protocol("HTTP status is invalid"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status_parts.next().is_none() {
        return Err(ArkdError::Protocol("status line is invalid"));
    }
    let mut content_length = None;
    let mut chunked = false;
    let mut location = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(ArkdError::Protocol("header line is invalid"))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ArkdError::Protocol("duplicate content-length"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| ArkdError::Protocol("content-length is invalid"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(ArkdError::Protocol("transfer-encoding is invalid"));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("location") {
            if location {
                return Err(ArkdError::Protocol("duplicate location header"));
            }
            location = true;
        }
    }
    if content_length.is_some() && chunked {
        return Err(ArkdError::Protocol(
            "content-length and chunked encoding conflict",
        ));
    }
    if (300..400).contains(&status) && !location {
        return Err(ArkdError::Protocol("redirect has no location"));
    }
    let encoded_body = &bytes[header_end + 4..];
    let body = if chunked {
        decode_chunked(encoded_body, limits.max_response_bytes)?
    } else if let Some(length) = content_length {
        if length > limits.max_response_bytes || encoded_body.len() != length {
            return Err(ArkdError::Protocol("content-length differs from body"));
        }
        encoded_body.to_vec()
    } else {
        if encoded_body.len() > limits.max_response_bytes {
            return Err(ArkdError::Protocol(
                "response body exceeds configured bound",
            ));
        }
        encoded_body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, ArkdError> {
    let mut output = Vec::new();
    let mut cursor = 0_usize;
    loop {
        let relative_end = find_bytes(&bytes[cursor..], b"\r\n")
            .ok_or(ArkdError::Protocol("chunk size terminator is missing"))?;
        let line_end = cursor
            .checked_add(relative_end)
            .ok_or(ArkdError::Protocol("chunk cursor overflow"))?;
        let size_text = std::str::from_utf8(&bytes[cursor..line_end])
            .map_err(|_| ArkdError::Protocol("chunk size is not ASCII"))?;
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ArkdError::Protocol("chunk size is invalid"));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ArkdError::Protocol("chunk size is invalid"))?;
        cursor = line_end
            .checked_add(2)
            .ok_or(ArkdError::Protocol("chunk cursor overflow"))?;
        if size == 0 {
            if bytes.get(cursor..) != Some(b"\r\n") {
                return Err(ArkdError::Protocol("chunk trailer is unsupported"));
            }
            return Ok(output);
        }
        if output.len().saturating_add(size) > maximum {
            return Err(ArkdError::Protocol("chunked body exceeds configured bound"));
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or(ArkdError::Protocol("chunk cursor overflow"))?;
        if bytes.get(data_end..data_end.saturating_add(2)) != Some(b"\r\n") {
            return Err(ArkdError::Protocol("chunk data terminator is missing"));
        }
        output.extend_from_slice(
            bytes
                .get(cursor..data_end)
                .ok_or(ArkdError::Protocol("chunk data is truncated"))?,
        );
        cursor = data_end
            .checked_add(2)
            .ok_or(ArkdError::Protocol("chunk cursor overflow"))?;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_json_response(bytes: &[u8]) -> Result<Value, ArkdError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ArkdError::Json("response is not UTF-8"))?;
    parse_json_without_duplicate_members(text, "arkd REST response").map_err(|error| {
        if error.contains("duplicate") {
            ArkdError::Json("duplicate JSON member")
        } else {
            ArkdError::Json("response is not valid JSON")
        }
    })
}

fn parse_info(value: &Value) -> Result<ArkdInfo, ArkdError> {
    let object = value
        .as_object()
        .ok_or(ArkdError::Json("info response is not an object"))?;
    let version = bounded_string(object, "version", MAX_VERSION_BYTES, "version")?;
    let signer_pubkey = bounded_string(object, "signerPubkey", 66, "signer public key")?;
    let forfeit_pubkey = bounded_string(object, "forfeitPubkey", 66, "forfeit public key")?;
    let checkpoint_tapscript = bounded_string(
        object,
        "checkpointTapscript",
        MAX_SCRIPT_BYTES * 2,
        "checkpoint tapscript",
    )?;
    let network = bounded_string(object, "network", 32, "network")?;
    let unilateral_exit_delay = unsigned_member(object, "unilateralExitDelay")?;
    let vtxo_min_amount = unsigned_member(object, "vtxoMinAmount")?;
    let vtxo_max_amount = unsigned_member(object, "vtxoMaxAmount")?;
    let digest = bounded_string(object, "digest", 64, "settings digest")?;
    let maximum_transaction_weight = unsigned_member(object, "maxTxWeight")?;
    let service_status = object
        .get("serviceStatus")
        .and_then(Value::as_object)
        .filter(|status| status.len() <= MAX_OPERATOR_STATUS_ENTRIES)
        .ok_or(ArkdError::Json("service status is invalid"))?
        .clone();
    for (name, state) in &service_status {
        if name.is_empty()
            || name.len() > MAX_OPERATOR_STATUS_BYTES
            || state
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= MAX_OPERATOR_STATUS_BYTES)
                .is_none()
        {
            return Err(ArkdError::Json("service status entry is invalid"));
        }
    }
    Ok(ArkdInfo {
        version,
        signer_pubkey,
        forfeit_pubkey,
        checkpoint_tapscript,
        network,
        unilateral_exit_delay,
        vtxo_min_amount,
        vtxo_max_amount,
        digest,
        maximum_transaction_weight,
        service_status,
    })
}

fn validate_info(info: &ArkdInfo, expected: &ArkdExpectedOperator) -> Result<(), ArkdError> {
    let signer = expected
        .descriptor
        .operator_keys
        .signer_pubkey
        .as_deref()
        .ok_or(ArkdError::OperatorMismatch("expected signer key is absent"))?;
    let forfeit = expected
        .descriptor
        .operator_keys
        .forfeit_pubkey
        .as_deref()
        .ok_or(ArkdError::OperatorMismatch(
            "expected forfeit key is absent",
        ))?;
    let minimum = expected
        .policy
        .minimum_vtxo_amount
        .parse::<u64>()
        .map_err(|_| ArkdError::OperatorMismatch("minimum VTXO amount"))?;
    let maximum = expected
        .policy
        .maximum_vtxo_amount
        .parse::<u64>()
        .map_err(|_| ArkdError::OperatorMismatch("maximum VTXO amount"))?;
    let exit_delay = expected
        .policy
        .unilateral_exit_delay
        .parse::<u64>()
        .map_err(|_| ArkdError::OperatorMismatch("unilateral exit delay"))?;
    let checkpoint_bytes = decode_lower_hex(
        &info.checkpoint_tapscript,
        MAX_SCRIPT_BYTES,
        "checkpoint tapscript",
    )?;
    let checkpoint_sha256 = encode_hex(&Sha256::digest(&checkpoint_bytes));
    require_lower_hex(&info.digest, 64, "arkd settings digest")?;
    if info.network != "regtest"
        || info.signer_pubkey != signer
        || info.forfeit_pubkey != forfeit
        || checkpoint_sha256 != expected.policy.checkpoint_script_sha256
        || info.vtxo_min_amount != minimum
        || info.vtxo_max_amount != maximum
        || info.unilateral_exit_delay != exit_delay
        || info.maximum_transaction_weight != expected.policy.maximum_transaction_weight
    {
        return Err(ArkdError::OperatorMismatch(
            "live info differs from the pinned public operator policy",
        ));
    }
    Ok(())
}

fn parse_exact_vtxo(value: &Value, expected: &ArkOutpoint) -> Result<ArkdVtxo, ArkdError> {
    let object = value
        .as_object()
        .ok_or(ArkdError::Json("VTXO response is not an object"))?;
    let vtxos = object
        .get("vtxos")
        .and_then(Value::as_array)
        .filter(|vtxos| vtxos.len() == 1)
        .ok_or(ArkdError::VtxoInvalid(
            "exact observation returned zero or multiple VTXOs",
        ))?;
    let vtxo = vtxos
        .first()
        .and_then(Value::as_object)
        .ok_or(ArkdError::VtxoInvalid("VTXO row is invalid"))?;
    let outpoint = parse_outpoint(
        vtxo.get("outpoint")
            .and_then(Value::as_object)
            .ok_or(ArkdError::VtxoInvalid("outpoint is absent"))?,
    )?;
    if &outpoint != expected {
        return Err(ArkdError::VtxoInvalid(
            "returned outpoint differs from the request",
        ));
    }
    let amount = unsigned_member(vtxo, "amount")?;
    if amount == 0 {
        return Err(ArkdError::VtxoInvalid("amount is zero"));
    }
    let script_pubkey = bounded_string(vtxo, "script", MAX_SCRIPT_BYTES * 2, "VTXO script")?;
    decode_lower_hex(&script_pubkey, MAX_SCRIPT_BYTES, "VTXO script")?;
    let created_at = unsigned_member(vtxo, "createdAt")?;
    let expires_at = unsigned_member(vtxo, "expiresAt")?;
    if expires_at == 0 {
        return Err(ArkdError::VtxoInvalid("expiry is zero"));
    }
    let commitment_transaction_ids = string_array(
        vtxo,
        "commitmentTxids",
        MAX_COMMITMENT_TRANSACTION_IDS,
        "commitment transaction ID",
    )?;
    if commitment_transaction_ids.is_empty() {
        return Err(ArkdError::VtxoInvalid(
            "commitment transaction set is empty",
        ));
    }
    for transaction_id in &commitment_transaction_ids {
        require_lower_hex(transaction_id, 64, "commitment transaction ID")?;
    }
    let ark_transaction_id = bounded_string(vtxo, "arkTxid", 64, "Ark transaction ID")?;
    require_lower_hex(&ark_transaction_id, 64, "Ark transaction ID")?;
    let depth = unsigned_member(vtxo, "depth")?;
    let depth = u32::try_from(depth).map_err(|_| ArkdError::VtxoInvalid("depth exceeds u32"))?;
    if depth == 0 || usize::try_from(depth).ok() > Some(MAX_COMMITMENT_TRANSACTION_IDS) {
        return Err(ArkdError::VtxoInvalid("depth is outside its bound"));
    }
    Ok(ArkdVtxo {
        outpoint,
        amount,
        script_pubkey,
        created_at,
        expires_at,
        preconfirmed: boolean_member(vtxo, "isPreconfirmed")?,
        spent: boolean_member(vtxo, "isSpent")?,
        swept: boolean_member(vtxo, "isSwept")?,
        unrolled: boolean_member(vtxo, "isUnrolled")?,
        spent_by: optional_bounded_string(vtxo, "spentBy", 64, "spending transaction ID")?,
        settled_by: optional_bounded_string(vtxo, "settledBy", 64, "settlement transaction ID")?,
        ark_transaction_id,
        commitment_transaction_ids,
        depth,
    })
}

fn parse_outpoint(object: &Map<String, Value>) -> Result<ArkOutpoint, ArkdError> {
    let transaction_id = bounded_string(object, "txid", 64, "VTXO transaction ID")?;
    let output_index = unsigned_member(object, "vout")?;
    let output_index =
        u32::try_from(output_index).map_err(|_| ArkdError::VtxoInvalid("VTXO vout exceeds u32"))?;
    ArkOutpoint::parse(&format!("{transaction_id}:{output_index}"))
        .map_err(|_| ArkdError::VtxoInvalid("outpoint is invalid"))
}

fn parse_submission(
    value: &Value,
    requested_transaction_id: &str,
) -> Result<ArkdSubmission, ArkdError> {
    let object = value
        .as_object()
        .ok_or(ArkdError::Json("submit response is not an object"))?;
    let ark_transaction_id = bounded_string(object, "arkTxid", 64, "Ark transaction ID")?;
    require_lower_hex(&ark_transaction_id, 64, "Ark transaction ID")?;
    let final_ark_transaction = bounded_string(
        object,
        "finalArkTx",
        MAX_TRANSACTION_BYTES * 2,
        "final Ark transaction",
    )?;
    let final_transaction_id =
        validate_transaction_hex(&final_ark_transaction, "final Ark transaction")?;
    if ark_transaction_id != requested_transaction_id || final_transaction_id != ark_transaction_id
    {
        return Err(ArkdError::ExternalEffectConflict(
            "returned Ark transaction ID differs from exact bytes",
        ));
    }
    let signed_checkpoint_transactions = string_array(
        object,
        "signedCheckpointTxs",
        MAX_CHECKPOINT_TRANSACTIONS,
        "signed checkpoint transaction",
    )?;
    validate_transaction_set(
        &signed_checkpoint_transactions,
        "signed checkpoint transaction",
    )?;
    Ok(ArkdSubmission {
        ark_transaction_id,
        final_ark_transaction,
        signed_checkpoint_transactions,
    })
}

fn validate_transaction_set(
    transactions: &[String],
    subject: &'static str,
) -> Result<(), ArkdError> {
    if transactions.len() > MAX_CHECKPOINT_TRANSACTIONS {
        return Err(ArkdError::InvalidConfiguration(
            "checkpoint transaction count exceeds its bound",
        ));
    }
    for transaction in transactions {
        validate_transaction_hex(transaction, subject)?;
    }
    Ok(())
}

fn validate_transaction_hex(value: &str, subject: &'static str) -> Result<String, ArkdError> {
    let bytes = decode_lower_hex(value, MAX_TRANSACTION_BYTES, subject)?;
    let transaction = Transaction::parse(&bytes)
        .map_err(|_| ArkdError::ExternalEffectConflict("transaction encoding is invalid"))?;
    transaction
        .txid()
        .map(|transaction_id| encode_hex(&transaction_id))
        .map_err(|_| ArkdError::ExternalEffectConflict("transaction ID cannot be computed"))
}

fn bounded_string(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
    detail: &'static str,
) -> Result<String, ArkdError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .map(str::to_owned)
        .ok_or(ArkdError::Json(detail))
}

fn optional_bounded_string(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
    detail: &'static str,
) -> Result<Option<String>, ArkdError> {
    match object.get(name).and_then(Value::as_str) {
        Some("") | None => Ok(None),
        Some(value) if value.len() <= maximum => {
            require_lower_hex(value, 64, detail)?;
            Ok(Some(value.to_owned()))
        }
        Some(_) => Err(ArkdError::Json(detail)),
    }
}

fn unsigned_member(object: &Map<String, Value>, name: &str) -> Result<u64, ArkdError> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(ArkdError::Json("unsigned integer member is invalid"))
}

fn boolean_member(object: &Map<String, Value>, name: &str) -> Result<bool, ArkdError> {
    object
        .get(name)
        .and_then(Value::as_bool)
        .ok_or(ArkdError::Json("boolean member is invalid"))
}

fn string_array(
    object: &Map<String, Value>,
    name: &str,
    maximum: usize,
    detail: &'static str,
) -> Result<Vec<String>, ArkdError> {
    object
        .get(name)
        .and_then(Value::as_array)
        .filter(|values| values.len() <= maximum)
        .ok_or(ArkdError::Json(detail))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|text| !text.is_empty() && text.len() <= MAX_TRANSACTION_BYTES * 2)
                .map(str::to_owned)
                .ok_or(ArkdError::Json(detail))
        })
        .collect()
}

fn require_lower_hex(value: &str, length: usize, detail: &'static str) -> Result<(), ArkdError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArkdError::Json(detail));
    }
    Ok(())
}

fn decode_lower_hex(
    value: &str,
    maximum_bytes: usize,
    detail: &'static str,
) -> Result<Vec<u8>, ArkdError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() / 2 > maximum_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ArkdError::Json(detail));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(ArkdError::Json(detail))?;
            let low = hex_nibble(pair[1]).ok_or(ArkdError::Json(detail))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const FIXTURE: &str = include_str!("../../../tests/fixtures/provider/arkd-rest-v1.json");
    const OPERATOR_DOCUMENT: &[u8] =
        include_bytes!("../../../tests/fixtures/provider/arkd-operator-regtest-v1.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("arkd REST fixture")
    }

    fn expected_operator() -> ArkdExpectedOperator {
        ArkdExpectedOperator::from_document_bytes(OPERATOR_DOCUMENT).expect("expected operator")
    }

    #[test]
    fn fixture_replays_info_vtxo_submit_and_finalize_shapes() {
        let fixture = fixture();
        let operator = expected_operator();
        assert_eq!(
            operator.identity_sha256(),
            fixture["operator"]["operator_identity_sha256"]
                .as_str()
                .expect("identity")
        );
        assert_eq!(
            operator.policy_sha256(),
            fixture["operator"]["operator_policy_sha256"]
                .as_str()
                .expect("policy digest")
        );
        let calls = fixture["calls"].as_array().expect("calls");
        assert_eq!(calls.len(), 4);

        let info = parse_info(&calls[0]["response"]).expect("info response");
        validate_info(&info, &operator).expect("pinned operator response");

        let outpoint = ArkOutpoint::parse(
            "395559425d103f3c76d13a85f3443d56c853fd5ac6c5291a1a4178c4d7289196:0",
        )
        .expect("fixture outpoint");
        let vtxo = parse_exact_vtxo(&calls[1]["response"], &outpoint).expect("VTXO response");
        assert!(vtxo.is_available());
        assert_eq!(vtxo.amount, 100_000);

        let requested = calls[2]["request"]["body"]["signedArkTx"]
            .as_str()
            .expect("signed Ark transaction");
        let requested_id =
            validate_transaction_hex(requested, "fixture transaction").expect("transaction ID");
        let submission =
            parse_submission(&calls[2]["response"], &requested_id).expect("submission response");
        assert_eq!(submission.ark_transaction_id, requested_id);
        assert!(
            calls[3]["response"]
                .as_object()
                .expect("finalize response")
                .is_empty()
        );
    }

    #[test]
    fn operator_document_is_closed_and_digest_bound() {
        let expected = expected_operator();
        assert_eq!(
            expected.identity_sha256(),
            "2d66cea26a24fc3f91b81559d83b9ddd456a71947e27249a389eb216f66fb4f9"
        );
        let mut changed = parse_json_without_duplicate_members(
            std::str::from_utf8(OPERATOR_DOCUMENT).expect("operator UTF-8"),
            "operator fixture",
        )
        .expect("operator JSON");
        changed["operator_policy_sha256"] = Value::String("00".repeat(32));
        let changed = serde_json::to_vec(&changed).expect("changed operator document");
        assert!(ArkdExpectedOperator::from_document_bytes(&changed).is_err());

        let duplicate = br#"{"schema":"openagents.immortal.arkd-operator.v1","schema":"openagents.immortal.arkd-operator.v1"}"#;
        assert!(ArkdExpectedOperator::from_document_bytes(duplicate).is_err());
    }

    #[tokio::test]
    async fn client_sends_the_exact_info_request_and_verifies_the_live_operator() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let response_body =
            serde_json::to_vec(&fixture()["calls"][0]["response"]).expect("fixture response body");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("fixture connection");
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 1024];
                let count = stream.read(&mut buffer).await.expect("fixture request");
                assert!(count > 0, "request ended before its header");
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 4096, "fixture request exceeded its bound");
                if find_bytes(&request, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            let request = std::str::from_utf8(&request).expect("request UTF-8");
            assert!(request.starts_with("GET /v1/info HTTP/1.1\r\n"));
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream
                .write_all(header.as_bytes())
                .await
                .expect("fixture response header");
            stream
                .write_all(&response_body)
                .await
                .expect("fixture response body");
        });
        let client = ArkdClient::new(
            ArkdEndpoint::plaintext_regtest("127.0.0.1", address.port()).expect("fixture endpoint"),
            expected_operator(),
            ArkdLimits::default(),
        )
        .expect("fixture client");
        let info = client.info().await.expect("verified live info");
        assert_eq!(info.network, "regtest");
        server.await.expect("fixture server");
    }

    #[test]
    fn fixture_requests_are_exact_bounded_and_credential_free() {
        let fixture = fixture();
        let endpoint =
            ArkdEndpoint::plaintext_regtest("127.0.0.1", 17_070).expect("loopback endpoint");
        let limits = ArkdLimits::default();
        for call in fixture["calls"].as_array().expect("calls") {
            let request = call["request"].as_object().expect("request");
            let method = request["method"].as_str().expect("method");
            let path = request["path"].as_str().expect("path");
            let body = request.get("body").filter(|value| !value.is_null());
            let encoded = encode_request(&endpoint, method, path, body, limits)
                .expect("encoded fixture request");
            let encoded = std::str::from_utf8(&encoded).expect("request UTF-8");
            assert!(encoded.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
            for forbidden in ["macaroon", "authorization", "seed", "private_key", "token"] {
                assert!(!encoded.to_ascii_lowercase().contains(forbidden));
            }
        }
    }

    #[test]
    fn response_parser_rejects_redirect_duplicate_json_and_framing_conflicts() {
        let limits = ArkdLimits::default();
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:17071/v1/info\r\nContent-Length: 0\r\n\r\n";
        let response = parse_http_response(redirect, limits).expect("framed redirect");
        assert_eq!(response.status, 302);
        assert!(matches!(
            parse_json_response(br#"{"version":"a","version":"b"}"#),
            Err(ArkdError::Json("duplicate JSON member"))
        ));
        let conflict =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}";
        assert!(parse_http_response(conflict, limits).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            parse_http_response(chunked, limits)
                .expect("chunked response")
                .body,
            b"{}"
        );
    }

    #[test]
    fn live_policy_and_effect_mutations_fail_closed() {
        let fixture = fixture();
        let operator = expected_operator();
        let calls = fixture["calls"].as_array().expect("calls");
        let mut changed_info = calls[0]["response"].clone();
        changed_info["signerPubkey"] = Value::String(
            "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766".to_owned(),
        );
        let changed_info = parse_info(&changed_info).expect("changed info shape");
        assert!(matches!(
            validate_info(&changed_info, &operator),
            Err(ArkdError::OperatorMismatch(_))
        ));

        let requested = calls[2]["request"]["body"]["signedArkTx"]
            .as_str()
            .expect("requested transaction");
        let requested_id =
            validate_transaction_hex(requested, "fixture transaction").expect("transaction ID");
        let mut changed_submission = calls[2]["response"].clone();
        changed_submission["arkTxid"] = Value::String("ff".repeat(32));
        assert!(matches!(
            parse_submission(&changed_submission, &requested_id),
            Err(ArkdError::ExternalEffectConflict(_))
        ));

        let outpoint = ArkOutpoint::parse(
            "395559425d103f3c76d13a85f3443d56c853fd5ac6c5291a1a4178c4d7289196:0",
        )
        .expect("fixture outpoint");
        let mut spent = calls[1]["response"].clone();
        spent["vtxos"][0]["isSpent"] = Value::Bool(true);
        let spent = parse_exact_vtxo(&spent, &outpoint).expect("spent VTXO observation");
        assert!(!spent.is_available());
    }
}
