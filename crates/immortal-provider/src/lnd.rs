use std::{
    fmt,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
    time::Duration,
};

use serde::de::IgnoredAny;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError,
        SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{
            WebPkiSupportedAlgorithms, ring::default_provider, verify_tls12_signature,
            verify_tls13_signature,
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};

use crate::cln::Millisatoshi;

pub const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESOLVED_ADDRESSES: usize = 8;
pub const DEFAULT_MAX_STREAM_MESSAGES: usize = 64;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_MACAROON_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 8 * 1024;
const MAX_BOLT11_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LndError {
    InvalidConfiguration(&'static str),
    SecretFile(&'static str),
    ResolutionFailed,
    NonLoopbackEndpoint,
    ConnectionFailed,
    Tls,
    TimedOut(&'static str),
    Io(&'static str),
    Protocol(&'static str),
    HttpStatus(u16),
    Json(&'static str),
    Rpc(u16),
}

impl fmt::Display for LndError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid LND configuration: {detail}")
            }
            Self::SecretFile(detail) => write!(formatter, "invalid LND credential file: {detail}"),
            Self::ResolutionFailed => formatter.write_str("LND address resolution failed"),
            Self::NonLoopbackEndpoint => {
                formatter.write_str("LND endpoint did not resolve and connect to loopback")
            }
            Self::ConnectionFailed => formatter.write_str("LND connection failed"),
            Self::Tls => formatter.write_str("LND pinned TLS verification failed"),
            Self::TimedOut(operation) => write!(formatter, "LND {operation} timed out"),
            Self::Io(operation) => write!(formatter, "LND {operation} failed"),
            Self::Protocol(detail) => write!(formatter, "invalid LND HTTP response: {detail}"),
            Self::HttpStatus(status) => write!(formatter, "LND returned HTTP status {status}"),
            Self::Json(detail) => write!(formatter, "invalid LND REST response: {detail}"),
            Self::Rpc(code) => write!(formatter, "LND REST request failed with code {code}"),
        }
    }
}

impl std::error::Error for LndError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndEndpoint {
    pub host: String,
    pub port: u16,
}

impl LndEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, LndError> {
        let host = host.into();
        if host.is_empty()
            || host.len() > 253
            || port == 0
            || host.bytes().any(|byte| {
                byte.is_ascii_control() || matches!(byte, b' ' | b'/' | b'\\' | b'@' | b'#')
            })
        {
            return Err(LndError::InvalidConfiguration(
                "REST host or port is invalid",
            ));
        }
        Ok(Self { host, port })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LndLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_response_bytes: usize,
    pub max_request_bytes: usize,
    pub max_stream_messages: usize,
}

impl Default for LndLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_stream_messages: DEFAULT_MAX_STREAM_MESSAGES,
        }
    }
}

impl LndLimits {
    fn validate(self) -> Result<Self, LndError> {
        if self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(30)
            || self.io_timeout.is_zero()
            || self.io_timeout > Duration::from_secs(300)
            || !(1024..=64 * 1024).contains(&self.max_header_bytes)
            || !(1024..=64 * 1024 * 1024).contains(&self.max_response_bytes)
            || !(1024..=16 * 1024 * 1024).contains(&self.max_request_bytes)
            || !(1..=1024).contains(&self.max_stream_messages)
        {
            return Err(LndError::InvalidConfiguration(
                "REST timeouts or limits are outside supported bounds",
            ));
        }
        Ok(self)
    }
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for SecretBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

struct SecretJson(Value);

impl SecretJson {
    fn decode(bytes: &[u8]) -> Result<Self, LndError> {
        let value = serde_json::from_slice(bytes)
            .map_err(|_| LndError::Json("REST stream message is not JSON"))?;
        let secret = Self(value);
        if let Some(error) = secret.0.get("error").and_then(Value::as_object) {
            let code = error
                .get("code")
                .and_then(Value::as_u64)
                .and_then(|code| u16::try_from(code).ok())
                .unwrap_or(1);
            return Err(LndError::Rpc(code));
        }
        Ok(secret)
    }

    fn as_value(&self) -> &Value {
        &self.0
    }

    fn wipe(&mut self) {
        wipe_json_strings(&mut self.0);
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn wipe_json_strings(value: &mut Value) {
    match value {
        Value::String(value) => {
            let mut bytes = std::mem::take(value).into_bytes();
            bytes.fill(0);
            value.extend(std::iter::repeat_n('\0', bytes.len()));
        }
        Value::Array(values) => values.iter_mut().for_each(wipe_json_strings),
        Value::Object(values) => values.values_mut().for_each(wipe_json_strings),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct LoadedFile {
    bytes: SecretBytes,
    identity: Option<FileIdentity>,
}

struct LndMacaroonSecret {
    bytes: SecretBytes,
    identity: Option<FileIdentity>,
}

#[derive(Clone)]
pub struct LndMacaroon(Arc<LndMacaroonSecret>);

impl LndMacaroon {
    pub fn load(path: &Path) -> Result<Self, LndError> {
        let loaded = read_bounded_regular_file(path, MAX_MACAROON_BYTES, true, "macaroon")?;
        if loaded.bytes.as_ref().is_empty() {
            return Err(LndError::SecretFile("macaroon is empty"));
        }
        Ok(Self(Arc::new(LndMacaroonSecret {
            bytes: loaded.bytes,
            identity: loaded.identity,
        })))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, LndError> {
        if bytes.is_empty() || bytes.len() > MAX_MACAROON_BYTES {
            return Err(LndError::SecretFile("macaroon size is invalid"));
        }
        Ok(Self(Arc::new(LndMacaroonSecret {
            bytes: SecretBytes(bytes),
            identity: None,
        })))
    }

    fn is_same_credential(&self, other: &Self) -> bool {
        self.0
            .identity
            .zip(other.0.identity)
            .is_some_and(|(identity, other_identity)| identity == other_identity)
            || self.0.bytes.as_ref() == other.0.bytes.as_ref()
    }
}

impl fmt::Debug for LndMacaroon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LndMacaroon([REDACTED])")
    }
}

#[derive(Clone)]
pub struct LndMacaroons {
    pub readonly: LndMacaroon,
    pub invoice: LndMacaroon,
    pub router: LndMacaroon,
}

impl LndMacaroons {
    pub fn new(
        readonly: LndMacaroon,
        invoice: LndMacaroon,
        router: LndMacaroon,
    ) -> Result<Self, LndError> {
        if readonly.is_same_credential(&invoice)
            || readonly.is_same_credential(&router)
            || invoice.is_same_credential(&router)
        {
            return Err(LndError::SecretFile(
                "readonly, invoice, and router macaroons must be distinct",
            ));
        }
        Ok(Self {
            readonly,
            invoice,
            router,
        })
    }
}

impl fmt::Debug for LndMacaroons {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LndMacaroons")
            .field("readonly", &self.readonly)
            .field("invoice", &self.invoice)
            .field("router", &self.router)
            .finish()
    }
}

#[derive(Clone)]
pub struct LndClient {
    endpoint: LndEndpoint,
    connector: TlsConnector,
    macaroons: LndMacaroons,
    limits: LndLimits,
}

struct PinnedCertificateVerifier {
    certificate: CertificateDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertificateVerifier([PINNED])")
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !intermediates.is_empty() || end_entity.as_ref() != self.certificate.as_ref() {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl fmt::Debug for LndClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LndClient")
            .field("endpoint", &self.endpoint)
            .field("macaroons", &self.macaroons)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacaroonScope {
    Readonly,
    Invoice,
    Router,
}

impl LndClient {
    pub fn new(
        endpoint: LndEndpoint,
        certificate_path: &Path,
        macaroons: LndMacaroons,
        limits: LndLimits,
    ) -> Result<Self, LndError> {
        let certificate = read_certificate(certificate_path)?;
        let verifier = PinnedCertificateVerifier {
            certificate,
            algorithms: default_provider().signature_verification_algorithms,
        };
        let tls = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self {
            endpoint,
            connector: TlsConnector::from(Arc::new(tls)),
            macaroons,
            limits: limits.validate()?,
        })
    }

    pub async fn node_info(&self) -> Result<LndNodeInfo, LndError> {
        let response = self
            .request(MacaroonScope::Readonly, "GET", "/v1/getinfo", None)
            .await?;
        parse_node_info(&response)
    }

    pub async fn channel_capacity(&self) -> Result<Millisatoshi, LndError> {
        let response = self
            .request(
                MacaroonScope::Readonly,
                "GET",
                "/v1/channels?active_only=true",
                None,
            )
            .await?;
        parse_channel_capacity(&response)
    }

    pub async fn hold_invoice(
        &self,
        payment_hash: &str,
        amount: Millisatoshi,
        expiry_seconds: u32,
        cltv_expiry: u32,
    ) -> Result<LndInvoice, LndError> {
        validate_hash(payment_hash)?;
        if expiry_seconds == 0 || expiry_seconds > 604_800 || cltv_expiry == 0 || cltv_expiry > 2016
        {
            return Err(LndError::InvalidConfiguration(
                "hold invoice expiry is outside supported bounds",
            ));
        }
        let body = json!({
            "hash":encode_base64(&decode_hex(payment_hash)?),
            "value_msat":amount.as_millisatoshis().to_string(),
            "expiry":expiry_seconds.to_string(),
            "cltv_expiry":cltv_expiry.to_string(),
            "private":true,
        });
        let response = self
            .request(
                MacaroonScope::Invoice,
                "POST",
                "/v2/invoices/hodl",
                Some(&body),
            )
            .await?;
        parse_invoice(&response, amount, Some(payment_hash), Some(expiry_seconds))
    }

    pub async fn lookup_invoice(&self, payment_hash: &str) -> Result<Value, LndError> {
        validate_hash(payment_hash)?;
        let path = format!("/v1/invoice/{payment_hash}");
        let response = self
            .request(MacaroonScope::Invoice, "GET", &path, None)
            .await?;
        validate_invoice_lookup(&response, payment_hash)?;
        Ok(response)
    }

    pub async fn normalized_hold_invoice(&self, payment_hash: &str) -> Result<Value, LndError> {
        let response = self.lookup_invoice(payment_hash).await?;
        let state = response
            .get("state")
            .and_then(Value::as_str)
            .and_then(normalized_invoice_state)
            .ok_or(LndError::Json("invoice lookup has an invalid state"))?;
        let bolt11 = response
            .get("payment_request")
            .and_then(Value::as_str)
            .filter(|invoice| !invoice.is_empty() && invoice.len() <= MAX_BOLT11_BYTES)
            .ok_or(LndError::Json("invoice lookup has no bounded BOLT11"))?;
        let htlcs = response
            .get("htlcs")
            .and_then(Value::as_array)
            .filter(|htlcs| htlcs.len() <= 64)
            .ok_or(LndError::Json("invoice lookup has no bounded HTLC set"))?
            .iter()
            .map(|htlc| {
                let htlc_state = htlc
                    .get("state")
                    .and_then(Value::as_str)
                    .and_then(normalized_htlc_state)
                    .ok_or(LndError::Json("invoice HTLC has an invalid state"))?;
                let amount = parse_u64_member(
                    htlc.as_object()
                        .ok_or(LndError::Json("invoice HTLC is not an object"))?,
                    "amt_msat",
                    "invoice HTLC amount is invalid",
                )?;
                let expiry = parse_u64_member(
                    htlc.as_object()
                        .ok_or(LndError::Json("invoice HTLC is not an object"))?,
                    "expiry_height",
                    "invoice HTLC expiry is invalid",
                )?;
                Ok(json!({
                    "state":htlc_state,
                    "msat":amount,
                    "cltv_expiry":expiry,
                }))
            })
            .collect::<Result<Vec<_>, LndError>>()?;
        Ok(json!({
            "holdinvoices":[{
                "payment_hash":payment_hash,
                "invoice":bolt11,
                "bolt11":bolt11,
                "state":state,
                "htlcs":htlcs,
            }]
        }))
    }

    pub async fn settle_hold_invoice(&self, preimage: &[u8; 32]) -> Result<(), LndError> {
        let body = settlement_request_body(preimage);
        self.request_encoded(
            MacaroonScope::Invoice,
            "POST",
            "/v2/invoices/settle",
            body.as_ref(),
        )
        .await?;
        Ok(())
    }

    pub async fn cancel_hold_invoice(&self, payment_hash: &str) -> Result<(), LndError> {
        validate_hash(payment_hash)?;
        let body = json!({"payment_hash":encode_base64(&decode_hex(payment_hash)?)});
        self.request(
            MacaroonScope::Invoice,
            "POST",
            "/v2/invoices/cancel",
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub async fn send_payment(
        &self,
        bolt11: &str,
        maximum_fee: Millisatoshi,
        timeout_seconds: u16,
    ) -> Result<LndPayment, LndError> {
        let invoice = immortal_core::mkt_swp_verify::parse_bolt11(bolt11)
            .map_err(|_| LndError::InvalidConfiguration("BOLT11 is invalid"))?;
        let expected_amount = invoice.amount_msat.ok_or(LndError::InvalidConfiguration(
            "BOLT11 has no fixed payment amount",
        ))?;
        let expected_hash = lower_hex(&invoice.payment_hash);
        if timeout_seconds == 0 || timeout_seconds > 300 {
            return Err(LndError::InvalidConfiguration(
                "payment timeout is outside supported bounds",
            ));
        }
        let body = json!({
            "payment_request":bolt11,
            "fee_limit_msat":maximum_fee.as_millisatoshis().to_string(),
            "timeout_seconds":timeout_seconds,
            "no_inflight_updates":true,
        });
        let response = self
            .request_stream_first(
                MacaroonScope::Router,
                "POST",
                "/v2/router/send",
                Some(&body),
            )
            .await?;
        let payment = parse_payment_stream(response.as_value())?;
        if payment.payment_hash != expected_hash
            || payment.amount.as_millisatoshis() != expected_amount
        {
            return Err(LndError::Json(
                "payment response does not bind the requested invoice",
            ));
        }
        Ok(payment)
    }

    pub async fn track_payment(&self, payment_hash: &str) -> Result<LndPayment, LndError> {
        validate_hash(payment_hash)?;
        let encoded = encode_base64url(&decode_hex(payment_hash)?);
        let path = format!("/v2/router/track/{encoded}?no_inflight_updates=true");
        let response = self
            .request_stream_first(MacaroonScope::Router, "GET", &path, None)
            .await?;
        let payment = parse_payment_stream(response.as_value())?;
        if payment.payment_hash != payment_hash {
            return Err(LndError::Json("tracked payment hash does not match"));
        }
        Ok(payment)
    }

    pub async fn block_epoch(&self) -> Result<LndBlockEpoch, LndError> {
        let response = self
            .request_stream_first(
                MacaroonScope::Readonly,
                "POST",
                "/v2/chainnotifier/register/blocks",
                Some(&json!({})),
            )
            .await?;
        parse_block_epoch_stream(response.as_value())
    }

    async fn request(
        &self,
        scope: MacaroonScope,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, LndError> {
        let body = SecretBytes(
            body.map(serde_json::to_vec)
                .transpose()
                .map_err(|_| LndError::InvalidConfiguration("REST request is not serializable"))?
                .unwrap_or_default(),
        );
        self.request_encoded(scope, method, path, body.as_ref())
            .await
    }

    async fn request_encoded(
        &self,
        scope: MacaroonScope,
        method: &'static str,
        path: &str,
        body: &[u8],
    ) -> Result<Value, LndError> {
        if body.len() > self.limits.max_request_bytes {
            return Err(LndError::InvalidConfiguration(
                "REST request exceeds the configured byte limit",
            ));
        }
        let request = encode_request(&self.endpoint, scope, &self.macaroons, method, path, body)?;
        let mut stream = self.connect().await?;
        timeout(self.limits.io_timeout, async {
            stream.write_all(request.as_ref()).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| LndError::TimedOut("request write"))?
        .map_err(|_| LndError::Io("request write"))?;
        let response = timeout(
            self.limits.io_timeout,
            read_http_response(&mut stream, self.limits),
        )
        .await
        .map_err(|_| LndError::TimedOut("response read"))??;
        if response.status != 200 {
            return Err(http_error(response.status, &response.body));
        }
        decode_json_or_stream(&response.body, self.limits.max_stream_messages)
    }

    async fn request_stream_first(
        &self,
        scope: MacaroonScope,
        method: &'static str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<SecretJson, LndError> {
        let body = SecretBytes(
            body.map(serde_json::to_vec)
                .transpose()
                .map_err(|_| LndError::InvalidConfiguration("REST request is not serializable"))?
                .unwrap_or_default(),
        );
        if body.as_ref().len() > self.limits.max_request_bytes {
            return Err(LndError::InvalidConfiguration(
                "REST request exceeds the configured byte limit",
            ));
        }
        let request = encode_request(
            &self.endpoint,
            scope,
            &self.macaroons,
            method,
            path,
            body.as_ref(),
        )?;
        let mut stream = self.connect().await?;
        timeout(self.limits.io_timeout, async {
            stream.write_all(request.as_ref()).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| LndError::TimedOut("request write"))?
        .map_err(|_| LndError::Io("request write"))?;
        let response = timeout(
            self.limits.io_timeout,
            read_http_stream_first(&mut stream, self.limits),
        )
        .await
        .map_err(|_| LndError::TimedOut("stream response read"))??;
        if response.status != 200 {
            return Err(http_error(response.status, &response.body));
        }
        SecretJson::decode(&response.body)
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, LndError> {
        let endpoint = (self.endpoint.host.as_str(), self.endpoint.port);
        let addresses = timeout(self.limits.connect_timeout, lookup_host(endpoint))
            .await
            .map_err(|_| LndError::TimedOut("address resolution"))?
            .map_err(|_| LndError::ResolutionFailed)?
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(LndError::ResolutionFailed);
        }
        if addresses.iter().any(|address| !address.ip().is_loopback()) {
            return Err(LndError::NonLoopbackEndpoint);
        }
        let tcp = timeout(self.limits.connect_timeout, connect_first(&addresses))
            .await
            .map_err(|_| LndError::TimedOut("connection"))??;
        let peer = tcp.peer_addr().map_err(|_| LndError::ConnectionFailed)?;
        if !peer.ip().is_loopback() || !addresses.contains(&peer) {
            return Err(LndError::NonLoopbackEndpoint);
        }
        let server_name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|_| LndError::InvalidConfiguration("REST TLS server name is invalid"))?;
        timeout(
            self.limits.connect_timeout,
            self.connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| LndError::TimedOut("TLS handshake"))?
        .map_err(|_| LndError::Tls)
    }
}

fn settlement_request_body(preimage: &[u8; 32]) -> SecretBytes {
    let mut body = SecretBytes(b"{\"preimage\":\"".to_vec());
    append_base64(
        &mut body,
        preimage,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    );
    body.extend_from_slice(b"\"}");
    body
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndNodeInfo {
    pub block_height: u32,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndInvoice {
    pub bolt11: String,
    pub payment_hash: String,
    pub expires_at: u64,
}

pub struct LndPayment {
    pub payment_hash: String,
    pub status: String,
    pub amount: Millisatoshi,
    pub amount_sent: Millisatoshi,
    pub released_preimage: Option<LndPaymentPreimage>,
    pub settled_at: Option<u64>,
}

impl fmt::Debug for LndPayment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LndPayment")
            .field("payment_hash", &self.payment_hash)
            .field("status", &self.status)
            .field("amount", &self.amount)
            .field("amount_sent", &self.amount_sent)
            .field(
                "released_preimage",
                &self.released_preimage.as_ref().map(|_| "[REDACTED]"),
            )
            .field("settled_at", &self.settled_at)
            .finish()
    }
}

pub struct LndPaymentPreimage([u8; 32]);

impl LndPaymentPreimage {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(mut self) -> [u8; 32] {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for LndPaymentPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LndPaymentPreimage([REDACTED])")
    }
}

impl Drop for LndPaymentPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndBlockEpoch {
    pub height: u32,
    pub block_hash: String,
}

fn encode_request(
    endpoint: &LndEndpoint,
    scope: MacaroonScope,
    macaroons: &LndMacaroons,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SecretBytes, LndError> {
    if !matches!(method, "GET" | "POST")
        || !safe_path(path)
        || path.len() > MAX_PATH_BYTES
        || (method == "GET" && !body.is_empty())
    {
        return Err(LndError::InvalidConfiguration(
            "REST method, path, or body is invalid",
        ));
    }
    let macaroon = match scope {
        MacaroonScope::Readonly => &macaroons.readonly,
        MacaroonScope::Invoice => &macaroons.invoice,
        MacaroonScope::Router => &macaroons.router,
    };
    let host = if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nGrpc-Metadata-Macaroon: ")
            .into_bytes();
    append_lower_hex(&mut request, macaroon.0.bytes.as_ref());
    request.extend_from_slice(b"\r\nAccept: application/json\r\nConnection: close\r\n");
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
    request.extend_from_slice(body);
    Ok(SecretBytes(request))
}

fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('#')
        && !path.contains("\\")
        && !path.contains("..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b' ')
}

fn parse_node_info(value: &Value) -> Result<LndNodeInfo, LndError> {
    let object = value
        .as_object()
        .ok_or(LndError::Json("getinfo response is not an object"))?;
    if object.get("synced_to_chain").and_then(Value::as_bool) != Some(true)
        || object.get("synced_to_graph").and_then(Value::as_bool) != Some(true)
    {
        return Err(LndError::Json("LND is not synchronized"));
    }
    let block_height = parse_u32_value(object.get("block_height"), "block height is invalid")?;
    let chains = object
        .get("chains")
        .and_then(Value::as_array)
        .ok_or(LndError::Json("getinfo response has no chains"))?;
    let network = chains
        .iter()
        .filter_map(Value::as_object)
        .find(|chain| chain.get("chain").and_then(Value::as_str) == Some("bitcoin"))
        .and_then(|chain| chain.get("network"))
        .and_then(Value::as_str)
        .filter(|network| {
            !network.is_empty()
                && network.len() <= 16
                && network.bytes().all(|byte| byte.is_ascii_lowercase())
        })
        .ok_or(LndError::Json("getinfo response has no Bitcoin network"))?;
    Ok(LndNodeInfo {
        block_height,
        network: network.to_owned(),
    })
}

fn parse_channel_capacity(value: &Value) -> Result<Millisatoshi, LndError> {
    let channels = value
        .get("channels")
        .and_then(Value::as_array)
        .filter(|channels| channels.len() <= 4096)
        .ok_or(LndError::Json("channel list is absent or too large"))?;
    let mut total_msat = 0_u64;
    for channel in channels {
        let object = channel
            .as_object()
            .ok_or(LndError::Json("channel entry is not an object"))?;
        if object.get("active").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let local_balance_sat =
            parse_u64_member(object, "local_balance", "channel local balance is invalid")?;
        let commit_fee_sat =
            parse_u64_member(object, "commit_fee", "channel commitment fee is invalid")?;
        let local_constraints = object
            .get("local_constraints")
            .and_then(Value::as_object)
            .ok_or(LndError::Json("channel local constraints are absent"))?;
        let reserve_sat = parse_u64_member(
            local_constraints,
            "chan_reserve_sat",
            "channel reserve is invalid",
        )?;
        let remote_constraints = object
            .get("remote_constraints")
            .and_then(Value::as_object)
            .ok_or(LndError::Json("channel remote constraints are absent"))?;
        let maximum_pending_msat = parse_u64_member(
            remote_constraints,
            "max_pending_amt_msat",
            "channel remote pending limit is invalid",
        )?;
        let maximum_accepted_htlcs = parse_u64_member(
            remote_constraints,
            "max_accepted_htlcs",
            "channel remote HTLC limit is invalid",
        )?;
        let pending_htlcs = object
            .get("pending_htlcs")
            .and_then(Value::as_array)
            .filter(|pending_htlcs| pending_htlcs.len() <= 4096)
            .ok_or(LndError::Json(
                "channel pending HTLC set is absent or too large",
            ))?;
        let mut outgoing_sat = 0_u64;
        let mut outgoing_count = 0_u64;
        for pending_htlc in pending_htlcs {
            let pending_htlc = pending_htlc
                .as_object()
                .ok_or(LndError::Json("pending HTLC is not an object"))?;
            let incoming = pending_htlc
                .get("incoming")
                .and_then(Value::as_bool)
                .ok_or(LndError::Json("pending HTLC direction is invalid"))?;
            if incoming {
                continue;
            }
            outgoing_count = outgoing_count
                .checked_add(1)
                .ok_or(LndError::Json("outgoing HTLC count overflowed"))?;
            outgoing_sat = outgoing_sat
                .checked_add(parse_u64_member(
                    pending_htlc,
                    "amount",
                    "pending HTLC amount is invalid",
                )?)
                .ok_or(LndError::Json("outgoing HTLC amount overflowed"))?;
        }
        if outgoing_count >= maximum_accepted_htlcs {
            continue;
        }
        let spendable_sat = local_balance_sat
            .checked_sub(reserve_sat)
            .and_then(|amount| amount.checked_sub(commit_fee_sat))
            .and_then(|amount| amount.checked_sub(outgoing_sat))
            .unwrap_or(0);
        let outgoing_msat = outgoing_sat
            .checked_mul(1000)
            .ok_or(LndError::Json("outgoing HTLC amount overflowed"))?;
        let pending_room_msat = maximum_pending_msat.saturating_sub(outgoing_msat);
        let spendable_msat = spendable_sat
            .checked_mul(1000)
            .ok_or(LndError::Json("channel capacity overflowed"))?;
        total_msat = total_msat
            .checked_add(spendable_msat.min(pending_room_msat))
            .ok_or(LndError::Json("channel capacity overflowed"))?;
    }
    Ok(Millisatoshi::from_millisatoshis(total_msat))
}

fn parse_invoice(
    value: &Value,
    expected_amount: Millisatoshi,
    expected_hash: Option<&str>,
    expected_expiry: Option<u32>,
) -> Result<LndInvoice, LndError> {
    let bolt11 = value
        .get("payment_request")
        .and_then(Value::as_str)
        .ok_or(LndError::Json("invoice response has no payment request"))?;
    let invoice = immortal_core::mkt_swp_verify::parse_bolt11(bolt11)
        .map_err(|_| LndError::Json("invoice response has an invalid BOLT11"))?;
    let payment_hash = lower_hex(&invoice.payment_hash);
    let expires_at = invoice
        .timestamp
        .checked_add(invoice.expiry_seconds)
        .ok_or(LndError::Json("invoice expiry overflows"))?;
    if invoice.amount_msat != Some(expected_amount.as_millisatoshis())
        || expected_hash.is_some_and(|expected| expected != payment_hash)
        || expected_expiry.is_some_and(|expected| invoice.expiry_seconds != u64::from(expected))
    {
        return Err(LndError::Json(
            "invoice response does not bind the requested amount, hash, or expiry",
        ));
    }
    Ok(LndInvoice {
        bolt11: bolt11.to_owned(),
        payment_hash,
        expires_at,
    })
}

fn validate_invoice_lookup(value: &Value, expected_hash: &str) -> Result<(), LndError> {
    let hash = value
        .get("r_hash")
        .and_then(Value::as_str)
        .ok_or(LndError::Json("invoice lookup has no payment hash"))?;
    let decoded = decode_base64(hash)?;
    if lower_hex(&decoded) != expected_hash {
        return Err(LndError::Json(
            "invoice lookup returned another payment hash",
        ));
    }
    Ok(())
}

fn normalized_invoice_state(state: &str) -> Option<&'static str> {
    match state {
        "OPEN" => Some("unpaid"),
        "ACCEPTED" => Some("accepted"),
        "SETTLED" => Some("settled"),
        "CANCELED" => Some("cancelled"),
        _ => None,
    }
}

fn normalized_htlc_state(state: &str) -> Option<&'static str> {
    match state {
        "ACCEPTED" => Some("accepted"),
        "SETTLED" => Some("settled"),
        "CANCELED" => Some("cancelled"),
        _ => None,
    }
}

fn parse_payment_stream(value: &Value) -> Result<LndPayment, LndError> {
    let result = value.get("result").unwrap_or(value);
    let object = result
        .as_object()
        .ok_or(LndError::Json("payment update is not an object"))?;
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or(LndError::Json("payment update has no status"))?;
    if status == "FAILED" {
        return Err(LndError::Rpc(1));
    }
    if status != "SUCCEEDED" {
        return Err(LndError::Json("payment update is not terminal"));
    }
    let payment_hash = decode_lower_hex_32_member(object, "payment_hash")?;
    let released_preimage =
        LndPaymentPreimage(decode_lower_hex_32_member(object, "payment_preimage")?);
    if Sha256::digest(released_preimage.as_bytes()).as_slice() != payment_hash {
        return Err(LndError::Json("payment preimage does not match its hash"));
    }
    let value_msat = parse_u64_member(object, "value_msat", "payment amount is invalid")?;
    let fee_msat = parse_u64_member(object, "fee_msat", "payment fee is invalid")?;
    let amount_sent = value_msat
        .checked_add(fee_msat)
        .ok_or(LndError::Json("payment amount overflows"))?;
    let settled_at = object
        .get("htlcs")
        .and_then(Value::as_array)
        .and_then(|attempts| {
            attempts
                .iter()
                .filter_map(|attempt| attempt.get("resolve_time_ns").and_then(Value::as_str))
                .filter_map(|value| value.parse::<u64>().ok())
                .max()
        })
        .map(|nanoseconds| nanoseconds / 1_000_000_000)
        .filter(|seconds| *seconds > 0);
    Ok(LndPayment {
        payment_hash: lower_hex(&payment_hash),
        status: "complete".to_owned(),
        amount: Millisatoshi::from_millisatoshis(value_msat),
        amount_sent: Millisatoshi::from_millisatoshis(amount_sent),
        released_preimage: Some(released_preimage),
        settled_at,
    })
}

fn parse_block_epoch_stream(value: &Value) -> Result<LndBlockEpoch, LndError> {
    let result = value.get("result").unwrap_or(value);
    let object = result
        .as_object()
        .ok_or(LndError::Json("block epoch update is not an object"))?;
    let height = object
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or(LndError::Json("block epoch height is invalid"))?;
    let hash = decode_base64_member(object, "hash")?;
    if hash.len() != 32 {
        return Err(LndError::Json("block epoch hash has another length"));
    }
    Ok(LndBlockEpoch {
        height,
        block_hash: lower_hex(&hash),
    })
}

struct HttpResponse {
    status: u16,
    body: SecretBytes,
}

async fn read_http_response<R: AsyncRead + Unpin>(
    stream: &mut R,
    limits: LndLimits,
) -> Result<HttpResponse, LndError> {
    let mut bytes = SecretBytes(Vec::new());
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| LndError::Io("response read"))?;
        if read == 0 {
            return Err(LndError::Protocol("truncated response headers"));
        }
        bytes.extend_from_slice(&chunk[..read]);
        chunk[..read].fill(0);
        if let Some(position) = find_header_end(&bytes) {
            if position > limits.max_header_bytes {
                return Err(LndError::Protocol("response headers are too large"));
            }
            break position;
        }
        if bytes.len() > limits.max_header_bytes {
            return Err(LndError::Protocol("response headers are too large"));
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| LndError::Protocol("response headers are not ASCII"))?;
    let mut lines = head.split("\r\n");
    let status = parse_status(
        lines
            .next()
            .ok_or(LndError::Protocol("response has no status line"))?,
    )?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(LndError::Protocol("malformed response header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() || value.contains(',') {
                return Err(LndError::Protocol("ambiguous Content-Length header"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| LndError::Protocol("invalid Content-Length header"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(LndError::Protocol("unsupported Transfer-Encoding header"));
            }
            chunked = true;
        }
    }
    if chunked && content_length.is_some() {
        return Err(LndError::Protocol("ambiguous response framing"));
    }
    let body_start = header_end + 4;
    let initial = SecretBytes(bytes[body_start..].to_vec());
    let body = if chunked {
        read_chunked(stream, initial, limits.max_response_bytes).await?
    } else if let Some(length) = content_length {
        read_content_length(stream, initial, length, limits.max_response_bytes).await?
    } else {
        read_to_end_bounded(stream, initial, limits.max_response_bytes).await?
    };
    Ok(HttpResponse { status, body })
}

async fn read_http_stream_first<R: AsyncRead + Unpin>(
    stream: &mut R,
    limits: LndLimits,
) -> Result<HttpResponse, LndError> {
    let mut bytes = SecretBytes(Vec::new());
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| LndError::Io("stream response read"))?;
        if read == 0 {
            return Err(LndError::Protocol("truncated response headers"));
        }
        bytes.extend_from_slice(&chunk[..read]);
        chunk[..read].fill(0);
        if let Some(position) = find_header_end(&bytes) {
            if position > limits.max_header_bytes {
                return Err(LndError::Protocol("response headers are too large"));
            }
            break position;
        }
        if bytes.len() > limits.max_header_bytes {
            return Err(LndError::Protocol("response headers are too large"));
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| LndError::Protocol("response headers are not ASCII"))?;
    let mut lines = head.split("\r\n");
    let status = parse_status(
        lines
            .next()
            .ok_or(LndError::Protocol("response has no status line"))?,
    )?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(LndError::Protocol("malformed response header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() || value.contains(',') {
                return Err(LndError::Protocol("ambiguous Content-Length header"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| LndError::Protocol("invalid Content-Length header"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(LndError::Protocol("unsupported Transfer-Encoding header"));
            }
            chunked = true;
        }
    }
    if chunked && content_length.is_some() {
        return Err(LndError::Protocol("ambiguous response framing"));
    }
    let initial = SecretBytes(bytes[header_end + 4..].to_vec());
    let body = if chunked {
        read_first_chunked_message(stream, initial, limits.max_response_bytes).await?
    } else if let Some(length) = content_length {
        let body = read_content_length(stream, initial, length, limits.max_response_bytes).await?;
        SecretBytes(first_stream_message(&body)?.to_vec())
    } else {
        read_first_unframed_message(stream, initial, limits.max_response_bytes).await?
    };
    Ok(HttpResponse { status, body })
}

async fn read_first_chunked_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial: SecretBytes,
    maximum: usize,
) -> Result<SecretBytes, LndError> {
    let mut reader = BufferedReader::new(stream, initial);
    let mut body = SecretBytes(Vec::new());
    loop {
        let line = reader.read_line(128).await?;
        let size_text = std::str::from_utf8(&line)
            .map_err(|_| LndError::Protocol("chunk size is not ASCII"))?;
        if size_text.contains(';') || size_text.is_empty() {
            return Err(LndError::Protocol("chunk extensions are unsupported"));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| LndError::Protocol("chunk size is invalid"))?;
        if size == 0 {
            if !reader.read_line(1024).await?.is_empty() {
                return Err(LndError::Protocol("chunk trailers are unsupported"));
            }
            return first_stream_message(&body).map(|message| SecretBytes(message.to_vec()));
        }
        if body.len().saturating_add(size) > maximum {
            return Err(LndError::Protocol("response body is too large"));
        }
        body.extend_from_slice(&reader.read_exact(size).await?);
        if !reader.read_line(2).await?.is_empty() {
            return Err(LndError::Protocol("chunk terminator is invalid"));
        }
        if let Ok(message) = first_stream_message(&body) {
            return Ok(SecretBytes(message.to_vec()));
        }
    }
}

async fn read_first_unframed_message<R: AsyncRead + Unpin>(
    stream: &mut R,
    mut body: SecretBytes,
    maximum: usize,
) -> Result<SecretBytes, LndError> {
    loop {
        if let Ok(message) = first_stream_message(&body) {
            return Ok(SecretBytes(message.to_vec()));
        }
        if body.len() >= maximum {
            return Err(LndError::Protocol("response body is too large"));
        }
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| LndError::Io("stream response read"))?;
        if read == 0 {
            return first_stream_message(&body).map(|message| SecretBytes(message.to_vec()));
        }
        if body.len().saturating_add(read) > maximum {
            return Err(LndError::Protocol("response body is too large"));
        }
        body.extend_from_slice(&chunk[..read]);
        chunk[..read].fill(0);
    }
}

fn first_stream_message(body: &[u8]) -> Result<&[u8], LndError> {
    let message = body
        .split(|byte| *byte == b'\n')
        .find(|line| !line.iter().all(u8::is_ascii_whitespace))
        .ok_or(LndError::Json("REST stream has no message"))?;
    let message = message.strip_suffix(b"\r").unwrap_or(message);
    serde_json::from_slice::<IgnoredAny>(message)
        .map(|_| message)
        .map_err(|_| LndError::Json("REST stream message is incomplete"))
}

async fn read_content_length<R: AsyncRead + Unpin>(
    stream: &mut R,
    mut body: SecretBytes,
    length: usize,
    maximum: usize,
) -> Result<SecretBytes, LndError> {
    if length > maximum || body.len() > length {
        return Err(LndError::Protocol("response body length is invalid"));
    }
    let remaining = length - body.len();
    if remaining > 0 {
        let start = body.len();
        body.resize(length, 0);
        stream
            .read_exact(&mut body[start..])
            .await
            .map_err(|_| LndError::Protocol("truncated response body"))?;
    }
    Ok(body)
}

async fn read_to_end_bounded<R: AsyncRead + Unpin>(
    stream: &mut R,
    mut body: SecretBytes,
    maximum: usize,
) -> Result<SecretBytes, LndError> {
    while body.len() <= maximum {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| LndError::Io("response read"))?;
        if read == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..read]);
        chunk[..read].fill(0);
    }
    Err(LndError::Protocol("response body is too large"))
}

async fn read_chunked<R: AsyncRead + Unpin>(
    stream: &mut R,
    initial: SecretBytes,
    maximum: usize,
) -> Result<SecretBytes, LndError> {
    let mut reader = BufferedReader::new(stream, initial);
    let mut body = SecretBytes(Vec::new());
    loop {
        let line = reader.read_line(128).await?;
        let size_text = std::str::from_utf8(&line)
            .map_err(|_| LndError::Protocol("chunk size is not ASCII"))?;
        if size_text.contains(';') || size_text.is_empty() {
            return Err(LndError::Protocol("chunk extensions are unsupported"));
        }
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| LndError::Protocol("chunk size is invalid"))?;
        if size == 0 {
            if !reader.read_line(1024).await?.is_empty() {
                return Err(LndError::Protocol("chunk trailers are unsupported"));
            }
            return Ok(body);
        }
        if body.len().saturating_add(size) > maximum {
            return Err(LndError::Protocol("response body is too large"));
        }
        body.extend_from_slice(&reader.read_exact(size).await?);
        if !reader.read_line(2).await?.is_empty() {
            return Err(LndError::Protocol("chunk terminator is invalid"));
        }
    }
}

struct BufferedReader<'a, R> {
    stream: &'a mut R,
    bytes: SecretBytes,
    offset: usize,
}

impl<'a, R: AsyncRead + Unpin> BufferedReader<'a, R> {
    fn new(stream: &'a mut R, bytes: SecretBytes) -> Self {
        Self {
            stream,
            bytes,
            offset: 0,
        }
    }

    async fn read_line(&mut self, maximum: usize) -> Result<Vec<u8>, LndError> {
        loop {
            if let Some(relative) = self.bytes[self.offset..]
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                let end = self.offset + relative;
                let line = self.bytes[self.offset..end].to_vec();
                self.offset = end + 2;
                return Ok(line);
            }
            if self.bytes.len().saturating_sub(self.offset) > maximum {
                return Err(LndError::Protocol("chunk line is too large"));
            }
            self.read_more().await?;
        }
    }

    async fn read_exact(&mut self, length: usize) -> Result<SecretBytes, LndError> {
        while self.bytes.len().saturating_sub(self.offset) < length {
            self.read_more().await?;
        }
        let end = self.offset + length;
        let output = SecretBytes(self.bytes[self.offset..end].to_vec());
        self.offset = end;
        Ok(output)
    }

    async fn read_more(&mut self) -> Result<(), LndError> {
        if self.offset > 0 {
            self.bytes.drain(..self.offset);
            self.offset = 0;
        }
        let mut chunk = [0_u8; 4096];
        let read = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|_| LndError::Io("response read"))?;
        if read == 0 {
            return Err(LndError::Protocol("truncated chunked response"));
        }
        self.bytes.extend_from_slice(&chunk[..read]);
        chunk[..read].fill(0);
        Ok(())
    }
}

fn decode_json_or_stream(body: &[u8], maximum_messages: usize) -> Result<Value, LndError> {
    if let Ok(value) = serde_json::from_slice(body) {
        return decode_gateway_error(value);
    }
    let mut last = None;
    let mut count = 0;
    for line in body.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > maximum_messages {
            return Err(LndError::Protocol("REST stream message bound reached"));
        }
        let value = serde_json::from_slice(line)
            .map_err(|_| LndError::Json("REST stream message is not JSON"))?;
        last = Some(decode_gateway_error(value)?);
    }
    last.ok_or(LndError::Json("REST response is not JSON"))
}

fn decode_gateway_error(value: Value) -> Result<Value, LndError> {
    if let Some(error) = value.get("error").and_then(Value::as_object) {
        let code = error
            .get("code")
            .and_then(Value::as_u64)
            .and_then(|code| u16::try_from(code).ok())
            .unwrap_or(1);
        return Err(LndError::Rpc(code));
    }
    Ok(value)
}

fn http_error(status: u16, body: &[u8]) -> LndError {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("code")
                .and_then(Value::as_u64)
                .and_then(|code| u16::try_from(code).ok())
        })
        .map(LndError::Rpc)
        .unwrap_or(LndError::HttpStatus(status))
}

fn read_certificate(path: &Path) -> Result<CertificateDer<'static>, LndError> {
    let loaded = read_bounded_regular_file(path, MAX_CERTIFICATE_BYTES, false, "certificate")?;
    let bytes = loaded.bytes;
    let text = std::str::from_utf8(bytes.as_ref())
        .map_err(|_| LndError::InvalidConfiguration("pinned certificate is not PEM"))?;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let encoded = text
        .trim_ascii()
        .strip_prefix(begin)
        .and_then(|text| text.strip_suffix(end))
        .ok_or(LndError::InvalidConfiguration(
            "pinned certificate must contain one exact PEM certificate",
        ))?;
    let compact = encoded
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let certificate = decode_base64(&compact)?;
    if certificate.is_empty() {
        return Err(LndError::InvalidConfiguration(
            "pinned certificate is empty",
        ));
    }
    Ok(CertificateDer::from(certificate))
}

fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
    mode_0600: bool,
    subject: &'static str,
) -> Result<LoadedFile, LndError> {
    if !path.is_absolute() {
        return Err(LndError::SecretFile("credential path is not absolute"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LndError::SecretFile("credential metadata is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LndError::SecretFile("credential is not a regular file"));
    }
    #[cfg(unix)]
    if mode_0600 {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(LndError::SecretFile("credential mode must be 0600"));
        }
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| LndError::SecretFile("credential is too large"))?;
    if length == 0 || length > maximum {
        return Err(LndError::SecretFile(match subject {
            "macaroon" => "macaroon size is invalid",
            _ => "certificate size is invalid",
        }));
    }
    let mut file = open_credential_file(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| LndError::SecretFile("credential metadata is unavailable"))?;
    if !opened_metadata.is_file() || !same_credential_file(&metadata, &opened_metadata) {
        return Err(LndError::SecretFile("credential changed before opening"));
    }
    #[cfg(unix)]
    if mode_0600 {
        use std::os::unix::fs::PermissionsExt;
        if opened_metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(LndError::SecretFile("credential mode must be 0600"));
        }
    }
    if opened_metadata.len() != metadata.len() {
        return Err(LndError::SecretFile("credential changed before reading"));
    }
    let mut bytes = Vec::with_capacity(length);
    file.by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LndError::SecretFile("credential could not be read"))?;
    if bytes.len() != length {
        return Err(LndError::SecretFile("credential changed while reading"));
    }
    Ok(LoadedFile {
        bytes: SecretBytes(bytes),
        identity: credential_identity(&opened_metadata),
    })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn open_credential_file(path: &Path) -> Result<File, LndError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const NO_FOLLOW: i32 = 0x20_000;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    const NO_FOLLOW: i32 = 0x100;

    OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW)
        .open(path)
        .map_err(|_| LndError::SecretFile("credential could not be opened"))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn open_credential_file(path: &Path) -> Result<File, LndError> {
    File::open(path).map_err(|_| LndError::SecretFile("credential could not be opened"))
}

#[cfg(unix)]
fn same_credential_file(before: &fs::Metadata, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_credential_file(_before: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn credential_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn credential_identity(_metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

async fn connect_first(addresses: &[SocketAddr]) -> Result<TcpStream, LndError> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(LndError::ConnectionFailed)
}

fn parse_status(status_line: &str) -> Result<u16, LndError> {
    let mut parts = status_line.split_ascii_whitespace();
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(LndError::Protocol("unsupported HTTP version"));
    }
    parts
        .next()
        .ok_or(LndError::Protocol("status line has no status"))?
        .parse::<u16>()
        .map_err(|_| LndError::Protocol("HTTP status is invalid"))
}

fn parse_u32_value(value: Option<&Value>, detail: &'static str) -> Result<u32, LndError> {
    let value = match value {
        Some(Value::Number(value)) => value.as_u64().ok_or(LndError::Json(detail))?,
        Some(Value::String(value)) => parse_u64(value, detail)?,
        _ => return Err(LndError::Json(detail)),
    };
    u32::try_from(value).map_err(|_| LndError::Json(detail))
}

fn parse_u64_member(
    object: &Map<String, Value>,
    name: &str,
    detail: &'static str,
) -> Result<u64, LndError> {
    match object.get(name) {
        Some(Value::Number(value)) => value.as_u64().ok_or(LndError::Json(detail)),
        Some(Value::String(value)) => parse_u64(value, detail),
        _ => Err(LndError::Json(detail)),
    }
}

fn parse_u64(value: &str, detail: &'static str) -> Result<u64, LndError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LndError::Json(detail));
    }
    value.parse::<u64>().map_err(|_| LndError::Json(detail))
}

fn decode_base64_member(object: &Map<String, Value>, name: &str) -> Result<Vec<u8>, LndError> {
    decode_base64(
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or(LndError::Json("REST bytes member is absent"))?,
    )
}

fn encode_base64(input: &[u8]) -> String {
    encode_base64_with(
        input,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    )
}

fn encode_base64url(input: &[u8]) -> String {
    encode_base64_with(
        input,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    )
}

fn encode_base64_with(input: &[u8], alphabet: &[u8; 64]) -> String {
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    append_base64(&mut output, input, alphabet);
    output.into_iter().map(char::from).collect()
}

fn append_base64(output: &mut Vec<u8>, input: &[u8], alphabet: &[u8; 64]) {
    output.reserve(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(alphabet[(first >> 2) as usize]);
        output.push(alphabet[(((first & 0x03) << 4) | (second >> 4)) as usize]);
        if chunk.len() > 1 {
            output.push(alphabet[(((second & 0x0f) << 2) | (third >> 6)) as usize]);
        } else {
            output.push(b'=');
        }
        if chunk.len() > 2 {
            output.push(alphabet[(third & 0x3f) as usize]);
        } else {
            output.push(b'=');
        }
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>, LndError> {
    if value.is_empty() || value.len() % 4 != 0 || value.len() > MAX_CERTIFICATE_BYTES * 2 {
        return Err(LndError::Json("base64 value has invalid length"));
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
        let last = index + 1 == value.len() / 4;
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        let third = if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' {
                return Err(LndError::Json("base64 padding is invalid"));
            }
            0
        } else {
            base64_value(chunk[2])?
        };
        let fourth = if chunk[3] == b'=' {
            if !last {
                return Err(LndError::Json("base64 padding is invalid"));
            }
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            output.push((second << 4) | (third >> 2));
        }
        if chunk[3] != b'=' {
            output.push((third << 6) | fourth);
        }
    }
    if encode_base64(&output) != value {
        return Err(LndError::Json("base64 value is noncanonical"));
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, LndError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(LndError::Json("base64 value has an invalid character")),
    }
}

fn validate_hash(value: &str) -> Result<(), LndError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(LndError::InvalidConfiguration(
            "hash is not 64-character lowercase hexadecimal",
        ))
    }
}

fn decode_lower_hex_32_member(
    object: &Map<String, Value>,
    member: &'static str,
) -> Result<[u8; 32], LndError> {
    let value = object
        .get(member)
        .and_then(Value::as_str)
        .ok_or(LndError::Json("payment response has no hash or preimage"))?;
    if value.len() != 64 {
        return Err(LndError::Json("payment hex field has another length"));
    }
    let mut bytes = [0_u8; 32];
    for (output, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high =
            hex_value(pair[0]).map_err(|_| LndError::Json("payment hex field is invalid"))?;
        let low = hex_value(pair[1]).map_err(|_| LndError::Json("payment hex field is invalid"))?;
        *output = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, LndError> {
    validate_hash(value)?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0])?;
            let low = hex_value(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, LndError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(LndError::InvalidConfiguration("hex value is invalid")),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn append_lower_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.reserve(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize]);
        output.push(HEX[(byte & 0x0f) as usize]);
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/provider/lnd-rest-v1.json"
        ))
        .expect("LND fixture")
    }

    fn case(name: &str) -> Value {
        fixture()["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|case| case["name"] == name)
            .cloned()
            .expect("named case")
    }

    fn macaroons() -> LndMacaroons {
        LndMacaroons::new(
            LndMacaroon::from_bytes(vec![0, 1, 2, 3]).expect("readonly macaroon"),
            LndMacaroon::from_bytes(vec![4, 5, 6, 7]).expect("invoice macaroon"),
            LndMacaroon::from_bytes(vec![8, 9, 10, 11]).expect("router macaroon"),
        )
        .expect("distinct macaroons")
    }

    #[test]
    fn fixture_requests_use_exact_paths_and_scoped_auth() {
        let endpoint = LndEndpoint::new("127.0.0.1", 8080).expect("endpoint");
        for (name, scope, expected_macaroon) in [
            ("node_info", MacaroonScope::Readonly, "00010203"),
            ("channel_capacity", MacaroonScope::Readonly, "00010203"),
            ("hold_invoice", MacaroonScope::Invoice, "04050607"),
            ("lookup_invoice", MacaroonScope::Invoice, "04050607"),
            ("settle_invoice", MacaroonScope::Invoice, "04050607"),
            ("cancel_invoice", MacaroonScope::Invoice, "04050607"),
            ("send_payment", MacaroonScope::Router, "08090a0b"),
            ("track_payment", MacaroonScope::Router, "08090a0b"),
            ("block_epoch", MacaroonScope::Readonly, "00010203"),
        ] {
            let case = case(name);
            let method = case["method"].as_str().expect("method");
            let path = case["path"].as_str().expect("path");
            let body = if case["request"].is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&case["request"]).expect("request")
            };
            let request = encode_request(&endpoint, scope, &macaroons(), method, path, &body)
                .expect("encoded request");
            let request = String::from_utf8(request.as_ref().to_vec()).expect("ASCII request");
            assert!(request.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
            assert!(request.contains(&format!("Grpc-Metadata-Macaroon: {expected_macaroon}\r\n")));
            assert!(!format!("{:?}", macaroons()).contains("00010203"));
        }
    }

    #[test]
    fn macaroon_scopes_reject_reused_credentials() {
        let readonly = LndMacaroon::from_bytes(vec![0, 1, 2, 3]).expect("readonly macaroon");
        let invoice = LndMacaroon::from_bytes(vec![0, 1, 2, 3]).expect("invoice macaroon");
        let router = LndMacaroon::from_bytes(vec![8, 9, 10, 11]).expect("router macaroon");
        assert!(LndMacaroons::new(readonly, invoice, router).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn macaroon_scopes_reject_reused_file_identity() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let path = std::env::temp_dir().join(format!(
            "immortal-lnd-macaroon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create credential");
        std::io::Write::write_all(&mut file, &[1, 2, 3, 4]).expect("write credential");
        drop(file);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set credential mode");
        let readonly = LndMacaroon::load(&path).expect("load readonly credential");
        fs::write(&path, [5, 6, 7, 8]).expect("replace credential contents");
        let invoice = LndMacaroon::load(&path).expect("load invoice credential");
        fs::remove_file(&path).expect("remove credential");
        let router = LndMacaroon::from_bytes(vec![9, 10, 11, 12]).expect("router credential");
        assert!(LndMacaroons::new(readonly, invoice, router).is_err());
    }

    #[test]
    fn fixture_responses_bind_node_invoice_payment_and_block_epoch() {
        let node = parse_node_info(&case("node_info")["response"]).expect("node info");
        assert_eq!(node.block_height, 144);
        assert_eq!(node.network, "regtest");
        assert_eq!(
            parse_channel_capacity(&case("channel_capacity")["response"])
                .expect("capacity")
                .as_millisatoshis(),
            19_400_000
        );
        let invoice = parse_invoice(
            &case("hold_invoice")["response"],
            Millisatoshi::from_millisatoshis(1_000_000),
            Some("96c772a829fb7c780410f1d85cf12a89e8b3c78c0bac5fb47f62758bf961ec30"),
            Some(604_800),
        )
        .expect("invoice");
        assert_eq!(
            invoice.payment_hash,
            "96c772a829fb7c780410f1d85cf12a89e8b3c78c0bac5fb47f62758bf961ec30"
        );
        let payment =
            parse_payment_stream(&case("send_payment")["response_stream"][0]).expect("payment");
        let payment_invoice = immortal_core::mkt_swp_verify::parse_bolt11(
            case("send_payment")["request"]["payment_request"]
                .as_str()
                .expect("payment request"),
        )
        .expect("payment request invoice");
        assert_eq!(
            payment.payment_hash,
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        );
        assert_eq!(
            payment.payment_hash,
            lower_hex(&payment_invoice.payment_hash)
        );
        assert_eq!(
            payment_invoice.amount_msat,
            Some(payment.amount.as_millisatoshis())
        );
        assert_eq!(payment.amount_sent.as_millisatoshis(), 1_009_000);
        assert_eq!(payment.settled_at, Some(1_674_164_541));
        let epoch = parse_block_epoch_stream(&case("block_epoch")["response_stream"][0])
            .expect("block epoch");
        assert_eq!(epoch.height, 144);
        assert_eq!(epoch.block_hash, "11".repeat(32));

        let lookup = &case("lookup_invoice")["response"];
        validate_invoice_lookup(
            lookup,
            "96c772a829fb7c780410f1d85cf12a89e8b3c78c0bac5fb47f62758bf961ec30",
        )
        .expect("lookup hash");
        assert_eq!(
            normalized_invoice_state(lookup["state"].as_str().expect("state")),
            Some("accepted")
        );
        assert_eq!(
            parse_u64_member(
                lookup["htlcs"][0].as_object().expect("HTLC"),
                "expiry_height",
                "expiry",
            )
            .expect("expiry"),
            224
        );
    }

    #[test]
    fn fixture_rejects_non_boolean_pending_htlc_direction() {
        assert!(matches!(
            parse_channel_capacity(&case("channel_capacity_invalid_pending_direction")["response"]),
            Err(LndError::Json("pending HTLC direction is invalid"))
        ));
    }

    #[test]
    fn fixture_secret_buffers_and_payment_json_are_overwritten() {
        let expected_body = serde_json::to_vec(&case("settle_invoice")["request"])
            .expect("fixture settlement request");
        let preimage = std::array::from_fn(|index| u8::try_from(index).expect("byte index"));
        let mut body = settlement_request_body(&preimage);
        assert_eq!(body.as_ref(), expected_body);
        body.wipe();
        assert!(body.iter().all(|byte| *byte == 0));

        let encoded = serde_json::to_vec(&case("send_payment")["response_stream"][0])
            .expect("fixture payment response");
        let mut payment = SecretJson::decode(&encoded).expect("secret payment JSON");
        assert!(parse_payment_stream(payment.as_value()).is_ok());
        payment.wipe();
        let preimage = payment.as_value()["result"]["payment_preimage"]
            .as_str()
            .expect("wiped preimage string");
        assert!(!preimage.is_empty());
        assert!(preimage.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn response_parser_accepts_content_length_and_chunked_streams() {
        let unary = serde_json::to_vec(&case("node_info")["response"]).expect("response");
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", unary.len()).into_bytes();
        response.extend_from_slice(&unary);
        let mut stream = response.as_slice();
        let parsed = read_http_response(&mut stream, LndLimits::default())
            .await
            .expect("content length");
        assert_eq!(
            decode_json_or_stream(&parsed.body, 64).expect("JSON"),
            case("node_info")["response"]
        );

        let line = serde_json::to_vec(&case("block_epoch")["response_stream"][0])
            .expect("stream response");
        let mut payload = line;
        payload.push(b'\n');
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        response.extend_from_slice(&payload);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut stream = response.as_slice();
        let parsed = read_http_response(&mut stream, LndLimits::default())
            .await
            .expect("chunked");
        assert_eq!(
            decode_json_or_stream(&parsed.body, 64).expect("stream JSON"),
            case("block_epoch")["response_stream"][0]
        );
    }

    #[tokio::test]
    async fn stream_parser_returns_first_chunk_without_waiting_for_close() {
        let line = serde_json::to_vec(&case("block_epoch")["response_stream"][0])
            .expect("stream response");
        let mut payload = line;
        payload.push(b'\n');
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        response.extend_from_slice(&payload);
        response.extend_from_slice(b"\r\n");
        let (mut server, mut client) = tokio::io::duplex(response.len() + 16);
        server.write_all(&response).await.expect("server write");

        let parsed = timeout(
            Duration::from_millis(100),
            read_http_stream_first(&mut client, LndLimits::default()),
        )
        .await
        .expect("parser must not wait for stream close")
        .expect("first stream response");
        assert_eq!(
            serde_json::from_slice::<Value>(&parsed.body).expect("stream JSON"),
            case("block_epoch")["response_stream"][0]
        );
        drop(server);
    }

    #[test]
    fn response_parser_rejects_wrong_hashes_and_secret_debug_output() {
        let mut lookup = case("lookup_invoice")["response"].clone();
        lookup["r_hash"] = Value::String(encode_base64(&[0; 32]));
        assert!(
            validate_invoice_lookup(
                &lookup,
                "96c772a829fb7c780410f1d85cf12a89e8b3c78c0bac5fb47f62758bf961ec30"
            )
            .is_err()
        );
        let mut payment = case("send_payment")["response_stream"][0].clone();
        payment["result"]["payment_preimage"] = Value::String("00".repeat(32));
        assert!(parse_payment_stream(&payment).is_err());
        let payment = parse_payment_stream(&case("send_payment")["response_stream"][0])
            .expect("valid payment");
        assert!(
            !format!("{payment:?}")
                .contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
        let client_debug = format!("{:?}", macaroons());
        assert!(!client_debug.contains("00010203"));
    }
}
