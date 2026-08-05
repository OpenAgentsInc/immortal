use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use immortal_core::mkt_swp_verify::{Bolt11Invoice, parse_bolt11};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

pub(crate) const DEFAULT_MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RPC_ID_BYTES: usize = 128;
const REQUIRED_METHODS: [&str; 10] = [
    "holdinvoice",
    "listholdinvoices",
    "settleholdinvoice",
    "cancelholdinvoice",
    "invoice",
    "pay",
    "listinvoices",
    "listpays",
    "listfunds",
    "getinfo",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClnError {
    InvalidConfiguration(&'static str),
    ConnectionFailed,
    TimedOut(&'static str),
    Io(&'static str),
    Protocol(&'static str),
    Json(&'static str),
    WrongResponseId,
    Rpc { code: i64 },
    MissingCapability(&'static str),
    Unsynced(&'static str),
    AmountOverflow,
    InexactSatoshiAmount,
}

impl fmt::Display for ClnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(formatter, "invalid CLN configuration: {detail}")
            }
            Self::ConnectionFailed => formatter.write_str("CLN Unix-socket connection failed"),
            Self::TimedOut(operation) => write!(formatter, "CLN {operation} timed out"),
            Self::Io(operation) => write!(formatter, "CLN {operation} failed"),
            Self::Protocol(detail) => write!(formatter, "invalid CLN response: {detail}"),
            Self::Json(detail) => write!(formatter, "invalid CLN JSON-RPC response: {detail}"),
            Self::WrongResponseId => formatter.write_str("CLN response ID did not match"),
            Self::Rpc { code } => write!(formatter, "CLN JSON-RPC failed with code {code}"),
            Self::MissingCapability(method) => {
                write!(formatter, "CLN is missing required method {method}")
            }
            Self::Unsynced(component) => write!(formatter, "CLN reports {component} is unsynced"),
            Self::AmountOverflow => formatter.write_str("CLN amount exceeds the msat range"),
            Self::InexactSatoshiAmount => {
                formatter.write_str("CLN msat amount is not an exact satoshi amount")
            }
        }
    }
}

impl std::error::Error for ClnError {}

#[derive(Clone, PartialEq, Eq)]
pub struct ClnEndpoint {
    socket_path: PathBuf,
}

impl fmt::Debug for ClnEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClnEndpoint([REDACTED])")
    }
}

impl ClnEndpoint {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ClnError> {
        let socket_path = path.into();
        let encoded = socket_path.as_os_str().as_encoded_bytes();
        if !socket_path.is_absolute()
            || encoded.is_empty()
            || encoded.len() > 4096
            || encoded.contains(&0)
        {
            return Err(ClnError::InvalidConfiguration(
                "Unix-socket path must be a bounded absolute path",
            ));
        }
        Ok(Self { socket_path })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClnLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for ClnLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(10),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

impl ClnLimits {
    fn validate(self) -> Result<Self, ClnError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || !(1024..=8 * 1024 * 1024).contains(&self.max_request_bytes)
            || !(1024..=32 * 1024 * 1024).contains(&self.max_response_bytes)
        {
            return Err(ClnError::InvalidConfiguration(
                "RPC timeouts or byte limits are outside supported bounds",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClnRequestId(String);

impl ClnRequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ClnError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RPC_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(ClnError::InvalidConfiguration("RPC request ID is invalid"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Millisatoshi(u64);

impl Millisatoshi {
    pub const fn from_millisatoshis(value: u64) -> Self {
        Self(value)
    }

    pub fn from_satoshis(value: u64) -> Result<Self, ClnError> {
        value
            .checked_mul(1_000)
            .map(Self)
            .ok_or(ClnError::AmountOverflow)
    }

    pub const fn as_millisatoshis(self) -> u64 {
        self.0
    }

    pub fn to_satoshis_exact(self) -> Result<u64, ClnError> {
        if self.0 % 1_000 == 0 {
            Ok(self.0 / 1_000)
        } else {
            Err(ClnError::InexactSatoshiAmount)
        }
    }

    pub fn wire_value(self) -> Value {
        Value::String(format!("{}msat", self.0))
    }

    pub fn parse(value: &Value) -> Result<Self, ClnError> {
        let amount = match value {
            Value::Number(number) => number.as_u64(),
            Value::String(amount) => amount
                .strip_suffix("msat")
                .and_then(|digits| parse_canonical_u64(digits).ok()),
            Value::Object(object) => object.get("msat").and_then(Value::as_u64),
            _ => None,
        }
        .ok_or(ClnError::Json("millisatoshi amount has invalid shape"))?;
        Ok(Self(amount))
    }
}

#[derive(Debug, Clone)]
pub struct ClnClient {
    endpoint: ClnEndpoint,
    limits: ClnLimits,
}

impl ClnClient {
    pub fn new(endpoint: ClnEndpoint, limits: ClnLimits) -> Result<Self, ClnError> {
        Ok(Self {
            endpoint,
            limits: limits.validate()?,
        })
    }

    pub async fn call(
        &self,
        request_id: &ClnRequestId,
        method: &'static str,
        params: Value,
    ) -> Result<Value, ClnError> {
        validate_method(method)?;
        if !params.is_object() && !params.is_array() {
            return Err(ClnError::InvalidConfiguration(
                "RPC params must be an object or array",
            ));
        }
        let mut request = serde_json::to_vec(&json!({
            "jsonrpc":"2.0",
            "id":request_id.as_str(),
            "method":method,
            "params":params,
        }))
        .map_err(|_| ClnError::InvalidConfiguration("RPC request is not serializable"))?;
        request.push(b'\n');
        if request.len() > self.limits.max_request_bytes {
            return Err(ClnError::InvalidConfiguration(
                "RPC request exceeds the configured byte limit",
            ));
        }

        let mut stream = timeout(
            self.limits.connect_timeout,
            UnixStream::connect(self.endpoint.socket_path()),
        )
        .await
        .map_err(|_| ClnError::TimedOut("connection"))?
        .map_err(|_| ClnError::ConnectionFailed)?;
        timeout(self.limits.io_timeout, async {
            stream.write_all(&request).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| ClnError::TimedOut("request write"))?
        .map_err(|_| ClnError::Io("request write"))?;
        let response = timeout(
            self.limits.io_timeout,
            read_newline_response(&mut stream, self.limits.max_response_bytes),
        )
        .await
        .map_err(|_| ClnError::TimedOut("response read"))??;
        decode_response(&response, request_id)
    }

    pub async fn probe_required_capabilities(
        &self,
        request_id_prefix: &str,
    ) -> Result<ClnCapabilities, ClnError> {
        validate_identifier(request_id_prefix, "capability request prefix is invalid")?;
        for (index, method) in REQUIRED_METHODS.into_iter().enumerate() {
            let request_id = ClnRequestId::new(format!("{request_id_prefix}:probe:{index}"))?;
            match self
                .call(&request_id, "help", json!({"command":method}))
                .await
            {
                Ok(result) if help_result_names_method(&result, method) => {}
                Ok(_) | Err(ClnError::Rpc { .. }) => {
                    return Err(ClnError::MissingCapability(method));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(ClnCapabilities { hold_plugin: true })
    }

    pub async fn node_info(&self, request_id: &ClnRequestId) -> Result<ClnNodeInfo, ClnError> {
        let result = self.call(request_id, "getinfo", json!({})).await?;
        let object = result
            .as_object()
            .ok_or(ClnError::Json("getinfo result is not an object"))?;
        if object.contains_key("warning_bitcoind_sync") {
            return Err(ClnError::Unsynced("bitcoind"));
        }
        if object.contains_key("warning_lightningd_sync") {
            return Err(ClnError::Unsynced("lightningd"));
        }
        let height = object
            .get("blockheight")
            .and_then(Value::as_u64)
            .ok_or(ClnError::Json("getinfo result has no blockheight"))?;
        let block_height =
            u32::try_from(height).map_err(|_| ClnError::Json("CLN blockheight exceeds v1"))?;
        let network = object
            .get("network")
            .and_then(Value::as_str)
            .filter(|network| {
                !network.is_empty()
                    && network.len() <= 16
                    && network.bytes().all(|byte| byte.is_ascii_lowercase())
            })
            .ok_or(ClnError::Json("getinfo result has no valid network"))?;
        Ok(ClnNodeInfo {
            block_height,
            network: network.to_owned(),
        })
    }

    pub async fn invoice(
        &self,
        request_id: &ClnRequestId,
        amount: Millisatoshi,
        label: &str,
        description: &str,
        expiry_seconds: u32,
    ) -> Result<InvoiceResult, ClnError> {
        validate_label(label)?;
        if description.is_empty()
            || description.len() > 1024
            || description.chars().any(char::is_control)
        {
            return Err(ClnError::InvalidConfiguration(
                "invoice description is invalid",
            ));
        }
        if expiry_seconds == 0 || expiry_seconds > 604_800 {
            return Err(ClnError::InvalidConfiguration(
                "invoice expiry is outside supported bounds",
            ));
        }
        let result = self
            .call(
                request_id,
                "invoice",
                json!({
                    "amount_msat":amount.wire_value(),
                    "label":label,
                    "description":description,
                    "expiry":expiry_seconds,
                }),
            )
            .await?;
        InvoiceResult::parse_standard(&result, amount, expiry_seconds)
    }

    pub async fn pay(
        &self,
        request_id: &ClnRequestId,
        bolt11: &str,
        max_fee: Option<Millisatoshi>,
    ) -> Result<PaymentResult, ClnError> {
        self.pay_response(request_id, bolt11, max_fee)
            .await
            .map(|(payment, _)| payment)
    }

    pub async fn pay_with_released_preimage(
        &self,
        request_id: &ClnRequestId,
        bolt11: &str,
        max_fee: Option<Millisatoshi>,
    ) -> Result<(PaymentResult, ReleasedPaymentPreimage), ClnError> {
        let (payment, response) = self.pay_response(request_id, bolt11, max_fee).await?;
        if payment.status != "complete" {
            return Err(ClnError::Json(
                "payment has not completed and released no preimage",
            ));
        }
        let preimage = ReleasedPaymentPreimage::parse(&response, &payment.payment_hash)?;
        Ok((payment, preimage))
    }

    async fn pay_response(
        &self,
        request_id: &ClnRequestId,
        bolt11: &str,
        max_fee: Option<Millisatoshi>,
    ) -> Result<(PaymentResult, Value), ClnError> {
        let invoice = validated_bolt11(bolt11)?;
        let invoice_amount = invoice
            .amount_msat
            .map(Millisatoshi::from_millisatoshis)
            .ok_or(ClnError::InvalidConfiguration(
                "amountless invoices require an explicit amount",
            ))?;
        let mut params = Map::new();
        params.insert("bolt11".to_owned(), Value::String(bolt11.to_owned()));
        if let Some(max_fee) = max_fee {
            params.insert("maxfee".to_owned(), max_fee.wire_value());
        }
        let result = self.call(request_id, "pay", Value::Object(params)).await?;
        let payment = PaymentResult::parse(&result)?;
        if payment.payment_hash != lower_hex(&invoice.payment_hash)
            || payment.amount != invoice_amount
        {
            return Err(ClnError::Json(
                "payment result does not bind the requested invoice",
            ));
        }
        Ok((payment, result))
    }

    pub async fn list_invoices(
        &self,
        request_id: &ClnRequestId,
        label: Option<&str>,
    ) -> Result<Value, ClnError> {
        let params = match label {
            Some(label) => {
                validate_label(label)?;
                json!({"label":label})
            }
            None => json!({}),
        };
        self.call(request_id, "listinvoices", params).await
    }

    pub async fn list_pays(
        &self,
        request_id: &ClnRequestId,
        bolt11: Option<&str>,
    ) -> Result<Value, ClnError> {
        let params = match bolt11 {
            Some(bolt11) => {
                validate_bolt11(bolt11)?;
                json!({"bolt11":bolt11})
            }
            None => json!({}),
        };
        self.call(request_id, "listpays", params).await
    }

    pub async fn hold_invoice(
        &self,
        request_id: &ClnRequestId,
        payment_hash: &str,
        amount: Millisatoshi,
    ) -> Result<InvoiceResult, ClnError> {
        validate_hash(payment_hash)?;
        let result = self
            .call(
                request_id,
                "holdinvoice",
                json!({
                    "payment_hash":payment_hash,
                    "amount":amount.as_millisatoshis(),
                }),
            )
            .await?;
        InvoiceResult::parse_hold(&result, amount, payment_hash)
    }

    pub async fn list_hold_invoices(
        &self,
        request_id: &ClnRequestId,
        payment_hash: Option<&str>,
    ) -> Result<Value, ClnError> {
        let params = match payment_hash {
            Some(payment_hash) => {
                validate_hash(payment_hash)?;
                json!({"payment_hash":payment_hash})
            }
            None => json!({}),
        };
        self.call(request_id, "listholdinvoices", params).await
    }

    pub async fn settle_hold_invoice(
        &self,
        request_id: &ClnRequestId,
        payment_preimage: &str,
    ) -> Result<Value, ClnError> {
        validate_hash(payment_preimage)?;
        self.call(
            request_id,
            "settleholdinvoice",
            json!({"preimage":payment_preimage}),
        )
        .await
    }

    pub async fn cancel_hold_invoice(
        &self,
        request_id: &ClnRequestId,
        payment_hash: &str,
    ) -> Result<Value, ClnError> {
        validate_hash(payment_hash)?;
        self.call(
            request_id,
            "cancelholdinvoice",
            json!({"payment_hash":payment_hash}),
        )
        .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClnCapabilities {
    pub hold_plugin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClnNodeInfo {
    pub block_height: u32,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceResult {
    pub bolt11: String,
    pub payment_hash: String,
    pub expires_at: u64,
}

impl InvoiceResult {
    fn parse_standard(
        value: &Value,
        expected_amount: Millisatoshi,
        expected_expiry_seconds: u32,
    ) -> Result<Self, ClnError> {
        let object = value
            .as_object()
            .ok_or(ClnError::Json("invoice result is not an object"))?;
        let bolt11 = object
            .get("bolt11")
            .and_then(Value::as_str)
            .ok_or(ClnError::Json("invoice result has no bolt11"))?;
        let response_payment_hash = object
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or(ClnError::Json("invoice result has no payment hash"))?;
        validate_hash(response_payment_hash)?;
        let response_expires_at = object
            .get("expires_at")
            .and_then(Value::as_u64)
            .ok_or(ClnError::Json("invoice result has no expiry"))?;
        Self::from_invoice(
            bolt11,
            expected_amount,
            Some(expected_expiry_seconds),
            Some(response_payment_hash),
            Some(response_expires_at),
        )
    }

    fn parse_hold(
        value: &Value,
        expected_amount: Millisatoshi,
        expected_payment_hash: &str,
    ) -> Result<Self, ClnError> {
        let bolt11 = value
            .as_object()
            .and_then(|object| object.get("bolt11"))
            .and_then(Value::as_str)
            .ok_or(ClnError::Json("hold-invoice result has no bolt11"))?;
        Self::from_invoice(
            bolt11,
            expected_amount,
            None,
            Some(expected_payment_hash),
            None,
        )
    }

    fn from_invoice(
        bolt11: &str,
        expected_amount: Millisatoshi,
        expected_expiry_seconds: Option<u32>,
        expected_payment_hash: Option<&str>,
        response_expires_at: Option<u64>,
    ) -> Result<Self, ClnError> {
        let invoice = validated_bolt11(bolt11)?;
        let payment_hash = lower_hex(&invoice.payment_hash);
        let invoice_expiry = invoice
            .timestamp
            .checked_add(invoice.expiry_seconds)
            .ok_or(ClnError::Json("invoice expiry overflows"))?;
        if invoice.amount_msat != Some(expected_amount.as_millisatoshis())
            || expected_expiry_seconds
                .is_some_and(|expected| invoice.expiry_seconds != u64::from(expected))
            || expected_payment_hash.is_some_and(|expected| expected != payment_hash)
            || response_expires_at.is_some_and(|expires_at| invoice_expiry != expires_at)
        {
            return Err(ClnError::Json(
                "invoice result does not bind the requested amount, hash, or expiry",
            ));
        }
        Ok(Self {
            bolt11: bolt11.to_owned(),
            payment_hash,
            expires_at: invoice_expiry,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentResult {
    pub payment_hash: String,
    pub status: String,
    pub amount: Millisatoshi,
    pub amount_sent: Millisatoshi,
}

pub struct ReleasedPaymentPreimage([u8; 32]);

impl fmt::Debug for ReleasedPaymentPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReleasedPaymentPreimage([REDACTED])")
    }
}

impl Drop for ReleasedPaymentPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl ReleasedPaymentPreimage {
    fn parse(response: &Value, expected_payment_hash: &str) -> Result<Self, ClnError> {
        let encoded = response
            .get("payment_preimage")
            .and_then(Value::as_str)
            .ok_or(ClnError::Json(
                "completed payment result has no released preimage",
            ))?;
        let bytes = decode_lower_hex_32(encoded)
            .map_err(|_| ClnError::Json("released payment preimage is invalid"))?;
        if lower_hex(&Sha256::digest(bytes)) != expected_payment_hash {
            return Err(ClnError::Json(
                "released payment preimage does not match its payment hash",
            ));
        }
        Ok(Self(bytes))
    }

    pub(crate) fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        self.0.fill(0);
        bytes
    }
}

impl PaymentResult {
    fn parse(value: &Value) -> Result<Self, ClnError> {
        let object = value
            .as_object()
            .ok_or(ClnError::Json("payment result is not an object"))?;
        let payment_hash = object
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or(ClnError::Json("payment result has no payment hash"))?;
        validate_hash(payment_hash)?;
        let status = object
            .get("status")
            .and_then(Value::as_str)
            .filter(|status| matches!(*status, "complete" | "pending" | "failed"))
            .ok_or(ClnError::Json("payment result has invalid status"))?;
        let amount = Millisatoshi::parse(
            object
                .get("amount_msat")
                .ok_or(ClnError::Json("payment result has no amount"))?,
        )?;
        let amount_sent = Millisatoshi::parse(
            object
                .get("amount_sent_msat")
                .ok_or(ClnError::Json("payment result has no sent amount"))?,
        )?;
        if amount_sent < amount {
            return Err(ClnError::Json(
                "payment sent amount is less than delivered amount",
            ));
        }
        Ok(Self {
            payment_hash: payment_hash.to_owned(),
            status: status.to_owned(),
            amount,
            amount_sent,
        })
    }
}

async fn read_newline_response(
    stream: &mut UnixStream,
    max_response_bytes: usize,
) -> Result<Vec<u8>, ClnError> {
    let mut response = Vec::new();
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| ClnError::Io("response read"))?;
        if read == 0 {
            return Err(ClnError::Protocol("truncated response without newline"));
        }
        let chunk = &chunk[..read];
        if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
            if response.len().saturating_add(newline) > max_response_bytes {
                return Err(ClnError::Protocol("response exceeds byte limit"));
            }
            response.extend_from_slice(&chunk[..newline]);
            if chunk[newline + 1..]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace())
            {
                return Err(ClnError::Protocol(
                    "multiple responses arrived on one connection",
                ));
            }
            return Ok(response);
        }
        if response.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(ClnError::Protocol("response exceeds byte limit"));
        }
        response.extend_from_slice(chunk);
    }
}

fn decode_response(body: &[u8], request_id: &ClnRequestId) -> Result<Value, ClnError> {
    let response: Value =
        serde_json::from_slice(body).map_err(|_| ClnError::Json("body is not JSON"))?;
    let object = response
        .as_object()
        .ok_or(ClnError::Json("response is not an object"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ClnError::Json("response has unsupported JSON-RPC version"));
    }
    if object.get("id").and_then(Value::as_str) != Some(request_id.as_str()) {
        return Err(ClnError::WrongResponseId);
    }
    if let Some(error) = object.get("error") {
        let code = error
            .as_object()
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64)
            .ok_or(ClnError::Json("RPC error has no numeric code"))?;
        return Err(ClnError::Rpc { code });
    }
    object
        .get("result")
        .cloned()
        .ok_or(ClnError::Json("response has no result member"))
}

fn validate_method(method: &str) -> Result<(), ClnError> {
    if method.is_empty()
        || method.len() > 64
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Err(ClnError::InvalidConfiguration("RPC method is invalid"))
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, detail: &'static str) -> Result<(), ClnError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Err(ClnError::InvalidConfiguration(detail))
    } else {
        Ok(())
    }
}

fn validate_label(label: &str) -> Result<(), ClnError> {
    validate_identifier(label, "invoice label is invalid")
}

fn validate_bolt11(bolt11: &str) -> Result<(), ClnError> {
    validated_bolt11(bolt11).map(|_| ())
}

fn validated_bolt11(bolt11: &str) -> Result<Bolt11Invoice, ClnError> {
    parse_bolt11(bolt11).map_err(|_| ClnError::InvalidConfiguration("bolt11 invoice is invalid"))
}

fn validate_hash(value: &str) -> Result<(), ClnError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ClnError::InvalidConfiguration(
            "hash is not 64-character lowercase hexadecimal",
        ))
    }
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], ()> {
    validate_hash(value).map_err(|_| ())?;
    let mut decoded = [0_u8; 32];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = lower_hex_digit(*pair.first().ok_or(())?).ok_or(())?;
        let low = lower_hex_digit(*pair.get(1).ok_or(())?).ok_or(())?;
        *output = (high << 4) | low;
    }
    Ok(decoded)
}

fn lower_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn parse_canonical_u64(value: &str) -> Result<u64, ClnError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(ClnError::Json("amount is not canonical decimal"));
    }
    value
        .parse::<u64>()
        .map_err(|_| ClnError::Json("amount exceeds u64"))
}

fn help_result_names_method(result: &Value, method: &str) -> bool {
    if result
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command == method || command.starts_with(&format!("{method} ")))
    {
        return true;
    }
    result
        .get("help")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| {
                        command == method || command.starts_with(&format!("{method} "))
                    })
            })
        })
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod released_preimage_tests {
    use super::*;

    #[test]
    fn released_preimage_is_hash_bound_and_redacted() -> Result<(), ClnError> {
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).map_err(|_| ClnError::AmountOverflow)?;
        }
        let encoded = lower_hex(&bytes);
        let payment_hash = lower_hex(&Sha256::digest(bytes));
        let released =
            ReleasedPaymentPreimage::parse(&json!({"payment_preimage":encoded}), &payment_hash)?;
        assert!(!format!("{released:?}").contains(&encoded));
        assert_eq!(released.into_bytes(), bytes);
        assert_eq!(
            ReleasedPaymentPreimage::parse(&json!({"payment_preimage":encoded}), &"11".repeat(32))
                .err(),
            Some(ClnError::Json(
                "released payment preimage does not match its payment hash"
            ))
        );
        Ok(())
    }
}
