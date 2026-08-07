//! Versioned, bounded JSON API for browser and other foreign-language hosts.
//!
//! The ABI never owns a signer, transport, wallet, chain client, preimage, or
//! node credential. Hosts pass verified public data and signed records in and
//! receive deterministic signing or external-effect requests back.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

use crate::{
    domain::{Event, MKT_OFFERING_KIND, validate_mkt_public_event},
    mkt_swp_client::{
        AwaitingVerification, Cancellation, CloseOutcome, ExitPackage, FundingAuthorizationRequest,
        LocalLightningReadiness, MktSigningRequest, ParticipantRole, RequesterContractLocalInputs,
        RequesterContractSigningInput, RequesterOrderInput, RequesterSessionView,
        SignedRecordDelivery, SwapClientConfig, SwapClientError, SwapRecordFactory, SwapSession,
        VerifyBeforeFundInput,
    },
};

pub const ABI_VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const REQUESTER_API_SHA256: &str =
    "bf52fda5f4d349fbbe195e4cff58af59a3930e1ee8ab1f1413b6338ba44fb3a8";
pub const ABI_SCHEMA: &str = "openagents.immortal.mkt-swp.browser-abi.v1";
pub const SOURCE_REVISION: &str = match option_env!("IMMORTAL_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unversioned",
};

pub const OPERATIONS: [&str; 16] = [
    "metadata",
    "validate_offering",
    "validate_delivery",
    "verify_signed",
    "requester_rfq",
    "requester_order",
    "requester_contract_draft",
    "requester_contract",
    "requester_cancel",
    "requester_close",
    "exit_package_inspect",
    "session_create",
    "session_ingest",
    "session_restore",
    "prepare_funding_request",
    "verify_before_fund",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    abi_version: u32,
    operation: String,
    input: Value,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: &'static str,
    abi_version: u32,
    source_revision: &'static str,
    requester_api_sha256: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ApiError>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ApiError {
    code: String,
    detail: String,
}

impl ApiError {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

impl From<SwapClientError> for ApiError {
    fn from(error: SwapClientError) -> Self {
        Self::new(error.code, error.detail)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventInput {
    event: Event,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifySignedInput {
    request: MktSigningRequest,
    event: Event,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryInput {
    raw_signed_event_hex: String,
    observed_at: u64,
    provenance: DirectProvenance,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DirectProvenance {
    LocallySigned,
    Direct,
}

impl DeliveryInput {
    fn parse(self) -> Result<SignedRecordDelivery, ApiError> {
        let bytes = decode_hex(&self.raw_signed_event_hex, "raw signed event")?;
        match self.provenance {
            DirectProvenance::LocallySigned => {
                SignedRecordDelivery::from_locally_signed(bytes, self.observed_at)
            }
            DirectProvenance::Direct => SignedRecordDelivery::from_direct(bytes, self.observed_at),
        }
        .map_err(ApiError::from)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RfqInput {
    config: SwapClientConfig,
    created_at: u64,
    distinct: String,
    expiration: u64,
    mkt_swp: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderInput {
    config: SwapClientConfig,
    rfq: Event,
    quote: Event,
    created_at: u64,
    observed_at: u64,
    distinct: String,
    #[serde(default)]
    selection: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractDraftInput {
    config: SwapClientConfig,
    rfq: Event,
    quote: Event,
    order: Event,
    order_observed_at: u64,
    local_inputs: RequesterContractLocalInputs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractInput {
    config: SwapClientConfig,
    rfq: Event,
    quote: Event,
    order: Event,
    order_observed_at: u64,
    created_at: u64,
    distinct: String,
    contract: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancellationInput {
    action: String,
    reason: String,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    accepted_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelInput {
    config: SwapClientConfig,
    created_at: u64,
    distinct: String,
    order_id: String,
    cancellation: CancellationInput,
    mkt_swp: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseInput {
    config: SwapClientConfig,
    created_at: u64,
    distinct: String,
    order_id: String,
    outcome: String,
    terminal_at: u64,
    mkt_swp: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitPackageInput {
    document: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCreateInput {
    config: SwapClientConfig,
    records: Vec<Event>,
    #[serde(default)]
    exit_packages: Vec<Value>,
    deliveries: Vec<DeliveryInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionIngestInput {
    snapshot_json_hex: String,
    records: Vec<Event>,
    deliveries: Vec<DeliveryInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRestoreInput {
    snapshot_json_hex: String,
    deliveries: Vec<DeliveryInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareFundingApiInput {
    snapshot_json_hex: String,
    verification: VerifyBeforeFundInput,
    #[serde(default)]
    lightning_readiness: Option<LocalLightningReadiness>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyBeforeFundApiInput {
    snapshot_json_hex: String,
    verification: VerifyBeforeFundInput,
    #[serde(default)]
    lightning_readiness: Option<LocalLightningReadiness>,
    expected_funding_request: FundingAuthorizationRequest,
}

/// Dispatch one complete ABI request. This is the same function used by the
/// native acceptance tests and the ordinary WASM wrapper.
pub fn dispatch(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return encode(Err(ApiError::new(
            "browser_request_bound",
            "browser ABI request is empty or exceeds 2097152 bytes",
        )));
    }
    let request = match serde_json::from_slice::<Request>(bytes) {
        Ok(request) => request,
        Err(error) => {
            return encode(Err(ApiError::new(
                "browser_request_invalid",
                format!("browser ABI request is invalid JSON: {error}"),
            )));
        }
    };
    if request.abi_version != ABI_VERSION {
        return encode(Err(ApiError::new(
            "browser_abi_version_mismatch",
            format!(
                "browser ABI version {} is unsupported; expected {ABI_VERSION}",
                request.abi_version
            ),
        )));
    }
    encode(dispatch_operation(&request.operation, request.input))
}

fn dispatch_operation(operation: &str, input: Value) -> Result<Value, ApiError> {
    match operation {
        "metadata" => {
            parse_input::<EmptyInput>(input)?;
            Ok(json!({
                "schema": ABI_SCHEMA,
                "abi_version": ABI_VERSION,
                "source_revision": SOURCE_REVISION,
                "requester_api_sha256": REQUESTER_API_SHA256,
                "maximum_request_bytes": MAX_REQUEST_BYTES,
                "maximum_response_bytes": MAX_RESPONSE_BYTES,
                "operations": OPERATIONS,
                "custody": "host_owned"
            }))
        }
        "validate_offering" => {
            let input: EventInput = parse_input(input)?;
            if input.event.kind != MKT_OFFERING_KIND {
                return Err(ApiError::new(
                    "browser_offering_invalid",
                    "browser Offering validation requires kind 39601",
                ));
            }
            input
                .event
                .validate_structure()
                .and_then(|()| input.event.validate_crypto())
                .map_err(|detail| ApiError::new("browser_offering_invalid", detail.to_string()))?;
            validate_mkt_public_event(&input.event)
                .map_err(|detail| ApiError::new("browser_offering_invalid", detail))?;
            to_value(input.event)
        }
        "validate_delivery" => {
            let delivery: DeliveryInput = parse_input(input)?;
            to_value(delivery.parse()?)
        }
        "verify_signed" => {
            let input: VerifySignedInput = parse_input(input)?;
            to_value(
                input
                    .request
                    .verify_signed(input.event)
                    .map_err(ApiError::from)?,
            )
        }
        "requester_rfq" => {
            let input: RfqInput = parse_input(input)?;
            let request = SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.rfq(
                        input.created_at,
                        &input.distinct,
                        input.expiration,
                        input.mkt_swp,
                    )
                })
                .map_err(ApiError::from)?;
            to_value(request)
        }
        "requester_order" => {
            let input: OrderInput = parse_input(input)?;
            let request = SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.requester_order(RequesterOrderInput {
                        rfq: &input.rfq,
                        quote: &input.quote,
                        created_at: input.created_at,
                        observed_at: input.observed_at,
                        distinct: &input.distinct,
                        selection: input.selection,
                    })
                })
                .map_err(ApiError::from)?;
            to_value(request)
        }
        "requester_contract_draft" => {
            let input: ContractDraftInput = parse_input(input)?;
            SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.requester_contract_draft(
                        &input.rfq,
                        &input.quote,
                        &input.order,
                        input.order_observed_at,
                        input.local_inputs,
                    )
                })
                .map_err(ApiError::from)
        }
        "requester_contract" => {
            let input: ContractInput = parse_input(input)?;
            let request = SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.requester_contract(RequesterContractSigningInput {
                        rfq: &input.rfq,
                        quote: &input.quote,
                        order: &input.order,
                        order_observed_at: input.order_observed_at,
                        created_at: input.created_at,
                        distinct: &input.distinct,
                        contract: input.contract,
                    })
                })
                .map_err(ApiError::from)?;
            to_value(request)
        }
        "requester_cancel" => {
            let input: CancelInput = parse_input(input)?;
            let request = SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.cancel(
                        ParticipantRole::Requester,
                        input.created_at,
                        &input.distinct,
                        &input.order_id,
                        Cancellation {
                            action: &input.cancellation.action,
                            reason: &input.cancellation.reason,
                            request_id: input.cancellation.request_id.as_deref(),
                            accepted_id: input.cancellation.accepted_id.as_deref(),
                        },
                        input.mkt_swp,
                    )
                })
                .map_err(ApiError::from)?;
            to_value(request)
        }
        "requester_close" => {
            let input: CloseInput = parse_input(input)?;
            let request = SwapRecordFactory::new(input.config)
                .and_then(|factory| {
                    factory.close(
                        ParticipantRole::Requester,
                        input.created_at,
                        &input.distinct,
                        &input.order_id,
                        CloseOutcome {
                            outcome: &input.outcome,
                            terminal_at: input.terminal_at,
                        },
                        input.mkt_swp,
                    )
                })
                .map_err(ApiError::from)?;
            to_value(request)
        }
        "exit_package_inspect" => {
            let input: ExitPackageInput = parse_input(input)?;
            let package = ExitPackage::parse(input.document).map_err(ApiError::from)?;
            let unsigned_transaction_hex = package.unsigned_transaction().ok().map(encode_hex);
            let signing_digest = package.signing_digest().ok().map(encode_hex);
            Ok(json!({
                "document": package.document(),
                "commitment_sha256": package.commitment_sha256().map_err(ApiError::from)?,
                "effect_id": package.effect_id().map_err(ApiError::from)?,
                "path": package.path().map_err(ApiError::from)?,
                "mode": package.mode().map_err(ApiError::from)?,
                "unsigned_transaction_hex": unsigned_transaction_hex,
                "signing_digest": signing_digest
            }))
        }
        "session_create" => session_create(parse_input(input)?),
        "session_ingest" => session_ingest(parse_input(input)?),
        "session_restore" => session_restore(parse_input(input)?),
        "prepare_funding_request" => prepare_funding_request(parse_input(input)?),
        "verify_before_fund" => verify_before_fund(parse_input(input)?),
        _ => Err(ApiError::new(
            "browser_operation_unsupported",
            format!("browser ABI operation {operation:?} is unsupported"),
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

fn session_create(input: SessionCreateInput) -> Result<Value, ApiError> {
    let packages = input
        .exit_packages
        .into_iter()
        .map(ExitPackage::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::from)?;
    let session = SwapSession::<AwaitingVerification>::from_signed_records(
        input.config,
        input.records,
        packages,
    )
    .map_err(ApiError::from)?;
    session_result(session.persist().map_err(ApiError::from)?, input.deliveries)
}

fn session_ingest(input: SessionIngestInput) -> Result<Value, ApiError> {
    let snapshot = decode_hex(&input.snapshot_json_hex, "snapshot JSON")?;
    let mut session =
        SwapSession::<AwaitingVerification>::restore(&snapshot).map_err(ApiError::from)?;
    let mut ingested = 0_u64;
    for record in input.records {
        ingested += u64::from(
            session
                .ingest_signed_record(record)
                .map_err(ApiError::from)?,
        );
    }
    let snapshot = session.persist().map_err(ApiError::from)?;
    let mut result = session_result(snapshot, input.deliveries)?;
    result
        .as_object_mut()
        .ok_or_else(|| {
            ApiError::new(
                "browser_response_invalid",
                "session result is not an object",
            )
        })?
        .insert("ingested_records".to_owned(), Value::from(ingested));
    Ok(result)
}

fn session_restore(input: SessionRestoreInput) -> Result<Value, ApiError> {
    let snapshot = decode_hex(&input.snapshot_json_hex, "snapshot JSON")?;
    let session =
        SwapSession::<AwaitingVerification>::restore(&snapshot).map_err(ApiError::from)?;
    session_result(session.persist().map_err(ApiError::from)?, input.deliveries)
}

fn session_result(snapshot: Vec<u8>, deliveries: Vec<DeliveryInput>) -> Result<Value, ApiError> {
    let parsed_deliveries = deliveries
        .into_iter()
        .map(DeliveryInput::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let view = RequesterSessionView::from_restored_snapshot(&snapshot, parsed_deliveries)
        .map_err(ApiError::from)?;
    Ok(json!({
        "snapshot_json_hex": encode_hex(&snapshot),
        "view": view
    }))
}

fn prepare_funding_request(input: PrepareFundingApiInput) -> Result<Value, ApiError> {
    let snapshot = decode_hex(&input.snapshot_json_hex, "snapshot JSON")?;
    let session =
        SwapSession::<AwaitingVerification>::restore(&snapshot).map_err(ApiError::from)?;
    let mut prepared = None;
    let outcome = if let Some(readiness) = input.lightning_readiness {
        session.verify_before_fund_with_lightning(
            input.verification,
            move |_| Ok(readiness.clone()),
            |request| {
                prepared = Some(request.clone());
                Err("browser host authorization is a separate operation".to_owned())
            },
        )
    } else {
        session.verify_before_fund(input.verification, |request| {
            prepared = Some(request.clone());
            Err("browser host authorization is a separate operation".to_owned())
        })
    };
    match (outcome, prepared) {
        (Err(error), Some(request)) if error.code == "swp_funding_not_authorized" => {
            to_value(request)
        }
        (Err(error), _) => Err(ApiError::from(error)),
        (Ok(_), _) => Err(ApiError::new(
            "browser_funding_preparation_invalid",
            "funding preparation unexpectedly crossed the authorization boundary",
        )),
    }
}

fn verify_before_fund(input: VerifyBeforeFundApiInput) -> Result<Value, ApiError> {
    let snapshot = decode_hex(&input.snapshot_json_hex, "snapshot JSON")?;
    let session =
        SwapSession::<AwaitingVerification>::restore(&snapshot).map_err(ApiError::from)?;
    let expected = input.expected_funding_request;
    let authorize = |request: &FundingAuthorizationRequest| {
        if request == &expected {
            Ok(())
        } else {
            Err("host authorization does not match the verified funding request".to_owned())
        }
    };
    let funded = if let Some(readiness) = input.lightning_readiness {
        session.verify_before_fund_with_lightning(
            input.verification,
            move |_| Ok(readiness.clone()),
            authorize,
        )
    } else {
        session.verify_before_fund(input.verification, authorize)
    }
    .map_err(ApiError::from)?;
    let request = funded.funding_request().map_err(ApiError::from)?.clone();
    let persisted = funded.persist().map_err(ApiError::from)?;
    Ok(json!({
        "funding_request": request,
        "snapshot_json_hex": encode_hex(persisted)
    }))
}

fn parse_input<T: DeserializeOwned>(input: Value) -> Result<T, ApiError> {
    serde_json::from_value(input).map_err(|error| {
        ApiError::new(
            "browser_input_invalid",
            format!("browser ABI operation input is invalid: {error}"),
        )
    })
}

fn to_value<T: Serialize>(value: T) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|error| {
        ApiError::new(
            "browser_response_invalid",
            format!("browser ABI response serialization failed: {error}"),
        )
    })
}

fn encode(result: Result<Value, ApiError>) -> Vec<u8> {
    let (result, error) = match result {
        Ok(result) => (Some(result), None),
        Err(error) => (None, Some(error)),
    };
    let response = serde_json::to_vec(&Response {
        schema: ABI_SCHEMA,
        abi_version: ABI_VERSION,
        source_revision: SOURCE_REVISION,
        requester_api_sha256: REQUESTER_API_SHA256,
        result,
        error,
    })
    .unwrap_or_else(|_| {
        br#"{"schema":"openagents.immortal.mkt-swp.browser-abi.v1","abi_version":1,"source_revision":"unavailable","requester_api_sha256":"unavailable","error":{"code":"browser_response_invalid","detail":"browser ABI response serialization failed"}}"#.to_vec()
    });
    if response.len() <= MAX_RESPONSE_BYTES {
        response
    } else {
        br#"{"schema":"openagents.immortal.mkt-swp.browser-abi.v1","abi_version":1,"source_revision":"unavailable","requester_api_sha256":"unavailable","error":{"code":"browser_response_bound","detail":"browser ABI response exceeds 8388608 bytes"}}"#.to_vec()
    }
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, ApiError> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > MAX_REQUEST_BYTES * 2 {
        return Err(ApiError::new(
            "browser_input_invalid",
            format!("{label} hex is empty, odd-length, or exceeds its bound"),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]);
            let low = decode_nibble(pair[1]);
            high.zip(low)
                .map(|(high, low)| high << 4 | low)
                .ok_or_else(|| {
                    ApiError::new("browser_input_invalid", format!("{label} is not lower hex"))
                })
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(operation: &str, input: Value) -> Value {
        serde_json::from_slice(&dispatch(
            &serde_json::to_vec(&json!({
                "abi_version": ABI_VERSION,
                "operation": operation,
                "input": input,
            }))
            .expect("request JSON"),
        ))
        .expect("response JSON")
    }

    fn reverse_fixture() -> (Value, Value, Value, Value, Value) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
        ))
        .expect("full-session fixture");
        let snapshot = fixture
            .pointer("/flows/reverse/snapshot")
            .and_then(Value::as_object)
            .expect("reverse snapshot");
        let records = snapshot
            .get("signed_records")
            .and_then(Value::as_array)
            .expect("reverse records");
        let record = |kind| {
            records
                .iter()
                .find(|record| record.get("kind").and_then(Value::as_u64) == Some(kind))
                .cloned()
                .expect("record kind")
        };
        (
            snapshot.get("config").cloned().expect("reverse config"),
            record(39_604),
            record(39_605),
            record(39_606),
            fixture
                .pointer("/flows/reverse/verification")
                .cloned()
                .expect("reverse verification"),
        )
    }

    fn delivery(record: &Value, requester_pubkey: &str) -> Value {
        json!({
            "raw_signed_event_hex": encode_hex(
                serde_json::to_vec(record).expect("signed record JSON")
            ),
            "observed_at": 500,
            "provenance": if record.get("pubkey").and_then(Value::as_str)
                == Some(requester_pubkey)
            {
                "locally_signed"
            } else {
                "direct"
            },
        })
    }

    #[test]
    fn version_mismatch_is_typed_and_fail_closed() {
        let response: Value = serde_json::from_slice(&dispatch(
            br#"{"abi_version":2,"operation":"metadata","input":{}}"#,
        ))
        .expect("response JSON");
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_str),
            Some("browser_abi_version_mismatch")
        );
        assert!(response.get("result").is_none());
    }

    #[test]
    fn metadata_is_machine_bounded() {
        let response: Value = serde_json::from_slice(&dispatch(
            br#"{"abi_version":1,"operation":"metadata","input":{}}"#,
        ))
        .expect("response JSON");
        assert_eq!(
            response
                .pointer("/result/requester_api_sha256")
                .and_then(Value::as_str),
            Some(REQUESTER_API_SHA256)
        );
        assert_eq!(
            response
                .pointer("/result/operations")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(OPERATIONS.len())
        );
    }

    #[test]
    fn browser_sessions_create_ingest_and_restore_progressive_prefixes() {
        let (config, rfq, quote, order, verification) = reverse_fixture();
        let requester = config
            .get("requester_pubkey")
            .and_then(Value::as_str)
            .expect("requester public key");
        let rfq_delivery = delivery(&rfq, requester);
        let quote_delivery = delivery(&quote, requester);
        let order_delivery = delivery(&order, requester);

        let quote_created = call(
            "session_create",
            json!({
                "config": config,
                "records": [rfq, quote],
                "exit_packages": [],
                "deliveries": [rfq_delivery, quote_delivery],
            }),
        );
        assert_eq!(
            quote_created
                .pointer("/result/view/verification/state")
                .and_then(Value::as_str),
            Some("quote_verified"),
            "Quote-stage create failed: {quote_created}"
        );
        let quote_snapshot = quote_created
            .pointer("/result/snapshot_json_hex")
            .and_then(Value::as_str)
            .expect("Quote-stage snapshot");
        let quote_restored = call(
            "session_restore",
            json!({
                "snapshot_json_hex": quote_snapshot,
                "deliveries": [rfq_delivery, quote_delivery],
            }),
        );
        assert_eq!(
            quote_restored["result"]["view"],
            quote_created["result"]["view"]
        );
        let funding_attempt = call(
            "prepare_funding_request",
            json!({
                "snapshot_json_hex": quote_snapshot,
                "verification": verification,
            }),
        );
        assert_eq!(
            funding_attempt
                .pointer("/error/code")
                .and_then(Value::as_str),
            Some("swp_contract_terms_mismatch"),
            "Quote-stage session crossed the negotiated-terms gate: {funding_attempt}"
        );
        assert!(funding_attempt.get("result").is_none());

        let order_ingested = call(
            "session_ingest",
            json!({
                "snapshot_json_hex": quote_snapshot,
                "records": [order],
                "deliveries": [rfq_delivery, quote_delivery, order_delivery],
            }),
        );
        assert_eq!(
            order_ingested
                .pointer("/result/view/verification/state")
                .and_then(Value::as_str),
            Some("order_verified"),
            "Order-stage ingest failed: {order_ingested}"
        );
        assert_eq!(
            order_ingested
                .pointer("/result/ingested_records")
                .and_then(Value::as_u64),
            Some(1)
        );
        let order_snapshot = order_ingested
            .pointer("/result/snapshot_json_hex")
            .and_then(Value::as_str)
            .expect("Order-stage snapshot");
        let order_restored = call(
            "session_restore",
            json!({
                "snapshot_json_hex": order_snapshot,
                "deliveries": [rfq_delivery, quote_delivery, order_delivery],
            }),
        );
        assert_eq!(
            order_restored["result"]["view"],
            order_ingested["result"]["view"]
        );
    }

    #[test]
    fn progressive_browser_session_still_requires_exact_delivery_evidence() {
        let (config, rfq, quote, _, _) = reverse_fixture();
        let requester = config
            .get("requester_pubkey")
            .and_then(Value::as_str)
            .expect("requester public key");
        let response = call(
            "session_create",
            json!({
                "config": config,
                "records": [rfq, quote],
                "exit_packages": [],
                "deliveries": [delivery(&rfq, requester)],
            }),
        );
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_str),
            Some("swp_unresolved_loss")
        );
        assert!(response.get("result").is_none());
    }
}
