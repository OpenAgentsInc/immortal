//! Closed user-input contract for dynamic public-regtest swap sessions.

use immortal_core::{
    domain::parse_json_without_duplicate_members,
    mkt_swp_verify::{BitcoinNetwork, parse_bolt11, parse_segwit_address, sha256},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA: &str = "openagents.immortal.dynamic-public-regtest-request.v1";
pub const NETWORK: &str = "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4";
pub const MINIMUM_AMOUNT_SAT: u64 = 10_000;
pub const MAXIMUM_AMOUNT_SAT: u64 = 1_000_000;
const MAXIMUM_REQUEST_LIFETIME_SECONDS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicRequest {
    pub schema: String,
    pub request_id: String,
    pub network: String,
    pub swap_type: DynamicSwapType,
    pub input_amount_sat: u64,
    pub maximum_total_fee_sat: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub destination: DynamicDestination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicSwapType {
    Reverse,
    Submarine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicDestination {
    BitcoinAddress { value: String },
    Bolt11Invoice { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDynamicRequestView {
    pub schema: &'static str,
    pub request_id: String,
    pub network: &'static str,
    pub swap_type: DynamicSwapType,
    pub input_amount_sat: u64,
    pub maximum_total_fee_sat: u64,
    pub destination_kind: &'static str,
    pub destination_commitment_sha256: String,
    pub destination_amount_sat: Option<u64>,
    pub payment_hash: Option<String>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedDynamicRequest {
    pub request: DynamicRequest,
    pub destination_script_pubkey: Option<Vec<u8>>,
    pub invoice: Option<String>,
    pub payment_hash: Option<String>,
    pub destination_amount_sat: Option<u64>,
    pub destination_commitment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicRequestError {
    pub code: &'static str,
    pub detail: String,
}

impl DynamicRequestError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for DynamicRequestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for DynamicRequestError {}

pub fn validate_request_json(
    bytes: &[u8],
    observed_at: u64,
) -> Result<PublicDynamicRequestView, DynamicRequestError> {
    validate_request(bytes, observed_at).map(|validated| validated.public_view())
}

pub(crate) fn validate_request(
    bytes: &[u8],
    observed_at: u64,
) -> Result<ValidatedDynamicRequest, DynamicRequestError> {
    if bytes.is_empty() || bytes.len() > 16 * 1_024 {
        return Err(DynamicRequestError::new(
            "swp_dynamic_request_bound",
            "dynamic request is empty or exceeds 16384 bytes",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        DynamicRequestError::new("swp_dynamic_request_invalid", "request is not UTF-8")
    })?;
    let value = parse_json_without_duplicate_members(text, "dynamic public regtest request")
        .map_err(|detail| DynamicRequestError::new("swp_dynamic_request_invalid", detail))?;
    let request: DynamicRequest = serde_json::from_value(value).map_err(|error| {
        DynamicRequestError::new(
            "swp_dynamic_request_invalid",
            format!("request does not match the closed schema: {error}"),
        )
    })?;
    validate_envelope(&request, observed_at)?;

    let (destination_script_pubkey, invoice, payment_hash, destination_amount_sat, material) =
        match (&request.swap_type, &request.destination) {
            (DynamicSwapType::Reverse, DynamicDestination::BitcoinAddress { value }) => {
                let address = parse_segwit_address(value).map_err(|error| {
                    DynamicRequestError::new(
                        "swp_dynamic_destination_invalid",
                        format!("Bitcoin destination is invalid: {error}"),
                    )
                })?;
                if address.network != BitcoinNetwork::Regtest {
                    return Err(DynamicRequestError::new(
                        "swp_dynamic_network_mismatch",
                        "Bitcoin destination is not regtest",
                    ));
                }
                let script_pubkey = address.script_pubkey;
                (Some(script_pubkey.clone()), None, None, None, script_pubkey)
            }
            (DynamicSwapType::Submarine, DynamicDestination::Bolt11Invoice { value }) => {
                let parsed = parse_bolt11(value).map_err(|error| {
                    DynamicRequestError::new(
                        "swp_dynamic_destination_invalid",
                        format!("Lightning invoice is invalid: {error}"),
                    )
                })?;
                if parsed.network != BitcoinNetwork::Regtest {
                    return Err(DynamicRequestError::new(
                        "swp_dynamic_network_mismatch",
                        "Lightning invoice is not regtest",
                    ));
                }
                let amount_msat = parsed.amount_msat.ok_or_else(|| {
                    DynamicRequestError::new(
                        "swp_dynamic_invoice_amount_required",
                        "Lightning invoice must contain an amount",
                    )
                })?;
                if amount_msat % 1_000 != 0 {
                    return Err(DynamicRequestError::new(
                        "swp_dynamic_invoice_amount_invalid",
                        "Lightning invoice amount is not whole satoshis",
                    ));
                }
                let expires_at = parsed.timestamp.saturating_add(parsed.expiry_seconds);
                if expires_at <= observed_at {
                    return Err(DynamicRequestError::new(
                        "swp_dynamic_invoice_expired",
                        "Lightning invoice is expired",
                    ));
                }
                let unsupported_required = unsupported_required_feature(&parsed.feature_bits);
                if let Some(bit) = unsupported_required {
                    return Err(DynamicRequestError::new(
                        "swp_dynamic_invoice_feature_unsupported",
                        format!("Lightning invoice requires unsupported feature bit {bit}"),
                    ));
                }
                (
                    None,
                    Some(value.clone()),
                    Some(lower_hex(&parsed.payment_hash)),
                    Some(amount_msat / 1_000),
                    value.as_bytes().to_vec(),
                )
            }
            _ => {
                return Err(DynamicRequestError::new(
                    "swp_dynamic_destination_mismatch",
                    "destination kind does not match swap type",
                ));
            }
        };
    Ok(ValidatedDynamicRequest {
        request,
        destination_script_pubkey,
        invoice,
        payment_hash,
        destination_amount_sat,
        destination_commitment_sha256: lower_hex(&sha256(&material)),
    })
}

fn validate_envelope(
    request: &DynamicRequest,
    observed_at: u64,
) -> Result<(), DynamicRequestError> {
    if request.schema != SCHEMA {
        return Err(DynamicRequestError::new(
            "swp_dynamic_schema_unsupported",
            "dynamic request schema is unsupported",
        ));
    }
    require_lower_hex_32(&request.request_id)?;
    if request.network != NETWORK {
        return Err(DynamicRequestError::new(
            "swp_dynamic_network_mismatch",
            "dynamic request is not Bitcoin regtest",
        ));
    }
    if !(MINIMUM_AMOUNT_SAT..=MAXIMUM_AMOUNT_SAT).contains(&request.input_amount_sat) {
        return Err(DynamicRequestError::new(
            "swp_dynamic_amount_out_of_range",
            format!("input amount must be {MINIMUM_AMOUNT_SAT}..={MAXIMUM_AMOUNT_SAT} sat"),
        ));
    }
    if request.maximum_total_fee_sat == 0
        || request.maximum_total_fee_sat > 50_000
        || request.maximum_total_fee_sat >= request.input_amount_sat
    {
        return Err(DynamicRequestError::new(
            "swp_dynamic_fee_out_of_range",
            "maximum fee is zero, at least the input, or above 50000 sat",
        ));
    }
    if request.created_at > observed_at.saturating_add(30)
        || request.expires_at <= observed_at
        || request.expires_at <= request.created_at
        || request.expires_at.saturating_sub(request.created_at) > MAXIMUM_REQUEST_LIFETIME_SECONDS
    {
        return Err(DynamicRequestError::new(
            "swp_dynamic_request_expired",
            "request time bounds are invalid or expired",
        ));
    }
    Ok(())
}

fn unsupported_required_feature(feature_bits: &[u16]) -> Option<u16> {
    feature_bits
        .iter()
        .copied()
        .find(|bit| bit % 2 == 0 && !matches!(*bit, 8 | 14 | 16))
}

impl ValidatedDynamicRequest {
    pub fn require_destination_amount(
        &self,
        expected_amount_sat: u64,
    ) -> Result<(), DynamicRequestError> {
        if self
            .destination_amount_sat
            .is_some_and(|amount| amount != expected_amount_sat)
        {
            return Err(DynamicRequestError::new(
                "swp_dynamic_invoice_amount_mismatch",
                "Lightning invoice amount differs from the selected Quote output",
            ));
        }
        Ok(())
    }

    pub fn public_view(&self) -> PublicDynamicRequestView {
        PublicDynamicRequestView {
            schema: SCHEMA,
            request_id: self.request.request_id.clone(),
            network: NETWORK,
            swap_type: self.request.swap_type,
            input_amount_sat: self.request.input_amount_sat,
            maximum_total_fee_sat: self.request.maximum_total_fee_sat,
            destination_kind: match self.request.destination {
                DynamicDestination::BitcoinAddress { .. } => "bitcoin_address",
                DynamicDestination::Bolt11Invoice { .. } => "bolt11_invoice",
            },
            destination_commitment_sha256: self.destination_commitment_sha256.clone(),
            destination_amount_sat: self.destination_amount_sat,
            payment_hash: self.payment_hash.clone(),
            expires_at: self.request.expires_at,
        }
    }
}

fn require_lower_hex_32(value: &str) -> Result<(), DynamicRequestError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(DynamicRequestError::new(
            "swp_dynamic_request_id_invalid",
            "request ID is not 32-byte lowercase hex",
        ));
    }
    Ok(())
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

pub fn fixture_contract() -> Result<Value, DynamicRequestError> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/lab/dynamic-public-regtest-v1.json"
    ))
    .map_err(|error| {
        DynamicRequestError::new(
            "swp_dynamic_fixture_invalid",
            format!("dynamic fixture is invalid: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "bcrt1pvcpgfdxvvnklep6kdyewn80pphta54nwwrex3ahrvh2uh0e9dgwsalmcu5";
    const INVOICE: &str = "lnbcrt10u1p489c7rpp5vvxu62txcsekdygj23ythvjmfl6p9fyuwvkm9j9tcxu9sx7hzrwsdq6d9kk6mmjw3skcttxd9u8gatjv5cqzzsxqyjw5qsp5cn6jpj7y8erx4ptq053e3wxsuqmzd2vf89spv0gnqwjyqpffy7lq9qxpqysgq7a3ujjdmarghmnawvwcrn0vcvt2wklkh8lccnp00geuxye5xaj09j2pjg3d0wf6gcvelgrhy23acaa7uu9ra30wfjr3qwswm3yvkc7gp7dllky";

    fn request(swap_type: &str, kind: &str, value: &str, now: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema":SCHEMA,
            "request_id":"11".repeat(32),
            "network":NETWORK,
            "swap_type":swap_type,
            "input_amount_sat":100_000,
            "maximum_total_fee_sat":5_000,
            "created_at":now,
            "expires_at":now + 300,
            "destination":{"kind":kind,"value":value}
        }))
        .unwrap()
    }

    #[test]
    fn reverse_address_is_private_material_with_a_public_commitment() {
        let validated = validate_request(&request("reverse", "bitcoin_address", ADDRESS, 10), 10)
            .expect("dynamic reverse");
        assert_eq!(
            validated.destination_script_pubkey.as_ref().unwrap()[..2],
            [0x51, 0x20]
        );
        let public = serde_json::to_string(&validated.public_view()).unwrap();
        assert!(!public.contains(ADDRESS));
        assert_eq!(validated.public_view().destination_kind, "bitcoin_address");
    }

    #[test]
    fn submarine_invoice_is_amount_network_expiry_and_hash_bound() {
        let invoice = parse_bolt11(INVOICE).expect("fixture invoice");
        let now = invoice.timestamp + 1;
        let validated =
            validate_request(&request("submarine", "bolt11_invoice", INVOICE, now), now)
                .expect("dynamic submarine");
        assert_eq!(validated.destination_amount_sat, Some(1_000));
        assert_eq!(
            validated.payment_hash,
            Some(lower_hex(&invoice.payment_hash))
        );
        assert_eq!(
            validated.require_destination_amount(999).unwrap_err().code,
            "swp_dynamic_invoice_amount_mismatch"
        );
        let observed_at = invoice.timestamp + invoice.expiry_seconds;
        let expired_request = request("submarine", "bolt11_invoice", INVOICE, observed_at);
        assert_eq!(
            validate_request(&expired_request, observed_at)
                .unwrap_err()
                .code,
            "swp_dynamic_invoice_expired"
        );
        assert!(
            !serde_json::to_string(&validated.public_view())
                .unwrap()
                .contains(INVOICE)
        );
    }

    #[test]
    fn malformed_duplicate_wrong_network_amount_and_kind_fail_typed() {
        let duplicate = format!(
            "{{\"schema\":\"{SCHEMA}\",\"schema\":\"changed\",\"request_id\":\"{}\",\"network\":\"{NETWORK}\",\"swap_type\":\"reverse\",\"input_amount_sat\":100000,\"maximum_total_fee_sat\":5000,\"created_at\":10,\"expires_at\":20,\"destination\":{{\"kind\":\"bitcoin_address\",\"value\":\"{ADDRESS}\"}}}}",
            "11".repeat(32)
        );
        assert_eq!(
            validate_request(duplicate.as_bytes(), 10).unwrap_err().code,
            "swp_dynamic_request_invalid"
        );
        let mut value: Value =
            serde_json::from_slice(&request("reverse", "bitcoin_address", ADDRESS, 10)).unwrap();
        for (pointer, replacement, code) in [
            (
                "/network",
                Value::String("mainnet".to_owned()),
                "swp_dynamic_network_mismatch",
            ),
            (
                "/input_amount_sat",
                Value::from(0),
                "swp_dynamic_amount_out_of_range",
            ),
            (
                "/destination/kind",
                Value::String("bolt11_invoice".to_owned()),
                "swp_dynamic_destination_mismatch",
            ),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert_eq!(
                validate_request(&serde_json::to_vec(&changed).unwrap(), 10)
                    .unwrap_err()
                    .code,
                code
            );
        }
        value["expires_at"] = Value::from(10);
        assert_eq!(
            validate_request(&serde_json::to_vec(&value).unwrap(), 10)
                .unwrap_err()
                .code,
            "swp_dynamic_request_expired"
        );
    }

    #[test]
    fn checked_fixture_declares_mutation_and_live_gates() {
        let fixture = fixture_contract().expect("fixture");
        assert_eq!(
            fixture["schema"],
            "openagents.immortal.dynamic-public-regtest-fixture.v1"
        );
        assert_eq!(fixture["request_schema"], SCHEMA);
        assert_eq!(
            fixture["live_journeys"],
            serde_json::json!(["reverse", "submarine"])
        );
        assert_eq!(fixture["quote_count"], 2);
        assert_eq!(unsupported_required_feature(&[9, 14, 101]), None);
        assert_eq!(unsupported_required_feature(&[9, 2, 14]), Some(2));
        let wrong_network = fixture["destination_vectors"]["wrong_network_address"]
            .as_str()
            .expect("wrong-network address");
        assert_eq!(
            validate_request(
                &request("reverse", "bitcoin_address", wrong_network, 10),
                10
            )
            .unwrap_err()
            .code,
            "swp_dynamic_network_mismatch"
        );
        let malformed_invoice = fixture["destination_vectors"]["malformed_invoice"]
            .as_str()
            .expect("malformed invoice");
        assert_eq!(
            validate_request(
                &request("submarine", "bolt11_invoice", malformed_invoice, 10),
                10
            )
            .unwrap_err()
            .code,
            "swp_dynamic_destination_invalid"
        );
    }
}
