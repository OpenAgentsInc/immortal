//! Persistent no-spend provider mode.

use immortal_client::mkt_swp_client::{Cancellation, CloseOutcome, MktSigningRequest, StatusState};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND,
        MKT_STATUS_KIND, MKT_SWP_SWAP_CONTRACT_KIND,
    },
    market::MarketSigner,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::ProviderSession;

use crate::relay_actor::{
    ProviderMode, RecordOrigin, has_kind_by_author, run_with_mode, session_id,
    stalled_session_disposition, tag_value, validate_relay_url,
};

const PROVIDER_ID: &str = "immortal-no-spend";
const OFFERING_ID: &str = "immortal-no-spend-swaps";
const QUOTE_LIFETIME_SECONDS: u64 = 600;
const FULL_SESSION_FIXTURES: &str =
    include_str!("../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json");

struct NoSpendMode;

pub fn run() -> Result<(), String> {
    let relay_url = required_environment("IMMORTAL_PROVIDER_RELAY_URL")?;
    validate_relay_url(&relay_url, "no-spend")?;
    let identity_secret = required_environment("IMMORTAL_PROVIDER_IDENTITY_SECRET")?;
    let signer = signer_from_lower_hex(&identity_secret)?;
    run_with_mode(relay_url, signer, NoSpendMode, None)
}

impl ProviderMode for NoSpendMode {
    fn mode_name(&self) -> &'static str {
        "no-spend"
    }

    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }

    fn offering_id(&self) -> &str {
        OFFERING_ID
    }

    fn discovery_metadata(&self) -> Value {
        json!({
            "name":"Immortal no-spend provider",
            "mode":"no_spend",
            "settlement_claim":"coordination only; no external spend effects"
        })
    }

    fn offering(&self) -> Value {
        no_spend_offering()
    }

    fn dispose_stalled_session(
        &mut self,
        session: &ProviderSession,
        requester_pubkey: &str,
        observed_at: u64,
    ) -> Result<Option<&'static str>, String> {
        stalled_session_disposition(session, requester_pubkey, observed_at)
    }

    fn construct_quote(
        &mut self,
        session: &mut ProviderSession,
        _requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String> {
        let records = session.signed_records();
        let rfq = exactly_one_kind(records, MKT_RFQ_KIND, "RFQ")?;
        let swap_type = rfq_swap_type(rfq)?;
        let rfq_expiration = tag_value(rfq, "expiration")
            .ok_or_else(|| "RFQ has no expiration".to_owned())?
            .parse::<u64>()
            .map_err(|_| "RFQ expiration is invalid".to_owned())?;
        if created_at >= rfq_expiration {
            return Err("RFQ expired before the no-spend Quote was created".to_owned());
        }
        let expiration = created_at
            .saturating_add(QUOTE_LIFETIME_SECONDS)
            .min(rfq_expiration);
        let profile = quote_profile(swap_type, rfq, expiration)?;
        let session_id = session.config().session_id.clone();
        session
            .soft_quote(
                created_at,
                &deterministic_id("quote", &session_id),
                expiration,
                profile,
            )
            .map(Some)
            .map_err(|error| format!("could not construct no-spend Quote: {error}"))
    }

    fn observe_durable_signed_record(
        &mut self,
        _session_id: &str,
        _record: &Event,
        _origin: RecordOrigin,
        _provider_authored: bool,
    ) -> Result<(), String> {
        Ok(())
    }

    fn next_after_contract_or_status(
        &mut self,
        session: &mut ProviderSession,
        requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String> {
        let records = session.signed_records();
        if !has_kind_by_author(records, MKT_ORDER_KIND, requester_pubkey) {
            return Ok(None);
        }

        let requester_contract = records.iter().find(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND && record.pubkey == requester_pubkey
        });
        if requester_contract.is_none() {
            return Ok(None);
        }
        if !records.iter().any(|record| {
            record.kind == MKT_SWP_SWAP_CONTRACT_KIND
                && record.pubkey == session.config().provider_pubkey
        }) {
            let contract = requester_contract
                .and_then(|record| record_profile(record).ok())
                .and_then(|profile| profile.get("contract").cloned())
                .ok_or_else(|| "requester Swap Contract has no complete contract".to_owned())?;
            let session_id = session.config().session_id.clone();
            return session
                .provider_swap_contract(
                    created_at,
                    &deterministic_id("provider-contract", &session_id),
                    None,
                    contract,
                )
                .map(Some)
                .map_err(|error| format!("could not countersign requester contract: {error}"));
        }
        if !has_kind_by_author(records, MKT_STATUS_KIND, &session.config().provider_pubkey) {
            let session_id = session.config().session_id.clone();
            return session
                .provider_status(
                    created_at,
                    &deterministic_id("accepted-status", &session_id),
                    StatusState {
                        sequence: 0,
                        previous: None,
                        base_state: "accepted",
                        swp_state: "accepted",
                    },
                    Map::new(),
                )
                .map(Some)
                .map_err(|error| format!("could not construct provider Status: {error}"));
        }

        let cancel_request = records.iter().find(|record| {
            record.kind == MKT_CANCEL_KIND
                && record.pubkey == requester_pubkey
                && tag_value(record, "action") == Some("request")
        });
        let Some(cancel_request) = cancel_request else {
            return Ok(None);
        };
        let accepted = records.iter().find(|record| {
            record.kind == MKT_CANCEL_KIND
                && record.pubkey == session.config().provider_pubkey
                && tag_value(record, "action") == Some("accepted")
        });
        if accepted.is_none() {
            let session_id = session.config().session_id.clone();
            return session
                .provider_cancel(
                    created_at,
                    &deterministic_id("cancel-accepted", &session_id),
                    Cancellation {
                        action: "accepted",
                        reason: "no_spend_rehearsal",
                        request_id: Some(&cancel_request.id),
                        accepted_id: None,
                    },
                    json!({"disposition":"no_funding_authorized"}),
                )
                .map(Some)
                .map_err(|error| format!("could not accept no-spend Cancel: {error}"));
        }
        let accepted = accepted.ok_or_else(|| "accepted Cancel disappeared".to_owned())?;
        let effective = records.iter().find(|record| {
            record.kind == MKT_CANCEL_KIND
                && record.pubkey == session.config().provider_pubkey
                && tag_value(record, "action") == Some("effective")
        });
        if effective.is_none() {
            let session_id = session.config().session_id.clone();
            return session
                .provider_cancel(
                    created_at,
                    &deterministic_id("cancel-effective", &session_id),
                    Cancellation {
                        action: "effective",
                        reason: "no_spend_rehearsal",
                        request_id: Some(&cancel_request.id),
                        accepted_id: Some(&accepted.id),
                    },
                    json!({"disposition":"no_funding_authorized"}),
                )
                .map(Some)
                .map_err(|error| format!("could not make no-spend Cancel effective: {error}"));
        }
        if has_kind_by_author(records, MKT_CLOSE_KIND, &session.config().provider_pubkey) {
            return Ok(None);
        }
        let effective = effective.ok_or_else(|| "effective Cancel disappeared".to_owned())?;
        let quote = exactly_one_kind(records, MKT_QUOTE_KIND, "Quote")?;
        let terms = record_profile(quote)?
            .get("terms")
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| "Quote has no complete terms".to_owned())?;
        let swap_type = terms
            .get("swap_type")
            .and_then(Value::as_str)
            .ok_or_else(|| "Quote has no swap type".to_owned())?;
        let output_amount = terms
            .get("output_amount")
            .and_then(Value::as_str)
            .ok_or_else(|| "Quote has no output amount".to_owned())?;
        let session_id = session.config().session_id.clone();
        session
            .provider_close(
                created_at,
                &deterministic_id("cancelled-close", &session_id),
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: created_at,
                },
                json!({
                    "final_state":"cancelled",
                    "external_spend_effects":0,
                    "loss_classification":"none",
                    "cancel_id":effective.id,
                    "loss_accounting":zero_loss(swap_type, output_amount)
                }),
            )
            .map(Some)
            .map_err(|error| format!("could not construct zero-loss Close: {error}"))
    }
}

fn no_spend_offering() -> Value {
    let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
    let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
    let second_chain = "swp:1:bip122:11111111111111111111111111111111:btc:chain";
    json!({
        "mkt_swp":{
            "swap_types":["submarine","reverse","chain"],
            "sides":[
                {"input_asset_id":chain,"output_asset_id":lightning,"min":"100000","max":"100000","fee_bps":"9800"},
                {"input_asset_id":lightning,"output_asset_id":chain,"min":"1000","max":"1000","fee_bps":"100"},
                {"input_asset_id":chain,"output_asset_id":second_chain,"min":"100000","max":"100000","fee_bps":"100"}
            ],
            "networks":[
                "bip122:00000000000000000000000000000000",
                "bip122:11111111111111111111111111111111"
            ],
            "script_modes":["taproot-musig2-script-exit"],
            "reservation_proof_classes":["provider_signed"],
            "confirmation_policies":[{
                "policy_id":"btc-1conf-no-rbf",
                "minimum_confirmations":"1",
                "reorg_safety_blocks":"6",
                "zero_confirmation":"forbidden",
                "rbf":"reject",
                "replacement":"reject"
            }],
            "availability":"limited",
            "evm_extension":"unsupported"
        }
    })
}

fn quote_profile(swap_type: &str, rfq: &Event, expiration: u64) -> Result<Value, String> {
    let fixtures: Value = serde_json::from_str(FULL_SESSION_FIXTURES)
        .map_err(|error| format!("full-session fixture is invalid: {error}"))?;
    let records = fixtures
        .get("flows")
        .and_then(|flows| flows.get(swap_type))
        .and_then(|flow| flow.get("snapshot"))
        .and_then(|snapshot| snapshot.get("signed_records"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no full-session fixture for {swap_type}"))?;
    let quote = records
        .iter()
        .find(|record| {
            record.get("kind").and_then(Value::as_u64) == Some(u64::from(MKT_QUOTE_KIND))
        })
        .and_then(|record| record.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("full-session fixture has no {swap_type} Quote"))?;
    let mut profile = serde_json::from_str::<Value>(quote)
        .map_err(|error| format!("fixture Quote content is invalid: {error}"))?
        .get("mkt_swp")
        .cloned()
        .ok_or_else(|| "fixture Quote has no MKT-SWP profile".to_owned())?;
    let desired_completion = record_profile(rfq)?
        .get("constraints")
        .and_then(|constraints| constraints.get("desired_completion_time"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "RFQ has no desired completion time".to_owned())?;
    profile["terms"]["desired_completion_time"] = Value::from(desired_completion);
    profile["reservation_terms"]["reservation_expires_at"] = Value::from(expiration);
    profile["reservation_terms"]["reservation_id"] =
        Value::String(deterministic_id("reservation", session_id(rfq)?));
    profile["reservation_terms"]["capacity_bucket_id"] =
        Value::String("no-spend-rehearsal".to_owned());
    profile["reservation_terms"]["proof_ref"] =
        Value::String(format!("provider-signed:no-spend:{}", session_id(rfq)?));
    profile["reservation_terms"]["capacity_commitment_sha256"] =
        Value::String(deterministic_id("capacity", session_id(rfq)?));
    Ok(profile)
}

fn zero_loss(swap_type: &str, reservation_released: &str) -> Value {
    let chain = "swp:1:bip122:00000000000000000000000000000000:btc:chain";
    let lightning = "swp:1:bip122:00000000000000000000000000000000:btc:lightning";
    let second_chain = "swp:1:bip122:11111111111111111111111111111111:btc:chain";
    let pair = match swap_type {
        "submarine" => [chain, lightning],
        "reverse" => [lightning, chain],
        "chain" => [chain, second_chain],
        _ => [chain, chain],
    };
    json!({
        "input_asset_id":pair[0],
        "output_asset_id":pair[1],
        "input_committed":"0",
        "input_recovered":"0",
        "output_received":"0",
        "provider_fee_paid":"0",
        "miner_fee_paid":"0",
        "lightning_routing_fee_paid":"0",
        "guarantee_recovery_received":"0",
        "principal_unresolved":"0",
        "reservation_released":reservation_released,
        "evidence_refs":[],
        "unknown_fields":[]
    })
}

fn required_environment(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn signer_from_lower_hex(secret: &str) -> Result<MarketSigner, String> {
    if secret.len() != 64
        || secret
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(
            "IMMORTAL_PROVIDER_IDENTITY_SECRET must be 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in secret.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    MarketSigner::from_secret_bytes(bytes)
        .map_err(|error| format!("provider identity key is invalid: {error}"))
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("provider identity key contains non-hexadecimal data".to_owned()),
    }
}

fn record_profile(event: &Event) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Value>(&event.content)
        .map_err(|error| format!("MKT-SWP content is invalid JSON: {error}"))?
        .get("mkt_swp")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "MKT-SWP record has no profile object".to_owned())
}

fn rfq_swap_type(event: &Event) -> Result<&str, String> {
    let profile = record_profile(event)?;
    let swap_type = profile
        .get("constraints")
        .and_then(|constraints| constraints.get("swap_type"))
        .and_then(Value::as_str)
        .ok_or_else(|| "RFQ has no swap type".to_owned())?
        .to_owned();
    match swap_type.as_str() {
        "submarine" => Ok("submarine"),
        "reverse" => Ok("reverse"),
        "chain" => Ok("chain"),
        _ => Err("RFQ requests an unsupported swap type".to_owned()),
    }
}

fn exactly_one_kind<'a>(records: &'a [Event], kind: u16, label: &str) -> Result<&'a Event, String> {
    let matching = records
        .iter()
        .filter(|record| record.kind == kind)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!("session requires exactly one {label}"));
    }
    Ok(matching[0])
}

fn deterministic_id(label: &str, session_id: &str) -> String {
    lower_hex(&Sha256::digest(
        format!("immortal-provider-no-spend-v1\0{label}\0{session_id}").as_bytes(),
    ))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Event, FULL_SESSION_FIXTURES, MKT_CLOSE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, NoSpendMode,
        OFFERING_ID, ProviderMode, ProviderSession, has_kind_by_author, no_spend_offering,
    };
    use immortal_client::mkt_swp_client::{SwapClientConfig, SwapRecordFactory};
    use immortal_core::market::MarketSigner;
    use serde_json::json;

    #[test]
    fn requester_status_and_close_do_not_suppress_provider_actions() {
        let requester = "11".repeat(32);
        let provider = "22".repeat(32);
        let records = vec![
            event(MKT_STATUS_KIND, &requester),
            event(MKT_CLOSE_KIND, &requester),
        ];

        assert!(!has_kind_by_author(&records, MKT_STATUS_KIND, &provider));
        assert!(!has_kind_by_author(&records, MKT_CLOSE_KIND, &provider));
        assert!(has_kind_by_author(&records, MKT_STATUS_KIND, &requester));
        assert!(has_kind_by_author(&records, MKT_CLOSE_KIND, &requester));
    }

    #[test]
    fn no_spend_discovery_hooks_preserve_the_public_contract() {
        let mode = NoSpendMode;
        assert_eq!(mode.mode_name(), "no-spend");
        assert_eq!(mode.provider_id(), "immortal-no-spend");
        assert_eq!(mode.offering_id(), "immortal-no-spend-swaps");
        assert_eq!(
            mode.discovery_metadata(),
            json!({
                "name":"Immortal no-spend provider",
                "mode":"no_spend",
                "settlement_claim":"coordination only; no external spend effects"
            })
        );
        assert_eq!(mode.offering(), no_spend_offering());
    }

    #[test]
    fn no_spend_mode_prunes_expired_pre_contract_sessions() {
        let provider = MarketSigner::from_secret_bytes([71; 32]).expect("provider signer");
        let requester = MarketSigner::from_secret_bytes([72; 32]).expect("requester signer");
        let config = SwapClientConfig {
            session_id: "73".repeat(32),
            requester_pubkey: requester.pubkey().to_owned(),
            provider_pubkey: provider.pubkey().to_owned(),
            offering_address: format!("39601:{}:{OFFERING_ID}", provider.pubkey()),
        };
        let fixtures: serde_json::Value =
            serde_json::from_str(FULL_SESSION_FIXTURES).expect("session fixtures");
        let fixture_record = &fixtures["flows"]["submarine"]["snapshot"]["signed_records"][0];
        assert_eq!(
            fixture_record["kind"].as_u64(),
            Some(u64::from(MKT_RFQ_KIND))
        );
        let fixture_content: serde_json::Value = serde_json::from_str(
            fixture_record["content"]
                .as_str()
                .expect("fixture RFQ content"),
        )
        .expect("fixture RFQ JSON");
        let request = SwapRecordFactory::new(config.clone())
            .expect("record factory")
            .rfq(
                100,
                &"74".repeat(32),
                300,
                fixture_content["mkt_swp"].clone(),
            )
            .expect("RFQ request");
        let event = requester.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        let mut session = ProviderSession::new(config).expect("provider session");
        session
            .ingest_signed(request.verify_signed(event).expect("signed RFQ"))
            .expect("ingest RFQ");
        let mut mode = NoSpendMode;

        assert_eq!(
            mode.dispose_stalled_session(&session, requester.pubkey(), 299),
            Ok(None)
        );
        assert_eq!(
            mode.dispose_stalled_session(&session, requester.pubkey(), 300),
            Ok(Some("rfq_expired"))
        );
    }

    fn event(kind: u16, pubkey: &str) -> Event {
        Event {
            id: "00".repeat(32),
            pubkey: pubkey.to_owned(),
            created_at: 0,
            kind,
            tags: Vec::new(),
            content: String::new(),
            sig: "00".repeat(64),
        }
    }
}
