use std::collections::{BTreeMap, BTreeSet};

use immortal_client::mkt_swp_client::provider_support;
use serde_json::{Map, Value, json};

use crate::funded::{self, FundedJourney};

const MANIFEST: &str = include_str!("../../../tests/fixtures/lab/adversarial-v1.json");
const MANIFEST_SCHEMA: &str = "openagents.immortal.adversarial-lab.v1";
const RESULT_SCHEMA: &str = "openagents.immortal.adversarial-case-result.v1";
const CASE_ID_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_CASE_ID";
const SELECTED_PROVIDER_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_SELECTED_PROVIDER";
const EXPECTED_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_EXPECTED";
const MAXIMUM_CASES: usize = 40;
const MAXIMUM_FIELD_BYTES: usize = 128;
const MAXIMUM_RESULT_BYTES: usize = 16 * 1_024;
const SCENARIO_GROUPS: [&str; 4] = ["routing", "failure_matrix", "doomsday", "cooperative"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestCase {
    case_id: String,
    expected: String,
    provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedCase {
    manifest: ManifestCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JourneyOutcome {
    Claimed,
    Refunded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofPlan {
    Journey {
        provider_index: usize,
        journey: FundedJourney,
        injection: Option<&'static str>,
        outcome: JourneyOutcome,
    },
    ExpectedJourneyError {
        provider_index: usize,
        journey: FundedJourney,
        injection: &'static str,
        evidence: &'static str,
        expected_code: &'static str,
        outcome: &'static str,
    },
    TopologyCancellation,
    CustodyRefusal {
        member: &'static str,
    },
    Unsupported {
        reason: &'static str,
    },
}

pub fn run_from_env() -> Result<Value, String> {
    let selected = selected_case_with(|name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid Unicode")),
    })?;
    let proof = execute_proof(&selected)?;
    let result = json!({
        "schema":RESULT_SCHEMA,
        "case_id":selected.manifest.case_id,
        "expected":selected.manifest.expected,
        "passed":true,
        "proof":proof,
    });
    validate_result(&result)?;
    Ok(result)
}

fn selected_case_with(
    mut environment: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<SelectedCase, String> {
    let case_id = required_environment(&mut environment, CASE_ID_ENV)?;
    let expected = required_environment(&mut environment, EXPECTED_ENV)?;
    let selected_provider = optional_provider(environment(SELECTED_PROVIDER_ENV)?)?;
    let cases = parse_manifest()?;
    let manifest = cases
        .get(&case_id)
        .cloned()
        .ok_or_else(|| format!("adversarial case ID is absent from the manifest: {case_id}"))?;
    if manifest.expected != expected {
        return Err(format!(
            "adversarial expected outcome differs from the manifest for {case_id}"
        ));
    }
    if manifest.provider != selected_provider {
        return Err(format!(
            "adversarial selected provider differs from the manifest for {case_id}"
        ));
    }
    Ok(SelectedCase { manifest })
}

fn required_environment(
    environment: &mut impl FnMut(&str) -> Result<Option<String>, String>,
    name: &str,
) -> Result<String, String> {
    let value = environment(name)?.ok_or_else(|| format!("{name} is required"))?;
    validate_bounded_field(&value, name)?;
    Ok(value)
}

fn optional_provider(value: Option<String>) -> Result<Option<String>, String> {
    match value.as_deref() {
        None | Some("") => Ok(None),
        Some("provider-a" | "provider-b") => Ok(value),
        Some(_) => Err(format!(
            "{SELECTED_PROVIDER_ENV} must be empty, provider-a, or provider-b"
        )),
    }
}

fn parse_manifest() -> Result<BTreeMap<String, ManifestCase>, String> {
    let manifest: Value = serde_json::from_str(MANIFEST)
        .map_err(|error| format!("adversarial manifest is invalid JSON: {error}"))?;
    if manifest.get("schema").and_then(Value::as_str) != Some(MANIFEST_SCHEMA) {
        return Err("adversarial manifest schema is unsupported".to_owned());
    }
    let maximum_cases = manifest
        .pointer("/execution/maximum_cases")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value == MAXIMUM_CASES)
        .ok_or_else(|| "adversarial manifest case bound differs from the executable".to_owned())?;
    let groups = manifest
        .get("scenario_groups")
        .and_then(Value::as_object)
        .ok_or_else(|| "adversarial manifest has no scenario groups".to_owned())?;
    if groups.len() != SCENARIO_GROUPS.len()
        || SCENARIO_GROUPS
            .iter()
            .any(|group| !groups.contains_key(*group))
    {
        return Err("adversarial manifest scenario groups differ from the executable".to_owned());
    }
    let mut cases = BTreeMap::new();
    for group_name in SCENARIO_GROUPS {
        let rows = groups
            .get(group_name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("adversarial scenario group {group_name} is not an array"))?;
        for row in rows {
            let object = row
                .as_object()
                .ok_or_else(|| "adversarial scenario row is not an object".to_owned())?;
            if !matches!(object.len(), 2 | 3)
                || object
                    .keys()
                    .any(|name| !matches!(name.as_str(), "id" | "expected" | "provider"))
            {
                return Err("adversarial scenario row has an unknown member".to_owned());
            }
            let case_id = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "adversarial scenario row has no ID".to_owned())?;
            let expected = object
                .get("expected")
                .and_then(Value::as_str)
                .ok_or_else(|| "adversarial scenario row has no expected outcome".to_owned())?;
            validate_bounded_field(case_id, "adversarial manifest case ID")?;
            validate_bounded_field(expected, "adversarial manifest expected outcome")?;
            let provider = object
                .get("provider")
                .map(|provider| {
                    provider
                        .as_str()
                        .ok_or_else(|| "adversarial provider is not text".to_owned())
                        .and_then(|provider| match provider {
                            "provider-a" | "provider-b" => Ok(provider.to_owned()),
                            _ => Err("adversarial provider is unsupported".to_owned()),
                        })
                })
                .transpose()?;
            let case = ManifestCase {
                case_id: case_id.to_owned(),
                expected: expected.to_owned(),
                provider,
            };
            if cases.insert(case.case_id.clone(), case).is_some() {
                return Err("adversarial manifest repeats a case ID".to_owned());
            }
        }
    }
    if cases.is_empty() || cases.len() > maximum_cases {
        return Err("adversarial manifest case count is outside its bound".to_owned());
    }
    Ok(cases)
}

fn validate_bounded_field(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAXIMUM_FIELD_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!(
            "{label} must be 1..={MAXIMUM_FIELD_BYTES} ASCII identifier bytes"
        ));
    }
    Ok(())
}

fn execute_proof(selected: &SelectedCase) -> Result<Value, String> {
    match proof_plan(&selected.manifest.case_id) {
        ProofPlan::Journey {
            provider_index,
            journey,
            injection,
            outcome,
        } => {
            let result =
                funded::run_adversarial_funded_journey(provider_index, journey, injection)?;
            journey_proof(&result, provider_index, journey, injection, outcome)
        }
        ProofPlan::ExpectedJourneyError {
            provider_index,
            journey,
            injection,
            evidence,
            expected_code,
            outcome,
        } => match funded::run_adversarial_funded_journey(provider_index, journey, Some(injection))
        {
            Ok(_) => Err(format!(
                "adversarial injection {injection} did not refuse the operation"
            )),
            Err(error) if error.contains(evidence) => {
                Ok(expected_refusal_proof(injection, expected_code, outcome))
            }
            Err(error) => Err(format!(
                "adversarial injection {injection} returned another refusal: {error}"
            )),
        },
        ProofPlan::TopologyCancellation => {
            let result = funded::run_funded_topology()?;
            if result.get("schema").and_then(Value::as_str)
                != Some("openagents.immortal.funded-topology-result.v1")
                || result
                    .pointer("/unselected/outcome")
                    .and_then(Value::as_str)
                    != Some("cancelled")
                || result
                    .pointer("/unselected/external_spend_effects")
                    .and_then(Value::as_u64)
                    != Some(0)
                || result.pointer("/selected/result").and_then(Value::as_str) != Some("claimed")
            {
                return Err(
                    "funded topology did not prove rank-two cancellation without an effect"
                        .to_owned(),
                );
            }
            topology_proof(&result)
        }
        ProofPlan::CustodyRefusal { member } => prove_custody_refusal(member),
        ProofPlan::Unsupported { reason } => Err(format!(
            "unsupported adversarial proof for {}: {reason}",
            selected.manifest.case_id
        )),
    }
}

fn journey_proof(
    result: &Value,
    provider_index: usize,
    journey: FundedJourney,
    injection: Option<&str>,
    outcome: JourneyOutcome,
) -> Result<Value, String> {
    let expected = match outcome {
        JourneyOutcome::Claimed => "claimed",
        JourneyOutcome::Refunded => "refunded",
    };
    if provider_index > 1
        || result.get("step").and_then(Value::as_str) != Some(journey.name())
        || result.pointer("/journey/result").and_then(Value::as_str) != Some(expected)
    {
        return Err(format!(
            "funded adversarial journey did not prove terminal {expected}"
        ));
    }
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("funded adversarial result contains custody material: {error}"))?;
    let provider_pubkey = required_hash(result, "/provider_pubkey", "journey provider pubkey")?;
    let order_id = required_hash(result, "/journey/order_id", "journey order ID")?;
    let lockup_txid = required_hash(result, "/journey/lockup_txid", "journey lockup txid")?;
    let payment_hash = required_hash(result, "/journey/payment_hash", "journey payment hash")?;
    let lockup_vout = result
        .pointer("/journey/lockup_vout")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "journey lockup vout is not a u32".to_owned())?;
    let resumed = match result.get("resumed") {
        Some(Value::Bool(resumed)) => *resumed,
        None => false,
        Some(_) => return Err("journey resumed flag is not Boolean".to_owned()),
    };
    let (terminal_member, terminal_txid) = match outcome {
        JourneyOutcome::Claimed => (
            "claim_txid",
            required_hash(result, "/journey/claim_txid", "journey claim txid")?,
        ),
        JourneyOutcome::Refunded => (
            "refund_txid",
            required_hash(result, "/journey/refund_txid", "journey refund txid")?,
        ),
    };
    let mut proof = json!({
        "proof_class":"funded_journey",
        "provider_index":provider_index,
        "provider_pubkey":provider_pubkey,
        "order_id":order_id,
        "lockup_txid":lockup_txid,
        "lockup_vout":lockup_vout,
        "payment_hash":payment_hash,
        "outcome":expected,
        "resumed":resumed,
        "checks":{
            "exact_transaction_outpoint_lineage":true,
            "confirmations":true,
            "lightning_terminal_state":true,
            "signed_close":true,
            "provider_health":true,
        }
    });
    let object = proof
        .as_object_mut()
        .ok_or_else(|| "journey proof is not an object".to_owned())?;
    object.insert(terminal_member.to_owned(), Value::String(terminal_txid));
    if let Some(injection) = injection {
        object.insert("injection".to_owned(), Value::String(injection.to_owned()));
    }
    Ok(proof)
}

fn topology_proof(result: &Value) -> Result<Value, String> {
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("funded topology result contains custody material: {error}"))?;
    let selected_provider_pubkey = required_hash(
        result,
        "/selection/selected_provider_pubkey",
        "selected provider pubkey",
    )?;
    let selected_quote_id =
        required_hash(result, "/selection/selected_quote_id", "selected Quote ID")?;
    let unselected_provider_pubkey = required_hash(
        result,
        "/unselected/provider_pubkey",
        "unselected provider pubkey",
    )?;
    let session_id = required_hash(result, "/unselected/session_id", "unselected session ID")?;
    let order_id = required_hash(result, "/unselected/order_id", "unselected Order ID")?;
    let cancel_request_id = required_hash(
        result,
        "/unselected/cancel_request_id",
        "unselected Cancel request ID",
    )?;
    let cancel_accepted_id = required_hash(
        result,
        "/unselected/cancel_accepted_id",
        "unselected accepted Cancel ID",
    )?;
    let cancel_effective_id = required_hash(
        result,
        "/unselected/cancel_effective_id",
        "unselected effective Cancel ID",
    )?;
    let close_id = required_hash(result, "/unselected/close_id", "unselected Close ID")?;
    let reservation_released = result
        .pointer("/unselected/reservation_released")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && (value == &"0" || !value.starts_with('0'))
        })
        .ok_or_else(|| "unselected reservation release is not a canonical amount".to_owned())?;
    Ok(json!({
        "proof_class":"funded_topology_cancellation",
        "selected":{
            "provider_pubkey":selected_provider_pubkey,
            "quote_id":selected_quote_id,
        },
        "unselected":{
            "provider_pubkey":unselected_provider_pubkey,
            "session_id":session_id,
            "order_id":order_id,
            "cancel_request_id":cancel_request_id,
            "cancel_accepted_id":cancel_accepted_id,
            "cancel_effective_id":cancel_effective_id,
            "close_id":close_id,
            "outcome":"cancelled",
            "reservation_released":reservation_released,
            "external_spend_effects":0,
        }
    }))
}

fn required_hash(value: &Value, pointer: &str, label: &str) -> Result<String, String> {
    let hash = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} is absent"))?;
    provider_support::require_lower_hex_32(hash, label)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    Ok(hash.to_owned())
}

fn prove_custody_refusal(member: &str) -> Result<Value, String> {
    let value = Value::Object(Map::from_iter([(
        member.to_owned(),
        Value::String("00".repeat(32)),
    )]));
    match provider_support::reject_custody_material(&value) {
        Err(error) if error.code == "swp_secret_material_forbidden" => Ok(json!({
            "proof_class":"custody_refusal",
            "member":member,
            "expected_code":"swp_secret_material_forbidden",
            "outcome":"rejected_before_effect",
        })),
        Err(error) => Err(format!(
            "custody tripwire returned another refusal for {member}: {error}"
        )),
        Ok(()) => Err(format!(
            "custody tripwire accepted forbidden member {member}"
        )),
    }
}

fn expected_refusal_proof(injection: &str, expected_code: &str, outcome: &str) -> Value {
    json!({
        "proof_class":"expected_refusal",
        "injection":injection,
        "expected_code":expected_code,
        "outcome":outcome,
    })
}

fn proof_plan(case_id: &str) -> ProofPlan {
    match case_id {
        "route-submarine-provider-a" => journey(0, FundedJourney::Submarine),
        "route-submarine-provider-b" => journey(1, FundedJourney::Submarine),
        "route-reverse-provider-a" => journey(0, FundedJourney::ReverseClaim),
        "route-reverse-provider-b" => journey(1, FundedJourney::ReverseClaim),
        "rank-two-cancelled-without-effect" => ProofPlan::TopologyCancellation,
        "replay-identical-order" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("duplicate_message"),
            outcome: JourneyOutcome::Claimed,
        },
        "conflict-order-bytes" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: "conflicting_message",
            evidence: "injected conflicting message rejected before funding",
            expected_code: "swp_idempotency_conflict",
            outcome: "rejected_before_effect",
        },
        "stale-quote" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: "stale_quote",
            evidence: "swp_quote_expired",
            expected_code: "swp_quote_expired",
            outcome: "rejected_before_effect",
        },
        "preimage-leak-rejected" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: "secret_leak",
            evidence: "injected custody material rejected before persistence or funding",
            expected_code: "swp_secret_material_forbidden",
            outcome: "rejected_before_effect",
        },
        "seed-leak-rejected" => ProofPlan::CustodyRefusal {
            member: "wallet_seed_hex",
        },
        "macaroon-leak-rejected" => ProofPlan::CustodyRefusal {
            member: "admin_macaroon_hex",
        },
        "musig-nonce-leak-rejected" => ProofPlan::CustodyRefusal {
            member: "musig_secret_nonce",
        },
        "reverse-requester-noncooperative-provider-refund" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::ReverseRefund,
            injection: None,
            outcome: JourneyOutcome::Refunded,
        },
        "relay-a-partition" | "relay-b-partition" => ProofPlan::Unsupported {
            reason: "the topology runner has no case-bound partition controller",
        },
        "provider-a-crash-restart" | "provider-b-crash-restart" | "wallet-crash-restart" => {
            ProofPlan::Unsupported {
                reason: "the topology runner has no case-bound process crash acknowledgement",
            }
        }
        "double-reservation" => ProofPlan::Unsupported {
            reason: "the funded harness has no concurrent reservation driver",
        },
        "status-gap" | "status-fork" => ProofPlan::Unsupported {
            reason: "the funded harness has no signed Status mutation driver",
        },
        "funding-reorg" | "claim-reorg" => ProofPlan::Unsupported {
            reason: "the funded harness has no case-bound regtest reorg controller",
        },
        "rbf-conflict" => ProofPlan::Unsupported {
            reason: "the funded harness has no conflicting replacement transaction driver",
        },
        "wrong-claim-key" => ProofPlan::Unsupported {
            reason: "the funded harness has no wrong-key signing attempt",
        },
        "submarine-provider-noncooperative-refund" => ProofPlan::Unsupported {
            reason: "the funded harness has no requester submarine timeout-refund journey",
        },
        "doomsday-submarine-provider-gone"
        | "doomsday-reverse-coordinator-gone"
        | "doomsday-keyless-esplora-broadcast" => ProofPlan::Unsupported {
            reason: "the direct-counterparty and keyless doomsday executors are not implemented",
        },
        "musig2-submarine-provider-a"
        | "musig2-submarine-provider-b"
        | "musig2-abort-script-path"
        | "musig2-crash-cut-recovery" => ProofPlan::Unsupported {
            reason: "the funded-process MuSig2 activation gate is not implemented",
        },
        _ => ProofPlan::Unsupported {
            reason: "the manifest case has no executable proof plan",
        },
    }
}

const fn journey(provider_index: usize, journey: FundedJourney) -> ProofPlan {
    ProofPlan::Journey {
        provider_index,
        journey,
        injection: None,
        outcome: JourneyOutcome::Claimed,
    }
}

fn validate_result(result: &Value) -> Result<(), String> {
    let object = result
        .as_object()
        .ok_or_else(|| "adversarial result is not an object".to_owned())?;
    let members = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if members != BTreeSet::from(["case_id", "expected", "passed", "proof", "schema"])
        || object.get("schema").and_then(Value::as_str) != Some(RESULT_SCHEMA)
        || object
            .get("case_id")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                validate_bounded_field(value, "adversarial result case ID").is_err()
            })
        || object
            .get("expected")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                validate_bounded_field(value, "adversarial result expected outcome").is_err()
            })
        || object.get("passed").and_then(Value::as_bool) != Some(true)
        || object.get("proof").and_then(Value::as_object).is_none()
    {
        return Err("adversarial result does not match its exact schema".to_owned());
    }
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("adversarial result contains custody material: {error}"))?;
    let encoded = serde_json::to_vec(result)
        .map_err(|error| format!("adversarial result is not serializable: {error}"))?;
    if encoded.len() > MAXIMUM_RESULT_BYTES {
        return Err("adversarial result exceeds its byte bound".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: &str) -> String {
        byte.repeat(64)
    }

    fn selection(
        case_id: &str,
        expected: &str,
        provider: Option<&str>,
    ) -> Result<SelectedCase, String> {
        let environment = BTreeMap::from([
            (CASE_ID_ENV, case_id.to_owned()),
            (EXPECTED_ENV, expected.to_owned()),
            (
                SELECTED_PROVIDER_ENV,
                provider.unwrap_or_default().to_owned(),
            ),
        ]);
        selected_case_with(|name| Ok(environment.get(name).cloned()))
    }

    #[test]
    fn manifest_has_exact_bounded_case_ledger() {
        let cases = parse_manifest().expect("adversarial manifest should parse");
        assert_eq!(cases.len(), 33);
        assert_eq!(
            cases
                .get("route-submarine-provider-a")
                .and_then(|case| case.provider.as_deref()),
            Some("provider-a")
        );
        assert_eq!(
            cases
                .get("rank-two-cancelled-without-effect")
                .and_then(|case| case.provider.as_deref()),
            None
        );
        assert!(
            cases
                .keys()
                .all(|case_id| case_id.len() <= MAXIMUM_FIELD_BYTES)
        );
    }

    #[test]
    fn environment_must_match_manifest_case_exactly() {
        assert!(
            selection(
                "route-submarine-provider-a",
                "completed",
                Some("provider-a")
            )
            .is_ok()
        );
        assert!(selection("route-submarine-provider-a", "refunded", Some("provider-a")).is_err());
        assert!(
            selection(
                "route-submarine-provider-a",
                "completed",
                Some("provider-b")
            )
            .is_err()
        );
        assert!(selection("missing-case", "completed", None).is_err());
        assert!(selection("rank-two-cancelled-without-effect", "cancelled", None).is_ok());
        assert!(
            selection(
                "rank-two-cancelled-without-effect",
                "cancelled",
                Some("provider-a")
            )
            .is_err()
        );
        assert!(selected_case_with(|_| Ok(None)).is_err());
        let invalid_provider = BTreeMap::from([
            (CASE_ID_ENV, "route-submarine-provider-a".to_owned()),
            (EXPECTED_ENV, "completed".to_owned()),
            (SELECTED_PROVIDER_ENV, "provider-c".to_owned()),
        ]);
        assert!(selected_case_with(|name| Ok(invalid_provider.get(name).cloned())).is_err());
    }

    #[test]
    fn proof_plan_covers_every_manifest_case_without_default_success() {
        let cases = parse_manifest().expect("adversarial manifest should parse");
        let supported = cases
            .keys()
            .filter(|case_id| !matches!(proof_plan(case_id), ProofPlan::Unsupported { .. }))
            .count();
        assert_eq!(supported, 13);
        for case_id in cases.keys() {
            if let ProofPlan::Unsupported { reason } = proof_plan(case_id) {
                assert!(
                    !reason.is_empty(),
                    "unsupported case {case_id} needs a reason"
                );
            }
        }
    }

    #[test]
    fn custody_tripwires_cover_each_manifest_leak_member() {
        for member in [
            "preimage",
            "wallet_seed_hex",
            "admin_macaroon_hex",
            "musig_secret_nonce",
        ] {
            let proof = prove_custody_refusal(member).expect("custody member should be rejected");
            assert_eq!(
                proof,
                json!({
                    "proof_class":"custody_refusal",
                    "member":member,
                    "expected_code":"swp_secret_material_forbidden",
                    "outcome":"rejected_before_effect",
                })
            );
        }
    }

    #[test]
    fn journey_proof_retains_only_auditable_terminal_evidence() {
        let result = json!({
            "step":"submarine",
            "provider_pubkey":hash("1"),
            "resumed":true,
            "debug":"discarded",
            "journey":{
                "order_id":hash("2"),
                "lockup_txid":hash("3"),
                "lockup_vout":1,
                "payment_hash":hash("4"),
                "claim_txid":hash("5"),
                "result":"claimed",
            }
        });
        let proof = journey_proof(
            &result,
            1,
            FundedJourney::Submarine,
            Some("duplicate_message"),
            JourneyOutcome::Claimed,
        )
        .expect("claimed journey proof");
        assert_eq!(
            proof,
            json!({
                "proof_class":"funded_journey",
                "provider_index":1,
                "provider_pubkey":hash("1"),
                "order_id":hash("2"),
                "lockup_txid":hash("3"),
                "lockup_vout":1,
                "payment_hash":hash("4"),
                "claim_txid":hash("5"),
                "outcome":"claimed",
                "resumed":true,
                "injection":"duplicate_message",
                "checks":{
                    "exact_transaction_outpoint_lineage":true,
                    "confirmations":true,
                    "lightning_terminal_state":true,
                    "signed_close":true,
                    "provider_health":true,
                }
            })
        );

        let refunded = json!({
            "step":"reverse_refund",
            "provider_pubkey":hash("6"),
            "journey":{
                "order_id":hash("7"),
                "lockup_txid":hash("8"),
                "lockup_vout":0,
                "payment_hash":hash("9"),
                "refund_txid":hash("a"),
                "result":"refunded",
            }
        });
        let proof = journey_proof(
            &refunded,
            0,
            FundedJourney::ReverseRefund,
            None,
            JourneyOutcome::Refunded,
        )
        .expect("refunded journey proof");
        assert_eq!(proof.get("refund_txid"), Some(&Value::String(hash("a"))));
        assert_eq!(proof.get("claim_txid"), None);
        assert_eq!(proof.get("resumed"), Some(&Value::Bool(false)));
    }

    #[test]
    fn topology_proof_retains_selection_and_cancelled_reservation_evidence() {
        let result = json!({
            "selection":{
                "selected_provider_pubkey":hash("1"),
                "selected_quote_id":hash("2"),
            },
            "unselected":{
                "provider_pubkey":hash("3"),
                "session_id":hash("4"),
                "order_id":hash("5"),
                "cancel_request_id":hash("6"),
                "cancel_accepted_id":hash("7"),
                "cancel_effective_id":hash("8"),
                "close_id":hash("9"),
                "reservation_released":"1000",
                "external_spend_effects":0,
                "outcome":"cancelled",
                "debug":"discarded",
            }
        });
        let proof = topology_proof(&result).expect("topology proof");
        assert_eq!(
            proof,
            json!({
                "proof_class":"funded_topology_cancellation",
                "selected":{
                    "provider_pubkey":hash("1"),
                    "quote_id":hash("2"),
                },
                "unselected":{
                    "provider_pubkey":hash("3"),
                    "session_id":hash("4"),
                    "order_id":hash("5"),
                    "cancel_request_id":hash("6"),
                    "cancel_accepted_id":hash("7"),
                    "cancel_effective_id":hash("8"),
                    "close_id":hash("9"),
                    "outcome":"cancelled",
                    "reservation_released":"1000",
                    "external_spend_effects":0,
                }
            })
        );
    }

    #[test]
    fn expected_refusal_proof_does_not_retain_error_text() {
        let proof = expected_refusal_proof(
            "conflicting_message",
            "swp_idempotency_conflict",
            "rejected_before_effect",
        );
        assert_eq!(
            proof,
            json!({
                "proof_class":"expected_refusal",
                "injection":"conflicting_message",
                "expected_code":"swp_idempotency_conflict",
                "outcome":"rejected_before_effect",
            })
        );
    }

    #[test]
    fn unsupported_case_fails_closed_without_a_result() {
        let selected = selection(
            "doomsday-keyless-esplora-broadcast",
            "broadcast_complete_presigned_transaction",
            None,
        )
        .expect("doomsday case should bind the manifest");
        let error = execute_proof(&selected).expect_err("unsupported proof must fail");
        assert!(error.starts_with("unsupported adversarial proof"));
        assert!(error.contains("keyless doomsday executors are not implemented"));
    }

    #[test]
    fn result_is_exact_bounded_and_custody_free() {
        let result = json!({
            "schema":RESULT_SCHEMA,
            "case_id":"rank-two-cancelled-without-effect",
            "expected":"cancelled",
            "passed":true,
            "proof":{
                "proof_class":"funded_topology_cancellation",
            },
        });
        validate_result(&result).expect("exact result should pass");
        assert!(serde_json::to_vec(&result).expect("result JSON").len() <= MAXIMUM_RESULT_BYTES);

        let mut changed = result.clone();
        changed
            .pointer_mut("/proof")
            .and_then(Value::as_object_mut)
            .expect("proof object")
            .insert("wallet_seed_hex".to_owned(), Value::String("00".repeat(32)));
        assert!(validate_result(&changed).is_err());

        let mut oversized = result;
        oversized
            .pointer_mut("/proof")
            .and_then(Value::as_object_mut)
            .expect("proof object")
            .insert(
                "evidence".to_owned(),
                Value::String("x".repeat(MAXIMUM_RESULT_BYTES)),
            );
        assert!(validate_result(&oversized).is_err());
    }
}
