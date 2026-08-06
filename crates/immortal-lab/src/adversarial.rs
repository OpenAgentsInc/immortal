use std::collections::{BTreeMap, BTreeSet};

use immortal_client::mkt_swp_client::provider_support;
use serde_json::{Map, Value, json};

use crate::funded::{
    self, CooperativeJourney, DoomsdayCase, FundedJourney, LiquidChainDirection, LiquidJourney,
};

const MANIFEST: &str = include_str!("../../../tests/fixtures/lab/adversarial-v1.json");
const MANIFEST_SCHEMA: &str = "openagents.immortal.adversarial-lab.v1";
const RESULT_SCHEMA: &str = "openagents.immortal.adversarial-case-result.v1";
const CASE_ID_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_CASE_ID";
const SELECTED_PROVIDER_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_SELECTED_PROVIDER";
const EXPECTED_ENV: &str = "IMMORTAL_LAB_ADVERSARIAL_EXPECTED";
const MAXIMUM_CASES: usize = 48;
const MAXIMUM_FIELD_BYTES: usize = 128;
const MAXIMUM_RESULT_BYTES: usize = 32 * 1_024;
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
    DoubleReservation,
    CustodyRefusal {
        member: &'static str,
    },
    RbfConflict,
    Cooperative {
        provider_index: usize,
        journey: CooperativeJourney,
    },
    LiquidChain {
        provider_index: usize,
        direction: LiquidChainDirection,
    },
    LiquidJourney {
        provider_index: usize,
        journey: LiquidJourney,
    },
    Doomsday(DoomsdayCase),
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
        ProofPlan::DoubleReservation => {
            let proof = funded::run_adversarial_double_reservation()?;
            double_reservation_proof(&proof)
        }
        ProofPlan::CustodyRefusal { member } => prove_custody_refusal(member),
        ProofPlan::RbfConflict => {
            let result = funded::run_adversarial_funded_journey(
                0,
                FundedJourney::Submarine,
                Some("rbf_conflict"),
            )?;
            rbf_conflict_proof(&result)
        }
        ProofPlan::Cooperative {
            provider_index,
            journey,
        } => {
            let result = funded::run_adversarial_cooperative_journey(provider_index, journey)?;
            cooperative_proof(&result, provider_index, journey)
        }
        ProofPlan::LiquidChain {
            provider_index,
            direction,
        } => funded::run_adversarial_liquid_chain_journey(provider_index, direction),
        ProofPlan::LiquidJourney {
            provider_index,
            journey,
        } => funded::run_adversarial_liquid_journey(provider_index, journey),
        ProofPlan::Doomsday(case) => funded::recover_doomsday_case(case),
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
    let checks = if journey == FundedJourney::SubmarineRefund {
        if result
            .pointer("/journey/both_bitcoind_nodes_agree")
            .and_then(Value::as_bool)
            != Some(true)
            || result
                .pointer("/journey/provider_claim_effects")
                .and_then(Value::as_u64)
                != Some(0)
            || result
                .pointer("/journey/lightning_state")
                .and_then(Value::as_str)
                != Some("unpaid_final")
            || result
                .pointer("/journey/exit_package_mode")
                .and_then(Value::as_str)
                != Some("wallet_sign")
            || result
                .pointer("/journey/client_recovery_action")
                .and_then(Value::as_str)
                != Some("request_wallet_refund")
        {
            return Err("submarine refund lacks independent terminal checks".to_owned());
        }
        json!({
            "exit_package_committed_before_funding":true,
            "client_recovery_authorized_wallet_refund":true,
            "exact_transaction_outpoint_lineage":true,
            "confirmations":true,
            "both_bitcoind_nodes_agree":true,
            "lightning_unpaid_final":true,
            "provider_claim_effects":0,
        })
    } else {
        json!({
            "exact_transaction_outpoint_lineage":true,
            "confirmations":true,
            "lightning_terminal_state":true,
            "signed_close":true,
            "provider_health":true,
        })
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
        "checks":checks
    });
    let object = proof
        .as_object_mut()
        .ok_or_else(|| "journey proof is not an object".to_owned())?;
    object.insert(terminal_member.to_owned(), Value::String(terminal_txid));
    if journey == FundedJourney::SubmarineRefund {
        let funding_confirmation_height = result
            .pointer("/journey/funding_confirmation_height")
            .and_then(Value::as_u64)
            .ok_or_else(|| "submarine refund has no funding confirmation height".to_owned())?;
        let refund_lock_height = result
            .pointer("/journey/refund_lock_height")
            .and_then(Value::as_u64)
            .filter(|height| *height > funding_confirmation_height)
            .ok_or_else(|| "submarine refund has no later CLTV height".to_owned())?;
        object.insert(
            "funding_confirmation_height".to_owned(),
            json!(funding_confirmation_height),
        );
        object.insert("refund_lock_height".to_owned(), json!(refund_lock_height));
    }
    if let Some(injection) = injection {
        object.insert("injection".to_owned(), Value::String(injection.to_owned()));
        if matches!(
            injection,
            "relay_loss"
                | "provider_crash"
                | "wallet_crash"
                | "provider_noncooperative"
                | "funding_reorg"
                | "claim_reorg"
        ) {
            let control = result
                .get("external_control")
                .and_then(Value::as_object)
                .ok_or_else(|| "external process injection has no control proof".to_owned())?;
            let expected_target = match injection {
                "relay_loss" => format!("relay-{}", if provider_index == 0 { "a" } else { "b" }),
                "provider_crash" => {
                    format!("provider-{}", if provider_index == 0 { "a" } else { "b" })
                }
                "wallet_crash" => "wallet-driver".to_owned(),
                "provider_noncooperative" => {
                    format!("provider-{}", if provider_index == 0 { "a" } else { "b" })
                }
                "funding_reorg" | "claim_reorg" => "provider-a".to_owned(),
                _ => return Err("external process injection is unsupported".to_owned()),
            };
            let expected_transition = match injection {
                "relay_loss" | "provider_crash" | "wallet_crash" => "process_replaced_and_ready",
                "provider_noncooperative" => "process_stopped",
                "funding_reorg" => "funding_reorg_waited_and_resumed",
                "claim_reorg" => "claim_watch_reorged_and_reconfirmed",
                _ => return Err("external injection has no transition".to_owned()),
            };
            let expected_restored = injection != "provider_noncooperative";
            if control.get("schema").and_then(Value::as_str)
                != Some("openagents.immortal.lab-injection-ack.v1")
                || control.get("restored").and_then(Value::as_bool) != Some(expected_restored)
                || control
                    .get("evidence")
                    .and_then(Value::as_object)
                    .and_then(|evidence| evidence.get("target"))
                    .and_then(Value::as_str)
                    != Some(expected_target.as_str())
                || control
                    .get("evidence")
                    .and_then(Value::as_object)
                    .and_then(|evidence| evidence.get("transition"))
                    .and_then(Value::as_str)
                    != Some(expected_transition)
            {
                return Err(
                    "external process control proof does not bind the selected target".to_owned(),
                );
            }
            if matches!(injection, "funding_reorg" | "claim_reorg") {
                let controlled_transaction = control
                    .get("evidence")
                    .and_then(Value::as_object)
                    .and_then(|evidence| evidence.get("transaction_id"))
                    .and_then(Value::as_str);
                let expected_transaction = if injection == "funding_reorg" {
                    object.get("lockup_txid").and_then(Value::as_str)
                } else {
                    object.get(terminal_member).and_then(Value::as_str)
                };
                if controlled_transaction != expected_transaction {
                    return Err(
                        "chain control proof does not bind the journey transaction".to_owned()
                    );
                }
            }
            object.insert(
                "external_control".to_owned(),
                Value::Object(control.clone()),
            );
        }
    }
    Ok(proof)
}

fn rbf_conflict_proof(result: &Value) -> Result<Value, String> {
    if result.get("step").and_then(Value::as_str) != Some("submarine") {
        return Err("RBF conflict did not run the submarine funding boundary".to_owned());
    }
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("RBF conflict result contains custody material: {error}"))?;
    let provider_pubkey = required_hash(result, "/provider_pubkey", "RBF provider pubkey")?;
    let order_id = required_hash(result, "/journey/order_id", "RBF order ID")?;
    let committed_txid = required_hash(
        result,
        "/journey/committed_txid",
        "RBF committed transaction ID",
    )?;
    let conflict_txid = required_hash(
        result,
        "/journey/conflict_txid",
        "RBF conflict transaction ID",
    )?;
    let input_txid = required_hash(result, "/journey/input_txid", "RBF input transaction ID")?;
    let input_vout = result
        .pointer("/journey/input_vout")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "RBF conflict input vout is not a u32".to_owned())?;
    if committed_txid == conflict_txid
        || result
            .pointer("/journey/expected_code")
            .and_then(Value::as_str)
            != Some("swp_rbf_policy_violation")
        || result.pointer("/journey/outcome").and_then(Value::as_str)
            != Some("rejected_before_effect")
        || result
            .pointer("/journey/conflict_in_mempool")
            .and_then(Value::as_bool)
            != Some(true)
        || result
            .pointer("/journey/committed_broadcast_rejected")
            .and_then(Value::as_bool)
            != Some(true)
        || result
            .pointer("/journey/external_settlement_effects")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err("RBF conflict did not prove exact fail-closed policy handling".to_owned());
    }
    Ok(json!({
        "proof_class":"real_same_input_conflict",
        "provider_pubkey":provider_pubkey,
        "order_id":order_id,
        "committed_txid":committed_txid,
        "conflict_txid":conflict_txid,
        "input_txid":input_txid,
        "input_vout":input_vout,
        "expected_code":"swp_rbf_policy_violation",
        "outcome":"rejected_before_effect",
        "checks":{
            "same_input":true,
            "conflict_broadcast_to_regtest":true,
            "committed_broadcast_rejected":true,
            "external_settlement_effects":0,
        }
    }))
}

fn cooperative_proof(
    result: &Value,
    provider_index: usize,
    journey: CooperativeJourney,
) -> Result<Value, String> {
    provider_support::reject_custody_material(result)
        .map_err(|error| format!("cooperative result contains custody material: {error}"))?;
    if provider_index > 1
        || result.get("step").and_then(Value::as_str) != Some(journey.name())
        || result.pointer("/journey/result").and_then(Value::as_str) != Some("claimed")
        || result
            .pointer("/journey/witness/exact_funding_outpoint")
            .and_then(Value::as_bool)
            != Some(true)
        || result
            .pointer("/journey/witness/both_bitcoind_nodes_agree")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("cooperative journey lacks exact terminal chain proof".to_owned());
    }
    let expected_path = if journey == CooperativeJourney::Complete {
        "key_path"
    } else {
        "script_claim"
    };
    let expected_vsize = if journey == CooperativeJourney::Complete {
        111
    } else {
        155
    };
    if result
        .pointer("/journey/witness/path")
        .and_then(Value::as_str)
        != Some(expected_path)
        || result
            .pointer("/journey/witness/virtual_size")
            .and_then(Value::as_u64)
            != Some(expected_vsize)
    {
        return Err("cooperative journey used another witness footprint".to_owned());
    }
    if journey == CooperativeJourney::Complete {
        if result
            .pointer("/journey/cooperative_status_count")
            .and_then(Value::as_u64)
            != Some(7)
            || result
                .pointer("/journey/witness/witness_item_count")
                .and_then(Value::as_u64)
                != Some(1)
            || result.pointer("/journey/witness/witness_item_lengths") != Some(&json!([64]))
        {
            return Err("cooperative key-path transcript or witness is incomplete".to_owned());
        }
    } else if result
        .pointer("/journey/provider_abort_count")
        .and_then(Value::as_u64)
        != Some(1)
        || result
            .pointer("/journey/provider_partial_count")
            .and_then(Value::as_u64)
            != Some(0)
        || result
            .pointer("/journey/provider_final_count")
            .and_then(Value::as_u64)
            != Some(0)
        || result
            .pointer("/journey/witness/witness_item_count")
            .and_then(Value::as_u64)
            != Some(4)
        || result
            .pointer("/journey/witness/exact_contract_leaf_and_control")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("cooperative fallback transcript or witness is incomplete".to_owned());
    }
    let proof = json!({
        "proof_class":"funded_cooperative_process",
        "provider_index":provider_index,
        "provider_pubkey":required_hash(result, "/provider_pubkey", "cooperative provider pubkey")?,
        "order_id":required_hash(result, "/journey/order_id", "cooperative order ID")?,
        "lockup_txid":required_hash(result, "/journey/lockup_txid", "cooperative lockup txid")?,
        "lockup_vout":0,
        "claim_txid":required_hash(result, "/journey/claim_txid", "cooperative claim txid")?,
        "payment_hash":required_hash(result, "/journey/payment_hash", "cooperative payment hash")?,
        "cooperative_status_ids":result.pointer("/journey/cooperative_status_ids").cloned().ok_or_else(|| "cooperative Status IDs are absent".to_owned())?,
        "cooperative_status_count":result.pointer("/journey/cooperative_status_count").cloned().ok_or_else(|| "cooperative Status count is absent".to_owned())?,
        "witness":result.pointer("/journey/witness").cloned().ok_or_else(|| "cooperative witness proof is absent".to_owned())?,
        "effect_states":result.pointer("/journey/effect_states").cloned().ok_or_else(|| "cooperative effect states are absent".to_owned())?,
        "external_control":result.pointer("/journey/external_control").cloned().unwrap_or(Value::Null),
        "outcome":if journey == CooperativeJourney::Complete { "completed_key_path" } else { "completed_script_path" },
    });
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

fn double_reservation_proof(proof: &Value) -> Result<Value, String> {
    provider_support::reject_custody_material(proof)
        .map_err(|error| format!("double-reservation proof contains custody material: {error}"))?;
    if proof.get("proof_class").and_then(Value::as_str) != Some("live_double_reservation")
        || proof
            .pointer("/refused/expected_code")
            .and_then(Value::as_str)
            != Some("swp_reservation_overallocated")
        || proof.pointer("/refused/provider_wire_refusal") != Some(&Value::Null)
        || proof.pointer("/refused/surface").and_then(Value::as_str)
            != Some("lab_process_audit_required")
        || proof
            .pointer("/checks/daemon_backed_hard_reservation_effects")
            .and_then(Value::as_u64)
            != Some(1)
        || proof
            .pointer("/checks/same_provider")
            .and_then(Value::as_bool)
            != Some(true)
        || proof
            .pointer("/checks/same_capacity_bucket")
            .and_then(Value::as_bool)
            != Some(true)
        || proof
            .pointer("/checks/overlapping_signed_sessions")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("double-reservation process proof has another outcome".to_owned());
    }
    for (pointer, label) in [
        ("/provider_pubkey", "double-reservation provider pubkey"),
        ("/daemon_reservation_id", "daemon-backed reservation ID"),
        ("/active/session_id", "active reservation session ID"),
        ("/active/rfq_id", "active reservation RFQ ID"),
        ("/active/quote_id", "active reservation Quote ID"),
        ("/active/reservation_id", "active reservation ID"),
        ("/refused/session_id", "refused reservation session ID"),
        ("/refused/rfq_id", "refused reservation RFQ ID"),
    ] {
        required_hash(proof, pointer, label)?;
    }
    let bucket = proof
        .get("capacity_bucket_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "double-reservation proof has no capacity bucket".to_owned())?;
    if bucket.is_empty()
        || bucket.len() > 64
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("double-reservation capacity bucket is invalid".to_owned());
    }
    Ok(proof.clone())
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
        "route-chain-btc-to-lbtc-provider-a" => ProofPlan::LiquidChain {
            provider_index: 0,
            direction: LiquidChainDirection::BitcoinToLiquid,
        },
        "route-chain-btc-to-lbtc-provider-b" => ProofPlan::LiquidChain {
            provider_index: 1,
            direction: LiquidChainDirection::BitcoinToLiquid,
        },
        "route-chain-lbtc-to-btc-provider-a" => ProofPlan::LiquidChain {
            provider_index: 0,
            direction: LiquidChainDirection::LiquidToBitcoin,
        },
        "route-chain-lbtc-to-btc-provider-b" => ProofPlan::LiquidChain {
            provider_index: 1,
            direction: LiquidChainDirection::LiquidToBitcoin,
        },
        "route-liquid-submarine-provider-a" => ProofPlan::LiquidJourney {
            provider_index: 0,
            journey: LiquidJourney::Submarine,
        },
        "route-liquid-submarine-provider-b" => ProofPlan::LiquidJourney {
            provider_index: 1,
            journey: LiquidJourney::Submarine,
        },
        "route-liquid-reverse-provider-a" => ProofPlan::LiquidJourney {
            provider_index: 0,
            journey: LiquidJourney::Reverse,
        },
        "route-liquid-reverse-provider-b" => ProofPlan::LiquidJourney {
            provider_index: 1,
            journey: LiquidJourney::Reverse,
        },
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
        "relay-a-partition" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("relay_loss"),
            outcome: JourneyOutcome::Claimed,
        },
        "relay-b-partition" => ProofPlan::Journey {
            provider_index: 1,
            journey: FundedJourney::Submarine,
            injection: Some("relay_loss"),
            outcome: JourneyOutcome::Claimed,
        },
        "provider-a-crash-restart" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("provider_crash"),
            outcome: JourneyOutcome::Claimed,
        },
        "provider-b-crash-restart" => ProofPlan::Journey {
            provider_index: 1,
            journey: FundedJourney::Submarine,
            injection: Some("provider_crash"),
            outcome: JourneyOutcome::Claimed,
        },
        "wallet-crash-restart" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("wallet_crash"),
            outcome: JourneyOutcome::Claimed,
        },
        "double-reservation" => ProofPlan::DoubleReservation,
        "status-gap" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: "status_gap",
            evidence: "swp_status_gap rejected before external effect",
            expected_code: "swp_status_gap",
            outcome: "rejected_before_effect",
        },
        "status-fork" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: "status_fork",
            evidence: "swp_status_fork rejected before external effect",
            expected_code: "swp_status_fork",
            outcome: "rejected_before_effect",
        },
        "funding-reorg" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("funding_reorg"),
            outcome: JourneyOutcome::Claimed,
        },
        "claim-reorg" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::Submarine,
            injection: Some("claim_reorg"),
            outcome: JourneyOutcome::Claimed,
        },
        "rbf-conflict" => ProofPlan::RbfConflict,
        "wrong-claim-key" => ProofPlan::ExpectedJourneyError {
            provider_index: 0,
            journey: FundedJourney::ReverseClaim,
            injection: "wrong_claim_key",
            evidence: "wrong claim key rejected before external effect",
            expected_code: "rejected_before_effect",
            outcome: "rejected_before_effect",
        },
        "submarine-provider-noncooperative-refund" => ProofPlan::Journey {
            provider_index: 0,
            journey: FundedJourney::SubmarineRefund,
            injection: Some("provider_noncooperative"),
            outcome: JourneyOutcome::Refunded,
        },
        "doomsday-submarine-provider-gone" => {
            ProofPlan::Doomsday(DoomsdayCase::SubmarineProviderGone)
        }
        "doomsday-reverse-coordinator-gone" => {
            ProofPlan::Doomsday(DoomsdayCase::ReverseCoordinatorGone)
        }
        "doomsday-keyless-esplora-broadcast" => {
            ProofPlan::Doomsday(DoomsdayCase::KeylessEsploraBroadcast)
        }
        "doomsday-liquid-submarine-provider-gone" => {
            ProofPlan::Doomsday(DoomsdayCase::LiquidSubmarineProviderGone)
        }
        "doomsday-liquid-reverse-coordinator-gone" => {
            ProofPlan::Doomsday(DoomsdayCase::LiquidReverseCoordinatorGone)
        }
        "musig2-submarine-provider-a" => ProofPlan::Cooperative {
            provider_index: 0,
            journey: CooperativeJourney::Complete,
        },
        "musig2-submarine-provider-b" => ProofPlan::Cooperative {
            provider_index: 1,
            journey: CooperativeJourney::Complete,
        },
        "musig2-abort-script-path" => ProofPlan::Cooperative {
            provider_index: 0,
            journey: CooperativeJourney::AbortAfterProviderNonce,
        },
        "musig2-crash-cut-recovery" => ProofPlan::Cooperative {
            provider_index: 0,
            journey: CooperativeJourney::CrashCutRecovery,
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
        assert_eq!(cases.len(), 43);
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
        assert_eq!(
            cases
                .get("route-chain-btc-to-lbtc-provider-b")
                .and_then(|case| case.provider.as_deref()),
            Some("provider-b")
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
        assert_eq!(supported, 43);
        let unsupported = cases
            .keys()
            .filter(|case_id| matches!(proof_plan(case_id), ProofPlan::Unsupported { .. }))
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert!(unsupported.is_empty());
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
    fn double_reservation_proof_requires_one_live_effect_and_exact_refusal() {
        let proof = json!({
            "proof_class":"live_double_reservation",
            "provider_pubkey":hash("1"),
            "capacity_bucket_id":"lightning-outbound",
            "daemon_reservation_id":hash("9"),
            "active":{
                "session_id":hash("2"),
                "rfq_id":hash("3"),
                "quote_id":hash("4"),
                "reservation_id":hash("5"),
            },
            "refused":{
                "session_id":hash("6"),
                "rfq_id":hash("7"),
                "expected_code":"swp_reservation_overallocated",
                "provider_wire_refusal":null,
                "surface":"lab_process_audit_required",
            },
            "checks":{
                "same_provider":true,
                "same_capacity_bucket":true,
                "overlapping_signed_sessions":true,
                "daemon_backed_hard_reservation_effects":1,
            }
        });
        assert_eq!(
            double_reservation_proof(&proof).expect("process proof should pass"),
            proof
        );
        let mut changed = proof;
        changed["checks"]["daemon_backed_hard_reservation_effects"] = json!(2);
        assert!(double_reservation_proof(&changed).is_err());
    }

    #[test]
    fn journey_proof_binds_external_recovery_to_selected_provider() {
        let result = json!({
            "step":"submarine",
            "provider_pubkey":hash("1"),
            "external_control":{
                "schema":"openagents.immortal.lab-injection-ack.v1",
                "run_id":"run-1",
                "checkpoint":"submarine:funding_effect_recorded",
                "injection":"provider_crash",
                "restored":true,
                "evidence":{
                    "target":"provider-b",
                    "before_pid":101,
                    "after_pid":202,
                    "transition":"process_replaced_and_ready",
                }
            },
            "journey":{
                "order_id":hash("2"),
                "lockup_txid":hash("3"),
                "lockup_vout":0,
                "payment_hash":hash("4"),
                "claim_txid":hash("5"),
                "result":"claimed",
            }
        });
        let proof = journey_proof(
            &result,
            1,
            FundedJourney::Submarine,
            Some("provider_crash"),
            JourneyOutcome::Claimed,
        )
        .expect("provider crash proof should bind provider B");
        assert_eq!(
            proof.pointer("/external_control/evidence/target"),
            Some(&Value::String("provider-b".to_owned()))
        );

        let mut wrong_target = result.clone();
        wrong_target["external_control"]["evidence"]["target"] =
            Value::String("provider-a".to_owned());
        assert!(
            journey_proof(
                &wrong_target,
                1,
                FundedJourney::Submarine,
                Some("provider_crash"),
                JourneyOutcome::Claimed,
            )
            .is_err()
        );

        let mut wallet = result;
        wallet["external_control"]["injection"] = Value::String("wallet_crash".to_owned());
        wallet["external_control"]["evidence"]["target"] =
            Value::String("wallet-driver".to_owned());
        let proof = journey_proof(
            &wallet,
            1,
            FundedJourney::Submarine,
            Some("wallet_crash"),
            JourneyOutcome::Claimed,
        )
        .expect("wallet crash proof should bind the wallet driver");
        assert_eq!(
            proof.pointer("/external_control/evidence/target"),
            Some(&Value::String("wallet-driver".to_owned()))
        );
    }

    #[test]
    fn submarine_refund_proof_binds_timeout_nodes_and_stopped_provider() {
        let result = json!({
            "step":"submarine_refund",
            "provider_pubkey":hash("1"),
            "external_control":{
                "schema":"openagents.immortal.lab-injection-ack.v1",
                "run_id":"run-2",
                "checkpoint":"submarine_refund:funding_effect_recorded",
                "injection":"provider_noncooperative",
                "restored":false,
                "evidence":{
                    "target":"provider-a",
                    "before_pid":303,
                    "transition":"process_stopped",
                }
            },
            "journey":{
                "order_id":hash("2"),
                "lockup_txid":hash("3"),
                "lockup_vout":0,
                "payment_hash":hash("4"),
                "funding_confirmation_height":110,
                "refund_lock_height":116,
                "refund_txid":hash("5"),
                "exit_package_mode":"wallet_sign",
                "client_recovery_action":"request_wallet_refund",
                "both_bitcoind_nodes_agree":true,
                "provider_claim_effects":0,
                "lightning_state":"unpaid_final",
                "result":"refunded",
            }
        });
        let proof = journey_proof(
            &result,
            0,
            FundedJourney::SubmarineRefund,
            Some("provider_noncooperative"),
            JourneyOutcome::Refunded,
        )
        .expect("submarine refund should produce a bounded proof");
        assert_eq!(
            proof.pointer("/external_control/evidence/transition"),
            Some(&Value::String("process_stopped".to_owned()))
        );
        assert_eq!(
            proof.pointer("/checks/provider_claim_effects"),
            Some(&json!(0))
        );
        assert_eq!(proof.get("funding_confirmation_height"), Some(&json!(110)));
        assert_eq!(proof.get("refund_lock_height"), Some(&json!(116)));

        let mut false_agreement = result;
        false_agreement["journey"]["both_bitcoind_nodes_agree"] = Value::Bool(false);
        assert!(
            journey_proof(
                &false_agreement,
                0,
                FundedJourney::SubmarineRefund,
                Some("provider_noncooperative"),
                JourneyOutcome::Refunded,
            )
            .is_err()
        );
    }

    #[test]
    fn journey_proof_retains_exact_chain_recovery_lineage() {
        let result = json!({
            "step":"submarine",
            "provider_pubkey":hash("1"),
            "external_control":{
                "schema":"openagents.immortal.lab-injection-ack.v1",
                "run_id":"run-1",
                "checkpoint":"submarine:funding_reorg_control",
                "injection":"funding_reorg",
                "restored":true,
                "evidence":{
                    "target":"provider-a",
                    "transaction_id":hash("3"),
                    "orphaned_block_hash":hash("6"),
                    "competing_tip_hash":hash("7"),
                    "reconfirmed_block_hash":hash("8"),
                    "transition":"funding_reorg_waited_and_resumed",
                    "wait_state":"funding_observed_without_finality",
                    "recovery_state":"funding_final_after_reconfirmation",
                }
            },
            "journey":{
                "order_id":hash("2"),
                "lockup_txid":hash("3"),
                "lockup_vout":0,
                "payment_hash":hash("4"),
                "claim_txid":hash("5"),
                "result":"claimed",
            }
        });
        let proof = journey_proof(
            &result,
            0,
            FundedJourney::Submarine,
            Some("funding_reorg"),
            JourneyOutcome::Claimed,
        )
        .expect("funding reorg proof should bind provider A");
        assert_eq!(
            proof.pointer("/external_control/evidence/orphaned_block_hash"),
            Some(&Value::String(hash("6")))
        );
        let mut wrong_transaction = result;
        wrong_transaction["external_control"]["evidence"]["transaction_id"] =
            Value::String(hash("9"));
        assert!(
            journey_proof(
                &wrong_transaction,
                0,
                FundedJourney::Submarine,
                Some("funding_reorg"),
                JourneyOutcome::Claimed,
            )
            .is_err()
        );
    }

    #[test]
    fn rbf_proof_requires_distinct_real_conflict_and_no_effect() {
        let result = json!({
            "step":"submarine",
            "provider_pubkey":hash("1"),
            "journey":{
                "order_id":hash("2"),
                "payment_hash":hash("3"),
                "committed_txid":hash("4"),
                "conflict_txid":hash("5"),
                "input_txid":hash("6"),
                "input_vout":1,
                "expected_code":"swp_rbf_policy_violation",
                "outcome":"rejected_before_effect",
                "conflict_in_mempool":true,
                "committed_broadcast_rejected":true,
                "external_settlement_effects":0,
            }
        });
        let proof = rbf_conflict_proof(&result).expect("real conflict proof should pass");
        assert_eq!(
            proof.get("proof_class").and_then(Value::as_str),
            Some("real_same_input_conflict")
        );
        let mut same_transaction = result;
        same_transaction["journey"]["conflict_txid"] = Value::String(hash("4"));
        assert!(rbf_conflict_proof(&same_transaction).is_err());
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
