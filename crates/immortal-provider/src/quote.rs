use crate::{
    bitcoind::ChainTip,
    pricing::{production_claim_leaf_script, production_refund_leaf_script},
    wallet::{BitcoinNetwork as WalletNetwork, ProviderWallet, WalletError, WalletPath},
};
use immortal_client::mkt_swp_client::provider_support::{
    canonical_json, reject_custody_material, validate_quote_against_rfq, validate_quote_profile,
};
use immortal_core::{
    domain::{
        Event, MKT_RFQ_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MktProfileSupport,
        validate_mkt_private_raw,
    },
    mkt_swp_verify::{
        BitcoinNetwork, VerificationError, musig2_aggregate_key, parse_bolt11,
        parse_swap_leaf_script, sha256, tapbranch_hash, tapleaf_hash, taproot_output_key,
        verify_control_block,
    },
};
use secp256k1::{PublicKey, XOnlyPublicKey};
use serde_json::{Map, Value, json};
use std::fmt;

const SCRIPT_MODE: &str = "taproot-musig2-script-exit";
const BITCOIN_VERIFIER: &str = "mkt-swp-bitcoin-v1";
const LIGHTNING_VERIFIER: &str = "mkt-swp-lightning-v1";
pub(crate) const MAX_INVOICE_SECONDS: u64 = 60 * 60 * 24 * 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementPolicy {
    Reject,
    Track,
}

impl ReplacementPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Track => "track",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedQuotePolicy<'a> {
    pub network_id: &'a str,
    pub cooperative_signing: bool,
    pub lightning_current_height: u32,
    pub fee_bps: u16,
    pub miner_fee_budget_sat: u64,
    pub lightning_routing_fee_budget_sat: u64,
    pub minimum_confirmations: u32,
    pub reorg_safety_blocks: u32,
    pub zero_confirmation: bool,
    pub rbf: ReplacementPolicy,
    pub replacement: ReplacementPolicy,
    pub quote_validity_seconds: u64,
    pub funding_window_blocks: u32,
    pub broadcast_safety_blocks: u32,
    pub lightning_settlement_blocks: u32,
    pub expected_block_seconds: u64,
    pub clock_skew_seconds: u32,
    pub recovery_target_blocks: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteWalletAllocation {
    pub unilateral_path: WalletPath,
    pub cooperative_path: WalletPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltFundedQuote {
    pub profile: Value,
    pub expiration: u64,
    pub input_amount_sat: u64,
    pub output_amount_sat: u64,
    pub reserved_asset_id: String,
    pub reserved_amount_sat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteBuildError {
    pub code: &'static str,
    detail: &'static str,
}

impl QuoteBuildError {
    pub const fn new(code: &'static str, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for QuoteBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for QuoteBuildError {}

pub fn build_funded_quote(
    rfq: &Event,
    raw_invoice: &str,
    wallet: &ProviderWallet,
    allocation: QuoteWalletAllocation,
    chain_tip: &ChainTip,
    policy: FundedQuotePolicy<'_>,
    now: u64,
) -> Result<BuiltFundedQuote, QuoteBuildError> {
    validate_policy(policy)?;
    validate_chain_tip(chain_tip)?;
    validate_rfq_event(rfq)?;
    if allocation.unilateral_path == allocation.cooperative_path {
        return Err(error(
            "swp_terms_mismatch",
            "provider unilateral and cooperative paths must be distinct",
        ));
    }

    let rfq_expiration = exact_tag(rfq, "expiration")?
        .parse::<u64>()
        .map_err(|_| error("swp_quote_expired", "RFQ expiration is invalid"))?;
    let profile: Value = serde_json::from_str(&rfq.content)
        .map_err(|_| error("swp_contract_terms_mismatch", "RFQ content is invalid"))?;
    reject_custody_material(&profile).map_err(|protocol| error(protocol.code, "RFQ is unsafe"))?;
    let root = object(Some(&profile), "RFQ envelope")?;
    if root.get("profile").and_then(Value::as_str) != Some(MKT_SWP_PROFILE_ID)
        || root.get("profile_version").and_then(Value::as_u64) != Some(MKT_SWP_PROFILE_VERSION)
    {
        return Err(error(
            "swp_unsupported_profile",
            "RFQ profile tuple is unsupported",
        ));
    }
    let mkt_swp = object(root.get("mkt_swp"), "RFQ MKT-SWP profile")?;
    validate_rfq_extensions(mkt_swp)?;
    let constraints = object(mkt_swp.get("constraints"), "RFQ constraints")?;
    validate_constraint_extensions(constraints)?;

    let swap_type = match string(constraints, "swap_type")? {
        "submarine" => SwapType::Submarine,
        "reverse" => SwapType::Reverse,
        "chain" => {
            return Err(error(
                "swp_unsupported_extension",
                "chain swaps need two independently observed bitcoind networks",
            ));
        }
        _ => {
            return Err(error(
                "swp_unsupported_extension",
                "swap type is unsupported in funded v1",
            ));
        }
    };
    let cooperative_execution = policy.cooperative_signing && swap_type == SwapType::Submarine;
    match (swap_type, mkt_swp.get("invoice")) {
        (SwapType::Submarine, Some(Value::String(invoice))) if invoice == raw_invoice => {}
        (SwapType::Submarine, _) => {
            return Err(error(
                "swp_invoice_invalid",
                "submarine RFQ does not carry the exact invoice being quoted",
            ));
        }
        (SwapType::Reverse, None) => {}
        (SwapType::Reverse, Some(_)) => {
            return Err(error(
                "swp_unsupported_extension",
                "reverse RFQ must not precommit the provider-created hold invoice",
            ));
        }
    }
    let asset_pair = exact_string_pair(constraints, "asset_pair")?;
    validate_asset_pair(swap_type, &asset_pair, policy.network_id)?;
    let input_amount = canonical_positive_amount(string(constraints, "input_amount")?)?;
    let maximum_total_fee =
        canonical_amount(string(constraints, "maximum_total_fee")?, "swp_invalid_fee")?;
    let payment_hash = lower_hex_32(string(constraints, "payment_hash")?, "payment hash")?;
    let requester_key = requester_key(constraints, swap_type)?;
    validate_requested_policy(constraints, policy)?;

    let invoice = parse_bolt11(raw_invoice)
        .map_err(|_| error("swp_invoice_invalid", "BOLT11 invoice is invalid"))?;
    validate_invoice_network(invoice.network, wallet.network())?;
    if invoice.payment_hash != payment_hash {
        return Err(error(
            "swp_payment_hash_mismatch",
            "invoice and RFQ payment hashes differ",
        ));
    }
    let invoice_digest = lower_hex(&sha256(raw_invoice.as_bytes()));
    match swap_type {
        SwapType::Submarine if string(constraints, "invoice_sha256")? != invoice_digest => {
            return Err(error(
                "swp_invoice_invalid",
                "invoice bytes differ from the RFQ digest",
            ));
        }
        SwapType::Submarine => {}
        SwapType::Reverse
            if !matches!(constraints.get("invoice_sha256"), None | Some(Value::Null)) =>
        {
            return Err(error(
                "swp_contract_terms_mismatch",
                "reverse RFQ must not precommit a provider-created invoice digest",
            ));
        }
        SwapType::Reverse => {}
    }
    let invoice_amount_msat = invoice.amount_msat.ok_or_else(|| {
        error(
            "swp_invoice_invalid",
            "amountless invoices are unsupported in v1",
        )
    })?;
    if invoice_amount_msat % 1_000 != 0 {
        return Err(error(
            "swp_invoice_invalid",
            "invoice amount is not an exact satoshi amount",
        ));
    }
    if invoice.expiry_seconds == 0 || invoice.expiry_seconds > MAX_INVOICE_SECONDS {
        return Err(error(
            "swp_invoice_invalid",
            "invoice expiry is outside the funded v1 bound",
        ));
    }
    if invoice.minimum_final_cltv_delta == 0
        || u32::try_from(invoice.minimum_final_cltv_delta).is_err()
    {
        return Err(error(
            "swp_invoice_invalid",
            "invoice final CLTV delta is outside the funded v1 bound",
        ));
    }
    let invoice_expiration = invoice
        .timestamp
        .checked_add(invoice.expiry_seconds)
        .ok_or_else(|| error("swp_invoice_invalid", "invoice expiry overflows"))?;
    if invoice_expiration <= now {
        return Err(error("swp_invoice_invalid", "invoice is expired"));
    }

    let provider_fee = u64::try_from(
        u128::from(input_amount)
            .checked_mul(u128::from(policy.fee_bps))
            .ok_or_else(|| error("swp_invalid_fee", "provider fee overflows"))?
            / 10_000,
    )
    .map_err(|_| error("swp_invalid_fee", "provider fee exceeds u64"))?;
    let total_fee = provider_fee
        .checked_add(policy.miner_fee_budget_sat)
        .and_then(|fee| fee.checked_add(policy.lightning_routing_fee_budget_sat))
        .ok_or_else(|| error("swp_invalid_fee", "quoted fee total overflows"))?;
    if total_fee > maximum_total_fee {
        return Err(error(
            "swp_invalid_fee",
            "quoted fee exceeds the RFQ maximum",
        ));
    }
    let output_amount = input_amount
        .checked_sub(total_fee)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| error("swp_invalid_amount", "fees consume the quoted input"))?;
    let lightning_amount = match swap_type {
        SwapType::Submarine => output_amount,
        SwapType::Reverse => input_amount,
    };
    if lightning_amount.checked_mul(1_000) != Some(invoice_amount_msat) {
        return Err(error(
            "swp_invoice_invalid",
            "invoice amount differs from the quoted Lightning leg",
        ));
    }

    let desired_completion_time = constraints
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .filter(|deadline| *deadline > now)
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "desired completion deadline has passed",
            )
        })?;
    let expiration = now
        .checked_add(policy.quote_validity_seconds)
        .map(|expiration| expiration.min(rfq_expiration).min(invoice_expiration))
        .filter(|expiration| *expiration > now)
        .ok_or_else(|| error("swp_quote_expired", "Quote has no safe acceptance window"))?;

    let unilateral = wallet
        .derive_address(allocation.unilateral_path)
        .map_err(wallet_error)?;
    let cooperative = wallet
        .derive_address(allocation.cooperative_path)
        .map_err(wallet_error)?;
    if unilateral.internal_key == cooperative.internal_key
        || unilateral.internal_key == requester_key.serialize()
        || cooperative.internal_key == requester_key.serialize()
    {
        return Err(error(
            "swp_terms_mismatch",
            "participant execution keys must be distinct",
        ));
    }

    let bitcoin_amount = match swap_type {
        SwapType::Submarine => input_amount,
        SwapType::Reverse => output_amount,
    };
    let ladder = build_timeout_ladder(
        swap_type,
        chain_tip,
        &invoice,
        policy,
        now,
        expiration,
        desired_completion_time,
    )?;
    let refund_height = ladder.refund_height;
    let provider_unilateral = XOnlyPublicKey::from_byte_array(unilateral.internal_key)
        .map_err(|_| error("swp_script_invalid", "provider unilateral key is invalid"))?;
    let (claim_key, refund_key, claim_role, refund_role, selected_path) = match swap_type {
        SwapType::Submarine => (
            provider_unilateral,
            requester_key,
            "provider",
            "requester",
            "refund",
        ),
        SwapType::Reverse => (
            requester_key,
            provider_unilateral,
            "requester",
            "provider",
            "claim",
        ),
    };
    let taproot = build_taproot(
        payment_hash,
        claim_key,
        refund_key,
        refund_height,
        requester_key,
        cooperative.internal_key,
        claim_role,
        refund_role,
    )?;

    let zero_confirmation = if policy.zero_confirmation {
        "allowed"
    } else {
        "forbidden"
    };
    let confirmation_policy = json!({
        "minimum_confirmations":policy.minimum_confirmations.to_string(),
        "reorg_safety_blocks":policy.reorg_safety_blocks.to_string(),
        "zero_confirmation":zero_confirmation,
        "rbf":policy.rbf.as_str(),
        "replacement":policy.replacement.as_str(),
    });
    let bitcoin_leg_id = match swap_type {
        SwapType::Submarine => "source",
        SwapType::Reverse => "destination",
    };
    let selected_script = if selected_path == "claim" {
        &taproot.claim_script
    } else {
        &taproot.refund_script
    };
    let selected_control_block = if selected_path == "claim" {
        &taproot.claim_control_block
    } else {
        &taproot.refund_control_block
    };
    let evidence_adapter_sha256 = lower_hex(&sha256(b"immortal-provider-local-verifier-v1"));
    let tree = json!([
        {
            "condition":"hashlock",
            "lock_value":null,
            "participant_role":claim_role,
            "path":"claim",
            "script":lower_hex(&taproot.claim_script),
            "signing_pubkey":lower_hex(&claim_key.serialize()),
        },
        {
            "condition":"cltv",
            "lock_value":refund_height.to_string(),
            "participant_role":refund_role,
            "path":"refund",
            "script":lower_hex(&taproot.refund_script),
            "signing_pubkey":lower_hex(&refund_key.serialize()),
        }
    ]);
    let tree_digest =
        lower_hex(&sha256(&canonical_json(&tree).map_err(|_| {
            error("swp_script_invalid", "Taproot tree is not canonical")
        })?));
    let mut bitcoin_verifier = json!({
        "amount":bitcoin_amount.to_string(),
        "chain_tip_hash":chain_tip.hash,
        "chain_tip_height":chain_tip.height.to_string(),
        "claim_script":lower_hex(&taproot.claim_script),
        "cooperative_internal_key":lower_hex(&taproot.internal_key.serialize()),
        "cooperative_pubkeys":[
            {"participant_role":"requester", "public_key":compressed_even(requester_key)},
            {"participant_role":"provider", "public_key":compressed_even(
                XOnlyPublicKey::from_byte_array(cooperative.internal_key).map_err(|_| {
                    error("swp_script_invalid", "provider cooperative key is invalid")
                })?
            )}
        ],
        "evidence_authority":{
            "adapter_sha256":evidence_adapter_sha256,
            "mode":"local",
            "pubkeys":[]
        },
        "exit_condition":if selected_path == "claim" { "hashlock" } else { "cltv" },
        "exit_lock_value":if selected_path == "claim" { Value::Null } else { Value::String(refund_height.to_string()) },
        "exit_path":selected_path,
        "exit_signing_pubkey":lower_hex(&requester_key.serialize()),
        "leg_id":bitcoin_leg_id,
        "minimum_confirmations":policy.minimum_confirmations.to_string(),
        "musig2_execution":cooperative_execution,
        "rbf_policy":policy.rbf.as_str(),
        "refund_script":lower_hex(&taproot.refund_script),
        "reorg_safety_blocks":policy.reorg_safety_blocks.to_string(),
        "replacement_policy":policy.replacement.as_str(),
        "script_pubkey":lower_hex(&taproot.script_pubkey),
        "sighash_policy":if cooperative_execution {
            "default_key_path_with_script_fallback"
        } else {
            "default_script_path_only"
        },
        "swap_tree_sha256":tree_digest,
        "taproot_claim_control_block":lower_hex(&taproot.claim_control_block),
        "taproot_control_block":lower_hex(selected_control_block),
        "taproot_merkle_root":lower_hex(&taproot.merkle_root),
        "taproot_output_key":lower_hex(&taproot.output_key.serialize()),
        "taproot_refund_control_block":lower_hex(&taproot.refund_control_block),
        "taproot_script":lower_hex(selected_script),
        "taproot_tree":tree,
        "verifier_policy":BITCOIN_VERIFIER,
        "zero_confirmation":zero_confirmation,
    });
    if cooperative_execution {
        let verifier = bitcoin_verifier
            .as_object_mut()
            .ok_or_else(|| error("swp_script_invalid", "Bitcoin verifier is not an object"))?;
        verifier.insert(
            "provider_exit_destination_script_pubkey".to_owned(),
            Value::String(lower_hex(&unilateral.script_pubkey)),
        );
        verifier.insert(
            "provider_exit_signer_ref".to_owned(),
            Value::String(format!(
                "immortal-provider:{bitcoin_leg_id}:{}",
                if swap_type == SwapType::Submarine {
                    "claim"
                } else {
                    "refund"
                }
            )),
        );
        verifier.insert(
            "provider_exit_policy".to_owned(),
            json!({
                "earliest_broadcast_height":chain_tip.height.to_string(),
                "latest_safe_broadcast_height":ladder.value
                    .get("claim_last")
                    .and_then(Value::as_u64)
                    .map(|height| height.to_string())
                    .ok_or_else(|| error("swp_timeout_ladder_unsafe", "submarine claim deadline is missing"))?,
                "bump_mode":"cpfp",
                "maximum_fee":policy.miner_fee_budget_sat.to_string(),
                "target_blocks":policy.recovery_target_blocks,
            }),
        );
    }
    let lightning_verifier = json!({
        "evidence_authority":{
            "adapter_sha256":lower_hex(&sha256(b"immortal-provider-local-verifier-v1")),
            "mode":"local",
            "pubkeys":[]
        },
        "invoice_amount_msat":invoice_amount_msat.to_string(),
        "invoice_expiration_time":invoice_expiration,
        "invoice_expiry_seconds":invoice.expiry_seconds.to_string(),
        "invoice_minimum_final_cltv_delta":invoice.minimum_final_cltv_delta.to_string(),
        "invoice_network":invoice_network_name(invoice.network),
        "invoice_sha256":invoice_digest,
        "leg_id":"lightning",
        "payment_hash":lower_hex(&payment_hash),
        "verifier_policy":LIGHTNING_VERIFIER,
    });
    let bitcoin_verifier_digest = verifier_digest(&bitcoin_verifier)?;
    let lightning_verifier_digest = verifier_digest(&lightning_verifier)?;
    let bitcoin_leg = json!({
        "amount":bitcoin_amount.to_string(),
        "asset_id":asset_pair[if swap_type == SwapType::Submarine { 0 } else { 1 }],
        "claim_public_key":lower_hex(&claim_key.serialize()),
        "claim_script":lower_hex(&taproot.claim_script),
        "confirmation_policy":{
            "minimum_confirmations":policy.minimum_confirmations.to_string(),
            "replacement_policy":policy.replacement.as_str()
        },
        "funding_role":if swap_type == SwapType::Submarine { "requester" } else { "provider" },
        "leg_id":bitcoin_leg_id,
        "network_id":policy.network_id,
        "payment_hash":lower_hex(&payment_hash),
        "rail":"bitcoin",
        "receiving_role":if swap_type == SwapType::Submarine { "provider" } else { "requester" },
        "refund_condition":"cltv",
        "refund_control_block":lower_hex(&taproot.refund_control_block),
        "refund_lock_value":refund_height.to_string(),
        "refund_public_key":lower_hex(&refund_key.serialize()),
        "refund_script":lower_hex(&taproot.refund_script),
        "script_pubkey":lower_hex(&taproot.script_pubkey),
        "verifier_digest":bitcoin_verifier_digest,
        "verifier_policy":BITCOIN_VERIFIER,
    });
    let lightning_leg = json!({
        "amount":lightning_amount.to_string(),
        "asset_id":asset_pair[if swap_type == SwapType::Submarine { 1 } else { 0 }],
        "funding_role":if swap_type == SwapType::Submarine { "provider" } else { "requester" },
        "invoice_expiry_seconds":invoice.expiry_seconds.to_string(),
        "invoice_minimum_final_cltv_delta":invoice.minimum_final_cltv_delta.to_string(),
        "invoice_sha256":invoice_digest,
        "leg_id":"lightning",
        "network_id":policy.network_id,
        "payment_hash":lower_hex(&payment_hash),
        "rail":"lightning",
        "receiving_role":if swap_type == SwapType::Submarine { "requester" } else { "provider" },
        "verifier_digest":lightning_verifier_digest,
        "verifier_policy":LIGHTNING_VERIFIER,
    });
    let (legs, verifier_inputs) = match swap_type {
        SwapType::Submarine => (
            vec![bitcoin_leg, lightning_leg],
            vec![bitcoin_verifier, lightning_verifier],
        ),
        SwapType::Reverse => (
            vec![lightning_leg, bitcoin_leg],
            vec![bitcoin_verifier, lightning_verifier],
        ),
    };
    let maximum_custody_seconds = u64::from(refund_height)
        .checked_sub(chain_tip.height)
        .and_then(|blocks| blocks.checked_mul(policy.expected_block_seconds))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "custody estimate overflows"))?;
    let mut effects = if swap_type == SwapType::Submarine {
        vec![
            json!({"actor":"requester","effect_role":"chain_fund","leg_id":"source"}),
            json!({"actor":"provider","effect_role":"chain_claim","leg_id":"source"}),
            json!({"actor":"requester","effect_role":"chain_refund","leg_id":"source"}),
            json!({"actor":"provider","effect_role":"invoice_pay","leg_id":"lightning"}),
        ]
    } else {
        vec![
            json!({"actor":"provider","effect_role":"invoice_create","leg_id":"lightning"}),
            json!({"actor":"requester","effect_role":"invoice_pay","leg_id":"lightning"}),
            json!({"actor":"provider","effect_role":"invoice_settle","leg_id":"lightning"}),
            json!({"actor":"provider","effect_role":"invoice_cancel","leg_id":"lightning"}),
            json!({"actor":"provider","effect_role":"chain_fund","leg_id":"destination"}),
            json!({"actor":"requester","effect_role":"chain_claim","leg_id":"destination"}),
            json!({"actor":"provider","effect_role":"chain_refund","leg_id":"destination"}),
        ]
    };
    if cooperative_execution {
        effects.push(json!({
            "actor":"provider",
            "effect_role":"cooperative_sign",
            "leg_id":bitcoin_leg_id,
        }));
    }
    let terms = json!({
        "amount_equation":"input_minus_provider_and_quoted_fees",
        "asset_pair":asset_pair,
        "cancellation":{"effective_before_external_effect":true},
        "clock_skew_seconds":policy.clock_skew_seconds.to_string(),
        "confirmation_policy":confirmation_policy,
        "custody":{
            "credential_exposure":"none",
            "execution_control":["verified_taproot_script_paths"],
            "funds_control":["participant_funded_legs"],
            "maximum_custody_duration_seconds":maximum_custody_seconds,
            "recourse":["unilateral_script_path"],
            "reversibility":["cltv_refund"],
            "settlement_authority":["bitcoin_consensus","lightning_protocol"]
        },
        "desired_completion_time":desired_completion_time,
        "effect_policy":{
            "effects":effects,
            "id_scheme":"openagents.mkt-swp.v1",
            "order_event_id_required":true,
            "replay":"idempotent_exact_bytes",
        },
        "evidence_requirements":{"minimum_rung":"verified"},
        "evm_leg":null,
        "fee_bps":policy.fee_bps.to_string(),
        "fee_payer":"requester",
        "input_amount":input_amount.to_string(),
        "legs":legs,
        "lightning_routing_fee_budget":policy.lightning_routing_fee_budget_sat.to_string(),
        "maximum_total_fee":total_fee.to_string(),
        "miner_fee_budget":policy.miner_fee_budget_sat.to_string(),
        "musig2_execution":cooperative_execution,
        "output_amount":output_amount.to_string(),
        "payment_hash":lower_hex(&payment_hash),
        "price_feed":null,
        "provider_fee":provider_fee.to_string(),
        "recovery":{
            "channel":"direct_or_relay_agnostic",
            "exit_policy":{
                "bump_mode":"cpfp",
                "earliest_broadcast_height":refund_height.to_string(),
                "latest_safe_broadcast_height":ladder.latest_safe_exit_height.to_string(),
                "maximum_fee":policy.miner_fee_budget_sat.to_string(),
                "target_blocks":policy.recovery_target_blocks
            }
        },
        "reservation_commitment":{},
        "rounding":"floor_output_sats",
        "script_mode":SCRIPT_MODE,
        "swap_type":swap_type.as_str(),
        "timeout_ladder":ladder.value,
        "verifier_inputs":verifier_inputs,
    });
    let profile = json!({
        "critical":["terms"],
        "terms":terms,
    });
    validate_quote_profile(&profile, "none")
        .map_err(|protocol| error(protocol.code, "constructed Quote profile is invalid"))?;
    validate_quote_against_rfq(rfq, &profile, "firm", now, expiration)
        .map_err(|protocol| error(protocol.code, "constructed Quote weakens its RFQ"))?;

    Ok(BuiltFundedQuote {
        profile,
        expiration,
        input_amount_sat: input_amount,
        output_amount_sat: output_amount,
        reserved_asset_id: asset_pair[1].clone(),
        reserved_amount_sat: output_amount,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapType {
    Submarine,
    Reverse,
}

impl SwapType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Submarine => "submarine",
            Self::Reverse => "reverse",
        }
    }
}

struct TimeoutTerms {
    value: Value,
    refund_height: u32,
    latest_safe_exit_height: u32,
}

fn build_timeout_ladder(
    swap_type: SwapType,
    chain_tip: &ChainTip,
    invoice: &immortal_core::mkt_swp_verify::Bolt11Invoice,
    policy: FundedQuotePolicy<'_>,
    now: u64,
    quote_expiration: u64,
    desired_completion_time: u64,
) -> Result<TimeoutTerms, QuoteBuildError> {
    let current_height = u32::try_from(chain_tip.height).map_err(|_| {
        error(
            "swp_timeout_ladder_unsafe",
            "chain height exceeds the v1 range",
        )
    })?;
    validate_lightning_height(current_height, policy)?;
    let acceptance_seconds = quote_expiration
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| error("swp_quote_expired", "Quote acceptance window is empty"))?;
    let acceptance_blocks = acceptance_seconds.div_ceil(policy.expected_block_seconds);
    let acceptance_blocks = u32::try_from(acceptance_blocks).map_err(|_| {
        error(
            "swp_timeout_ladder_unsafe",
            "Quote acceptance window exceeds the ladder height range",
        )
    })?;
    let estimated_acceptance_height = current_height
        .checked_add(acceptance_blocks)
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "acceptance height overflows"))?;
    let first_deadline = estimated_acceptance_height
        .checked_add(policy.funding_window_blocks)
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "funding deadline overflows"))?;
    let claim_last = first_deadline
        .checked_add(policy.minimum_confirmations)
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "claim deadline overflows"))?;
    let refund_first = claim_last
        .checked_add(policy.broadcast_safety_blocks)
        .and_then(|height| height.checked_add(policy.reorg_safety_blocks))
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "refund deadline overflows"))?;
    let post_acceptance_claim_blocks = policy
        .funding_window_blocks
        .checked_add(policy.minimum_confirmations)
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "claim window overflows"))?;
    let expected_claim_time = quote_expiration
        .checked_add(
            u64::from(post_acceptance_claim_blocks)
                .checked_mul(policy.expected_block_seconds)
                .ok_or_else(|| {
                    error("swp_timeout_ladder_unsafe", "claim time estimate overflows")
                })?,
        )
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "claim time overflows"))?;
    if expected_claim_time > desired_completion_time {
        return Err(error(
            "swp_timeout_ladder_unsafe",
            "requested completion deadline is too short",
        ));
    }
    let latest_safe_exit_height = refund_first
        .checked_add(policy.broadcast_safety_blocks)
        .and_then(|height| height.checked_add(policy.reorg_safety_blocks))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "exit deadline overflows"))?;
    match swap_type {
        SwapType::Submarine => {
            let invoice_expiration_time = invoice
                .timestamp
                .checked_add(invoice.expiry_seconds)
                .ok_or_else(|| error("swp_invoice_invalid", "invoice expiry overflows"))?;
            if invoice_expiration_time <= expected_claim_time {
                return Err(error(
                    "swp_timeout_ladder_unsafe",
                    "invoice expires before the safe Lightning payment deadline",
                ));
            }
            Ok(TimeoutTerms {
                value: json!({
                    "swap_type":"submarine",
                    "current_height":current_height,
                    "fund_last":first_deadline,
                    "claim_last":claim_last,
                    "refund_first":refund_first,
                    "chain_finality_blocks":policy.minimum_confirmations,
                    "broadcast_safety_blocks":policy.broadcast_safety_blocks,
                    "reorg_safety_blocks":policy.reorg_safety_blocks,
                    "invoice_expiration_time":invoice_expiration_time,
                    "claim_expected_time":expected_claim_time,
                }),
                refund_height: refund_first,
                latest_safe_exit_height,
            })
        }
        SwapType::Reverse => {
            let hold_delta = u32::try_from(invoice.minimum_final_cltv_delta).map_err(|_| {
                error(
                    "swp_timeout_ladder_unsafe",
                    "invoice final CLTV delta exceeds v1",
                )
            })?;
            let hold_expiry_height = policy
                .lightning_current_height
                .checked_add(hold_delta)
                .ok_or_else(|| {
                    error("swp_timeout_ladder_unsafe", "hold expiry height overflows")
                })?;
            let required_hold_margin = refund_first
                .checked_add(policy.broadcast_safety_blocks)
                .and_then(|height| height.checked_add(policy.lightning_settlement_blocks))
                .ok_or_else(|| error("swp_timeout_ladder_unsafe", "hold margin overflows"))?;
            if required_hold_margin >= hold_expiry_height {
                return Err(error(
                    "swp_timeout_ladder_unsafe",
                    "invoice final CLTV delta cannot preserve provider refund",
                ));
            }
            let invoice_expiration_time = invoice
                .timestamp
                .checked_add(invoice.expiry_seconds)
                .ok_or_else(|| error("swp_invoice_invalid", "invoice expiry overflows"))?;
            // After payment begins, the held HTLC is governed by the CLTV margin
            // checked above; BOLT11 wall-clock expiry only bounds payment initiation.
            if invoice_expiration_time <= quote_expiration {
                return Err(error(
                    "swp_invoice_invalid",
                    "hold invoice expires before the Quote acceptance deadline",
                ));
            }
            Ok(TimeoutTerms {
                value: json!({
                    "swap_type":"reverse",
                    "current_height":current_height,
                    "lock_last":first_deadline,
                    "user_claim_last":claim_last,
                    "provider_refund_first":refund_first,
                    "hold_expiry_height":hold_expiry_height,
                    "chain_finality_blocks":policy.minimum_confirmations,
                    "broadcast_safety_blocks":policy.broadcast_safety_blocks,
                    "reorg_safety_blocks":policy.reorg_safety_blocks,
                    "lightning_settlement_blocks":policy.lightning_settlement_blocks,
                }),
                refund_height: refund_first,
                latest_safe_exit_height,
            })
        }
    }
}

struct TaprootTerms {
    internal_key: XOnlyPublicKey,
    output_key: XOnlyPublicKey,
    merkle_root: [u8; 32],
    script_pubkey: Vec<u8>,
    claim_script: Vec<u8>,
    refund_script: Vec<u8>,
    claim_control_block: Vec<u8>,
    refund_control_block: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn build_taproot(
    payment_hash: [u8; 32],
    claim_key: XOnlyPublicKey,
    refund_key: XOnlyPublicKey,
    refund_height: u32,
    requester_key: XOnlyPublicKey,
    provider_cooperative_key: [u8; 32],
    claim_role: &str,
    refund_role: &str,
) -> Result<TaprootTerms, QuoteBuildError> {
    if claim_role == refund_role || !matches!(claim_role, "requester" | "provider") {
        return Err(error(
            "swp_script_invalid",
            "claim and refund roles are invalid",
        ));
    }
    let claim_script = claim_script(payment_hash, claim_key);
    let refund_script = refund_script(refund_height, refund_key)?;
    let claim_hash = tapleaf_hash(0xc0, &claim_script).map_err(script_error)?;
    let refund_hash = tapleaf_hash(0xc0, &refund_script).map_err(script_error)?;
    let merkle_root = tapbranch_hash(claim_hash, refund_hash);
    let cooperative_keys = [
        PublicKey::from_slice(&compressed_even_bytes(requester_key))
            .map_err(|_| error("swp_script_invalid", "requester cooperative key is invalid"))?,
        PublicKey::from_slice(&compressed_even_raw(provider_cooperative_key))
            .map_err(|_| error("swp_script_invalid", "provider cooperative key is invalid"))?,
    ];
    let internal_key = musig2_aggregate_key(&cooperative_keys).map_err(script_error)?;
    let (output_key, parity) =
        taproot_output_key(internal_key, Some(merkle_root)).map_err(script_error)?;
    let first = 0xc0
        | if parity == secp256k1::Parity::Odd {
            1
        } else {
            0
        };
    let mut claim_control_block = Vec::with_capacity(65);
    claim_control_block.push(first);
    claim_control_block.extend_from_slice(&internal_key.serialize());
    claim_control_block.extend_from_slice(&refund_hash);
    let mut refund_control_block = Vec::with_capacity(65);
    refund_control_block.push(first);
    refund_control_block.extend_from_slice(&internal_key.serialize());
    refund_control_block.extend_from_slice(&claim_hash);
    parse_swap_leaf_script(&claim_script).map_err(script_error)?;
    parse_swap_leaf_script(&refund_script).map_err(script_error)?;
    verify_control_block(&output_key, &claim_script, &claim_control_block).map_err(script_error)?;
    verify_control_block(&output_key, &refund_script, &refund_control_block)
        .map_err(script_error)?;
    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.extend_from_slice(&[0x51, 0x20]);
    script_pubkey.extend_from_slice(&output_key.serialize());
    Ok(TaprootTerms {
        internal_key,
        output_key,
        merkle_root,
        script_pubkey,
        claim_script,
        refund_script,
        claim_control_block,
        refund_control_block,
    })
}

fn claim_script(payment_hash: [u8; 32], signing_key: XOnlyPublicKey) -> Vec<u8> {
    production_claim_leaf_script(payment_hash, signing_key.serialize())
}

fn refund_script(
    refund_height: u32,
    signing_key: XOnlyPublicKey,
) -> Result<Vec<u8>, QuoteBuildError> {
    production_refund_leaf_script(refund_height, signing_key.serialize()).ok_or_else(|| {
        error(
            "swp_timeout_ladder_unsafe",
            "refund height is outside the height-valued CLTV range",
        )
    })
}

fn validate_policy(policy: FundedQuotePolicy<'_>) -> Result<(), QuoteBuildError> {
    validate_network_id(policy.network_id)?;
    if policy.fee_bps > 10_000 {
        return Err(error("swp_invalid_fee", "fee basis points exceed 10000"));
    }
    if policy.minimum_confirmations == 0
        || policy.reorg_safety_blocks == 0
        || policy.quote_validity_seconds == 0
        || policy.funding_window_blocks == 0
        || policy.broadcast_safety_blocks == 0
        || policy.lightning_settlement_blocks == 0
        || policy.expected_block_seconds == 0
        || policy.clock_skew_seconds > 120
        || policy.recovery_target_blocks == 0
    {
        return Err(error(
            "swp_timeout_ladder_unsafe",
            "funded Quote policy has a zero or out-of-range safety bound",
        ));
    }
    Ok(())
}

fn validate_lightning_height(
    current_height: u32,
    policy: FundedQuotePolicy<'_>,
) -> Result<(), QuoteBuildError> {
    let lag = current_height
        .checked_sub(policy.lightning_current_height)
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "CLN height is ahead of the verified bitcoind tip",
            )
        })?;
    if lag > policy.reorg_safety_blocks {
        return Err(error(
            "swp_timeout_ladder_unsafe",
            "CLN height is stale relative to the verified bitcoind tip",
        ));
    }
    Ok(())
}

fn validate_chain_tip(chain_tip: &ChainTip) -> Result<(), QuoteBuildError> {
    lower_hex_32(&chain_tip.hash, "chain tip hash")?;
    u32::try_from(chain_tip.height)
        .map(|_| ())
        .map_err(|_| error("swp_timeout_ladder_unsafe", "chain tip height exceeds v1"))
}

fn validate_rfq_event(rfq: &Event) -> Result<(), QuoteBuildError> {
    if rfq.kind != MKT_RFQ_KIND {
        return Err(error(
            "swp_contract_terms_mismatch",
            "funded Quote input is not an RFQ",
        ));
    }
    let raw = serde_json::to_vec(rfq)
        .map_err(|_| error("swp_contract_terms_mismatch", "RFQ cannot be encoded"))?;
    let support = [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }];
    validate_mkt_private_raw(&raw, &support)
        .map(|_| ())
        .map_err(|_| {
            error(
                "swp_contract_terms_mismatch",
                "RFQ signature or grammar is invalid",
            )
        })
}

fn validate_rfq_extensions(profile: &Map<String, Value>) -> Result<(), QuoteBuildError> {
    if profile
        .keys()
        .any(|name| !matches!(name.as_str(), "constraints" | "critical" | "invoice"))
    {
        return Err(error(
            "swp_unsupported_extension",
            "RFQ contains an unsupported profile extension",
        ));
    }
    if let Some(critical) = profile.get("critical") {
        let critical = critical.as_array().ok_or_else(|| {
            error(
                "swp_unsupported_critical_member",
                "RFQ critical members are invalid",
            )
        })?;
        if critical.is_empty()
            || critical.len() > 2
            || critical.iter().any(|member| {
                !matches!(member.as_str(), Some("constraints" | "invoice"))
                    || member.as_str() == Some("invoice") && !profile.contains_key("invoice")
            })
            || critical.len() == 2 && critical.first() == critical.get(1)
        {
            return Err(error(
                "swp_unsupported_critical_member",
                "RFQ names an unsupported critical member",
            ));
        }
    }
    Ok(())
}

fn validate_constraint_extensions(constraints: &Map<String, Value>) -> Result<(), QuoteBuildError> {
    const SUPPORTED: &[&str] = &[
        "allowed_script_modes",
        "asset_pair",
        "confirmation_policy",
        "desired_completion_time",
        "firm_quote_required",
        "input_amount",
        "invoice_sha256",
        "maximum_total_fee",
        "payment_hash",
        "requester_public_keys",
        "swap_type",
    ];
    if constraints
        .keys()
        .any(|name| !SUPPORTED.contains(&name.as_str()))
    {
        return Err(error(
            "swp_unsupported_extension",
            "RFQ contains a funded-v1 constraint that is not implemented",
        ));
    }
    if SUPPORTED
        .iter()
        .filter(|member| **member != "invoice_sha256")
        .any(|member| !constraints.contains_key(*member))
    {
        return Err(error(
            "swp_contract_terms_mismatch",
            "RFQ omits a funded-v1 constraint",
        ));
    }
    let modes = constraints
        .get("allowed_script_modes")
        .and_then(Value::as_array)
        .filter(|modes| !modes.is_empty() && modes.len() <= 8)
        .ok_or_else(|| {
            error(
                "swp_unsupported_extension",
                "RFQ script mode set is invalid",
            )
        })?;
    if modes.len() != 1 || modes.first().and_then(Value::as_str) != Some(SCRIPT_MODE) {
        return Err(error(
            "swp_unsupported_extension",
            "RFQ requests an unsupported script mode",
        ));
    }
    if constraints
        .get("firm_quote_required")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(error(
            "swp_contract_terms_mismatch",
            "RFQ firm-Quote requirement must be boolean",
        ));
    }
    Ok(())
}

fn validate_requested_policy(
    constraints: &Map<String, Value>,
    policy: FundedQuotePolicy<'_>,
) -> Result<(), QuoteBuildError> {
    let requested = object(
        constraints.get("confirmation_policy"),
        "RFQ confirmation policy",
    )?;
    if requested.len() != 5 {
        return Err(error(
            "swp_unsupported_extension",
            "RFQ confirmation policy shape is unsupported",
        ));
    }
    let minimum = canonical_amount(
        string(requested, "minimum_confirmations")?,
        "swp_terms_mismatch",
    )?;
    let reorg = canonical_amount(
        string(requested, "reorg_safety_blocks")?,
        "swp_terms_mismatch",
    )?;
    let expected_zero = if policy.zero_confirmation {
        "allowed"
    } else {
        "forbidden"
    };
    if u64::from(policy.minimum_confirmations) < minimum
        || u64::from(policy.reorg_safety_blocks) < reorg
        || string(requested, "zero_confirmation")? != expected_zero
        || string(requested, "rbf")? != policy.rbf.as_str()
        || string(requested, "replacement")? != policy.replacement.as_str()
    {
        return Err(error(
            "swp_terms_mismatch",
            "provider confirmation policy weakens the RFQ",
        ));
    }
    Ok(())
}

fn validate_asset_pair(
    swap_type: SwapType,
    pair: &[String; 2],
    network_id: &str,
) -> Result<(), QuoteBuildError> {
    let chain = format!("swp:1:{network_id}:btc:chain");
    let lightning = format!("swp:1:{network_id}:btc:lightning");
    let expected = match swap_type {
        SwapType::Submarine => [&chain, &lightning],
        SwapType::Reverse => [&lightning, &chain],
    };
    if pair[0] != *expected[0] || pair[1] != *expected[1] {
        return Err(error(
            "swp_invalid_pair",
            "RFQ asset pair does not match the funded network and direction",
        ));
    }
    Ok(())
}

fn requester_key(
    constraints: &Map<String, Value>,
    swap_type: SwapType,
) -> Result<XOnlyPublicKey, QuoteBuildError> {
    let keys = constraints
        .get("requester_public_keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 1)
        .ok_or_else(|| {
            error(
                "swp_terms_mismatch",
                "RFQ must bind one requester unilateral key",
            )
        })?;
    let key = object(keys.first(), "requester public key")?;
    if key.len() != 3 {
        return Err(error(
            "swp_unsupported_extension",
            "requester public key shape is unsupported",
        ));
    }
    let (leg_id, path) = match swap_type {
        SwapType::Submarine => ("source", "refund"),
        SwapType::Reverse => ("destination", "claim"),
    };
    if string(key, "leg_id")? != leg_id || string(key, "path")? != path {
        return Err(error(
            "swp_terms_mismatch",
            "requester public key is bound to the wrong leg or path",
        ));
    }
    let bytes = lower_hex_32(string(key, "public_key")?, "requester public key")?;
    XOnlyPublicKey::from_byte_array(bytes)
        .map_err(|_| error("swp_terms_mismatch", "requester public key is invalid"))
}

fn validate_invoice_network(
    invoice: BitcoinNetwork,
    wallet: WalletNetwork,
) -> Result<(), QuoteBuildError> {
    let matches = matches!(
        (invoice, wallet),
        (BitcoinNetwork::Bitcoin, WalletNetwork::Mainnet)
            | (BitcoinNetwork::Testnet, WalletNetwork::Testnet)
            | (BitcoinNetwork::Signet, WalletNetwork::Signet)
            | (BitcoinNetwork::Regtest, WalletNetwork::Regtest)
    );
    if matches {
        Ok(())
    } else {
        Err(error(
            "swp_invoice_invalid",
            "invoice network differs from the provider wallet network",
        ))
    }
}

fn invoice_network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Bitcoin => "bitcoin",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}

fn verifier_digest(verifier: &Value) -> Result<String, QuoteBuildError> {
    canonical_json(verifier)
        .map(|bytes| lower_hex(&sha256(&bytes)))
        .map_err(|_| error("swp_terms_mismatch", "verifier inputs are not canonical"))
}

fn validate_network_id(network_id: &str) -> Result<(), QuoteBuildError> {
    let Some(reference) = network_id.strip_prefix("bip122:") else {
        return Err(error("swp_invalid_asset_id", "network ID is invalid"));
    };
    if reference.len() != 32
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(error("swp_invalid_asset_id", "network ID is invalid"));
    }
    Ok(())
}

fn exact_string_pair(
    object: &Map<String, Value>,
    name: &str,
) -> Result<[String; 2], QuoteBuildError> {
    let pair = object
        .get(name)
        .and_then(Value::as_array)
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| error("swp_invalid_pair", "asset pair must contain two assets"))?;
    let first = pair
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| error("swp_invalid_asset_id", "input asset is invalid"))?;
    let second = pair
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| error("swp_invalid_asset_id", "output asset is invalid"))?;
    Ok([first.to_owned(), second.to_owned()])
}

fn object<'a>(
    value: Option<&'a Value>,
    label: &'static str,
) -> Result<&'a Map<String, Value>, QuoteBuildError> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| error("swp_contract_terms_mismatch", label))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, QuoteBuildError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| error("swp_contract_terms_mismatch", name))
}

fn canonical_positive_amount(value: &str) -> Result<u64, QuoteBuildError> {
    canonical_amount(value, "swp_invalid_amount").and_then(|amount| {
        if amount == 0 {
            Err(error("swp_invalid_amount", "amount must be positive"))
        } else {
            Ok(amount)
        }
    })
}

fn canonical_amount(value: &str, code: &'static str) -> Result<u64, QuoteBuildError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(error(code, "decimal amount is not canonical"));
    }
    value
        .parse::<u64>()
        .map_err(|_| error(code, "decimal amount exceeds u64"))
}

fn lower_hex_32(value: &str, label: &'static str) -> Result<[u8; 32], QuoteBuildError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(error("swp_terms_mismatch", label));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| error("swp_terms_mismatch", label))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| error("swp_terms_mismatch", label))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn compressed_even(key: XOnlyPublicKey) -> String {
    lower_hex(&compressed_even_bytes(key))
}

fn compressed_even_bytes(key: XOnlyPublicKey) -> [u8; 33] {
    compressed_even_raw(key.serialize())
}

fn compressed_even_raw(key: [u8; 32]) -> [u8; 33] {
    let mut compressed = [0_u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&key);
    compressed
}

fn exact_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str, QuoteBuildError> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| tag.name() == Some(name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [tag] if tag.as_slice().len() == 2 => tag
            .value()
            .ok_or_else(|| error("swp_contract_terms_mismatch", "RFQ tag is empty")),
        _ => Err(error(
            "swp_contract_terms_mismatch",
            "RFQ requires one exact tag",
        )),
    }
}

fn wallet_error(_error: WalletError) -> QuoteBuildError {
    error(
        "swp_script_invalid",
        "provider wallet could not derive Quote keys",
    )
}

fn script_error(_error: VerificationError) -> QuoteBuildError {
    error(
        "swp_script_invalid",
        "provider could not construct the Taproot commitment",
    )
}

const fn error(code: &'static str, detail: &'static str) -> QuoteBuildError {
    QuoteBuildError::new(code, detail)
}
