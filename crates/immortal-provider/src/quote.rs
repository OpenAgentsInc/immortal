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
    liquid::{
        LiquidAssetId, liquid_tapbranch_hash, liquid_tapleaf_hash, liquid_taproot_output_key,
        verify_liquid_control_block,
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
const LIQUID_BLOCK_INTERVAL_SECONDS: u64 = 60;
const LIGHTNING_BLOCK_INTERVAL_SECONDS: u64 = 600;
const CROSS_DOMAIN_SAFETY_SECONDS: u64 = 3_600;
const HEIGHT_OBSERVATION_MAX_AGE_SECONDS: u32 = 120;

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
    pub liquid: Option<LiquidQuotePolicy<'a>>,
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
pub struct LiquidQuotePolicy<'a> {
    pub network_id: &'a str,
    pub pegged_asset: LiquidAssetId,
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
    let chain_rail = validate_asset_pair(swap_type, &asset_pair, policy)?;
    let cooperative_execution = policy.cooperative_signing
        && swap_type == SwapType::Submarine
        && matches!(chain_rail, ChainRail::Bitcoin);
    let input_amount = canonical_positive_amount(string(constraints, "input_amount")?)?;
    let maximum_total_fee =
        canonical_amount(string(constraints, "maximum_total_fee")?, "swp_invalid_fee")?;
    let payment_hash = lower_hex_32(string(constraints, "payment_hash")?, "payment hash")?;
    let destination_commitment = match constraints.get("destination_commitment_sha256") {
        None => None,
        Some(Value::String(value)) => {
            Some(lower_hex(&lower_hex_32(value, "destination commitment")?))
        }
        Some(_) => {
            return Err(error(
                "swp_contract_terms_mismatch",
                "RFQ destination commitment is not lowercase hex",
            ));
        }
    };
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
        chain_rail,
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
        chain_rail,
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
        "taproot_internal_key":lower_hex(&taproot.internal_key.serialize()),
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
    let chain_network_id = match chain_rail {
        ChainRail::Bitcoin => policy.network_id,
        ChainRail::Liquid(liquid) => liquid.network_id,
    };
    let chain_verifier_policy = match chain_rail {
        ChainRail::Bitcoin => BITCOIN_VERIFIER,
        ChainRail::Liquid(_) => "mkt-swp-liquid-v1",
    };
    let chain_rail_name = match chain_rail {
        ChainRail::Bitcoin => "bitcoin",
        ChainRail::Liquid(_) => "liquid",
    };
    if let ChainRail::Liquid(liquid) = chain_rail {
        let verifier = bitcoin_verifier
            .as_object_mut()
            .ok_or_else(|| error("swp_liquid_output_invalid", "Liquid verifier is invalid"))?;
        let mut wire_asset = liquid.pegged_asset.display_bytes();
        wire_asset.reverse();
        let mut serialized_asset = String::from("01");
        serialized_asset.push_str(&lower_hex(&wire_asset));
        let mut serialized_value = String::from("01");
        serialized_value.push_str(&lower_hex(&bitcoin_amount.to_be_bytes()));
        verifier.insert(
            "asset_id".to_owned(),
            Value::String(
                asset_pair[if swap_type == SwapType::Submarine {
                    0
                } else {
                    1
                }]
                .clone(),
            ),
        );
        verifier.insert(
            "network_id".to_owned(),
            Value::String(liquid.network_id.to_owned()),
        );
        verifier.insert(
            "confidentiality".to_owned(),
            Value::String("explicit".to_owned()),
        );
        verifier.insert(
            "serialized_commitments".to_owned(),
            json!({
                "asset":serialized_asset,
                "value":serialized_value,
                "nonce":"00",
                "rangeproof_sha256":null,
                "surjectionproof_sha256":null,
            }),
        );
        verifier.insert(
            "verifier_policy".to_owned(),
            Value::String(chain_verifier_policy.to_owned()),
        );
        verifier.insert(
            "evidence_authority".to_owned(),
            json!({
                "adapter_sha256":lower_hex(&sha256(b"immortal-provider-elementsd-v1")),
                "mode":"local_elementsd_unblind",
                "pubkeys":[]
            }),
        );
    }
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
        "network_id":chain_network_id,
        "payment_hash":lower_hex(&payment_hash),
        "rail":chain_rail_name,
        "receiving_role":if swap_type == SwapType::Submarine { "provider" } else { "requester" },
        "refund_condition":"cltv",
        "refund_control_block":lower_hex(&taproot.refund_control_block),
        "refund_lock_value":refund_height.to_string(),
        "refund_public_key":lower_hex(&refund_key.serialize()),
        "refund_script":lower_hex(&taproot.refund_script),
        "script_pubkey":lower_hex(&taproot.script_pubkey),
        "verifier_digest":bitcoin_verifier_digest,
        "verifier_policy":chain_verifier_policy,
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
    let mut terms = json!({
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
            "settlement_authority":[if chain_rail_name == "liquid" { "elements_consensus" } else { "bitcoin_consensus" },"lightning_protocol"]
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
    if let Some(commitment) = destination_commitment {
        terms
            .as_object_mut()
            .ok_or_else(|| error("swp_contract_terms_mismatch", "Quote terms are invalid"))?
            .insert(
                "destination_commitment_sha256".to_owned(),
                Value::String(commitment),
            );
    }
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

pub fn build_funded_chain_quote(
    rfq: &Event,
    wallet: &ProviderWallet,
    allocation: QuoteWalletAllocation,
    bitcoin_tip: &ChainTip,
    liquid_tip: &ChainTip,
    policy: FundedQuotePolicy<'_>,
    now: u64,
) -> Result<BuiltFundedQuote, QuoteBuildError> {
    validate_policy(policy)?;
    validate_chain_tip(bitcoin_tip)?;
    validate_chain_tip(liquid_tip)?;
    validate_rfq_event(rfq)?;
    let liquid = policy.liquid.ok_or_else(|| {
        error(
            "swp_unsupported_extension",
            "Liquid chain swaps require an enabled Liquid rail",
        )
    })?;
    validate_network_id(liquid.network_id)?;
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
    if string(constraints, "swap_type")? != "chain"
        || !matches!(mkt_swp.get("invoice"), None | Some(Value::Null))
        || !matches!(constraints.get("invoice_sha256"), None | Some(Value::Null))
    {
        return Err(error(
            "swp_contract_terms_mismatch",
            "chain RFQ carries unsupported Lightning terms",
        ));
    }
    let asset_pair = exact_string_pair(constraints, "asset_pair")?;
    let bitcoin_asset = format!("swp:1:{}:btc:chain", policy.network_id);
    let liquid_asset = format!(
        "swp:1:{}:elements:{}:liquid",
        liquid.network_id, liquid.pegged_asset
    );
    let btc_to_liquid = asset_pair == [bitcoin_asset.clone(), liquid_asset.clone()];
    if !btc_to_liquid && asset_pair != [liquid_asset.clone(), bitcoin_asset.clone()] {
        return Err(error(
            "swp_invalid_pair",
            "chain RFQ must contain the exact enabled BTC/L-BTC pair",
        ));
    }
    let input_amount = canonical_positive_amount(string(constraints, "input_amount")?)?;
    let maximum_total_fee =
        canonical_amount(string(constraints, "maximum_total_fee")?, "swp_invalid_fee")?;
    let payment_hash = lower_hex_32(string(constraints, "payment_hash")?, "payment hash")?;
    validate_requested_policy(constraints, policy)?;
    let provider_fee = u64::try_from(
        u128::from(input_amount)
            .checked_mul(u128::from(policy.fee_bps))
            .ok_or_else(|| error("swp_invalid_fee", "provider fee overflows"))?
            / 10_000,
    )
    .map_err(|_| error("swp_invalid_fee", "provider fee exceeds u64"))?;
    let total_fee = provider_fee
        .checked_add(policy.miner_fee_budget_sat)
        .ok_or_else(|| error("swp_invalid_fee", "chain fee total overflows"))?;
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
    let expiration = now
        .checked_add(policy.quote_validity_seconds)
        .map(|value| value.min(rfq_expiration))
        .filter(|value| *value > now)
        .ok_or_else(|| error("swp_quote_expired", "Quote has no safe acceptance window"))?;
    let desired_completion_time = constraints
        .get("desired_completion_time")
        .and_then(Value::as_u64)
        .filter(|value| *value > expiration)
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "chain completion deadline is unsafe",
            )
        })?;
    let source_rail = if btc_to_liquid {
        ChainRail::Bitcoin
    } else {
        ChainRail::Liquid(liquid)
    };
    let destination_rail = if btc_to_liquid {
        ChainRail::Liquid(liquid)
    } else {
        ChainRail::Bitcoin
    };
    let source_tip = if btc_to_liquid {
        bitcoin_tip
    } else {
        liquid_tip
    };
    let destination_tip = if btc_to_liquid {
        liquid_tip
    } else {
        bitcoin_tip
    };
    let source_block_seconds = chain_block_interval_seconds(source_rail, policy);
    let destination_block_seconds = chain_block_interval_seconds(destination_rail, policy);
    let acceptance_seconds = expiration.checked_sub(now).ok_or_else(|| {
        error(
            "swp_timeout_ladder_unsafe",
            "chain acceptance time underflows",
        )
    })?;
    let destination_acceptance_blocks = acceptance_seconds.div_ceil(destination_block_seconds);
    let destination_base_blocks = policy
        .funding_window_blocks
        .checked_add(policy.minimum_confirmations)
        .and_then(|value| value.checked_add(policy.reorg_safety_blocks))
        .and_then(|value| value.checked_add(policy.broadcast_safety_blocks))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "destination refund height overflows",
            )
        })?;
    let destination_refund_blocks = u64::from(destination_base_blocks)
        .checked_add(destination_acceptance_blocks)
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "destination refund height overflows",
            )
        })?;
    let destination_refund_time = destination_refund_blocks
        .checked_mul(destination_block_seconds)
        .and_then(|duration| now.checked_add(duration))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "chain ladder overflows"))?;
    let provider_claim_margin = source_block_seconds
        .checked_mul(u64::from(policy.broadcast_safety_blocks.max(1)))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "claim margin overflows"))?;
    let both_network_reorg_margins = u64::from(policy.reorg_safety_blocks)
        .checked_mul(source_block_seconds)
        .and_then(|source| {
            u64::from(policy.reorg_safety_blocks)
                .checked_mul(destination_block_seconds)
                .and_then(|destination| source.checked_add(destination))
        })
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "reorg margin overflows"))?;
    let both_network_broadcast_margins = u64::from(policy.broadcast_safety_blocks)
        .checked_mul(source_block_seconds)
        .and_then(|source| {
            u64::from(policy.broadcast_safety_blocks)
                .checked_mul(destination_block_seconds)
                .and_then(|destination| source.checked_add(destination))
        })
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "broadcast margin overflows"))?;
    let safe_source_refund_time = destination_refund_time
        .checked_add(provider_claim_margin)
        .and_then(|value| value.checked_add(both_network_reorg_margins))
        .and_then(|value| value.checked_add(both_network_broadcast_margins))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "source refund time overflows"))?;
    let source_refund_blocks = safe_source_refund_time
        .checked_sub(now)
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "source refund time underflows"))?
        .div_ceil(source_block_seconds);
    let source_refund_time = source_refund_blocks
        .checked_mul(source_block_seconds)
        .and_then(|duration| now.checked_add(duration))
        .ok_or_else(|| error("swp_timeout_ladder_unsafe", "source refund time overflows"))?;
    if source_refund_time > desired_completion_time {
        return Err(error(
            "swp_timeout_ladder_unsafe",
            "desired completion time cannot cover both chain exits",
        ));
    }
    let source_refund_lock = u32::try_from(source_tip.height)
        .ok()
        .and_then(|height| {
            u32::try_from(source_refund_blocks)
                .ok()
                .and_then(|blocks| height.checked_add(blocks))
        })
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "source refund height exceeds u32",
            )
        })?;
    let destination_refund_lock = u32::try_from(destination_tip.height)
        .ok()
        .and_then(|height| {
            u32::try_from(destination_refund_blocks)
                .ok()
                .and_then(|blocks| height.checked_add(blocks))
        })
        .ok_or_else(|| {
            error(
                "swp_timeout_ladder_unsafe",
                "destination refund height exceeds u32",
            )
        })?;
    let (source_requester_key, destination_requester_key) = chain_requester_keys(constraints)?;
    let source_provider = wallet
        .derive_address(allocation.unilateral_path)
        .map_err(wallet_error)?;
    let source_cooperative = wallet
        .derive_address(allocation.cooperative_path)
        .map_err(wallet_error)?;
    let destination_provider_path = WalletPath::new(
        allocation.unilateral_path.account,
        allocation.unilateral_path.change,
        allocation
            .unilateral_path
            .address_index
            .checked_add(2)
            .ok_or_else(|| error("swp_script_invalid", "destination wallet path overflows"))?,
    )
    .map_err(wallet_error)?;
    let destination_cooperative_path = WalletPath::new(
        allocation.cooperative_path.account,
        allocation.cooperative_path.change,
        allocation
            .cooperative_path
            .address_index
            .checked_add(2)
            .ok_or_else(|| error("swp_script_invalid", "destination wallet path overflows"))?,
    )
    .map_err(wallet_error)?;
    let destination_provider = wallet
        .derive_address(destination_provider_path)
        .map_err(wallet_error)?;
    let destination_cooperative = wallet
        .derive_address(destination_cooperative_path)
        .map_err(wallet_error)?;
    let source_provider_key = XOnlyPublicKey::from_byte_array(source_provider.internal_key)
        .map_err(|_| error("swp_script_invalid", "source provider key is invalid"))?;
    let destination_provider_key =
        XOnlyPublicKey::from_byte_array(destination_provider.internal_key)
            .map_err(|_| error("swp_script_invalid", "destination provider key is invalid"))?;
    let source_tree = build_taproot(
        payment_hash,
        source_provider_key,
        source_requester_key,
        source_refund_lock,
        source_requester_key,
        source_cooperative.internal_key,
        "provider",
        "requester",
        source_rail,
    )?;
    let destination_tree = build_taproot(
        payment_hash,
        destination_requester_key,
        destination_provider_key,
        destination_refund_lock,
        destination_requester_key,
        destination_cooperative.internal_key,
        "requester",
        "provider",
        destination_rail,
    )?;
    let (source_leg, source_verifier) = build_chain_leg(
        "source",
        &asset_pair[0],
        input_amount,
        "requester",
        "provider",
        source_provider_key,
        source_requester_key,
        source_refund_lock,
        &source_tree,
        source_rail,
        source_tip,
        payment_hash,
        policy,
        policy.zero_confirmation && matches!(source_rail, ChainRail::Bitcoin),
    )?;
    let (destination_leg, destination_verifier) = build_chain_leg(
        "destination",
        &asset_pair[1],
        output_amount,
        "provider",
        "requester",
        destination_requester_key,
        destination_provider_key,
        destination_refund_lock,
        &destination_tree,
        destination_rail,
        destination_tip,
        payment_hash,
        policy,
        false,
    )?;
    let confirmation_policy = json!({
        "minimum_confirmations":policy.minimum_confirmations.to_string(),
        "reorg_safety_blocks":policy.reorg_safety_blocks.to_string(),
        "zero_confirmation":if policy.zero_confirmation && matches!(source_rail, ChainRail::Bitcoin) { "allowed" } else { "forbidden" },
        "rbf":policy.rbf.as_str(),
        "replacement":policy.replacement.as_str(),
    });
    let timeout_ladder = json!({
        "swap_type":"chain",
        "destination_final":true,
        "destination_refund_time":destination_refund_time,
        "source_refund_time":source_refund_time,
        "provider_claim_margin":provider_claim_margin,
        "both_network_reorg_margins":both_network_reorg_margins,
        "both_network_broadcast_margins":both_network_broadcast_margins,
    });
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
            "maximum_custody_duration_seconds":source_refund_time.saturating_sub(now),
            "recourse":["unilateral_script_path"],
            "reversibility":["cltv_refund"],
            "settlement_authority":["bitcoin_consensus","elements_consensus"]
        },
        "desired_completion_time":desired_completion_time,
        "effect_policy":{
            "effects":[
                {"actor":"requester","effect_role":"chain_fund","leg_id":"source"},
                {"actor":"provider","effect_role":"chain_claim","leg_id":"source"},
                {"actor":"requester","effect_role":"chain_refund","leg_id":"source"},
                {"actor":"provider","effect_role":"chain_fund","leg_id":"destination"},
                {"actor":"requester","effect_role":"chain_claim","leg_id":"destination"},
                {"actor":"provider","effect_role":"chain_refund","leg_id":"destination"}
            ],
            "id_scheme":"openagents.mkt-swp.v1",
            "order_event_id_required":true,
            "replay":"idempotent_exact_bytes"
        },
        "evidence_requirements":{"minimum_rung":"verified"},
        "evm_leg":null,
        "fee_bps":policy.fee_bps.to_string(),
        "fee_payer":"requester",
        "input_amount":input_amount.to_string(),
        "legs":[source_leg,destination_leg],
        "lightning_routing_fee_budget":"0",
        "maximum_total_fee":total_fee.to_string(),
        "miner_fee_budget":policy.miner_fee_budget_sat.to_string(),
        "musig2_execution":false,
        "output_amount":output_amount.to_string(),
        "payment_hash":lower_hex(&payment_hash),
        "price_feed":null,
        "provider_fee":provider_fee.to_string(),
        "recovery":{
            "channel":"direct_or_relay_agnostic",
            "exit_policy":{
                "bump_mode":"cpfp",
                "earliest_broadcast_height":destination_refund_time.to_string(),
                "latest_safe_broadcast_height":source_refund_time.to_string(),
                "maximum_fee":policy.miner_fee_budget_sat.to_string(),
                "target_blocks":policy.recovery_target_blocks
            }
        },
        "reservation_commitment":{},
        "rounding":"floor_output_sats",
        "script_mode":SCRIPT_MODE,
        "swap_type":"chain",
        "timeout_ladder":timeout_ladder,
        "verifier_inputs":[source_verifier,destination_verifier]
    });
    let profile = json!({"critical":["terms"],"terms":terms});
    validate_quote_profile(&profile, "none")
        .map_err(|protocol| error(protocol.code, "constructed chain Quote profile is invalid"))?;
    validate_quote_against_rfq(rfq, &profile, "firm", now, expiration)
        .map_err(|protocol| error(protocol.code, "constructed chain Quote weakens its RFQ"))?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainRail<'a> {
    Bitcoin,
    Liquid(LiquidQuotePolicy<'a>),
}

fn chain_block_interval_seconds(rail: ChainRail<'_>, policy: FundedQuotePolicy<'_>) -> u64 {
    match rail {
        ChainRail::Bitcoin => policy.expected_block_seconds,
        ChainRail::Liquid(_) => LIQUID_BLOCK_INTERVAL_SECONDS,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_chain_leg(
    leg_id: &str,
    asset_id: &str,
    amount: u64,
    funding_role: &str,
    receiving_role: &str,
    claim_key: XOnlyPublicKey,
    refund_key: XOnlyPublicKey,
    refund_lock: u32,
    taproot: &TaprootTerms,
    rail: ChainRail<'_>,
    chain_tip: &ChainTip,
    payment_hash: [u8; 32],
    policy: FundedQuotePolicy<'_>,
    zero_confirmation: bool,
) -> Result<(Value, Value), QuoteBuildError> {
    let (rail_name, network_id, verifier_policy) = match rail {
        ChainRail::Bitcoin => ("bitcoin", policy.network_id, BITCOIN_VERIFIER),
        ChainRail::Liquid(liquid) => ("liquid", liquid.network_id, "mkt-swp-liquid-v1"),
    };
    let tree = json!([
        {
            "condition":"hashlock",
            "lock_value":null,
            "participant_role":if leg_id == "source" { "provider" } else { "requester" },
            "path":"claim",
            "script":lower_hex(&taproot.claim_script),
            "signing_pubkey":lower_hex(&claim_key.serialize())
        },
        {
            "condition":"cltv",
            "lock_value":refund_lock.to_string(),
            "participant_role":if leg_id == "source" { "requester" } else { "provider" },
            "path":"refund",
            "script":lower_hex(&taproot.refund_script),
            "signing_pubkey":lower_hex(&refund_key.serialize())
        }
    ]);
    let tree_digest =
        lower_hex(&sha256(&canonical_json(&tree).map_err(|_| {
            error("swp_script_invalid", "chain Taproot tree is not canonical")
        })?));
    let provider_path = if leg_id == "source" {
        "claim"
    } else {
        "refund"
    };
    let provider_script = if provider_path == "claim" {
        &taproot.claim_script
    } else {
        &taproot.refund_script
    };
    let provider_control_block = if provider_path == "claim" {
        &taproot.claim_control_block
    } else {
        &taproot.refund_control_block
    };
    let mut verifier = json!({
        "amount":amount.to_string(),
        "chain_tip_hash":chain_tip.hash,
        "chain_tip_height":chain_tip.height.to_string(),
        "claim_script":lower_hex(&taproot.claim_script),
        "cooperative_internal_key":lower_hex(&taproot.internal_key.serialize()),
        "cooperative_pubkeys":[
            {
                "participant_role":"requester",
                "public_key":lower_hex(&taproot.cooperative_keys[0].serialize()),
            },
            {
                "participant_role":"provider",
                "public_key":lower_hex(&taproot.cooperative_keys[1].serialize()),
            }
        ],
        "evidence_authority":{
            "adapter_sha256":lower_hex(&sha256(if rail_name == "liquid" { b"immortal-provider-elementsd-v1" } else { b"immortal-provider-local-verifier-v1" })),
            "mode":if rail_name == "liquid" { "local_elementsd_unblind" } else { "local" },
            "pubkeys":[]
        },
        "exit_condition":if provider_path == "claim" { "hashlock" } else { "cltv" },
        "exit_lock_value":if provider_path == "claim" { Value::Null } else { Value::String(refund_lock.to_string()) },
        "exit_path":provider_path,
        "exit_signing_pubkey":if provider_path == "claim" { lower_hex(&claim_key.serialize()) } else { lower_hex(&refund_key.serialize()) },
        "leg_id":leg_id,
        "minimum_confirmations":policy.minimum_confirmations.to_string(),
        "musig2_execution":false,
        "rbf_policy":policy.rbf.as_str(),
        "refund_script":lower_hex(&taproot.refund_script),
        "reorg_safety_blocks":policy.reorg_safety_blocks.to_string(),
        "replacement_policy":policy.replacement.as_str(),
        "script_pubkey":lower_hex(&taproot.script_pubkey),
        "sighash_policy":"default_script_path_only",
        "swap_tree_sha256":tree_digest,
        "taproot_claim_control_block":lower_hex(&taproot.claim_control_block),
        "taproot_control_block":lower_hex(provider_control_block),
        "taproot_internal_key":lower_hex(&taproot.internal_key.serialize()),
        "taproot_merkle_root":lower_hex(&taproot.merkle_root),
        "taproot_output_key":lower_hex(&taproot.output_key.serialize()),
        "taproot_refund_control_block":lower_hex(&taproot.refund_control_block),
        "taproot_script":lower_hex(provider_script),
        "taproot_tree":tree,
        "verifier_policy":verifier_policy,
        "zero_confirmation":if zero_confirmation { "allowed" } else { "forbidden" }
    });
    if let ChainRail::Liquid(liquid) = rail {
        let mut wire_asset = liquid.pegged_asset.display_bytes();
        wire_asset.reverse();
        let mut serialized_asset = String::from("01");
        serialized_asset.push_str(&lower_hex(&wire_asset));
        let mut serialized_value = String::from("01");
        serialized_value.push_str(&lower_hex(&amount.to_be_bytes()));
        let object = verifier
            .as_object_mut()
            .ok_or_else(|| error("swp_liquid_output_invalid", "Liquid verifier is invalid"))?;
        object.insert("asset_id".to_owned(), Value::String(asset_id.to_owned()));
        object.insert(
            "network_id".to_owned(),
            Value::String(network_id.to_owned()),
        );
        object.insert(
            "confidentiality".to_owned(),
            Value::String("explicit".to_owned()),
        );
        object.insert(
            "serialized_commitments".to_owned(),
            json!({
                "asset":serialized_asset,
                "value":serialized_value,
                "nonce":"00",
                "rangeproof_sha256":null,
                "surjectionproof_sha256":null
            }),
        );
    }
    let verifier_digest = verifier_digest(&verifier)?;
    let leg = json!({
        "amount":amount.to_string(),
        "asset_id":asset_id,
        "claim_public_key":lower_hex(&claim_key.serialize()),
        "claim_script":lower_hex(&taproot.claim_script),
        "confirmation_policy":{
            "minimum_confirmations":policy.minimum_confirmations.to_string(),
            "replacement_policy":policy.replacement.as_str(),
            "zero_confirmation":if zero_confirmation { "allowed" } else { "forbidden" }
        },
        "funding_role":funding_role,
        "leg_id":leg_id,
        "network_id":network_id,
        "payment_hash":lower_hex(&payment_hash),
        "rail":rail_name,
        "receiving_role":receiving_role,
        "refund_condition":"cltv",
        "refund_control_block":lower_hex(&taproot.refund_control_block),
        "refund_lock_value":refund_lock.to_string(),
        "refund_public_key":lower_hex(&refund_key.serialize()),
        "refund_script":lower_hex(&taproot.refund_script),
        "script_pubkey":lower_hex(&taproot.script_pubkey),
        "verifier_digest":verifier_digest,
        "verifier_policy":verifier_policy
    });
    Ok((leg, verifier))
}

fn chain_requester_keys(
    constraints: &Map<String, Value>,
) -> Result<(XOnlyPublicKey, XOnlyPublicKey), QuoteBuildError> {
    let keys = constraints
        .get("requester_public_keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 2)
        .ok_or_else(|| {
            error(
                "swp_terms_mismatch",
                "chain RFQ must bind two requester keys",
            )
        })?;
    let parse = |leg_id: &str, path: &str| {
        let key = keys
            .iter()
            .filter_map(Value::as_object)
            .find(|key| {
                key.get("leg_id").and_then(Value::as_str) == Some(leg_id)
                    && key.get("path").and_then(Value::as_str) == Some(path)
            })
            .ok_or_else(|| error("swp_terms_mismatch", "chain requester key is absent"))?;
        if key.len() != 3 {
            return Err(error(
                "swp_terms_mismatch",
                "chain requester key has extensions",
            ));
        }
        XOnlyPublicKey::from_byte_array(lower_hex_32(
            string(key, "public_key")?,
            "requester public key",
        )?)
        .map_err(|_| error("swp_script_invalid", "requester public key is invalid"))
    };
    Ok((parse("source", "refund")?, parse("destination", "claim")?))
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

#[allow(clippy::too_many_arguments)]
fn build_timeout_ladder(
    swap_type: SwapType,
    chain_tip: &ChainTip,
    chain_rail: ChainRail<'_>,
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
    if matches!(chain_rail, ChainRail::Bitcoin) {
        validate_lightning_height(current_height, policy)?;
    }
    let chain_block_interval_seconds = match chain_rail {
        ChainRail::Bitcoin => policy.expected_block_seconds,
        ChainRail::Liquid(_) => LIQUID_BLOCK_INTERVAL_SECONDS,
    };
    let acceptance_seconds = quote_expiration
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| error("swp_quote_expired", "Quote acceptance window is empty"))?;
    let acceptance_blocks = acceptance_seconds.div_ceil(chain_block_interval_seconds);
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
                .checked_mul(chain_block_interval_seconds)
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
            let cross_domain = matches!(chain_rail, ChainRail::Liquid(_));
            let cross_domain_terms = if cross_domain {
                let chain_blocks_to_refund = refund_first
                    .checked_sub(current_height)
                    .and_then(|blocks| blocks.checked_add(policy.broadcast_safety_blocks))
                    .ok_or_else(|| {
                        error("swp_timeout_ladder_unsafe", "refund conversion underflows")
                    })?;
                let lightning_blocks_to_expiry = hold_expiry_height
                    .checked_sub(policy.lightning_current_height)
                    .ok_or_else(|| {
                        error("swp_timeout_ladder_unsafe", "hold conversion underflows")
                    })?;
                let provider_refund_expected_at = now
                    .checked_add(
                        u64::from(chain_blocks_to_refund)
                            .checked_mul(chain_block_interval_seconds)
                            .ok_or_else(|| {
                                error("swp_timeout_ladder_unsafe", "refund conversion overflows")
                            })?,
                    )
                    .ok_or_else(|| error("swp_timeout_ladder_unsafe", "refund time overflows"))?;
                let hold_expiry_expected_at = now
                    .checked_add(
                        u64::from(lightning_blocks_to_expiry)
                            .checked_mul(LIGHTNING_BLOCK_INTERVAL_SECONDS)
                            .ok_or_else(|| {
                                error("swp_timeout_ladder_unsafe", "hold conversion overflows")
                            })?,
                    )
                    .ok_or_else(|| error("swp_timeout_ladder_unsafe", "hold time overflows"))?;
                let required_hold_time = provider_refund_expected_at
                    .checked_add(
                        u64::from(policy.lightning_settlement_blocks)
                            .checked_mul(LIGHTNING_BLOCK_INTERVAL_SECONDS)
                            .ok_or_else(|| {
                                error(
                                    "swp_timeout_ladder_unsafe",
                                    "settlement conversion overflows",
                                )
                            })?,
                    )
                    .and_then(|time| time.checked_add(CROSS_DOMAIN_SAFETY_SECONDS))
                    .ok_or_else(|| {
                        error("swp_timeout_ladder_unsafe", "cross-domain margin overflows")
                    })?;
                if required_hold_time >= hold_expiry_expected_at {
                    return Err(error(
                        "swp_timeout_ladder_unsafe",
                        "cross-domain hold margin cannot preserve provider refund",
                    ));
                }
                Some(json!({
                    "height_observed_at":now,
                    "height_observation_max_age_seconds":HEIGHT_OBSERVATION_MAX_AGE_SECONDS,
                    "chain_block_interval_seconds":chain_block_interval_seconds,
                    "lightning_block_interval_seconds":LIGHTNING_BLOCK_INTERVAL_SECONDS,
                    "cross_domain_safety_seconds":CROSS_DOMAIN_SAFETY_SECONDS,
                    "provider_refund_expected_at":provider_refund_expected_at,
                    "hold_expiry_expected_at":hold_expiry_expected_at,
                }))
            } else {
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
                None
            };
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
            let mut value = json!({
                "swap_type":"reverse",
                "current_height":current_height,
                "lightning_current_height":policy.lightning_current_height,
                "lock_last":first_deadline,
                "user_claim_last":claim_last,
                "provider_refund_first":refund_first,
                "hold_expiry_height":hold_expiry_height,
                "chain_finality_blocks":policy.minimum_confirmations,
                "broadcast_safety_blocks":policy.broadcast_safety_blocks,
                "reorg_safety_blocks":policy.reorg_safety_blocks,
                "lightning_settlement_blocks":policy.lightning_settlement_blocks,
            });
            if let Some(cross_domain_terms) = cross_domain_terms {
                let object = value.as_object_mut().ok_or_else(|| {
                    error(
                        "swp_timeout_ladder_unsafe",
                        "timeout ladder is not an object",
                    )
                })?;
                let cross_domain_terms = cross_domain_terms.as_object().ok_or_else(|| {
                    error(
                        "swp_timeout_ladder_unsafe",
                        "cross-domain timeout terms are not an object",
                    )
                })?;
                object.extend(cross_domain_terms.clone());
            }
            Ok(TimeoutTerms {
                value,
                refund_height: refund_first,
                latest_safe_exit_height,
            })
        }
    }
}

struct TaprootTerms {
    internal_key: XOnlyPublicKey,
    cooperative_keys: [PublicKey; 2],
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
    rail: ChainRail<'_>,
) -> Result<TaprootTerms, QuoteBuildError> {
    if claim_role == refund_role || !matches!(claim_role, "requester" | "provider") {
        return Err(error(
            "swp_script_invalid",
            "claim and refund roles are invalid",
        ));
    }
    let claim_script = claim_script(payment_hash, claim_key);
    let refund_script = refund_script(refund_height, refund_key)?;
    let (claim_hash, refund_hash, merkle_root, leaf_version) = match rail {
        ChainRail::Bitcoin => {
            let claim_hash = tapleaf_hash(0xc0, &claim_script).map_err(script_error)?;
            let refund_hash = tapleaf_hash(0xc0, &refund_script).map_err(script_error)?;
            (
                claim_hash,
                refund_hash,
                tapbranch_hash(claim_hash, refund_hash),
                0xc0,
            )
        }
        ChainRail::Liquid(_) => {
            let claim_hash = liquid_tapleaf_hash(&claim_script).map_err(|_| {
                error(
                    "swp_script_invalid",
                    "provider could not construct the Liquid Taproot commitment",
                )
            })?;
            let refund_hash = liquid_tapleaf_hash(&refund_script).map_err(|_| {
                error(
                    "swp_script_invalid",
                    "provider could not construct the Liquid Taproot commitment",
                )
            })?;
            (
                claim_hash,
                refund_hash,
                liquid_tapbranch_hash(claim_hash, refund_hash),
                0xc4,
            )
        }
    };
    let cooperative_keys = [
        PublicKey::from_slice(&compressed_even_bytes(requester_key))
            .map_err(|_| error("swp_script_invalid", "requester cooperative key is invalid"))?,
        PublicKey::from_slice(&compressed_even_raw(provider_cooperative_key))
            .map_err(|_| error("swp_script_invalid", "provider cooperative key is invalid"))?,
    ];
    let internal_key = musig2_aggregate_key(&cooperative_keys).map_err(script_error)?;
    let (output_key, parity) = match rail {
        ChainRail::Bitcoin => {
            taproot_output_key(internal_key, Some(merkle_root)).map_err(script_error)?
        }
        ChainRail::Liquid(_) => liquid_taproot_output_key(internal_key, Some(merkle_root))
            .map_err(|_| {
                error(
                    "swp_script_invalid",
                    "provider could not construct the Liquid Taproot output key",
                )
            })?,
    };
    let first = leaf_version
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
    match rail {
        ChainRail::Bitcoin => {
            verify_control_block(&output_key, &claim_script, &claim_control_block)
                .map_err(script_error)?;
            verify_control_block(&output_key, &refund_script, &refund_control_block)
                .map_err(script_error)?;
        }
        ChainRail::Liquid(_) => {
            verify_liquid_control_block(&output_key, &claim_script, &claim_control_block).map_err(
                |_| {
                    error(
                        "swp_script_invalid",
                        "provider could not verify the Liquid claim control block",
                    )
                },
            )?;
            verify_liquid_control_block(&output_key, &refund_script, &refund_control_block)
                .map_err(|_| {
                    error(
                        "swp_script_invalid",
                        "provider could not verify the Liquid refund control block",
                    )
                })?;
        }
    }
    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.extend_from_slice(&[0x51, 0x20]);
    script_pubkey.extend_from_slice(&output_key.serialize());
    Ok(TaprootTerms {
        internal_key,
        cooperative_keys,
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
        "destination_commitment_sha256",
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
        .filter(|member| !matches!(**member, "invoice_sha256" | "destination_commitment_sha256"))
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

fn validate_asset_pair<'a>(
    swap_type: SwapType,
    pair: &[String; 2],
    policy: FundedQuotePolicy<'a>,
) -> Result<ChainRail<'a>, QuoteBuildError> {
    let chain = format!("swp:1:{}:btc:chain", policy.network_id);
    let lightning = format!("swp:1:{}:btc:lightning", policy.network_id);
    let bitcoin_expected = match swap_type {
        SwapType::Submarine => [&chain, &lightning],
        SwapType::Reverse => [&lightning, &chain],
    };
    if pair[0] == *bitcoin_expected[0] && pair[1] == *bitcoin_expected[1] {
        return Ok(ChainRail::Bitcoin);
    }
    if let Some(liquid) = policy.liquid {
        validate_network_id(liquid.network_id)?;
        let liquid_asset = format!(
            "swp:1:{}:elements:{}:liquid",
            liquid.network_id, liquid.pegged_asset
        );
        let liquid_expected = match swap_type {
            SwapType::Submarine => [&liquid_asset, &lightning],
            SwapType::Reverse => [&lightning, &liquid_asset],
        };
        if pair[0] == *liquid_expected[0] && pair[1] == *liquid_expected[1] {
            return Ok(ChainRail::Liquid(liquid));
        }
    }
    Err(error(
        "swp_invalid_pair",
        "RFQ asset pair does not match an enabled funded network and direction",
    ))
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
