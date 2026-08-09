//! Deterministic MKT-SWP quote derivation: spread, miner-fee pass-through,
//! and dynamic limits (issue #28).
//!
//! This module decides *what number goes in a Quote*. It is pure and
//! reproducible: the same [`PricingConfig`], [`FeerateObservation`],
//! [`CapacityBounds`], [`QuoteRequest`], and optional [`PriceFeedPacket`]
//! always derive the same [`DerivedQuote`]. It performs no I/O, no clock
//! reads, and no rail calls.
//!
//! # Integration point
//!
//! Funded mode derives terms here before it invokes the existing session
//! Quote constructor:
//!
//! 1. Build a [`PricingConfig`] once at startup with
//!    [`PricingConfig::from_env`] (fail-fast, relay-style env contract).
//! 2. Per RFQ, obtain a feerate with [`feerate_for_quote`]: a live
//!    `estimatesmartfee`-derived value when available, the configured
//!    fallback otherwise, and a refusal when neither exists.
//! 3. Call [`derive_quote`]. The returned [`DerivedQuote`] carries the exact
//!    fee components (spread and miner-fee separated), limits, expiry, and
//!    reservation tier.
//! 4. Feed the derived spread, miner budget, routing budget, and expiry to
//!    funded Quote construction, then compare every emitted amount term with
//!    [`DerivedQuote::amount_terms`] before the reserve/signing gate. A
//!    disagreement fails closed.
//!
//! The remaining Quote terms (asset pair, payment hash, legs, timeout
//! ladder, verifier inputs, recovery, cancellation, evidence requirements)
//! stay with the embedding: they bind rail facts this module does not own.
//! MKT-SWP §3.4 exact price-feed pinning remains a separate wire concern.
//! [`PriceFeedPacket`] is a provider-local pricing input supplied by an
//! operator-controlled file. It never becomes the Quote `price_feed` member,
//! which v1 validators still require to be `null`. A fresh packet adjusts the
//! provider spread and records USD valuation metadata. Missing, invalid, or
//! stale input uses the static spread path. Miner-fee arithmetic is unchanged.
//!
//! # Environment contract
//!
//! Same style as the relay gateway config: environment variables only,
//! fail-fast validation, exact error messages.
//!
//! | Variable | Default | Meaning |
//! | --- | --- | --- |
//! | `IMMORTAL_PROVIDER_SPREAD_BPS` | `0` | Provider spread in basis points, `0..=1000`. Becomes the Quote `fee_bps`; the spread component is `floor(input * spread_bps / 10000)`. |
//! | `IMMORTAL_PROVIDER_PRICE_FEED_FILE` | unset | Absolute path to the optional bounded public JSON packet specified in `docs/protocol/provider-price-feed.md`. The funded provider reads it per Quote outside this module. Missing, invalid, or stale data uses the static spread. |
//! | `IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB` | unset | Explicit fallback feerate, `1..=2000` sat/vB, for regtest/lab use where `estimatesmartfee` has no fee history. **No default exists.** With no live estimate and this unset, quoting refuses; it never silently invents a feerate. |
//! | `IMMORTAL_PROVIDER_QUOTE_MIN_SAT` | `10000` | Absolute minimum quotable input amount in satoshis, positive. |
//! | `IMMORTAL_PROVIDER_QUOTE_MAX_SAT` | `1000000` | Absolute maximum quotable input amount in satoshis, `>= min`, `<= 2100000000000000`. |
//! | `IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS` | `300` | Quote validity window, `1..=3600` seconds. `quote_expires_at = created_at + expiry`. |
//! | `IMMORTAL_PROVIDER_RESERVATION_TIER` | `hard` | Reservation tier stamped on firm Quotes: `none`, `soft`, or `hard`. Funded mode requires `hard` because rail effects require a confirmed reserve. |
//! | `IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM` | `0` | Lightning routing-fee budget in parts per million of the input, `0..=100000`. Applied only to `submarine` swaps, where the provider pays outbound Lightning. |
//!
//! # Fee floor invariant
//!
//! A Quote's fee is never below its worst-case redeemable path cost at the
//! quoted feerate. The miner-fee component is exactly
//! `worst_case_redeem_vbytes(swap_type) * sat_per_vb`, and [`derive_quote`]
//! re-checks the inequality before returning, so the invariant is enforced
//! in code on every derivation, not just in tests.
//!
//! # Weight derivation
//!
//! Worst-case vbyte weights for the `taproot-musig2-script-exit` script
//! shapes are derived arithmetically in this module (see
//! [`claim_spend_vbytes`], [`refund_spend_vbytes`], [`lockup_vbytes`]) from
//! the same constructors used by funded Quote construction. Tests parse the
//! templates through the core verification primitives and replay measured
//! transaction weights so pricing cannot drift from production scripts.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use immortal_client::mkt_swp_client::{SwapClientError, provider_support::error as provider_error};

pub use immortal_client::mkt_swp_client::SwapType;

/// Largest quotable satoshi amount: 21,000,000 BTC.
pub(crate) const MAX_AMOUNT_SAT: u64 = 2_100_000_000_000_000;
pub(crate) const MAX_SPREAD_BPS: u64 = 1_000;
pub(crate) const MAX_FEERATE_SAT_PER_VB: u64 = 2_000;
pub(crate) const MAX_QUOTE_EXPIRY_SECONDS: u64 = 3_600;
pub(crate) const MAX_LIGHTNING_ROUTING_FEE_PPM: u64 = 100_000;
pub const PRICE_FEED_SCHEMA: &str = "openagents.immortal.provider-price-feed.v1";
pub const MAX_PRICE_FEED_BYTES: usize = 16_384;
pub const MAX_PRICE_FEED_AGE_SECONDS: u64 = 3_600;
pub const MAX_REALIZED_VOLATILITY_BPS: u64 = 100_000;
pub const MAX_INDEX_PRICE_USD_CENTS: u64 = 10_000_000_000;
const REFERENCE_REALIZED_VOLATILITY_BPS: u64 = 5_000;
const SATOSHIS_PER_BITCOIN: u64 = 100_000_000;
pub const LIQUID_SINGLE_INPUT_FUNDING_VBYTES: u64 = 1_700;
pub const LIQUID_CLAIM_VBYTES: u64 = 300;
pub const LIQUID_REFUND_VBYTES: u64 = 300;

/// Bitcoin Core's dust threshold for a P2TR output: dustRelayFee of
/// 3 sat/vB applied to the 43-byte output plus the 67.75-vbyte input needed
/// to spend it (rounded to 110 vbytes) = 330 sat. A chain-settled output
/// below this is unrelayable, so reverse and chain quotes never promise one.
const CHAIN_OUTPUT_DUST_SAT: u64 = 330;

/// Minimum promised output for a Lightning-settled leg.
const LIGHTNING_OUTPUT_FLOOR_SAT: u64 = 1;

/// Bounded search width when locating the smallest viable input around the
/// closed-form candidate. Floor interactions move the boundary by at most a
/// few satoshis; exceeding this bound is an internal arithmetic error.
const MIN_VIABLE_SEARCH_STEPS: u64 = 64;

// ---------------------------------------------------------------------------
// Worst-case redeemable path weights
// ---------------------------------------------------------------------------

pub(crate) fn production_claim_leaf_script(
    payment_hash: [u8; 32],
    signing_key: [u8; 32],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(73);
    script.extend_from_slice(&[0x82, 0x01, 0x20, 0x88, 0xa8, 0x20]);
    script.extend_from_slice(&payment_hash);
    script.extend_from_slice(&[0x88, 0x20]);
    script.extend_from_slice(&signing_key);
    script.push(0xac);
    script
}

#[cfg_attr(not(feature = "funded"), allow(dead_code))]
pub(crate) fn production_refund_leaf_script(
    refund_height: u32,
    signing_key: [u8; 32],
) -> Option<Vec<u8>> {
    if refund_height == 0 || refund_height >= 500_000_000 {
        return None;
    }
    Some(refund_leaf_script(refund_height, signing_key))
}

fn refund_leaf_script(refund_height: u32, signing_key: [u8; 32]) -> Vec<u8> {
    let lock = script_number(refund_height);
    let lock_length = lock.len() as u8;
    let mut script = Vec::with_capacity(1 + lock.len() + 35);
    script.push(lock_length);
    script.extend_from_slice(&lock);
    script.extend_from_slice(&[0xb1, 0x75, 0x20]);
    script.extend_from_slice(&signing_key);
    script.push(0xac);
    script
}

fn script_number(value: u32) -> Vec<u8> {
    let mut remaining = value;
    let mut encoded = Vec::with_capacity(5);
    while remaining != 0 {
        encoded.push((remaining & 0xff) as u8);
        remaining >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

/// Canonical claim-leaf tapscript template:
///
/// `OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <32-byte payment hash>
/// OP_EQUALVERIFY <32-byte x-only claim key> OP_CHECKSIG`
///
/// This is the exact production constructor used by funded Quotes: 73 bytes.
pub fn claim_leaf_script_template() -> Vec<u8> {
    production_claim_leaf_script([0; 32], [0; 32])
}

/// Canonical refund-leaf tapscript template:
///
/// `<4-byte locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <32-byte x-only refund
/// key> OP_CHECKSIG`
///
/// The template uses the largest height-valued CLTV lock, so the exact
/// production constructor emits its 41-byte worst case.
pub fn refund_leaf_script_template() -> Vec<u8> {
    refund_leaf_script(499_999_999, [0; 32])
}

/// Worst-case BIP-340 signature length: 64 bytes plus one explicit sighash
/// byte when the sighash is not `SIGHASH_DEFAULT`.
const SCHNORR_SIG_WORST_CASE_BYTES: usize = 65;

/// Depth-1 taproot control block: 1 byte (leaf version and output-key
/// parity) + 32 bytes (internal key) + 32 bytes (sibling leaf hash) = 65.
const CONTROL_BLOCK_DEPTH1_BYTES: usize = 65;

/// Virtual size of a one-input transaction spending to `output_count` P2TR
/// outputs, with the given witness stack item lengths.
///
/// Base (non-witness) arithmetic: version 4, input count 1, input (36
/// outpoint, 1 empty-scriptSig length, 4 sequence: 41), output count 1,
/// `output_count` times (8 value, 1 script length, 34 P2TR scriptPubKey:
/// 43), locktime 4. Witness arithmetic: segwit marker and flag 2, stack
/// count 1, and per item a 1-byte compact-size length plus the item bytes
/// (every item is under 253 bytes). `weight = base * 4 + witness`,
/// `vsize = ceil(weight / 4)`.
fn spend_vbytes(witness_item_lens: &[usize], output_count: u64) -> u64 {
    let base: u64 = 4 + 1 + 41 + 1 + output_count * 43 + 4;
    let mut witness: u64 = 2 + 1;
    for len in witness_item_lens {
        debug_assert!(*len < 253, "witness item needs a 1-byte compact size");
        witness += 1 + *len as u64;
    }
    let weight = base * 4 + witness;
    weight.div_ceil(4)
}

/// Worst-case script-path claim spend of the swap output: witness stack
/// `[65-byte signature, 32-byte preimage, 73-byte claim leaf, 65-byte
/// control block]`, one P2TR output. The production OP_SIZE-bound leaf makes
/// this 155 vbytes.
pub fn claim_spend_vbytes() -> u64 {
    spend_vbytes(
        &[
            SCHNORR_SIG_WORST_CASE_BYTES,
            32,
            claim_leaf_script_template().len(),
            CONTROL_BLOCK_DEPTH1_BYTES,
        ],
        1,
    )
}

/// Worst-case script-path refund spend of the swap output: witness stack
/// `[65-byte signature, 41-byte refund leaf, 65-byte control block]`, one
/// P2TR output: 139 vbytes.
pub fn refund_spend_vbytes() -> u64 {
    spend_vbytes(
        &[
            SCHNORR_SIG_WORST_CASE_BYTES,
            refund_leaf_script_template().len(),
            CONTROL_BLOCK_DEPTH1_BYTES,
        ],
        1,
    )
}

/// Provider lockup funding transaction: one P2TR key-path wallet input
/// (witness stack `[65-byte signature]`) paying the swap output plus one
/// change output. 137 base bytes, 69 witness bytes, weight 617, vsize 155.
pub fn lockup_vbytes() -> u64 {
    spend_vbytes(&[SCHNORR_SIG_WORST_CASE_BYTES], 2)
}

/// Worst-case redeemable-path vbytes the provider must budget per swap
/// type:
///
/// - `submarine`: the requester funds the lockup; the provider's chain cost
///   is the script-path claim spend.
/// - `reverse`: the provider funds the chain lockup and must remain able to
///   refund it unilaterally if the requester never claims: lockup + refund.
/// - `chain`: the provider funds the destination lockup and either claims
///   the source leg (success) or refunds the destination (failure); the
///   worst single path is lockup + max(claim, refund).
pub fn worst_case_redeem_vbytes(swap_type: SwapType) -> u64 {
    match swap_type {
        SwapType::Submarine => claim_spend_vbytes(),
        SwapType::Reverse => lockup_vbytes() + refund_spend_vbytes(),
        SwapType::Chain => lockup_vbytes() + claim_spend_vbytes().max(refund_spend_vbytes()),
    }
}

pub fn liquid_submarine_quote_vbytes() -> u64 {
    LIQUID_CLAIM_VBYTES
}

pub fn liquid_reverse_quote_vbytes() -> u64 {
    LIQUID_SINGLE_INPUT_FUNDING_VBYTES + LIQUID_REFUND_VBYTES
}

pub fn bitcoin_to_liquid_chain_quote_vbytes() -> u64 {
    LIQUID_SINGLE_INPUT_FUNDING_VBYTES + LIQUID_REFUND_VBYTES.max(claim_spend_vbytes())
}

pub fn liquid_to_bitcoin_chain_quote_vbytes() -> u64 {
    lockup_vbytes() + LIQUID_CLAIM_VBYTES.max(refund_spend_vbytes())
}

pub fn funding_feerate_from_quote_budget(
    swap_type: SwapType,
    miner_fee_budget_sat: u64,
) -> Result<u64, SwapClientError> {
    funding_feerate_from_priced_vbytes(worst_case_redeem_vbytes(swap_type), miner_fee_budget_sat)
}

pub fn funding_feerate_from_priced_vbytes(
    priced_vbytes: u64,
    miner_fee_budget_sat: u64,
) -> Result<u64, SwapClientError> {
    if priced_vbytes == 0 {
        return Err(provider_error(
            "swp_invalid_fee",
            "signed miner-fee weight must be positive",
        ));
    }
    if miner_fee_budget_sat % priced_vbytes != 0 {
        return Err(provider_error(
            "swp_invalid_fee",
            "signed miner-fee budget does not encode an exact feerate",
        ));
    }
    let sat_per_vb = miner_fee_budget_sat / priced_vbytes;
    if !(1..=MAX_FEERATE_SAT_PER_VB).contains(&sat_per_vb) {
        return Err(provider_error(
            "swp_invalid_fee",
            "signed funding feerate is outside the provider bound",
        ));
    }
    Ok(sat_per_vb)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Fail-fast pricing configuration error, relay-config style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricingConfigError(pub String);

impl std::fmt::Display for PricingConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "pricing config error: {}", self.0)
    }
}

impl std::error::Error for PricingConfigError {}

fn config_error(detail: impl Into<String>) -> PricingConfigError {
    PricingConfigError(detail.into())
}

/// Reservation tier stamped on derived firm Quotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationTier {
    None,
    Soft,
    Hard,
}

impl ReservationTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }
}

/// Validated provider pricing policy. See the module docs for the exact
/// environment contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricingConfig {
    pub spread_bps: u64,
    pub fallback_feerate_sat_per_vb: Option<u64>,
    pub min_swap_sat: u64,
    pub max_swap_sat: u64,
    pub quote_expiry_seconds: u64,
    pub reservation_tier: ReservationTier,
    pub lightning_routing_fee_ppm: u64,
}

impl PricingConfig {
    /// Read and validate the pricing policy from process environment
    /// variables, failing fast with exact messages.
    pub fn from_env() -> Result<Self, PricingConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read and validate the pricing policy through an explicit lookup
    /// function. `from_env` is this with `std::env::var`; tests supply maps
    /// so process-global environment state is never mutated.
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, PricingConfigError> {
        let config = Self {
            spread_bps: parse_or(&lookup, "IMMORTAL_PROVIDER_SPREAD_BPS", "0")?,
            fallback_feerate_sat_per_vb: parse_optional(
                &lookup,
                "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB",
            )?,
            min_swap_sat: parse_or(&lookup, "IMMORTAL_PROVIDER_QUOTE_MIN_SAT", "10000")?,
            max_swap_sat: parse_or(&lookup, "IMMORTAL_PROVIDER_QUOTE_MAX_SAT", "1000000")?,
            quote_expiry_seconds: parse_or(
                &lookup,
                "IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS",
                "300",
            )?,
            reservation_tier: match lookup("IMMORTAL_PROVIDER_RESERVATION_TIER")
                .unwrap_or_else(|| "hard".to_owned())
                .as_str()
            {
                "none" => ReservationTier::None,
                "soft" => ReservationTier::Soft,
                "hard" => ReservationTier::Hard,
                _ => {
                    return Err(config_error(
                        "IMMORTAL_PROVIDER_RESERVATION_TIER must be one of none, soft, hard",
                    ));
                }
            },
            lightning_routing_fee_ppm: parse_or(
                &lookup,
                "IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM",
                "0",
            )?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate every policy bound, failing fast with exact messages.
    pub fn validate(&self) -> Result<(), PricingConfigError> {
        if self.spread_bps > MAX_SPREAD_BPS {
            return Err(config_error(
                "IMMORTAL_PROVIDER_SPREAD_BPS must be between 0 and 1000",
            ));
        }
        if let Some(fallback) = self.fallback_feerate_sat_per_vb {
            if !(1..=MAX_FEERATE_SAT_PER_VB).contains(&fallback) {
                return Err(config_error(
                    "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB must be between 1 and 2000",
                ));
            }
        }
        if self.min_swap_sat == 0 {
            return Err(config_error(
                "IMMORTAL_PROVIDER_QUOTE_MIN_SAT must be positive",
            ));
        }
        if self.max_swap_sat < self.min_swap_sat {
            return Err(config_error(
                "IMMORTAL_PROVIDER_QUOTE_MAX_SAT must be at least IMMORTAL_PROVIDER_QUOTE_MIN_SAT",
            ));
        }
        if self.max_swap_sat > MAX_AMOUNT_SAT {
            return Err(config_error(
                "IMMORTAL_PROVIDER_QUOTE_MAX_SAT must be at most 2100000000000000",
            ));
        }
        if !(1..=MAX_QUOTE_EXPIRY_SECONDS).contains(&self.quote_expiry_seconds) {
            return Err(config_error(
                "IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS must be between 1 and 3600",
            ));
        }
        if self.lightning_routing_fee_ppm > MAX_LIGHTNING_ROUTING_FEE_PPM {
            return Err(config_error(
                "IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM must be between 0 and 100000",
            ));
        }
        Ok(())
    }
}

fn parse_or(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: &str,
) -> Result<u64, PricingConfigError> {
    lookup(name)
        .unwrap_or_else(|| default.to_owned())
        .parse::<u64>()
        .map_err(|_| config_error(format!("{name} is not a valid non-negative integer")))
}

fn parse_optional(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<u64>, PricingConfigError> {
    match lookup(name) {
        None => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| config_error(format!("{name} is not a valid non-negative integer"))),
    }
}

// ---------------------------------------------------------------------------
// Feerate observation
// ---------------------------------------------------------------------------

/// The feerate a quote derivation is pinned to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FeerateObservation {
    /// A live node estimate, e.g. `bitcoind estimatesmartfee`. `source`
    /// names the estimator and target for the audit trail.
    Live { sat_per_vb: u64, source: String },
    /// The explicitly configured
    /// `IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB`, for regtest/lab use
    /// where `estimatesmartfee` has no fee history.
    Fallback { sat_per_vb: u64 },
}

impl FeerateObservation {
    pub fn sat_per_vb(&self) -> u64 {
        match self {
            Self::Live { sat_per_vb, .. } | Self::Fallback { sat_per_vb } => *sat_per_vb,
        }
    }
}

/// Select the feerate for a quote. A live estimate wins; without one, the
/// explicitly configured fallback applies; with neither, quoting refuses.
/// There is never a silent default feerate.
pub fn feerate_for_quote(
    config: &PricingConfig,
    live: Option<(u64, &str)>,
) -> Result<FeerateObservation, SwapClientError> {
    match live {
        Some((sat_per_vb, source)) => {
            if !(1..=MAX_FEERATE_SAT_PER_VB).contains(&sat_per_vb) {
                return Err(provider_error(
                    "swp_invalid_fee",
                    "live feerate estimate must be between 1 and 2000 sat/vB",
                ));
            }
            if source.is_empty() || source.len() > 128 {
                return Err(provider_error(
                    "swp_invalid_fee",
                    "live feerate source label must be 1 through 128 bytes",
                ));
            }
            Ok(FeerateObservation::Live {
                sat_per_vb,
                source: source.to_owned(),
            })
        }
        None => match config.fallback_feerate_sat_per_vb {
            Some(sat_per_vb) => Ok(FeerateObservation::Fallback { sat_per_vb }),
            None => Err(provider_error(
                "swp_invalid_fee",
                "no live feerate estimate and IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB is not configured; refusing to quote",
            )),
        },
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Available inventory for one capacity bucket, in the reservation ledger's
/// shape: the same canonical satoshi decimal strings and
/// `capacity_bucket_id` naming as [`crate::session::ReservationRequest`]
/// and [`crate::session::ReservationConfirmation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityBounds {
    pub capacity_bucket_id: String,
    /// Uncommitted capacity available for new quotes, canonical satoshi
    /// decimal string (committed capacity minus active reservations).
    pub available_capacity: String,
}

/// Which side of the pair the requested amount denominates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteSide {
    /// The amount is what the requester sends; the output is derived.
    Input,
    /// The amount is what the requester wants to receive; the smallest
    /// input whose promised output covers it is derived.
    Output,
}

/// Stable identity for a public market-data source. Every member uses a
/// lowercase machine identifier so a sidecar and provider compare the same
/// bytes without URL or display-name normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceFeedSource {
    pub venue: String,
    pub environment: String,
    pub instrument: String,
}

/// Provider-local public market-data input. Decimal quantities are strings
/// to keep the file and pricing calculation independent of floating point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceFeedPacket {
    pub schema: String,
    pub source: PriceFeedSource,
    pub index_price_usd_cents: String,
    pub realized_volatility_bps: String,
    pub realized_volatility_window_seconds: u64,
    pub observed_at: u64,
    pub max_age_seconds: u64,
}

/// Audit metadata retained with a quote derived from a fresh feed packet.
/// This is provider-local metadata, not the MKT-SWP wire `price_feed` pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceFeedApplication {
    pub source: PriceFeedSource,
    pub index_price_usd_cents: String,
    pub realized_volatility_bps: String,
    pub realized_volatility_window_seconds: u64,
    pub observed_at: u64,
    pub max_age_seconds: u64,
    pub static_spread_bps: String,
    pub effective_spread_bps: String,
    pub input_value_usd_cents: String,
    pub output_value_usd_cents: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceFeedFallback {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceFeedValidationError(pub String);

impl std::fmt::Display for PriceFeedValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "price feed validation error: {}", self.0)
    }
}

impl std::error::Error for PriceFeedValidationError {}

fn price_feed_error(detail: impl Into<String>) -> PriceFeedValidationError {
    PriceFeedValidationError(detail.into())
}

fn machine_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn canonical_feed_quantity(
    value: &str,
    label: &str,
    maximum: u64,
) -> Result<u64, PriceFeedValidationError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(price_feed_error(format!(
            "{label} is not a canonical decimal string"
        )));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| price_feed_error(format!("{label} exceeds u64")))?;
    if parsed > maximum {
        return Err(price_feed_error(format!("{label} exceeds its bound")));
    }
    Ok(parsed)
}

impl PriceFeedPacket {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, PriceFeedValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_PRICE_FEED_BYTES {
            return Err(price_feed_error(
                "packet size is outside the provider bound",
            ));
        }
        serde_json::from_slice(bytes)
            .map_err(|_| price_feed_error("packet is not strict JSON in the v1 shape"))
    }

    pub fn validate_at(
        &self,
        observed_at: u64,
    ) -> Result<ValidatedPriceFeed, PriceFeedValidationError> {
        if self.schema != PRICE_FEED_SCHEMA {
            return Err(price_feed_error("packet schema is unsupported"));
        }
        if !machine_identifier(&self.source.venue)
            || !machine_identifier(&self.source.environment)
            || !machine_identifier(&self.source.instrument)
        {
            return Err(price_feed_error("source identity is invalid"));
        }
        let index_price_usd_cents = canonical_feed_quantity(
            &self.index_price_usd_cents,
            "index price",
            MAX_INDEX_PRICE_USD_CENTS,
        )?;
        if index_price_usd_cents == 0 {
            return Err(price_feed_error("index price must be positive"));
        }
        let realized_volatility_bps = canonical_feed_quantity(
            &self.realized_volatility_bps,
            "realized volatility",
            MAX_REALIZED_VOLATILITY_BPS,
        )?;
        if self.realized_volatility_window_seconds == 0
            || self.realized_volatility_window_seconds > 604_800
        {
            return Err(price_feed_error(
                "realized volatility window must be between 1 and 604800 seconds",
            ));
        }
        if self.observed_at == 0 || self.observed_at > observed_at {
            return Err(price_feed_error("observation time is invalid"));
        }
        if !(1..=MAX_PRICE_FEED_AGE_SECONDS).contains(&self.max_age_seconds) {
            return Err(price_feed_error(
                "maximum age must be between 1 and 3600 seconds",
            ));
        }
        let expires_at = self
            .observed_at
            .checked_add(self.max_age_seconds)
            .ok_or_else(|| price_feed_error("staleness timestamp overflows"))?;
        if observed_at > expires_at {
            return Err(price_feed_error("packet is stale"));
        }
        Ok(ValidatedPriceFeed {
            packet: self.clone(),
            index_price_usd_cents,
            realized_volatility_bps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPriceFeed {
    packet: PriceFeedPacket,
    index_price_usd_cents: u64,
    realized_volatility_bps: u64,
}

impl ValidatedPriceFeed {
    fn effective_spread_bps(&self, static_spread_bps: u64) -> u64 {
        let adjusted = u128::from(static_spread_bps) * u128::from(self.realized_volatility_bps)
            / u128::from(REFERENCE_REALIZED_VOLATILITY_BPS);
        u64::try_from(adjusted)
            .unwrap_or(u64::MAX)
            .min(MAX_SPREAD_BPS)
    }

    fn usd_value_cents(&self, amount_sat: u64) -> Result<u64, SwapClientError> {
        u64::try_from(
            u128::from(amount_sat) * u128::from(self.index_price_usd_cents)
                / u128::from(SATOSHIS_PER_BITCOIN),
        )
        .map_err(|_| provider_error("swp_invalid_amount", "USD quote valuation overflows"))
    }
}

/// One quote request: pair shape, side, and canonical satoshi amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRequest {
    pub swap_type: SwapType,
    pub side: QuoteSide,
    pub amount: String,
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Exact derived quote terms. Amounts are canonical satoshi decimal
/// strings, matching the wire grammar the session validators enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedQuote {
    pub swap_type: SwapType,
    pub side: QuoteSide,
    pub input_amount: String,
    pub output_amount: String,
    /// The spread promise: equals the configured spread basis points.
    pub fee_bps: String,
    /// Spread component: `floor(input_amount * fee_bps / 10000)`.
    pub provider_fee: String,
    /// Miner-fee component: `worst_case_vbytes * feerate` exactly.
    pub miner_fee_budget: String,
    /// Routing component: `floor(input_amount * routing_ppm / 1000000)` for
    /// submarine swaps, `"0"` otherwise.
    pub lightning_routing_fee_budget: String,
    /// `provider_fee + miner_fee_budget + lightning_routing_fee_budget`.
    pub maximum_total_fee: String,
    /// Smallest quotable input for this derivation context (config floor
    /// raised to the smallest fee-viable input). Advisory limit for the
    /// published Quote range; per-amount validation is authoritative.
    pub min_input: String,
    /// Largest quotable input: configured maximum clamped to the capacity
    /// bucket's available amount.
    pub max_input: String,
    pub quote_created_at: u64,
    pub quote_expires_at: u64,
    pub reservation: ReservationTier,
    pub capacity_bucket_id: String,
    pub feerate: FeerateObservation,
    pub worst_case_vbytes: u64,
    pub amount_equation: String,
    pub rounding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_feed_application: Option<PriceFeedApplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_feed_fallback: Option<PriceFeedFallback>,
}

impl DerivedQuote {
    /// The exact amount and fee members of the MKT-SWP Quote `terms`
    /// object, ready to merge into the profile passed to the session Quote
    /// constructors. The embedding supplies every remaining `terms` member.
    pub fn amount_terms(&self) -> Map<String, Value> {
        let mut terms = Map::new();
        terms.insert(
            "input_amount".into(),
            Value::String(self.input_amount.clone()),
        );
        terms.insert(
            "output_amount".into(),
            Value::String(self.output_amount.clone()),
        );
        terms.insert("fee_bps".into(), Value::String(self.fee_bps.clone()));
        terms.insert(
            "provider_fee".into(),
            Value::String(self.provider_fee.clone()),
        );
        terms.insert(
            "miner_fee_budget".into(),
            Value::String(self.miner_fee_budget.clone()),
        );
        terms.insert(
            "lightning_routing_fee_budget".into(),
            Value::String(self.lightning_routing_fee_budget.clone()),
        );
        terms.insert(
            "maximum_total_fee".into(),
            Value::String(self.maximum_total_fee.clone()),
        );
        terms.insert(
            "amount_equation".into(),
            Value::String(self.amount_equation.clone()),
        );
        terms.insert("rounding".into(), Value::String(self.rounding.clone()));
        terms
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

fn canonical_sat(value: &str, label: &str) -> Result<u64, SwapClientError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(provider_error(
            "swp_invalid_amount",
            format!("{label} is not a canonical satoshi decimal string"),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| provider_error("swp_invalid_amount", format!("{label} exceeds u64")))
}

fn floor_scaled(amount: u64, numerator: u64, denominator: u64) -> Result<u64, SwapClientError> {
    u64::try_from(u128::from(amount) * u128::from(numerator) / u128::from(denominator)).map_err(
        |_| {
            provider_error(
                "swp_invalid_fee",
                "fee component exceeds the v1 amount range",
            )
        },
    )
}

fn output_floor(swap_type: SwapType) -> u64 {
    match swap_type {
        // Submarine output settles on Lightning; any positive amount pays.
        SwapType::Submarine => LIGHTNING_OUTPUT_FLOOR_SAT,
        // Reverse and chain outputs settle on chain and must clear dust.
        SwapType::Reverse | SwapType::Chain => CHAIN_OUTPUT_DUST_SAT,
    }
}

fn routing_ppm(config: &PricingConfig, swap_type: SwapType) -> u64 {
    match swap_type {
        // The provider pays outbound Lightning only on submarine swaps.
        SwapType::Submarine => config.lightning_routing_fee_ppm,
        SwapType::Reverse | SwapType::Chain => 0,
    }
}

struct FeeComponents {
    provider_fee: u64,
    miner_fee_budget: u64,
    lightning_routing_fee_budget: u64,
    output: Option<u64>,
}

fn fee_components(
    config: &PricingConfig,
    swap_type: SwapType,
    miner_fee_budget: u64,
    input: u64,
) -> Result<FeeComponents, SwapClientError> {
    let provider_fee = floor_scaled(input, config.spread_bps, 10_000)?;
    let lightning_routing_fee_budget =
        floor_scaled(input, routing_ppm(config, swap_type), 1_000_000)?;
    let output = input
        .checked_sub(provider_fee)
        .and_then(|value| value.checked_sub(miner_fee_budget))
        .and_then(|value| value.checked_sub(lightning_routing_fee_budget));
    Ok(FeeComponents {
        provider_fee,
        miner_fee_budget,
        lightning_routing_fee_budget,
        output,
    })
}

/// Smallest input whose promised output clears the settlement floor, found
/// as a bounded deterministic search around the closed-form candidate.
fn min_viable_input(
    config: &PricingConfig,
    swap_type: SwapType,
    miner_fee_budget: u64,
) -> Result<u64, SwapClientError> {
    let floor = output_floor(swap_type);
    let variable_ppm = config.spread_bps * 100 + routing_ppm(config, swap_type);
    if variable_ppm >= 1_000_000 {
        return Err(provider_error(
            "swp_invalid_fee",
            "variable fee rate consumes the entire input",
        ));
    }
    let needed = u128::from(miner_fee_budget) + u128::from(floor);
    let mut candidate =
        u64::try_from((needed * 1_000_000).div_ceil(u128::from(1_000_000 - variable_ppm)))
            .map_err(|_| {
                provider_error(
                    "swp_invalid_fee",
                    "minimum viable amount exceeds the v1 amount range",
                )
            })?;
    let viable = |input: u64| -> Result<bool, SwapClientError> {
        Ok(fee_components(config, swap_type, miner_fee_budget, input)?
            .output
            .is_some_and(|output| output >= floor))
    };
    let mut steps = 0;
    while !viable(candidate)? {
        candidate = candidate.checked_add(1).ok_or_else(|| {
            provider_error(
                "swp_invalid_fee",
                "minimum viable amount exceeds the v1 amount range",
            )
        })?;
        steps += 1;
        if steps > MIN_VIABLE_SEARCH_STEPS {
            return Err(provider_error(
                "swp_invalid_fee",
                "minimum viable amount search did not converge",
            ));
        }
    }
    while candidate > 1 && viable(candidate - 1)? {
        candidate -= 1;
        steps += 1;
        if steps > MIN_VIABLE_SEARCH_STEPS {
            return Err(provider_error(
                "swp_invalid_fee",
                "minimum viable amount search did not converge",
            ));
        }
    }
    Ok(candidate)
}

/// Smallest input whose promised output covers `desired`, found as a
/// bounded deterministic search around the closed-form candidate.
fn input_for_output(
    config: &PricingConfig,
    swap_type: SwapType,
    miner_fee_budget: u64,
    desired: u64,
) -> Result<u64, SwapClientError> {
    let variable_ppm = config.spread_bps * 100 + routing_ppm(config, swap_type);
    if variable_ppm >= 1_000_000 {
        return Err(provider_error(
            "swp_invalid_fee",
            "variable fee rate consumes the entire input",
        ));
    }
    let needed = u128::from(miner_fee_budget) + u128::from(desired);
    let mut candidate =
        u64::try_from((needed * 1_000_000).div_ceil(u128::from(1_000_000 - variable_ppm)))
            .map_err(|_| {
                provider_error(
                    "swp_invalid_amount",
                    "requested output amount exceeds the v1 amount range",
                )
            })?;
    let covers = |input: u64| -> Result<bool, SwapClientError> {
        Ok(fee_components(config, swap_type, miner_fee_budget, input)?
            .output
            .is_some_and(|output| output >= desired))
    };
    let mut steps = 0;
    while !covers(candidate)? {
        candidate = candidate.checked_add(1).ok_or_else(|| {
            provider_error(
                "swp_invalid_amount",
                "requested output amount exceeds the v1 amount range",
            )
        })?;
        steps += 1;
        if steps > MIN_VIABLE_SEARCH_STEPS {
            return Err(provider_error(
                "swp_invalid_amount",
                "input search for the requested output did not converge",
            ));
        }
    }
    while candidate > 1 && covers(candidate - 1)? {
        candidate -= 1;
        steps += 1;
        if steps > MIN_VIABLE_SEARCH_STEPS {
            return Err(provider_error(
                "swp_invalid_amount",
                "input search for the requested output did not converge",
            ));
        }
    }
    Ok(candidate)
}

/// Derive the exact quote terms for one request. Pure and reproducible:
/// no I/O, no clock, no randomness.
pub fn derive_quote(
    config: &PricingConfig,
    feerate: &FeerateObservation,
    capacity: &CapacityBounds,
    request: &QuoteRequest,
    created_at: u64,
) -> Result<DerivedQuote, SwapClientError> {
    derive_quote_with_worst_case_vbytes(
        config,
        feerate,
        capacity,
        request,
        created_at,
        worst_case_redeem_vbytes(request.swap_type),
    )
}

/// Derive a quote with an optional provider-local market-data packet. A
/// missing, invalid, or stale packet produces the same static result as
/// [`derive_quote`]. A fresh packet adjusts only the provider spread and adds
/// deterministic USD valuation metadata.
pub fn derive_quote_with_price_feed(
    config: &PricingConfig,
    feerate: &FeerateObservation,
    capacity: &CapacityBounds,
    request: &QuoteRequest,
    created_at: u64,
    price_feed: Option<&PriceFeedPacket>,
) -> Result<DerivedQuote, SwapClientError> {
    derive_quote_with_price_feed_and_worst_case_vbytes(
        config,
        feerate,
        capacity,
        request,
        created_at,
        worst_case_redeem_vbytes(request.swap_type),
        price_feed,
    )
}

pub fn derive_quote_with_price_feed_and_worst_case_vbytes(
    config: &PricingConfig,
    feerate: &FeerateObservation,
    capacity: &CapacityBounds,
    request: &QuoteRequest,
    created_at: u64,
    worst_case_vbytes: u64,
    price_feed: Option<&PriceFeedPacket>,
) -> Result<DerivedQuote, SwapClientError> {
    let (validated_feed, fallback) = match price_feed {
        Some(packet) => match packet.validate_at(created_at) {
            Ok(feed) => (Some(feed), None),
            Err(error) => (None, Some(PriceFeedFallback { reason: error.0 })),
        },
        None => (None, None),
    };
    let mut effective_config = config.clone();
    if let Some(feed) = &validated_feed {
        effective_config.spread_bps = feed.effective_spread_bps(config.spread_bps);
    }
    let mut derived = derive_quote_with_worst_case_vbytes(
        &effective_config,
        feerate,
        capacity,
        request,
        created_at,
        worst_case_vbytes,
    )?;
    if let Some(feed) = validated_feed {
        let input_amount = canonical_sat(&derived.input_amount, "derived input amount")?;
        let output_amount = canonical_sat(&derived.output_amount, "derived output amount")?;
        let input_value_usd_cents = feed.usd_value_cents(input_amount)?.to_string();
        let output_value_usd_cents = feed.usd_value_cents(output_amount)?.to_string();
        derived.price_feed_application = Some(PriceFeedApplication {
            source: feed.packet.source,
            index_price_usd_cents: feed.packet.index_price_usd_cents,
            realized_volatility_bps: feed.packet.realized_volatility_bps,
            realized_volatility_window_seconds: feed.packet.realized_volatility_window_seconds,
            observed_at: feed.packet.observed_at,
            max_age_seconds: feed.packet.max_age_seconds,
            static_spread_bps: config.spread_bps.to_string(),
            effective_spread_bps: effective_config.spread_bps.to_string(),
            input_value_usd_cents,
            output_value_usd_cents,
        });
    }
    derived.price_feed_fallback = fallback;
    Ok(derived)
}

pub fn derive_quote_with_worst_case_vbytes(
    config: &PricingConfig,
    feerate: &FeerateObservation,
    capacity: &CapacityBounds,
    request: &QuoteRequest,
    created_at: u64,
    worst_case_vbytes: u64,
) -> Result<DerivedQuote, SwapClientError> {
    config
        .validate()
        .map_err(|error| provider_error("swp_invalid_fee", error.0))?;
    if worst_case_vbytes == 0 || worst_case_vbytes > 100_000 {
        return Err(provider_error(
            "swp_invalid_fee",
            "quote fee weight is outside the provider bound",
        ));
    }
    let sat_per_vb = feerate.sat_per_vb();
    if !(1..=MAX_FEERATE_SAT_PER_VB).contains(&sat_per_vb) {
        return Err(provider_error(
            "swp_invalid_fee",
            "quote feerate must be between 1 and 2000 sat/vB",
        ));
    }
    let amount = canonical_sat(&request.amount, "requested amount")?;
    if amount == 0 || amount > MAX_AMOUNT_SAT {
        return Err(provider_error(
            "swp_invalid_amount",
            "requested amount must be positive and at most 2100000000000000",
        ));
    }
    let available = canonical_sat(&capacity.available_capacity, "available capacity")?;

    let miner_fee_budget = worst_case_vbytes
        .checked_mul(sat_per_vb)
        .ok_or_else(|| provider_error("swp_invalid_fee", "miner fee component overflows"))?;

    let max_input = config.max_swap_sat.min(available);
    let min_input = config.min_swap_sat.max(min_viable_input(
        config,
        request.swap_type,
        miner_fee_budget,
    )?);
    if max_input < min_input {
        return Err(provider_error(
            "swp_side_disabled",
            "available capacity is below the minimum quotable amount",
        ));
    }

    let input = match request.side {
        QuoteSide::Input => amount,
        QuoteSide::Output => input_for_output(config, request.swap_type, miner_fee_budget, amount)?,
    };
    if input < min_input || input > max_input {
        return Err(provider_error(
            "swp_invalid_amount",
            "requested amount is outside the quotable range",
        ));
    }

    let components = fee_components(config, request.swap_type, miner_fee_budget, input)?;
    let output = components
        .output
        .filter(|output| *output >= output_floor(request.swap_type))
        .ok_or_else(|| {
            provider_error(
                "swp_invalid_amount",
                "requested amount cannot cover the quoted fees and settlement floor",
            )
        })?;

    // Invariant, enforced on every derivation: the quote's fee is never
    // below its worst-case redeemable path cost at the quoted feerate.
    let worst_case_cost = worst_case_vbytes
        .checked_mul(sat_per_vb)
        .ok_or_else(|| provider_error("swp_invalid_fee", "miner fee component overflows"))?;
    let total_fee = components
        .provider_fee
        .checked_add(components.miner_fee_budget)
        .and_then(|fee| fee.checked_add(components.lightning_routing_fee_budget))
        .ok_or_else(|| provider_error("swp_invalid_fee", "total fee overflows"))?;
    if components.miner_fee_budget < worst_case_cost || total_fee < worst_case_cost {
        return Err(provider_error(
            "swp_invalid_fee",
            "derived fee is below the worst-case redeemable path cost",
        ));
    }

    let quote_expires_at = created_at
        .checked_add(config.quote_expiry_seconds)
        .ok_or_else(|| provider_error("swp_quote_expired", "quote expiry timestamp overflows"))?;

    Ok(DerivedQuote {
        swap_type: request.swap_type,
        side: request.side,
        input_amount: input.to_string(),
        output_amount: output.to_string(),
        fee_bps: config.spread_bps.to_string(),
        provider_fee: components.provider_fee.to_string(),
        miner_fee_budget: components.miner_fee_budget.to_string(),
        lightning_routing_fee_budget: components.lightning_routing_fee_budget.to_string(),
        maximum_total_fee: total_fee.to_string(),
        min_input: min_input.to_string(),
        max_input: max_input.to_string(),
        quote_created_at: created_at,
        quote_expires_at,
        reservation: config.reservation_tier,
        capacity_bucket_id: capacity.capacity_bucket_id.clone(),
        feerate: feerate.clone(),
        worst_case_vbytes,
        amount_equation: "input_minus_provider_and_quoted_fees".to_owned(),
        rounding: "floor_output_sats".to_owned(),
        price_feed_application: None,
        price_feed_fallback: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_core::mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, parse_swap_script, tapleaf_hash,
    };

    fn base_config() -> PricingConfig {
        PricingConfig {
            spread_bps: 25,
            fallback_feerate_sat_per_vb: Some(2),
            min_swap_sat: 10_000,
            max_swap_sat: 1_000_000,
            quote_expiry_seconds: 300,
            reservation_tier: ReservationTier::Soft,
            lightning_routing_fee_ppm: 1_000,
        }
    }

    fn capacity(available: &str) -> CapacityBounds {
        CapacityBounds {
            capacity_bucket_id: "bucket-1".into(),
            available_capacity: available.into(),
        }
    }

    fn live_10() -> FeerateObservation {
        FeerateObservation::Live {
            sat_per_vb: 10,
            source: "bitcoind-estimatesmartfee-2".into(),
        }
    }

    #[test]
    fn leaf_templates_parse_through_core_primitives() -> Result<(), Box<dyn std::error::Error>> {
        let claim = claim_leaf_script_template();
        let refund = refund_leaf_script_template();
        assert_eq!(claim.len(), 73);
        assert_eq!(refund.len(), 41);
        parse_swap_script(&claim)?;
        parse_swap_script(&refund)?;
        tapleaf_hash(0xc0, &claim)?;
        tapleaf_hash(0xc0, &refund)?;
        Ok(())
    }

    #[test]
    fn weight_arithmetic_matches_documented_values() {
        assert_eq!(claim_spend_vbytes(), 155);
        assert_eq!(refund_spend_vbytes(), 139);
        assert_eq!(lockup_vbytes(), 155);
        assert_eq!(worst_case_redeem_vbytes(SwapType::Submarine), 155);
        assert_eq!(worst_case_redeem_vbytes(SwapType::Reverse), 294);
        assert_eq!(worst_case_redeem_vbytes(SwapType::Chain), 310);
        assert_eq!(
            funding_feerate_from_quote_budget(SwapType::Reverse, 2_940),
            Ok(10)
        );
        assert!(funding_feerate_from_quote_budget(SwapType::Reverse, 2_939).is_err());
    }

    #[test]
    fn weight_arithmetic_matches_constructed_transactions() -> Result<(), Box<dyn std::error::Error>>
    {
        let claim_script = production_claim_leaf_script([0; 32], [0; 32]);
        let refund_script = production_refund_leaf_script(499_999_999, [0; 32])
            .ok_or("worst-case refund height must be valid")?;
        let claim = representative_transaction(
            vec![vec![0; 65], vec![0; 32], claim_script, vec![0; 65]],
            1,
        );
        let refund = representative_transaction(vec![vec![0; 65], refund_script, vec![0; 65]], 1);
        let lockup = representative_transaction(vec![vec![0; 65]], 2);

        assert_eq!(claim.virtual_size()?, claim_spend_vbytes());
        assert_eq!(refund.virtual_size()?, refund_spend_vbytes());
        assert_eq!(lockup.virtual_size()?, lockup_vbytes());
        Ok(())
    }

    fn representative_transaction(witness: Vec<Vec<u8>>, output_count: usize) -> Transaction {
        let mut p2tr_script_pubkey = vec![0x51, 0x20];
        p2tr_script_pubkey.extend_from_slice(&[0; 32]);
        Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [0; 32],
                previous_output: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness,
            }],
            (0..output_count)
                .map(|_| TransactionOutput {
                    value_sat: 1_000,
                    script_pubkey: p2tr_script_pubkey.clone(),
                })
                .collect(),
            0,
        )
    }

    #[test]
    fn quote_fee_never_below_worst_case_redeemable_cost() {
        let config = base_config();
        for swap_type in [SwapType::Submarine, SwapType::Reverse, SwapType::Chain] {
            for sat_per_vb in [1u64, 2, 7, 25, 144, 800, 2_000] {
                for amount in [10_000u64, 25_000, 123_457, 500_000, 1_000_000] {
                    let feerate = FeerateObservation::Fallback { sat_per_vb };
                    let request = QuoteRequest {
                        swap_type,
                        side: QuoteSide::Input,
                        amount: amount.to_string(),
                    };
                    let derived = match derive_quote(
                        &config,
                        &feerate,
                        &capacity("1000000"),
                        &request,
                        1_785_859_200,
                    ) {
                        Ok(derived) => derived,
                        // High feerates can price small amounts out of the
                        // quotable range; refusal is the correct outcome.
                        Err(error) => {
                            assert!(
                                matches!(error.code, "swp_invalid_amount" | "swp_side_disabled"),
                                "unexpected refusal {error}"
                            );
                            continue;
                        }
                    };
                    let worst_case = worst_case_redeem_vbytes(swap_type) * sat_per_vb;
                    let miner: u64 = derived.miner_fee_budget.parse().unwrap();
                    let total: u64 = derived.maximum_total_fee.parse().unwrap();
                    assert!(miner >= worst_case, "miner component below redeemable cost");
                    assert!(total >= worst_case, "total fee below redeemable cost");
                    let input: u64 = derived.input_amount.parse().unwrap();
                    let output: u64 = derived.output_amount.parse().unwrap();
                    let provider: u64 = derived.provider_fee.parse().unwrap();
                    let routing: u64 = derived.lightning_routing_fee_budget.parse().unwrap();
                    assert_eq!(output, input - provider - miner - routing);
                    assert_eq!(provider, input * config.spread_bps / 10_000);
                }
            }
        }
    }

    #[test]
    fn derivation_is_reproducible() -> Result<(), SwapClientError> {
        let config = base_config();
        let request = QuoteRequest {
            swap_type: SwapType::Submarine,
            side: QuoteSide::Input,
            amount: "100000".into(),
        };
        let first = derive_quote(
            &config,
            &live_10(),
            &capacity("500000"),
            &request,
            1_785_859_200,
        )?;
        let second = derive_quote(
            &config,
            &live_10(),
            &capacity("500000"),
            &request,
            1_785_859_200,
        )?;
        assert_eq!(first, second);
        assert_eq!(first.output_amount, "98100");
        assert_eq!(first.provider_fee, "250");
        assert_eq!(first.miner_fee_budget, "1550");
        assert_eq!(first.lightning_routing_fee_budget, "100");
        assert_eq!(first.maximum_total_fee, "1900");
        assert_eq!(first.quote_expires_at, 1_785_859_500);
        Ok(())
    }

    #[test]
    fn output_side_finds_smallest_covering_input() -> Result<(), Box<dyn std::error::Error>> {
        let config = base_config();
        let request = QuoteRequest {
            swap_type: SwapType::Submarine,
            side: QuoteSide::Output,
            amount: "98110".into(),
        };
        let derived = derive_quote(
            &config,
            &live_10(),
            &capacity("500000"),
            &request,
            1_785_859_200,
        )?;
        assert_eq!(derived.input_amount, "100010");
        assert_eq!(derived.output_amount, "98110");
        let input: u64 = derived.input_amount.parse()?;
        let smaller = fee_components(&config, SwapType::Submarine, 1_550, input - 1)?.output;
        let Some(smaller) = smaller else {
            return Err("smaller output unexpectedly underflowed".into());
        };
        assert!(smaller < 98_110, "a smaller input would also cover");
        Ok(())
    }

    #[test]
    fn refuses_without_live_estimate_or_configured_fallback() {
        let mut config = base_config();
        config.fallback_feerate_sat_per_vb = None;
        let error = feerate_for_quote(&config, None).unwrap_err();
        assert_eq!(error.code, "swp_invalid_fee");
        assert_eq!(
            error.detail,
            "no live feerate estimate and IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB is not configured; refusing to quote"
        );
    }

    #[test]
    fn fallback_applies_only_when_configured() {
        let config = base_config();
        assert_eq!(
            feerate_for_quote(&config, None).unwrap(),
            FeerateObservation::Fallback { sat_per_vb: 2 }
        );
        assert_eq!(
            feerate_for_quote(&config, Some((12, "bitcoind-estimatesmartfee-2"))).unwrap(),
            FeerateObservation::Live {
                sat_per_vb: 12,
                source: "bitcoind-estimatesmartfee-2".into()
            }
        );
        assert_eq!(
            feerate_for_quote(&config, Some((0, "bad")))
                .unwrap_err()
                .code,
            "swp_invalid_fee"
        );
    }

    #[test]
    fn config_from_lookup_validates_fail_fast() {
        let ok = PricingConfig::from_lookup(|name| match name {
            "IMMORTAL_PROVIDER_SPREAD_BPS" => Some("25".into()),
            "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB" => Some("2".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(ok.spread_bps, 25);
        assert_eq!(ok.fallback_feerate_sat_per_vb, Some(2));
        assert_eq!(ok.min_swap_sat, 10_000);
        assert_eq!(ok.max_swap_sat, 1_000_000);
        assert_eq!(ok.quote_expiry_seconds, 300);
        assert_eq!(ok.reservation_tier, ReservationTier::Hard);
        assert_eq!(ok.lightning_routing_fee_ppm, 0);

        for (value, expected) in [
            ("none", ReservationTier::None),
            ("soft", ReservationTier::Soft),
            ("hard", ReservationTier::Hard),
        ] {
            assert_eq!(
                PricingConfig::from_lookup(|name| {
                    (name == "IMMORTAL_PROVIDER_RESERVATION_TIER").then(|| value.to_owned())
                })
                .map(|config| config.reservation_tier),
                Ok(expected)
            );
        }

        for (name, value, message) in [
            (
                "IMMORTAL_PROVIDER_SPREAD_BPS",
                "1001",
                "IMMORTAL_PROVIDER_SPREAD_BPS must be between 0 and 1000",
            ),
            (
                "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB",
                "0",
                "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB must be between 1 and 2000",
            ),
            (
                "IMMORTAL_PROVIDER_QUOTE_MIN_SAT",
                "0",
                "IMMORTAL_PROVIDER_QUOTE_MIN_SAT must be positive",
            ),
            (
                "IMMORTAL_PROVIDER_QUOTE_MAX_SAT",
                "9999",
                "IMMORTAL_PROVIDER_QUOTE_MAX_SAT must be at least IMMORTAL_PROVIDER_QUOTE_MIN_SAT",
            ),
            (
                "IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS",
                "0",
                "IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS must be between 1 and 3600",
            ),
            (
                "IMMORTAL_PROVIDER_RESERVATION_TIER",
                "firm",
                "IMMORTAL_PROVIDER_RESERVATION_TIER must be one of none, soft, hard",
            ),
            (
                "IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM",
                "100001",
                "IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM must be between 0 and 100000",
            ),
            (
                "IMMORTAL_PROVIDER_SPREAD_BPS",
                "abc",
                "IMMORTAL_PROVIDER_SPREAD_BPS is not a valid non-negative integer",
            ),
        ] {
            let error = PricingConfig::from_lookup(|lookup_name| {
                if lookup_name == name {
                    Some(value.into())
                } else {
                    None
                }
            })
            .unwrap_err();
            assert_eq!(error.0, message, "wrong message for {name}={value}");
        }
    }

    #[test]
    fn capacity_and_range_boundaries() {
        let config = base_config();
        let request = |amount: &str| QuoteRequest {
            swap_type: SwapType::Submarine,
            side: QuoteSide::Input,
            amount: amount.into(),
        };
        // Below the configured minimum.
        assert_eq!(
            derive_quote(
                &config,
                &live_10(),
                &capacity("500000"),
                &request("9999"),
                1_785_859_200
            )
            .unwrap_err()
            .code,
            "swp_invalid_amount"
        );
        // Above the capacity-clamped maximum.
        assert_eq!(
            derive_quote(
                &config,
                &live_10(),
                &capacity("500000"),
                &request("500001"),
                1_785_859_200
            )
            .unwrap_err()
            .code,
            "swp_invalid_amount"
        );
        // Capacity below the minimum disables the side.
        assert_eq!(
            derive_quote(
                &config,
                &live_10(),
                &capacity("5000"),
                &request("12000"),
                1_785_859_200
            )
            .unwrap_err()
            .code,
            "swp_side_disabled"
        );
        // Expiry overflow is refused, never wrapped.
        assert_eq!(
            derive_quote(
                &config,
                &live_10(),
                &capacity("500000"),
                &request("100000"),
                u64::MAX
            )
            .unwrap_err()
            .code,
            "swp_quote_expired"
        );
    }

    #[test]
    fn miner_fee_floor_raises_minimum_input_above_config_floor() -> Result<(), SwapClientError> {
        let mut config = base_config();
        config.min_swap_sat = 1_000;
        let derived = derive_quote(
            &config,
            &live_10(),
            &capacity("1000000"),
            &QuoteRequest {
                swap_type: SwapType::Submarine,
                side: QuoteSide::Input,
                amount: "1555".into(),
            },
            1_785_859_200,
        )?;
        assert_eq!(derived.min_input, "1555");
        assert_eq!(derived.output_amount, "1");
        assert_eq!(
            derive_quote(
                &config,
                &live_10(),
                &capacity("1000000"),
                &QuoteRequest {
                    swap_type: SwapType::Submarine,
                    side: QuoteSide::Input,
                    amount: "1000".into(),
                },
                1_785_859_200,
            )
            .unwrap_err()
            .code,
            "swp_invalid_amount"
        );
        Ok(())
    }
}
