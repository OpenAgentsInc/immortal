//! Replays the closed swp-pricing-v1 derivation-vector manifest (issue #28).

use serde_json::Value;

use immortal_provider::pricing::{
    CapacityBounds, FeerateObservation, PriceFeedPacket, PricingConfig, QuoteRequest, SwapType,
    claim_leaf_script_template, claim_spend_vbytes, derive_quote, derive_quote_with_price_feed,
    feerate_for_quote, lockup_vbytes, refund_leaf_script_template, refund_spend_vbytes,
    worst_case_redeem_vbytes,
};

const FIXTURES: &str = include_str!("../../../tests/fixtures/nipmkt/swp-pricing-v1.json");
const PRICE_FEED_FIXTURES: &str =
    include_str!("../../../tests/fixtures/provider/price-feed-v1.json");

#[test]
fn price_feed_fixture_replays_fresh_and_stale_paths() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: Value = serde_json::from_str(PRICE_FEED_FIXTURES)?;
    if manifest["schema"] != "openagents.immortal.provider-price-feed-fixtures.v1" {
        return Err("price-feed fixture schema changed".into());
    }
    let packet_json = serde_json::to_vec(&manifest["fresh_packet"])?;
    let packet = PriceFeedPacket::from_json_bytes(&packet_json)?;
    let input = &manifest["quote_input"];
    let config: PricingConfig = serde_json::from_value(input["config"].clone())?;
    let feerate: FeerateObservation = serde_json::from_value(input["feerate"].clone())?;
    let capacity: CapacityBounds = serde_json::from_value(input["capacity"].clone())?;
    let request: QuoteRequest = serde_json::from_value(input["request"].clone())?;
    let created_at = input["created_at"]
        .as_u64()
        .ok_or("price-feed fixture creation time is invalid")?;

    let fresh = derive_quote_with_price_feed(
        &config,
        &feerate,
        &capacity,
        &request,
        created_at,
        Some(&packet),
    )?;
    let fresh_expect = &manifest["fresh_expect"];
    assert_eq!(fresh.fee_bps, fresh_expect["fee_bps"]);
    assert_eq!(fresh.provider_fee, fresh_expect["provider_fee"]);
    assert_eq!(fresh.output_amount, fresh_expect["output_amount"]);
    let application = fresh
        .price_feed_application
        .ok_or("fresh packet was not applied")?;
    assert_eq!(
        application.input_value_usd_cents,
        fresh_expect["input_value_usd_cents"]
    );
    assert_eq!(
        application.output_value_usd_cents,
        fresh_expect["output_value_usd_cents"]
    );
    assert!(fresh.price_feed_fallback.is_none());

    let stale_at = manifest["stale_at"]
        .as_u64()
        .ok_or("price-feed fixture stale time is invalid")?;
    let stale = derive_quote_with_price_feed(
        &config,
        &feerate,
        &capacity,
        &request,
        stale_at,
        Some(&packet),
    )?;
    let stale_expect = &manifest["stale_expect"];
    assert_eq!(stale.fee_bps, stale_expect["fee_bps"]);
    assert_eq!(stale.provider_fee, stale_expect["provider_fee"]);
    assert_eq!(stale.output_amount, stale_expect["output_amount"]);
    assert!(stale.price_feed_application.is_none());
    let fallback = stale
        .price_feed_fallback
        .ok_or("stale fallback is absent")?;
    assert_eq!(fallback.reason, stale_expect["fallback_reason"]);

    let mut unknown_member = manifest["fresh_packet"].clone();
    unknown_member["credential"] = Value::String("must-not-be-accepted".to_owned());
    let unknown_member_json = serde_json::to_vec(&unknown_member)?;
    assert_eq!(
        PriceFeedPacket::from_json_bytes(&unknown_member_json),
        Err(immortal_provider::pricing::PriceFeedValidationError(
            "packet is not strict JSON in the v1 shape".to_owned()
        ))
    );

    let mut future = packet;
    future.observed_at = created_at + 1;
    let future_quote = derive_quote_with_price_feed(
        &config,
        &feerate,
        &capacity,
        &request,
        created_at,
        Some(&future),
    )?;
    assert!(future_quote.price_feed_application.is_none());
    assert_eq!(
        future_quote
            .price_feed_fallback
            .ok_or("future fallback is absent")?
            .reason,
        "observation time is invalid"
    );
    Ok(())
}

#[test]
fn pricing_fixture_weights_match_module_derivations() {
    let manifest: Value = serde_json::from_str(FIXTURES).expect("fixture manifest parses");
    assert_eq!(
        manifest["schema"],
        "openagents.mkt-swp.provider-pricing-fixtures.v1"
    );
    let weights = &manifest["weights"];
    assert_eq!(
        weights["claim_leaf_script_bytes"].as_u64().unwrap(),
        claim_leaf_script_template().len() as u64
    );
    assert_eq!(
        weights["refund_leaf_script_bytes"].as_u64().unwrap(),
        refund_leaf_script_template().len() as u64
    );
    assert_eq!(
        weights["claim_spend_vbytes"].as_u64().unwrap(),
        claim_spend_vbytes()
    );
    assert_eq!(
        weights["refund_spend_vbytes"].as_u64().unwrap(),
        refund_spend_vbytes()
    );
    assert_eq!(weights["lockup_vbytes"].as_u64().unwrap(), lockup_vbytes());
    let worst = &weights["worst_case_redeem_vbytes"];
    assert_eq!(
        worst["submarine"].as_u64().unwrap(),
        worst_case_redeem_vbytes(SwapType::Submarine)
    );
    assert_eq!(
        worst["reverse"].as_u64().unwrap(),
        worst_case_redeem_vbytes(SwapType::Reverse)
    );
    assert_eq!(
        worst["chain"].as_u64().unwrap(),
        worst_case_redeem_vbytes(SwapType::Chain)
    );
}

#[test]
fn pricing_fixture_vectors_replay_exactly() {
    let manifest: Value = serde_json::from_str(FIXTURES).expect("fixture manifest parses");
    let vectors = manifest["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 16, "closed manifest lost vectors");
    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let config: PricingConfig = serde_json::from_value(vector["config"].clone())
            .unwrap_or_else(|error| panic!("{name}: config parses: {error}"));
        config
            .validate()
            .unwrap_or_else(|error| panic!("{name}: config validates: {error}"));
        let capacity: CapacityBounds = serde_json::from_value(vector["capacity"].clone())
            .unwrap_or_else(|error| panic!("{name}: capacity parses: {error}"));
        let request: QuoteRequest = serde_json::from_value(vector["request"].clone())
            .unwrap_or_else(|error| panic!("{name}: request parses: {error}"));
        let created_at = vector["created_at"].as_u64().expect("created_at");
        let expect = &vector["expect"];
        let expected_error = expect["error"].as_str();

        let feerate_spec = &vector["feerate"];
        let live = match feerate_spec["kind"].as_str().expect("feerate kind") {
            "live" => Some((
                feerate_spec["sat_per_vb"]
                    .as_u64()
                    .expect("live sat_per_vb"),
                feerate_spec["source"].as_str().expect("live source"),
            )),
            "fallback" | "none" => None,
            other => panic!("{name}: unknown feerate kind {other}"),
        };
        let feerate = match feerate_for_quote(&config, live) {
            Ok(feerate) => feerate,
            Err(error) => {
                let expected = expected_error
                    .unwrap_or_else(|| panic!("{name}: unexpected feerate refusal {error}"));
                assert_eq!(error.code, expected, "{name}: feerate refusal code");
                continue;
            }
        };

        match derive_quote(&config, &feerate, &capacity, &request, created_at) {
            Ok(derived) => {
                assert!(
                    expected_error.is_none(),
                    "{name}: expected error {expected_error:?} but derivation succeeded"
                );
                let actual = serde_json::to_value(&derived).expect("derived quote serializes");
                assert_eq!(actual, expect["quote"], "{name}: derived terms differ");
                // Re-derivation is bit-identical: derivation is pure.
                let again =
                    derive_quote(&config, &feerate, &capacity, &request, created_at).unwrap();
                assert_eq!(derived, again, "{name}: derivation is not reproducible");
            }
            Err(error) => {
                let expected =
                    expected_error.unwrap_or_else(|| panic!("{name}: unexpected refusal {error}"));
                assert_eq!(error.code, expected, "{name}: refusal code");
            }
        }
    }
}
