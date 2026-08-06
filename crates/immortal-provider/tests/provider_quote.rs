use immortal_client::mkt_swp_client::{MktSigningRequest, SwapClientConfig, SwapRecordFactory};
use immortal_core::{
    domain::Event,
    market::MarketSigner,
    mkt_swp_verify::{parse_bolt11, sha256},
};
use immortal_provider::{
    ProviderSession, ReservationConfirmation, ReservationRequest,
    bitcoind::ChainTip,
    pricing::{
        CapacityBounds, FeerateObservation, PricingConfig, QuoteRequest, QuoteSide,
        ReservationTier, SwapType as PricingSwapType, derive_quote, feerate_for_quote,
        funding_feerate_from_quote_budget,
    },
    quote::{
        BuiltFundedQuote, FundedQuotePolicy, QuoteWalletAllocation, ReplacementPolicy,
        build_funded_quote,
    },
    wallet::{BitcoinNetwork, ProviderWallet, WalletPath},
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const FIXTURE: &str = include_str!("../../../tests/fixtures/provider/quote-builder-v1.json");
static NEXT_SEED_FILE: AtomicU64 = AtomicU64::new(0);

struct Setup {
    requester: MarketSigner,
    provider: MarketSigner,
    factory: SwapRecordFactory,
    config: SwapClientConfig,
}

impl Setup {
    fn new(session_byte: u8) -> Self {
        let requester = MarketSigner::from_secret_bytes([11; 32]).expect("requester key");
        let provider = MarketSigner::from_secret_bytes([12; 32]).expect("provider key");
        let config = SwapClientConfig {
            session_id: format!("{session_byte:02x}").repeat(32),
            requester_pubkey: requester.pubkey().to_owned(),
            provider_pubkey: provider.pubkey().to_owned(),
            offering_address: format!("39601:{}:funded-swaps", provider.pubkey()),
            provider_route: None,
        };
        let factory = SwapRecordFactory::new(config.clone()).expect("record factory");
        Self {
            requester,
            provider,
            factory,
            config,
        }
    }
}

struct TestWallet {
    wallet: ProviderWallet,
    path: PathBuf,
}

impl TestWallet {
    fn new(network: BitcoinNetwork) -> Self {
        use std::os::unix::fs::OpenOptionsExt;

        let sequence = NEXT_SEED_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "immortal-provider-quote-{}-{sequence}.seed",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create wallet seed file");
        file.write_all("2a".repeat(32).as_bytes())
            .expect("write wallet seed file");
        file.sync_all().expect("sync wallet seed file");
        drop(file);
        let wallet = ProviderWallet::load(&path, network).expect("load wallet");
        Self { wallet, path }
    }
}

impl Drop for TestWallet {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            eprintln!("could not remove provider Quote test seed file: {error}");
        }
    }
}

#[test]
fn fixture_builds_dynamic_submarine_and_reverse_hard_quotes() {
    let fixture = fixture();
    let invoice = fixture["invoice"].as_str().expect("invoice");
    let now = fixture["now"].as_u64().expect("now");
    let tip = chain_tip(fixture);
    let wallet = TestWallet::new(BitcoinNetwork::Mainnet);
    let allocation = wallet_allocation();

    for (index, case) in fixture["cases"]
        .as_array()
        .expect("positive cases")
        .iter()
        .enumerate()
    {
        let setup = Setup::new(u8::try_from(0xa0 + index).expect("session byte"));
        let rfq = signed_rfq(&setup, case, invoice, now, None, None, None, None);
        let rfq_content: Value = serde_json::from_str(&rfq.content).expect("RFQ content");
        if case["swap_type"] == "submarine" {
            assert_eq!(rfq_content["mkt_swp"]["invoice"], invoice);
        } else {
            assert!(rfq_content["mkt_swp"].get("invoice").is_none());
        }
        let policy = policy(fixture, case);
        let built =
            build_funded_quote(&rfq, invoice, &wallet.wallet, allocation, &tip, policy, now)
                .expect("dynamic funded Quote");
        assert_positive_fixture(case, &built);
        if case["swap_type"] == "reverse" {
            let parsed_invoice = parse_bolt11(invoice).expect("fixture invoice");
            assert_eq!(
                built.profile["terms"]["timeout_ladder"]["hold_expiry_height"],
                json!(
                    u64::from(policy.lightning_current_height)
                        + parsed_invoice.minimum_final_cltv_delta
                )
            );
            assert_eq!(
                u64::from(policy.reorg_safety_blocks),
                tip.height - u64::from(policy.lightning_current_height)
            );
        }
        let acceptance_seconds = built
            .expiration
            .checked_sub(now)
            .expect("Quote expires after construction");
        let acceptance_blocks = acceptance_seconds.div_ceil(policy.expected_block_seconds);
        let expected_first_deadline = tip
            .height
            .checked_add(acceptance_blocks)
            .and_then(|height| height.checked_add(u64::from(policy.funding_window_blocks)))
            .expect("fixture deadline");
        let first_deadline = if case["swap_type"] == "submarine" {
            &built.profile["terms"]["timeout_ladder"]["fund_last"]
        } else {
            &built.profile["terms"]["timeout_ladder"]["lock_last"]
        };
        assert_eq!(first_deadline, &json!(expected_first_deadline));
        if case["swap_type"] == "submarine" {
            assert_eq!(
                built.profile["terms"]["timeout_ladder"]["claim_expected_time"],
                built.expiration
                    + u64::from(policy.funding_window_blocks + policy.minimum_confirmations)
                        * policy.expected_block_seconds
            );
        }
        assert!(!built.profile.to_string().contains(invoice));
        assert_eq!(built.profile["terms"]["musig2_execution"], false);
        assert_eq!(
            built.profile["terms"]["verifier_inputs"][0]["musig2_execution"],
            false
        );

        let mut provider = ProviderSession::new(setup.config.clone()).expect("provider session");
        provider.ingest_signed(rfq).expect("ingest RFQ");
        let reservation = ReservationRequest {
            reservation_id: format!("{:02x}", 0xc0 + index).repeat(32),
            capacity_bucket_id: format!(
                "{}-output",
                case["swap_type"].as_str().expect("swap type")
            ),
            reserved_asset_id: built.reserved_asset_id.clone(),
            reserved_amount: built.reserved_amount_sat.to_string(),
            reservation_expires_at: built.expiration,
        };
        let request = provider
            .hard_quote_with_reserve(
                now,
                &format!("{:02x}", 0xd0 + index).repeat(32),
                built.expiration,
                reservation,
                built.profile.clone(),
                |effect| {
                    Ok(ReservationConfirmation {
                        reservation_id: effect.reservation_id.clone(),
                        capacity_bucket_id: effect.capacity_bucket_id.clone(),
                        reserved_asset_id: effect.reserved_asset_id.clone(),
                        reserved_amount: effect.reserved_amount.clone(),
                        committed_capacity: effect.reserved_amount.clone(),
                        reservation_expires_at: effect.reservation_expires_at,
                        allocation_sequence: "1".into(),
                        proof_class: if case["swap_type"] == "submarine" {
                            "lightning_liquidity".into()
                        } else {
                            "utxo_control".into()
                        },
                        proof_ref: format!(
                            "provider-quote-fixture:{}",
                            case["name"].as_str().expect("case name")
                        ),
                        capacity_commitment_sha256: lower_hex(&sha256(
                            case["name"].as_str().expect("case name").as_bytes(),
                        )),
                    })
                },
            )
            .expect("hard Quote reserve gate");
        let signed = sign_private(request, &setup.provider);
        assert!(provider.ingest_signed(signed).expect("ingest hard Quote"));
    }
}

#[test]
fn cooperative_quote_shape_exists_under_the_production_opt_in() {
    let runtime: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-provider-cooperative-runtime-v1.json"
    ))
    .expect("cooperative runtime fixture");
    assert_eq!(runtime["process_gate"]["production_enabled"], true);
    assert_eq!(
        runtime["process_gate"]["provider_contract_advertisement"],
        true
    );

    let fixture = fixture();
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| cases.first())
        .expect("submarine Quote fixture case");
    let invoice = fixture["invoice"].as_str().expect("invoice");
    let now = fixture["now"].as_u64().expect("now");
    let setup = Setup::new(0xde);
    let rfq = signed_rfq(&setup, case, invoice, now, None, None, None, None);
    let wallet = TestWallet::new(BitcoinNetwork::Mainnet);
    let mut cooperative_policy = policy(fixture, case);
    cooperative_policy.cooperative_signing = true;
    let built = build_funded_quote(
        &rfq,
        invoice,
        &wallet.wallet,
        wallet_allocation(),
        &chain_tip(fixture),
        cooperative_policy,
        now,
    )
    .expect("process-gated cooperative Quote");
    let terms = &built.profile["terms"];
    assert_eq!(
        terms["musig2_execution"],
        runtime["quote_profile"]["terms_musig2_execution"]
    );
    let verifier = terms["verifier_inputs"]
        .as_array()
        .and_then(|verifiers| {
            verifiers
                .iter()
                .find(|verifier| verifier["rail"].as_str() == Some("bitcoin"))
                .or_else(|| {
                    verifiers
                        .iter()
                        .find(|verifier| verifier.get("script_pubkey").is_some())
                })
        })
        .expect("Bitcoin verifier");
    assert_eq!(
        verifier["musig2_execution"],
        runtime["quote_profile"]["verifier_musig2_execution"]
    );
    assert_eq!(
        verifier["sighash_policy"],
        runtime["quote_profile"]["sighash_policy"]
    );
    assert!(
        verifier["provider_exit_destination_script_pubkey"]
            .as_str()
            .is_some_and(|script| script.starts_with("5120"))
    );
    assert_eq!(
        verifier["provider_exit_signer_ref"],
        "immortal-provider:source:claim"
    );
    assert_eq!(
        verifier["provider_exit_policy"]["latest_safe_broadcast_height"],
        terms["timeout_ladder"]["claim_last"]
            .as_u64()
            .expect("claim deadline")
            .to_string()
    );
    assert!(
        terms["effect_policy"]["effects"]
            .as_array()
            .is_some_and(|effects| effects.iter().any(|effect| {
                effect["effect_role"] == runtime["quote_profile"]["effect_role"]
                    && effect["leg_id"] == "source"
            }))
    );

    let mut provider = ProviderSession::new(setup.config.clone()).expect("provider session");
    provider.ingest_signed(rfq).expect("ingest RFQ");
    let request = provider
        .hard_quote_with_reserve(
            now,
            &"df".repeat(32),
            built.expiration,
            ReservationRequest {
                reservation_id: "cf".repeat(32),
                capacity_bucket_id: "submarine-output".to_owned(),
                reserved_asset_id: built.reserved_asset_id,
                reserved_amount: built.reserved_amount_sat.to_string(),
                reservation_expires_at: built.expiration,
            },
            built.profile,
            |effect| {
                Ok(ReservationConfirmation {
                    reservation_id: effect.reservation_id.clone(),
                    capacity_bucket_id: effect.capacity_bucket_id.clone(),
                    reserved_asset_id: effect.reserved_asset_id.clone(),
                    reserved_amount: effect.reserved_amount.clone(),
                    committed_capacity: effect.reserved_amount.clone(),
                    reservation_expires_at: effect.reservation_expires_at,
                    allocation_sequence: "1".to_owned(),
                    proof_class: "lightning_liquidity".to_owned(),
                    proof_ref: "provider-cooperative-quote-fixture".to_owned(),
                    capacity_commitment_sha256: lower_hex(&sha256(b"cooperative-quote")),
                })
            },
        )
        .expect("cooperative hard Quote reserve gate");
    let signed = sign_private(request, &setup.provider);
    assert!(provider.ingest_signed(signed).expect("ingest hard Quote"));

    let reverse_case = fixture["cases"]
        .as_array()
        .and_then(|cases| cases.get(1))
        .expect("reverse Quote fixture case");
    let reverse_setup = Setup::new(0xdd);
    let reverse_rfq = signed_rfq(
        &reverse_setup,
        reverse_case,
        invoice,
        now,
        None,
        None,
        None,
        None,
    );
    let mut reverse_policy = policy(fixture, reverse_case);
    reverse_policy.cooperative_signing = true;
    let reverse = build_funded_quote(
        &reverse_rfq,
        invoice,
        &wallet.wallet,
        wallet_allocation(),
        &chain_tip(fixture),
        reverse_policy,
        now,
    )
    .expect("reverse Quote remains script-only under the incomplete gate");
    assert_eq!(reverse.profile["terms"]["musig2_execution"], false);
    assert!(
        reverse.profile["terms"]["verifier_inputs"]
            .as_array()
            .is_some_and(|verifiers| verifiers.iter().all(|verifier| {
                verifier.get("provider_exit_policy").is_none()
                    && verifier.get("provider_exit_signer_ref").is_none()
            }))
    );
}

#[test]
fn pricing_decision_feeds_the_exact_funded_reverse_quote_terms()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture();
    let invoice = fixture["invoice"]
        .as_str()
        .ok_or("Quote fixture invoice is missing")?;
    let now = fixture["now"]
        .as_u64()
        .ok_or("Quote fixture timestamp is missing")?;
    let mut case = fixture["cases"]
        .as_array()
        .and_then(|cases| cases.get(1))
        .cloned()
        .ok_or("reverse Quote fixture case is missing")?;
    case["maximum_total_fee"] = Value::String("500".to_owned());
    let setup = Setup::new(0xd0);
    let rfq = signed_rfq(&setup, &case, invoice, now, None, None, None, None);
    let config = PricingConfig {
        spread_bps: 100,
        fallback_feerate_sat_per_vb: Some(1),
        min_swap_sat: 1,
        max_swap_sat: 10_000,
        quote_expiry_seconds: 60,
        reservation_tier: ReservationTier::Hard,
        lightning_routing_fee_ppm: 0,
    };
    let feerate = feerate_for_quote(&config, None)?;
    let capacity = CapacityBounds {
        capacity_bucket_id: "btc-pricing-integration".to_owned(),
        available_capacity: "5000".to_owned(),
    };
    let derived = derive_quote(
        &config,
        &feerate,
        &capacity,
        &QuoteRequest {
            swap_type: PricingSwapType::Reverse,
            side: QuoteSide::Input,
            amount: "1000".to_owned(),
        },
        now,
    )?;
    let wallet = TestWallet::new(BitcoinNetwork::Mainnet);
    let quote = build_funded_quote(
        &rfq,
        invoice,
        &wallet.wallet,
        wallet_allocation(),
        &chain_tip(fixture),
        FundedQuotePolicy {
            network_id: fixture["network_id"]
                .as_str()
                .ok_or("Quote fixture network is missing")?,
            cooperative_signing: false,
            lightning_current_height: u32::try_from(
                fixture["lightning_height"]
                    .as_u64()
                    .ok_or("Quote fixture Lightning height is missing")?,
            )?,
            fee_bps: derived.fee_bps.parse()?,
            miner_fee_budget_sat: derived.miner_fee_budget.parse()?,
            lightning_routing_fee_budget_sat: derived.lightning_routing_fee_budget.parse()?,
            minimum_confirmations: 1,
            reorg_safety_blocks: 1,
            zero_confirmation: false,
            rbf: ReplacementPolicy::Reject,
            replacement: ReplacementPolicy::Reject,
            quote_validity_seconds: config.quote_expiry_seconds,
            funding_window_blocks: 2,
            broadcast_safety_blocks: 1,
            lightning_settlement_blocks: 1,
            expected_block_seconds: 600,
            clock_skew_seconds: 60,
            recovery_target_blocks: 2,
        },
        now,
    )?;
    let terms = quote
        .profile
        .get("terms")
        .and_then(Value::as_object)
        .ok_or("funded Quote terms are missing")?;
    for (name, expected) in derived.amount_terms() {
        assert_eq!(terms.get(&name), Some(&expected), "pricing term {name}");
    }
    assert_eq!(quote.expiration, derived.quote_expires_at);
    assert_eq!(derived.capacity_bucket_id, "btc-pricing-integration");
    assert_eq!(derived.reservation, ReservationTier::Hard);
    assert_eq!(
        derived.feerate,
        FeerateObservation::Fallback { sat_per_vb: 1 }
    );
    let live_feerate = feerate_for_quote(&config, Some((2, "bitcoind-estimatesmartfee-2")))?;
    assert_eq!(
        live_feerate,
        FeerateObservation::Live {
            sat_per_vb: 2,
            source: "bitcoind-estimatesmartfee-2".to_owned(),
        }
    );
    assert_eq!(
        funding_feerate_from_quote_budget(
            PricingSwapType::Reverse,
            derived.miner_fee_budget.parse()?,
        )?,
        1
    );
    let reduced_capacity = CapacityBounds {
        capacity_bucket_id: capacity.capacity_bucket_id,
        available_capacity: "999".to_owned(),
    };
    assert!(
        derive_quote(
            &config,
            &feerate,
            &reduced_capacity,
            &QuoteRequest {
                swap_type: PricingSwapType::Reverse,
                side: QuoteSide::Input,
                amount: "1000".to_owned(),
            },
            now,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn fixture_negative_cases_fail_closed_with_typed_errors() {
    let fixture = fixture();
    let invoice = fixture["invoice"].as_str().expect("invoice");
    let now = fixture["now"].as_u64().expect("now");
    let tip = chain_tip(fixture);
    let mainnet_wallet = TestWallet::new(BitcoinNetwork::Mainnet);
    let testnet_wallet = TestWallet::new(BitcoinNetwork::Testnet);
    let submarine_case = &fixture["cases"][0];
    let reverse_case = &fixture["cases"][1];

    for (index, negative) in fixture["negative_cases"]
        .as_array()
        .expect("negative cases")
        .iter()
        .enumerate()
    {
        let name = negative["name"].as_str().expect("negative name");
        let setup = Setup::new(u8::try_from(0xb0 + index).expect("session byte"));
        let mut case = if name == "reverse_invoice_expires_before_quote" {
            reverse_case.clone()
        } else {
            submarine_case.clone()
        };
        let mut policy = policy(fixture, &case);
        let mut build_now = now;
        let mut rfq_now = now;
        let mut invoice_digest = None;
        let mut payment_hash = None;
        let mut requester_key = None;
        let mut extension = None;
        let wallet = match name {
            "raw_invoice_digest_mismatch" => {
                invoice_digest = Some("00".repeat(32));
                &mainnet_wallet.wallet
            }
            "rfq_invoice_mismatch" => {
                case["rfq_invoice_mismatch"] = json!(true);
                &mainnet_wallet.wallet
            }
            "invoice_network_mismatch" => &testnet_wallet.wallet,
            "invoice_amount_mismatch" => {
                case["input_amount"] = json!("2100");
                case["maximum_total_fee"] = json!("2000");
                &mainnet_wallet.wallet
            }
            "expired_invoice" => {
                let parsed = parse_bolt11(invoice).expect("fixture invoice");
                build_now = parsed.timestamp + parsed.expiry_seconds + 1;
                &mainnet_wallet.wallet
            }
            "payment_hash_mismatch" => {
                payment_hash = Some("00".repeat(32));
                &mainnet_wallet.wallet
            }
            "invalid_requester_key" => {
                requester_key = Some("ff".repeat(32));
                &mainnet_wallet.wallet
            }
            "unsafe_deadline" => &mainnet_wallet.wallet,
            "invoice_expires_within_acceptance_ladder" => {
                let parsed = parse_bolt11(invoice).expect("fixture invoice");
                let invoice_expiration = parsed.timestamp + parsed.expiry_seconds;
                let remaining = invoice_expiration
                    .checked_sub(now)
                    .expect("fixture invoice remains payable");
                let post_acceptance_blocks =
                    u64::from(policy.funding_window_blocks + policy.minimum_confirmations);
                policy.expected_block_seconds =
                    (remaining - policy.quote_validity_seconds / 2) / post_acceptance_blocks;
                case["desired_completion_offset"] = json!(
                    remaining
                        .checked_add(policy.quote_validity_seconds)
                        .and_then(|offset| offset.checked_add(1))
                        .expect("fixture completion offset")
                );
                &mainnet_wallet.wallet
            }
            "reverse_invoice_expires_before_quote" => {
                let parsed = parse_bolt11(invoice).expect("fixture invoice");
                let invoice_expiration = parsed.timestamp + parsed.expiry_seconds;
                rfq_now = invoice_expiration
                    .checked_sub(30)
                    .expect("fixture invoice timestamp leaves a short acceptance window");
                build_now = rfq_now;
                case["desired_completion_offset"] = json!(10_000);
                &mainnet_wallet.wallet
            }
            "lightning_height_stale" => {
                policy.lightning_current_height = u32::try_from(tip.height)
                    .expect("fixture chain height")
                    .saturating_sub(policy.reorg_safety_blocks + 1);
                &mainnet_wallet.wallet
            }
            "lightning_height_ahead" => {
                policy.lightning_current_height = u32::try_from(tip.height)
                    .expect("fixture chain height")
                    .checked_add(1)
                    .expect("ahead height");
                &mainnet_wallet.wallet
            }
            "unsupported_extension" => {
                extension = Some(("evm_leg", Value::Null));
                &mainnet_wallet.wallet
            }
            "fee_amount_underflow" => {
                case["input_amount"] = json!("100");
                case["maximum_total_fee"] = json!("10000");
                &mainnet_wallet.wallet
            }
            "unsupported_chain" => {
                case["swap_type"] = json!("chain");
                &mainnet_wallet.wallet
            }
            _ => panic!("unhandled negative case {name}"),
        };
        if name == "unsafe_deadline" {
            case["desired_completion_offset"] = json!(1);
        }
        if name == "fee_amount_underflow" {
            policy.miner_fee_budget_sat = 800;
        }
        let rfq = signed_rfq(
            &setup,
            &case,
            invoice,
            rfq_now,
            invoice_digest.as_deref(),
            payment_hash.as_deref(),
            requester_key.as_deref(),
            extension,
        );
        let error = build_funded_quote(
            &rfq,
            invoice,
            wallet,
            wallet_allocation(),
            &tip,
            policy,
            build_now,
        )
        .expect_err(name);
        assert_eq!(error.code, negative["expected_error"], "{name}");
    }
}

#[test]
fn fixture_case_names_and_invoice_commitment_are_closed() {
    let fixture = fixture();
    assert_eq!(
        fixture["schema"],
        "openagents.mkt-swp.provider-quote-builder.v1"
    );
    assert_eq!(
        fixture["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .map(|case| case["name"].as_str().expect("case name"))
            .collect::<Vec<_>>(),
        ["submarine_dynamic_quote", "reverse_dynamic_quote"]
    );
    assert_eq!(
        fixture["negative_cases"]
            .as_array()
            .expect("negative cases")
            .iter()
            .map(|case| case["name"].as_str().expect("negative case name"))
            .collect::<Vec<_>>(),
        [
            "raw_invoice_digest_mismatch",
            "rfq_invoice_mismatch",
            "invoice_network_mismatch",
            "invoice_amount_mismatch",
            "expired_invoice",
            "payment_hash_mismatch",
            "invalid_requester_key",
            "unsafe_deadline",
            "invoice_expires_within_acceptance_ladder",
            "reverse_invoice_expires_before_quote",
            "lightning_height_stale",
            "lightning_height_ahead",
            "unsupported_extension",
            "fee_amount_underflow",
            "unsupported_chain",
        ]
    );
    assert_eq!(
        lower_hex(&sha256(
            fixture["invoice"].as_str().expect("invoice").as_bytes()
        )),
        fixture["invoice_sha256"]
    );
}

fn assert_positive_fixture(case: &Value, built: &BuiltFundedQuote) {
    let verifier = &built.profile["terms"]["verifier_inputs"][0];
    let profile_digest = lower_hex(&sha256(
        &immortal_client::mkt_swp_client::provider_support::canonical_json(&built.profile)
            .expect("canonical Quote profile"),
    ));
    let bitcoin_leg = built.profile["terms"]["legs"]
        .as_array()
        .expect("Quote legs")
        .iter()
        .find(|leg| leg["rail"] == "bitcoin")
        .expect("Bitcoin leg");
    let observed = json!({
        "expected_profile_sha256":profile_digest,
        "expected_script_pubkey":verifier["script_pubkey"],
        "expected_output_key":verifier["taproot_output_key"],
        "expected_claim_public_key":bitcoin_leg["claim_public_key"],
        "expected_refund_public_key":bitcoin_leg["refund_public_key"],
        "expected_refund_height":bitcoin_leg["refund_lock_value"],
    });
    for member in [
        "expected_profile_sha256",
        "expected_script_pubkey",
        "expected_output_key",
        "expected_claim_public_key",
        "expected_refund_public_key",
        "expected_refund_height",
    ] {
        assert_eq!(
            case[member], observed[member],
            "{} {member}: observed {observed}",
            case["name"]
        );
    }
    assert_eq!(
        built.output_amount_sat.to_string(),
        case["expected_output_amount"]
    );
}

#[allow(clippy::too_many_arguments)]
fn signed_rfq(
    setup: &Setup,
    case: &Value,
    invoice: &str,
    now: u64,
    invoice_digest: Option<&str>,
    payment_hash: Option<&str>,
    requester_key: Option<&str>,
    extension: Option<(&str, Value)>,
) -> Event {
    let fixture = fixture();
    let swap_type = case["swap_type"].as_str().expect("swap type");
    let network_id = fixture["network_id"].as_str().expect("network ID");
    let (asset_pair, leg_id, path) = match swap_type {
        "submarine" => (
            json!([
                format!("swp:1:{network_id}:btc:chain"),
                format!("swp:1:{network_id}:btc:lightning")
            ]),
            "source",
            "refund",
        ),
        "reverse" => (
            json!([
                format!("swp:1:{network_id}:btc:lightning"),
                format!("swp:1:{network_id}:btc:chain")
            ]),
            "destination",
            "claim",
        ),
        "chain" => (
            json!([
                format!("swp:1:{network_id}:btc:chain"),
                format!("swp:1:{network_id}:btc:chain")
            ]),
            "source",
            "refund",
        ),
        _ => panic!("unsupported test swap type"),
    };
    let desired_offset = case["desired_completion_offset"].as_u64().unwrap_or(10_000);
    let mut constraints = json!({
        "allowed_script_modes":["taproot-musig2-script-exit"],
        "asset_pair":asset_pair,
        "confirmation_policy":{
            "minimum_confirmations":"1",
            "reorg_safety_blocks":"1",
            "zero_confirmation":"forbidden",
            "rbf":"reject",
            "replacement":"reject"
        },
        "desired_completion_time":now + desired_offset,
        "firm_quote_required":true,
        "input_amount":case["input_amount"],
        "invoice_sha256":invoice_digest.unwrap_or(
            fixture["invoice_sha256"].as_str().expect("invoice digest")
        ),
        "maximum_total_fee":case["maximum_total_fee"],
        "payment_hash":payment_hash.unwrap_or(
            fixture["payment_hash"].as_str().expect("payment hash")
        ),
        "requester_public_keys":[{
            "leg_id":leg_id,
            "path":path,
            "public_key":requester_key.unwrap_or(setup.requester.pubkey())
        }],
        "swap_type":swap_type
    });
    if swap_type == "reverse" {
        constraints
            .as_object_mut()
            .expect("constraints object")
            .remove("invoice_sha256");
    }
    if let Some((name, value)) = extension {
        constraints
            .as_object_mut()
            .expect("constraints object")
            .insert(name.to_owned(), value);
    }
    let mut rfq_profile = json!({"constraints":constraints});
    if swap_type == "submarine" {
        rfq_profile.as_object_mut().expect("RFQ profile").insert(
            "invoice".to_owned(),
            Value::String(if case["rfq_invoice_mismatch"] == true {
                format!("{invoice}x")
            } else {
                invoice.to_owned()
            }),
        );
    }
    let request = setup
        .factory
        .rfq(
            now - 1,
            &lower_hex(&sha256(
                format!("{}:{swap_type}", setup.config.session_id).as_bytes(),
            )),
            now + 300,
            rfq_profile,
        )
        .expect("RFQ request");
    assert_eq!(
        lower_hex(&sha256(invoice.as_bytes())),
        fixture["invoice_sha256"]
    );
    sign_private(request, &setup.requester)
}

fn sign_private(request: MktSigningRequest, signer: &MarketSigner) -> Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).expect("signed private record")
}

fn policy<'a>(fixture: &'a Value, case: &Value) -> FundedQuotePolicy<'a> {
    FundedQuotePolicy {
        network_id: fixture["network_id"].as_str().expect("network ID"),
        cooperative_signing: false,
        lightning_current_height: u32::try_from(
            fixture["lightning_height"]
                .as_u64()
                .expect("lightning height"),
        )
        .expect("v1 lightning height"),
        fee_bps: u16::try_from(case["fee_bps"].as_u64().expect("fee bps")).expect("u16 fee"),
        miner_fee_budget_sat: case["miner_fee_budget_sat"].as_u64().expect("miner fee"),
        lightning_routing_fee_budget_sat: case["lightning_routing_fee_budget_sat"]
            .as_u64()
            .expect("routing fee"),
        minimum_confirmations: 1,
        reorg_safety_blocks: 1,
        zero_confirmation: false,
        rbf: ReplacementPolicy::Reject,
        replacement: ReplacementPolicy::Reject,
        quote_validity_seconds: 60,
        funding_window_blocks: 2,
        broadcast_safety_blocks: 1,
        lightning_settlement_blocks: 1,
        expected_block_seconds: 600,
        clock_skew_seconds: 60,
        recovery_target_blocks: 2,
    }
}

fn wallet_allocation() -> QuoteWalletAllocation {
    QuoteWalletAllocation {
        unilateral_path: WalletPath::new(0, false, 10).expect("unilateral path"),
        cooperative_path: WalletPath::new(0, false, 11).expect("cooperative path"),
    }
}

fn chain_tip(fixture: &Value) -> ChainTip {
    ChainTip {
        hash: fixture["chain_tip"]["hash"]
            .as_str()
            .expect("tip hash")
            .to_owned(),
        height: fixture["chain_tip"]["height"].as_u64().expect("tip height"),
    }
}

fn fixture() -> &'static Value {
    static FIXTURE_VALUE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    FIXTURE_VALUE.get_or_init(|| serde_json::from_str(FIXTURE).expect("Quote fixture JSON"))
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
