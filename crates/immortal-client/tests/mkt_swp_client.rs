#![cfg(feature = "mkt-swp-verify")]

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};

use immortal_client::{
    browser_api,
    liquid::{
        LiquidBeforeFundRequest, LiquidConfidentiality, LiquidExitMode,
        LiquidFundingVerificationInput, LiquidLegPurpose, LiquidNodeAuthority, LiquidNodeRequest,
        LiquidSwapType, LiquidUnblindRequest, LiquidUnilateralExitPackage,
        LocalLiquidNodeObservation, LocalLiquidObservation, LocalLiquidUnblind,
    },
    market::MarketSigner,
    market::{WrapMaterial, unwrap_mkt_record, unwrap_mkt_record_raw, wrap_mkt_record},
    mkt_swp_client::{
        AwaitingVerification, BitcoinObservationRequest, Cancellation, ChainRecoveryState,
        CloseOutcome, CooperativePrevout, CooperativeSigningContext, CooperativeSigningMessage,
        CooperativeTweak, ExitPackage, ExitSigningOutcome, ExternalEffectRequest, FundingAction,
        FundingAuthorized, FundingVerificationInput, InvoiceVerificationInput,
        KeylessEsploraExecutor, LightningDispositionState, LightningProgressRequest,
        LightningProgressState, LightningReadinessRequest, LightningReadinessState,
        LightningRecoveryState, LiquidVerifyBeforeFundInput, LocalBitcoinObservation,
        LocalLightningDisposition, LocalLightningProgress, LocalLightningReadiness,
        LocalRailEvidence, LocalRecoveryObservation, MktSigningRequest, ParticipantRole,
        ProviderRoutePin, QuotePolicy, RecoveryAction, RequesterContractLocalInputs,
        RequesterContractSigningInput, RequesterFundingResolution, RequesterOrderInput,
        RequesterPriceFeedView, RequesterSessionView, RequesterTerminalState,
        RequesterVerificationState, SignedRecordDelivery, StatusState, SwapClientConfig,
        SwapContractReferences, SwapRecordFactory, SwapSession, SwapType, TimeoutLadder,
        VerifyBeforeFundInput, provider_support, validate_cooperative_signing_exchange,
    },
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, musig2_aggregate_key, musig2_nonce_gen,
        musig2_partial_sign, musig2_taproot_tweak, musig2_tweaked_aggregate_key, sha256,
        tagged_hash, tapleaf_hash, taproot_key_spend_sighash, taproot_output_key,
    },
};

#[test]
fn provider_route_is_pinned_with_the_session_configuration() {
    let mut config = Setup::new(&fixture()).config;
    let pinned = ProviderRoutePin {
        http_origin: "https://provider.example.com".to_owned(),
        websocket_origin: "wss://provider.example.com".to_owned(),
        selection_policy_sha256: "91".repeat(32),
    };
    config.provider_route = Some(pinned.clone());
    config.validate().unwrap();
    config.require_provider_route(&pinned).unwrap();

    let encoded = serde_json::to_vec(&config).unwrap();
    let restored: SwapClientConfig = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored.provider_route.as_ref(), Some(&pinned));

    let mut changed = pinned.clone();
    changed.websocket_origin = "wss://standby.example.com".to_owned();
    assert_eq!(
        restored.require_provider_route(&changed).unwrap_err().code,
        "swp_provider_route_changed"
    );

    let mut insecure = pinned;
    insecure.http_origin = "http://provider.example.com".to_owned();
    config.provider_route = Some(insecure);
    assert_eq!(
        config.validate().unwrap_err().code,
        "swp_provider_route_invalid"
    );

    for invalid_origin in [
        "https://provider.example.com:abc",
        "https://provider.example.com:0",
        "https://[::1",
        "https://provider.example.com:443:444",
    ] {
        config.provider_route = Some(ProviderRoutePin {
            http_origin: invalid_origin.to_owned(),
            websocket_origin: "wss://provider.example.com".to_owned(),
            selection_policy_sha256: "91".repeat(32),
        });
        assert_eq!(
            config.validate().unwrap_err().code,
            "swp_provider_route_invalid"
        );
    }
}
use immortal_core::liquid::{
    LiquidGenesisHash, LiquidPrevout, LiquidTransaction, liquid_taproot_script_spend_sighash,
    parse_liquid_transaction, sign_liquid_taproot_sighash,
};
use secp256k1::{Keypair, Parity, PublicKey, Secp256k1, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn fixture_manifest_is_complete_and_unique() {
    let fixture = fixture();
    #[cfg(feature = "mkt-swp-fixture-probe")]
    {
        let replay =
            immortal_client::mkt_swp_client::fixture_replay::replay_embedded_manifest().unwrap();
        assert_eq!(replay.cases, 65);
        assert_eq!(replay.custody_tripwires, 23);
        immortal_client::mkt_swp_client::fixture_replay::replay_requester_api_fixture().unwrap();
    }
    assert_eq!(
        fixture["schema"],
        "openagents.mkt-swp.client-engine-fixtures.v1"
    );
    assert_eq!(
        fixture["source"]["commit"],
        "a7f5522c0a7430f9f5b1cfa09477dae2d16d3682"
    );
    let mut names = BTreeSet::new();
    for section in [
        "record_construction",
        "flows",
        "flow_topologies",
        "verify_before_fund",
        "sequencing",
        "external_effects",
        "recovery",
        "lifecycle",
    ] {
        for case in fixture[section].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert!(names.insert(name), "duplicate client case {name}");
        }
    }
    assert_eq!(names.len(), 65);
    assert!(names.contains("swp-v1-negative-payment-hash-mismatch"));
    assert!(names.contains("swp-v1-negative-signed-status-base-state-mismatch"));
    assert!(names.contains("swp-v1-rail-evidence-orphan-crash-restore"));
    assert!(names.contains("swp-v1-reverse-refund-bitcoin-spend-evidence"));
    assert!(names.contains("swp-v1-lightning-disposition-orphan-crash-restore"));
    assert!(names.contains("swp-v1-negative-loss-vanished-principal"));
    assert!(names.contains("swp-v1-negative-loss-unknown-input-disputed"));
    assert!(names.contains("swp-v1-reverse-refunded-paid-loss"));
    assert!(names.contains("swp-v1-negative-contract-digest-fork"));
    assert!(names.contains("swp-v1-negative-exit-funding-txid"));
    assert!(names.contains("swp-v1-negative-effective-cancel-before-fund"));

    let tripwires = fixture["custody_tripwires"].as_array().unwrap();
    assert_eq!(tripwires.len(), 23);
    let members = tripwires
        .iter()
        .map(|case| case["member"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(members.len(), tripwires.len());
}

#[cfg(feature = "mkt-swp-fixture-probe")]
#[test]
fn requester_api_v2_schema_fails_closed() {
    let bytes = include_bytes!("../../../tests/fixtures/nipmkt/swp-requester-api-v2.json");
    let mut unsupported: Value = serde_json::from_slice(bytes).unwrap();
    unsupported["$defs"]["hex32"]["patternProperties"] = json!({});
    assert!(
        immortal_client::mkt_swp_client::fixture_replay::replay_requester_api_fixture_bytes(
            &serde_json::to_vec(&unsupported).unwrap(),
        )
        .is_err()
    );

    let mut ambiguous: Value = serde_json::from_slice(bytes).unwrap();
    ambiguous["$defs"]["nullable_decimal"]["oneOf"][0] = json!({"type":"null"});
    assert!(
        immortal_client::mkt_swp_client::fixture_replay::replay_requester_api_fixture_bytes(
            &serde_json::to_vec(&ambiguous).unwrap(),
        )
        .is_err()
    );
}

#[cfg(feature = "mkt-swp-fixture-probe")]
#[test]
fn requester_api_v2_source_keeps_source_bound_terminal_references() {
    let source =
        immortal_client::mkt_swp_client::fixture_replay::generate_requester_api_v2_source()
            .expect("requester API source generation");
    let snapshot = source
        .pointer("/terminal/snapshot_json_hex")
        .and_then(Value::as_str)
        .expect("terminal snapshot hex");
    let snapshot: Value = serde_json::from_slice(&decode_hex(snapshot)).expect("terminal snapshot");
    let requests = snapshot["external_effect_requests"]
        .as_array()
        .expect("external effect requests");
    let source_bound = requests
        .iter()
        .filter(|request| {
            matches!(
                request["evidence_class"].as_str(),
                Some(
                    "bitcoin_output"
                        | "bitcoin_spend"
                        | "liquid_output"
                        | "liquid_spend"
                        | "reservation"
                )
            )
        })
        .collect::<Vec<_>>();
    assert!(!source_bound.is_empty());
    for request in source_bound {
        assert_eq!(
            request["reference"], request["source_reference"],
            "{}",
            request["evidence_class"]
        );
    }
}

#[test]
fn published_requester_api_v1_bytes_are_frozen() {
    let bytes = include_bytes!("../../../tests/fixtures/nipmkt/swp-requester-api-v1.json");
    assert_eq!(
        lower_hex(&Sha256::digest(bytes)),
        "7ccd8c25db2ac505d805e22da2ee5d8535092e7eb2141b845749d99fe3173b17"
    );
}

#[test]
fn requester_api_fixture_projects_terms_and_refuses_unsafe_signing() {
    let fixture = fixture();
    let api_fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-requester-api-v1.json"
    ))
    .unwrap();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let records = session.signed_records();
    let quote_only = RequesterSessionView::from_signed_records(
        &setup.config,
        &records[..2],
        delivery_receipts(&records[..2], 100),
    )
    .unwrap();
    assert_eq!(
        quote_only.verification.state,
        RequesterVerificationState::QuoteVerified
    );
    let view = RequesterSessionView::from_signed_records(
        &setup.config,
        records,
        delivery_receipts(records, 100),
    )
    .unwrap();
    let expected = &api_fixture["submarine_quote"];
    assert_eq!(view.schema, api_fixture["view_schema"]);
    assert_eq!(view.quote.swap_type, SwapType::Submarine);
    assert_eq!(view.quote.input_amount, expected["input_amount"]);
    assert_eq!(view.quote.output_amount, expected["output_amount"]);
    assert_eq!(view.quote.fees.fee_bps, expected["fee_bps"]);
    assert_eq!(view.quote.fees.provider_fee, expected["provider_fee"]);
    assert_eq!(
        view.quote.fees.miner_fee_budget,
        expected["miner_fee_budget"]
    );
    assert_eq!(
        view.quote.fees.lightning_routing_fee_budget,
        expected["lightning_routing_fee_budget"]
    );
    assert_eq!(
        view.quote.fees.maximum_total_fee,
        expected["maximum_total_fee"]
    );
    assert_eq!(view.quote.fees.fee_payer, expected["fee_payer"]);
    assert_eq!(view.quote.amount_equation, expected["amount_equation"]);
    assert_eq!(view.quote.rounding, expected["rounding"]);
    assert_eq!(
        view.quote.clock_skew_seconds,
        expected["clock_skew_seconds"]
    );
    assert_eq!(
        view.quote.effective_acceptance_deadline,
        expected["effective_acceptance_deadline"].as_u64().unwrap()
    );
    assert!(view.quote.price_feed.is_none());
    let feed = RequesterPriceFeedView::from_pinned_terms(&api_fixture["price_feed_projection"])
        .unwrap()
        .unwrap();
    assert_eq!(feed.url, api_fixture["price_feed_projection"]["url"]);
    assert_eq!(
        feed.value_pointer,
        api_fixture["price_feed_projection"]["value_pointer"]
    );
    assert_eq!(
        feed.observed_value,
        api_fixture["price_feed_projection"]["observed_value"]
    );
    assert_eq!(
        feed.response_sha256,
        api_fixture["price_feed_projection"]["response_sha256"]
    );
    assert_eq!(
        feed.observed_at,
        api_fixture["price_feed_projection"]["observed_at"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        feed.max_age_seconds,
        api_fixture["price_feed_projection"]["max_age_seconds"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        view.verification.state,
        RequesterVerificationState::ContractTermsVerified
    );
    assert!(view.verification.local_verification_required);
    assert!(!view.verification.funding_authorized);

    let rfq = records.iter().find(|event| event.kind == 39_604).unwrap();
    let quote = records.iter().find(|event| event.kind == 39_605).unwrap();
    let order = records.iter().find(|event| event.kind == 39_606).unwrap();
    let requester_contract = records
        .iter()
        .find(|event| event.kind == 39_610 && event.pubkey == setup.config.requester_pubkey)
        .unwrap();
    let mut late_order_delivery = delivery_receipts(records, 100);
    let order_delivery = late_order_delivery
        .iter_mut()
        .find(|delivery| delivery.event_id() == order.id)
        .unwrap();
    *order_delivery =
        SignedRecordDelivery::from_direct(serde_json::to_vec(order).unwrap(), 901).unwrap();
    assert_eq!(
        RequesterSessionView::from_signed_records(&setup.config, records, late_order_delivery)
            .unwrap_err()
            .code,
        "swp_quote_expired"
    );
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    factory
        .requester_order(RequesterOrderInput {
            rfq,
            quote,
            created_at: order.created_at,
            observed_at: order.created_at,
            distinct: &"13".repeat(32),
            selection: None,
        })
        .unwrap()
        .verify_signed(order.clone())
        .unwrap();
    let local_contract =
        serde_json::from_str::<Value>(&requester_contract.content).unwrap()["mkt_swp"]["contract"]
            .clone();
    let local_inputs: RequesterContractLocalInputs = serde_json::from_value(json!({
        "effect_bindings": local_contract["effect_bindings"],
        "exit_package_commitments": local_contract["exit_package_commitments"]
    }))
    .unwrap();
    let contract = factory
        .requester_contract_draft(rfq, quote, order, order.created_at, local_inputs)
        .unwrap();
    factory
        .requester_contract(RequesterContractSigningInput {
            rfq,
            quote,
            order,
            order_observed_at: order.created_at,
            created_at: requester_contract.created_at,
            distinct: &"14".repeat(32),
            contract,
        })
        .unwrap()
        .verify_signed(requester_contract.clone())
        .unwrap();
    assert_eq!(
        factory
            .requester_order(RequesterOrderInput {
                rfq,
                quote,
                created_at: 901,
                observed_at: 901,
                distinct: &"91".repeat(32),
                selection: None,
            })
            .unwrap_err()
            .code,
        "swp_quote_expired"
    );
    factory
        .requester_contract(RequesterContractSigningInput {
            rfq,
            quote,
            order,
            order_observed_at: order.created_at,
            created_at: 901,
            distinct: &"94".repeat(32),
            contract: serde_json::from_str::<Value>(&requester_contract.content).unwrap()
                ["mkt_swp"]["contract"]
                .clone(),
        })
        .unwrap();

    let mut timeline_records = records.to_vec();
    let first_status = signed(
        factory
            .status(
                ParticipantRole::Provider,
                1_000,
                &"92".repeat(32),
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let second_status = signed(
        factory
            .status(
                ParticipantRole::Provider,
                999,
                &"93".repeat(32),
                &order.id,
                StatusState {
                    sequence: 1,
                    previous: Some(&first_status.id),
                    base_state: "awaiting_input",
                    swp_state: "lock_terms_ready",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    timeline_records.extend([second_status, first_status]);
    let timeline = RequesterSessionView::from_signed_records(
        &setup.config,
        &timeline_records,
        delivery_receipts(&timeline_records, 100),
    )
    .unwrap();
    let status_sequences = timeline
        .timeline
        .iter()
        .filter_map(|entry| entry.sequence)
        .collect::<Vec<_>>();
    assert_eq!(status_sequences, [0, 1]);
}

#[test]
fn requester_delivery_archive_rejects_mutation_and_duplicate_members() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let event = session.signed_records().first().unwrap();
    let raw = serde_json::to_vec_pretty(event).unwrap();
    let evidence = SignedRecordDelivery::from_direct(raw.clone(), 100).unwrap();
    evidence.validate(event).unwrap();
    assert_eq!(evidence.raw_signed_event(), raw);

    let mut mutated = raw.clone();
    let event_id = event.id.as_bytes();
    let offset = mutated
        .windows(event_id.len())
        .position(|window| window == event_id)
        .unwrap();
    mutated[offset] ^= 1;
    assert!(SignedRecordDelivery::from_direct(mutated, 100).is_err());

    let raw_text = String::from_utf8(raw).unwrap();
    let duplicate = raw_text.replacen('{', &format!("{{\"id\":\"{}\",", event.id), 1);
    assert!(SignedRecordDelivery::from_direct(duplicate.into_bytes(), 100).is_err());
    let mut receipts = delivery_receipts(session.signed_records(), 100);
    receipts[0] = evidence;
    assert!(
        RequesterSessionView::from_signed_records(
            &setup.config,
            session.signed_records(),
            receipts,
        )
        .is_ok()
    );
}

#[test]
fn requester_price_feed_is_inspectable_but_execution_fails_closed() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let feed_value = json!({
        "url":"https://prices.example.test/btc-usd",
        "value_pointer":"/data/price",
        "observed_value":"6543210",
        "response_sha256":"52".repeat(32),
        "observed_at":100_u64,
        "max_age_seconds":30_u64
    });
    let feed = RequesterPriceFeedView::from_pinned_terms(&feed_value)
        .unwrap()
        .unwrap();
    assert_eq!(feed.observed_value, "6543210");
    assert_eq!(feed.response_sha256, "52".repeat(32));

    for invalid in [
        json!({"url":"https://user@example.test/feed"}),
        json!({"url":"https://example.test/feed#value"}),
        json!({"observed_value":"06543210"}),
        json!({"value_pointer":"/data/~2price"}),
    ] {
        let mut candidate = feed_value.clone();
        for (name, value) in invalid.as_object().unwrap() {
            candidate[name] = value.clone();
        }
        assert_eq!(
            RequesterPriceFeedView::from_pinned_terms(&candidate)
                .unwrap_err()
                .code,
            "swp_price_feed_invalid"
        );
    }

    let rfq_event = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_604)
        .unwrap();
    let quote_event = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_605)
        .unwrap();
    let mut profile =
        serde_json::from_str::<Value>(&quote_event.content).unwrap()["mkt_swp"].clone();
    profile["terms"]["price_feed"] = feed_value;
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let feed_quote = signed(
        factory
            .soft_quote(
                quote_event.created_at,
                &"79".repeat(32),
                &rfq_event.id,
                1_000,
                profile,
            )
            .unwrap(),
        &setup.provider,
    );
    assert_eq!(
        factory
            .requester_order(RequesterOrderInput {
                rfq: rfq_event,
                quote: &feed_quote,
                created_at: 102,
                observed_at: 102,
                distinct: &"7b".repeat(32),
                selection: None,
            })
            .unwrap_err()
            .code,
        "swp_price_feed_unsupported"
    );

    let feed_order = signed(
        factory
            .order(
                102,
                &"7c".repeat(32),
                &feed_quote.id,
                json!({"accepted_quote_id":feed_quote.id}),
            )
            .unwrap(),
        &setup.requester,
    );
    let requester_contract = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_610 && event.pubkey == setup.requester.pubkey())
        .unwrap();
    let contract =
        serde_json::from_str::<Value>(&requester_contract.content).unwrap()["mkt_swp"]["contract"]
            .clone();
    let local_inputs: RequesterContractLocalInputs = serde_json::from_value(json!({
        "effect_bindings": contract["effect_bindings"],
        "exit_package_commitments": contract["exit_package_commitments"]
    }))
    .unwrap();
    assert_eq!(
        factory
            .requester_contract_draft(rfq_event, &feed_quote, &feed_order, 102, local_inputs,)
            .unwrap_err()
            .code,
        "swp_price_feed_unsupported"
    );
    assert_eq!(
        factory
            .requester_contract(RequesterContractSigningInput {
                rfq: rfq_event,
                quote: &feed_quote,
                order: &feed_order,
                order_observed_at: 102,
                created_at: 103,
                distinct: &"7d".repeat(32),
                contract,
            })
            .unwrap_err()
            .code,
        "swp_price_feed_unsupported"
    );
    let feed_records = vec![rfq_event.clone(), feed_quote, feed_order];
    assert_eq!(
        RequesterSessionView::from_signed_records(
            &setup.config,
            &feed_records,
            delivery_receipts(&feed_records, 102),
        )
        .unwrap_err()
        .code,
        "swp_price_feed_unsupported"
    );
    assert_eq!(
        SwapSession::<AwaitingVerification>::from_signed_records(
            setup.config,
            feed_records,
            Vec::new(),
        )
        .unwrap_err()
        .code,
        "swp_price_feed_unsupported"
    );
}

#[test]
fn requester_delivery_binds_verified_outer_wrap_and_is_mandatory() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let event = session.signed_records().first().unwrap();
    let wrapped = wrap_mkt_record(
        &serde_json::to_vec(event).unwrap(),
        &setup.requester,
        setup.provider.pubkey(),
        WrapMaterial {
            seal_created_at: 8,
            wrap_created_at: 9,
            seal_nonce: [3; 32],
            wrap_nonce: [4; 32],
            wrap_secret: [5; 32],
        },
    )
    .unwrap();
    let profiles = [immortal_client::domain::MktProfileSupport {
        profile_id: "mkt-swp",
        version: 1,
        critical_members: &["mkt_swp"],
        understood_members: &["mkt_swp"],
    }];
    let raw_wrap = serde_json::to_vec_pretty(&wrapped.event).unwrap();
    let no_raw_delivery = unwrap_mkt_record(&wrapped.event, &setup.provider, &profiles).unwrap();
    assert!(SignedRecordDelivery::from_delivered(&no_raw_delivery, 10).is_err());
    let delivered = unwrap_mkt_record_raw(&raw_wrap, &setup.provider, &profiles).unwrap();
    let receipt = SignedRecordDelivery::from_delivered(&delivered, 10).unwrap();
    assert_eq!(receipt.raw_wrap_event(), Some(raw_wrap.as_slice()));

    let mut forged_id = wrapped.event.clone();
    forged_id.id = "ff".repeat(32);
    assert!(
        unwrap_mkt_record_raw(
            &serde_json::to_vec(&forged_id).unwrap(),
            &setup.provider,
            &profiles,
        )
        .is_err()
    );
    let mut outer_mutation = wrapped.event.clone();
    outer_mutation.content.push('x');
    assert!(
        unwrap_mkt_record_raw(
            &serde_json::to_vec(&outer_mutation).unwrap(),
            &setup.provider,
            &profiles,
        )
        .is_err()
    );
    let duplicate_outer = String::from_utf8(raw_wrap.clone()).unwrap().replacen(
        '{',
        &format!("{{\"id\":\"{}\",", wrapped.event.id),
        1,
    );
    assert!(
        unwrap_mkt_record_raw(duplicate_outer.as_bytes(), &setup.provider, &profiles,).is_err()
    );

    let mut missing = delivery_receipts(session.signed_records(), 100);
    missing.pop();
    assert_eq!(
        RequesterSessionView::from_signed_records(
            &setup.config,
            session.signed_records(),
            missing,
        )
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );
}

#[test]
fn requester_status_sequence_is_bounded_before_gap_expansion() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let order = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap();
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    factory
        .status(
            ParticipantRole::Provider,
            200,
            &"71".repeat(32),
            &order.id,
            StatusState {
                sequence: 511,
                previous: Some(&"72".repeat(32)),
                base_state: "accepted",
                swp_state: "accepted",
            },
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        factory
            .status(
                ParticipantRole::Provider,
                200,
                &"73".repeat(32),
                &order.id,
                StatusState {
                    sequence: 512,
                    previous: Some(&"74".repeat(32)),
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Default::default(),
            )
            .unwrap_err()
            .code,
        "swp_status_gap"
    );
}

#[test]
fn requester_view_refuses_duplicate_orders_and_participant_contracts() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let quote = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_605)
        .unwrap();
    let order = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap();
    let order_profile = serde_json::from_str::<Value>(&order.content).unwrap()["mkt_swp"].clone();
    let duplicate_order = signed(
        factory
            .order(
                order.created_at + 1,
                &"75".repeat(32),
                &quote.id,
                order_profile,
            )
            .unwrap(),
        &setup.requester,
    );
    let mut duplicate_order_records = session.signed_records().to_vec();
    duplicate_order_records.push(duplicate_order);
    assert_eq!(
        RequesterSessionView::from_signed_records(
            &setup.config,
            &duplicate_order_records,
            delivery_receipts(&duplicate_order_records, 100),
        )
        .unwrap_err()
        .code,
        "swp_idempotency_conflict"
    );

    let requester_contract = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_610 && event.pubkey == setup.config.requester_pubkey)
        .unwrap();
    let contract =
        serde_json::from_str::<Value>(&requester_contract.content).unwrap()["mkt_swp"]["contract"]
            .clone();
    let duplicate_contract = signed(
        factory
            .swap_contract(
                ParticipantRole::Requester,
                requester_contract.created_at + 1,
                &"76".repeat(32),
                SwapContractReferences {
                    order_id: &order.id,
                    quote_id: &quote.id,
                    accepted_status_id: None,
                },
                contract,
            )
            .unwrap(),
        &setup.requester,
    );
    let mut duplicate_contract_records = session.signed_records().to_vec();
    duplicate_contract_records.push(duplicate_contract);
    assert_eq!(
        RequesterSessionView::from_signed_records(
            &setup.config,
            &duplicate_contract_records,
            delivery_receipts(&duplicate_contract_records, 100),
        )
        .unwrap_err()
        .code,
        "swp_idempotency_conflict"
    );
}

#[test]
fn requester_order_fails_closed_for_indicative_quotes() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Submarine, true);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    let rfq = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_604)
        .unwrap();
    let quote = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_605)
        .unwrap();
    let profile = serde_json::from_str::<Value>(&quote.content).unwrap()["mkt_swp"].clone();
    let indicative = signed(
        factory
            .indicative_quote(quote.created_at, &"77".repeat(32), &rfq.id, 1_000, profile)
            .unwrap(),
        &setup.provider,
    );
    assert_eq!(
        factory
            .requester_order(RequesterOrderInput {
                rfq,
                quote: &indicative,
                created_at: 102,
                observed_at: 102,
                distinct: &"78".repeat(32),
                selection: None,
            })
            .unwrap_err()
            .code,
        "swp_order_selection_invalid"
    );
}

#[test]
fn requester_contract_composer_applies_each_allowed_order_selection() {
    let fixture = fixture();
    let selectable = json!({
        "input_amount":{"minimum":"100000","maximum":"200000"},
        "fee_payer":["requester","provider"],
        "confirmation_policy":["one_confirmation"],
        "public_receipt_consent":[false,true]
    });
    for (name, selected) in [
        ("input_amount", json!("100000")),
        ("fee_payer", json!("provider")),
        ("confirmation_policy", json!("one_confirmation")),
        ("public_receipt_consent", json!(true)),
    ] {
        let selection = json!({name:selected});
        let session = build_session_with_options(
            &fixture,
            SwapType::Submarine,
            BuildOptions {
                quote_selectable: Some(&selectable),
                order_selection: Some(&selection),
                contract_selection: Some(&selection),
                ..BuildOptions::default()
            },
        );
        let setup = Setup::new(&fixture);
        let factory = SwapRecordFactory::new(setup.config).unwrap();
        let rfq = session
            .signed_records()
            .iter()
            .find(|event| event.kind == 39_604)
            .unwrap();
        let quote = session
            .signed_records()
            .iter()
            .find(|event| event.kind == 39_605)
            .unwrap();
        let order = session
            .signed_records()
            .iter()
            .find(|event| event.kind == 39_606)
            .unwrap();
        let signed_contract = session
            .signed_records()
            .iter()
            .find(|event| event.kind == 39_610 && event.pubkey == setup.requester.pubkey())
            .unwrap();
        let contract = serde_json::from_str::<Value>(&signed_contract.content).unwrap()["mkt_swp"]
            ["contract"]
            .clone();
        let local_inputs: RequesterContractLocalInputs = serde_json::from_value(json!({
            "effect_bindings":contract["effect_bindings"],
            "exit_package_commitments":contract["exit_package_commitments"]
        }))
        .unwrap();
        let draft = factory
            .requester_contract_draft(rfq, quote, order, 102, local_inputs)
            .unwrap();
        assert_eq!(draft["order_selection"][name], selection[name], "{name}");
        assert_eq!(draft[name], selection[name], "{name}");
    }
}

#[test]
fn requester_close_projection_distinguishes_terminal_loss_and_conflicts() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let completed = terminal_close_session(&fixture, "completed");
    let completed_view = RequesterSessionView::from_signed_records(
        &setup.config,
        completed.signed_records(),
        delivery_receipts(completed.signed_records(), 100),
    )
    .unwrap();
    assert_eq!(
        completed_view.terminal.claimed_state,
        RequesterTerminalState::Completed
    );
    assert!(!completed_view.terminal.watch_terminal);
    assert!(!completed_view.terminal.local_effects_verified);
    assert_eq!(
        completed_view.verification.state,
        RequesterVerificationState::ContractTermsVerified
    );
    let completed_snapshot = completed.persist().unwrap();
    let completed_verified = RequesterSessionView::from_restored_snapshot(
        &completed_snapshot,
        delivery_receipts(completed.signed_records(), 100),
    )
    .unwrap();
    assert_eq!(
        completed_verified.terminal.claimed_state,
        RequesterTerminalState::Completed
    );
    assert!(completed_verified.terminal.watch_terminal);
    assert!(completed_verified.terminal.local_effects_verified);
    assert_eq!(
        completed_verified.verification.state,
        RequesterVerificationState::TerminalVerified
    );
    let mut forged_request: Value = serde_json::from_slice(&completed_snapshot).unwrap();
    forged_request["external_effects"][0]["request_sha256"] = json!("ff".repeat(32));
    assert_eq!(
        RequesterSessionView::from_restored_snapshot(
            &serde_json::to_vec(&forged_request).unwrap(),
            delivery_receipts(completed.signed_records(), 100),
        )
        .unwrap_err()
        .code,
        "swp_external_effect_conflict"
    );
    let mut forged_result: Value = serde_json::from_slice(&completed_snapshot).unwrap();
    let rail_effect_id = forged_result["external_effect_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["request_type"] == "rail_evidence")
        .and_then(|request| request.get("effect_id"))
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let rail_effect = forged_result["external_effects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|effect| effect["effect_id"] == rail_effect_id)
        .unwrap();
    rail_effect["result_sha256"] = json!("ff".repeat(32));
    assert_eq!(
        RequesterSessionView::from_restored_snapshot(
            &serde_json::to_vec(&forged_result).unwrap(),
            delivery_receipts(completed.signed_records(), 100),
        )
        .unwrap_err()
        .code,
        "swp_external_effect_conflict"
    );
    let mut orphaned_snapshot: Value = serde_json::from_slice(&completed_snapshot).unwrap();
    orphaned_snapshot["external_effect_requests"] = json!([]);
    assert_eq!(
        RequesterSessionView::from_restored_snapshot(
            &serde_json::to_vec(&orphaned_snapshot).unwrap(),
            delivery_receipts(completed.signed_records(), 100),
        )
        .unwrap_err()
        .code,
        "swp_external_effect_conflict"
    );

    let mut permuted_snapshot: Value = serde_json::from_slice(&completed_snapshot).unwrap();
    permuted_snapshot["signed_records"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let permuted_records: Vec<immortal_client::domain::Event> =
        serde_json::from_value(permuted_snapshot["signed_records"].clone()).unwrap();
    let permuted_view = RequesterSessionView::from_restored_snapshot(
        &serde_json::to_vec(&permuted_snapshot).unwrap(),
        delivery_receipts(&permuted_records, 100),
    )
    .unwrap();
    assert_eq!(permuted_view.terminal, completed_verified.terminal);
    assert_eq!(permuted_view.timeline, completed_verified.timeline);

    let base = build_session(&fixture, SwapType::Submarine, true);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let order_id = base
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let terms = base_terms(&fixture, SwapType::Submarine);
    let terminal = |distinct: &str, outcome: &str, loss_accounting: Value| {
        signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    300,
                    distinct,
                    &order_id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 300,
                    },
                    json!({"loss_accounting":loss_accounting}),
                )
                .unwrap(),
            &setup.requester,
        )
    };
    let project = |close: immortal_client::domain::Event| {
        let mut records = base.signed_records().to_vec();
        records.push(close);
        RequesterSessionView::from_signed_records(
            &setup.config,
            &records,
            delivery_receipts(&records, 100),
        )
        .unwrap()
    };
    let mut complete_failed = empty_loss_accounting(&terms);
    complete_failed["evidence_refs"] =
        json!([bound_failure_evidence(&terms, setup.requester.pubkey())]);
    let failed = terminal(&"81".repeat(32), "failed", complete_failed.clone());
    let failed_view = project(failed.clone());
    assert_eq!(
        failed_view.terminal.claimed_state,
        RequesterTerminalState::Failed
    );
    assert!(!failed_view.terminal.watch_terminal);
    let mut failed_records = base.signed_records().to_vec();
    failed_records.push(failed.clone());
    let mut failed_session = base.clone();
    failed_session.ingest_signed_record(failed.clone()).unwrap();
    let failed_from_snapshot = RequesterSessionView::from_restored_snapshot(
        &failed_session.persist().unwrap(),
        delivery_receipts(&failed_records, 100),
    )
    .unwrap();
    assert!(!failed_from_snapshot.terminal.watch_terminal);
    assert!(!failed_from_snapshot.terminal.local_effects_verified);
    assert_ne!(
        failed_from_snapshot.verification.state,
        RequesterVerificationState::TerminalVerified
    );

    let mut unresolved_principal = complete_failed.clone();
    unresolved_principal["input_committed"] = json!("1");
    unresolved_principal["principal_unresolved"] = json!("1");
    let unresolved_failed = project(terminal(&"82".repeat(32), "failed", unresolved_principal));
    assert!(!unresolved_failed.terminal.watch_terminal);

    let mut incomplete_failed = complete_failed.clone();
    incomplete_failed
        .as_object_mut()
        .unwrap()
        .remove("miner_fee_paid");
    let incomplete = project(terminal(&"83".repeat(32), "failed", incomplete_failed));
    assert!(!incomplete.terminal.loss_accounting_complete);
    assert!(!incomplete.terminal.watch_terminal);

    for (index, outcome) in ["disputed", "unresolved"].into_iter().enumerate() {
        let view = project(terminal(
            &format!("{:02x}", 132 + index).repeat(32),
            outcome,
            complete_failed.clone(),
        ));
        assert!(!view.terminal.watch_terminal);
    }

    let unresolved = terminal(&"86".repeat(32), "unresolved", complete_failed);
    let mut conflicting_records = base.signed_records().to_vec();
    conflicting_records.extend([failed, unresolved]);
    let conflicted = RequesterSessionView::from_signed_records(
        &setup.config,
        &conflicting_records,
        delivery_receipts(&conflicting_records, 100),
    )
    .unwrap();
    assert_eq!(
        conflicted.terminal.claimed_state,
        RequesterTerminalState::Conflicted
    );
    assert!(
        conflicted
            .timeline
            .iter()
            .filter(|entry| matches!(
                entry.kind,
                immortal_client::mkt_swp_client::RequesterTimelineKind::Close
            ))
            .all(|entry| entry.conflict.is_some())
    );
    conflicting_records.reverse();
    let permuted_conflict = RequesterSessionView::from_signed_records(
        &setup.config,
        &conflicting_records,
        delivery_receipts(&conflicting_records, 100),
    )
    .unwrap();
    assert_eq!(permuted_conflict.terminal, conflicted.terminal);
    assert_eq!(permuted_conflict.timeline, conflicted.timeline);
}

#[test]
fn cooperative_signing_exchange_verifies_and_aborts_to_script_path() {
    let wire_fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-cooperative-signing-v1.json"
    ))
    .unwrap();
    assert_eq!(wire_fixture["actions"].as_array().unwrap().len(), 5);
    assert_eq!(
        wire_fixture["security"]["unilateral_exit_required_before_funding"],
        true
    );
    let (requester_secret, requester_key) = even_key([1; 32]);
    let (provider_secret, provider_key) = even_key([2; 32]);
    let keys = vec![requester_key, provider_key];
    let merkle_root = [3; 32];
    let tweak = musig2_taproot_tweak(&keys, merkle_root).unwrap();
    let aggregate_key = musig2_tweaked_aggregate_key(&keys, &[tweak]).unwrap();
    let mut script_pubkey = vec![0x51, 0x20];
    script_pubkey.extend_from_slice(&aggregate_key.serialize());
    let transaction = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid: [4; 32],
            previous_output: 0,
            script_sig: Vec::new(),
            sequence: 0xffff_fffe,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: 99_000,
            script_pubkey: vec![0x51],
        }],
        0,
    );
    let prevouts = vec![TransactionOutput {
        value_sat: 100_000,
        script_pubkey: script_pubkey.clone(),
    }];
    let raw = transaction.serialize(false).unwrap();
    let signature_hash = taproot_key_spend_sighash(&transaction, &prevouts, 0).unwrap();
    let order_id = "11".repeat(32);
    let context = CooperativeSigningContext {
        schema: "openagents.mkt-swp.cooperative-signing.v1".into(),
        order_id: order_id.clone(),
        swap_contract_sha256: "22".repeat(32),
        effect_id: cooperative_effect_id(&order_id, "source"),
        leg_id: "source".into(),
        unsigned_transaction: lower_hex(&raw),
        transaction_sha256: lower_hex(&sha256(&raw)),
        input_index: 0,
        prevouts: vec![CooperativePrevout {
            amount: "100000".into(),
            script_pubkey: lower_hex(&script_pubkey),
        }],
        signature_hash: lower_hex(&signature_hash),
        sighash_type: "DEFAULT".into(),
        participant_keys: keys.iter().map(|key| lower_hex(&key.serialize())).collect(),
        tweaks: vec![CooperativeTweak {
            value: lower_hex(&tweak.value),
            xonly: tweak.xonly,
        }],
        aggregate_key: lower_hex(&aggregate_key.serialize()),
        exit_package_sha256: "33".repeat(32),
        latest_safe_height: "500".into(),
    };
    context.validate().unwrap();
    let transcript_digest: [u8; 32] = decode_hex(&context.sha256().unwrap()).try_into().unwrap();
    let aggregate = aggregate_key.serialize();
    let mut requester_nonce = musig2_nonce_gen(
        &requester_secret,
        &aggregate,
        &signature_hash,
        &transcript_digest,
        [5; 32],
    )
    .unwrap();
    let mut provider_nonce = musig2_nonce_gen(
        &provider_secret,
        &aggregate,
        &signature_hash,
        &transcript_digest,
        [6; 32],
    )
    .unwrap();
    let public_nonces = [
        requester_nonce.public_nonce(),
        provider_nonce.public_nonce(),
    ];
    let commitments = [
        CooperativeSigningMessage::nonce_commitment(
            context.clone(),
            ParticipantRole::Requester,
            sha256(&public_nonces[0]),
        )
        .unwrap(),
        CooperativeSigningMessage::nonce_commitment(
            context.clone(),
            ParticipantRole::Provider,
            sha256(&public_nonces[1]),
        )
        .unwrap(),
    ];
    let reveals = [
        CooperativeSigningMessage::public_nonce(
            context.clone(),
            ParticipantRole::Requester,
            public_nonces[0],
        )
        .unwrap(),
        CooperativeSigningMessage::public_nonce(
            context.clone(),
            ParticipantRole::Provider,
            public_nonces[1],
        )
        .unwrap(),
    ];
    let partials = [
        musig2_partial_sign(
            &mut requester_nonce,
            &requester_secret,
            &keys,
            &public_nonces,
            &[tweak],
            &signature_hash,
        )
        .unwrap(),
        musig2_partial_sign(
            &mut provider_nonce,
            &provider_secret,
            &keys,
            &public_nonces,
            &[tweak],
            &signature_hash,
        )
        .unwrap(),
    ];
    let partial_messages = [
        CooperativeSigningMessage::partial_signature(
            context.clone(),
            ParticipantRole::Requester,
            public_nonces,
            partials[0],
        )
        .unwrap(),
        CooperativeSigningMessage::partial_signature(
            context.clone(),
            ParticipantRole::Provider,
            public_nonces,
            partials[1],
        )
        .unwrap(),
    ];
    let final_message = CooperativeSigningMessage::final_signature(
        context.clone(),
        ParticipantRole::Provider,
        public_nonces,
        partials,
    )
    .unwrap();
    validate_cooperative_signing_exchange(&[
        (ParticipantRole::Requester, commitments[0].clone()),
        (ParticipantRole::Provider, commitments[1].clone()),
        (ParticipantRole::Requester, reveals[0].clone()),
        (ParticipantRole::Provider, reveals[1].clone()),
        (ParticipantRole::Requester, partial_messages[0].clone()),
        (ParticipantRole::Provider, partial_messages[1].clone()),
        (ParticipantRole::Provider, final_message.clone()),
    ])
    .unwrap();

    assert!(
        validate_cooperative_signing_exchange(&[
            (ParticipantRole::Requester, commitments[0].clone()),
            (ParticipantRole::Requester, reveals[0].clone()),
            (ParticipantRole::Provider, commitments[1].clone()),
        ])
        .is_err()
    );

    let abort = CooperativeSigningMessage::aborted(
        context.clone(),
        ParticipantRole::Provider,
        "counterparty_unavailable",
    )
    .unwrap();
    validate_cooperative_signing_exchange(&[
        (ParticipantRole::Requester, commitments[0].clone()),
        (ParticipantRole::Provider, commitments[1].clone()),
        (ParticipantRole::Requester, reveals[0].clone()),
        (ParticipantRole::Provider, reveals[1].clone()),
        (ParticipantRole::Provider, abort.clone()),
    ])
    .unwrap();
    let requester_abort = CooperativeSigningMessage::aborted(
        context.clone(),
        ParticipantRole::Requester,
        "counterparty_unavailable",
    )
    .unwrap();
    validate_cooperative_signing_exchange(&[
        (ParticipantRole::Requester, commitments[0].clone()),
        (ParticipantRole::Provider, commitments[1].clone()),
        (ParticipantRole::Provider, abort.clone()),
        (ParticipantRole::Requester, requester_abort.clone()),
    ])
    .unwrap();
    assert!(
        validate_cooperative_signing_exchange(&[
            (ParticipantRole::Requester, commitments[0].clone()),
            (ParticipantRole::Provider, commitments[1].clone()),
            (ParticipantRole::Provider, abort),
            (ParticipantRole::Requester, reveals[0].clone()),
        ])
        .is_err()
    );
    assert!(
        validate_cooperative_signing_exchange(&[
            (ParticipantRole::Requester, commitments[0].clone()),
            (ParticipantRole::Provider, commitments[1].clone()),
            (ParticipantRole::Requester, reveals[0].clone()),
            (ParticipantRole::Provider, reveals[1].clone()),
            (ParticipantRole::Requester, partial_messages[0].clone()),
            (ParticipantRole::Provider, partial_messages[1].clone()),
            (ParticipantRole::Provider, final_message.clone()),
            (ParticipantRole::Requester, requester_abort),
        ])
        .is_err()
    );

    let mut forged_index = CooperativeSigningMessage::aborted(
        context.clone(),
        ParticipantRole::Provider,
        "wallet_refused",
    )
    .unwrap();
    forged_index.participant_index = 2;
    assert!(
        validate_cooperative_signing_exchange(&[(ParticipantRole::Provider, forged_index)])
            .is_err()
    );

    let mut invalid = final_message;
    invalid.final_signature = Some("00".repeat(64));
    assert_eq!(
        invalid
            .validate(ParticipantRole::Provider)
            .unwrap_err()
            .code,
        "swp_musig_transcript_invalid"
    );
    let mut changed_transaction = context;
    changed_transaction.transaction_sha256 = "00".repeat(32);
    assert_eq!(
        changed_transaction.validate().unwrap_err().code,
        "swp_musig_transcript_invalid"
    );

    let mut noncanonical_height = changed_transaction;
    noncanonical_height.transaction_sha256 = lower_hex(&sha256(&raw));
    noncanonical_height.latest_safe_height = "0500".into();
    assert_eq!(
        noncanonical_height.validate().unwrap_err().code,
        "swp_musig_transcript_invalid"
    );
}

#[test]
fn custody_filter_rejects_normalized_secret_aliases_and_keeps_public_identifiers() {
    for member in [
        "unreleased_preimage",
        "released-preimage",
        "wallet_seed_hex",
        "claim_spend_key",
        "refund_private_key_bytes",
        "admin_macaroon_hex",
        "node_credentials",
        "liquid-blinding-key",
        "valueBlinderHex",
        "asset_blinder_bytes",
    ] {
        let error = provider_support::reject_custody_material(&json!({member:"forbidden"}))
            .expect_err(member);
        assert_eq!(error.code, "swp_secret_material_forbidden", "{member}");
    }
    provider_support::reject_custody_material(&json!({
        "payment_hash":"00".repeat(32),
        "claim_public_key":"11".repeat(32),
        "refund_public_key":"22".repeat(32),
        "requester_public_keys":[],
        "preimage_recovery_ref":"watchtower:public-reference",
        "credential_exposure":"none"
    }))
    .expect("public protocol identifiers are not custody material");
}

#[cfg(feature = "mkt-swp-fixture-probe")]
#[test]
fn fixture_replay_rejects_expectation_and_nameset_drift() {
    let original = fixture();
    for (section, index, member, replacement, expected_code) in [
        ("verify_before_fund", 0, "error", "swp_invoice_invalid", 33),
        ("recovery", 0, "action", "explicit_loss", 33),
        ("flows", 0, "name", "swp-v1-renamed-flow", 50),
    ] {
        let mut mutated = original.clone();
        mutated[section][index][member] = json!(replacement);
        let encoded = serde_json::to_vec(&mutated).unwrap();
        assert_eq!(
            immortal_client::mkt_swp_client::fixture_replay::replay_manifest_bytes(&encoded)
                .unwrap_err()
                .code(),
            expected_code,
            "{section}[{index}].{member}"
        );
    }
}

#[test]
fn submarine_fixture_enforces_verify_before_fund_and_external_signing() {
    let fixture = fixture();
    let mut session = build_session(&fixture, SwapType::Submarine, true);
    let awaiting_snapshot = session.persist().unwrap();
    let verification = verification_input(&fixture, SwapType::Submarine);
    let prepared = browser_result(
        "prepare_funding_request",
        json!({
            "snapshot_json_hex": lower_hex(&awaiting_snapshot),
            "verification": verification,
            "lightning_readiness": null
        }),
    );
    let browser_authorized = browser_result(
        "verify_before_fund",
        json!({
            "snapshot_json_hex": lower_hex(&awaiting_snapshot),
            "verification": verification,
            "lightning_readiness": null,
            "expected_funding_request": prepared
        }),
    );
    assert_eq!(browser_authorized["funding_request"], prepared);

    let mut changed_request = prepared.clone();
    changed_request["order_id"] = Value::String("00".repeat(32));
    let changed_response = browser_response(
        "verify_before_fund",
        json!({
            "snapshot_json_hex": lower_hex(&awaiting_snapshot),
            "verification": verification,
            "lightning_readiness": null,
            "expected_funding_request": changed_request
        }),
    );
    assert_eq!(
        changed_response["error"]["code"],
        "swp_funding_not_authorized"
    );

    let authorization = session
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |request| {
                assert_eq!(request.swap_type, SwapType::Submarine);
                let FundingAction::BroadcastBitcoin {
                    leg_id,
                    raw_transaction,
                    ..
                } = &request.action
                else {
                    panic!("submarine requester must broadcast Bitcoin funding")
                };
                assert_eq!(leg_id, "source");
                assert_eq!(
                    raw_transaction,
                    &verification_input(&fixture, SwapType::Submarine)
                        .funding
                        .raw_transaction
                );
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        authorization.funding_request().unwrap().swap_type,
        SwapType::Submarine
    );

    let snapshot = authorization.persist().unwrap();
    let restored = SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
    assert!(
        restored
            .verify_before_fund(verification_input(&fixture, SwapType::Submarine), |_| {
                Err("wallet locked".into())
            })
            .unwrap_err()
            .code
            == "swp_funding_not_authorized"
    );

    session = build_session(&fixture, SwapType::Submarine, false);
    let error = session
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |_| Ok(()),
        )
        .unwrap_err();
    assert_eq!(error.code, "swp_exit_package_missing");
}

#[test]
fn deterministic_record_factory_covers_all_private_base_records() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed(
        factory
            .rfq(
                100,
                &"01".repeat(32),
                1_000,
                json!({"swap_type":"submarine"}),
            )
            .unwrap(),
        &setup.requester,
    );
    let quote = signed(
        factory
            .soft_quote(
                101,
                &"02".repeat(32),
                &rfq.id,
                1_000,
                json!({"terms": base_terms(&fixture, SwapType::Submarine)}),
            )
            .unwrap(),
        &setup.provider,
    );
    let order = signed(
        factory
            .order(
                102,
                &"03".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .unwrap(),
        &setup.requester,
    );
    let status = signed(
        factory
            .status(
                ParticipantRole::Requester,
                103,
                &"04".repeat(32),
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let cancel = signed(
        factory
            .cancel(
                ParticipantRole::Requester,
                104,
                &"05".repeat(32),
                &order.id,
                Cancellation {
                    action: "request",
                    reason: "user_request",
                    request_id: None,
                    accepted_id: None,
                },
                json!({}),
            )
            .unwrap(),
        &setup.requester,
    );
    let close = signed(
        factory
            .close(
                ParticipantRole::Requester,
                105,
                &"06".repeat(32),
                &order.id,
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: 105,
                },
                json!({"loss_accounting":{"principal_unresolved":"0"}}),
            )
            .unwrap(),
        &setup.requester,
    );
    assert_eq!(
        [
            rfq.kind,
            quote.kind,
            order.kind,
            status.kind,
            cancel.kind,
            close.kind
        ],
        [39_604, 39_605, 39_606, 39_607, 39_608, 39_609]
    );

    let request = factory
        .rfq(
            110,
            &"07".repeat(32),
            1_000,
            json!({"swap_type":"submarine"}),
        )
        .unwrap();
    let mut changed = setup.requester.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    changed.content.push(' ');
    let error = request.verify_signed(changed).unwrap_err().code;
    assert_eq!(error, "swp_external_signature_mismatch");
    assert_eq!(
        fixture["external_effects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-negative-external-signature-mismatch")
            .and_then(|vector| vector["error"].as_str()),
        Some(error)
    );
}

#[test]
fn provider_lightning_paid_status_uses_completed_base_state() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    let request = factory
        .status(
            ParticipantRole::Provider,
            100,
            &"06".repeat(32),
            &"07".repeat(32),
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "completed",
                swp_state: "lightning_paid",
            },
            Default::default(),
        )
        .unwrap();
    assert!(
        request
            .tags
            .iter()
            .any(|tag| { tag.name() == Some("state") && tag.value() == Some("completed") })
    );
}

#[test]
fn chain_source_funding_required_is_a_provider_instruction() {
    let fixture = fixture();
    let liquid_vectors = liquid_fixture();
    let setup = Setup::new(&fixture);
    let session = build_session(&fixture, SwapType::Chain, true);
    let order = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap();
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let request = factory
        .status(
            ParticipantRole::Provider,
            110,
            &"16".repeat(32),
            &order.id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "funding_required",
                swp_state: "source_funding_required",
            },
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        factory
            .status(
                ParticipantRole::Requester,
                110,
                &"17".repeat(32),
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "funding_required",
                    swp_state: "source_funding_required",
                },
                Default::default(),
            )
            .unwrap_err()
            .code,
        liquid_client_vector_expected(
            &liquid_vectors,
            "swp-v1-negative-requester-claims-source-funding-required",
        )
    );
    let source_before_preflight = factory
        .status(
            ParticipantRole::Requester,
            111,
            &"18".repeat(32),
            &order.id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "funding_observed",
                swp_state: "requester_source_broadcast",
            },
            Default::default(),
        )
        .unwrap();
    let mut premature_records = session.signed_records().to_vec();
    premature_records.push(signed(source_before_preflight, &setup.requester));
    let premature_session = SwapSession::from_signed_records(
        setup.config.clone(),
        premature_records,
        session.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        premature_session
            .status_projection()
            .unwrap()
            .require_contiguous()
            .unwrap_err()
            .code,
        liquid_client_vector_expected(
            &liquid_vectors,
            "swp-v1-negative-btc-liquid-source-before-preflight",
        )
    );

    let provider_accepted = signed(
        factory
            .status(
                ParticipantRole::Provider,
                1,
                &"20".repeat(32),
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let source_terms = signed(
        factory
            .status(
                ParticipantRole::Provider,
                2,
                &"21".repeat(32),
                &order.id,
                StatusState {
                    sequence: 1,
                    previous: Some(&provider_accepted.id),
                    base_state: "awaiting_input",
                    swp_state: "source_lock_terms_ready",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let source_verified = signed(
        factory
            .status_after(
                ParticipantRole::Requester,
                3,
                &"22".repeat(32),
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "awaiting_input",
                    swp_state: "requester_source_verified",
                },
                &source_terms.id,
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let chain_terms = base_terms(&fixture, SwapType::Chain);
    let destination_verifier = verifier_inputs_for(&chain_terms, "destination");
    let destination_handoff = json!({
        "funding_transaction":destination_verifier["funding_transaction"],
        "funding_transaction_sha256":destination_verifier["funding_transaction_sha256"],
    })
    .as_object()
    .expect("destination handoff")
    .clone();
    let destination_terms = signed(
        factory
            .status_after(
                ParticipantRole::Provider,
                4,
                &"23".repeat(32),
                &order.id,
                StatusState {
                    sequence: 2,
                    previous: Some(&source_terms.id),
                    base_state: "awaiting_input",
                    swp_state: "destination_lock_terms_ready",
                },
                &source_verified.id,
                destination_handoff.clone(),
            )
            .unwrap(),
        &setup.provider,
    );
    let mut changed_handoff = destination_handoff;
    changed_handoff.insert(
        "funding_transaction_sha256".to_owned(),
        json!("ff".repeat(32)),
    );
    let changed_destination_terms = signed(
        factory
            .status_after(
                ParticipantRole::Provider,
                4,
                &"28".repeat(32),
                &order.id,
                StatusState {
                    sequence: 2,
                    previous: Some(&source_terms.id),
                    base_state: "awaiting_input",
                    swp_state: "destination_lock_terms_ready",
                },
                &source_verified.id,
                changed_handoff,
            )
            .unwrap(),
        &setup.provider,
    );
    let mut changed_handoff_records = session.signed_records().to_vec();
    changed_handoff_records.extend([
        provider_accepted.clone(),
        source_terms.clone(),
        source_verified.clone(),
        changed_destination_terms,
    ]);
    assert_eq!(
        SwapSession::from_signed_records(
            setup.config.clone(),
            changed_handoff_records,
            session.exit_packages().to_vec(),
        )
        .unwrap()
        .status_projection()
        .unwrap()
        .require_contiguous()
        .unwrap_err()
        .code,
        "swp_status_transition_invalid"
    );
    let destination_verified = signed(
        factory
            .status_after(
                ParticipantRole::Requester,
                5,
                &"24".repeat(32),
                &order.id,
                StatusState {
                    sequence: 1,
                    previous: Some(&source_verified.id),
                    base_state: "awaiting_input",
                    swp_state: "requester_destination_verified",
                },
                &destination_terms.id,
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let funding_required = signed(
        factory
            .status_after(
                ParticipantRole::Provider,
                6,
                &"25".repeat(32),
                &order.id,
                StatusState {
                    sequence: 3,
                    previous: Some(&destination_terms.id),
                    base_state: "funding_required",
                    swp_state: "source_funding_required",
                },
                &destination_verified.id,
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let unsigned_broadcast = signed(
        factory
            .status(
                ParticipantRole::Requester,
                10_000,
                &"26".repeat(32),
                &order.id,
                StatusState {
                    sequence: 2,
                    previous: Some(&destination_verified.id),
                    base_state: "funding_observed",
                    swp_state: "requester_source_broadcast",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let causal_broadcast = signed(
        factory
            .status_after(
                ParticipantRole::Requester,
                0,
                &"27".repeat(32),
                &order.id,
                StatusState {
                    sequence: 2,
                    previous: Some(&destination_verified.id),
                    base_state: "funding_observed",
                    swp_state: "requester_source_broadcast",
                },
                &funding_required.id,
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let preflight = [
        provider_accepted,
        source_terms,
        source_verified,
        destination_terms,
        destination_verified,
        funding_required,
    ];
    let mut prepublished_records = session.signed_records().to_vec();
    prepublished_records.extend(preflight.clone());
    prepublished_records.push(unsigned_broadcast);
    assert_eq!(
        SwapSession::from_signed_records(
            setup.config.clone(),
            prepublished_records,
            session.exit_packages().to_vec(),
        )
        .unwrap()
        .status_projection()
        .unwrap()
        .require_contiguous()
        .unwrap_err()
        .code,
        liquid_client_vector_expected(
            &liquid_vectors,
            "swp-v1-negative-cross-signer-status-prepublish",
        )
    );
    let mut causal_records = session.signed_records().to_vec();
    causal_records.extend(preflight);
    causal_records.push(causal_broadcast);
    SwapSession::from_signed_records(
        setup.config.clone(),
        causal_records,
        session.exit_packages().to_vec(),
    )
    .unwrap()
    .status_projection()
    .unwrap()
    .require_contiguous()
    .unwrap();
    factory
        .status(
            ParticipantRole::Provider,
            112,
            &"19".repeat(32),
            &order.id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "funding_observed",
                swp_state: "provider_destination_broadcast",
            },
            Default::default(),
        )
        .unwrap();

    let vocabulary = liquid_vectors["chain_status_vocabulary"]
        .as_array()
        .unwrap()
        .clone();
    for (index, row) in vocabulary.iter().enumerate() {
        let role = match row["role"].as_str().unwrap() {
            "requester" => ParticipantRole::Requester,
            "provider" => ParticipantRole::Provider,
            value => panic!("unsupported fixture role {value}"),
        };
        let distinct = format!("{:064x}", index + 32);
        factory
            .status(
                role,
                120 + u64::try_from(index).unwrap(),
                &distinct,
                &order.id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: row["base_state"].as_str().unwrap(),
                    swp_state: row["state"].as_str().unwrap(),
                },
                Default::default(),
            )
            .unwrap_or_else(|error| panic!("fixture state {} failed: {error}", row["state"]));
    }

    let mut records = session.signed_records().to_vec();
    records.push(signed(request, &setup.provider));
    RequesterSessionView::from_signed_records(
        &setup.config,
        &records,
        delivery_receipts(&records, 110),
    )
    .unwrap();
}

#[test]
fn lightning_payment_pending_status_is_valid_for_either_funding_direction() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    for role in [ParticipantRole::Requester, ParticipantRole::Provider] {
        factory
            .status(
                role,
                100,
                &"08".repeat(32),
                &"09".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "executing",
                    swp_state: "lightning_payment_pending",
                },
                Default::default(),
            )
            .expect("either Lightning payer can announce payment initiation");
    }
}

#[test]
fn legacy_quote_api_preserves_safe_source_compatibility() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    let soft = factory
        .quote(
            101,
            &"02".repeat(32),
            &"03".repeat(32),
            1_000,
            QuotePolicy {
                quote_class: "firm",
                reservation: "soft",
            },
            json!({"terms":{}}),
        )
        .unwrap();
    assert_eq!(soft.kind, 39_605);
    assert_eq!(
        factory
            .quote(
                101,
                &"04".repeat(32),
                &"05".repeat(32),
                1_000,
                QuotePolicy {
                    quote_class: "firm",
                    reservation: "hard",
                },
                json!({"terms":{}}),
            )
            .unwrap_err()
            .code,
        "swp_reservation_unconfirmed"
    );
}

#[test]
fn doomsday_snapshot_builds_keyless_esplora_request() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);
    let snapshot = session.persist().unwrap();
    let restored = SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
    let action = restored
        .recovery_action_with(|request| {
            assert_eq!(request.swap_type, SwapType::Submarine);
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 140,
                source_funding_confirmation_height: Some(100),
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: None,
            })
        })
        .unwrap();
    assert!(matches!(action, RecoveryAction::BroadcastPresigned { .. }));
    let request = KeylessEsploraExecutor::request(
        &restored.exit_packages()[0],
        "https://esplora.example/api",
    )
    .unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "https://esplora.example/api/tx");
    assert!(!request.body.is_empty());
}

#[test]
fn exit_commitment_excludes_only_circular_contract_bindings() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);
    let package = &session.exit_packages()[0];
    let original = package.commitment_sha256().unwrap();

    let mut circular = package.document().clone();
    circular["swap_contract_ids"] = json!(["aa".repeat(32), "bb".repeat(32)]);
    circular["contract_sha256"] = json!("cc".repeat(32));
    assert_eq!(
        ExitPackage::parse(circular)
            .unwrap()
            .commitment_sha256()
            .unwrap(),
        original
    );

    let mut relabeled = package.document().clone();
    relabeled["order_id"] = json!("dd".repeat(32));
    assert_ne!(
        ExitPackage::parse(relabeled)
            .unwrap()
            .commitment_sha256()
            .unwrap(),
        original
    );
}

#[test]
fn provider_exit_seed_commitment_matches_the_accepted_session_canonical_package() {
    let fixture = fixture();
    let session = build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            provider_cooperative_exit: true,
            ..BuildOptions::default()
        },
    );
    assert_eq!(session.exit_packages().len(), 2);
}

#[test]
fn reverse_and_chain_requester_flows_authorize_and_plan_recovery() {
    let fixture = fixture();
    for swap_type in [SwapType::Reverse, SwapType::Chain] {
        let session = build_session(&fixture, swap_type, true);
        let authorized = if swap_type == SwapType::Reverse {
            session
                .verify_before_fund_with_lightning(
                    verification_input(&fixture, swap_type),
                    lightning_ready,
                    |_| Ok(()),
                )
                .unwrap()
        } else {
            session
                .verify_before_fund(verification_input(&fixture, swap_type), |_| Ok(()))
                .unwrap()
        };
        assert_eq!(authorized.funding_request().unwrap().swap_type, swap_type);
        match (&authorized.funding_request().unwrap().action, swap_type) {
            (
                FundingAction::PayLightningInvoice {
                    leg_id, invoice, ..
                },
                SwapType::Reverse,
            ) => {
                assert_eq!(leg_id, "lightning");
                assert_eq!(invoice, &fixture_string(&fixture, "invoice"));
            }
            (FundingAction::BroadcastBitcoin { leg_id, .. }, SwapType::Chain) => {
                assert_eq!(leg_id, "source");
            }
            _ => panic!("requester funding action does not match swap topology"),
        }
        let action = authorized
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 140,
                    source_funding_confirmation_height: Some(100),
                    counterparty_available: false,
                    completed: false,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state: (swap_type == SwapType::Reverse)
                        .then_some(LightningRecoveryState::Pending),
                    chain_state: Some(ChainRecoveryState::DestinationClaimable),
                })
            })
            .unwrap();
        assert!(matches!(action, RecoveryAction::RequestWalletClaim { .. }));
    }
}

#[test]
fn flow_contracts_freeze_distinct_requester_topologies() {
    let fixture = fixture();
    for topology in fixture["flow_topologies"].as_array().unwrap() {
        let swap_type = match topology["swap_type"].as_str().unwrap() {
            "submarine" => SwapType::Submarine,
            "reverse" => SwapType::Reverse,
            "chain" => SwapType::Chain,
            _ => panic!("unknown fixture topology"),
        };
        let session = build_session(&fixture, swap_type, true);
        let contract = contract_document(&session);
        let funding = &topology["requester_funding"];
        assert!(
            contract["effect_bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|binding| {
                    binding["role"] == funding["role"] && binding["leg_id"] == funding["leg_id"]
                })
        );
        let exits = session
            .exit_packages()
            .iter()
            .map(|package| {
                (
                    package.document()["leg_id"].as_str().unwrap(),
                    package.document()["exit"]["path"].as_str().unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        let expected = topology["requester_exits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|exit| {
                (
                    exit["leg_id"].as_str().unwrap(),
                    exit["path"].as_str().unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(exits, expected);
    }
}

#[test]
fn provider_quote_extensions_acceptance_deadline_and_order_selection_are_checked() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    let mut profile = provider_quote_profile(&fixture, 200);
    profile["future_extension"] = json!({"retained":true});
    provider_support::validate_quote_profile(&profile, "soft").unwrap();

    profile["critical"] = json!(["future_extension"]);
    assert_eq!(
        provider_support::validate_quote_profile(&profile, "soft")
            .unwrap_err()
            .code,
        "swp_unsupported_critical_member"
    );
    profile.as_object_mut().unwrap().remove("critical");

    let terms = &profile["terms"];
    let rfq = signed(
        factory
            .rfq(
                100,
                &"31".repeat(32),
                300,
                json!({
                    "constraints":{
                        "swap_type":terms["swap_type"],
                        "asset_pair":terms["asset_pair"],
                        "input_amount":terms["input_amount"],
                        "maximum_total_fee":terms["maximum_total_fee"],
                        "confirmation_policy":terms["confirmation_policy"],
                        "allowed_script_modes":["taproot-musig2-script-exit"],
                        "desired_completion_time":terms["desired_completion_time"],
                        "firm_quote_required":true,
                        "payment_hash":terms["payment_hash"],
                        "invoice_sha256":verifier_inputs_for(terms, "lightning")["invoice_sha256"],
                        "requester_public_keys":requester_public_keys(terms)
                    }
                }),
            )
            .unwrap(),
        &setup.requester,
    );
    provider_support::validate_quote_against_rfq(&rfq, &profile, "firm", 101, 250).unwrap();
    provider_support::validate_order_acceptance_deadline(profile.as_object().unwrap(), 250, 200)
        .unwrap();
    assert_eq!(
        provider_support::validate_order_acceptance_deadline(
            profile.as_object().unwrap(),
            250,
            201,
        )
        .unwrap_err()
        .code,
        "swp_quote_expired"
    );
    profile["reservation_terms"]["profile_timeout_at"] = json!(150);
    assert_eq!(
        provider_support::validate_order_acceptance_deadline(
            profile.as_object().unwrap(),
            250,
            151,
        )
        .unwrap_err()
        .code,
        "swp_quote_expired"
    );

    let quote_profile = json!({
        "terms":{},
        "selectable":{"input_amount":{"minimum":"10","maximum":"20"}}
    });
    let invalid_order = json!({
        "accepted_quote_id":"32".repeat(32),
        "selection":{"input_amount":"21"}
    });
    assert_eq!(
        provider_support::validate_order_selection(
            quote_profile.as_object().unwrap(),
            invalid_order.as_object().unwrap(),
        )
        .unwrap_err()
        .code,
        "swp_order_selection_invalid"
    );
}

#[test]
fn quote_expiry_and_order_selection_are_checked_before_funding() {
    let fixture = fixture();
    let expired = build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            quote_expiration: 102,
            order_created_at: 102,
            ..BuildOptions::default()
        },
    );
    assert_eq!(
        expired
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
            )
            .unwrap_err()
            .code,
        "swp_quote_expired"
    );

    let selectable = json!({
        "input_amount":{"minimum":"100000","maximum":"200000"},
        "fee_payer":["requester","provider"],
        "confirmation_policy":["one_confirmation"],
        "public_receipt_consent":[false,true]
    });
    let selection = json!({
        "input_amount":"100000",
        "fee_payer":"requester",
        "confirmation_policy":"one_confirmation",
        "public_receipt_consent":false
    });
    let valid = build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            quote_selectable: Some(&selectable),
            order_selection: Some(&selection),
            contract_selection: Some(&selection),
            ..BuildOptions::default()
        },
    );
    assert!(
        valid
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
            )
            .is_ok()
    );

    for selection in [json!({}), Value::Null, json!({"fee_payer":"requester"})] {
        let inherited = build_session_with_options(
            &fixture,
            SwapType::Submarine,
            BuildOptions {
                quote_selectable: Some(&selectable),
                order_selection: Some(&selection),
                contract_selection: Some(&selection),
                ..BuildOptions::default()
            },
        );
        inherited
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(()),
            )
            .unwrap();
    }

    let outside_selection = json!({"input_amount":"200001"});
    let outside = build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            quote_selectable: Some(&selectable),
            order_selection: Some(&outside_selection),
            contract_selection: Some(&outside_selection),
            ..BuildOptions::default()
        },
    );
    assert_eq!(
        outside
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
            )
            .unwrap_err()
            .code,
        "swp_order_selection_invalid"
    );
}

#[test]
fn invoice_expiry_and_minimum_final_cltv_are_locally_verified() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);
    let mut expired = verification_input(&fixture, SwapType::Submarine);
    let invoice = expired.invoice.as_mut().unwrap();
    invoice.observed_at = fixture["deterministic_session"]["invoice_timestamp"]
        .as_u64()
        .unwrap()
        + fixture["deterministic_session"]["invoice_expiry_seconds"]
            .as_u64()
            .unwrap();
    assert_eq!(
        session
            .clone()
            .verify_before_fund(expired, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_invoice_invalid"
    );

    let mut final_cltv = verification_input(&fixture, SwapType::Submarine);
    final_cltv
        .invoice
        .as_mut()
        .unwrap()
        .required_minimum_final_cltv_delta = 19;
    assert_eq!(
        session
            .verify_before_fund(final_cltv, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_invoice_invalid"
    );
}

#[test]
fn exit_leaf_execution_rejects_wrong_hashlock_and_premature_timeouts() {
    let fixture = fixture();
    let chain = build_session(&fixture, SwapType::Chain, true);
    let authorized = chain
        .verify_before_fund(verification_input(&fixture, SwapType::Chain), |_| Ok(()))
        .unwrap();
    let claim_package = authorized.exit_packages()[1].clone();
    let error = authorized
        .sign_exit_with(1, |request| {
            Ok(add_signed_taproot_witness(
                &claim_package,
                &request.unsigned_transaction,
                &request.signature_hash,
                Some([0xff; 32]),
            ))
        })
        .unwrap_err()
        .code;
    assert_eq!(error, "swp_external_signature_invalid");
    assert_eq!(
        fixture["external_effects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-negative-external-signature-invalid")
            .and_then(|vector| vector["error"].as_str()),
        Some(error)
    );

    let contract_ids = ["01".repeat(32), "02".repeat(32)];
    let mut premature_cltv = exit_document(
        &fixture,
        SwapType::Submarine,
        ExitDocumentBindings {
            order_id: &"03".repeat(32),
            quote_id: &"04".repeat(32),
            contract_ids: &contract_ids,
            contract_sha256: &"05".repeat(32),
        },
        flow_exit_specs(SwapType::Submarine)[0],
        "wallet_sign",
    );
    premature_cltv["exit"]["lock_time"] = json!(139);
    refresh_exit_template_digest(&mut premature_cltv);
    assert_eq!(
        ExitPackage::parse(premature_cltv).unwrap_err().code,
        "swp_exit_package_unusable"
    );

    let mut premature_csv = exit_document(
        &fixture,
        SwapType::Chain,
        ExitDocumentBindings {
            order_id: &"03".repeat(32),
            quote_id: &"04".repeat(32),
            contract_ids: &contract_ids,
            contract_sha256: &"05".repeat(32),
        },
        ExitSpec {
            leg_id: "source",
            path: "refund",
            condition: "csv",
            mode: "wallet_sign",
        },
        "wallet_sign",
    );
    premature_csv["exit"]["input_sequence"] = json!(19);
    refresh_exit_template_digest(&mut premature_csv);
    assert_eq!(
        ExitPackage::parse(premature_csv).unwrap_err().code,
        "swp_exit_package_unusable"
    );
}

#[test]
fn chain_recovery_waits_for_destination_before_source_refund() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Chain, true);
    let observation = |request: &immortal_client::mkt_swp_client::RecoveryObservationRequest,
                       chain_state| LocalRecoveryObservation {
        session_id: request.session_id.clone(),
        order_id: request.order_id.clone(),
        binding_sha256: request.binding_sha256.clone(),
        current_height: 140,
        source_funding_confirmation_height: Some(100),
        counterparty_available: false,
        completed: false,
        record_loss: false,
        rail_state_unknown: false,
        lightning_state: None,
        chain_state: Some(chain_state),
    };
    assert!(matches!(
        session
            .recovery_action_with(|request| {
                Ok(observation(
                    request,
                    ChainRecoveryState::DestinationClaimable,
                ))
            })
            .unwrap(),
        RecoveryAction::RequestWalletClaim { .. }
    ));
    assert_eq!(
        session
            .recovery_action_with(|request| {
                Ok(observation(
                    request,
                    ChainRecoveryState::DestinationFundedUnclaimed,
                ))
            })
            .unwrap(),
        RecoveryAction::WaitForDestinationRefund
    );
    let source_effect = session.exit_packages()[0].effect_id().unwrap();
    assert_eq!(
        session
            .recovery_action_with(|request| {
                Ok(observation(
                    request,
                    ChainRecoveryState::DestinationRefundedFinal,
                ))
            })
            .unwrap(),
        RecoveryAction::BroadcastPresigned {
            effect_id: source_effect.to_owned()
        }
    );
}

#[test]
fn chain_terminal_refund_requires_exact_requester_source_release() {
    let fixture = fixture();
    let liquid_vectors = liquid_fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let session = build_session(&fixture, SwapType::Chain, true);
    let order_id = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let provider_destination_refunded = signed(
        factory
            .status(
                ParticipantRole::Provider,
                300,
                &"71".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "refunded",
                    swp_state: "provider_destination_refunded",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let requester_source_refunded = signed(
        factory
            .status(
                ParticipantRole::Requester,
                200,
                &"72".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "refunded",
                    swp_state: "requester_source_refunded",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let terminal_without_release = signed(
        factory
            .status(
                ParticipantRole::Provider,
                400,
                &"73".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&provider_destination_refunded.id),
                    base_state: "refunded",
                    swp_state: "refunded",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let mut invalid_records = session.signed_records().to_vec();
    invalid_records.extend([
        provider_destination_refunded.clone(),
        requester_source_refunded.clone(),
        terminal_without_release,
    ]);
    assert_eq!(
        SwapSession::from_signed_records(
            setup.config.clone(),
            invalid_records,
            session.exit_packages().to_vec(),
        )
        .unwrap()
        .status_projection()
        .unwrap()
        .require_contiguous()
        .unwrap_err()
        .code,
        liquid_client_vector_expected(
            &liquid_vectors,
            "swp-v1-negative-liquid-chain-terminal-refund-without-source-release",
        )
    );

    let terminal_with_release = signed(
        factory
            .status_after(
                ParticipantRole::Provider,
                100,
                &"74".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&provider_destination_refunded.id),
                    base_state: "refunded",
                    swp_state: "refunded",
                },
                &requester_source_refunded.id,
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    let mut valid_records = session.signed_records().to_vec();
    valid_records.extend([
        provider_destination_refunded,
        requester_source_refunded,
        terminal_with_release,
    ]);
    SwapSession::from_signed_records(
        setup.config.clone(),
        valid_records,
        session.exit_packages().to_vec(),
    )
    .unwrap()
    .status_projection()
    .unwrap()
    .require_contiguous()
    .unwrap();
}

#[test]
fn chain_exits_select_requester_paths_from_provider_selected_trees() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Chain, true);
    let contract = contract_document(&session);
    for (package, leg_id, requester_path, provider_path) in [
        (&session.exit_packages()[0], "source", "refund", "claim"),
        (
            &session.exit_packages()[1],
            "destination",
            "claim",
            "refund",
        ),
    ] {
        let verifier = verifier_inputs_for(&contract, leg_id);
        let verification = &package.document()["verification"];
        assert_eq!(verifier["exit_path"], provider_path);
        assert_eq!(package.document()["exit"]["path"], requester_path);
        let (script_member, control_member) = if requester_path == "claim" {
            ("claim_script", "taproot_claim_control_block")
        } else {
            ("refund_script", "taproot_refund_control_block")
        };
        assert_eq!(verification["taproot_script"], verifier[script_member]);
        assert_eq!(
            verification["taproot_control_block"],
            verifier[control_member]
        );
        assert_ne!(verification["taproot_script"], verifier["taproot_script"]);
    }
    session
        .verify_before_fund(verification_input(&fixture, SwapType::Chain), |_| Ok(()))
        .expect("both requester chain exits must verify against their path-specific leaves");

    let tampered = try_build_session_with_options(
        &fixture,
        SwapType::Chain,
        BuildOptions {
            path_specific_exit_tamper: true,
            ..BuildOptions::default()
        },
    )
    .expect("signed path-specific tamper fixture");
    let error = tampered
        .verify_before_fund(verification_input(&fixture, SwapType::Chain), |_| Ok(()))
        .expect_err("path-specific verifier tampering must fail closed");
    assert_eq!(
        error.code, "swp_contract_terms_mismatch",
        "{}",
        error.detail
    );
    assert!(error.detail.contains("taproot_script"));
}

#[test]
fn reverse_refunded_destination_never_overclaims_completion() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Reverse, true);
    let recover = |lightning_state, counterparty_available| {
        session
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 200,
                    source_funding_confirmation_height: Some(100),
                    counterparty_available,
                    completed: false,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state,
                    chain_state: Some(ChainRecoveryState::DestinationRefundedFinal),
                })
            })
            .unwrap()
    };
    for counterparty_available in [false, true] {
        assert_eq!(
            recover(
                Some(LightningRecoveryState::UnpaidFinal),
                counterparty_available
            ),
            RecoveryAction::Cancelled
        );
        assert!(matches!(
            recover(Some(LightningRecoveryState::Paid), counterparty_available),
            RecoveryAction::ExplicitLoss { .. }
        ));
        assert!(matches!(
            recover(None, counterparty_available),
            RecoveryAction::ExplicitLoss { .. }
        ));
    }
    assert_eq!(
        recover(Some(LightningRecoveryState::Pending), true),
        RecoveryAction::WaitForCounterparty
    );
    assert!(matches!(
        recover(Some(LightningRecoveryState::Pending), false),
        RecoveryAction::ExplicitLoss { .. }
    ));
}

#[test]
fn verification_refusals_cover_contract_rail_timeout_and_secret_boundaries() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);

    let mut payment_hash = verification_input(&fixture, SwapType::Submarine);
    payment_hash.payment_hash = "ff".repeat(32);
    assert_eq!(
        session
            .clone()
            .verify_before_fund(payment_hash, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_payment_hash_mismatch"
    );

    let mut script = verification_input(&fixture, SwapType::Submarine);
    script.funding.taproot_script = "51".into();
    assert_eq!(
        session
            .clone()
            .verify_before_fund(script, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_script_commitment_mismatch"
    );

    let authorized = session
        .clone()
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |_| Ok(()),
        )
        .unwrap();
    let funding_raw = verification_input(&fixture, SwapType::Submarine)
        .funding
        .raw_transaction;
    assert_eq!(
        authorized
            .observe_bitcoin_funding_with("source", |request| {
                Ok(local_bitcoin_observation(
                    request,
                    &funding_raw,
                    0,
                    false,
                    false,
                ))
            })
            .unwrap_err()
            .code,
        "swp_confirmation_insufficient"
    );

    assert_eq!(
        authorized
            .observe_bitcoin_funding_with("source", |request| {
                Ok(local_bitcoin_observation(
                    request,
                    &funding_raw,
                    1,
                    true,
                    false,
                ))
            })
            .unwrap_err()
            .code,
        "swp_rbf_policy_violation"
    );
    let observed = authorized
        .observe_bitcoin_funding_with("source", |request| {
            Ok(local_bitcoin_observation(
                request,
                &funding_raw,
                2,
                false,
                false,
            ))
        })
        .unwrap();
    assert_eq!(observed.leg_id, "source");
    assert_eq!(observed.confirmations, 2);

    let mut timeout = verification_input(&fixture, SwapType::Submarine);
    timeout.timeout_ladder = TimeoutLadder::Submarine {
        current_height: 110,
        fund_last: 110,
        claim_last: 120,
        refund_first: 140,
        chain_finality_blocks: 1,
        broadcast_safety_blocks: 2,
        reorg_safety_blocks: 6,
        invoice_expiration_time: 2_000,
        claim_expected_time: 1_000,
    };
    assert_eq!(
        session
            .clone()
            .verify_before_fund(timeout, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_timeout_ladder_unsafe"
    );

    let mut amountless = verification_input(&fixture, SwapType::Submarine);
    amountless.invoice.as_mut().unwrap().invoice = serde_json::from_str::<Value>(include_str!(
        "../../../tests/fixtures/nipmkt/swp-verification.json"
    ))
    .unwrap()["bolt11"]["invoice"]
        .as_str()
        .unwrap()
        .into();
    assert_eq!(
        session
            .clone()
            .verify_before_fund(amountless, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_invoice_invalid"
    );

    let mut one_contract = session.signed_records().to_vec();
    one_contract.retain(|event| {
        event.kind != 39_610 || event.pubkey == Setup::new(&fixture).requester.pubkey()
    });
    let one_contract = SwapSession::from_signed_records(
        session.config().clone(),
        one_contract,
        session.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        one_contract
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
            )
            .unwrap_err()
            .code,
        "swp_contract_missing"
    );

    let mut no_rfq = session.signed_records().to_vec();
    no_rfq.retain(|event| event.kind != 39_604);
    assert_eq!(
        SwapSession::from_signed_records(
            session.config().clone(),
            no_rfq,
            session.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );

    let mut snapshot: Value = serde_json::from_slice(&session.persist().unwrap()).unwrap();
    snapshot
        .as_object_mut()
        .unwrap()
        .insert("seed".into(), json!("forbidden"));
    assert_eq!(
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&snapshot).unwrap())
            .unwrap_err()
            .code,
        "swp_secret_material_forbidden"
    );
}

#[test]
fn submarine_contract_resolves_only_the_requester_source_funding_transaction() {
    let fixture = fixture();
    let verification_fixture = verification_fixture();
    let vector = &verification_fixture["quote_contract_funding_resolution"];
    assert_eq!(
        vector["allowed_additions"],
        json!([
            "funding_transaction",
            "funding_transaction_sha256",
            "output_index"
        ])
    );
    let valid = try_build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            funding_resolution: Some(FundingResolutionMutation::Valid),
            ..BuildOptions::default()
        },
    )
    .expect("requester source funding resolution");
    let quote = valid
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_605)
        .expect("Quote");
    let quote: Value = serde_json::from_str(&quote.content).expect("Quote JSON");
    let quote_source = verifier_inputs_for(&quote["mkt_swp"]["terms"], "source");
    for member in vector["allowed_additions"].as_array().expect("additions") {
        assert!(
            quote_source
                .get(member.as_str().expect("addition name"))
                .is_none(),
            "Quote must leave the requester funding choice unresolved"
        );
    }
    let contract = contract_document(&valid);
    let contract_source = verifier_inputs_for(&contract, "source");
    assert_eq!(
        contract_source["funding_transaction"],
        vector["funding_transaction"]
    );
    assert_eq!(
        contract_source["funding_transaction_sha256"],
        vector["funding_transaction_sha256"]
    );
    assert_eq!(contract_source["output_index"], vector["output_index"]);
    assert_eq!(contract_source["amount"], vector["quoted_amount"]);
    assert_eq!(
        contract_source["script_pubkey"],
        vector["quoted_script_pubkey"]
    );
    valid
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |_| Ok(()),
        )
        .expect("resolved contract remains fundable after local verification");

    let valid_chain = try_build_session_with_options(
        &fixture,
        SwapType::Chain,
        BuildOptions {
            funding_resolution: Some(FundingResolutionMutation::Valid),
            ..BuildOptions::default()
        },
    )
    .expect("requester Bitcoin chain-source funding resolution");
    valid_chain
        .verify_before_fund(verification_input(&fixture, SwapType::Chain), |_| Ok(()))
        .expect("resolved Bitcoin chain Contract remains fundable");

    let mutation_names = vector["mutation_failures"]
        .as_array()
        .expect("mutation failures");
    assert_eq!(mutation_names.len(), 8);
    for mutation_name in mutation_names {
        let mutation_name = mutation_name.as_str().expect("mutation name");
        let mutation = FundingResolutionMutation::from_fixture_name(mutation_name);
        let swap_type = if mutation == FundingResolutionMutation::WrongSwap {
            SwapType::Reverse
        } else {
            SwapType::Submarine
        };
        let error = match try_build_session_with_options(
            &fixture,
            swap_type,
            BuildOptions {
                funding_resolution: Some(mutation),
                ..BuildOptions::default()
            },
        ) {
            Ok(session) => session
                .verify_before_fund(verification_input(&fixture, swap_type), |_| Ok(()))
                .expect_err(mutation_name),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            vector["expected_error"].as_str().expect("error code"),
            "{mutation_name}"
        );
    }
}

#[test]
fn status_streams_surface_gaps_forks_and_illegal_regressions() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let base = build_session(&fixture, SwapType::Submarine, true);
    let order_id = base
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let first = signed(
        factory
            .status(
                ParticipantRole::Requester,
                200,
                &"21".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let gap = signed(
        factory
            .status(
                ParticipantRole::Requester,
                202,
                &"22".repeat(32),
                &order_id,
                StatusState {
                    sequence: 2,
                    previous: Some(&"ff".repeat(32)),
                    base_state: "refund_pending",
                    swp_state: "refund_prepared",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut gap_records = base.signed_records().to_vec();
    gap_records.extend([first.clone(), gap]);
    let gap_session = SwapSession::from_signed_records(
        base.config().clone(),
        gap_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        gap_session
            .status_projection()
            .unwrap()
            .require_contiguous()
            .unwrap_err()
            .code,
        "swp_status_gap"
    );

    let fork = signed(
        factory
            .status(
                ParticipantRole::Requester,
                201,
                &"23".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut fork_records = base.signed_records().to_vec();
    fork_records.extend([first.clone(), fork]);
    let fork_session = SwapSession::from_signed_records(
        base.config().clone(),
        fork_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        fork_session
            .status_projection()
            .unwrap()
            .require_contiguous()
            .unwrap_err()
            .code,
        "swp_status_fork"
    );

    let first_fork = signed(
        factory
            .status(
                ParticipantRole::Requester,
                201,
                &"25".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&first.id),
                    base_state: "funding_observed",
                    swp_state: "requester_funding_broadcast",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let second_fork = signed(
        factory
            .status(
                ParticipantRole::Requester,
                202,
                &"26".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&first.id),
                    base_state: "refund_pending",
                    swp_state: "refund_prepared",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let after_fork = signed(
        factory
            .status(
                ParticipantRole::Requester,
                203,
                &"27".repeat(32),
                &order_id,
                StatusState {
                    sequence: 2,
                    previous: Some(&first_fork.id),
                    base_state: "refund_pending",
                    swp_state: "refund_pending",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let after_fork_id = after_fork.id.clone();
    let mut after_fork_records = base.signed_records().to_vec();
    after_fork_records.extend([first.clone(), first_fork, second_fork, after_fork]);
    let after_fork_session = SwapSession::from_signed_records(
        base.config().clone(),
        after_fork_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        after_fork_session
            .status_projection()
            .unwrap()
            .require_contiguous()
            .unwrap_err()
            .code,
        "swp_status_fork"
    );
    assert!(
        after_fork_session
            .status_projection()
            .unwrap()
            .invalid_claims
            .contains_key(&after_fork_id)
    );

    let regression = signed(
        factory
            .status(
                ParticipantRole::Requester,
                203,
                &"24".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&first.id),
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let regression_id = regression.id.clone();
    let mut regression_records = base.signed_records().to_vec();
    regression_records.extend([first, regression]);
    let regression_session = SwapSession::from_signed_records(
        base.config().clone(),
        regression_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    let projection = regression_session.status_projection().unwrap();
    assert!(projection.invalid_claims.contains_key(&regression_id));
    assert_eq!(
        projection.require_contiguous().unwrap_err().code,
        "swp_status_transition_invalid"
    );

    let completed_request = factory
        .status(
            ParticipantRole::Requester,
            204,
            &"28".repeat(32),
            &order_id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "completed",
                swp_state: "completed",
            },
            Default::default(),
        )
        .unwrap();
    let mut mismatched_tags = completed_request.tags.clone();
    let state_tag = mismatched_tags
        .iter_mut()
        .find(|tag| tag.name() == Some("state"))
        .unwrap();
    *state_tag.0.get_mut(1).unwrap() = "awaiting_input".into();
    let mismatched = setup.requester.sign(
        completed_request.created_at,
        completed_request.kind,
        mismatched_tags,
        completed_request.content,
    );
    let mismatched_id = mismatched.id.clone();
    let mut mismatched_records = base.signed_records().to_vec();
    mismatched_records.push(mismatched);
    let mismatched_session = SwapSession::from_signed_records(
        base.config().clone(),
        mismatched_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    let projection = mismatched_session.status_projection().unwrap();
    assert!(projection.invalid_claims.contains_key(&mismatched_id));
    assert!(
        !projection
            .last_valid_status
            .contains_key(setup.requester.pubkey())
    );
    assert_eq!(
        mismatched_session
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 200,
                    source_funding_confirmation_height: Some(100),
                    counterparty_available: false,
                    completed: true,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state: Some(LightningRecoveryState::Paid),
                    chain_state: None,
                })
            })
            .unwrap_err()
            .code,
        "swp_status_transition_invalid"
    );
}

#[test]
fn cancellation_requires_two_exact_consents_and_refuses_funded_history() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let base = build_session(&fixture, SwapType::Submarine, true);
    let order_id = base
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let request = signed(
        factory
            .cancel(
                ParticipantRole::Requester,
                200,
                &"51".repeat(32),
                &order_id,
                Cancellation {
                    action: "request",
                    reason: "user_request",
                    request_id: None,
                    accepted_id: None,
                },
                json!({}),
            )
            .unwrap(),
        &setup.requester,
    );
    let accepted = signed(
        factory
            .cancel(
                ParticipantRole::Provider,
                201,
                &"52".repeat(32),
                &order_id,
                Cancellation {
                    action: "accepted",
                    reason: "user_request",
                    request_id: Some(&request.id),
                    accepted_id: None,
                },
                json!({}),
            )
            .unwrap(),
        &setup.provider,
    );
    let effective_request = factory
        .cancel(
            ParticipantRole::Requester,
            202,
            &"53".repeat(32),
            &order_id,
            Cancellation {
                action: "effective",
                reason: "user_request",
                request_id: Some(&request.id),
                accepted_id: Some(&accepted.id),
            },
            json!({}),
        )
        .unwrap();
    let effective = signed(effective_request.clone(), &setup.requester);
    let terms = base_terms(&fixture, SwapType::Submarine);
    let close = signed(
        factory
            .close(
                ParticipantRole::Requester,
                203,
                &"54".repeat(32),
                &order_id,
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: 203,
                },
                json!({
                    "cancel_id":effective.id,
                    "loss_accounting":empty_loss_accounting(&terms)
                }),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut valid_records = base.signed_records().to_vec();
    valid_records.extend([request.clone(), accepted.clone(), effective.clone(), close]);
    let cancelled = SwapSession::from_signed_records(
        base.config().clone(),
        valid_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        cancelled.status_projection().unwrap().close_records.len(),
        1
    );
    let cancellation_view = RequesterSessionView::from_signed_records(
        &setup.config,
        cancelled.signed_records(),
        delivery_receipts(cancelled.signed_records(), 100),
    )
    .unwrap();
    let accepted_entry = cancellation_view
        .timeline
        .iter()
        .find(|entry| entry.event_id == accepted.id)
        .unwrap();
    assert!(accepted_entry.causal_event_ids.contains(&request.id));
    assert!(accepted_entry.causal_event_ids.contains(&order_id));
    let effective_entry = cancellation_view
        .timeline
        .iter()
        .find(|entry| entry.event_id == effective.id)
        .unwrap();
    assert!(effective_entry.causal_event_ids.contains(&accepted.id));
    assert!(effective_entry.causal_event_ids.contains(&request.id));
    let request_index = cancellation_view
        .timeline
        .iter()
        .position(|entry| entry.event_id == request.id)
        .unwrap();
    let accepted_index = cancellation_view
        .timeline
        .iter()
        .position(|entry| entry.event_id == accepted.id)
        .unwrap();
    let effective_index = cancellation_view
        .timeline
        .iter()
        .position(|entry| entry.event_id == effective.id)
        .unwrap();
    assert!(request_index < accepted_index);
    assert!(accepted_index < effective_index);
    let close_entry = cancellation_view.timeline.last().unwrap();
    assert!(close_entry.causal_event_ids.contains(&effective.id));
    let mut permuted_records = cancelled.signed_records().to_vec();
    permuted_records.reverse();
    let permuted_view = RequesterSessionView::from_signed_records(
        &setup.config,
        &permuted_records,
        delivery_receipts(&permuted_records, 100),
    )
    .unwrap();
    assert_eq!(permuted_view.timeline, cancellation_view.timeline);
    let acceptor_effective_request = factory
        .cancel(
            ParticipantRole::Provider,
            202,
            &"57".repeat(32),
            &order_id,
            Cancellation {
                action: "effective",
                reason: "user_request",
                request_id: Some(&request.id),
                accepted_id: Some(&accepted.id),
            },
            json!({}),
        )
        .unwrap();
    let acceptor_effective = signed(acceptor_effective_request.clone(), &setup.provider);
    let mut acceptor_records = base.signed_records().to_vec();
    acceptor_records.extend([request.clone(), accepted.clone(), acceptor_effective]);
    SwapSession::from_signed_records(
        base.config().clone(),
        acceptor_records,
        base.exit_packages().to_vec(),
    )
    .unwrap();

    let outsider = MarketSigner::from_secret_bytes(test_signing_key(b"cancel-outsider")).unwrap();
    let outsider_effective = outsider.sign(
        acceptor_effective_request.created_at,
        acceptor_effective_request.kind,
        acceptor_effective_request.tags,
        acceptor_effective_request.content,
    );
    let mut outsider_records = base.signed_records().to_vec();
    outsider_records.extend([request.clone(), accepted.clone(), outsider_effective]);
    assert_eq!(
        SwapSession::from_signed_records(
            base.config().clone(),
            outsider_records,
            base.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_contract_signer_invalid"
    );
    assert_eq!(
        cancelled
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
            )
            .unwrap_err()
            .code,
        "swp_cancel_ineffective"
    );

    let assert_bad_effective = |bad_effective| {
        let mut records = base.signed_records().to_vec();
        records.extend([request.clone(), accepted.clone(), bad_effective]);
        assert_eq!(
            SwapSession::from_signed_records(
                base.config().clone(),
                records,
                base.exit_packages().to_vec(),
            )
            .unwrap_err()
            .code,
            "swp_cancel_ineffective"
        );
    };
    let mut missing_tags = effective_request.tags.clone();
    missing_tags.retain(|tag| tag.as_slice().get(3).map(String::as_str) != Some("cancel-accept"));
    assert_bad_effective(setup.requester.sign(
        effective_request.created_at,
        effective_request.kind,
        missing_tags,
        effective_request.content.clone(),
    ));
    let mut swapped_tags = effective_request.tags.clone();
    for tag in &mut swapped_tags {
        if tag.as_slice().get(3).map(String::as_str) == Some("cancel-request") {
            *tag.0.get_mut(3).unwrap() = "cancel-accept".into();
        } else if tag.as_slice().get(3).map(String::as_str) == Some("cancel-accept") {
            *tag.0.get_mut(3).unwrap() = "cancel-request".into();
        }
    }
    assert_bad_effective(setup.requester.sign(
        effective_request.created_at,
        effective_request.kind,
        swapped_tags,
        effective_request.content.clone(),
    ));
    let duplicate = signed(
        factory
            .cancel(
                ParticipantRole::Requester,
                202,
                &"55".repeat(32),
                &order_id,
                Cancellation {
                    action: "effective",
                    reason: "user_request",
                    request_id: Some(&request.id),
                    accepted_id: Some(&request.id),
                },
                json!({}),
            )
            .unwrap(),
        &setup.requester,
    );
    assert_bad_effective(duplicate);

    let funded_status = signed(
        factory
            .status(
                ParticipantRole::Requester,
                201,
                &"56".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "funding_observed",
                    swp_state: "requester_funding_broadcast",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut funded_records = base.signed_records().to_vec();
    funded_records.extend([request, accepted, funded_status, effective]);
    assert_eq!(
        SwapSession::from_signed_records(
            base.config().clone(),
            funded_records,
            base.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_cancel_ineffective"
    );
}

#[test]
fn close_terminal_variants_bind_failure_evidence_or_explicit_unknowns() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let base = build_session(&fixture, SwapType::Submarine, true);
    let order_id = base
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let terms = base_terms(&fixture, SwapType::Submarine);
    let evidence = bound_failure_evidence(&terms, setup.requester.pubkey());
    let terminal = |distinct: &str, outcome: &str, loss_accounting: Value| {
        signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    300,
                    distinct,
                    &order_id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 300,
                    },
                    json!({"loss_accounting":loss_accounting}),
                )
                .unwrap(),
            &setup.requester,
        )
    };
    let mut failed_loss = empty_loss_accounting(&terms);
    failed_loss["evidence_refs"] = json!([evidence.clone()]);
    let failed = terminal(&"61".repeat(32), "failed", failed_loss);
    let mut disputed_loss = empty_loss_accounting(&terms);
    disputed_loss["evidence_refs"] = json!([evidence]);
    let disputed = terminal(&"62".repeat(32), "disputed", disputed_loss);
    let mut unresolved_loss = empty_loss_accounting(&terms);
    unresolved_loss["input_committed"] = terms["input_amount"].clone();
    unresolved_loss
        .as_object_mut()
        .unwrap()
        .remove("principal_unresolved");
    unresolved_loss["unknown_fields"] = json!(["principal_unresolved"]);
    let unresolved = terminal(&"63".repeat(32), "unresolved", unresolved_loss);
    for close in [failed, disputed, unresolved] {
        let mut records = base.signed_records().to_vec();
        records.push(close);
        SwapSession::from_signed_records(
            base.config().clone(),
            records,
            base.exit_packages().to_vec(),
        )
        .unwrap();
    }

    let mut forged_loss = empty_loss_accounting(&terms);
    let mut forged_evidence = bound_failure_evidence(&terms, setup.requester.pubkey());
    forged_evidence["artifact_sha256"] = json!("ff".repeat(32));
    forged_evidence["verifier_pubkey"] = json!(setup.provider.pubkey());
    forged_loss["evidence_refs"] = json!([forged_evidence]);
    let forged = terminal(&"64".repeat(32), "failed", forged_loss);
    let mut records = base.signed_records().to_vec();
    records.push(forged);
    assert_eq!(
        SwapSession::from_signed_records(
            base.config().clone(),
            records,
            base.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );

    let mut vanished_loss = empty_loss_accounting(&terms);
    vanished_loss["input_committed"] = terms["input_amount"].clone();
    vanished_loss["evidence_refs"] =
        json!([bound_failure_evidence(&terms, setup.requester.pubkey())]);
    let vanished = terminal(&"65".repeat(32), "failed", vanished_loss);
    let mut records = base.signed_records().to_vec();
    records.push(vanished);
    assert_eq!(
        SwapSession::from_signed_records(
            base.config().clone(),
            records,
            base.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );

    for (index, unknown_field) in ["output_received", "miner_fee_paid"]
        .into_iter()
        .enumerate()
    {
        let mut unknown_loss = empty_loss_accounting(&terms);
        unknown_loss["input_committed"] = terms["input_amount"].clone();
        unknown_loss["evidence_refs"] =
            json!([bound_failure_evidence(&terms, setup.requester.pubkey())]);
        unknown_loss.as_object_mut().unwrap().remove(unknown_field);
        unknown_loss["unknown_fields"] = json!([unknown_field]);
        let close = terminal(
            &format!("{:02x}", 102 + index).repeat(32),
            "unresolved",
            unknown_loss,
        );
        let mut records = base.signed_records().to_vec();
        records.push(close);
        assert_eq!(
            SwapSession::from_signed_records(
                base.config().clone(),
                records,
                base.exit_packages().to_vec(),
            )
            .unwrap_err()
            .code,
            "swp_unresolved_loss",
            "{unknown_field} cannot hide missing principal"
        );
    }

    for (index, outcome) in ["failed", "disputed", "unresolved"].into_iter().enumerate() {
        let mut unknown_loss = empty_loss_accounting(&terms);
        unknown_loss["evidence_refs"] =
            json!([bound_failure_evidence(&terms, setup.requester.pubkey())]);
        let Some(unknown_loss_object) = unknown_loss.as_object_mut() else {
            panic!("loss accounting fixture must be an object");
        };
        unknown_loss_object.remove("input_committed");
        unknown_loss["unknown_fields"] = json!(["input_committed"]);
        let close = terminal(
            &format!("{:02x}", 110 + index).repeat(32),
            outcome,
            unknown_loss,
        );
        let mut records = base.signed_records().to_vec();
        records.push(close);
        assert_eq!(
            SwapSession::from_signed_records(
                base.config().clone(),
                records,
                base.exit_packages().to_vec(),
            )
            .unwrap_err()
            .code,
            "swp_unresolved_loss",
            "{outcome} cannot make committed principal unknown"
        );
    }
}

#[test]
fn wallet_callback_effect_replay_and_custody_tripwires_are_bounded() {
    let fixture = fixture();
    let session = build_session_mode(&fixture, SwapType::Submarine, Some("wallet_sign"));
    let mut authorized = session
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |_| Ok(()),
        )
        .unwrap();
    let refund_package = authorized.exit_packages()[0].clone();
    let signed_exit = authorized
        .sign_exit_with(0, |request| {
            Ok(add_signed_taproot_witness(
                &refund_package,
                &request.unsigned_transaction,
                &request.signature_hash,
                None,
            ))
        })
        .unwrap();
    assert!(matches!(
        signed_exit,
        ExitSigningOutcome::Signed(ref signed) if signed.path == "refund"
    ));
    assert_eq!(
        authorized
            .sign_exit_with(0, |request| {
                let mut invalid = add_signed_taproot_witness(
                    &refund_package,
                    &request.unsigned_transaction,
                    &request.signature_hash,
                    None,
                );
                invalid[61] ^= 1;
                Ok(invalid)
            })
            .unwrap_err()
            .code,
        "swp_external_signature_invalid"
    );

    let claim_session = build_session(&fixture, SwapType::Chain, true);
    let claim_authorized = claim_session
        .verify_before_fund(verification_input(&fixture, SwapType::Chain), |_| Ok(()))
        .unwrap();
    let claim_package = claim_authorized.exit_packages()[1].clone();
    let signed_claim = claim_authorized
        .sign_exit_with(1, |request| {
            Ok(add_signed_taproot_witness(
                &claim_package,
                &request.unsigned_transaction,
                &request.signature_hash,
                Some(test_released_preimage()),
            ))
        })
        .unwrap();
    assert!(matches!(
        signed_claim,
        ExitSigningOutcome::Signed(ref signed) if signed.path == "claim"
    ));

    let effect_request =
        ExternalEffectRequest::Funding(authorized.funding_request().unwrap().clone());
    let effect = authorized
        .record_external_effect(&effect_request, "regtest:funding:0", "88".repeat(32))
        .unwrap()
        .clone();
    assert_eq!(
        authorized
            .record_external_effect(&effect_request, "regtest:funding:0", "88".repeat(32))
            .unwrap(),
        &effect
    );
    assert_eq!(
        authorized
            .record_external_effect(&effect_request, "regtest:funding:0", "99".repeat(32))
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );

    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config).unwrap();
    for case in fixture["custody_tripwires"].as_array().unwrap() {
        let member = case["member"].as_str().unwrap();
        let mut body = serde_json::Map::new();
        body.insert(member.into(), Value::String("forbidden".into()));
        assert_eq!(
            factory
                .rfq(300, &"31".repeat(32), 400, Value::Object(body))
                .unwrap_err()
                .code,
            "swp_secret_material_forbidden",
            "{member}"
        );
    }
    assert_eq!(
        factory
            .rfq(
                300,
                &"32".repeat(32),
                400,
                json!({"connection":"nostr+walletconnect://secret"}),
            )
            .unwrap_err()
            .code,
        "swp_secret_material_forbidden"
    );
}

#[test]
fn persisted_effect_digests_suppress_funding_and_wallet_callbacks_after_restart() {
    let fixture = fixture();
    let session = build_session_mode(&fixture, SwapType::Reverse, Some("wallet_sign"));
    let mut authorized = session
        .verify_before_fund_with_lightning(
            verification_input(&fixture, SwapType::Reverse),
            lightning_ready,
            |_| Ok(()),
        )
        .unwrap();
    let funding_request =
        ExternalEffectRequest::Funding(authorized.funding_request().unwrap().clone());
    authorized
        .record_external_effect(
            &funding_request,
            "lightning:test-payment:1",
            "81".repeat(32),
        )
        .unwrap();
    let mut authorized = authorized
        .observe_reverse_payment_with(lightning_pending)
        .unwrap();

    let captured_wallet_request = RefCell::new(None);
    assert_eq!(
        authorized
            .sign_exit_with(0, |request| {
                captured_wallet_request.replace(Some(request.clone()));
                Err("capture request before delegating to wallet".into())
            })
            .unwrap_err()
            .code,
        "swp_funding_not_authorized"
    );
    let wallet_request = captured_wallet_request.into_inner().unwrap();
    let wallet_effect_request = ExternalEffectRequest::WalletSigning(wallet_request.clone());
    authorized
        .record_external_effect(
            &wallet_effect_request,
            "wallet:test-signature:1",
            "82".repeat(32),
        )
        .unwrap();

    let snapshot = authorized.persist().unwrap();
    let snapshot_value: Value = serde_json::from_slice(&snapshot).unwrap();
    for effect in snapshot_value["external_effects"].as_array().unwrap() {
        assert_eq!(effect.as_object().unwrap().len(), 5);
        assert!(effect.get("request_type").is_none());
        assert!(effect.get("body").is_none());
    }
    let restored = SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
    let funding_callback_called = Cell::new(false);
    let restored = restored
        .verify_before_fund_with_lightning(
            verification_input(&fixture, SwapType::Reverse),
            lightning_ready,
            |_| {
                funding_callback_called.set(true);
                Ok(())
            },
        )
        .unwrap();
    assert!(!funding_callback_called.get());
    let restored = restored
        .observe_reverse_payment_with(lightning_pending)
        .unwrap();
    let wallet_callback_called = Cell::new(false);
    assert!(matches!(
        restored
            .sign_exit_with(0, |_| {
                wallet_callback_called.set(true);
                Err("callback must be suppressed".into())
            })
            .unwrap(),
        ExitSigningOutcome::AlreadyExecuted { ref effect_id, .. }
            if effect_id == &wallet_request.effect_id
    ));
    assert!(!wallet_callback_called.get());
}

#[test]
fn wallet_signing_derives_null_funding_txid_and_presigned_requires_it() {
    let fixture = fixture();
    let wallet_session = build_session_with_options(
        &fixture,
        SwapType::Reverse,
        BuildOptions {
            null_funding_transaction_id: true,
            ..BuildOptions::default()
        },
    );
    let authorized = wallet_session
        .verify_before_fund_with_lightning(
            verification_input(&fixture, SwapType::Reverse),
            lightning_ready,
            |_| Ok(()),
        )
        .unwrap();
    let restored = SwapSession::<AwaitingVerification>::restore(&authorized.persist().unwrap())
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    assert_eq!(
        restored.funding_request().unwrap(),
        authorized.funding_request().unwrap()
    );
    assert!(
        !restored.exit_packages()[0]
            .unsigned_transaction()
            .unwrap()
            .is_empty()
    );

    let mut incomplete_wallet = restored.exit_packages()[0].document().clone();
    incomplete_wallet["funding"]["transaction_template"] = Value::Null;
    assert_eq!(
        ExitPackage::parse(incomplete_wallet).unwrap_err().code,
        "swp_exit_package_unusable"
    );

    let presigned_session = build_session(&fixture, SwapType::Submarine, true);
    let mut document = presigned_session.exit_packages()[0].document().clone();
    document["funding"]["transaction_id"] = Value::Null;
    assert_eq!(
        ExitPackage::parse(document).unwrap_err().code,
        "swp_exit_package_unusable"
    );
}

#[test]
fn keyless_esplora_allows_only_https_or_loopback_http() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);
    let package = &session.exit_packages()[0];
    for endpoint in [
        "https://esplora.example/api",
        "http://127.0.0.1:3002/api",
        "http://localhost:3002/api",
        "http://[::1]:3002/api",
    ] {
        assert!(KeylessEsploraExecutor::request(package, endpoint).is_ok());
    }
    for endpoint in [
        "http://esplora.example/api",
        "http://192.168.1.10/api",
        "http://user@localhost/api",
    ] {
        assert_eq!(
            KeylessEsploraExecutor::request(package, endpoint)
                .unwrap_err()
                .code,
            "swp_exit_package_unusable"
        );
    }
}

#[test]
fn reverse_funding_requires_typed_readiness_and_post_effect_progress() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Reverse, true);
    assert_eq!(
        session
            .clone()
            .verify_before_fund(verification_input(&fixture, SwapType::Reverse), |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_funding_not_authorized"
    );
    let mut authorized = session
        .verify_before_fund_with_lightning(
            verification_input(&fixture, SwapType::Reverse),
            |request| {
                assert_eq!(request.leg_id, "lightning");
                assert_eq!(
                    request.payment_hash,
                    flow_payment_hash(&fixture, SwapType::Reverse)
                );
                assert_eq!(request.maximum_routing_fee, "0");
                assert!(request.hold_invoice_required);
                lightning_ready(request)
            },
            |request| {
                let FundingAction::PayLightningInvoice {
                    maximum_routing_fee,
                    invoice_expires_at,
                    minimum_final_cltv_delta,
                    hold_invoice_required,
                    hold_expiry_height,
                    ..
                } = &request.action
                else {
                    panic!("reverse funding did not bind the Lightning invoice")
                };
                assert_eq!(maximum_routing_fee, "0");
                assert!(*invoice_expires_at > 0);
                assert!(*minimum_final_cltv_delta > 0);
                assert!(*hold_invoice_required);
                assert_eq!(*hold_expiry_height, 160);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        authorized
            .sign_exit_with(0, |_| Ok(Vec::new()))
            .unwrap_err()
            .code,
        "swp_funding_not_authorized"
    );
    let funding_request =
        ExternalEffectRequest::Funding(authorized.funding_request().unwrap().clone());
    authorized
        .record_external_effect(&funding_request, "lightning:pending", "84".repeat(32))
        .unwrap();
    assert_eq!(
        authorized
            .clone()
            .observe_reverse_payment_with(|request| {
                let mut observation = lightning_pending(request)?;
                observation.state = LightningProgressState::Settled;
                Ok(observation)
            })
            .unwrap_err()
            .code,
        "swp_unresolved_loss"
    );
    authorized
        .observe_reverse_payment_with(lightning_pending)
        .unwrap();
}

#[test]
fn terminal_close_requires_exact_persisted_rail_evidence_and_last_status() {
    let fixture = fixture();
    let funding_only = build_session(&fixture, SwapType::Submarine, true);
    assert_eq!(
        funding_only
            .verify_terminal_rail_evidence_with("source", "completed", |request| {
                Ok(LocalRailEvidence {
                    artifact_sha256: "9a".repeat(32),
                    observed_at: 200,
                    view: "funding outpoint only".into(),
                    settlement_reference: request.reference.clone(),
                    verifier_pubkey: None,
                    producer_pubkey: Setup::new(&fixture).requester.pubkey().to_owned(),
                    external_identifier: request.reference.clone(),
                })
            })
            .unwrap_err()
            .code,
        "swp_funding_not_authorized"
    );
    let funding_only = funded_submarine_session(&fixture);
    assert_eq!(
        funding_only
            .verify_terminal_rail_evidence_with("source", "completed", |request| {
                Ok(LocalRailEvidence {
                    artifact_sha256: "9a".repeat(32),
                    observed_at: 200,
                    view: "funding outpoint only".into(),
                    settlement_reference: request.reference.clone(),
                    verifier_pubkey: None,
                    producer_pubkey: Setup::new(&fixture).requester.pubkey().to_owned(),
                    external_identifier: request.reference.clone(),
                })
            })
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    for outcome in ["completed", "refunded"] {
        let mut session = terminal_close_session(&fixture, outcome);
        let snapshot = session.persist().unwrap();
        SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
        let snapshot_value: Value = serde_json::from_slice(&snapshot).unwrap();
        let rail_request: ExternalEffectRequest = serde_json::from_value(
            snapshot_value["external_effect_requests"]
                .as_array()
                .unwrap()
                .iter()
                .find(|request| request["request_type"] == "rail_evidence")
                .unwrap()
                .clone(),
        )
        .unwrap();
        let mut generic_restore = SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
        assert_eq!(
            generic_restore
                .record_external_effect(&rail_request, "unverified:rail", "f9".repeat(32))
                .unwrap_err()
                .code,
            "swp_external_effect_conflict"
        );

        let setup = Setup::new(&fixture);
        let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
        let order_id = session
            .signed_records()
            .iter()
            .find(|event| event.kind == 39_606)
            .unwrap()
            .id
            .clone();
        let provider_gap = signed(
            factory
                .status(
                    ParticipantRole::Provider,
                    249,
                    &"79".repeat(32),
                    &order_id,
                    StatusState {
                        sequence: 1,
                        previous: Some(&"78".repeat(32)),
                        base_state: "accepted",
                        swp_state: "accepted",
                    },
                    Default::default(),
                )
                .unwrap(),
            &setup.provider,
        );
        session.ingest_signed_record(provider_gap).unwrap();
        assert!(
            session
                .status_projection()
                .unwrap()
                .gaps
                .contains_key(setup.provider.pubkey())
        );
        let fork = signed(
            factory
                .status(
                    ParticipantRole::Requester,
                    251,
                    &"7a".repeat(32),
                    &order_id,
                    StatusState {
                        sequence: 0,
                        previous: None,
                        base_state: outcome,
                        swp_state: outcome,
                    },
                    Default::default(),
                )
                .unwrap(),
            &setup.requester,
        );
        assert_eq!(
            session.ingest_signed_record(fork).unwrap_err().code,
            "swp_status_fork"
        );

        let mut tampered: Value = serde_json::from_slice(&snapshot).unwrap();
        let terminal_effect_id = tampered["external_effect_requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|request| request["request_type"] == "rail_evidence")
            .unwrap()["effect_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let terminal_effect = tampered["external_effects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|effect| effect["effect_id"] == terminal_effect_id)
            .unwrap();
        terminal_effect["result_sha256"] = json!("fa".repeat(32));
        assert_eq!(
            SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&tampered).unwrap())
                .unwrap_err()
                .code,
            "swp_external_effect_conflict"
        );

        for mutation in ["view", "policy", "swapped_legs", "outcome"] {
            let mut records = session.signed_records().to_vec();
            let close_index = records
                .iter()
                .position(|event| event.kind == 39_609)
                .unwrap();
            let original_close = &records[close_index];
            let mut profile: Value = serde_json::from_str(original_close.content.as_str()).unwrap();
            let replacement_outcome = if mutation == "outcome" {
                if outcome == "completed" {
                    "refunded"
                } else {
                    "completed"
                }
            } else {
                outcome
            };
            match mutation {
                "view" => {
                    profile["mkt_swp"]["loss_accounting"]["evidence_refs"][0]["view"] =
                        json!("tampered-local-view");
                }
                "policy" => {
                    profile["mkt_swp"]["loss_accounting"]["evidence_refs"][0]["verifier_policy"] =
                        json!("mkt-swp-tampered-v1");
                }
                "swapped_legs" => {
                    profile["mkt_swp"]["loss_accounting"]["evidence_refs"]
                        .as_array_mut()
                        .unwrap()
                        .swap(0, 1);
                }
                "outcome" => {}
                _ => panic!("unknown terminal tamper"),
            }
            records[close_index] = signed(
                factory
                    .close(
                        ParticipantRole::Requester,
                        original_close.created_at,
                        tag_value_test(original_close, "d"),
                        &order_id,
                        CloseOutcome {
                            outcome: replacement_outcome,
                            terminal_at: 260,
                        },
                        profile["mkt_swp"].clone(),
                    )
                    .unwrap(),
                &setup.requester,
            );
            let mut tampered: Value = serde_json::from_slice(&snapshot).unwrap();
            tampered["signed_records"] = serde_json::to_value(records).unwrap();
            assert_eq!(
                SwapSession::<AwaitingVerification>::restore(
                    &serde_json::to_vec(&tampered).unwrap()
                )
                .unwrap_err()
                .code,
                "swp_unresolved_loss"
            );

            let mut records = session.signed_records().to_vec();
            let status_index = records
                .iter()
                .position(|event| {
                    event.kind == 39_607
                        && event.pubkey == setup.requester.pubkey()
                        && tag_value_test(event, "seq") == "0"
                })
                .unwrap();
            let original_status = records[status_index].clone();
            let mut status_tags = original_status.tags.clone();
            let state_tag = status_tags
                .iter_mut()
                .find(|tag| tag.name() == Some("state"))
                .unwrap();
            *state_tag.0.get_mut(1).unwrap() = "awaiting_input".into();
            let mismatched_status = setup.requester.sign(
                original_status.created_at,
                original_status.kind,
                status_tags,
                original_status.content,
            );
            records[status_index] = mismatched_status.clone();
            let close_index = records
                .iter()
                .position(|event| event.kind == 39_609)
                .unwrap();
            let original_close = records[close_index].clone();
            let mut profile: Value = serde_json::from_str(&original_close.content).unwrap();
            profile["mkt_swp"]["status_id"] = json!(mismatched_status.id);
            records[close_index] = signed(
                factory
                    .close(
                        ParticipantRole::Requester,
                        original_close.created_at,
                        tag_value_test(&original_close, "d"),
                        &order_id,
                        CloseOutcome {
                            outcome,
                            terminal_at: 260,
                        },
                        profile["mkt_swp"].clone(),
                    )
                    .unwrap(),
                &setup.requester,
            );
            let mut tampered: Value = serde_json::from_slice(&snapshot).unwrap();
            tampered["signed_records"] = serde_json::to_value(records).unwrap();
            assert_eq!(
                SwapSession::<AwaitingVerification>::restore(
                    &serde_json::to_vec(&tampered).unwrap()
                )
                .unwrap_err()
                .code,
                "swp_status_transition_invalid"
            );
        }

        if outcome == "completed" {
            let mut records = session.signed_records().to_vec();
            let close_index = records
                .iter()
                .position(|event| event.kind == 39_609)
                .unwrap();
            let original_close = &records[close_index];
            let mut profile: Value = serde_json::from_str(original_close.content.as_str()).unwrap();
            profile["mkt_swp"]["loss_accounting"]["input_committed"] = json!("0");
            records[close_index] = signed(
                factory
                    .close(
                        ParticipantRole::Requester,
                        original_close.created_at,
                        tag_value_test(original_close, "d"),
                        &order_id,
                        CloseOutcome {
                            outcome,
                            terminal_at: 260,
                        },
                        profile["mkt_swp"].clone(),
                    )
                    .unwrap(),
                &setup.requester,
            );
            let mut tampered: Value = serde_json::from_slice(&snapshot).unwrap();
            tampered["signed_records"] = serde_json::to_value(records).unwrap();
            assert_eq!(
                SwapSession::<AwaitingVerification>::restore(
                    &serde_json::to_vec(&tampered).unwrap()
                )
                .unwrap_err()
                .code,
                "swp_unresolved_loss"
            );
        }
    }
}

#[test]
fn reverse_no_fund_evidence_allows_mutual_cancel_and_rejects_forgery() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let mut session = build_session(&fixture, SwapType::Reverse, true)
        .verify_before_fund_with_lightning(
            verification_input(&fixture, SwapType::Reverse),
            lightning_ready,
            |_| Ok(()),
        )
        .unwrap();
    let order_id = session.funding_request().unwrap().order_id.clone();
    let funding_request =
        ExternalEffectRequest::Funding(session.funding_request().unwrap().clone());
    session
        .record_external_effect(&funding_request, "lightning:initiation", "85".repeat(32))
        .unwrap();
    let disposition = session
        .verify_reverse_no_fund_with(|request| {
            Ok(LocalLightningDisposition {
                invoice_sha256: request.invoice_sha256.clone(),
                payment_hash: request.payment_hash.clone(),
                observed_at: 350,
                view_sha256: "86".repeat(32),
                state: LightningDispositionState::UnpaidFinal,
                principal_moved: false,
                external_identifier: "lightning:unpaid-final".into(),
            })
        })
        .unwrap();
    let disposition_value = disposition.request_document().unwrap();
    let mut disposition_request_value = disposition_value.clone();
    disposition_request_value.as_object_mut().unwrap().insert(
        "request_type".into(),
        Value::String("lightning_disposition".into()),
    );
    let disposition_request: ExternalEffectRequest =
        serde_json::from_value(disposition_request_value).unwrap();
    assert_eq!(
        session
            .record_external_effect(
                &disposition_request,
                "unverified:lightning",
                "f8".repeat(32),
            )
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    session
        .record_verified_lightning_disposition(disposition)
        .unwrap();
    session = SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap())
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    let status = signed(
        factory
            .status(
                ParticipantRole::Provider,
                360,
                &"87".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "refunded",
                    swp_state: "invoice_cancelled",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.provider,
    );
    session.ingest_signed_record(status).unwrap();
    let request = signed(
        factory
            .cancel(
                ParticipantRole::Provider,
                400,
                &"88".repeat(32),
                &order_id,
                Cancellation {
                    action: "request",
                    reason: "invoice_unpaid",
                    request_id: None,
                    accepted_id: None,
                },
                json!({}),
            )
            .unwrap(),
        &setup.provider,
    );
    session.ingest_signed_record(request.clone()).unwrap();
    let accepted = signed(
        factory
            .cancel(
                ParticipantRole::Requester,
                100,
                &"89".repeat(32),
                &order_id,
                Cancellation {
                    action: "accepted",
                    reason: "invoice_unpaid",
                    request_id: Some(&request.id),
                    accepted_id: None,
                },
                json!({}),
            )
            .unwrap(),
        &setup.requester,
    );
    session.ingest_signed_record(accepted.clone()).unwrap();

    let mut expired_session = session.clone();
    let expired = signed(
        factory
            .close(
                ParticipantRole::Provider,
                405,
                &"8d".repeat(32),
                &order_id,
                CloseOutcome {
                    outcome: "expired",
                    terminal_at: 405,
                },
                json!({
                    "lightning_disposition": disposition_value,
                    "loss_accounting": empty_loss_accounting(&base_terms(&fixture, SwapType::Reverse)),
                }),
            )
            .unwrap(),
        &setup.provider,
    );
    expired_session.ingest_signed_record(expired).unwrap();

    let mut forged_session = session.clone();
    let mut forged_disposition = disposition_value.clone();
    forged_disposition["view_sha256"] = json!("90".repeat(32));
    let forged = signed(
        factory
            .cancel(
                ParticipantRole::Provider,
                50,
                &"8a".repeat(32),
                &order_id,
                Cancellation {
                    action: "effective",
                    reason: "invoice_unpaid",
                    request_id: Some(&request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({"lightning_disposition":forged_disposition}),
            )
            .unwrap(),
        &setup.provider,
    );
    assert_eq!(
        forged_session
            .ingest_signed_record(forged)
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );

    let effective = signed(
        factory
            .cancel(
                ParticipantRole::Provider,
                50,
                &"8b".repeat(32),
                &order_id,
                Cancellation {
                    action: "effective",
                    reason: "invoice_unpaid",
                    request_id: Some(&request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({"lightning_disposition":disposition_value}),
            )
            .unwrap(),
        &setup.provider,
    );
    session.ingest_signed_record(effective.clone()).unwrap();
    let close = signed(
        factory
            .close(
                ParticipantRole::Provider,
                410,
                &"8c".repeat(32),
                &order_id,
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: 410,
                },
                json!({
                    "cancel_id": effective.id,
                    "loss_accounting": empty_loss_accounting(&base_terms(&fixture, SwapType::Reverse)),
                }),
            )
            .unwrap(),
        &setup.provider,
    );
    session.ingest_signed_record(close).unwrap();
    SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap()).unwrap();
}

#[test]
fn recovery_rejects_contradictions_and_requires_contiguous_terminal_status() {
    let fixture = fixture();
    let base = build_session(&fixture, SwapType::Reverse, true);
    let no_fund = base
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 100,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: Some(ChainRecoveryState::DestinationNotFunded),
            })
        })
        .unwrap();
    assert_eq!(no_fund, RecoveryAction::Cancelled);
    assert_eq!(
        base.recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 100,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: true,
                record_loss: true,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Paid),
                chain_state: Some(ChainRecoveryState::DestinationClaimable),
            })
        })
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );
    assert_eq!(
        base.recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 100,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: true,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Paid),
                chain_state: Some(ChainRecoveryState::DestinationClaimable),
            })
        })
        .unwrap_err()
        .code,
        "swp_unresolved_loss"
    );

    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let order_id = base
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let completed = signed(
        factory
            .status(
                ParticipantRole::Requester,
                300,
                &"91".repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "completed",
                    swp_state: "completed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut completed_session = base.clone();
    completed_session.ingest_signed_record(completed).unwrap();
    assert_eq!(
        completed_session
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 100,
                    source_funding_confirmation_height: None,
                    counterparty_available: false,
                    completed: true,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state: Some(LightningRecoveryState::Paid),
                    chain_state: Some(ChainRecoveryState::DestinationClaimable),
                })
            })
            .unwrap(),
        RecoveryAction::Completed
    );

    let gap = signed(
        factory
            .status(
                ParticipantRole::Requester,
                301,
                &"92".repeat(32),
                &order_id,
                StatusState {
                    sequence: 1,
                    previous: Some(&"ff".repeat(32)),
                    base_state: "completed",
                    swp_state: "completed",
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut gap_session = base;
    gap_session.ingest_signed_record(gap).unwrap();
    assert_eq!(
        gap_session
            .recovery_action_with(|request| {
                Ok(LocalRecoveryObservation {
                    session_id: request.session_id.clone(),
                    order_id: request.order_id.clone(),
                    binding_sha256: request.binding_sha256.clone(),
                    current_height: 100,
                    source_funding_confirmation_height: None,
                    counterparty_available: false,
                    completed: true,
                    record_loss: false,
                    rail_state_unknown: false,
                    lightning_state: Some(LightningRecoveryState::Paid),
                    chain_state: Some(ChainRecoveryState::DestinationClaimable),
                })
            })
            .unwrap_err()
            .code,
        "swp_status_gap"
    );
}

#[test]
fn signed_record_ingestion_replays_exactly_and_scans_custody_aliases() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let mut session = build_session(&fixture, SwapType::Submarine, true);
    let order_id = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let request = factory
        .status(
            ParticipantRole::Requester,
            300,
            &"93".repeat(32),
            &order_id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "awaiting_input",
                swp_state: "requester_verification_passed",
            },
            Default::default(),
        )
        .unwrap();
    let event = signed(request.clone(), &setup.requester);
    assert!(session.ingest_signed_record(event.clone()).unwrap());
    assert!(!session.ingest_signed_record(event).unwrap());

    let conflicting = factory
        .status(
            ParticipantRole::Requester,
            301,
            &"93".repeat(32),
            &order_id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "funding_observed",
                swp_state: "requester_funding_broadcast",
            },
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        session
            .ingest_signed_record(signed(conflicting, &setup.requester))
            .unwrap_err()
            .code,
        "swp_idempotency_conflict"
    );

    let mut custody_content: Value = serde_json::from_str(&request.content).unwrap();
    custody_content["mkt_swp"]["claim_key"] = json!("94".repeat(32));
    let custody = setup.requester.sign(
        request.created_at,
        request.kind,
        request.tags,
        serde_json::to_string(&custody_content).unwrap(),
    );
    let mut clean_session = build_session(&fixture, SwapType::Submarine, true);
    assert_eq!(
        clean_session
            .ingest_signed_record(custody)
            .unwrap_err()
            .code,
        "swp_secret_material_forbidden"
    );
}

fn terminal_close_session(fixture: &Value, outcome: &str) -> SwapSession<AwaitingVerification> {
    let setup = Setup::new(fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let mut session = funded_submarine_session(fixture);
    let order_id = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_606)
        .unwrap()
        .id
        .clone();
    let terms = base_terms(fixture, SwapType::Submarine);
    let leg_ids = terms["legs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|leg| leg["leg_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut evidence_refs = Vec::new();
    for (index, leg_id) in leg_ids.iter().enumerate() {
        let verified = session
            .verify_terminal_rail_evidence_with(leg_id, outcome, |request| {
                Ok(LocalRailEvidence {
                    artifact_sha256: format!("{:02x}", 160 + index).repeat(32),
                    observed_at: 240,
                    view: format!("locally verified {} {} settlement", request.rail, outcome),
                    settlement_reference: if request.rail == "bitcoin" {
                        let transaction_id = format!("{:02x}", 176 + index).repeat(32);
                        if request.evidence_class == "bitcoin_spend" {
                            request.reference.clone()
                        } else {
                            transaction_id
                        }
                    } else {
                        request.reference.clone()
                    },
                    verifier_pubkey: None,
                    producer_pubkey: setup.requester.pubkey().to_owned(),
                    external_identifier: format!("local:{}:{}", request.rail, outcome),
                })
            })
            .unwrap();
        evidence_refs.push(verified.evidence_reference().clone());
        session.record_verified_rail_evidence(verified).unwrap();
    }
    session = SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap())
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    let status = signed(
        factory
            .status(
                ParticipantRole::Requester,
                250,
                &format!("{:02x}", if outcome == "completed" { 96 } else { 97 }).repeat(32),
                &order_id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: outcome,
                    swp_state: outcome,
                },
                Default::default(),
            )
            .unwrap(),
        &setup.requester,
    );
    assert!(session.ingest_signed_record(status.clone()).unwrap());
    assert!(!session.ingest_signed_record(status.clone()).unwrap());
    let mut loss = empty_loss_accounting(&terms);
    loss["input_committed"] = terms["input_amount"].clone();
    loss["evidence_refs"] = Value::Array(evidence_refs);
    if outcome == "completed" {
        loss["output_received"] = terms["output_amount"].clone();
    } else {
        loss["input_recovered"] = terms["input_amount"].clone();
    }
    let close = signed(
        factory
            .close(
                ParticipantRole::Requester,
                260,
                &format!("{:02x}", if outcome == "completed" { 98 } else { 99 }).repeat(32),
                &order_id,
                CloseOutcome {
                    outcome,
                    terminal_at: 260,
                },
                json!({
                    "status_id": status.id,
                    "loss_accounting": loss,
                }),
            )
            .unwrap(),
        &setup.requester,
    );
    session.ingest_signed_record(close).unwrap();
    SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap()).unwrap()
}

fn funded_submarine_session(fixture: &Value) -> SwapSession<FundingAuthorized> {
    let mut session = build_session(fixture, SwapType::Submarine, true)
        .verify_before_fund(verification_input(fixture, SwapType::Submarine), |_| Ok(()))
        .unwrap();
    let request = ExternalEffectRequest::Funding(session.funding_request().unwrap().clone());
    session
        .record_external_effect(&request, "bitcoin:broadcast", "91".repeat(32))
        .unwrap();
    session
}

struct Setup {
    config: SwapClientConfig,
    requester: MarketSigner,
    provider: MarketSigner,
}

impl Setup {
    fn new(fixture: &Value) -> Self {
        let deterministic = &fixture["deterministic_session"];
        let requester = MarketSigner::from_secret_bytes(test_signing_key(b"requester")).unwrap();
        let provider = MarketSigner::from_secret_bytes(test_signing_key(b"provider")).unwrap();
        let config = SwapClientConfig {
            session_id: deterministic["session_id"].as_str().unwrap().into(),
            requester_pubkey: requester.pubkey().into(),
            provider_pubkey: provider.pubkey().into(),
            offering_address: format!(
                "39601:{}:{}",
                provider.pubkey(),
                deterministic["offering_id"].as_str().unwrap()
            ),
            provider_route: None,
        };
        Self {
            config,
            requester,
            provider,
        }
    }
}

const LIQUID_NETWORK: &str = "bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LIQUID_ASSET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const LIQUID_INTERNAL_KEY: &str =
    "08228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968";
const LIQUID_ORIGINAL_OUTPUT_KEY: &str =
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct LiquidExitPath {
    output_key: &'static str,
    merkle_root: &'static str,
    script: &'static str,
    control_block: &'static str,
    path: &'static str,
    timelock: u32,
}

const LIQUID_REFUND: LiquidExitPath = LiquidExitPath {
    output_key: "6f28a027ecd92a3d9af9798d032bc0040310a15a5dd7c0e0abb8ea8959523009",
    merkle_root: "be8e5d61bd9415b53af92f729857dfeeabd4e26a7827ec20d7ce99703d21548c",
    script: "028c00b17520716022efaca232dd8a7927619a9e5f1eb8f1c8b87436a52a03ae7e1239a1662aac",
    control_block: "c408228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d968ad4f0cd39b48ad95bd00c6f1f1d08ff3a776c62c9c0e7832b71cdf87d5834bcd",
    path: "refund",
    timelock: 140,
};

const LIQUID_CLAIM: LiquidExitPath = LiquidExitPath {
    output_key: "e299c811d598407b65670e5b11eca62be410095cbb0cce80e782bec4d6fb19fb",
    merkle_root: "3158fb84c8a56733a5d1bcd080d90097b4cf7456bbcf2736d028ac0d588dde3e",
    script: "82012088a820a8cdda70ab7c99dc8dc6a38f979a908a92177eb0dd689770417a5b9a92f78af3882033def30752282502724206c0e18eebed01b436a81cc6ed8b0476f4aaee151ce4ac",
    control_block: "c408228c6db36b8b938de59d8021472522e721233bf4f397f951c5f26f15e5d9685146765099b4d9f38c16ba9664d855287be8e74c1ae9f80f6980672166ace146",
    path: "claim",
    timelock: 0,
};

#[test]
fn liquid_requester_engine_authorizes_persists_and_restores_all_flows() {
    let fixture = fixture();
    let liquid_fixture = liquid_fixture();
    let cases = [
        (SwapType::Submarine, &LIQUID_REFUND, false),
        (SwapType::Reverse, &LIQUID_CLAIM, false),
        (SwapType::Chain, &LIQUID_CLAIM, false),
        (SwapType::Chain, &LIQUID_REFUND, true),
    ];
    for (swap_type, exit, liquid_source) in cases {
        let amount = bitcoin_leg_amount(
            swap_type,
            if swap_type == SwapType::Submarine || liquid_source {
                "source"
            } else {
                "destination"
            },
        );
        let (request, unblinded_transaction) = if liquid_source {
            liquid_source_chain_request(&fixture, amount, exit)
        } else {
            liquid_request(&fixture, swap_type, amount, exit)
        };
        let session = build_session_with_options(
            &fixture,
            swap_type,
            BuildOptions {
                liquid: Some(&request),
                ..BuildOptions::default()
            },
        );
        let legacy = verification_input(&fixture, swap_type);
        let input = LiquidVerifyBeforeFundInput {
            observed_at: legacy.observed_at,
            payment_hash: legacy.payment_hash,
            bitcoin_funding: (swap_type == SwapType::Chain && !liquid_source)
                .then_some(legacy.funding),
            invoice: legacy.invoice,
            timeout_ladder: legacy.timeout_ladder,
            liquid: request.clone(),
        };
        let unblind = |adapter_request: &LiquidUnblindRequest| {
            assert_eq!(adapter_request.network_id, LIQUID_NETWORK);
            Ok(LocalLiquidUnblind {
                authority: LiquidNodeAuthority::LocalElementsd,
                network_id: adapter_request.network_id.clone(),
                pegged_asset: LIQUID_ASSET.to_owned(),
                transaction_sha256: adapter_request.transaction_sha256.clone(),
                output_index: adapter_request.output_index,
                unblinded_transaction: unblinded_transaction.clone(),
            })
        };
        let observe = |node_request: &LiquidNodeRequest| {
            Ok(LocalLiquidNodeObservation {
                authority: LiquidNodeAuthority::LocalElementsd,
                network_id: LIQUID_NETWORK.to_owned(),
                genesis_hash: request.exit_package.genesis_hash.clone(),
                pegged_asset: LIQUID_ASSET.to_owned(),
                observation: LocalLiquidObservation {
                    transaction_id: node_request.transaction_id.clone(),
                    transaction_sha256: node_request.transaction_sha256.clone(),
                    confirmations: u32::from(
                        request.purpose == LiquidLegPurpose::CounterpartyLock
                            && swap_type != SwapType::Chain,
                    ),
                    mempool_accepted: request.purpose == LiquidLegPurpose::RequesterBroadcast
                        || swap_type == SwapType::Chain,
                    replacement_detected: false,
                    competing_spend_detected: false,
                },
            })
        };
        let mut authorized = if swap_type == SwapType::Reverse {
            session.verify_before_fund_with_liquid_and_lightning(
                input,
                unblind,
                observe,
                lightning_ready,
                |_| Ok(()),
            )
        } else {
            session.verify_before_fund_with_liquid(input, unblind, observe, |_| Ok(()))
        }
        .unwrap();
        let binding = authorized
            .funding_request()
            .unwrap()
            .liquid
            .as_ref()
            .unwrap();
        assert!(
            binding
                .request
                .funding
                .trusted_unblind_transaction
                .is_none()
        );
        assert_eq!(binding.provenance.network_id, LIQUID_NETWORK);
        assert_eq!(binding.provenance.pegged_asset, LIQUID_ASSET);
        assert!(binding.provenance.unblinded_transaction_sha256.is_some());
        match (
            swap_type,
            liquid_source,
            &authorized.funding_request().unwrap().action,
        ) {
            (SwapType::Submarine, false, FundingAction::BroadcastLiquid { .. })
            | (SwapType::Reverse, false, FundingAction::PayLightningInvoice { .. })
            | (SwapType::Chain, false, FundingAction::BroadcastBitcoin { .. })
            | (SwapType::Chain, true, FundingAction::BroadcastLiquid { .. }) => {}
            other => panic!("unexpected Liquid requester action: {other:?}"),
        }
        let effect_request =
            ExternalEffectRequest::Funding(authorized.funding_request().unwrap().clone());
        authorized
            .record_external_effect(&effect_request, "local:liquid", "91".repeat(32))
            .unwrap();
        let restored = SwapSession::<AwaitingVerification>::restore(&authorized.persist().unwrap())
            .unwrap()
            .resume_funding_authorized()
            .unwrap();
        assert_eq!(
            restored.funding_request().unwrap(),
            authorized.funding_request().unwrap()
        );
        if swap_type == SwapType::Chain {
            let recovery = restored
                .recovery_action_with(|observation_request| {
                    assert!(observation_request.rail_bindings.iter().any(|binding| {
                        binding.rail == "liquid"
                            && if liquid_source {
                                binding.refund_effect_id.is_some()
                            } else {
                                binding.claim_effect_id.is_some()
                            }
                    }));
                    Ok(LocalRecoveryObservation {
                        session_id: observation_request.session_id.clone(),
                        order_id: observation_request.order_id.clone(),
                        binding_sha256: observation_request.binding_sha256.clone(),
                        current_height: 100,
                        source_funding_confirmation_height: None,
                        counterparty_available: false,
                        completed: false,
                        record_loss: true,
                        rail_state_unknown: false,
                        lightning_state: None,
                        chain_state: None,
                    })
                })
                .unwrap();
            assert_eq!(
                recovery,
                RecoveryAction::ExplicitLoss {
                    code: "swp_unresolved_loss".to_owned()
                }
            );
        }
    }
    assert_eq!(
        liquid_fixture["requester_engine_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vector| vector["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "swp-v1-liquid-requester-submarine-persisted-refund",
            "swp-v1-liquid-requester-reverse-persisted-claim",
            "swp-v1-liquid-requester-btc-liquid-chain-persisted-claim",
            "swp-v1-liquid-requester-liquid-btc-chain-post-order-refund",
            "swp-v1-liquid-requester-source-resolution-tamper",
            "swp-v1-liquid-requester-chain-path-specific-exits",
            "swp-v1-liquid-requester-provenance-tamper",
            "swp-v1-liquid-requester-exit-commitment-tamper",
            "swp-v1-liquid-requester-recovery-binding",
            "swp-v1-liquid-requester-presigned-broadcast-replay",
            "swp-v1-liquid-requester-wallet-broadcast-replay",
            "swp-v1-liquid-wallet-broadcast-crash-retry",
            "swp-v1-liquid-exit-wallet-claim",
            "swp-v1-privacy-post-claim-snapshot",
        ]
    );
}

#[test]
fn liquid_reverse_recovery_restores_signs_and_replays_without_persisting_preimage() {
    let fixture = fixture();
    let (mut authorized, _) = funded_liquid_case(&fixture, SwapType::Reverse, false);
    let snapshot = authorized.persist().unwrap();
    assert!(
        !String::from_utf8_lossy(&snapshot).contains(&lower_hex(&test_released_preimage())),
        "the unreleased Liquid claim preimage must not enter the client snapshot"
    );
    let restored = SwapSession::<AwaitingVerification>::restore(&snapshot)
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    let recovery = restored
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 120,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Paid),
                chain_state: Some(ChainRecoveryState::DestinationClaimable),
            })
        })
        .unwrap();
    let effect_id = match recovery {
        RecoveryAction::RequestWalletClaim { effect_id } => effect_id,
        other => panic!("unexpected Liquid recovery action: {other:?}"),
    };
    let binding = authorized
        .funding_request()
        .unwrap()
        .liquid
        .as_deref()
        .unwrap();
    assert_eq!(
        binding.recovery_package.schema,
        "openagents.mkt-swp.exit.v1"
    );
    assert_eq!(binding.recovery_package.exit.mode, "wallet_sign");
    assert!(binding.recovery_package.exit.signed_transaction.is_none());
    assert_eq!(binding.recovery_package.broadcast.mode, "local_elementsd");
    assert_eq!(
        binding.recovery_package.broadcast.rpc_method,
        "sendrawtransaction"
    );
    assert_eq!(
        binding.recovery_package.broadcast.genesis_hash,
        binding.recovery_package.verification.genesis_hash
    );
    assert_ne!(
        binding.recovery_package.exit.signer_ref,
        binding
            .recovery_package
            .secret_commitments
            .preimage_recovery_ref
    );
    let amount = binding.amount.parse::<u64>().unwrap();
    let funding =
        parse_liquid_transaction(&decode_hex(&binding.request.funding.raw_transaction)).unwrap();
    let signed_transaction =
        liquid_exit_transaction(&funding, LIQUID_CLAIM.output_key, &LIQUID_CLAIM, amount);
    let signing_request = RefCell::new(None);
    let signed = restored
        .sign_liquid_exit_with("destination", "claim", |request| {
            assert_eq!(request.effect_id, effect_id);
            assert_eq!(request.signer_ref, Some("44".repeat(32)));
            assert_eq!(request.preimage_recovery_ref, Some("45".repeat(32)));
            assert_ne!(request.preimage_recovery_ref, request.signer_ref);
            signing_request.replace(Some(request.clone()));
            Ok(signed_transaction.clone())
        })
        .unwrap();
    let ExitSigningOutcome::Signed(signed) = signed else {
        panic!("Liquid claim was not signed")
    };
    let signing_request =
        ExternalEffectRequest::WalletSigning(signing_request.into_inner().unwrap());
    assert_eq!(
        authorized
            .record_external_effect(&signing_request, "wallet:signed", "92".repeat(32))
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    let broadcast = restored
        .liquid_exit_broadcast_request(&signed, "private-wallet-artifact:claim")
        .unwrap();
    assert_eq!(broadcast.rpc_method, "sendrawtransaction");
    assert_eq!(
        broadcast.transaction_sha256,
        lower_hex(&sha256(&signed_transaction))
    );
    let mut crashed = SwapSession::<AwaitingVerification>::restore(&snapshot)
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    let retried = crashed
        .sign_liquid_exit_with("destination", "claim", |_| Ok(signed_transaction.clone()))
        .unwrap();
    let ExitSigningOutcome::Signed(retried) = retried else {
        panic!("crash retry did not reload the retained Liquid claim")
    };
    assert_eq!(retried, signed);
    assert_eq!(
        crashed
            .record_external_effect(
                &ExternalEffectRequest::LiquidBroadcast(broadcast.clone()),
                "unverified:liquid",
                broadcast.transaction_sha256.clone(),
            )
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    crashed
        .record_liquid_broadcast_effect_with(&broadcast, |artifact_ref| {
            assert_eq!(artifact_ref, "private-wallet-artifact:claim");
            Ok(signed_transaction.clone())
        })
        .unwrap();
    assert_eq!(
        liquid_fixture()["requester_engine_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-liquid-wallet-broadcast-crash-retry")
            .and_then(|vector| vector["expected"].as_str()),
        Some("load_exact_private_artifact_without_resigning")
    );
    let completed_snapshot = crashed.persist().unwrap();
    let completed_snapshot_text = String::from_utf8_lossy(&completed_snapshot);
    assert!(!completed_snapshot_text.contains(&lower_hex(&test_released_preimage())));
    assert!(!completed_snapshot_text.contains(&lower_hex(&signed_transaction)));
    assert!(completed_snapshot_text.contains("private-wallet-artifact:claim"));
    let replayed = SwapSession::<AwaitingVerification>::restore(&completed_snapshot)
        .unwrap()
        .resume_funding_authorized()
        .unwrap()
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 120,
                source_funding_confirmation_height: None,
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::Paid),
                chain_state: Some(ChainRecoveryState::DestinationClaimable),
            })
        })
        .unwrap();
    assert!(matches!(
        replayed,
        RecoveryAction::AlreadyExecuted {
            effect_id: replayed_effect_id,
            ..
        } if replayed_effect_id == effect_id
    ));
    let engine_fixture = liquid_fixture();
    let expected = engine_fixture["requester_engine_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "swp-v1-liquid-requester-wallet-broadcast-replay")
        .and_then(|vector| vector["expected"].as_str())
        .unwrap();
    assert_eq!(expected, "sign_then_local_elementsd_exact_once");
}

#[test]
fn liquid_submarine_recovery_restores_the_exact_presigned_refund() {
    let fixture = fixture();
    let (mut authorized, _) = funded_liquid_case(&fixture, SwapType::Submarine, false);
    let restored = SwapSession::<AwaitingVerification>::restore(&authorized.persist().unwrap())
        .unwrap()
        .resume_funding_authorized()
        .unwrap();
    let recovery = restored
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 200,
                source_funding_confirmation_height: Some(100),
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: None,
            })
        })
        .unwrap();
    let effect_id = match recovery {
        RecoveryAction::BroadcastPresigned { effect_id } => effect_id,
        other => panic!("unexpected Liquid refund action: {other:?}"),
    };
    let refund = restored.liquid_presigned_exit("source", "refund").unwrap();
    assert_eq!(refund.effect_id, effect_id);
    assert_eq!(
        refund.transaction,
        restored
            .funding_request()
            .unwrap()
            .liquid
            .as_deref()
            .unwrap()
            .request
            .exit_package
            .transaction
    );
    let broadcast = restored
        .liquid_presigned_broadcast_request("source", "refund")
        .unwrap();
    assert_eq!(broadcast.effect_id, effect_id);
    assert_eq!(broadcast.path, "refund");
    assert_eq!(broadcast.rpc_method, "sendrawtransaction");
    assert_eq!(
        broadcast.transaction_sha256,
        lower_hex(&sha256(&decode_hex(&refund.transaction)))
    );
    assert_eq!(
        broadcast.transaction_artifact_ref,
        format!("exit-package:{effect_id}")
    );
    let mut changed = broadcast.clone();
    changed.transaction_artifact_ref.clear();
    assert_eq!(
        authorized
            .record_liquid_broadcast_effect_with(&changed, |_| {
                Ok(decode_hex(&refund.transaction))
            })
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    authorized
        .record_liquid_broadcast_effect_with(&broadcast, |_| Ok(decode_hex(&refund.transaction)))
        .unwrap();
    let replayed = SwapSession::<AwaitingVerification>::restore(&authorized.persist().unwrap())
        .unwrap()
        .resume_funding_authorized()
        .unwrap()
        .recovery_action_with(|request| {
            Ok(LocalRecoveryObservation {
                session_id: request.session_id.clone(),
                order_id: request.order_id.clone(),
                binding_sha256: request.binding_sha256.clone(),
                current_height: 200,
                source_funding_confirmation_height: Some(100),
                counterparty_available: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                lightning_state: Some(LightningRecoveryState::UnpaidFinal),
                chain_state: None,
            })
        })
        .unwrap();
    assert!(matches!(
        replayed,
        RecoveryAction::AlreadyExecuted {
            effect_id: replayed_effect_id,
            ..
        } if replayed_effect_id == effect_id
    ));
}

#[test]
fn liquid_terminal_close_evidence_covers_all_swap_directions_and_refunds() {
    let fixture = fixture();
    let terminal_fixture = liquid_fixture();
    let vectors = terminal_fixture["terminal_evidence_vectors"]["positive"]
        .as_array()
        .expect("Liquid terminal positive vectors");
    assert_eq!(vectors.len(), 8);
    for (case_index, vector) in vectors.iter().enumerate() {
        let swap_type = match vector["swap_type"].as_str().expect("swap type") {
            "submarine" => SwapType::Submarine,
            "reverse" => SwapType::Reverse,
            "chain" => SwapType::Chain,
            value => panic!("unexpected Liquid terminal swap type {value}"),
        };
        let liquid_source =
            vector.get("direction").and_then(Value::as_str) == Some("liquid_to_btc");
        let outcome = vector["outcome"].as_str().expect("terminal outcome");
        let liquid_leg = vector["liquid_leg"].as_str().expect("Liquid leg");
        let (mut session, terms) = funded_liquid_case(&fixture, swap_type, liquid_source);
        let setup = Setup::new(&fixture);
        let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
        let order_id = session.funding_request().unwrap().order_id.clone();
        let leg_ids = terms["legs"]
            .as_array()
            .expect("terminal legs")
            .iter()
            .map(|leg| leg["leg_id"].as_str().expect("terminal leg ID").to_owned())
            .collect::<Vec<_>>();
        let mut evidence_refs = Vec::with_capacity(leg_ids.len());
        for (leg_index, leg_id) in leg_ids.iter().enumerate() {
            let funding_artifact =
                verifier_inputs_for(&terms, leg_id)["funding_transaction_sha256"]
                    .as_str()
                    .map(str::to_owned);
            let verified = session
                .verify_terminal_rail_evidence_with(leg_id, outcome, |request| {
                    if leg_id == liquid_leg {
                        assert_eq!(request.evidence_class, vector["class"]);
                        assert_eq!(request.rung, vector["rung"]);
                        assert_eq!(request.finality_state, vector["finality_state"]);
                    }
                    if request.evidence_class == "reservation" {
                        let unfunded = request
                            .unfunded_destination
                            .as_ref()
                            .expect("unfunded destination observation identities");
                        assert_eq!(unfunded.reservation_id, request.reference);
                        assert_ne!(unfunded.contracted_outpoint, request.reference);
                        assert_eq!(unfunded.contracted_outpoint.split(':').count(), 2);
                        assert_eq!(
                            unfunded.destination_broadcast_status_state,
                            "provider_destination_broadcast"
                        );
                        assert_eq!(
                            unfunded.destination_funding_effect_id,
                            provider_support::effect_id(&order_id, "chain_fund", "destination",)
                                .unwrap()
                        );
                    } else {
                        assert!(request.unfunded_destination.is_none());
                    }
                    let artifact_sha256 = if matches!(
                        request.evidence_class.as_str(),
                        "bitcoin_output" | "liquid_output"
                    ) {
                        funding_artifact
                            .clone()
                            .expect("terminal output funding artifact")
                    } else {
                        format!("{:02x}", 160 + case_index * 2 + leg_index).repeat(32)
                    };
                    Ok(LocalRailEvidence {
                        artifact_sha256,
                        observed_at: 800,
                        view: format!("fixture {} {} {outcome}", request.rail, request.leg_id),
                        settlement_reference: request.reference.clone(),
                        verifier_pubkey: None,
                        producer_pubkey: setup.requester.pubkey().to_owned(),
                        external_identifier: format!(
                            "fixture:{}:{outcome}:{}",
                            vector["name"].as_str().expect("case name"),
                            request.leg_id
                        ),
                    })
                })
                .unwrap_or_else(|error| {
                    panic!(
                        "{} terminal evidence failed: {error}",
                        vector["name"].as_str().expect("case name")
                    )
                });
            evidence_refs.push(verified.evidence_reference().clone());
            session.record_verified_rail_evidence(verified).unwrap();
        }
        session = SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap())
            .unwrap()
            .resume_funding_authorized()
            .unwrap();
        let status = signed(
            factory
                .status(
                    ParticipantRole::Requester,
                    900,
                    &format!("{:02x}", 176 + case_index).repeat(32),
                    &order_id,
                    StatusState {
                        sequence: 0,
                        previous: None,
                        base_state: outcome,
                        swp_state: outcome,
                    },
                    Default::default(),
                )
                .unwrap(),
            &setup.requester,
        );
        session.ingest_signed_record(status.clone()).unwrap();
        let mut loss = empty_loss_accounting(&terms);
        loss["input_committed"] = terms["input_amount"].clone();
        loss["evidence_refs"] = Value::Array(evidence_refs);
        if outcome == "completed" {
            loss["output_received"] = terms["output_amount"].clone();
        } else {
            loss["input_recovered"] = terms["input_amount"].clone();
        }
        let close = signed(
            factory
                .close(
                    ParticipantRole::Requester,
                    910,
                    &format!("{:02x}", 192 + case_index).repeat(32),
                    &order_id,
                    CloseOutcome {
                        outcome,
                        terminal_at: 910,
                    },
                    json!({"status_id":status.id,"loss_accounting":loss}),
                )
                .unwrap(),
            &setup.requester,
        );
        session.ingest_signed_record(close).unwrap_or_else(|error| {
            panic!(
                "{} terminal Close failed: {error}",
                vector["name"].as_str().expect("case name")
            )
        });
        SwapSession::<AwaitingVerification>::restore(&session.persist().unwrap()).unwrap();
    }
}

#[test]
fn liquid_terminal_evidence_rejects_artifact_outpoint_release_and_replay_mutations() {
    let fixture = fixture();
    let terminal_fixture = liquid_fixture();
    let expected = |name: &str| {
        terminal_fixture["terminal_evidence_vectors"]["negative"]
            .as_array()
            .expect("Liquid terminal negative vectors")
            .iter()
            .find(|vector| vector["name"] == name)
            .and_then(|vector| vector["expected"].as_str())
            .expect("Liquid terminal negative expectation")
    };

    let (submarine, terms) = funded_liquid_case(&fixture, SwapType::Submarine, false);
    let funding_artifact = verifier_inputs_for(&terms, "source")["funding_transaction_sha256"]
        .as_str()
        .expect("Liquid funding artifact")
        .to_owned();
    assert_eq!(
        submarine
            .verify_terminal_rail_evidence_with("source", "completed", |request| {
                Ok(terminal_observation(
                    &fixture,
                    request,
                    funding_artifact.clone(),
                    request.reference.clone(),
                ))
            })
            .unwrap_err()
            .code,
        expected("swp-v1-negative-liquid-terminal-spend-reuses-funding")
    );

    let (reverse, _) = funded_liquid_case(&fixture, SwapType::Reverse, false);
    assert_eq!(
        reverse
            .verify_terminal_rail_evidence_with("destination", "completed", |request| {
                Ok(terminal_observation(
                    &fixture,
                    request,
                    "a1".repeat(32),
                    format!("{}:1", "b1".repeat(32)),
                ))
            })
            .unwrap_err()
            .code,
        expected("swp-v1-negative-liquid-terminal-spend-outpoint")
    );

    let (bitcoin_liquid, _) = funded_liquid_case(&fixture, SwapType::Chain, false);
    assert_eq!(
        bitcoin_liquid
            .verify_terminal_rail_evidence_with("destination", "completed", |request| {
                Ok(terminal_observation(
                    &fixture,
                    request,
                    "a2".repeat(32),
                    request.reference.clone(),
                ))
            })
            .unwrap_err()
            .code,
        expected("swp-v1-negative-liquid-terminal-output-artifact")
    );

    let (liquid_bitcoin, _) = funded_liquid_case(&fixture, SwapType::Chain, true);
    assert_eq!(
        liquid_bitcoin
            .verify_terminal_rail_evidence_with("destination", "refunded", |request| {
                Ok(terminal_observation(
                    &fixture,
                    request,
                    "a3".repeat(32),
                    "changed-reservation".to_owned(),
                ))
            })
            .unwrap_err()
            .code,
        expected("swp-v1-negative-liquid-terminal-unfunded-release")
    );

    let (mut persisted, _) = funded_liquid_case(&fixture, SwapType::Submarine, false);
    let verified = persisted
        .verify_terminal_rail_evidence_with("source", "completed", |request| {
            Ok(terminal_observation(
                &fixture,
                request,
                "a4".repeat(32),
                request.reference.clone(),
            ))
        })
        .unwrap();
    persisted.record_verified_rail_evidence(verified).unwrap();
    let mut snapshot: Value = serde_json::from_slice(&persisted.persist().unwrap()).unwrap();
    let rail_effect = snapshot["external_effects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|effect| {
            effect["effect_id"].as_str().is_some_and(|effect_id| {
                effect_id != persisted.funding_request().unwrap().action.effect_id()
            })
        })
        .expect("persisted Liquid rail effect");
    rail_effect["result_sha256"] = json!("ff".repeat(32));
    assert_eq!(
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&snapshot).unwrap())
            .unwrap_err()
            .code,
        expected("swp-v1-negative-liquid-terminal-persisted-result")
    );
}

#[test]
fn requester_contract_draft_resolves_liquid_sources_after_order() {
    let fixture = fixture();
    let setup = Setup::new(&fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let (submarine, _) = liquid_request(
        &fixture,
        SwapType::Submarine,
        bitcoin_leg_amount(SwapType::Submarine, "source"),
        &LIQUID_REFUND,
    );
    let (chain, _) = liquid_source_chain_request(
        &fixture,
        bitcoin_leg_amount(SwapType::Chain, "source"),
        &LIQUID_REFUND,
    );
    for (swap_type, request) in [(SwapType::Submarine, submarine), (SwapType::Chain, chain)] {
        let session = build_session_with_options(
            &fixture,
            swap_type,
            BuildOptions {
                liquid: Some(&request),
                ..BuildOptions::default()
            },
        );
        let records = session.signed_records();
        let rfq = records.iter().find(|event| event.kind == 39_604).unwrap();
        let quote = records.iter().find(|event| event.kind == 39_605).unwrap();
        let order = records.iter().find(|event| event.kind == 39_606).unwrap();
        let quote: Value = serde_json::from_str(&quote.content).unwrap();
        let quote_source = verifier_inputs_for(&quote["mkt_swp"]["terms"], "source");
        for member in [
            "funding_transaction",
            "funding_transaction_sha256",
            "output_index",
        ] {
            assert!(quote_source.get(member).is_none(), "{swap_type:?} {member}");
        }
        let quote = records.iter().find(|event| event.kind == 39_605).unwrap();
        let accepted_contract = contract_document(&session);
        let local_inputs = RequesterContractLocalInputs {
            effect_bindings: serde_json::from_value(accepted_contract["effect_bindings"].clone())
                .unwrap(),
            exit_package_commitments: serde_json::from_value(
                accepted_contract["exit_package_commitments"].clone(),
            )
            .unwrap(),
            funding_resolution: Some(RequesterFundingResolution {
                leg_id: "source".to_owned(),
                funding_transaction: request.funding.raw_transaction.clone(),
                funding_transaction_sha256: request.funding.transaction_sha256.clone(),
                output_index: request.funding.output_index,
            }),
        };
        let draft = factory
            .requester_contract_draft(rfq, quote, order, order.created_at, local_inputs.clone())
            .expect("Liquid source resolution must compose through the public requester API");
        assert_eq!(draft, accepted_contract);

        let mut tampered = local_inputs;
        tampered
            .funding_resolution
            .as_mut()
            .unwrap()
            .funding_transaction_sha256 = "ff".repeat(32);
        assert_eq!(
            factory
                .requester_contract_draft(rfq, quote, order, order.created_at, tampered)
                .unwrap_err()
                .code,
            "swp_contract_terms_mismatch"
        );
    }
}

#[test]
fn liquid_requester_snapshot_rejects_provenance_and_exit_tampering() {
    let fixture = fixture();
    let (request, unblinded_transaction) =
        liquid_request(&fixture, SwapType::Submarine, 100_000, &LIQUID_REFUND);
    let session = build_session_with_options(
        &fixture,
        SwapType::Submarine,
        BuildOptions {
            liquid: Some(&request),
            ..BuildOptions::default()
        },
    );
    let taproot_tree =
        verifier_inputs_for(&contract_document(&session), "source")["taproot_tree"].clone();
    let legacy = verification_input(&fixture, SwapType::Submarine);
    let authorized = session
        .verify_before_fund_with_liquid(
            LiquidVerifyBeforeFundInput {
                observed_at: legacy.observed_at,
                payment_hash: legacy.payment_hash,
                bitcoin_funding: None,
                invoice: legacy.invoice,
                timeout_ladder: legacy.timeout_ladder,
                liquid: request.clone(),
            },
            |adapter_request| {
                Ok(LocalLiquidUnblind {
                    authority: LiquidNodeAuthority::LocalElementsd,
                    network_id: adapter_request.network_id.clone(),
                    pegged_asset: LIQUID_ASSET.to_owned(),
                    transaction_sha256: adapter_request.transaction_sha256.clone(),
                    output_index: adapter_request.output_index,
                    unblinded_transaction: unblinded_transaction.clone(),
                })
            },
            |node_request| {
                Ok(LocalLiquidNodeObservation {
                    authority: LiquidNodeAuthority::LocalElementsd,
                    network_id: LIQUID_NETWORK.to_owned(),
                    genesis_hash: request.exit_package.genesis_hash.clone(),
                    pegged_asset: LIQUID_ASSET.to_owned(),
                    observation: LocalLiquidObservation {
                        transaction_id: node_request.transaction_id.clone(),
                        transaction_sha256: node_request.transaction_sha256.clone(),
                        confirmations: 0,
                        mempool_accepted: true,
                        replacement_detected: false,
                        competing_spend_detected: false,
                    },
                })
            },
            |_| Ok(()),
        )
        .unwrap();
    let snapshot = authorized.persist().unwrap();
    let mut provenance: Value = serde_json::from_slice(&snapshot).unwrap();
    provenance["funding_request"]["liquid"]["provenance"]["pegged_asset"] = json!("22".repeat(32));
    assert_eq!(
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&provenance).unwrap())
            .unwrap_err()
            .code,
        "swp_external_effect_conflict"
    );
    let mut exit: Value = serde_json::from_slice(&snapshot).unwrap();
    exit["funding_request"]["liquid"]["request"]["exit_package"]["transaction_sha256"] =
        json!("ff".repeat(32));
    assert_eq!(
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&exit).unwrap())
            .unwrap_err()
            .code,
        "swp_exit_package_mismatch"
    );
    let mut invalid_shape: Value = serde_json::from_slice(&snapshot).unwrap();
    invalid_shape["funding_request"]["liquid"]["recovery_package"]["verification"]
        .as_object_mut()
        .unwrap()
        .remove("swap_tree_sha256");
    let error =
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&invalid_shape).unwrap())
            .unwrap_err()
            .code;
    assert_eq!(error, "swp_exit_package_unusable");
    assert_eq!(
        liquid_fixture()["client_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-negative-liquid-exit-schema")
            .and_then(|vector| vector["expected"].as_str()),
        Some(error)
    );
    let mut optional_tree: Value = serde_json::from_slice(&snapshot).unwrap();
    optional_tree["funding_request"]["liquid"]["recovery_package"]["verification"]["taproot_tree"] =
        taproot_tree;
    SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&optional_tree).unwrap())
        .unwrap();
    assert_eq!(
        liquid_fixture()["client_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-liquid-exit-optional-taproot-tree")
            .and_then(|vector| vector["expected"].as_str()),
        Some("restored")
    );
    let mut unknown_member: Value = serde_json::from_slice(&snapshot).unwrap();
    unknown_member["funding_request"]["liquid"]["recovery_package"]["verification"]["unknown_member"] =
        json!(true);
    let error =
        SwapSession::<AwaitingVerification>::restore(&serde_json::to_vec(&unknown_member).unwrap())
            .unwrap_err()
            .code;
    assert_eq!(error, "swp_exit_package_unusable");
    assert_eq!(
        liquid_fixture()["client_vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "swp-v1-negative-liquid-exit-unknown-member")
            .and_then(|vector| vector["expected"].as_str()),
        Some(error)
    );
}

fn liquid_request(
    fixture: &Value,
    swap_type: SwapType,
    amount: u64,
    exit: &LiquidExitPath,
) -> (LiquidBeforeFundRequest, String) {
    let liquid_asset = format!("swp:1:{LIQUID_NETWORK}:elements:{LIQUID_ASSET}:liquid");
    let (input_asset_id, output_asset_id, purpose, liquid_swap_type) = match swap_type {
        SwapType::Submarine => (
            liquid_asset.clone(),
            fixture_string(fixture, "lightning_asset_a"),
            LiquidLegPurpose::RequesterBroadcast,
            LiquidSwapType::Submarine,
        ),
        SwapType::Reverse => (
            fixture_string(fixture, "lightning_asset_a"),
            liquid_asset.clone(),
            LiquidLegPurpose::CounterpartyLock,
            LiquidSwapType::Reverse,
        ),
        SwapType::Chain => (
            fixture_string(fixture, "chain_asset_a"),
            liquid_asset.clone(),
            LiquidLegPurpose::CounterpartyLock,
            LiquidSwapType::Chain,
        ),
    };
    let vector = &liquid_fixture()["parser_vectors"][0];
    let replace_key = |value: &str| {
        value.replace(
            &format!("5120{LIQUID_ORIGINAL_OUTPUT_KEY}"),
            &format!("5120{}", exit.output_key),
        )
    };
    let funding_transaction = replace_key(vector["raw_transaction"].as_str().unwrap());
    let unblinded_transaction = replace_key(vector["trusted_local_unblind"].as_str().unwrap())
        .replacen("00000000000186a0", &format!("{amount:016x}"), 1);
    let funding_raw = decode_hex(&funding_transaction);
    let funding = parse_liquid_transaction(&funding_raw).unwrap();
    let exit_transaction = if exit.path == "claim" {
        serialize_liquid_exit_transaction(
            funding.transaction_id,
            exit.output_key,
            exit,
            amount,
            None,
        )
    } else {
        liquid_exit_transaction(&funding, exit.output_key, exit, amount)
    };
    (
        LiquidBeforeFundRequest {
            swap_type: liquid_swap_type,
            purpose,
            input_asset_id,
            output_asset_id,
            funding: LiquidFundingVerificationInput {
                raw_transaction: funding_transaction,
                trusted_unblind_transaction: None,
                transaction_sha256: lower_hex(&sha256(&funding_raw)),
                output_index: 0,
                asset_id: liquid_asset.clone(),
                amount: amount.to_string(),
                script_pubkey: format!("5120{}", exit.output_key),
                taproot_internal_key: LIQUID_INTERNAL_KEY.to_owned(),
                taproot_merkle_root: Some(exit.merkle_root.to_owned()),
                confidentiality: LiquidConfidentiality::Confidential,
                minimum_confirmations: 1,
                replacement_policy: "reject".to_owned(),
            },
            exit_package: LiquidUnilateralExitPackage {
                schema: "openagents.mkt-swp.liquid-exit.v1".to_owned(),
                network_id: LIQUID_NETWORK.to_owned(),
                genesis_hash: liquid_fixture()["network"]["genesis_hash"]
                    .as_str()
                    .expect("Liquid fixture genesis hash")
                    .to_owned(),
                asset_id: liquid_asset,
                funding_transaction_id: lower_hex(&funding.transaction_id),
                funding_output_index: 0,
                funding_amount: amount.to_string(),
                funding_script_pubkey: format!("5120{}", exit.output_key),
                path: exit.path.to_owned(),
                script: exit.script.to_owned(),
                control_block: exit.control_block.to_owned(),
                timelock: exit.timelock,
                spend_input_index: 0,
                fee_output_index: 1,
                fee_amount: "50".to_owned(),
                transaction_sha256: lower_hex(&sha256(&exit_transaction)),
                transaction: lower_hex(&exit_transaction),
                mode: if exit.path == "claim" {
                    LiquidExitMode::Wallet
                } else {
                    LiquidExitMode::Presigned
                },
                wallet_signing_handle_sha256: (exit.path == "claim").then(|| "44".repeat(32)),
                preimage_recovery_ref: (exit.path == "claim").then(|| "45".repeat(32)),
            },
        },
        unblinded_transaction,
    )
}

fn liquid_source_chain_request(
    fixture: &Value,
    amount: u64,
    exit: &LiquidExitPath,
) -> (LiquidBeforeFundRequest, String) {
    let (mut request, unblinded) = liquid_request(fixture, SwapType::Submarine, amount, exit);
    request.swap_type = LiquidSwapType::Chain;
    request.output_asset_id = fixture_string(fixture, "chain_asset_b");
    (request, unblinded)
}

fn funded_liquid_case(
    fixture: &Value,
    swap_type: SwapType,
    liquid_source: bool,
) -> (SwapSession<FundingAuthorized>, Value) {
    let exit = if swap_type == SwapType::Submarine || liquid_source {
        &LIQUID_REFUND
    } else {
        &LIQUID_CLAIM
    };
    let leg_id = if swap_type == SwapType::Submarine || liquid_source {
        "source"
    } else {
        "destination"
    };
    let amount = bitcoin_leg_amount(swap_type, leg_id);
    let (request, unblinded_transaction) = if liquid_source {
        liquid_source_chain_request(fixture, amount, exit)
    } else {
        liquid_request(fixture, swap_type, amount, exit)
    };
    let session = build_session_with_options(
        fixture,
        swap_type,
        BuildOptions {
            liquid: Some(&request),
            ..BuildOptions::default()
        },
    );
    let legacy = verification_input(fixture, swap_type);
    let input = LiquidVerifyBeforeFundInput {
        observed_at: legacy.observed_at,
        payment_hash: legacy.payment_hash,
        bitcoin_funding: (swap_type == SwapType::Chain && !liquid_source).then_some(legacy.funding),
        invoice: legacy.invoice,
        timeout_ladder: legacy.timeout_ladder,
        liquid: request.clone(),
    };
    let unblind = |adapter_request: &LiquidUnblindRequest| {
        Ok(LocalLiquidUnblind {
            authority: LiquidNodeAuthority::LocalElementsd,
            network_id: adapter_request.network_id.clone(),
            pegged_asset: LIQUID_ASSET.to_owned(),
            transaction_sha256: adapter_request.transaction_sha256.clone(),
            output_index: adapter_request.output_index,
            unblinded_transaction: unblinded_transaction.clone(),
        })
    };
    let observe = |node_request: &LiquidNodeRequest| {
        Ok(LocalLiquidNodeObservation {
            authority: LiquidNodeAuthority::LocalElementsd,
            network_id: LIQUID_NETWORK.to_owned(),
            genesis_hash: request.exit_package.genesis_hash.clone(),
            pegged_asset: LIQUID_ASSET.to_owned(),
            observation: LocalLiquidObservation {
                transaction_id: node_request.transaction_id.clone(),
                transaction_sha256: node_request.transaction_sha256.clone(),
                confirmations: u32::from(
                    request.purpose == LiquidLegPurpose::CounterpartyLock
                        && swap_type != SwapType::Chain,
                ),
                mempool_accepted: request.purpose == LiquidLegPurpose::RequesterBroadcast
                    || swap_type == SwapType::Chain,
                replacement_detected: false,
                competing_spend_detected: false,
            },
        })
    };
    let mut authorized = if swap_type == SwapType::Reverse {
        session.verify_before_fund_with_liquid_and_lightning(
            input,
            unblind,
            observe,
            lightning_ready,
            |_| Ok(()),
        )
    } else {
        session.verify_before_fund_with_liquid(input, unblind, observe, |_| Ok(()))
    }
    .expect("Liquid terminal fixture authorizes funding");
    let funding = ExternalEffectRequest::Funding(
        authorized
            .funding_request()
            .expect("Liquid terminal funding request")
            .clone(),
    );
    authorized
        .record_external_effect(&funding, "fixture:liquid:funding", "91".repeat(32))
        .expect("Liquid terminal funding effect");
    let mut terms = base_terms(fixture, swap_type);
    apply_liquid_terms(&mut terms, &request);
    (authorized, terms)
}

fn terminal_observation(
    fixture: &Value,
    request: &immortal_client::mkt_swp_client::RailObservationRequest,
    artifact_sha256: String,
    settlement_reference: String,
) -> LocalRailEvidence {
    LocalRailEvidence {
        artifact_sha256,
        observed_at: 800,
        view: format!("fixture terminal {} view", request.rail),
        settlement_reference,
        verifier_pubkey: None,
        producer_pubkey: Setup::new(fixture).requester.pubkey().to_owned(),
        external_identifier: format!("fixture:terminal:{}:{}", request.rail, request.leg_id),
    }
}

fn liquid_exit_transaction(
    funding: &LiquidTransaction,
    destination_key: &str,
    exit: &LiquidExitPath,
    amount: u64,
) -> Vec<u8> {
    let unsigned = serialize_liquid_exit_transaction(
        funding.transaction_id,
        destination_key,
        exit,
        amount,
        None,
    );
    let transaction = parse_liquid_transaction(&unsigned).expect("unsigned Liquid exit");
    let funding_output = funding.outputs.first().expect("Liquid funding output");
    let prevout = LiquidPrevout {
        asset: funding_output.asset.clone(),
        value: funding_output.value.clone(),
        script_pubkey: funding_output.script_pubkey.clone(),
    };
    let script = decode_hex(exit.script);
    let control_block = decode_hex(exit.control_block);
    let fixture = liquid_fixture();
    let genesis_hash = LiquidGenesisHash::parse_display(
        fixture["network"]["genesis_hash"]
            .as_str()
            .expect("Liquid fixture genesis hash"),
    )
    .expect("Liquid genesis hash");
    let sighash = liquid_taproot_script_spend_sighash(
        &transaction,
        &[prevout],
        0,
        genesis_hash,
        &script,
        &control_block,
        None,
    )
    .expect("Liquid exit sighash");
    let signer_label = if exit.path == "claim" {
        b"exit:destination:claim".as_slice()
    } else {
        b"exit:source:refund".as_slice()
    };
    let secret = SecretKey::from_byte_array(test_signing_key(signer_label))
        .expect("Liquid exit signing key");
    let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
    let signature = sign_liquid_taproot_sighash(sighash, &keypair);
    serialize_liquid_exit_transaction(
        funding.transaction_id,
        destination_key,
        exit,
        amount,
        Some(signature),
    )
}

fn serialize_liquid_exit_transaction(
    funding_transaction_id: [u8; 32],
    destination_key: &str,
    exit: &LiquidExitPath,
    amount: u64,
    signature: Option<[u8; 64]>,
) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&2_i32.to_le_bytes());
    raw.push(u8::from(signature.is_some()));
    raw.push(1);
    let mut wire_transaction_id = funding_transaction_id;
    wire_transaction_id.reverse();
    raw.extend_from_slice(&wire_transaction_id);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0);
    raw.extend_from_slice(
        &if exit.path == "refund" {
            0xffff_fffe_u32
        } else {
            u32::MAX
        }
        .to_le_bytes(),
    );
    raw.push(2);
    push_liquid_explicit_output(
        &mut raw,
        amount.checked_sub(50).unwrap(),
        &decode_hex(&format!("5120{destination_key}")),
    );
    push_liquid_explicit_output(&mut raw, 50, &[]);
    raw.extend_from_slice(&exit.timelock.to_le_bytes());
    if let Some(signature) = signature {
        raw.push(0);
        raw.push(0);
        raw.push(if exit.path == "claim" { 4 } else { 3 });
        push_liquid_bytes(&mut raw, &signature);
        if exit.path == "claim" {
            push_liquid_bytes(&mut raw, &test_released_preimage());
        }
        push_liquid_bytes(&mut raw, &decode_hex(exit.script));
        push_liquid_bytes(&mut raw, &decode_hex(exit.control_block));
        raw.push(0);
        for _ in 0..2 {
            raw.push(0);
            raw.push(0);
        }
    }
    raw
}

fn push_liquid_explicit_output(raw: &mut Vec<u8>, amount: u64, script_pubkey: &[u8]) {
    raw.push(1);
    raw.extend_from_slice(&[0x11; 32]);
    raw.push(1);
    raw.extend_from_slice(&amount.to_be_bytes());
    raw.push(0);
    push_liquid_bytes(raw, script_pubkey);
}

fn push_liquid_bytes(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.push(u8::try_from(bytes.len()).unwrap());
    raw.extend_from_slice(bytes);
}

fn liquid_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/liquid-rail-v1.json"
    ))
    .unwrap()
}

fn liquid_client_vector_expected<'a>(fixture: &'a Value, name: &str) -> &'a str {
    fixture["client_vectors"]
        .as_array()
        .expect("Liquid client vectors")
        .iter()
        .find(|case| case["name"] == name)
        .and_then(|case| case["expected"].as_str())
        .expect("Liquid client vector expected error")
}

fn build_session(
    fixture: &Value,
    swap_type: SwapType,
    include_exit: bool,
) -> SwapSession<AwaitingVerification> {
    build_session_with_options(
        fixture,
        swap_type,
        BuildOptions {
            include_exit,
            ..BuildOptions::default()
        },
    )
}

fn build_session_mode(
    fixture: &Value,
    swap_type: SwapType,
    exit_mode: Option<&str>,
) -> SwapSession<AwaitingVerification> {
    build_session_with_options(
        fixture,
        swap_type,
        BuildOptions {
            include_exit: exit_mode.is_some(),
            exit_mode,
            ..BuildOptions::default()
        },
    )
}

#[derive(Clone, Copy)]
struct BuildOptions<'a> {
    include_exit: bool,
    exit_mode: Option<&'a str>,
    quote_expiration: u64,
    order_created_at: u64,
    quote_selectable: Option<&'a Value>,
    order_selection: Option<&'a Value>,
    contract_selection: Option<&'a Value>,
    null_funding_transaction_id: bool,
    funding_resolution: Option<FundingResolutionMutation>,
    provider_cooperative_exit: bool,
    path_specific_exit_tamper: bool,
    liquid: Option<&'a LiquidBeforeFundRequest>,
}

impl Default for BuildOptions<'_> {
    fn default() -> Self {
        Self {
            include_exit: true,
            exit_mode: None,
            quote_expiration: 1_000,
            order_created_at: 102,
            quote_selectable: None,
            order_selection: None,
            contract_selection: None,
            null_funding_transaction_id: false,
            funding_resolution: None,
            provider_cooperative_exit: false,
            path_specific_exit_tamper: false,
            liquid: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FundingResolutionMutation {
    Valid,
    ExtraField,
    WrongHash,
    WrongIndex,
    WrongScript,
    WrongAmount,
    WrongDigest,
    WrongSwap,
    WrongLeg,
}

impl FundingResolutionMutation {
    fn from_fixture_name(name: &str) -> Self {
        match name {
            "extra_field" => Self::ExtraField,
            "wrong_hash" => Self::WrongHash,
            "wrong_index" => Self::WrongIndex,
            "wrong_script" => Self::WrongScript,
            "wrong_amount" => Self::WrongAmount,
            "wrong_digest" => Self::WrongDigest,
            "wrong_swap" => Self::WrongSwap,
            "wrong_leg" => Self::WrongLeg,
            _ => panic!("unknown funding-resolution mutation {name}"),
        }
    }
}

#[derive(Clone, Copy)]
struct ExitSpec {
    leg_id: &'static str,
    path: &'static str,
    condition: &'static str,
    mode: &'static str,
}

fn flow_exit_specs(swap_type: SwapType) -> &'static [ExitSpec] {
    match swap_type {
        SwapType::Submarine => &[ExitSpec {
            leg_id: "source",
            path: "refund",
            condition: "cltv",
            mode: "presigned",
        }],
        SwapType::Reverse => &[ExitSpec {
            leg_id: "destination",
            path: "claim",
            condition: "hashlock",
            mode: "wallet_sign",
        }],
        SwapType::Chain => &[
            ExitSpec {
                leg_id: "source",
                path: "refund",
                condition: "cltv",
                mode: "presigned",
            },
            ExitSpec {
                leg_id: "destination",
                path: "claim",
                condition: "hashlock",
                mode: "wallet_sign",
            },
        ],
    }
}

fn build_session_with_options(
    fixture: &Value,
    swap_type: SwapType,
    options: BuildOptions<'_>,
) -> SwapSession<AwaitingVerification> {
    try_build_session_with_options(fixture, swap_type, options).unwrap()
}

fn try_build_session_with_options(
    fixture: &Value,
    swap_type: SwapType,
    options: BuildOptions<'_>,
) -> Result<SwapSession<AwaitingVerification>, immortal_client::mkt_swp_client::SwapClientError> {
    let setup = Setup::new(fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let mut terms = base_terms(fixture, swap_type);
    if let Some(request) = options.liquid {
        apply_liquid_terms(&mut terms, request);
        if request.purpose == LiquidLegPurpose::RequesterBroadcast {
            omit_quote_funding_resolution(&mut terms, "source");
        }
    }
    if options.provider_cooperative_exit {
        enable_provider_cooperative_exit(fixture, &mut terms);
    }
    if options.path_specific_exit_tamper {
        tamper_path_specific_exit(&mut terms);
    }
    if options
        .funding_resolution
        .is_some_and(|mutation| mutation != FundingResolutionMutation::WrongLeg)
    {
        let leg_id = if swap_type == SwapType::Reverse {
            "destination"
        } else {
            "source"
        };
        omit_quote_funding_resolution(&mut terms, leg_id);
    }
    let rfq = signed(
        factory
            .rfq(
                100,
                &"11".repeat(32),
                1_000,
                json!({
                    "constraints": {
                        "swap_type": terms["swap_type"],
                        "asset_pair": terms["asset_pair"],
                        "input_amount": terms["input_amount"],
                        "maximum_total_fee": terms["maximum_total_fee"],
                        "confirmation_policy": terms["confirmation_policy"],
                        "allowed_script_modes": ["taproot-musig2-script-exit"],
                        "desired_completion_time": terms["desired_completion_time"],
                        "firm_quote_required": true,
                        "payment_hash": terms["payment_hash"],
                        "invoice_sha256": if swap_type == SwapType::Chain {
                            Value::Null
                        } else {
                            verifier_inputs_for(&terms, "lightning")["invoice_sha256"].clone()
                        },
                        "requester_public_keys": requester_public_keys(&terms)
                    }
                }),
            )
            .unwrap(),
        &setup.requester,
    );
    let reservation_terms = json!({
        "reservation_id":"ab".repeat(32),
        "capacity_bucket_id":"test-capacity",
        "reserved_asset_id":terms["asset_pair"][1],
        "reserved_amount":terms["output_amount"],
        "handler_committed_capacity":terms["output_amount"],
        "allocation_sequence":"1",
        "proof_class":"provider_signed",
        "proof_ref":"provider-signed:test-capacity:1",
        "capacity_commitment_sha256":"cd".repeat(32),
        "reservation_expires_at":900
    });
    let mut quote_profile = json!({"terms":terms,"reservation_terms":reservation_terms});
    if let Some(selectable) = options.quote_selectable {
        quote_profile["selectable"] = selectable.clone();
    }
    let quote = signed(
        factory
            .soft_quote(
                101,
                &"12".repeat(32),
                &rfq.id,
                options.quote_expiration,
                quote_profile,
            )
            .unwrap(),
        &setup.provider,
    );
    let mut order_profile = json!({"accepted_quote_id":quote.id});
    if let Some(selection) = options.order_selection {
        order_profile["selection"] = selection.clone();
    }
    let order = signed(
        factory
            .order(
                options.order_created_at,
                &"13".repeat(32),
                &quote.id,
                order_profile,
            )
            .unwrap(),
        &setup.requester,
    );
    let bitcoin_exit_specs = flow_exit_specs(swap_type)
        .iter()
        .copied()
        .filter(|spec| {
            options
                .liquid
                .is_none_or(|request| spec.leg_id != liquid_request_leg_id(request))
        })
        .collect::<Vec<_>>();
    let mut package_seeds = bitcoin_exit_specs
        .iter()
        .map(|spec| {
            let mode = options.exit_mode.unwrap_or(spec.mode);
            let mut document = exit_document(
                fixture,
                swap_type,
                ExitDocumentBindings {
                    order_id: &order.id,
                    quote_id: &quote.id,
                    contract_ids: &["01".repeat(32), "02".repeat(32)],
                    contract_sha256: &"03".repeat(32),
                },
                *spec,
                mode,
            );
            if options.null_funding_transaction_id {
                document["funding"]["transaction_id"] = Value::Null;
            }
            ExitPackage::parse(document).unwrap()
        })
        .collect::<Vec<_>>();
    let mut contract = base_terms(fixture, swap_type);
    if let Some(request) = options.liquid {
        apply_liquid_terms(&mut contract, request);
    }
    if options.provider_cooperative_exit {
        enable_provider_cooperative_exit(fixture, &mut contract);
    }
    if let Some(mutation) = options.funding_resolution {
        mutate_contract_funding_resolution(&mut contract, mutation);
    }
    if options.path_specific_exit_tamper {
        tamper_path_specific_exit(&mut contract);
    }
    let object = contract.as_object_mut().unwrap();
    if let Some(selection) = options.contract_selection {
        object.insert("order_selection".into(), selection.clone());
        if let Some(input_amount) = selection.get("input_amount").and_then(Value::as_str) {
            object.insert("input_amount".into(), json!(input_amount));
            let input = input_amount.parse::<u64>().unwrap();
            let provider_fee = object["provider_fee"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let miner_fee = object["miner_fee_budget"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let lightning_fee = object["lightning_routing_fee_budget"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            object.insert(
                "output_amount".into(),
                json!((input - provider_fee - miner_fee - lightning_fee).to_string()),
            );
        }
        for name in ["fee_payer", "confirmation_policy", "public_receipt_consent"] {
            if let Some(value) = selection.get(name) {
                object.insert(name.into(), value.clone());
            }
        }
    }
    object.insert("order_id".into(), Value::String(order.id.clone()));
    object.insert("quote_id".into(), Value::String(quote.id.clone()));
    let topology = &fixture["flow_topologies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|topology| topology["swap_type"] == swap_name(swap_type))
        .unwrap()["requester_funding"];
    let mut effect_bindings = vec![json!({
        "role":topology["role"],
        "leg_id":topology["leg_id"]
    })];
    effect_bindings.extend(
        flow_exit_specs(swap_type)
            .iter()
            .map(|spec| json!({"role":format!("chain_{}", spec.path),"leg_id":spec.leg_id})),
    );
    if options.provider_cooperative_exit {
        effect_bindings.extend([
            json!({"role":"cooperative_sign","leg_id":"source"}),
            json!({"role":"chain_claim","leg_id":"source"}),
        ]);
    }
    object.insert("effect_bindings".into(), Value::Array(effect_bindings));
    if options.provider_cooperative_exit {
        package_seeds.push(
            provider_support::build_provider_submarine_claim_exit_package_seed(
                &setup.config,
                &order.id,
                &quote.id,
                &Value::Object(object.clone()),
            )
            .expect("cooperative test must construct the canonical provider seed"),
        );
    }
    let mut commitments = bitcoin_exit_specs
        .iter()
        .zip(&package_seeds)
        .map(|(spec, package)| {
            json!({
                "participant_role":"requester",
                "leg_id":spec.leg_id,
                "path":spec.path,
                "package_mode":options.exit_mode.unwrap_or(spec.mode),
                "package_sha256":package.commitment_sha256().unwrap()
            })
        })
        .collect::<Vec<_>>();
    if let Some(request) = options.liquid {
        commitments.push(json!({
            "participant_role":"requester",
            "leg_id":liquid_request_leg_id(request),
            "path":request.exit_package.path,
            "package_mode":match request.exit_package.mode {
                LiquidExitMode::Presigned => "presigned",
                LiquidExitMode::Wallet => "wallet_sign",
            },
            "package_sha256":liquid_exit_commitment(&request.exit_package)
        }));
    }
    if options.provider_cooperative_exit {
        let provider_seed = package_seeds
            .last()
            .expect("cooperative test must contain the canonical provider seed");
        commitments.push(json!({
            "participant_role":"provider",
            "leg_id":"source",
            "path":"claim",
            "package_mode":"external_signer",
            "package_sha256":provider_seed
                .commitment_sha256()
                .expect("cooperative provider seed must have a canonical commitment")
        }));
    }
    object.insert("exit_package_commitments".into(), Value::Array(commitments));
    let reservation_commitment = json!({
        "session_id":setup.config.session_id,
        "rfq_id":rfq.id,
        "quote_id":quote.id,
        "reservation_id":"ab".repeat(32),
        "reservation_class":"soft",
        "capacity_bucket_id":"test-capacity",
        "reserved_asset_id":object["asset_pair"][1],
        "reserved_amount":object["output_amount"],
        "handler_committed_capacity":object["output_amount"],
        "allocation_sequence":"1",
        "proof_class":"provider_signed",
        "proof_strength":10,
        "proof_ref_sha256":lower_hex(&sha256(b"provider-signed:test-capacity:1")),
        "capacity_commitment_sha256":"cd".repeat(32),
        "reservation_expires_at":900,
        "profile_timeout_at":null,
        "covenant_commitment":null
    });
    object.insert("reservation_commitment".into(), reservation_commitment);
    let requester_contract = signed(
        factory
            .swap_contract(
                ParticipantRole::Requester,
                options.order_created_at + 1,
                &"14".repeat(32),
                SwapContractReferences {
                    order_id: &order.id,
                    quote_id: &quote.id,
                    accepted_status_id: None,
                },
                contract.clone(),
            )
            .unwrap(),
        &setup.requester,
    );
    let provider_contract = signed(
        factory
            .swap_contract(
                ParticipantRole::Provider,
                options.order_created_at + 2,
                &"15".repeat(32),
                SwapContractReferences {
                    order_id: &order.id,
                    quote_id: &quote.id,
                    accepted_status_id: None,
                },
                contract,
            )
            .unwrap(),
        &setup.provider,
    );
    let contract_sha256 = requester_contract
        .tags
        .iter()
        .find(|tag| tag.name() == Some("x"))
        .and_then(|tag| tag.value())
        .unwrap();
    let mut exit_packages = if options.include_exit {
        bitcoin_exit_specs
            .iter()
            .map(|spec| {
                let mut document = exit_document(
                    fixture,
                    swap_type,
                    ExitDocumentBindings {
                        order_id: &order.id,
                        quote_id: &quote.id,
                        contract_ids: &[
                            requester_contract.id.clone(),
                            provider_contract.id.clone(),
                        ],
                        contract_sha256,
                    },
                    *spec,
                    options.exit_mode.unwrap_or(spec.mode),
                );
                if options.null_funding_transaction_id {
                    document["funding"]["transaction_id"] = Value::Null;
                }
                ExitPackage::parse(document).unwrap()
            })
            .collect()
    } else {
        Vec::new()
    };
    let records = vec![rfq, quote, order, requester_contract, provider_contract];
    if options.provider_cooperative_exit {
        let canonical =
            provider_support::build_provider_submarine_claim_exit_package(&setup.config, &records)
                .expect("accepted cooperative session must construct the provider package");
        assert_eq!(
            package_seeds
                .last()
                .expect("cooperative test must retain its provider seed")
                .commitment_sha256()
                .expect("cooperative provider seed must have a canonical commitment"),
            canonical
                .commitment_sha256()
                .expect("accepted provider package must have a canonical commitment"),
            "pre-contract provider seed and accepted-session canonical package must commit identically"
        );
        exit_packages.push(canonical);
    }
    SwapSession::from_signed_records(setup.config, records, exit_packages)
}

fn enable_provider_cooperative_exit(fixture: &Value, terms: &mut Value) {
    let payment_hash = flow_payment_hash(fixture, SwapType::Submarine);
    let claim_material = exit_material(
        &payment_hash,
        ExitSpec {
            leg_id: "source",
            path: "claim",
            condition: "hashlock",
            mode: "external_signer",
        },
        bitcoin_leg_amount(SwapType::Submarine, "source"),
    );
    terms["musig2_execution"] = Value::Bool(true);
    terms["effect_policy"] = json!({
        "effects":[{
            "actor":"provider",
            "effect_role":"cooperative_sign",
            "leg_id":"source"
        }],
        "id_scheme":"openagents.mkt-swp.v1",
        "order_event_id_required":true,
        "replay":"idempotent_exact_bytes"
    });
    let verifier = terms["verifier_inputs"]
        .as_array_mut()
        .expect("cooperative test terms must contain verifier inputs")
        .iter_mut()
        .find(|verifier| verifier["leg_id"] == "source")
        .and_then(Value::as_object_mut)
        .expect("cooperative test terms must contain the source verifier");
    verifier.insert("claim_script".into(), json!(claim_material.script));
    verifier.insert(
        "taproot_claim_control_block".into(),
        json!(claim_material.control_block),
    );
    verifier.insert(
        "provider_exit_destination_script_pubkey".into(),
        json!(format!("5120{}", claim_material.output_key)),
    );
    verifier.insert("musig2_execution".into(), Value::Bool(true));
    verifier.insert(
        "sighash_policy".into(),
        json!("default_key_path_with_script_fallback"),
    );
    verifier.insert("chain_tip_height".into(), json!("100"));
    verifier.insert(
        "provider_exit_signer_ref".into(),
        json!("immortal-provider:source:claim"),
    );
    verifier.insert(
        "provider_exit_policy".into(),
        json!({
            "earliest_broadcast_height":"100",
            "latest_safe_broadcast_height":"120",
            "target_blocks":2,
            "maximum_fee":flow_amounts(SwapType::Submarine).4,
            "bump_mode":"cpfp"
        }),
    );
    refresh_leg_verifier_digest(terms, "source");
}

fn base_terms(fixture: &Value, swap_type: SwapType) -> Value {
    let deterministic = &fixture["deterministic_session"];
    let asset_pair = match swap_type {
        SwapType::Submarine => json!([
            deterministic["chain_asset_a"],
            deterministic["lightning_asset_a"]
        ]),
        SwapType::Reverse => json!([
            deterministic["lightning_asset_a"],
            deterministic["chain_asset_a"]
        ]),
        SwapType::Chain => json!([
            deterministic["chain_asset_a"],
            deterministic["chain_asset_b"]
        ]),
    };
    let payment_hash = flow_payment_hash(fixture, swap_type);
    let (input_amount, output_amount, fee_bps, provider_fee, miner_fee, amount_equation) =
        flow_amounts(swap_type);
    let bitcoin_amount = |leg_id| bitcoin_leg_amount(swap_type, leg_id);
    let mut verifier_inputs = flow_exit_specs(swap_type)
        .iter()
        .map(|spec| {
            bitcoin_verifier(
                &exit_material(&payment_hash, *spec, bitcoin_amount(spec.leg_id)),
                *spec,
            )
        })
        .collect::<Vec<_>>();
    if !matches!(swap_type, SwapType::Chain) {
        verifier_inputs.push(json!({
            "leg_id":"lightning",
            "verifier_policy":"mkt-swp-lightning-v1",
            "evidence_authority":{"mode":"local","pubkeys":[],"adapter_sha256":"ef".repeat(32)},
            "invoice_sha256": lower_hex(&sha256(fixture_string(fixture, "invoice").as_bytes())),
            "invoice_amount_msat": deterministic["invoice_amount_msat"],
            "invoice_network":"bitcoin",
            "invoice_expiry_seconds":deterministic["invoice_expiry_seconds"].to_string(),
            "invoice_minimum_final_cltv_delta":deterministic["invoice_minimum_final_cltv_delta"].to_string()
        }));
    }
    let mut legs = match swap_type {
        SwapType::Submarine => json!([
            {"leg_id":"source","rail":"bitcoin","funding_role":"requester","receiving_role":"provider"},
            {"leg_id":"lightning","rail":"lightning","funding_role":"provider","receiving_role":"requester"}
        ]),
        SwapType::Reverse => json!([
            {"leg_id":"lightning","rail":"lightning","funding_role":"requester","receiving_role":"provider"},
            {"leg_id":"destination","rail":"bitcoin","funding_role":"provider","receiving_role":"requester"}
        ]),
        SwapType::Chain => json!([
            {"leg_id":"source","rail":"bitcoin","funding_role":"requester","receiving_role":"provider"},
            {"leg_id":"destination","rail":"bitcoin","funding_role":"provider","receiving_role":"requester"}
        ]),
    };
    for (index, leg) in legs.as_array_mut().unwrap().iter_mut().enumerate() {
        let leg_id = leg["leg_id"].as_str().unwrap();
        let verifier = verifier_inputs
            .iter()
            .find(|verifier| verifier["leg_id"] == leg_id)
            .unwrap();
        let asset_id = asset_pair[index].clone();
        let network_id = asset_id
            .as_str()
            .unwrap()
            .strip_prefix("swp:1:")
            .unwrap()
            .split(":btc:")
            .next()
            .unwrap();
        let leg = leg.as_object_mut().unwrap();
        leg.insert("network_id".into(), json!(network_id));
        leg.insert("asset_id".into(), asset_id);
        leg.insert("payment_hash".into(), json!(payment_hash));
        leg.insert(
            "verifier_digest".into(),
            json!(lower_hex(&sha256(&canonical_json_test(verifier)))),
        );
        leg.insert(
            "verifier_policy".into(),
            verifier["verifier_policy"].clone(),
        );
        if verifier.get("funding_transaction_sha256").is_some() {
            leg.insert("amount".into(), verifier["amount"].clone());
            leg.insert("script_pubkey".into(), verifier["script_pubkey"].clone());
            leg.insert(
                "confirmation_policy".into(),
                json!({
                    "minimum_confirmations":verifier["minimum_confirmations"],
                    "replacement_policy":verifier["replacement_policy"]
                }),
            );
            let tree = verifier["taproot_tree"].as_array().unwrap();
            for path in ["claim", "refund"] {
                let leaf = tree.iter().find(|leaf| leaf["path"] == path).unwrap();
                leg.insert(format!("{path}_public_key"), leaf["signing_pubkey"].clone());
                if path == "refund" {
                    leg.insert("refund_condition".into(), leaf["condition"].clone());
                    leg.insert("refund_lock_value".into(), leaf["lock_value"].clone());
                }
            }
        } else {
            leg.insert(
                "amount".into(),
                json!(if swap_type == SwapType::Reverse {
                    input_amount
                } else {
                    output_amount
                }),
            );
            for member in [
                "invoice_sha256",
                "invoice_expiry_seconds",
                "invoice_minimum_final_cltv_delta",
            ] {
                leg.insert(member.into(), verifier[member].clone());
            }
        }
    }
    json!({
        "swap_type":swap_name(swap_type),
        "asset_pair":asset_pair,
        "payment_hash":payment_hash,
        "input_amount":input_amount,
        "output_amount":output_amount,
        "fee_bps":fee_bps,
        "provider_fee":provider_fee,
        "miner_fee_budget":miner_fee,
        "lightning_routing_fee_budget":"0",
        "maximum_total_fee":(provider_fee.parse::<u64>().unwrap() + miner_fee.parse::<u64>().unwrap()).to_string(),
        "confirmation_policy":{
            "minimum_confirmations":"1",
            "zero_confirmation":"forbidden",
            "rbf":"reject",
            "replacement":"reject",
            "reorg_safety_blocks":"6"
        },
        "script_mode":"taproot-musig2-script-exit",
        "desired_completion_time":2000,
        "clock_skew_seconds":"60",
        "amount_equation":amount_equation,
        "rounding":"floor_output_sats",
        "fee_payer":"requester",
        "legs":legs,
        "timeout_ladder":timeout_ladder(swap_type),
        "verifier_inputs":verifier_inputs,
        "recovery":{
            "channel":"direct_or_relay_agnostic",
            "exit_policy":{
                "earliest_broadcast_height":"140",
                "latest_safe_broadcast_height":"200",
                "target_blocks":2,
                "maximum_fee":miner_fee,
                "bump_mode":"cpfp"
            }
        },
        "reservation_commitment":{},
        "cancellation":{"effective_before_external_effect":true},
        "evidence_requirements":{"minimum_rung":"verified"},
        "price_feed":null,
        "evm_leg":null
    })
}

fn liquid_request_leg_id(request: &LiquidBeforeFundRequest) -> &'static str {
    match request.swap_type {
        LiquidSwapType::Submarine => "source",
        LiquidSwapType::Reverse => "destination",
        LiquidSwapType::Chain => match request.purpose {
            LiquidLegPurpose::RequesterBroadcast => "source",
            LiquidLegPurpose::CounterpartyLock => "destination",
        },
    }
}

fn liquid_exit_commitment(package: &LiquidUnilateralExitPackage) -> String {
    let value = serde_json::to_value(package).unwrap();
    lower_hex(&sha256(&canonical_json_test(&value)))
}

fn apply_liquid_terms(terms: &mut Value, request: &LiquidBeforeFundRequest) {
    let leg_id = liquid_request_leg_id(request);
    let liquid_index = usize::from(request.purpose == LiquidLegPurpose::CounterpartyLock);
    terms["asset_pair"] = json!([request.input_asset_id, request.output_asset_id]);
    let expected_amount = if liquid_index == 0 {
        terms["input_amount"].as_str().unwrap()
    } else {
        terms["output_amount"].as_str().unwrap()
    };
    assert_eq!(request.funding.amount, expected_amount);
    let verifier = terms["verifier_inputs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|verifier| verifier["leg_id"] == leg_id)
        .unwrap()
        .as_object_mut()
        .unwrap();
    verifier.insert("verifier_policy".into(), json!("mkt-swp-liquid-v1"));
    verifier.insert(
        "funding_transaction".into(),
        json!(request.funding.raw_transaction),
    );
    verifier.insert(
        "funding_transaction_sha256".into(),
        json!(request.funding.transaction_sha256),
    );
    verifier.insert("output_index".into(), json!(request.funding.output_index));
    verifier.insert("asset_id".into(), json!(request.funding.asset_id));
    verifier.insert("amount".into(), json!(request.funding.amount));
    verifier.insert("script_pubkey".into(), json!(request.funding.script_pubkey));
    verifier.insert(
        "taproot_internal_key".into(),
        json!(request.funding.taproot_internal_key),
    );
    verifier.insert(
        "taproot_merkle_root".into(),
        serde_json::to_value(&request.funding.taproot_merkle_root).unwrap(),
    );
    verifier.insert(
        "confidentiality".into(),
        json!(match request.funding.confidentiality {
            LiquidConfidentiality::Explicit => "explicit",
            LiquidConfidentiality::Confidential => "confidential",
        }),
    );
    verifier.insert(
        "minimum_confirmations".into(),
        json!(request.funding.minimum_confirmations.to_string()),
    );
    verifier.insert(
        "replacement_policy".into(),
        json!(request.funding.replacement_policy),
    );
    let legs = terms["legs"].as_array_mut().unwrap();
    for (index, leg) in legs.iter_mut().enumerate() {
        let asset_id = if index == 0 {
            request.input_asset_id.as_str()
        } else {
            request.output_asset_id.as_str()
        };
        let network_id = asset_id
            .strip_prefix("swp:1:")
            .unwrap()
            .split_once(if index == liquid_index {
                ":elements:"
            } else {
                ":btc:"
            })
            .unwrap()
            .0;
        leg["asset_id"] = json!(asset_id);
        leg["network_id"] = json!(network_id);
        if index == liquid_index {
            leg["rail"] = json!("liquid");
            leg["verifier_policy"] = json!("mkt-swp-liquid-v1");
            leg["amount"] = json!(request.funding.amount);
            leg["script_pubkey"] = json!(request.funding.script_pubkey);
            leg["confirmation_policy"] = json!({
                "minimum_confirmations":request.funding.minimum_confirmations.to_string(),
                "replacement_policy":request.funding.replacement_policy
            });
        }
    }
    refresh_leg_verifier_digest(terms, leg_id);
}

fn omit_quote_funding_resolution(terms: &mut Value, leg_id: &str) {
    let verifier = terms["verifier_inputs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|verifier| verifier["leg_id"] == leg_id)
        .unwrap()
        .as_object_mut()
        .unwrap();
    for member in [
        "funding_transaction",
        "funding_transaction_sha256",
        "output_index",
    ] {
        verifier.remove(member).unwrap();
    }
    refresh_leg_verifier_digest(terms, leg_id);
}

fn mutate_contract_funding_resolution(contract: &mut Value, mutation: FundingResolutionMutation) {
    let verification_fixture = verification_fixture();
    let vector = &verification_fixture["quote_contract_funding_resolution"];
    let leg_id = if mutation == FundingResolutionMutation::WrongLeg {
        "lightning"
    } else if mutation == FundingResolutionMutation::WrongSwap {
        "destination"
    } else {
        "source"
    };
    if mutation == FundingResolutionMutation::WrongLeg {
        let verifier = contract["verifier_inputs"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|verifier| verifier["leg_id"] == leg_id)
            .unwrap()
            .as_object_mut()
            .unwrap();
        for member in [
            "funding_transaction",
            "funding_transaction_sha256",
            "output_index",
        ] {
            verifier.insert(member.to_owned(), vector[member].clone());
        }
        refresh_leg_verifier_digest(contract, leg_id);
        return;
    }
    if matches!(
        mutation,
        FundingResolutionMutation::Valid | FundingResolutionMutation::WrongSwap
    ) {
        return;
    }
    let verifier = contract["verifier_inputs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|verifier| verifier["leg_id"] == leg_id)
        .unwrap()
        .as_object_mut()
        .unwrap();
    match mutation {
        FundingResolutionMutation::ExtraField => {
            verifier.insert("unexpected_resolution_field".to_owned(), json!(true));
        }
        FundingResolutionMutation::WrongHash => {
            verifier.insert(
                "funding_transaction_sha256".to_owned(),
                json!("ff".repeat(32)),
            );
        }
        FundingResolutionMutation::WrongIndex => {
            verifier.insert("output_index".to_owned(), json!(1));
        }
        FundingResolutionMutation::WrongScript => {
            verifier.insert(
                "funding_transaction".to_owned(),
                vector["wrong_script_transaction"].clone(),
            );
            verifier.insert(
                "funding_transaction_sha256".to_owned(),
                vector["wrong_script_transaction_sha256"].clone(),
            );
        }
        FundingResolutionMutation::WrongAmount => {
            verifier.insert(
                "funding_transaction".to_owned(),
                vector["wrong_amount_transaction"].clone(),
            );
            verifier.insert(
                "funding_transaction_sha256".to_owned(),
                vector["wrong_amount_transaction_sha256"].clone(),
            );
        }
        FundingResolutionMutation::WrongDigest => {
            let leg = contract["legs"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|leg| leg["leg_id"] == leg_id)
                .unwrap();
            leg["verifier_digest"] = json!("ff".repeat(32));
            return;
        }
        FundingResolutionMutation::Valid
        | FundingResolutionMutation::WrongSwap
        | FundingResolutionMutation::WrongLeg => unreachable!(),
    }
    refresh_leg_verifier_digest(contract, leg_id);
}

fn refresh_leg_verifier_digest(terms: &mut Value, leg_id: &str) {
    let verifier = terms["verifier_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|verifier| verifier["leg_id"] == leg_id)
        .unwrap();
    let digest = lower_hex(&sha256(&canonical_json_test(verifier)));
    let leg = terms["legs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|leg| leg["leg_id"] == leg_id)
        .unwrap();
    leg["verifier_digest"] = json!(digest);
}

fn tamper_path_specific_exit(terms: &mut Value) {
    let verifier = terms["verifier_inputs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|verifier| verifier["leg_id"] == "source")
        .and_then(Value::as_object_mut)
        .unwrap();
    let claim_script = verifier["claim_script"].clone();
    verifier.insert("refund_script".to_owned(), claim_script);
    refresh_leg_verifier_digest(terms, "source");
}

fn provider_quote_profile(fixture: &Value, reservation_expires_at: u64) -> Value {
    let terms = base_terms(fixture, SwapType::Submarine);
    json!({
        "terms":terms.clone(),
        "reservation_terms":{
            "reservation_id":"ab".repeat(32),
            "capacity_bucket_id":"test-capacity",
            "reserved_asset_id":terms["asset_pair"][1],
            "reserved_amount":terms["output_amount"],
            "handler_committed_capacity":terms["output_amount"],
            "allocation_sequence":"1",
            "proof_class":"provider_signed",
            "proof_ref":"provider-signed:test-capacity:1",
            "capacity_commitment_sha256":"cd".repeat(32),
            "reservation_expires_at":reservation_expires_at
        }
    })
}

fn empty_loss_accounting(terms: &Value) -> Value {
    json!({
        "input_asset_id":terms["asset_pair"][0],
        "output_asset_id":terms["asset_pair"][1],
        "input_committed":"0",
        "input_recovered":"0",
        "output_received":"0",
        "provider_fee_paid":"0",
        "miner_fee_paid":"0",
        "lightning_routing_fee_paid":"0",
        "guarantee_recovery_received":"0",
        "principal_unresolved":"0",
        "reservation_released":terms["output_amount"],
        "evidence_refs":[]
    })
}

fn bound_failure_evidence(terms: &Value, producer_pubkey: &str) -> Value {
    let verifier = verifier_inputs_for(terms, "source");
    let raw = decode_hex(verifier["funding_transaction"].as_str().unwrap());
    let transaction = Transaction::parse(&raw).unwrap();
    json!({
        "class":"replacement",
        "rung":"measured",
        "rail":"bitcoin",
        "reference":lower_hex(&transaction.txid().unwrap()),
        "artifact_sha256":verifier["funding_transaction_sha256"],
        "producer_pubkey":producer_pubkey,
        "verifier_pubkey":null,
        "verifier_policy":verifier["verifier_policy"],
        "observed_at":300,
        "view":"regtest-height:300"
    })
}

fn flow_amounts(
    swap_type: SwapType,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match swap_type {
        SwapType::Submarine => (
            "100000",
            "1000",
            "9800",
            "98000",
            "1000",
            "input_minus_provider_and_quoted_fees",
        ),
        SwapType::Reverse => (
            "1000",
            "890",
            "100",
            "10",
            "100",
            "input_minus_provider_and_quoted_fees",
        ),
        SwapType::Chain => (
            "100000",
            "98000",
            "100",
            "1000",
            "1000",
            "one_to_one_less_quoted_fees",
        ),
    }
}

fn bitcoin_leg_amount(swap_type: SwapType, leg_id: &str) -> u64 {
    let (input, output, _, _, _, _) = flow_amounts(swap_type);
    if leg_id == "source" {
        input.parse().unwrap()
    } else {
        output.parse().unwrap()
    }
}

fn verifier_inputs_for<'a>(terms: &'a Value, leg_id: &str) -> &'a Value {
    terms["verifier_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|verifier| verifier["leg_id"] == leg_id)
        .unwrap()
}

fn requester_public_keys(terms: &Value) -> Value {
    let mut keys = terms["verifier_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|verifier| {
            verifier["taproot_tree"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|leaf| leaf["participant_role"] == "requester")
                .map(|leaf| {
                    json!({
                        "leg_id":verifier["leg_id"],
                        "path":leaf["path"],
                        "public_key":leaf["signing_pubkey"]
                    })
                })
        })
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.to_string());
    Value::Array(keys)
}

fn verification_input(fixture: &Value, swap_type: SwapType) -> VerifyBeforeFundInput {
    let deterministic = &fixture["deterministic_session"];
    let payment_hash = flow_payment_hash(fixture, swap_type);
    let verifier_spec = match swap_type {
        SwapType::Submarine | SwapType::Chain => flow_exit_specs(swap_type)[0],
        SwapType::Reverse => flow_exit_specs(swap_type)[0],
    };
    let funding_amount = bitcoin_leg_amount(swap_type, verifier_spec.leg_id);
    let material = exit_material(&payment_hash, verifier_spec, funding_amount);
    VerifyBeforeFundInput {
        observed_at: 500,
        payment_hash,
        funding: FundingVerificationInput {
            raw_transaction: material.funding_transaction,
            output_index: 0,
            expected_amount: funding_amount.to_string(),
            expected_script_pubkey: format!("5120{}", material.output_key),
            taproot_output_key: material.output_key,
            taproot_script: material.script,
            taproot_control_block: material.control_block,
        },
        invoice: (!matches!(swap_type, SwapType::Chain)).then(|| InvoiceVerificationInput {
            invoice: deterministic["invoice"].as_str().unwrap().into(),
            expected_network: "bitcoin".into(),
            expected_amount_msat: deterministic["invoice_amount_msat"]
                .as_str()
                .unwrap()
                .into(),
            observed_at: deterministic["invoice_observed_at"].as_u64().unwrap(),
            required_minimum_final_cltv_delta: deterministic["invoice_minimum_final_cltv_delta"]
                .as_u64()
                .unwrap(),
        }),
        timeout_ladder: ladder(swap_type),
        minimum_confirmations: 1,
        replacement_policy: "reject".into(),
    }
}

fn ladder(swap_type: SwapType) -> TimeoutLadder {
    match swap_type {
        SwapType::Submarine => TimeoutLadder::Submarine {
            current_height: 100,
            fund_last: 110,
            claim_last: 120,
            refund_first: 140,
            chain_finality_blocks: 1,
            broadcast_safety_blocks: 2,
            reorg_safety_blocks: 6,
            invoice_expiration_time: 2_000,
            claim_expected_time: 1_000,
        },
        SwapType::Reverse => TimeoutLadder::Reverse {
            current_height: 100,
            lightning_current_height: 100,
            lock_last: 110,
            user_claim_last: 120,
            provider_refund_first: 140,
            hold_expiry_height: 160,
            chain_finality_blocks: 1,
            broadcast_safety_blocks: 2,
            reorg_safety_blocks: 6,
            lightning_settlement_blocks: 6,
            height_observed_at: None,
            height_observation_max_age_seconds: None,
            chain_block_interval_seconds: None,
            lightning_block_interval_seconds: None,
            cross_domain_safety_seconds: None,
            provider_refund_expected_at: None,
            hold_expiry_expected_at: None,
        },
        SwapType::Chain => TimeoutLadder::Chain {
            destination_final: true,
            destination_refund_time: 1_000,
            source_refund_time: 1_100,
            provider_claim_margin: 20,
            both_network_reorg_margins: 20,
            both_network_broadcast_margins: 20,
        },
    }
}

#[test]
fn liquid_reverse_timeout_ladder_separates_chain_and_lightning_heights() {
    let fixture = liquid_fixture();
    let vectors = fixture["timeout_vectors"]
        .as_array()
        .expect("Liquid timeout vectors");
    assert_eq!(
        vectors
            .iter()
            .map(|vector| vector["name"].as_str().expect("timeout vector name"))
            .collect::<Vec<_>>(),
        [
            "swp-v1-liquid-reverse-cross-domain-timeout",
            "swp-v1-negative-liquid-reverse-cross-domain-timeout",
        ]
    );
    let ladder: TimeoutLadder =
        serde_json::from_value(vectors[0]["ladder"].clone()).expect("safe timeout ladder");
    ladder.validate().expect("safe cross-domain ladder");
    ladder
        .validate_observation_time(
            vectors[0]["observed_at"].as_u64().expect("observed at"),
            vectors[0]["clock_skew_seconds"]
                .as_u64()
                .expect("clock skew"),
        )
        .expect("bounded observation age");
    assert_eq!(
        ladder
            .validate_observation_time(1_181, 60)
            .expect_err("stale cross-domain observation")
            .code,
        "swp_timeout_ladder_unsafe"
    );

    let changed: TimeoutLadder =
        serde_json::from_value(vectors[1]["ladder"].clone()).expect("changed timeout shape");
    assert_eq!(
        changed
            .validate()
            .expect_err("changed conversion result")
            .code,
        "swp_timeout_ladder_unsafe"
    );

    let mut incomplete = vectors[0]["ladder"].clone();
    incomplete
        .as_object_mut()
        .expect("timeout object")
        .remove("cross_domain_safety_seconds");
    let incomplete: TimeoutLadder = serde_json::from_value(incomplete).expect("timeout shape");
    assert_eq!(
        incomplete
            .validate()
            .expect_err("incomplete cross-domain terms")
            .code,
        "swp_timeout_ladder_unsafe"
    );
}

fn timeout_ladder(swap_type: SwapType) -> Value {
    serde_json::to_value(ladder(swap_type)).unwrap()
}

struct ExitDocumentBindings<'a> {
    order_id: &'a str,
    quote_id: &'a str,
    contract_ids: &'a [String; 2],
    contract_sha256: &'a str,
}

fn exit_document(
    fixture: &Value,
    swap_type: SwapType,
    bindings: ExitDocumentBindings<'_>,
    spec: ExitSpec,
    mode: &str,
) -> Value {
    let deterministic = &fixture["deterministic_session"];
    let payment_hash = flow_payment_hash(fixture, swap_type);
    let funding_amount = bitcoin_leg_amount(swap_type, spec.leg_id);
    let material = exit_material(&payment_hash, spec, funding_amount);
    let verifier = bitcoin_verifier(&material, spec);
    let verifier_digest = lower_hex(&sha256(&canonical_json_test(&verifier)));
    let confirmation_policy = json!({
        "minimum_confirmations":"1",
        "replacement_policy":"reject"
    });
    let confirmation_policy_sha256 = lower_hex(&sha256(&canonical_json_test(&confirmation_policy)));
    let funding = Transaction::parse(&decode_hex(&material.funding_transaction)).unwrap();
    let funding_txid = lower_hex(&funding.txid().unwrap());
    let mut txid_wire = funding.txid().unwrap();
    txid_wire.reverse();
    let maximum_fee = flow_amounts(swap_type).4.parse::<u64>().unwrap();
    let (lock_time, input_sequence) = match spec.condition {
        "cltv" => (140, u32::MAX - 1),
        "csv" => (0, 20),
        "hashlock" => (0, u32::MAX - 2),
        _ => panic!("unknown test exit condition"),
    };
    let unsigned = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid: txid_wire,
            previous_output: 0,
            script_sig: Vec::new(),
            sequence: input_sequence,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: funding_amount - maximum_fee,
            script_pubkey: decode_hex(deterministic["destination_script_pubkey"].as_str().unwrap()),
        }],
        lock_time,
    )
    .serialize(false)
    .unwrap();
    let (network_id, asset_id) = match (swap_type, spec.leg_id) {
        (SwapType::Chain, "destination") => (
            deterministic["network_b"].clone(),
            deterministic["chain_asset_b"].clone(),
        ),
        _ => (
            deterministic["network_a"].clone(),
            deterministic["chain_asset_a"].clone(),
        ),
    };
    let mut document = json!({
        "schema":"openagents.mkt-swp.exit.v1",
        "profile":"mkt-swp",
        "profile_version":1,
        "order_id":bindings.order_id,
        "swap_contract_ids":bindings.contract_ids,
        "contract_sha256":bindings.contract_sha256,
        "participant_role":"requester",
        "leg_id":spec.leg_id,
        "network_id":network_id,
        "asset_id":asset_id,
        "effect_id":exit_effect_id(bindings.order_id, spec.path, spec.leg_id),
        "funding":{
            "transaction_id":funding_txid,
            "transaction_template_sha256":lower_hex(&sha256(&decode_hex(&material.funding_transaction))),
            "transaction_template":material.funding_transaction,
            "output_index":0,
            "amount":funding_amount.to_string(),
            "script_pubkey":format!("5120{}", material.output_key),
            "confirmation_policy_sha256":confirmation_policy_sha256
        },
        "exit":{
            "mode":if mode == "presigned" { "wallet_sign" } else { mode },
            "path":spec.path,
            "transaction_template_sha256":lower_hex(&sha256(&unsigned)),
            "signed_transaction":null,
            "signer_ref":format!("wallet:{}:{}", spec.leg_id, spec.path),
            "transaction_version":2,
            "lock_time":lock_time,
            "input_sequence":input_sequence,
            "sighash_type":"DEFAULT",
            "destination_script_pubkey":deterministic["destination_script_pubkey"],
            "earliest_broadcast_height":"140",
            "latest_safe_broadcast_height":"200",
            "fee_policy":{"target_blocks":2,"maximum_fee":maximum_fee.to_string(),"bump_mode":"cpfp"}
        },
        "verification":{
            "swap_tree_sha256":material.swap_tree_sha256,
            "quote_id":bindings.quote_id,
            "verifier_digest":verifier_digest,
            "taproot_script":material.script,
            "taproot_control_block":material.control_block,
            "taproot_tree":material.taproot_tree
        },
        "secret_commitments":{
            "payment_hash":payment_hash,
            "preimage_recovery_ref":null
        },
        "broadcast":{
            "esplora_urls":["https://esplora.example/api"],
            "minimum_agreeing_sources":1
        }
    });
    if mode == "presigned" {
        let draft = ExitPackage::parse(document.clone()).unwrap();
        let signature_hash = lower_hex(&draft.signing_digest().unwrap());
        let signed =
            add_signed_taproot_witness(&draft, &lower_hex(&unsigned), &signature_hash, None);
        let exit = document["exit"].as_object_mut().unwrap();
        exit.insert("mode".into(), json!("presigned"));
        exit.insert("signed_transaction".into(), json!(lower_hex(&signed)));
        exit.insert("signer_ref".into(), Value::Null);
    }
    document
}

fn signed(request: MktSigningRequest, signer: &MarketSigner) -> immortal_client::domain::Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).unwrap()
}

fn delivery_receipts(
    records: &[immortal_client::domain::Event],
    observed_at: u64,
) -> Vec<SignedRecordDelivery> {
    records
        .iter()
        .map(|event| {
            SignedRecordDelivery::from_locally_signed(
                serde_json::to_vec(event).unwrap(),
                observed_at,
            )
            .unwrap()
        })
        .collect()
}

fn add_signed_taproot_witness(
    package: &ExitPackage,
    unsigned: &str,
    signature_hash: &str,
    preimage: Option<[u8; 32]>,
) -> Vec<u8> {
    let unsigned = decode_hex(unsigned);
    let leg_id = package.document()["leg_id"].as_str().unwrap();
    let path = package.document()["exit"]["path"].as_str().unwrap();
    let signer_label = format!("exit:{leg_id}:{path}");
    let secret = SecretKey::from_byte_array(test_signing_key(signer_label.as_bytes())).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let digest: [u8; 32] = decode_hex(signature_hash).try_into().unwrap();
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&digest, &keypair);
    let script = decode_hex(
        package.document()["verification"]["taproot_script"]
            .as_str()
            .unwrap(),
    );
    let control = decode_hex(
        package.document()["verification"]["taproot_control_block"]
            .as_str()
            .unwrap(),
    );
    let mut signed = Vec::with_capacity(
        unsigned.len()
            + signature.as_ref().len()
            + preimage.as_ref().map_or(0, |_| 32)
            + script.len()
            + control.len()
            + 10,
    );
    signed.extend_from_slice(&unsigned[..4]);
    signed.extend_from_slice(&[0, 1]);
    signed.extend_from_slice(&unsigned[4..unsigned.len() - 4]);
    signed.push(if preimage.is_some() { 4 } else { 3 });
    signed.push(64);
    signed.extend_from_slice(signature.as_ref());
    if let Some(preimage) = preimage {
        signed.push(32);
        signed.extend_from_slice(&preimage);
    }
    signed.push(u8::try_from(script.len()).unwrap());
    signed.extend_from_slice(&script);
    signed.push(u8::try_from(control.len()).unwrap());
    signed.extend_from_slice(&control);
    signed.extend_from_slice(&unsigned[unsigned.len() - 4..]);
    signed
}

struct ExitMaterial {
    funding_transaction: String,
    funding_amount: u64,
    output_key: String,
    script: String,
    control_block: String,
    claim_script: String,
    refund_script: String,
    claim_control_block: String,
    refund_control_block: String,
    claim_signing_key: String,
    refund_signing_key: String,
    internal_key: String,
    swap_tree_sha256: String,
    taproot_merkle_root: String,
    taproot_tree: Value,
}

fn flow_payment_hash(fixture: &Value, swap_type: SwapType) -> String {
    if swap_type == SwapType::Chain {
        lower_hex(&sha256(&test_released_preimage()))
    } else {
        fixture_string(fixture, "payment_hash")
    }
}

fn test_released_preimage() -> [u8; 32] {
    sha256(b"immortal-mkt-swp-test-only:released-preimage")
}

fn exit_material(payment_hash: &str, spec: ExitSpec, funding_amount: u64) -> ExitMaterial {
    fn leaf_script(
        payment_hash: &str,
        leg_id: &str,
        path: &str,
        condition: &str,
    ) -> (Vec<u8>, [u8; 32]) {
        let signer_label = format!("exit:{leg_id}:{path}");
        let signer_secret =
            SecretKey::from_byte_array(test_signing_key(signer_label.as_bytes())).unwrap();
        let signer_keypair = Keypair::from_secret_key(&Secp256k1::new(), &signer_secret);
        let signer_key = signer_keypair.x_only_public_key().0.serialize();
        let mut script = Vec::new();
        match condition {
            "hashlock" => {
                script.extend_from_slice(&[0x82, 1, 32, 0x88, 0xa8, 32]);
                script.extend_from_slice(&decode_hex(payment_hash));
                script.extend_from_slice(&[0x88, 32]);
            }
            "cltv" => {
                let lock = script_number_bytes(140);
                script.push(u8::try_from(lock.len()).unwrap());
                script.extend_from_slice(&lock);
                script.extend_from_slice(&[0xb1, 0x75, 32]);
            }
            "csv" => {
                let delay = script_number_bytes(20);
                script.push(u8::try_from(delay.len()).unwrap());
                script.extend_from_slice(&delay);
                script.extend_from_slice(&[0xb2, 0x75, 32]);
            }
            _ => panic!("unknown test exit condition"),
        }
        script.extend_from_slice(&signer_key);
        script.push(0xac);
        (script, signer_key)
    }
    let other_path = if spec.path == "claim" {
        "refund"
    } else {
        "claim"
    };
    let other_condition = if other_path == "claim" {
        "hashlock"
    } else {
        "cltv"
    };
    let (script, signer_key) = leaf_script(payment_hash, spec.leg_id, spec.path, spec.condition);
    let (other_script, other_signing_key) =
        leaf_script(payment_hash, spec.leg_id, other_path, other_condition);
    let selected_leaf_hash = tapleaf_hash(0xc0, &script).unwrap();
    let other_leaf_hash = tapleaf_hash(0xc0, &other_script).unwrap();
    let merkle_root = test_tapbranch_hash(selected_leaf_hash, other_leaf_hash);
    let internal_key = cooperative_test_key();
    let (output_key, parity) = taproot_output_key(internal_key, Some(merkle_root)).unwrap();
    let mut control_block = vec![0xc0 | u8::from(parity == Parity::Odd)];
    control_block.extend_from_slice(&internal_key.serialize());
    control_block.extend_from_slice(&other_leaf_hash);
    let mut other_control_block = vec![0xc0 | u8::from(parity == Parity::Odd)];
    other_control_block.extend_from_slice(&internal_key.serialize());
    other_control_block.extend_from_slice(&selected_leaf_hash);
    let (
        claim_script,
        refund_script,
        claim_control_block,
        refund_control_block,
        claim_signing_key,
        refund_signing_key,
    ) = if spec.path == "claim" {
        (
            &script,
            &other_script,
            &control_block,
            &other_control_block,
            &signer_key,
            &other_signing_key,
        )
    } else {
        (
            &other_script,
            &script,
            &other_control_block,
            &control_block,
            &other_signing_key,
            &signer_key,
        )
    };

    let leaf_document = |path: &str,
                         condition: &str,
                         participant_role: &str,
                         script: &[u8],
                         signing_key: &[u8; 32]| {
        json!({
            "path":path,
            "condition":condition,
            "participant_role":participant_role,
            "script":lower_hex(script),
            "signing_pubkey":lower_hex(signing_key),
            "lock_value":match condition {
                "cltv" => json!("140"),
                "csv" => json!("20"),
                _ => Value::Null,
            }
        })
    };
    let selected_document =
        leaf_document(spec.path, spec.condition, "requester", &script, &signer_key);
    let other_document = leaf_document(
        other_path,
        other_condition,
        "provider",
        &other_script,
        &other_signing_key,
    );
    let taproot_tree = if spec.path == "claim" {
        json!([selected_document, other_document])
    } else {
        json!([other_document, selected_document])
    };

    let previous_txid = sha256(format!("funding:{}:{}", spec.leg_id, spec.path).as_bytes());
    let funding = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid,
            previous_output: u32::MAX,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: funding_amount,
            script_pubkey: [vec![0x51, 0x20], output_key.serialize().to_vec()].concat(),
        }],
        0,
    )
    .serialize(false)
    .unwrap();
    ExitMaterial {
        funding_transaction: lower_hex(&funding),
        funding_amount,
        output_key: lower_hex(&output_key.serialize()),
        script: lower_hex(&script),
        control_block: lower_hex(&control_block),
        claim_script: lower_hex(claim_script),
        refund_script: lower_hex(refund_script),
        claim_control_block: lower_hex(claim_control_block),
        refund_control_block: lower_hex(refund_control_block),
        claim_signing_key: lower_hex(claim_signing_key),
        refund_signing_key: lower_hex(refund_signing_key),
        internal_key: lower_hex(&internal_key.serialize()),
        swap_tree_sha256: lower_hex(&sha256(&canonical_json_test(&taproot_tree))),
        taproot_merkle_root: lower_hex(&merkle_root),
        taproot_tree,
    }
}

fn cooperative_test_key() -> secp256k1::XOnlyPublicKey {
    let keys = ["requester", "provider"]
        .into_iter()
        .map(|role| {
            let secret = SecretKey::from_byte_array(test_signing_key(
                format!("cooperative-spend:{role}").as_bytes(),
            ))
            .unwrap();
            PublicKey::from_secret_key(&Secp256k1::new(), &secret)
        })
        .collect::<Vec<_>>();
    musig2_aggregate_key(&keys).unwrap()
}

fn cooperative_test_pubkeys() -> Value {
    Value::Array(
        ["requester", "provider"]
            .into_iter()
            .map(|role| {
                let secret = SecretKey::from_byte_array(test_signing_key(
                    format!("cooperative-spend:{role}").as_bytes(),
                ))
                .unwrap();
                let key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
                json!({
                    "participant_role": role,
                    "public_key": lower_hex(&key.serialize())
                })
            })
            .collect(),
    )
}

fn test_tapbranch_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    let mut branch = [0_u8; 64];
    branch[..32].copy_from_slice(&left);
    branch[32..].copy_from_slice(&right);
    tagged_hash("TapBranch", &branch)
}

fn script_number_bytes(value: u32) -> Vec<u8> {
    let mut value = value;
    let mut bytes = Vec::new();
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    bytes
}

fn bitcoin_verifier(material: &ExitMaterial, spec: ExitSpec) -> Value {
    let (
        exit_path,
        exit_condition,
        exit_lock_value,
        exit_signing_key,
        taproot_script,
        taproot_control_block,
    ) = match spec.path {
        "claim" => (
            "refund",
            "cltv",
            json!("140"),
            &material.refund_signing_key,
            &material.refund_script,
            &material.refund_control_block,
        ),
        "refund" => (
            "claim",
            "hashlock",
            Value::Null,
            &material.claim_signing_key,
            &material.claim_script,
            &material.claim_control_block,
        ),
        _ => panic!("unknown test exit path"),
    };
    json!({
        "leg_id":spec.leg_id,
        "verifier_policy":"mkt-swp-bitcoin-v1",
        "evidence_authority":{"mode":"local","pubkeys":[],"adapter_sha256":"ef".repeat(32)},
        "funding_transaction_sha256":lower_hex(&sha256(&decode_hex(&material.funding_transaction))),
        "funding_transaction":material.funding_transaction,
        "output_index":0,
        "amount":material.funding_amount.to_string(),
        "script_pubkey":format!("5120{}", material.output_key),
        "taproot_output_key":material.output_key,
        "taproot_script":taproot_script,
        "taproot_control_block":taproot_control_block,
        "claim_script":material.claim_script,
        "refund_script":material.refund_script,
        "taproot_claim_control_block":material.claim_control_block,
        "taproot_refund_control_block":material.refund_control_block,
        "swap_tree_sha256":material.swap_tree_sha256,
        "taproot_merkle_root":material.taproot_merkle_root,
        "taproot_tree":material.taproot_tree,
        "cooperative_internal_key":material.internal_key,
        "cooperative_pubkeys":cooperative_test_pubkeys(),
        "exit_path":exit_path,
        "exit_condition":exit_condition,
        "exit_signing_pubkey":exit_signing_key,
        "exit_lock_value":exit_lock_value,
        "minimum_confirmations":"1",
        "replacement_policy":"reject"
        ,"zero_confirmation":"forbidden"
        ,"rbf_policy":"reject"
        ,"reorg_safety_blocks":"6"
    })
}

fn canonical_json_test(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => output.push_str(&serde_json::to_string(value).unwrap()),
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(value, output);
                }
                output.push(']');
            }
            Value::Object(values) => {
                output.push('{');
                let mut values = values.iter().collect::<Vec<_>>();
                values.sort_by(|left, right| left.0.cmp(right.0));
                for (index, (name, value)) in values.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(name).unwrap());
                    output.push(':');
                    write(value, output);
                }
                output.push('}');
            }
        }
    }
    let mut output = String::new();
    write(value, &mut output);
    output.into_bytes()
}

fn local_bitcoin_observation(
    request: &BitcoinObservationRequest,
    raw_transaction: &str,
    confirmations: u32,
    replacement_detected: bool,
    competing_spend_detected: bool,
) -> LocalBitcoinObservation {
    assert_eq!(
        request.transaction_template_sha256,
        lower_hex(&sha256(&decode_hex(raw_transaction)))
    );
    LocalBitcoinObservation {
        raw_transaction: raw_transaction.to_owned(),
        confirmations,
        replacement_detected,
        competing_spend_detected,
    }
}

fn contract_document(session: &SwapSession<AwaitingVerification>) -> Value {
    let event = session
        .signed_records()
        .iter()
        .find(|event| event.kind == 39_610)
        .unwrap();
    serde_json::from_str::<Value>(&event.content).unwrap()["mkt_swp"]["contract"].clone()
}

fn refresh_exit_template_digest(document: &mut Value) {
    let funding = &document["funding"];
    let mut previous_txid: [u8; 32] = decode_hex(funding["transaction_id"].as_str().unwrap())
        .try_into()
        .unwrap();
    previous_txid.reverse();
    let exit = &document["exit"];
    let amount = funding["amount"].as_str().unwrap().parse::<u64>().unwrap();
    let maximum_fee = exit["fee_policy"]["maximum_fee"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let transaction = Transaction::new(
        i32::try_from(exit["transaction_version"].as_i64().unwrap()).unwrap(),
        vec![TransactionInput {
            previous_txid,
            previous_output: u32::try_from(funding["output_index"].as_u64().unwrap()).unwrap(),
            script_sig: Vec::new(),
            sequence: u32::try_from(exit["input_sequence"].as_u64().unwrap()).unwrap(),
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: amount - maximum_fee,
            script_pubkey: decode_hex(exit["destination_script_pubkey"].as_str().unwrap()),
        }],
        u32::try_from(exit["lock_time"].as_u64().unwrap()).unwrap(),
    )
    .serialize(false)
    .unwrap();
    document["exit"]["transaction_template_sha256"] = json!(lower_hex(&sha256(&transaction)));
}

fn swap_name(swap_type: SwapType) -> &'static str {
    match swap_type {
        SwapType::Submarine => "submarine",
        SwapType::Reverse => "reverse",
        SwapType::Chain => "chain",
    }
}

fn fixture_string(fixture: &Value, name: &str) -> String {
    fixture["deterministic_session"][name]
        .as_str()
        .unwrap()
        .into()
}

fn lightning_ready(request: &LightningReadinessRequest) -> Result<LocalLightningReadiness, String> {
    Ok(LocalLightningReadiness {
        invoice_sha256: request.invoice_sha256.clone(),
        payment_hash: request.payment_hash.clone(),
        observed_at: request.invoice_expires_at.saturating_sub(1),
        state: LightningReadinessState::Acceptable,
    })
}

fn lightning_pending(request: &LightningProgressRequest) -> Result<LocalLightningProgress, String> {
    Ok(LocalLightningProgress {
        invoice_sha256: request.invoice_sha256.clone(),
        payment_hash: request.payment_hash.clone(),
        observed_at: 1,
        view_sha256: "ce".repeat(32),
        state: LightningProgressState::PaymentPending,
    })
}

fn tag_value_test<'a>(event: &'a immortal_client::domain::Event, name: &str) -> &'a str {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == Some(name))
        .and_then(|tag| tag.value())
        .unwrap()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-client-engine-v1.json"
    ))
    .unwrap()
}

fn verification_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-verification.json"
    ))
    .unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = match pair[0] {
                b'0'..=b'9' => pair[0] - b'0',
                b'a'..=b'f' => pair[0] - b'a' + 10,
                _ => panic!("fixture hex is invalid"),
            };
            let low = match pair[1] {
                b'0'..=b'9' => pair[1] - b'0',
                b'a'..=b'f' => pair[1] - b'a' + 10,
                _ => panic!("fixture hex is invalid"),
            };
            high << 4 | low
        })
        .collect()
}

fn browser_response(operation: &str, input: Value) -> Value {
    let request = serde_json::to_vec(&json!({
        "abi_version": 1,
        "operation": operation,
        "input": input
    }))
    .unwrap();
    serde_json::from_slice(&browser_api::dispatch(&request)).unwrap()
}

fn browser_result(operation: &str, input: Value) -> Value {
    let response = browser_response(operation, input);
    assert!(
        response.get("error").is_none(),
        "browser {operation} failed: {response}"
    );
    response["result"].clone()
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

fn test_signing_key(role: &[u8]) -> [u8; 32] {
    Sha256::digest([b"immortal-mkt-swp-test-only:".as_slice(), role].concat()).into()
}

fn exit_effect_id(order_id: &str, path: &str, leg_id: &str) -> String {
    let mut preimage = b"openagents.mkt-swp.v1".to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&decode_hex(order_id));
    preimage.push(0);
    preimage.extend_from_slice(format!("chain_{path}").as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(leg_id.as_bytes());
    lower_hex(&sha256(&preimage))
}

fn cooperative_effect_id(order_id: &str, leg_id: &str) -> String {
    let mut preimage = b"openagents.mkt-swp.v1".to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&decode_hex(order_id));
    preimage.push(0);
    preimage.extend_from_slice(b"cooperative_sign");
    preimage.push(0);
    preimage.extend_from_slice(leg_id.as_bytes());
    lower_hex(&sha256(&preimage))
}

fn even_key(bytes: [u8; 32]) -> (SecretKey, PublicKey) {
    let mut secret = SecretKey::from_byte_array(bytes).unwrap();
    let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
    if keypair.x_only_public_key().1 == Parity::Odd {
        secret = secret.negate();
    }
    let public = PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret);
    (secret, public)
}
