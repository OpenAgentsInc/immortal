#![cfg(feature = "mkt-swp-verify")]

use std::collections::BTreeSet;

use immortal::{
    market::MarketSigner,
    mkt_swp_client::{
        AwaitingVerification, Cancellation, CloseOutcome, ExitPackage, ExternalEffectResult,
        FundingVerificationInput, InvoiceVerificationInput, KeylessEsploraExecutor,
        MktSigningRequest, ParticipantRole, QuotePolicy, RecoveryAction, RecoveryObservation,
        StatusState, SwapClientConfig, SwapContractReferences, SwapRecordFactory, SwapSession,
        SwapType, TimeoutLadder, VerifyBeforeFundInput,
    },
    mkt_swp_verify::{Transaction, TransactionInput, TransactionOutput, sha256},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[test]
fn fixture_manifest_is_complete_and_unique() {
    let fixture = fixture();
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
        "verify_before_fund",
        "sequencing",
        "external_effects",
        "recovery",
    ] {
        for case in fixture[section].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert!(names.insert(name), "duplicate client case {name}");
        }
    }
    assert_eq!(names.len(), 45);
    assert!(names.contains("swp-v1-doomsday-submarine-provider-gone"));
    assert!(names.contains("swp-v1-doomsday-keyless-esplora-broadcast"));

    let tripwires = fixture["custody_tripwires"].as_array().unwrap();
    assert_eq!(tripwires.len(), 10);
    let members = tripwires
        .iter()
        .map(|case| case["member"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(members.len(), tripwires.len());
}

#[test]
fn submarine_fixture_enforces_verify_before_fund_and_external_signing() {
    let fixture = fixture();
    let mut session = build_session(&fixture, SwapType::Submarine, true);
    let authorization = session
        .verify_before_fund(
            verification_input(&fixture, SwapType::Submarine),
            |request| {
                assert_eq!(request.swap_type, SwapType::Submarine);
                assert_eq!(
                    request.raw_transaction,
                    fixture_string(&fixture, "funding_transaction")
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
            .quote(
                101,
                &"02".repeat(32),
                &rfq.id,
                1_000,
                QuotePolicy {
                    quote_class: "firm",
                    reservation: "soft",
                },
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
    assert_eq!(
        request.verify_signed(changed).unwrap_err().code,
        "swp_external_signature_mismatch"
    );
}

#[test]
fn doomsday_snapshot_builds_keyless_esplora_request() {
    let fixture = fixture();
    let session = build_session(&fixture, SwapType::Submarine, true);
    let snapshot = session.persist().unwrap();
    let restored = SwapSession::<AwaitingVerification>::restore(&snapshot).unwrap();
    let action = restored
        .recovery_action(&RecoveryObservation {
            counterparty_available: false,
            timeout_reached: true,
            claim_observed: false,
            completed: false,
            record_loss: false,
            rail_state_unknown: false,
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
fn reverse_and_chain_requester_flows_authorize_and_plan_recovery() {
    let fixture = fixture();
    for swap_type in [SwapType::Reverse, SwapType::Chain] {
        let session = build_session(&fixture, swap_type, true);
        let authorized = session
            .verify_before_fund(verification_input(&fixture, swap_type), |_| Ok(()))
            .unwrap();
        assert_eq!(authorized.funding_request().unwrap().swap_type, swap_type);
        let action = authorized
            .recovery_action(&RecoveryObservation {
                counterparty_available: false,
                timeout_reached: true,
                claim_observed: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
            })
            .unwrap();
        if swap_type == SwapType::Reverse {
            assert!(matches!(action, RecoveryAction::BroadcastPresigned { .. }));
        } else {
            assert!(matches!(
                action,
                RecoveryAction::OrderedUnilateralExits { .. }
            ));
        }
    }
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

    let mut confirmations = verification_input(&fixture, SwapType::Submarine);
    confirmations.funding.confirmations = 0;
    assert_eq!(
        session
            .clone()
            .verify_before_fund(confirmations, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_confirmation_insufficient"
    );

    let mut replacement = verification_input(&fixture, SwapType::Submarine);
    replacement.funding.replacement_detected = true;
    assert_eq!(
        session
            .clone()
            .verify_before_fund(replacement, |_| Ok(()))
            .unwrap_err()
            .code,
        "swp_rbf_policy_violation"
    );

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
    amountless.invoice.as_mut().unwrap().invoice =
        serde_json::from_str::<Value>(include_str!("fixtures/nipmkt/swp-verification.json"))
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
                    previous: Some(&first.id),
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
    let mut regression_records = base.signed_records().to_vec();
    regression_records.extend([first, regression]);
    assert_eq!(
        SwapSession::from_signed_records(
            base.config().clone(),
            regression_records,
            base.exit_packages().to_vec(),
        )
        .unwrap_err()
        .code,
        "swp_status_transition_invalid"
    );
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
    let signed_exit = authorized
        .sign_exit_with(0, |request| {
            Ok(add_single_witness(&decode_hex(
                &request.unsigned_transaction,
            )))
        })
        .unwrap();
    assert_eq!(signed_exit.path, "refund");

    let claim_session = build_session_path_mode(
        &fixture,
        SwapType::Reverse,
        "claim",
        Some("external_signer"),
    );
    let claim_authorized = claim_session
        .verify_before_fund(verification_input(&fixture, SwapType::Reverse), |_| Ok(()))
        .unwrap();
    let signed_claim = claim_authorized
        .sign_exit_with(0, |request| {
            Ok(add_single_witness(&decode_hex(
                &request.unsigned_transaction,
            )))
        })
        .unwrap();
    assert_eq!(signed_claim.path, "claim");

    let effect = ExternalEffectResult {
        effect_id: authorized
            .funding_request()
            .unwrap()
            .funding_effect_id
            .clone(),
        request_sha256: "77".repeat(32),
        external_identifier: "regtest:funding:0".into(),
        result_sha256: "88".repeat(32),
    };
    assert_eq!(
        authorized.record_external_effect(effect.clone()).unwrap(),
        &effect
    );
    assert_eq!(
        authorized.record_external_effect(effect.clone()).unwrap(),
        &effect
    );
    let mut conflict = effect;
    conflict.result_sha256 = "99".repeat(32);
    assert_eq!(
        authorized
            .record_external_effect(conflict)
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
}

struct Setup {
    config: SwapClientConfig,
    requester: MarketSigner,
    provider: MarketSigner,
}

impl Setup {
    fn new(fixture: &Value) -> Self {
        let deterministic = &fixture["deterministic_session"];
        let requester_byte = deterministic["requester_secret_byte"].as_u64().unwrap() as u8;
        let provider_byte = deterministic["provider_secret_byte"].as_u64().unwrap() as u8;
        let requester = MarketSigner::from_secret_bytes([requester_byte; 32]).unwrap();
        let provider = MarketSigner::from_secret_bytes([provider_byte; 32]).unwrap();
        let config = SwapClientConfig {
            session_id: deterministic["session_id"].as_str().unwrap().into(),
            requester_pubkey: requester.pubkey().into(),
            provider_pubkey: provider.pubkey().into(),
            offering_address: format!(
                "39601:{}:{}",
                provider.pubkey(),
                deterministic["offering_id"].as_str().unwrap()
            ),
        };
        Self {
            config,
            requester,
            provider,
        }
    }
}

fn build_session(
    fixture: &Value,
    swap_type: SwapType,
    include_exit: bool,
) -> SwapSession<AwaitingVerification> {
    build_session_mode(fixture, swap_type, include_exit.then_some("presigned"))
}

fn build_session_mode(
    fixture: &Value,
    swap_type: SwapType,
    exit_mode: Option<&str>,
) -> SwapSession<AwaitingVerification> {
    build_session_path_mode(fixture, swap_type, "refund", exit_mode)
}

fn build_session_path_mode(
    fixture: &Value,
    swap_type: SwapType,
    exit_path: &str,
    exit_mode: Option<&str>,
) -> SwapSession<AwaitingVerification> {
    let setup = Setup::new(fixture);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed(
        factory
            .rfq(
                100,
                &"11".repeat(32),
                1_000,
                json!({"swap_type":swap_name(swap_type)}),
            )
            .unwrap(),
        &setup.requester,
    );
    let terms = base_terms(fixture, swap_type);
    let quote = signed(
        factory
            .quote(
                101,
                &"12".repeat(32),
                &rfq.id,
                1_000,
                QuotePolicy {
                    quote_class: "firm",
                    reservation: "soft",
                },
                json!({"terms":terms}),
            )
            .unwrap(),
        &setup.provider,
    );
    let order = signed(
        factory
            .order(
                102,
                &"13".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .unwrap(),
        &setup.requester,
    );
    let package_seed = exit_document(
        fixture,
        &order.id,
        &quote.id,
        &["01".repeat(32), "02".repeat(32)],
        &"03".repeat(32),
        exit_path,
        exit_mode.unwrap_or("presigned"),
    );
    let package = ExitPackage::parse(package_seed).unwrap();
    let package_digest = package.commitment_sha256().unwrap();
    let mut contract = base_terms(fixture, swap_type);
    let object = contract.as_object_mut().unwrap();
    object.insert("order_id".into(), Value::String(order.id.clone()));
    object.insert("quote_id".into(), Value::String(quote.id.clone()));
    object.insert(
        "effect_bindings".into(),
        json!([{"role":"chain_fund","leg_id":"source"}]),
    );
    object.insert(
        "exit_package_commitments".into(),
        json!([{
            "participant_role":"requester",
            "leg_id":"source",
            "path":exit_path,
            "package_sha256":package_digest
        }]),
    );
    object.insert("reservation_commitment".into(), json!({}));
    let requester_contract = signed(
        factory
            .swap_contract(
                ParticipantRole::Requester,
                103,
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
                104,
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
    let exit_packages = if let Some(exit_mode) = exit_mode {
        vec![
            ExitPackage::parse(exit_document(
                fixture,
                &order.id,
                &quote.id,
                &[requester_contract.id.clone(), provider_contract.id.clone()],
                contract_sha256,
                exit_path,
                exit_mode,
            ))
            .unwrap(),
        ]
    } else {
        Vec::new()
    };
    SwapSession::from_signed_records(
        setup.config,
        vec![rfq, quote, order, requester_contract, provider_contract],
        exit_packages,
    )
    .unwrap()
}

fn base_terms(fixture: &Value, swap_type: SwapType) -> Value {
    let deterministic = &fixture["deterministic_session"];
    let (asset_pair, invoice_fields) = match swap_type {
        SwapType::Submarine => (
            json!([
                deterministic["chain_asset_a"],
                deterministic["lightning_asset_a"]
            ]),
            json!({
                "invoice_sha256": lower_hex(&sha256(fixture_string(fixture, "invoice").as_bytes())),
                "invoice_amount_msat": deterministic["invoice_amount_msat"],
                "invoice_network": "bitcoin"
            }),
        ),
        SwapType::Reverse => (
            json!([
                deterministic["lightning_asset_a"],
                deterministic["chain_asset_a"]
            ]),
            json!({
                "invoice_sha256": lower_hex(&sha256(fixture_string(fixture, "invoice").as_bytes())),
                "invoice_amount_msat": deterministic["invoice_amount_msat"],
                "invoice_network": "bitcoin"
            }),
        ),
        SwapType::Chain => (
            json!([
                deterministic["chain_asset_a"],
                deterministic["chain_asset_b"]
            ]),
            json!({}),
        ),
    };
    let raw_funding = decode_hex(&fixture_string(fixture, "funding_transaction"));
    let mut verifier = json!({
        "leg_id":"source",
        "funding_transaction_sha256":lower_hex(&sha256(&raw_funding)),
        "output_index":deterministic["funding_output_index"],
        "amount":deterministic["funding_amount"],
        "script_pubkey":format!("5120{}", fixture_string(fixture, "taproot_output_key")),
        "taproot_output_key":deterministic["taproot_output_key"],
        "taproot_script":deterministic["taproot_script"],
        "taproot_control_block":deterministic["taproot_control_block"],
        "minimum_confirmations":"1",
        "replacement_policy":"reject"
    });
    verifier
        .as_object_mut()
        .unwrap()
        .extend(invoice_fields.as_object().unwrap().clone());
    json!({
        "swap_type":swap_name(swap_type),
        "asset_pair":asset_pair,
        "payment_hash":deterministic["payment_hash"],
        "legs":[{"leg_id":"source","rail":"bitcoin"}],
        "timeout_ladder":timeout_ladder(swap_type),
        "verifier_inputs":[verifier],
        "recovery":{"channel":"direct_or_relay_agnostic"},
        "evm_leg":null
    })
}

fn verification_input(fixture: &Value, swap_type: SwapType) -> VerifyBeforeFundInput {
    let deterministic = &fixture["deterministic_session"];
    VerifyBeforeFundInput {
        payment_hash: deterministic["payment_hash"].as_str().unwrap().into(),
        funding: FundingVerificationInput {
            raw_transaction: deterministic["funding_transaction"]
                .as_str()
                .unwrap()
                .into(),
            output_index: deterministic["funding_output_index"].as_u64().unwrap() as u32,
            expected_amount: deterministic["funding_amount"].as_str().unwrap().into(),
            expected_script_pubkey: format!(
                "5120{}",
                deterministic["taproot_output_key"].as_str().unwrap()
            ),
            taproot_output_key: deterministic["taproot_output_key"].as_str().unwrap().into(),
            taproot_script: deterministic["taproot_script"].as_str().unwrap().into(),
            taproot_control_block: deterministic["taproot_control_block"]
                .as_str()
                .unwrap()
                .into(),
            confirmations: 1,
            replacement_detected: false,
        },
        invoice: (!matches!(swap_type, SwapType::Chain)).then(|| InvoiceVerificationInput {
            invoice: deterministic["invoice"].as_str().unwrap().into(),
            expected_network: "bitcoin".into(),
            expected_amount_msat: deterministic["invoice_amount_msat"]
                .as_str()
                .unwrap()
                .into(),
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
            lock_last: 110,
            user_claim_last: 120,
            provider_refund_first: 140,
            hold_expiry_height: 160,
            chain_finality_blocks: 1,
            broadcast_safety_blocks: 2,
            reorg_safety_blocks: 6,
            lightning_settlement_blocks: 6,
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

fn timeout_ladder(swap_type: SwapType) -> Value {
    serde_json::to_value(ladder(swap_type)).unwrap()
}

fn exit_document(
    fixture: &Value,
    order_id: &str,
    quote_id: &str,
    contract_ids: &[String; 2],
    contract_sha256: &str,
    path: &str,
    mode: &str,
) -> Value {
    let deterministic = &fixture["deterministic_session"];
    let funding =
        Transaction::parse(&decode_hex(&fixture_string(fixture, "funding_transaction"))).unwrap();
    let funding_txid = lower_hex(&funding.txid().unwrap());
    let mut txid_wire = funding.txid().unwrap();
    txid_wire.reverse();
    let maximum_fee = 1_000_u64;
    let unsigned = Transaction::new(
        2,
        vec![TransactionInput {
            previous_txid: txid_wire,
            previous_output: 0,
            script_sig: Vec::new(),
            sequence: 0,
            witness: Vec::new(),
        }],
        vec![TransactionOutput {
            value_sat: 100_000 - maximum_fee,
            script_pubkey: decode_hex(deterministic["destination_script_pubkey"].as_str().unwrap()),
        }],
        140,
    )
    .serialize(false)
    .unwrap();
    let signed = add_single_witness(&unsigned);
    let (signed_transaction, signer_ref) = if mode == "presigned" {
        (Value::String(lower_hex(&signed)), Value::Null)
    } else {
        (Value::Null, Value::String(format!("wallet:{path}")))
    };
    json!({
        "schema":"openagents.mkt-swp.exit.v1",
        "profile":"mkt-swp",
        "profile_version":1,
        "order_id":order_id,
        "swap_contract_ids":contract_ids,
        "contract_sha256":contract_sha256,
        "participant_role":"requester",
        "leg_id":"source",
        "network_id":deterministic["network_a"],
        "asset_id":deterministic["chain_asset_a"],
        "effect_id":lower_hex(&Sha256::digest(format!("{path}-effect").as_bytes())),
        "funding":{
            "transaction_id":funding_txid,
            "transaction_template_sha256":lower_hex(&sha256(&decode_hex(&fixture_string(fixture, "funding_transaction")))),
            "output_index":0,
            "amount":"100000",
            "script_pubkey":format!("5120{}", deterministic["taproot_output_key"].as_str().unwrap()),
            "confirmation_policy_sha256":"44".repeat(32)
        },
        "exit":{
            "mode":mode,
            "path":path,
            "transaction_template_sha256":lower_hex(&sha256(&unsigned)),
            "signed_transaction":signed_transaction,
            "signer_ref":signer_ref,
            "transaction_version":2,
            "lock_time":140,
            "input_sequence":0,
            "sighash_type":"DEFAULT",
            "destination_script_pubkey":deterministic["destination_script_pubkey"],
            "earliest_broadcast_height":"140",
            "latest_safe_broadcast_height":"200",
            "fee_policy":{"target_blocks":2,"maximum_fee":"1000","bump_mode":"cpfp"}
        },
        "verification":{
            "swap_tree_sha256":"55".repeat(32),
            "quote_id":quote_id,
            "verifier_digest":"66".repeat(32)
        },
        "secret_commitments":{
            "payment_hash":deterministic["payment_hash"],
            "preimage_recovery_ref":null
        },
        "broadcast":{
            "esplora_urls":["https://esplora.example/api"],
            "minimum_agreeing_sources":1
        }
    })
}

fn signed(request: MktSigningRequest, signer: &MarketSigner) -> immortal::domain::Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).unwrap()
}

fn add_single_witness(unsigned: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(unsigned.len() + 5);
    signed.extend_from_slice(&unsigned[..4]);
    signed.extend_from_slice(&[0, 1]);
    signed.extend_from_slice(&unsigned[4..unsigned.len() - 4]);
    signed.extend_from_slice(&[1, 1, 1]);
    signed.extend_from_slice(&unsigned[unsigned.len() - 4..]);
    signed
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

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipmkt/swp-client-engine-v1.json")).unwrap()
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
