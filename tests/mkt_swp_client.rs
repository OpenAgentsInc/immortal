#![cfg(feature = "mkt-swp-verify")]

use std::collections::BTreeSet;

use immortal::{
    market::MarketSigner,
    mkt_swp_client::{
        AwaitingVerification, BitcoinObservationRequest, Cancellation, ChainRecoveryState,
        CloseOutcome, ExitPackage, ExternalEffectResult, FundingAction, FundingVerificationInput,
        InvoiceVerificationInput, KeylessEsploraExecutor, LocalBitcoinObservation,
        MktSigningRequest, ParticipantRole, QuotePolicy, RecoveryAction, RecoveryObservation,
        StatusState, SwapClientConfig, SwapContractReferences, SwapRecordFactory, SwapSession,
        SwapType, TimeoutLadder, VerifyBeforeFundInput,
    },
    mkt_swp_verify::{
        Transaction, TransactionInput, TransactionOutput, sha256, tapleaf_hash, taproot_output_key,
    },
};
use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};
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
        "flow_topologies",
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
    assert_eq!(names.len(), 63);
    assert!(names.contains("swp-v1-doomsday-submarine-provider-gone"));
    assert!(names.contains("swp-v1-doomsday-keyless-esplora-broadcast"));

    let tripwires = fixture["custody_tripwires"].as_array().unwrap();
    assert_eq!(tripwires.len(), 20);
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
            claim_ready: false,
            completed: false,
            record_loss: false,
            rail_state_unknown: false,
            chain_state: None,
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
fn reverse_and_chain_requester_flows_authorize_and_plan_recovery() {
    let fixture = fixture();
    for swap_type in [SwapType::Reverse, SwapType::Chain] {
        let session = build_session(&fixture, swap_type, true);
        let authorized = session
            .verify_before_fund(verification_input(&fixture, swap_type), |_| Ok(()))
            .unwrap();
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
            .recovery_action(&RecoveryObservation {
                counterparty_available: false,
                timeout_reached: true,
                claim_ready: swap_type == SwapType::Reverse,
                claim_observed: false,
                completed: false,
                record_loss: false,
                rail_state_unknown: false,
                chain_state: (swap_type == SwapType::Chain)
                    .then_some(ChainRecoveryState::DestinationClaimable),
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
        "input_amount":"120000",
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
    assert_eq!(
        authorized
            .sign_exit_with(1, |request| {
                Ok(add_signed_taproot_witness(
                    &claim_package,
                    &request.unsigned_transaction,
                    &request.signature_hash,
                    Some([0xff; 32]),
                ))
            })
            .unwrap_err()
            .code,
        "swp_external_signature_invalid"
    );

    let contract_ids = ["01".repeat(32), "02".repeat(32)];
    let mut premature_cltv = exit_document(
        &fixture,
        SwapType::Submarine,
        &"03".repeat(32),
        &"04".repeat(32),
        &contract_ids,
        &"05".repeat(32),
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
        &"03".repeat(32),
        &"04".repeat(32),
        &contract_ids,
        &"05".repeat(32),
        flow_exit_specs(SwapType::Chain)[0],
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
    let observation = |chain_state| RecoveryObservation {
        counterparty_available: false,
        timeout_reached: true,
        claim_ready: false,
        claim_observed: false,
        completed: false,
        record_loss: false,
        rail_state_unknown: false,
        chain_state: Some(chain_state),
    };
    assert!(matches!(
        session
            .recovery_action(&observation(ChainRecoveryState::DestinationClaimable))
            .unwrap(),
        RecoveryAction::RequestWalletClaim { .. }
    ));
    assert_eq!(
        session
            .recovery_action(&observation(ChainRecoveryState::DestinationFundedUnclaimed))
            .unwrap(),
        RecoveryAction::WaitForDestinationRefund
    );
    let source_effect = session.exit_packages()[0].effect_id().unwrap();
    assert_eq!(
        session
            .recovery_action(&observation(ChainRecoveryState::DestinationRefundedFinal))
            .unwrap(),
        RecoveryAction::BroadcastPresigned {
            effect_id: source_effect.to_owned()
        }
    );
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

    let mut no_rfq = session.signed_records().to_vec();
    no_rfq.retain(|event| event.kind != 39_604);
    let no_rfq = SwapSession::from_signed_records(
        session.config().clone(),
        no_rfq,
        session.exit_packages().to_vec(),
    )
    .unwrap();
    assert_eq!(
        no_rfq
            .verify_before_fund(
                verification_input(&fixture, SwapType::Submarine),
                |_| Ok(())
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
    assert_eq!(signed_exit.path, "refund");
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
    assert_eq!(signed_claim.path, "claim");

    let effect = ExternalEffectResult {
        effect_id: authorized
            .funding_request()
            .unwrap()
            .action
            .effect_id()
            .to_owned(),
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
                condition: "csv",
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
    let mut quote_profile = json!({"terms":terms});
    if let Some(selectable) = options.quote_selectable {
        quote_profile["selectable"] = selectable.clone();
    }
    let quote = signed(
        factory
            .quote(
                101,
                &"12".repeat(32),
                &rfq.id,
                options.quote_expiration,
                QuotePolicy {
                    quote_class: "firm",
                    reservation: "soft",
                },
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
    let package_seeds = flow_exit_specs(swap_type)
        .iter()
        .map(|spec| {
            let mode = options.exit_mode.unwrap_or(spec.mode);
            ExitPackage::parse(exit_document(
                fixture,
                swap_type,
                &order.id,
                &quote.id,
                &["01".repeat(32), "02".repeat(32)],
                &"03".repeat(32),
                *spec,
                mode,
            ))
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut contract = base_terms(fixture, swap_type);
    let object = contract.as_object_mut().unwrap();
    if let Some(selection) = options.contract_selection {
        object.insert("order_selection".into(), selection.clone());
        if let Some(input_amount) = selection.get("input_amount").and_then(Value::as_str) {
            object.insert("input_amount".into(), json!(input_amount));
            let input = input_amount.parse::<u64>().unwrap();
            object.insert("output_amount".into(), json!((input - 1_000).to_string()));
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
    object.insert("effect_bindings".into(), Value::Array(effect_bindings));
    let commitments = flow_exit_specs(swap_type)
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
        .collect();
    object.insert("exit_package_commitments".into(), Value::Array(commitments));
    object.insert("reservation_commitment".into(), json!({}));
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
    let exit_packages = if options.include_exit {
        flow_exit_specs(swap_type)
            .iter()
            .map(|spec| {
                ExitPackage::parse(exit_document(
                    fixture,
                    swap_type,
                    &order.id,
                    &quote.id,
                    &[requester_contract.id.clone(), provider_contract.id.clone()],
                    contract_sha256,
                    *spec,
                    options.exit_mode.unwrap_or(spec.mode),
                ))
                .unwrap()
            })
            .collect()
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
    let mut verifier_inputs = flow_exit_specs(swap_type)
        .iter()
        .map(|spec| bitcoin_verifier(&exit_material(&payment_hash, *spec), *spec))
        .collect::<Vec<_>>();
    if !matches!(swap_type, SwapType::Chain) {
        verifier_inputs.push(json!({
            "leg_id":"lightning",
            "invoice_sha256": lower_hex(&sha256(fixture_string(fixture, "invoice").as_bytes())),
            "invoice_amount_msat": deterministic["invoice_amount_msat"],
            "invoice_network":"bitcoin",
            "invoice_expiry_seconds":deterministic["invoice_expiry_seconds"].to_string(),
            "invoice_minimum_final_cltv_delta":deterministic["invoice_minimum_final_cltv_delta"].to_string()
        }));
    }
    let legs = match swap_type {
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
    json!({
        "swap_type":swap_name(swap_type),
        "asset_pair":asset_pair,
        "payment_hash":payment_hash,
        "input_amount":"100000",
        "output_amount":"99000",
        "fee_bps":"100",
        "provider_fee":"1000",
        "miner_fee_budget":"0",
        "lightning_routing_fee_budget":"0",
        "amount_equation":"input_minus_provider_and_quoted_fees",
        "legs":legs,
        "timeout_ladder":timeout_ladder(swap_type),
        "verifier_inputs":verifier_inputs,
        "recovery":{"channel":"direct_or_relay_agnostic"},
        "evm_leg":null
    })
}

fn verification_input(fixture: &Value, swap_type: SwapType) -> VerifyBeforeFundInput {
    let deterministic = &fixture["deterministic_session"];
    let payment_hash = flow_payment_hash(fixture, swap_type);
    let verifier_spec = match swap_type {
        SwapType::Submarine | SwapType::Chain => flow_exit_specs(swap_type)[0],
        SwapType::Reverse => flow_exit_specs(swap_type)[0],
    };
    let material = exit_material(&payment_hash, verifier_spec);
    VerifyBeforeFundInput {
        payment_hash,
        funding: FundingVerificationInput {
            raw_transaction: material.funding_transaction,
            output_index: 0,
            expected_amount: "100000".into(),
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
    swap_type: SwapType,
    order_id: &str,
    quote_id: &str,
    contract_ids: &[String; 2],
    contract_sha256: &str,
    spec: ExitSpec,
    mode: &str,
) -> Value {
    let deterministic = &fixture["deterministic_session"];
    let payment_hash = flow_payment_hash(fixture, swap_type);
    let material = exit_material(&payment_hash, spec);
    let funding = Transaction::parse(&decode_hex(&material.funding_transaction)).unwrap();
    let funding_txid = lower_hex(&funding.txid().unwrap());
    let mut txid_wire = funding.txid().unwrap();
    txid_wire.reverse();
    let maximum_fee = 1_000_u64;
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
            value_sat: 100_000 - maximum_fee,
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
        "order_id":order_id,
        "swap_contract_ids":contract_ids,
        "contract_sha256":contract_sha256,
        "participant_role":"requester",
        "leg_id":spec.leg_id,
        "network_id":network_id,
        "asset_id":asset_id,
        "effect_id":exit_effect_id(order_id, spec.path, spec.leg_id),
        "funding":{
            "transaction_id":funding_txid,
            "transaction_template_sha256":lower_hex(&sha256(&decode_hex(&material.funding_transaction))),
            "output_index":0,
            "amount":"100000",
            "script_pubkey":format!("5120{}", material.output_key),
            "confirmation_policy_sha256":"44".repeat(32)
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
            "fee_policy":{"target_blocks":2,"maximum_fee":"1000","bump_mode":"cpfp"}
        },
        "verification":{
            "swap_tree_sha256":"55".repeat(32),
            "quote_id":quote_id,
            "verifier_digest":"66".repeat(32),
            "taproot_script":material.script,
            "taproot_control_block":material.control_block
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

fn signed(request: MktSigningRequest, signer: &MarketSigner) -> immortal::domain::Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).unwrap()
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
    output_key: String,
    script: String,
    control_block: String,
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

fn exit_material(payment_hash: &str, spec: ExitSpec) -> ExitMaterial {
    let signer_label = format!("exit:{}:{}", spec.leg_id, spec.path);
    let signer_secret =
        SecretKey::from_byte_array(test_signing_key(signer_label.as_bytes())).unwrap();
    let signer_keypair = Keypair::from_secret_key(&Secp256k1::new(), &signer_secret);
    let signer_key = signer_keypair.x_only_public_key().0.serialize();
    let mut script = Vec::new();
    match spec.condition {
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

    let internal_label = format!("internal:{}:{}", spec.leg_id, spec.path);
    let internal_secret =
        SecretKey::from_byte_array(test_signing_key(internal_label.as_bytes())).unwrap();
    let internal_keypair = Keypair::from_secret_key(&Secp256k1::new(), &internal_secret);
    let internal_key = internal_keypair.x_only_public_key().0;
    let leaf_hash = tapleaf_hash(0xc0, &script).unwrap();
    let (output_key, parity) = taproot_output_key(internal_key, Some(leaf_hash)).unwrap();
    let mut control_block = vec![0xc0 | u8::from(parity == Parity::Odd)];
    control_block.extend_from_slice(&internal_key.serialize());

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
            value_sat: 100_000,
            script_pubkey: [vec![0x51, 0x20], output_key.serialize().to_vec()].concat(),
        }],
        0,
    )
    .serialize(false)
    .unwrap();
    ExitMaterial {
        funding_transaction: lower_hex(&funding),
        output_key: lower_hex(&output_key.serialize()),
        script: lower_hex(&script),
        control_block: lower_hex(&control_block),
    }
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
    json!({
        "leg_id":spec.leg_id,
        "funding_transaction_sha256":lower_hex(&sha256(&decode_hex(&material.funding_transaction))),
        "output_index":0,
        "amount":"100000",
        "script_pubkey":format!("5120{}", material.output_key),
        "taproot_output_key":material.output_key,
        "taproot_script":material.script,
        "taproot_control_block":material.control_block,
        "minimum_confirmations":"1",
        "replacement_policy":"reject"
    })
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
