use std::cell::Cell;

use immortal_client::mkt_swp_client::{
    Cancellation, CloseOutcome, MktSigningRequest, ParticipantRole, StatusState, SwapClientConfig,
    SwapContractReferences, SwapRecordFactory, SwapSession,
};
use immortal_core::{domain::Event, market::MarketSigner};
use immortal_provider::{
    MktPublicSigningRequest, ProviderDiscoveryFactory, ProviderEffectReceipt,
    ProviderEffectRequest, ProviderSession, ReservationConfirmation, ReservationReleaseCause,
    ReservationRequest, session::fixture_replay,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

struct Setup {
    requester: MarketSigner,
    provider: MarketSigner,
    config: SwapClientConfig,
}

impl Setup {
    fn new(session_byte: u8) -> Self {
        let requester = MarketSigner::from_secret_bytes([1; 32]).expect("requester key");
        let provider = MarketSigner::from_secret_bytes([2; 32]).expect("provider key");
        let config = SwapClientConfig {
            session_id: format!("{session_byte:02x}").repeat(32),
            requester_pubkey: requester.pubkey().into(),
            provider_pubkey: provider.pubkey().into(),
            offering_address: format!("39601:{}:regtest-swaps", provider.pubkey()),
            provider_route: None,
        };
        Self {
            requester,
            provider,
            config,
        }
    }
}

#[test]
fn provider_fixture_manifest_is_closed_and_embedded() {
    assert_eq!(fixture_replay::replay_embedded_manifest().unwrap(), 30);
}

#[test]
fn quote_constructors_reject_rfq_mismatch_before_reserving() {
    let setup = Setup::new(0xab);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed_private(
        factory
            .rfq(
                100,
                &"31".repeat(32),
                300,
                complete_rfq_profile("submarine"),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    provider.ingest_signed(rfq).unwrap();
    assert_eq!(
        provider
            .soft_quote(
                101,
                &"32".repeat(32),
                300,
                complete_quote_profile("reverse"),
            )
            .unwrap_err()
            .code,
        "swp_contract_terms_mismatch"
    );
    let reserve_calls = Cell::new(0);
    let reservation = ReservationRequest {
        reservation_id: "33".repeat(32),
        capacity_bucket_id: "reverse-output".into(),
        reserved_asset_id: asset(&network(0), "chain"),
        reserved_amount: "890".into(),
        reservation_expires_at: 250,
    };
    assert_eq!(
        provider
            .hard_quote_with_reserve(
                101,
                &"34".repeat(32),
                300,
                reservation,
                complete_unreserved_quote_profile("reverse"),
                |_| {
                    reserve_calls.set(reserve_calls.get() + 1);
                    Err("must not reserve".into())
                },
            )
            .unwrap_err()
            .code,
        "swp_contract_terms_mismatch"
    );
    assert_eq!(reserve_calls.get(), 0);

    let setup = Setup::new(0xac);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let mut rfq_profile = complete_rfq_profile("submarine");
    rfq_profile["constraints"]["firm_quote_required"] = Value::Bool(false);
    let rfq = signed_private(
        factory
            .rfq(100, &"35".repeat(32), 300, rfq_profile)
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config).unwrap();
    provider.ingest_signed(rfq).unwrap();
    assert_eq!(
        provider
            .indicative_quote(
                101,
                &"36".repeat(32),
                300,
                complete_unreserved_quote_profile("reverse"),
            )
            .unwrap_err()
            .code,
        "swp_contract_terms_mismatch"
    );
}

#[test]
fn provider_fixture_replay_rejects_name_action_and_expectation_drift() {
    let source = include_str!("../../../tests/fixtures/nipmkt/swp-provider-engine-v1.json");
    for (collection, index, member, value) in [
        ("flows", 0, "name", json!("swp-v1-provider-renamed")),
        ("reservation_effects", 0, "operation", json!("release")),
        (
            "reservation_effects",
            1,
            "error",
            json!("swp_reservation_confirmation_invalid"),
        ),
    ] {
        let mut manifest: Value = serde_json::from_str(source).unwrap();
        manifest[collection][index][member] = value;
        let mutated = serde_json::to_string(&manifest).unwrap();
        assert_eq!(
            fixture_replay::replay_manifest(&mutated).unwrap_err().code,
            "swp_provider_fixture_invalid"
        );
    }
}

#[test]
fn provider_discovery_requests_support_nip01_rotation() {
    let setup = Setup::new(0xaa);
    let factory = ProviderDiscoveryFactory::new(setup.provider.pubkey()).unwrap();
    let profile = signed_public(
        factory
            .profile(
                100,
                "regtest-provider",
                "active",
                json!({"name":"Regtest swap provider"}),
            )
            .unwrap(),
        &setup.provider,
    );
    let rotated_profile = signed_public(
        factory
            .profile(
                101,
                "regtest-provider",
                "paused",
                json!({"name":"Regtest swap provider"}),
            )
            .unwrap(),
        &setup.provider,
    );
    assert_eq!(tag(&profile, "d"), tag(&rotated_profile, "d"));
    assert_ne!(profile.id, rotated_profile.id);

    let offering = signed_public(
        factory
            .offering(
                102,
                "regtest-provider",
                "regtest-swaps",
                "active",
                offering_content("available"),
            )
            .unwrap(),
        &setup.provider,
    );
    let rotated_offering = signed_public(
        factory
            .offering(
                103,
                "regtest-provider",
                "regtest-swaps",
                "paused",
                offering_content("limited"),
            )
            .unwrap(),
        &setup.provider,
    );
    assert_eq!(tag(&offering, "d"), tag(&rotated_offering, "d"));
    assert_ne!(offering.id, rotated_offering.id);
}

#[test]
fn hard_quote_requires_confirmed_reserve_and_replays_effects() {
    let setup = Setup::new(0xbb);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed_private(
        factory
            .rfq(
                100,
                &"01".repeat(32),
                300,
                complete_rfq_profile("submarine"),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    assert!(provider.ingest_signed(rfq).unwrap());

    let reservation = ReservationRequest {
        reservation_id: "02".repeat(32),
        capacity_bucket_id: "lightning-outbound".into(),
        reserved_asset_id: asset(&network(0), "lightning"),
        reserved_amount: "1000".into(),
        reservation_expires_at: 250,
    };
    let rejected = provider
        .hard_quote_with_reserve(
            101,
            &"03".repeat(32),
            200,
            reservation.clone(),
            complete_unreserved_quote_profile("submarine"),
            |_| Err("inventory unavailable".into()),
        )
        .unwrap_err();
    assert_eq!(rejected.code, "swp_reservation_unconfirmed");
    assert!(provider.reservation().is_none());

    let reserve_calls = Cell::new(0);
    let mut wrong_asset = reservation.clone();
    wrong_asset.reserved_asset_id = asset(&network(0), "chain");
    assert_eq!(
        provider
            .hard_quote_with_reserve(
                101,
                &"03".repeat(32),
                200,
                wrong_asset,
                complete_unreserved_quote_profile("submarine"),
                |_| {
                    reserve_calls.set(reserve_calls.get() + 1);
                    Err("must not reserve".into())
                },
            )
            .unwrap_err()
            .code,
        "swp_contract_terms_mismatch"
    );
    assert_eq!(reserve_calls.get(), 0);
    assert!(
        provider
            .hard_quote_with_reserve(
                101,
                "invalid-distinct",
                200,
                reservation.clone(),
                complete_unreserved_quote_profile("submarine"),
                |_| {
                    reserve_calls.set(reserve_calls.get() + 1);
                    Err("must not reserve".into())
                },
            )
            .is_err()
    );
    assert_eq!(reserve_calls.get(), 0);

    let reserve_calls = Cell::new(0);
    let mut reserve = |request: &ProviderEffectRequest| {
        reserve_calls.set(reserve_calls.get() + 1);
        Ok(ReservationConfirmation {
            reservation_id: request.reservation_id.clone(),
            capacity_bucket_id: request.capacity_bucket_id.clone(),
            reserved_asset_id: request.reserved_asset_id.clone(),
            reserved_amount: request.reserved_amount.clone(),
            committed_capacity: "5000".into(),
            reservation_expires_at: request.reservation_expires_at,
            allocation_sequence: "1".into(),
            proof_class: "lightning_liquidity".into(),
            proof_ref: "node-view:outbound:1".into(),
            capacity_commitment_sha256: "04".repeat(32),
        })
    };
    let quote_request = provider
        .hard_quote_with_reserve(
            101,
            &"03".repeat(32),
            200,
            reservation.clone(),
            complete_unreserved_quote_profile("submarine"),
            &mut reserve,
        )
        .unwrap();
    let replay = provider
        .hard_quote_with_reserve(
            101,
            &"03".repeat(32),
            200,
            reservation.clone(),
            complete_unreserved_quote_profile("submarine"),
            &mut reserve,
        )
        .unwrap();
    assert_eq!(reserve_calls.get(), 1);
    assert_eq!(quote_request, replay);
    let distinct_error = provider
        .hard_quote_with_reserve(
            102,
            &"06".repeat(32),
            200,
            reservation,
            complete_unreserved_quote_profile("submarine"),
            &mut reserve,
        )
        .unwrap_err();
    assert_eq!(distinct_error.code, "swp_idempotency_conflict");
    assert_eq!(reserve_calls.get(), 1);
    let quote = signed_private(quote_request, &setup.provider);
    provider.ingest_signed(quote.clone()).unwrap();
    let order = signed_private(
        factory
            .order(
                103,
                &"07".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(order).unwrap();
    assert_eq!(
        provider
            .provider_close(
                104,
                &"08".repeat(32),
                CloseOutcome {
                    outcome: "failed",
                    terminal_at: 104,
                },
                json!({"final_state":"failed"}),
            )
            .unwrap_err()
            .code,
        "swp_reservation_release_invalid"
    );

    let snapshot = provider.persist().unwrap();
    let mut restored = ProviderSession::restore(&snapshot).unwrap();
    let release_calls = Cell::new(0);
    let mut release = |request: &ProviderEffectRequest| {
        release_calls.set(release_calls.get() + 1);
        Ok(ProviderEffectReceipt {
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            external_reference: "inventory-release:1".into(),
            result_sha256: "05".repeat(32),
        })
    };
    let first = restored
        .release_reservation(
            ReservationReleaseCause::ReservationExpired,
            250,
            &mut release,
        )
        .unwrap();
    let second = restored
        .release_reservation(
            ReservationReleaseCause::ReservationExpired,
            250,
            &mut release,
        )
        .unwrap();
    assert_eq!(release_calls.get(), 1);
    assert_eq!(first, second);
    assert!(restored.reservation_released());
    ProviderSession::restore(&restored.persist().unwrap()).unwrap();
}

#[test]
fn snapshot_release_flag_requires_a_matching_durable_effect() {
    let setup = Setup::new(0xbc);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed_private(
        factory
            .rfq(
                100,
                &"41".repeat(32),
                300,
                complete_rfq_profile("submarine"),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config).unwrap();
    provider.ingest_signed(rfq).unwrap();
    let reservation = ReservationRequest {
        reservation_id: "42".repeat(32),
        capacity_bucket_id: "lightning-outbound".into(),
        reserved_asset_id: asset(&network(0), "lightning"),
        reserved_amount: "1000".into(),
        reservation_expires_at: 300,
    };
    provider
        .hard_quote_with_reserve(
            101,
            &"43".repeat(32),
            300,
            reservation,
            complete_unreserved_quote_profile("submarine"),
            |request| {
                Ok(ReservationConfirmation {
                    reservation_id: request.reservation_id.clone(),
                    capacity_bucket_id: request.capacity_bucket_id.clone(),
                    reserved_asset_id: request.reserved_asset_id.clone(),
                    reserved_amount: request.reserved_amount.clone(),
                    committed_capacity: request.reserved_amount.clone(),
                    reservation_expires_at: request.reservation_expires_at,
                    allocation_sequence: "1".into(),
                    proof_class: "lightning_liquidity".into(),
                    proof_ref: "node-view:outbound:flag".into(),
                    capacity_commitment_sha256: "44".repeat(32),
                })
            },
        )
        .unwrap();
    let mut snapshot: Value = serde_json::from_slice(&provider.persist().unwrap()).unwrap();
    snapshot["released"] = Value::Bool(true);
    assert_eq!(
        ProviderSession::restore(&serde_json::to_vec(&snapshot).unwrap())
            .unwrap_err()
            .code,
        "swp_provider_snapshot_invalid"
    );
}

#[test]
fn order_cancel_and_status_authoring_are_signer_local_and_fail_closed() {
    let setup = Setup::new(0xbd);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed_private(
        factory
            .rfq(
                100,
                &"51".repeat(32),
                300,
                complete_rfq_profile("submarine"),
            )
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    provider.ingest_signed(rfq).unwrap();
    let quote = signed_private(
        provider
            .soft_quote(
                101,
                &"52".repeat(32),
                300,
                complete_quote_profile("submarine"),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(quote.clone()).unwrap();
    let invalid_order = signed_private(
        factory
            .order(
                102,
                &"53".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id,"changed_non_selectable":"1"}),
            )
            .unwrap(),
        &setup.requester,
    );
    assert_eq!(
        provider.ingest_signed(invalid_order).unwrap_err().code,
        "swp_order_selection_invalid"
    );
    let order = signed_private(
        factory
            .order(
                102,
                &"53".repeat(32),
                &quote.id,
                json!({"accepted_quote_id":quote.id}),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(order.clone()).unwrap();

    assert_eq!(
        provider
            .provider_cancel(
                103,
                &"54".repeat(32),
                Cancellation {
                    action: "accepted",
                    reason: "invalid",
                    request_id: Some(&"55".repeat(32)),
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap_err()
            .code,
        "swp_cancel_ineffective"
    );
    let cancel_request = signed_private(
        factory
            .cancel(
                ParticipantRole::Requester,
                103,
                &"56".repeat(32),
                &order.id,
                Cancellation {
                    action: "request",
                    reason: "test",
                    request_id: None,
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(cancel_request.clone()).unwrap();
    let accepted = signed_private(
        provider
            .provider_cancel(
                104,
                &"56".repeat(32),
                Cancellation {
                    action: "accepted",
                    reason: "test",
                    request_id: Some(&cancel_request.id),
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(accepted).unwrap();

    let requester_gap = signed_private(
        factory
            .status(
                ParticipantRole::Requester,
                105,
                &"57".repeat(32),
                &order.id,
                StatusState {
                    sequence: 1,
                    previous: Some(&"58".repeat(32)),
                    base_state: "awaiting_input",
                    swp_state: "requester_verification_passed",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(requester_gap).unwrap();
    provider
        .provider_status(
            106,
            &"59".repeat(32),
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "accepted",
                swp_state: "accepted",
            },
            Map::new(),
        )
        .unwrap();
}

#[test]
fn provider_session_drives_all_shapes_to_no_spend_close() {
    for (index, swap_type) in ["submarine", "reverse", "chain"].into_iter().enumerate() {
        let setup = Setup::new(u8::try_from(0xc0 + index).unwrap());
        let records = no_spend_flow(&setup, swap_type);
        let requester =
            SwapSession::from_signed_records(setup.config.clone(), records.clone(), Vec::new())
                .unwrap();
        requester.validate_negotiated_terms().unwrap();
        let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
        for record in records {
            provider.ingest_signed(record).unwrap();
        }
        assert!(provider.reservation().is_none());
        assert_eq!(provider.signed_records().len(), 10);
        let restored = ProviderSession::restore(&provider.persist().unwrap()).unwrap();
        assert_eq!(restored.signed_records(), provider.signed_records());
    }
}

#[test]
fn provider_status_rejects_malformed_public_evidence() {
    let setup = Setup::new(0xdd);
    let records = no_spend_flow_through_order(&setup, "submarine");
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    for record in records {
        provider.ingest_signed(record).unwrap();
    }
    let error = provider
        .provider_status_with_evidence(
            104,
            &"20".repeat(32),
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "accepted",
                swp_state: "accepted",
            },
            json!({"class":"reservation","reference":"missing-required-fields"}),
            Map::new(),
        )
        .unwrap_err();
    assert_eq!(error.code, "swp_evidence_invalid");
}

#[test]
fn incoming_status_anomalies_are_retained_but_provider_cannot_author_them() {
    let setup = Setup::new(0xde);
    let mut provider = provider_through_order(&setup, "submarine");
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    assert_eq!(
        provider
            .provider_status(
                104,
                &"21".repeat(32),
                StatusState {
                    sequence: 1,
                    previous: Some(&"22".repeat(32)),
                    base_state: "executing",
                    swp_state: "lightning_payment_pending",
                },
                Map::new(),
            )
            .unwrap_err()
            .code,
        "swp_status_gap"
    );
    let gap = signed_private(
        factory
            .status(
                ParticipantRole::Provider,
                104,
                &"21".repeat(32),
                &provider.signed_records()[2].id,
                StatusState {
                    sequence: 1,
                    previous: Some(&"22".repeat(32)),
                    base_state: "executing",
                    swp_state: "lightning_payment_pending",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    assert!(provider.ingest_signed(gap).unwrap());
    let projection = provider.status_projection().unwrap();
    assert_eq!(projection.gaps[setup.provider.pubkey()], vec![0]);

    let setup = Setup::new(0xdf);
    let mut provider = provider_through_order(&setup, "submarine");
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();

    let initial = signed_private(
        provider
            .provider_status(
                104,
                &"23".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(initial.clone()).unwrap();
    assert_eq!(
        provider
            .provider_status(
                105,
                &"24".repeat(32),
                StatusState {
                    sequence: 1,
                    previous: Some(&initial.id),
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap_err()
            .code,
        "swp_status_transition_invalid"
    );
    let regression = signed_private(
        factory
            .status(
                ParticipantRole::Provider,
                105,
                &"24".repeat(32),
                &provider.signed_records()[2].id,
                StatusState {
                    sequence: 1,
                    previous: Some(&initial.id),
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    assert!(provider.ingest_signed(regression.clone()).unwrap());
    let projection = provider.status_projection().unwrap();
    assert_eq!(
        projection.invalid_claims[&regression.id],
        "swp_status_transition_invalid: claim regresses or leaves the flow"
    );
    assert_eq!(
        provider
            .provider_close(
                106,
                &"26".repeat(32),
                CloseOutcome {
                    outcome: "rejected",
                    terminal_at: 106
                },
                json!({"final_state":"rejected"})
            )
            .unwrap_err()
            .code,
        "swp_status_transition_invalid"
    );

    let setup = Setup::new(0xe0);
    let mut provider = provider_through_order(&setup, "submarine");
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let initial = signed_private(
        provider
            .provider_status(
                104,
                &"23".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(initial).unwrap();
    assert_eq!(
        provider
            .provider_status(
                105,
                &"25".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap_err()
            .code,
        "swp_status_fork"
    );
    let fork = signed_private(
        factory
            .status(
                ParticipantRole::Provider,
                105,
                &"25".repeat(32),
                &provider.signed_records()[2].id,
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    assert!(provider.ingest_signed(fork).unwrap());
    let projection = provider.status_projection().unwrap();
    assert_eq!(projection.forks[setup.provider.pubkey()], vec![0]);
}

fn no_spend_flow(setup: &Setup, swap_type: &str) -> Vec<Event> {
    let mut records = no_spend_flow_through_order(setup, swap_type);
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    for record in &records {
        provider.ingest_signed(record.clone()).unwrap();
    }
    let contract = complete_contract(setup, swap_type, &records[0], &records[1], &records[2]);
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let requester_contract = signed_private(
        factory
            .swap_contract(
                ParticipantRole::Requester,
                103,
                &"14".repeat(32),
                SwapContractReferences {
                    order_id: &records[2].id,
                    quote_id: &records[1].id,
                    accepted_status_id: None,
                },
                contract.clone(),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(requester_contract.clone()).unwrap();
    records.push(requester_contract);
    let provider_contract = signed_private(
        provider
            .provider_swap_contract(104, &"15".repeat(32), None, contract)
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(provider_contract.clone()).unwrap();
    records.push(provider_contract);
    let status = signed_private(
        provider
            .provider_status(
                105,
                &"16".repeat(32),
                StatusState {
                    sequence: 0,
                    previous: None,
                    base_state: "accepted",
                    swp_state: "accepted",
                },
                Map::new(),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(status.clone()).unwrap();
    records.push(status);
    let order_id = records[2].id.clone();
    let cancel_request = signed_private(
        factory
            .cancel(
                ParticipantRole::Requester,
                106,
                &"17".repeat(32),
                &order_id,
                Cancellation {
                    action: "request",
                    reason: "local_no_spend_complete",
                    request_id: None,
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap(),
        &setup.requester,
    );
    provider.ingest_signed(cancel_request.clone()).unwrap();
    records.push(cancel_request.clone());
    let accepted = signed_private(
        provider
            .provider_cancel(
                107,
                &"18".repeat(32),
                Cancellation {
                    action: "accepted",
                    reason: "local_no_spend_complete",
                    request_id: Some(&cancel_request.id),
                    accepted_id: None,
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(accepted.clone()).unwrap();
    records.push(accepted.clone());
    let effective = signed_private(
        provider
            .provider_cancel(
                108,
                &"19".repeat(32),
                Cancellation {
                    action: "effective",
                    reason: "local_no_spend_complete",
                    request_id: Some(&cancel_request.id),
                    accepted_id: Some(&accepted.id),
                },
                json!({"disposition":"no_funding_authorized"}),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(effective.clone()).unwrap();
    records.push(effective.clone());
    let close = signed_private(
        provider
            .provider_close(
                109,
                &"20".repeat(32),
                CloseOutcome {
                    outcome: "cancelled",
                    terminal_at: 109,
                },
                json!({
                    "final_state":"cancelled",
                    "loss_classification":"none",
                    "external_spend_effects":0,
                    "cancel_id":effective.id,
                    "loss_accounting":zero_loss(swap_type)
                }),
            )
            .unwrap(),
        &setup.provider,
    );
    records.push(close);
    records
}

fn no_spend_flow_through_order(setup: &Setup, swap_type: &str) -> Vec<Event> {
    let factory = SwapRecordFactory::new(setup.config.clone()).unwrap();
    let rfq = signed_private(
        factory
            .rfq(100, &"11".repeat(32), 300, complete_rfq_profile(swap_type))
            .unwrap(),
        &setup.requester,
    );
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    provider.ingest_signed(rfq.clone()).unwrap();
    let quote = signed_private(
        provider
            .soft_quote(
                101,
                &"12".repeat(32),
                300,
                complete_quote_profile(swap_type),
            )
            .unwrap(),
        &setup.provider,
    );
    provider.ingest_signed(quote.clone()).unwrap();
    let order = signed_private(
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
    vec![rfq, quote, order]
}

fn provider_through_order(setup: &Setup, swap_type: &str) -> ProviderSession {
    let mut provider = ProviderSession::new(setup.config.clone()).unwrap();
    for record in no_spend_flow_through_order(setup, swap_type) {
        provider.ingest_signed(record).unwrap();
    }
    provider
}

fn offering_content(availability: &str) -> Value {
    let first_network = network(0);
    let second_network = network(1);
    json!({
        "mkt_swp": {
            "swap_types": ["submarine", "reverse", "chain"],
            "networks": [first_network, second_network],
            "script_modes": ["taproot-musig2-script-exit"],
            "reservation_proof_classes": ["handler_accounted", "lightning_liquidity"],
            "availability": availability,
            "evm_extension": "unsupported",
            "sides": [
                {
                    "input_asset_id": asset(&first_network, "chain"),
                    "output_asset_id": asset(&first_network, "lightning"),
                    "min": "1",
                    "max": "1000000",
                    "fee_bps": "25"
                },
                {
                    "input_asset_id": asset(&first_network, "lightning"),
                    "output_asset_id": asset(&first_network, "chain"),
                    "min": "1",
                    "max": "1000000",
                    "fee_bps": "25"
                },
                {
                    "input_asset_id": asset(&first_network, "chain"),
                    "output_asset_id": asset(&second_network, "chain"),
                    "min": "1",
                    "max": "1000000",
                    "fee_bps": "25"
                }
            ],
            "confirmation_policies": [{
                "policy_id": "regtest",
                "minimum_confirmations": "1",
                "reorg_safety_blocks": "1",
                "zero_confirmation": "forbidden",
                "rbf": "track",
                "replacement": "track"
            }]
        }
    })
}

fn network(byte: u8) -> String {
    let byte = if byte == 1 { 0x11 } else { byte };
    format!("bip122:{}", format!("{byte:02x}").repeat(16))
}

fn asset(network: &str, rail: &str) -> String {
    format!("swp:1:{network}:btc:{rail}")
}

fn complete_quote_profile(swap_type: &str) -> Value {
    let mut profile = complete_record_profile(swap_type, 39_605, None);
    upgrade_legacy_reverse_timeout_ladder(swap_type, &mut profile);
    profile
}

fn complete_rfq_profile(swap_type: &str) -> Value {
    complete_record_profile(swap_type, 39_604, None)
}

fn complete_record_profile(swap_type: &str, kind: u64, signer_role: Option<&str>) -> Value {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
    ))
    .unwrap();
    let record = fixtures["flows"][swap_type]["snapshot"]["signed_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| {
            if record["kind"] != kind {
                return false;
            }
            signer_role.is_none_or(|expected| {
                serde_json::from_str::<Value>(record["content"].as_str().unwrap()).unwrap()
                    ["mkt_swp"]["signer_role"]
                    == expected
            })
        })
        .unwrap();
    let content: Value = serde_json::from_str(record["content"].as_str().unwrap()).unwrap();
    content["mkt_swp"].clone()
}

fn complete_unreserved_quote_profile(swap_type: &str) -> Value {
    let mut profile = complete_quote_profile(swap_type);
    profile.as_object_mut().unwrap().remove("reservation_terms");
    profile
}

fn complete_contract(
    setup: &Setup,
    swap_type: &str,
    rfq: &Event,
    quote: &Event,
    order: &Event,
) -> Value {
    let mut contract =
        complete_record_profile(swap_type, 39_610, Some("requester"))["contract"].clone();
    contract["order_id"] = json!(order.id);
    contract["quote_id"] = json!(quote.id);
    upgrade_legacy_reverse_timeout_ladder(swap_type, &mut contract);
    let quote_content: Value = serde_json::from_str(&quote.content).unwrap();
    let reservation = &quote_content["mkt_swp"]["reservation_terms"];
    let proof_ref = reservation["proof_ref"].as_str().unwrap();
    contract["reservation_commitment"] = json!({
        "session_id":setup.config.session_id,
        "rfq_id":rfq.id,
        "quote_id":quote.id,
        "reservation_id":reservation["reservation_id"],
        "reservation_class":"soft",
        "capacity_bucket_id":reservation["capacity_bucket_id"],
        "reserved_asset_id":reservation["reserved_asset_id"],
        "reserved_amount":reservation["reserved_amount"],
        "handler_committed_capacity":reservation["handler_committed_capacity"],
        "allocation_sequence":reservation["allocation_sequence"],
        "proof_class":reservation["proof_class"],
        "proof_strength":10,
        "proof_ref_sha256":hex(&Sha256::digest(proof_ref.as_bytes())),
        "capacity_commitment_sha256":reservation["capacity_commitment_sha256"],
        "reservation_expires_at":reservation["reservation_expires_at"],
        "profile_timeout_at":null,
        "covenant_commitment":null
    });
    contract
}

fn upgrade_legacy_reverse_timeout_ladder(swap_type: &str, terms: &mut Value) {
    if swap_type != "reverse" {
        return;
    }
    let timeout_ladder = if terms.get("timeout_ladder").is_some() {
        terms.get_mut("timeout_ladder")
    } else {
        terms
            .get_mut("terms")
            .and_then(|terms| terms.get_mut("timeout_ladder"))
    }
    .and_then(Value::as_object_mut)
    .expect("legacy reverse timeout ladder");
    let current_height = timeout_ladder["current_height"].clone();
    timeout_ladder.insert("lightning_current_height".to_owned(), current_height);
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn asset_pair(swap_type: &str) -> Value {
    let first_network = network(0);
    let second_network = network(1);
    match swap_type {
        "submarine" => json!([
            asset(&first_network, "chain"),
            asset(&first_network, "lightning")
        ]),
        "reverse" => json!([
            asset(&first_network, "lightning"),
            asset(&first_network, "chain")
        ]),
        "chain" => json!([
            asset(&first_network, "chain"),
            asset(&second_network, "chain")
        ]),
        _ => Value::Null,
    }
}

fn zero_loss(swap_type: &str) -> Value {
    let assets = asset_pair(swap_type);
    json!({
        "input_asset_id":assets[0],
        "output_asset_id":assets[1],
        "input_committed":"0",
        "input_recovered":"0",
        "output_received":"0",
        "provider_fee_paid":"0",
        "miner_fee_paid":"0",
        "lightning_routing_fee_paid":"0",
        "guarantee_recovery_received":"0",
        "principal_unresolved":"0",
        "reservation_released":match swap_type {
            "submarine" => "1000",
            "reverse" => "890",
            "chain" => "98000",
            _ => "0"
        },
        "evidence_refs":[],
        "unknown_fields":[]
    })
}

fn signed_private(request: MktSigningRequest, signer: &MarketSigner) -> Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).unwrap()
}

fn signed_public(request: MktPublicSigningRequest, signer: &MarketSigner) -> Event {
    let event = signer.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    request.verify_signed(event).unwrap()
}

fn tag<'a>(event: &'a Event, name: &str) -> &'a str {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == Some(name))
        .and_then(|tag| tag.value())
        .unwrap()
}
