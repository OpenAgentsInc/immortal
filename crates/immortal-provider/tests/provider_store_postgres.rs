#![cfg(feature = "funded")]

use std::time::{SystemTime, UNIX_EPOCH};

use immortal_client::mkt_swp_client::{
    ParticipantRole, StatusState, SwapClientConfig, SwapRecordFactory,
};
use immortal_core::{
    domain::{Event, MKT_CLOSE_KIND, MKT_RFQ_KIND, MKT_STATUS_KIND, Tag},
    market::MarketSigner,
    mkt_swp_verify::parse_bolt11,
};
use immortal_provider::store::{
    HardReservationRequest, OutPoint, ProviderStore, ProviderStoreError, PublicEffectRequest,
    PublicExitPackage, ReservationOutcome, StoreWriteOutcome, UtxoObservation, WatchJobRequest,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn provider_state_is_atomic_bounded_and_restart_safe() {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let id = |label: &str| digest(format!("provider-store-test:{namespace}:{label}").as_bytes());
    let bucket = |label: &str| format!("test-{}", &id(label)[..32]);
    let asset_id = "swp:1:bitcoin-regtest";

    let (mut first, migration) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    assert!(migration.applied_versions.len() <= 3);
    let mut second = ProviderStore::connect_verified(&database_url)
        .await
        .expect("provider migrations must verify");

    let capacity_bucket = bucket("capacity");
    first
        .configure_capacity_bucket(&capacity_bucket, asset_id, 100, 1)
        .await
        .expect("capacity bucket must configure");
    let first_request = reservation(&id, "first", &capacity_bucket, asset_id, 60, 1, vec![]);
    let second_request = reservation(&id, "second", &capacity_bucket, asset_id, 60, 1, vec![]);
    let (first_result, second_result) = tokio::join!(
        first.reserve(&first_request),
        second.reserve(&second_request)
    );
    let first_result = first_result.expect("first concurrent reservation must resolve");
    let second_result = second_result.expect("second concurrent reservation must resolve");
    let winner = match (&first_result, &second_result) {
        (
            ReservationOutcome::Reserved(_),
            ReservationOutcome::AllocationSequenceMismatch { .. },
        ) => &first_request,
        (
            ReservationOutcome::AllocationSequenceMismatch { .. },
            ReservationOutcome::Reserved(_),
        ) => &second_request,
        outcomes => {
            panic!("expected one atomic reservation and one sequence refusal: {outcomes:?}")
        }
    };
    assert_eq!(
        first
            .reserve(winner)
            .await
            .expect("exact replay must resolve"),
        ReservationOutcome::Replay(
            first
                .reservation(&winner.reservation_id)
                .await
                .expect("reservation read must work")
                .expect("winning reservation must exist")
        )
    );
    let mut changed = winner.clone();
    changed.amount += 1;
    assert!(matches!(
        first.reserve(&changed).await,
        Err(ProviderStoreError::Conflict(_))
    ));

    let shared_outpoint = OutPoint {
        txid: id("shared-utxo"),
        vout: 0,
    };
    first
        .observe_utxo(&UtxoObservation {
            outpoint: shared_outpoint.clone(),
            asset_id: asset_id.to_owned(),
            amount: 100,
            script_pubkey: "5120".to_owned() + &"11".repeat(32),
            state: "available".to_owned(),
            confirmations: 6,
            block_hash: Some(id("utxo-block")),
            replacement_txid: None,
            observed_at: 2,
        })
        .await
        .expect("UTXO observation must persist");
    let first_utxo_bucket = bucket("first-utxo-bucket");
    let second_utxo_bucket = bucket("second-utxo-bucket");
    first
        .configure_capacity_bucket(&first_utxo_bucket, asset_id, 100, 2)
        .await
        .expect("first UTXO bucket must configure");
    first
        .configure_capacity_bucket(&second_utxo_bucket, asset_id, 100, 2)
        .await
        .expect("second UTXO bucket must configure");
    let first_utxo_request = reservation(
        &id,
        "first-utxo",
        &first_utxo_bucket,
        asset_id,
        50,
        1,
        vec![shared_outpoint.clone()],
    );
    let second_utxo_request = reservation(
        &id,
        "second-utxo",
        &second_utxo_bucket,
        asset_id,
        50,
        1,
        vec![shared_outpoint.clone()],
    );
    let (first_utxo_result, second_utxo_result) = tokio::join!(
        first.reserve(&first_utxo_request),
        second.reserve(&second_utxo_request)
    );
    let outcomes = [
        first_utxo_result.expect("first UTXO reservation must resolve"),
        second_utxo_result.expect("second UTXO reservation must resolve"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ReservationOutcome::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ReservationOutcome::UtxoUnavailable(_)))
            .count(),
        1
    );
    let utxo_winner_id = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            ReservationOutcome::Reserved(record) => Some(record.reservation_id.clone()),
            _ => None,
        })
        .expect("one UTXO reservation must win");

    let mut broadcast_job = watch_request(&id, "broadcast", 3);
    // Signed protocol timestamps can be slightly ahead of the poller's wall clock.
    broadcast_job.created_at = 20;
    assert_eq!(
        first
            .enqueue_watch_job(&broadcast_job)
            .await
            .expect("watch insert must work"),
        StoreWriteOutcome::Stored
    );
    let claimed = first
        .claim_due_watch_jobs(0, 10, 20, 8)
        .await
        .expect("due watch must claim");
    assert!(claimed.iter().any(|job| job.job_id == broadcast_job.job_id));
    let broadcast_txid = id("broadcast-txid");
    let result_digest = id("broadcast-result");
    let public_result = json!({ "txid": broadcast_txid });
    assert_eq!(
        first
            .record_broadcast(
                &broadcast_job.job_id,
                &broadcast_job.request_sha256,
                &result_digest,
                &public_result,
                public_result["txid"].as_str().expect("txid is a string"),
                11,
            )
            .await
            .expect("broadcast must persist"),
        StoreWriteOutcome::Stored
    );
    assert_eq!(
        first
            .record_broadcast(
                &broadcast_job.job_id,
                &broadcast_job.request_sha256,
                &result_digest,
                &public_result,
                public_result["txid"].as_str().expect("txid is a string"),
                12,
            )
            .await
            .expect("broadcast replay must resolve"),
        StoreWriteOutcome::Replay
    );
    first
        .record_confirmation(&broadcast_job.job_id, 2, 2, &id("confirmed-block"), 13)
        .await
        .expect("confirmation must persist");
    assert!(
        first
            .watch_jobs_for_observation(8)
            .await
            .expect("observation query must work")
            .iter()
            .any(|job| job.job_id == broadcast_job.job_id && job.state == "confirmed")
    );
    first
        .record_reorg(&broadcast_job.job_id, &id("reorg-tip"), 14)
        .await
        .expect("reorg must roll confirmation back");
    let reorged = first
        .watch_job(&broadcast_job.job_id)
        .await
        .expect("watch read must work")
        .expect("watch must exist");
    assert_eq!(reorged.state, "pending");
    assert_eq!(reorged.confirmations, 0);
    assert_eq!(reorged.last_chain_event.as_deref(), Some("reorg"));
    assert_eq!(
        first
            .record_broadcast(
                &broadcast_job.job_id,
                &broadcast_job.request_sha256,
                &result_digest,
                &public_result,
                public_result["txid"].as_str().expect("txid is a string"),
                15,
            )
            .await
            .expect("rebroadcast after reorg must persist"),
        StoreWriteOutcome::Stored
    );
    first
        .record_confirmation(&broadcast_job.job_id, 2, 2, &id("replacement-block"), 16)
        .await
        .expect("replacement confirmation must persist");
    first
        .record_replacement(&broadcast_job.job_id, &id("replacement-txid"), 17)
        .await
        .expect("replacement must roll confirmation back");

    let page_job = watch_request(&id, "page", 2);
    first
        .enqueue_watch_job(&page_job)
        .await
        .expect("page watch insert must work");
    first
        .claim_due_watch_jobs(0, 30, 40, 8)
        .await
        .expect("first page attempt must claim");
    let second_claim = first
        .claim_due_watch_jobs(0, 41, 50, 8)
        .await
        .expect("expired page attempt must reclaim");
    assert!(second_claim.iter().any(|job| {
        job.job_id == page_job.job_id
            && job.state == "page"
            && job.page_code.as_deref() == Some("attempts_exhausted")
    }));

    let unresolved_job = watch_request(&id, "unresolved", 3);
    first
        .enqueue_watch_job(&unresolved_job)
        .await
        .expect("unresolved watch insert must work");
    let unresolved_context = json!({ "job_id": unresolved_job.job_id });
    assert_eq!(
        first
            .mark_watch_unresolved(
                unresolved_context["job_id"]
                    .as_str()
                    .expect("job ID is a string"),
                "poller_unavailable",
                &unresolved_context,
                51,
            )
            .await
            .expect("watch unresolved state must persist"),
        StoreWriteOutcome::Stored
    );

    let completion_job = watch_request(&id, "completion", 3);
    first
        .enqueue_watch_job(&completion_job)
        .await
        .expect("completion watch insert must work");
    assert_eq!(
        first
            .complete_watch_job(&completion_job.job_id, "claim_settled", 52)
            .await
            .expect("watch completion must persist"),
        StoreWriteOutcome::Stored
    );
    assert_eq!(
        first
            .complete_watch_job(&completion_job.job_id, "claim_settled", 53)
            .await
            .expect("watch completion must replay"),
        StoreWriteOutcome::Replay
    );
    let completed = first
        .watch_job(&completion_job.job_id)
        .await
        .expect("completed watch must be readable")
        .expect("completed watch must exist");
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.last_chain_event.as_deref(), Some("claim_settled"));

    for (index, member) in [
        "unreleased_preimage",
        "wallet_seed_hex",
        "claim_spend_key",
        "refund_private_key_bytes",
        "admin_macaroon_hex",
        "node_credentials",
    ]
    .into_iter()
    .enumerate()
    {
        let custody_request = PublicEffectRequest {
            effect_id: id(&format!("custody-effect-{index}")),
            session_id: id(&format!("custody-session-{index}")),
            operation: "forbidden".to_owned(),
            request_sha256: id(&format!("custody-request-{index}")),
            public_request: json!({ member: "00".repeat(32) }),
            created_at: 52,
        };
        assert!(matches!(
            first.persist_effect_request(&custody_request).await,
            Err(ProviderStoreError::InvalidInput(_))
        ));
        assert_database_rejects_custody_json(&database_url, &custody_request)
            .await
            .expect("database custody tripwire must execute");
    }
    assert_eq!(
        first
            .health_counts()
            .await
            .expect("reservation effects must be queryable")
            .pending_effects,
        0,
        "an atomic reservation must complete its durable effect"
    );
    let public_reference_request = PublicEffectRequest {
        effect_id: id("public-reference-effect"),
        session_id: id("public-reference-session"),
        operation: "public_reference".to_owned(),
        request_sha256: id("public-reference-request"),
        public_request: json!({
            "preimage_recovery_ref":"watchtower:public-reference",
            "payment_hash":"00".repeat(32),
            "claim_public_key":"11".repeat(32),
            "refund_public_key":"22".repeat(32)
        }),
        created_at: 52,
    };
    assert_eq!(
        first
            .persist_effect_request(&public_reference_request)
            .await
            .expect("public recovery references must remain storable"),
        StoreWriteOutcome::Stored
    );

    let cooperative_package = PublicExitPackage {
        package_id: id("cooperative-package"),
        session_id: id("cooperative-session"),
        order_id: id("cooperative-order"),
        leg_id: "source".to_owned(),
        path: "claim".to_owned(),
        package_sha256: id("cooperative-package-digest"),
        public_package: json!({
            "effect_id":id("cooperative-unilateral-effect"),
            "mode":"external_signer",
            "path":"claim",
            "transaction_template_sha256":id("cooperative-transaction"),
        }),
        created_at: 53,
    };
    assert_eq!(
        first
            .persist_exit_package(&cooperative_package)
            .await
            .expect("cooperative exit package must persist"),
        StoreWriteOutcome::Stored
    );
    assert_eq!(
        first
            .persist_exit_package(&cooperative_package)
            .await
            .expect("cooperative exit package replay must persist"),
        StoreWriteOutcome::Replay
    );
    let cooperative_effect = PublicEffectRequest {
        effect_id: id("cooperative-effect"),
        session_id: cooperative_package.session_id.clone(),
        operation: "cooperative_sign".to_owned(),
        request_sha256: id("cooperative-effect-request"),
        public_request: json!({
            "context_sha256":id("cooperative-context"),
            "exit_package_sha256":cooperative_package.package_sha256,
            "operation":"cooperative_sign",
        }),
        created_at: 54,
    };
    assert_eq!(
        first
            .persist_effect_request(&cooperative_effect)
            .await
            .expect("cooperative effect request must persist"),
        StoreWriteOutcome::Stored
    );
    let cooperative_claim_effect = PublicEffectRequest {
        effect_id: id("cooperative-claim-effect"),
        session_id: cooperative_package.session_id.clone(),
        operation: "chain_claim".to_owned(),
        request_sha256: id("cooperative-claim-request"),
        public_request: json!({
            "exit_package_sha256":cooperative_package.package_sha256,
            "funding_transaction_id":id("cooperative-funding"),
            "output_index":0,
            "path":"claim",
            "payment_hash":id("cooperative-payment-hash"),
            "transaction_template_sha256":id("cooperative-transaction"),
        }),
        created_at: 54,
    };
    assert_eq!(
        first
            .persist_effect_request(&cooperative_claim_effect)
            .await
            .expect("cooperative claim request must persist"),
        StoreWriteOutcome::Stored
    );
    let stored_package = first
        .exit_package(&cooperative_package.package_id)
        .await
        .expect("cooperative exit package must be readable")
        .expect("cooperative exit package must exist");
    assert_eq!(stored_package.package, cooperative_package);
    assert_eq!(stored_package.state, "prepared");
    let stored_effect = first
        .public_effect(&cooperative_effect.effect_id)
        .await
        .expect("cooperative effect must be readable")
        .expect("cooperative effect must exist");
    assert_eq!(stored_effect.request, cooperative_effect);
    assert_eq!(stored_effect.state, "pending");
    assert_eq!(
        first
            .public_effect(&cooperative_claim_effect.effect_id)
            .await
            .expect("cooperative claim effect must be readable")
            .expect("cooperative claim effect must exist")
            .request,
        cooperative_claim_effect
    );

    let health = first
        .health_counts()
        .await
        .expect("health counts must query");
    assert!(health.active_reservations >= 2);
    assert!(health.paged_watch_jobs >= 1);
    assert!(health.unresolved_watch_jobs >= 1);
    assert!(health.active_alerts >= 2);

    let winner_id = winner.reservation_id.clone();
    drop(first);
    drop(second);
    let restarted = ProviderStore::connect_verified(&database_url)
        .await
        .expect("restart must verify the migration ledger");
    assert!(
        restarted
            .reservation(&winner_id)
            .await
            .expect("reservation restart read must work")
            .is_some()
    );
    let recovered_utxos = restarted
        .reserved_utxos(&utxo_winner_id)
        .await
        .expect("reserved UTXOs must be recoverable after restart");
    assert_eq!(recovered_utxos.len(), 1);
    assert_eq!(recovered_utxos[0].outpoint, shared_outpoint);
    assert_eq!(
        restarted
            .exit_package(&cooperative_package.package_id)
            .await
            .expect("cooperative package restart read must work")
            .expect("cooperative package must survive restart")
            .package,
        cooperative_package
    );
    assert_eq!(
        restarted
            .public_effect(&cooperative_effect.effect_id)
            .await
            .expect("cooperative effect restart read must work")
            .expect("cooperative effect must survive restart")
            .request,
        cooperative_effect
    );
    assert_eq!(
        restarted
            .public_effect(&cooperative_claim_effect.effect_id)
            .await
            .expect("cooperative claim restart read must work")
            .expect("cooperative claim must survive restart")
            .request,
        cooperative_claim_effect
    );
    assert_eq!(recovered_utxos[0].state, "reserved");
    assert_eq!(
        restarted
            .watch_job(&broadcast_job.job_id)
            .await
            .expect("watch restart read must work")
            .expect("watch must survive restart")
            .last_chain_event
            .as_deref(),
        Some("replacement")
    );
}

#[tokio::test]
async fn reservation_replay_uses_the_durable_allocation_sequence_after_restart() {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let id = |label: &str| digest(format!("provider-replay-test:{namespace}:{label}").as_bytes());
    let bucket_id = format!("test-{}", &id("bucket")[..32]);
    let asset_id = "swp:1:bitcoin-regtest";

    let (mut store, _) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    store
        .configure_capacity_bucket(&bucket_id, asset_id, 100, 1)
        .await
        .expect("capacity bucket must configure");
    let first = reservation(&id, "first", &bucket_id, asset_id, 10, 1, vec![]);
    let second = reservation(&id, "second", &bucket_id, asset_id, 10, 2, vec![]);
    assert!(matches!(
        store.reserve(&first).await.expect("first reserve"),
        ReservationOutcome::Reserved(_)
    ));
    assert!(matches!(
        store.reserve(&second).await.expect("second reserve"),
        ReservationOutcome::Reserved(_)
    ));
    drop(store);

    let mut restarted = ProviderStore::connect_verified(&database_url)
        .await
        .expect("restart must verify migrations");
    let mut retry = second.clone();
    retry.expected_allocation_sequence = 1;
    let replay = restarted
        .reserve(&retry)
        .await
        .expect("retry must replay the durable reservation");
    assert!(matches!(
        replay,
        ReservationOutcome::Replay(record) if record.allocation_sequence == 2
    ));
    retry.amount += 1;
    assert!(matches!(
        restarted.reserve(&retry).await,
        Err(ProviderStoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn active_session_recovery_excludes_only_durable_dispositions() {
    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let session =
        |label: &str| digest(format!("provider-recovery-test:{namespace}:{label}").as_bytes());
    let active_session = session("active");
    let closed_session = session("closed");
    let disposed_session = session("disposed");
    let signer = MarketSigner::from_secret_bytes([37; 32]).expect("test signer");
    let active_rfq = signed_store_event(&signer, &active_session, MKT_RFQ_KIND, 1);
    let closed_rfq = signed_store_event(&signer, &closed_session, MKT_RFQ_KIND, 2);
    let close = signed_store_event(&signer, &closed_session, MKT_CLOSE_KIND, 3);
    let disposed_rfq = signed_store_event(&signer, &disposed_session, MKT_RFQ_KIND, 4);

    let (mut store, _) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    for event in [&active_rfq, &closed_rfq, &close, &disposed_rfq] {
        store
            .persist_session_record(event)
            .await
            .expect("session record must persist");
    }
    assert_eq!(
        store
            .dispose_session(&disposed_session, "quote_expired", 5)
            .await
            .expect("session disposition must persist"),
        StoreWriteOutcome::Stored
    );
    assert_eq!(
        store
            .dispose_session(&disposed_session, "quote_expired", 6)
            .await
            .expect("same disposition must replay"),
        StoreWriteOutcome::Replay
    );
    assert_eq!(
        store
            .session_disposition(&disposed_session)
            .await
            .expect("disposed session lookup must succeed"),
        Some("quote_expired".to_owned())
    );
    assert_eq!(
        store
            .session_disposition(&active_session)
            .await
            .expect("active session lookup must succeed"),
        None
    );
    assert!(matches!(
        store
            .dispose_session(&disposed_session, "contract_stalled", 6)
            .await,
        Err(ProviderStoreError::Conflict(_))
    ));
    let recovery = store
        .active_session_records(6_144)
        .await
        .expect("active recovery must query");
    assert!(recovery.has_prior_records);
    assert!(recovery.records.iter().any(|record| record == &active_rfq));
    assert!(recovery.records.iter().any(|record| record == &closed_rfq));
    assert!(recovery.records.iter().any(|record| record == &close));
    assert!(
        recovery
            .records
            .iter()
            .all(|record| record != &disposed_rfq)
    );
    assert_eq!(
        store
            .dispose_session(&closed_session, "provider_close_completed", 7)
            .await
            .expect("provider Close disposition must persist"),
        StoreWriteOutcome::Stored
    );
    let recovery = store
        .active_session_records(6_144)
        .await
        .expect("disposed Close group must be excluded");
    assert!(
        recovery
            .records
            .iter()
            .all(|record| record != &closed_rfq && record != &close)
    );
    let terminal_history = store
        .session_records(&closed_session, 512)
        .await
        .expect("terminal session history must remain queryable");
    assert_eq!(terminal_history.len(), 2);
    assert!(terminal_history.iter().any(|record| record == &closed_rfq));
    assert!(terminal_history.iter().any(|record| record == &close));
}

#[tokio::test]
async fn reverse_invoice_lookup_is_indexed_beyond_global_history_prefix() {
    const BOLT11: &str = "lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0";

    let Ok(database_url) = std::env::var("IMMORTAL_PROVIDER_TEST_DATABASE_URL") else {
        eprintln!("skipping provider Postgres test: IMMORTAL_PROVIDER_TEST_DATABASE_URL is unset");
        return;
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_nanos();
    let namespace = format!("{}-{nonce}", std::process::id());
    let id = |label: &str| digest(format!("provider-invoice-index:{namespace}:{label}").as_bytes());
    let event_prefix = &id("event-prefix")[..48];
    let session_prefix = &id("session-prefix")[..48];
    let (mut store, _) = ProviderStore::connect(&database_url)
        .await
        .expect("provider migrations must apply");
    let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
        .await
        .expect("test database must connect");
    let connection = tokio::spawn(connection);
    let statement = client
        .prepare(
            r#"
            WITH generated AS (
                SELECT sequence,
                       $1::text || lpad(to_hex(sequence), 16, '0') AS event_id,
                       $2::text || lpad(to_hex(((sequence - 1) / 512) + 1), 16, '0') AS session_id
                FROM generate_series(1::bigint, 6144::bigint) AS sequence
            )
            INSERT INTO provider_session_record
                (event_id, session_id, author_pubkey, kind, created_at,
                 event_sha256, signed_event)
            SELECT event_id, session_id, repeat('1', 64), 39604, sequence,
                   repeat('a', 64),
                   jsonb_build_object(
                       'id', event_id,
                       'pubkey', repeat('1', 64),
                       'created_at', sequence,
                       'kind', 39604,
                       'tags', jsonb_build_array(jsonb_build_array('session', session_id)),
                       'content', '{"mkt_swp":{"fixture":"invoice-index-history"}}',
                       'sig', repeat('2', 128)
                   )
            FROM generated
            "#,
        )
        .await
        .expect("history insert must prepare");
    assert_eq!(
        client
            .execute(&statement, &[&event_prefix, &session_prefix])
            .await
            .expect("history records must insert"),
        6_144
    );

    let payment_hash = parse_bolt11(BOLT11)
        .expect("fixture BOLT11 must parse")
        .payment_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let target_session = "aa".repeat(32);
    let requester = MarketSigner::from_secret_bytes([40; 32]).expect("requester signer");
    let provider = MarketSigner::from_secret_bytes([41; 32]).expect("provider signer");
    let target_records = canonical_reverse_invoice_records(BOLT11);
    for record in &target_records {
        store
            .persist_session_record(record)
            .await
            .expect("validated invoice session record must persist");
    }
    assert_eq!(
        store
            .reverse_invoice_session(BOLT11)
            .await
            .expect("indexed invoice lookup must succeed"),
        Some(target_session.clone())
    );

    let hold_status = target_records
        .iter()
        .find(|event| {
            event.kind == MKT_STATUS_KIND
                && event
                    .content
                    .contains("\"swp_state\":\"hold_invoice_ready\"")
        })
        .expect("canonical hold-invoice Status");
    let status_one = canonical_reverse_status(
        &target_records,
        1,
        hold_status.id.as_str(),
        "executing",
        "lightning_htlcs_held",
    );
    let status_two = canonical_reverse_status(
        &target_records,
        2,
        status_one.id.as_str(),
        "awaiting_input",
        "provider_lock_terms_ready",
    );
    store
        .persist_session_record(&status_two)
        .await
        .expect("out-of-order later Status must not invalidate the invoice prefix");
    drop(store);
    let mut store = ProviderStore::connect_verified(&database_url)
        .await
        .expect("restart must retain an invoice binding while later Status has a gap");
    assert_eq!(
        store
            .reverse_invoice_session(BOLT11)
            .await
            .expect("invoice lookup after out-of-order restart must succeed"),
        Some(target_session.clone())
    );
    store
        .persist_session_record(&status_one)
        .await
        .expect("late predecessor must persist without changing the invoice binding");

    let poisoned_session = id("poisoned-session");
    let foreign = MarketSigner::from_secret_bytes([42; 32]).expect("foreign signer");
    for record in reverse_session_prerequisites(
        &requester,
        &provider,
        &poisoned_session,
        &payment_hash,
        7_000,
    ) {
        store
            .persist_session_record(&record)
            .await
            .expect("poison-session prerequisite must persist");
    }
    for (signer, created_at) in [(&requester, 7_004), (&foreign, 7_005)] {
        let poison = signed_store_profile_event(
            signer,
            &poisoned_session,
            MKT_STATUS_KIND,
            created_at,
            json!({"invoice":BOLT11,"swp_state":"hold_invoice_ready"}),
        );
        store
            .persist_session_record(&poison)
            .await
            .expect("non-provider invoice Status remains durable evidence");
    }
    assert_eq!(
        store
            .reverse_invoice_session(BOLT11)
            .await
            .expect("invoice lookup after poison records must succeed"),
        Some(target_session.clone())
    );
    let delete_binding = client
        .prepare("DELETE FROM provider_boltz_invoice_binding WHERE session_id = $1")
        .await
        .expect("binding deletion must prepare");
    assert_eq!(
        client
            .execute(&delete_binding, &[&target_session])
            .await
            .expect("test binding must delete"),
        1
    );
    drop(store);
    let (rebuilt, _) = ProviderStore::connect(&database_url)
        .await
        .expect("startup reconciliation must validate and rebuild the invoice index");
    assert_eq!(
        rebuilt
            .reverse_invoice_session(BOLT11)
            .await
            .expect("rebuilt invoice lookup must succeed"),
        Some(target_session.clone())
    );
    drop(rebuilt);
    assert_eq!(
        client
            .execute(&delete_binding, &[&target_session])
            .await
            .expect("rebuilt binding must delete before continuation proof"),
        1
    );
    let poison_prefix = &id("invoice-reconciliation-poison")[..48];
    let insert_poison_candidates = client
        .prepare(
            r#"
            WITH generated AS (
                SELECT sequence,
                       lpad(to_hex(sequence), 64, '0') AS session_id,
                       $1::text || lpad(to_hex(sequence), 16, '0') AS event_id
                FROM generate_series(1::bigint, 65::bigint) AS sequence
            )
            INSERT INTO provider_session_record
                (event_id, session_id, author_pubkey, kind, created_at,
                 event_sha256, signed_event)
            SELECT event_id, session_id, repeat('1', 64), 39607, 8000 + sequence,
                   repeat('b', 64),
                   jsonb_build_object(
                       'id', event_id,
                       'pubkey', repeat('1', 64),
                       'created_at', 8000 + sequence,
                       'kind', 39607,
                       'tags', jsonb_build_array(jsonb_build_array('session', session_id)),
                       'content', jsonb_build_object(
                           'mkt_swp', jsonb_build_object(
                               'swp_state', 'hold_invoice_ready',
                               'invoice', 'invalid-historical-bolt11'
                           )
                       )::text,
                       'sig', repeat('2', 128)
                   )
            FROM generated
            "#,
        )
        .await
        .expect("poison candidate insert must prepare");
    assert_eq!(
        client
            .execute(&insert_poison_candidates, &[&poison_prefix])
            .await
            .expect("poison historical hold candidates must insert"),
        65
    );
    let insert_conflicting_quotes = client
        .prepare(
            r#"
            INSERT INTO provider_session_record
                (event_id, session_id, author_pubkey, kind, created_at,
                 event_sha256, signed_event)
            SELECT $1 || lpad(to_hex(sequence), 16, '0'),
                   lpad(to_hex(1), 64, '0'), repeat('3', 64), 39605,
                   9000 + sequence, repeat('c', 64),
                   jsonb_build_object(
                       'id', $1 || lpad(to_hex(sequence), 16, '0'),
                       'pubkey', repeat('3', 64),
                       'created_at', 9000 + sequence,
                       'kind', 39605,
                       'tags', jsonb_build_array(
                           jsonb_build_array('session', lpad(to_hex(1), 64, '0'))
                       ),
                       'content', '{"mkt_swp":{"terms":{}}}',
                       'sig', repeat('4', 128)
                   )
            FROM generate_series(1::bigint, 2::bigint) AS sequence
            "#,
        )
        .await
        .expect("conflicting Quote insert must prepare");
    let quote_prefix = id("poison-quotes");
    let quote_prefix = &quote_prefix[..48];
    assert_eq!(
        client
            .execute(&insert_conflicting_quotes, &[&quote_prefix])
            .await
            .expect("conflicting historical Quotes must insert"),
        2
    );
    client
        .batch_execute("BEGIN")
        .await
        .expect("target advisory-lock transaction must begin");
    let advisory_lock = client
        .prepare("SELECT pg_advisory_xact_lock(hashtextextended('provider-session:' || $1, 0))")
        .await
        .expect("target advisory lock must prepare");
    client
        .execute(&advisory_lock, &[&target_session])
        .await
        .expect("target advisory lock must be held");
    let (bounded_restart, _) = ProviderStore::connect(&database_url)
        .await
        .expect("startup must continue after the first bounded candidate page");
    assert_eq!(
        bounded_restart
            .reverse_invoice_session(BOLT11)
            .await
            .expect("background target lookup before lock release must succeed"),
        None
    );
    client
        .batch_execute("COMMIT")
        .await
        .expect("target advisory lock must release");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if bounded_restart
                .reverse_invoice_session(BOLT11)
                .await
                .expect("background invoice lookup must succeed")
                == Some(target_session.clone())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background reconciliation must advance past 65 historical candidates");
    drop(bounded_restart);
    drop(client);
    connection
        .await
        .expect("database connection task must join")
        .expect("database connection must close cleanly");
}

fn canonical_reverse_invoice_records(invoice: &str) -> Vec<Event> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
    ))
    .expect("full MKT-SWP sessions fixture");
    let snapshot = &fixture["flows"]["reverse"]["snapshot"];
    let config: SwapClientConfig =
        serde_json::from_value(snapshot["config"].clone()).expect("reverse fixture config");
    let mut records: Vec<Event> = serde_json::from_value(snapshot["signed_records"].clone())
        .expect("reverse fixture records");
    let provider = fixture_market_signer(b"provider");
    assert_eq!(provider.pubkey(), config.provider_pubkey);
    let order_id = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_ORDER_KIND)
        .map(|event| event.id.as_str())
        .expect("reverse fixture Order");
    let factory = SwapRecordFactory::new(config).expect("reverse fixture record factory");
    let request = factory
        .status(
            ParticipantRole::Provider,
            700,
            &digest(b"provider-invoice-index:hold-invoice-ready"),
            order_id,
            StatusState {
                sequence: 0,
                previous: None,
                base_state: "awaiting_input",
                swp_state: "hold_invoice_ready",
            },
            json!({"invoice":invoice})
                .as_object()
                .expect("invoice Status fields")
                .clone(),
        )
        .expect("hold-invoice Status request");
    let status = provider.sign(
        request.created_at,
        request.kind,
        request.tags.clone(),
        request.content.clone(),
    );
    records.push(
        request
            .verify_signed(status)
            .expect("signed hold-invoice Status"),
    );
    records
}

fn fixture_market_signer(label: &[u8]) -> MarketSigner {
    let key: [u8; 32] =
        Sha256::digest([b"immortal-mkt-swp-test-only:".as_slice(), label].concat()).into();
    MarketSigner::from_secret_bytes(key).expect("fixture market signer")
}

fn canonical_reverse_status(
    records: &[Event],
    sequence: u64,
    previous: &str,
    base_state: &str,
    swp_state: &str,
) -> Event {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
    ))
    .expect("full MKT-SWP sessions fixture");
    let config: SwapClientConfig =
        serde_json::from_value(fixture["flows"]["reverse"]["snapshot"]["config"].clone())
            .expect("reverse fixture config");
    let order_id = records
        .iter()
        .find(|event| event.kind == immortal_core::domain::MKT_ORDER_KIND)
        .map(|event| event.id.as_str())
        .expect("reverse fixture Order");
    let request = SwapRecordFactory::new(config)
        .expect("reverse fixture record factory")
        .status(
            ParticipantRole::Provider,
            701 + sequence,
            &digest(format!("provider-invoice-index:{sequence}:{swp_state}").as_bytes()),
            order_id,
            StatusState {
                sequence,
                previous: Some(previous),
                base_state,
                swp_state,
            },
            serde_json::Map::new(),
        )
        .expect("later reverse Status request");
    let provider = fixture_market_signer(b"provider");
    request
        .verify_signed(provider.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        ))
        .expect("signed later reverse Status")
}

fn reverse_session_prerequisites(
    requester: &MarketSigner,
    provider: &MarketSigner,
    session_id: &str,
    payment_hash: &str,
    created_at: u64,
) -> Vec<Event> {
    let contract = json!({"payment_hash":payment_hash,"swap_type":"reverse"});
    vec![
        signed_store_profile_event(
            requester,
            session_id,
            MKT_RFQ_KIND,
            created_at,
            json!({"constraints":{"payment_hash":payment_hash}}),
        ),
        signed_store_profile_event(
            provider,
            session_id,
            immortal_core::domain::MKT_QUOTE_KIND,
            created_at + 1,
            json!({"terms":{"payment_hash":payment_hash,"swap_type":"reverse"}}),
        ),
        signed_store_profile_event(
            requester,
            session_id,
            immortal_core::domain::MKT_SWP_SWAP_CONTRACT_KIND,
            created_at + 2,
            json!({"contract":contract}),
        ),
        signed_store_profile_event(
            provider,
            session_id,
            immortal_core::domain::MKT_SWP_SWAP_CONTRACT_KIND,
            created_at + 3,
            json!({"contract":contract}),
        ),
    ]
}

fn signed_store_profile_event(
    signer: &MarketSigner,
    session_id: &str,
    kind: u16,
    created_at: u64,
    profile: serde_json::Value,
) -> Event {
    signer.sign(
        created_at,
        kind,
        vec![Tag::new(vec!["session".to_owned(), session_id.to_owned()])],
        json!({"mkt_swp":profile}).to_string(),
    )
}

fn reservation(
    id: &impl Fn(&str) -> String,
    label: &str,
    bucket_id: &str,
    asset_id: &str,
    amount: u64,
    sequence: u64,
    utxos: Vec<OutPoint>,
) -> HardReservationRequest {
    HardReservationRequest {
        reservation_id: id(&format!("{label}-reservation")),
        effect_id: id(&format!("{label}-effect")),
        session_id: id(&format!("{label}-session")),
        bucket_id: bucket_id.to_owned(),
        asset_id: asset_id.to_owned(),
        amount,
        request_sha256: id(&format!("{label}-request")),
        expected_allocation_sequence: sequence,
        expires_at: 1_000,
        utxos,
        ark_reserve: None,
        created_at: 3,
    }
}

fn signed_store_event(
    signer: &MarketSigner,
    session_id: &str,
    kind: u16,
    created_at: u64,
) -> Event {
    signer.sign(
        created_at,
        kind,
        vec![Tag::new(vec!["session".to_owned(), session_id.to_owned()])],
        json!({"mkt_swp":{"fixture":"provider_store_recovery"}}).to_string(),
    )
}

fn watch_request(id: &impl Fn(&str) -> String, label: &str, attempts: u16) -> WatchJobRequest {
    WatchJobRequest {
        job_id: id(&format!("{label}-job")),
        session_id: id(&format!("{label}-watch-session")),
        effect_id: None,
        job_kind: "bitcoin_watch".to_owned(),
        request_sha256: id(&format!("{label}-watch-request")),
        public_payload: json!({ "transaction_id": id(&format!("{label}-watched-tx")) }),
        due_height: None,
        due_at: Some(1),
        maximum_attempts: attempts,
        created_at: 1,
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn assert_database_rejects_custody_json(
    database_url: &str,
    request: &PublicEffectRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls).await?;
    let connection = tokio::spawn(connection);
    let statement = client
        .prepare(
            "INSERT INTO provider_effect
             (effect_id, session_id, operation, request_sha256, public_request,
              state, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, $6)",
        )
        .await?;
    let result = client
        .execute(
            &statement,
            &[
                &request.effect_id,
                &request.session_id,
                &request.operation,
                &request.request_sha256,
                &request.public_request,
                &i64::try_from(request.created_at)?,
            ],
        )
        .await;
    let error = result.expect_err("custody JSON must violate the schema constraint");
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    drop(client);
    connection.await??;
    Ok(())
}
