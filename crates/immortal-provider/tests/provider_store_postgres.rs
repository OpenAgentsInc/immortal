#![cfg(feature = "funded")]

use std::time::{SystemTime, UNIX_EPOCH};

use immortal_core::{
    domain::{Event, MKT_CLOSE_KIND, MKT_RFQ_KIND, Tag},
    market::MarketSigner,
};
use immortal_provider::store::{
    HardReservationRequest, OutPoint, ProviderStore, ProviderStoreError, PublicEffectRequest,
    ReservationOutcome, StoreWriteOutcome, UtxoObservation, WatchJobRequest,
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
    assert!(migration.applied_versions.len() <= 1);
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
