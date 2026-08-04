//! Live M2 conformance. Set `IMMORTAL_TEST_DATABASE_URL`, or run
//! `scripts/test-postgres.sh`, to exercise an isolated real Postgres cluster.

use std::{collections::BTreeMap, time::Duration};

use immortal::{
    domain::{Event, Filter, Tag},
    store::{AdmissionOutcome, AdmissionRejection, NotificationListener, Store, StoreError},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use tokio::{sync::watch, time::timeout};
use tokio_postgres::NoTls;

const NOW: u64 = 10_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m2_store_contract_against_postgres() {
    let Ok(database_url) = std::env::var("IMMORTAL_TEST_DATABASE_URL") else {
        eprintln!("skipped: set IMMORTAL_TEST_DATABASE_URL or run scripts/test-postgres.sh");
        return;
    };
    if std::env::var("IMMORTAL_TEST_ALLOW_DESTRUCTIVE").as_deref() != Ok("1") {
        eprintln!(
            "skipped: the live suite changes roles and migration metadata; use scripts/test-postgres.sh"
        );
        return;
    }

    let (initial_store, report) = Store::connect_with_report(&database_url).await.unwrap();
    assert_eq!(report.applied_versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    drop(initial_store);
    seed_pre_v9_search_rows(&database_url).await;

    let (mut store, report) = Store::connect_with_report(&database_url).await.unwrap();
    assert_eq!(report.applied_versions, vec![9]);
    assert_pre_v9_search_rows_are_private_and_preserved(&database_url).await;
    assert!(store.is_current());

    let (_second_store, report) = Store::connect_with_report(&database_url).await.unwrap();
    assert!(
        report.applied_versions.is_empty(),
        "migrations are idempotent"
    );
    let _verified_store = Store::connect_verified(&database_url).await.unwrap();
    if database_url.contains("dbname=immortal_test") {
        least_privilege_runtime(&database_url).await;
    }

    nostr_effect_import_is_idempotent(&database_url, &mut store).await;

    let mut listener = NotificationListener::connect(&database_url, 64)
        .await
        .unwrap();

    let regular = signed_event(
        1,
        100,
        1,
        vec![
            Tag::new(vec!["e".into(), "indexed-value".into(), "ignored".into()]),
            Tag::new(vec!["alt".into(), "not-indexed".into()]),
        ],
        "hello searchable world",
    );
    let stored = store.admit(&regular, NOW).await.unwrap();
    let AdmissionOutcome::Stored { ingest_seq } = stored else {
        panic!("regular event was not stored: {stored:?}");
    };
    assert_eq!(
        timeout(Duration::from_secs(2), listener.recv())
            .await
            .unwrap(),
        Some(ingest_seq),
        "NOTIFY is delivered only after commit"
    );
    assert_eq!(
        store.admit(&regular, NOW).await.unwrap(),
        AdmissionOutcome::Duplicate
    );
    assert_eq!(
        store
            .event_by_id(&regular.id, NOW)
            .await
            .unwrap()
            .unwrap()
            .event,
        regular
    );

    let tag_filter = Filter {
        tags: BTreeMap::from([('e', vec!["indexed-value".to_owned()])]),
        ..Filter::default()
    };
    assert_eq!(
        store
            .query_filter(&tag_filter, NOW, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let ignored_filter = Filter {
        tags: BTreeMap::from([('e', vec!["ignored".to_owned()])]),
        ..Filter::default()
    };
    assert!(
        store
            .query_filter(&ignored_filter, NOW, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let (cancel, cancelled) = watch::channel(false);
    cancel.send(true).unwrap();
    assert!(matches!(
        store
            .query_filter_cancellable(&Filter::default(), NOW, 10, i64::MAX, cancelled)
            .await,
        Err(StoreError::QueryCancelled)
    ));

    let ephemeral = signed_event(1, 110, 20_000, Vec::new(), "never stored");
    assert_eq!(
        store.admit(&ephemeral, NOW).await.unwrap(),
        AdmissionOutcome::Ephemeral
    );
    assert!(
        store
            .event_by_id(&ephemeral.id, NOW)
            .await
            .unwrap()
            .is_none()
    );

    let expiring = signed_event(
        1,
        120,
        1,
        vec![Tag::new(vec!["expiration".into(), "200".into()])],
        "temporary",
    );
    store.admit(&expiring, 150).await.unwrap();
    assert!(
        store
            .event_by_id(&expiring.id, 199)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .event_by_id(&expiring.id, 200)
            .await
            .unwrap()
            .is_none()
    );

    let expiring_target = signed_event(12, 121, 1, Vec::new(), "remains deleted");
    let expiring_deletion = signed_event(
        12,
        122,
        5,
        vec![
            Tag::new(vec!["e".into(), expiring_target.id.clone()]),
            Tag::new(vec!["expiration".into(), "200".into()]),
        ],
        "expiring deletion publication",
    );
    store.admit(&expiring_deletion, 150).await.unwrap();
    assert!(store.delete_expired(200).await.unwrap() >= 2);
    assert!(
        store
            .event_by_id(&expiring_deletion.id, 199)
            .await
            .unwrap()
            .is_none(),
        "the deletion publication was physically removed"
    );
    assert_eq!(
        store.admit(&expiring_target, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::Deleted),
        "the durable tombstone outlives its expired source event"
    );

    replacement_race(&database_url, &mut store).await;
    mkt_immutable_admission(&database_url, &mut store).await;
    deletion_before_event(&database_url, &mut store).await;
    concurrent_deletion_race(&database_url, &mut store).await;
    concurrent_media_quota(&database_url, &mut store).await;
    policy_and_fts(&database_url, &mut store).await;

    let high_water = store.latest_ingest_seq().await.unwrap();
    let catch_up = store.events_after(0, high_water, NOW, 100).await.unwrap();
    assert!(!catch_up.is_empty());
    assert!(
        catch_up
            .windows(2)
            .all(|pair| pair[0].ingest_seq < pair[1].ingest_seq)
    );
    assert!(listener.is_current());
    migration_hash_drift_fails_closed(&database_url).await;
}

async fn seed_pre_v9_search_rows(database_url: &str) {
    let (mut client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let transaction = client.transaction().await.unwrap();
    transaction
        .batch_execute(
            r#"
DROP INDEX nostr_event_search_idx;
ALTER TABLE nostr_event DROP COLUMN search_vector;
ALTER TABLE nostr_event ADD COLUMN search_vector tsvector GENERATED ALWAYS AS (
    CASE
        WHEN kind IN (30078, 30174, 30175, 30178, 30300, 30350, 30622, 44200)
        THEN NULL::tsvector
        ELSE to_tsvector('simple'::regconfig, content)
    END
) STORED;
CREATE INDEX nostr_event_search_idx ON nostr_event USING gin (search_vector);
DELETE FROM schema_migrations WHERE version = 9;
"#,
        )
        .await
        .unwrap();
    let insert = transaction
        .prepare(
            r#"
INSERT INTO nostr_event (
    id, pubkey, created_at, kind, tags, content, sig, replacement_identifier
) VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, $8)
"#,
        )
        .await
        .unwrap();
    let wrap = signed_event(
        90,
        8,
        1_059,
        vec![Tag::new(vec!["p".into(), "c".repeat(64)])],
        "pre-v9 gift wrap searchable marker",
    );
    let private = signed_event(
        91,
        9,
        39_604,
        vec![Tag::new(vec!["d".into(), "d".repeat(64)])],
        "pre-v9 private MKT searchable marker",
    );
    transaction
        .execute(
            &insert,
            &[
                &wrap.id,
                &wrap.pubkey,
                &i64::try_from(wrap.created_at).unwrap(),
                &1_059_i32,
                &serde_json::to_string(&wrap.tags).unwrap(),
                &wrap.content,
                &wrap.sig,
                &None::<String>,
            ],
        )
        .await
        .unwrap();
    transaction
        .execute(
            &insert,
            &[
                &private.id,
                &private.pubkey,
                &i64::try_from(private.created_at).unwrap(),
                &39_604_i32,
                &serde_json::to_string(&private.tags).unwrap(),
                &private.content,
                &private.sig,
                &Some("d".repeat(64)),
            ],
        )
        .await
        .unwrap();
    let indexed = transaction
        .query_one(
            "SELECT count(*) FROM nostr_event WHERE content LIKE '%pre-v9%' AND search_vector IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(indexed, 2);
    transaction.commit().await.unwrap();
}

async fn assert_pre_v9_search_rows_are_private_and_preserved(database_url: &str) {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let row = client
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE search_vector IS NULL) FROM nostr_event WHERE content LIKE '%pre-v9%'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 2, "migration preserves both rows");
    assert_eq!(
        row.get::<_, i64>(1),
        2,
        "migration recalculates both search vectors to NULL"
    );
}

async fn nostr_effect_import_is_idempotent(database_url: &str, store: &mut Store) {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
        .batch_execute(
            r#"
CREATE TABLE events (
    id text PRIMARY KEY,
    pubkey text NOT NULL,
    created_at bigint NOT NULL,
    kind integer NOT NULL,
    tags jsonb NOT NULL,
    content text NOT NULL,
    sig text NOT NULL,
    d_tag text
)
"#,
        )
        .await
        .unwrap();
    let event = signed_event(99, 99, 1, vec![], "legacy event");
    let group_event = signed_event(
        98,
        98,
        9,
        vec![Tag::new(vec!["h".into(), "legacy-group".into()])],
        "legacy group event",
    );
    let expired = signed_event(
        97,
        50,
        1,
        vec![Tag::new(vec!["expiration".into(), "60".into()])],
        "expired legacy event",
    );
    let private = signed_event(
        96,
        96,
        39_604,
        vec![Tag::new(vec!["d".into(), "9".repeat(64)])],
        "legacy private first",
    );
    let private_conflict = signed_event(
        96,
        97,
        39_604,
        private.tags.clone(),
        "legacy private changed bytes",
    );
    let insert = client
        .prepare(
            r#"
INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, d_tag)
VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, NULL)
"#,
        )
        .await
        .unwrap();
    for source in [&event, &group_event, &expired, &private, &private_conflict] {
        let tags = serde_json::to_string(&source.tags).unwrap();
        let created_at = source.created_at as i64;
        let kind = i32::from(source.kind);
        client
            .execute(
                &insert,
                &[
                    &source.id,
                    &source.pubkey,
                    &created_at,
                    &kind,
                    &tags,
                    &source.content,
                    &source.sig,
                ],
            )
            .await
            .unwrap();
    }

    let report = store.import_nostr_effect_events(NOW, None).await.unwrap();
    assert_eq!(report.scanned, 5);
    assert_eq!(report.stored, 3);
    assert_eq!(report.expired, 1);
    assert_eq!(report.rejected, 1);
    assert_eq!(report.rejection_reasons["mkt_idempotency_conflict"], 1);
    assert_eq!(
        store
            .event_by_id(&event.id, NOW)
            .await
            .unwrap()
            .unwrap()
            .event,
        event
    );
    assert_eq!(
        store
            .event_by_id(&group_event.id, NOW)
            .await
            .unwrap()
            .unwrap()
            .event,
        group_event,
        "legacy group history bypasses only newer group-derived admission"
    );
    assert!(store.event_by_id(&expired.id, NOW).await.unwrap().is_none());
    assert!(store.event_by_id(&private.id, NOW).await.unwrap().is_some());
    assert!(
        store
            .event_by_id(&private_conflict.id, NOW)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .import_nostr_effect_events(NOW, None)
            .await
            .unwrap()
            .is_empty(),
        "ledger makes the compatibility import idempotent"
    );
    let retry = store
        .retry_rejected_nostr_effect_events(NOW, None)
        .await
        .unwrap();
    assert_eq!(retry.scanned, 1);
    assert_eq!(retry.rejected, 1);
    assert_eq!(retry.rejection_reasons["mkt_idempotency_conflict"], 1);
}

async fn replacement_race(database_url: &str, store: &mut Store) {
    let first = signed_event(
        2,
        300,
        30_000,
        vec![Tag::new(vec!["d".into(), "race".into()])],
        "candidate one",
    );
    let second = signed_event(
        2,
        300,
        30_000,
        vec![Tag::new(vec!["d".into(), "race".into()])],
        "candidate two",
    );
    let (lower, higher) = if first.id < second.id {
        (first, second)
    } else {
        (second, first)
    };
    let mut other = Store::connect(database_url).await.unwrap();
    let (left, right) = tokio::join!(store.admit(&higher, NOW), other.admit(&lower, NOW));
    left.unwrap();
    right.unwrap();

    let filter = Filter {
        kinds: Some(vec![30_000]),
        tags: BTreeMap::from([('d', vec!["race".to_owned()])]),
        ..Filter::default()
    };
    let events = store.query_filter(&filter, NOW, 10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.id, lower.id, "lowest ID wins timestamp tie");
    assert!(store.event_by_id(&higher.id, NOW).await.unwrap().is_none());
}

async fn mkt_immutable_admission(database_url: &str, store: &mut Store) {
    for (offset, kind) in (39_604..=39_609).enumerate() {
        let identifier = format!("{:064x}", offset + 1);
        let first = signed_event(
            20,
            1_000,
            kind,
            vec![Tag::new(vec!["d".into(), identifier.clone()])],
            "first signed bytes",
        );
        assert!(matches!(
            store.admit(&first, NOW).await.unwrap(),
            AdmissionOutcome::Stored { .. }
        ));
        assert_eq!(
            store.admit(&first, NOW).await.unwrap(),
            AdmissionOutcome::Duplicate
        );
        if kind == 39_604 {
            let alternate_signature = with_alternate_signature(&first, 20);
            assert_ne!(alternate_signature.sig, first.sig);
            assert_eq!(alternate_signature.id, first.id);
            assert_eq!(
                store.admit(&alternate_signature, NOW).await.unwrap(),
                AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict),
                "event ID plus signature binds the exact signed event"
            );
        }

        for created_at in [999, 1_001] {
            let conflicting = signed_event(
                20,
                created_at,
                kind,
                vec![Tag::new(vec!["d".into(), identifier.clone()])],
                "changed signed bytes",
            );
            assert_eq!(
                store.admit(&conflicting, NOW).await.unwrap(),
                AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict),
                "private MKT conflict must not depend on timestamp ordering"
            );
        }
        assert!(store.event_by_id(&first.id, NOW).await.unwrap().is_some());
    }

    mkt_binding_survives_deletion_and_expiry(store).await;
    rejected_first_candidates_do_not_bind(database_url, store).await;

    let identifier = "f".repeat(64);
    let left = signed_event(
        21,
        1_100,
        39_604,
        vec![Tag::new(vec!["d".into(), identifier.clone()])],
        "concurrent left",
    );
    let right = signed_event(
        21,
        1_101,
        39_604,
        vec![Tag::new(vec!["d".into(), identifier])],
        "concurrent right",
    );
    let mut other = Store::connect(database_url).await.unwrap();
    let (left_outcome, right_outcome) =
        tokio::join!(store.admit(&left, NOW), other.admit(&right, NOW));
    let left_outcome = left_outcome.unwrap();
    let right_outcome = right_outcome.unwrap();
    assert!(matches!(
        (&left_outcome, &right_outcome),
        (
            AdmissionOutcome::Stored { .. },
            AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict)
        ) | (
            AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict),
            AdmissionOutcome::Stored { .. }
        )
    ));

    let (stored, conflicting) = if matches!(left_outcome, AdmissionOutcome::Stored { .. }) {
        (&left, &right)
    } else {
        (&right, &left)
    };
    assert_eq!(
        store.admit(stored, NOW).await.unwrap(),
        AdmissionOutcome::Duplicate
    );
    assert_eq!(
        store.admit(conflicting, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict)
    );

    let same_id = signed_event(
        26,
        1_102,
        39_604,
        vec![Tag::new(vec!["d".into(), "a".repeat(64)])],
        "same ID signature race",
    );
    let alternate_signature = with_alternate_signature(&same_id, 26);
    let mut other = Store::connect(database_url).await.unwrap();
    let (original_outcome, alternate_outcome) = tokio::join!(
        store.admit(&same_id, NOW),
        other.admit(&alternate_signature, NOW)
    );
    assert!(matches!(
        (original_outcome.unwrap(), alternate_outcome.unwrap()),
        (
            AdmissionOutcome::Stored { .. },
            AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict)
        ) | (
            AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict),
            AdmissionOutcome::Stored { .. }
        )
    ));

    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let private_heads = client
        .query_one(
            "SELECT count(*) FROM replaceable_head WHERE kind BETWEEN 39604 AND 39609",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(private_heads, 0, "private MKT bypasses generic head state");
    drop(client);
    driver.await.unwrap().unwrap();
}

async fn mkt_binding_survives_deletion_and_expiry(store: &mut Store) {
    let deleted = signed_event(
        22,
        1_200,
        39_605,
        vec![Tag::new(vec!["d".into(), "d".repeat(64)])],
        "delete-visible-copy",
    );
    assert!(matches!(
        store.admit(&deleted, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    let deletion = signed_event(
        22,
        1_201,
        5,
        vec![Tag::new(vec!["e".into(), deleted.id.clone()])],
        "NIP-09 is not market cancellation",
    );
    store.admit(&deletion, NOW).await.unwrap();
    assert!(store.event_by_id(&deleted.id, NOW).await.unwrap().is_none());
    let high_water = store.latest_ingest_seq().await.unwrap();
    assert_eq!(
        store.admit(&deleted, NOW).await.unwrap(),
        AdmissionOutcome::Duplicate,
        "replay after deletion returns the prior result without reinsertion"
    );
    assert_eq!(store.latest_ingest_seq().await.unwrap(), high_water);
    let deleted_conflict = signed_event(
        22,
        1_202,
        39_605,
        deleted.tags.clone(),
        "changed after deletion",
    );
    assert_eq!(
        store.admit(&deleted_conflict, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict)
    );
    assert!(store.event_by_id(&deleted.id, NOW).await.unwrap().is_none());

    let expiration = NOW + 100;
    let expired = signed_event(
        23,
        1_300,
        39_606,
        vec![
            Tag::new(vec!["d".into(), "e".repeat(64)]),
            Tag::new(vec!["expiration".into(), expiration.to_string()]),
        ],
        "expires visibly",
    );
    store.admit(&expired, NOW).await.unwrap();
    assert!(store.delete_expired(expiration).await.unwrap() >= 1);
    assert!(
        store
            .event_by_id(&expired.id, expiration)
            .await
            .unwrap()
            .is_none()
    );
    let high_water = store.latest_ingest_seq().await.unwrap();
    assert_eq!(
        store.admit(&expired, expiration).await.unwrap(),
        AdmissionOutcome::Duplicate,
        "binding lookup precedes expiration and does not resurrect the row"
    );
    assert_eq!(store.latest_ingest_seq().await.unwrap(), high_water);
    let expired_conflict = signed_event(
        23,
        1_301,
        39_606,
        vec![Tag::new(vec!["d".into(), "e".repeat(64)])],
        "changed after expiry",
    );
    assert_eq!(
        store.admit(&expired_conflict, expiration).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::MktIdempotencyConflict)
    );
}

async fn rejected_first_candidates_do_not_bind(database_url: &str, store: &mut Store) {
    let expired_first = signed_event(
        24,
        1_400,
        39_607,
        vec![
            Tag::new(vec!["d".into(), "1".repeat(64)]),
            Tag::new(vec!["expiration".into(), NOW.to_string()]),
        ],
        "first candidate is expired",
    );
    assert!(matches!(
        store.admit(&expired_first, NOW).await,
        Err(StoreError::Domain(_))
    ));
    let after_expired = signed_event(
        24,
        1_401,
        39_607,
        vec![Tag::new(vec!["d".into(), "1".repeat(64)])],
        "valid first acceptance",
    );
    assert!(matches!(
        store.admit(&after_expired, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));

    let deleted_identifier = "2".repeat(64);
    let deleted_address = format!("39608:{}:{deleted_identifier}", after_expired.pubkey);
    let deletion = signed_event(
        24,
        1_500,
        5,
        vec![Tag::new(vec!["a".into(), deleted_address])],
        "delete before first arrival",
    );
    store.admit(&deletion, NOW).await.unwrap();
    let deleted_first = signed_event(
        24,
        1_499,
        39_608,
        vec![Tag::new(vec!["d".into(), deleted_identifier.clone()])],
        "covered first candidate",
    );
    assert_eq!(
        store.admit(&deleted_first, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::Deleted)
    );
    let after_deleted = signed_event(
        24,
        1_501,
        39_608,
        vec![Tag::new(vec!["d".into(), deleted_identifier])],
        "accepted after tombstone boundary",
    );
    assert!(matches!(
        store.admit(&after_deleted, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));

    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    client
        .execute(
            "INSERT INTO relay_blocked_kind (kind, reason) VALUES ($1, $2)",
            &[&39_609_i32, &"MKT policy test"],
        )
        .await
        .unwrap();
    let blocked = signed_event(
        25,
        1_600,
        39_609,
        vec![Tag::new(vec!["d".into(), "3".repeat(64)])],
        "policy-rejected first candidate",
    );
    assert_eq!(
        store.admit(&blocked, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::BlockedKind(
            "MKT policy test".to_owned()
        ))
    );
    client
        .execute(
            "DELETE FROM relay_blocked_kind WHERE kind = $1",
            &[&39_609_i32],
        )
        .await
        .unwrap();
    drop(client);
    driver.await.unwrap().unwrap();
    let after_policy = signed_event(
        25,
        1_601,
        39_609,
        blocked.tags,
        "accepted after policy rejection",
    );
    assert!(matches!(
        store.admit(&after_policy, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
}

async fn deletion_before_event(_database_url: &str, store: &mut Store) {
    let target = signed_event(3, 400, 1, Vec::new(), "arrives too late");
    let deletion = signed_event(
        3,
        500,
        5,
        vec![Tag::new(vec!["e".into(), target.id.clone()])],
        "delete target",
    );
    store.admit(&deletion, NOW).await.unwrap();
    assert_eq!(
        store.admit(&target, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::Deleted)
    );

    let old = signed_event(
        3,
        600,
        30_001,
        vec![Tag::new(vec!["d".into(), "deleted-address".into()])],
        "old address version",
    );
    store.admit(&old, NOW).await.unwrap();
    let address = format!("30001:{}:deleted-address", old.pubkey);
    let address_deletion = signed_event(
        3,
        700,
        5,
        vec![Tag::new(vec!["a".into(), address])],
        "delete address",
    );
    store.admit(&address_deletion, NOW).await.unwrap();
    assert!(store.event_by_id(&old.id, NOW).await.unwrap().is_none());

    let newer = signed_event(
        3,
        701,
        30_001,
        vec![Tag::new(vec!["d".into(), "deleted-address".into()])],
        "new address version",
    );
    assert!(matches!(
        store.admit(&newer, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
}

async fn concurrent_deletion_race(database_url: &str, store: &mut Store) {
    let target = signed_event(4, 800, 1, Vec::new(), "racing target");
    let deletion = signed_event(
        4,
        801,
        5,
        vec![Tag::new(vec!["e".into(), target.id.clone()])],
        "racing deletion",
    );
    let mut other = Store::connect(database_url).await.unwrap();
    let (target_result, deletion_result) =
        tokio::join!(store.admit(&target, NOW), other.admit(&deletion, NOW));
    target_result.unwrap();
    assert!(matches!(
        deletion_result.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    assert!(store.event_by_id(&target.id, NOW).await.unwrap().is_none());
}

async fn concurrent_media_quota(database_url: &str, store: &mut Store) {
    let mut other = Store::connect(database_url).await.unwrap();
    let pubkey = "f".repeat(64);
    let first_authorization = "a".repeat(64);
    let first_hash = "b".repeat(64);
    let second_authorization = "c".repeat(64);
    let second_hash = "d".repeat(64);
    let first = store.register_media(
        &first_authorization,
        &pubkey,
        &first_hash,
        600,
        "application/octet-stream",
        NOW,
        1_000,
    );
    let second = other.register_media(
        &second_authorization,
        &pubkey,
        &second_hash,
        600,
        "application/octet-stream",
        NOW,
        1_000,
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Media(reason)) if reason.contains("quota")))
            .count(),
        1,
        "different hashes for one owner must serialize quota accounting"
    );
}

async fn policy_and_fts(database_url: &str, store: &mut Store) {
    let (admin, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);

    let blocked = signed_event(5, 900, 1, Vec::new(), "blocked author");
    let statement = admin
        .prepare("INSERT INTO relay_blocked_pubkey (pubkey, reason) VALUES ($1, $2)")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&blocked.pubkey, &"fixture block"])
        .await
        .unwrap();
    assert_eq!(
        store.admit(&blocked, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::BlockedPubkey(
            "fixture block".to_owned()
        ))
    );

    let blocked_kind = signed_event(7, 901, 42, Vec::new(), "blocked kind");
    let statement = admin
        .prepare("INSERT INTO relay_blocked_kind (kind, reason) VALUES ($1, $2)")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&42_i32, &"fixture kind block"])
        .await
        .unwrap();
    assert_eq!(
        store.admit(&blocked_kind, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::BlockedKind(
            "fixture kind block".to_owned()
        ))
    );

    let kind_not_allowed = signed_event(7, 902, 7, Vec::new(), "kind allowlist");
    let statement = admin
        .prepare("INSERT INTO relay_allowed_kind (kind, reason) VALUES ($1, $2)")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&1_i32, &"fixture allow"])
        .await
        .unwrap();
    assert_eq!(
        store.admit(&kind_not_allowed, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::KindNotAllowed)
    );
    let statement = admin
        .prepare("DELETE FROM relay_allowed_kind")
        .await
        .unwrap();
    admin.execute(&statement, &[]).await.unwrap();

    let allowed_author = signed_event(7, 903, 1, Vec::new(), "allowed author");
    let disallowed_author = signed_event(8, 903, 1, Vec::new(), "other author");
    let statement = admin
        .prepare("INSERT INTO relay_allowed_pubkey (pubkey, reason) VALUES ($1, $2)")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&allowed_author.pubkey, &"fixture allow"])
        .await
        .unwrap();
    assert_eq!(
        store.admit(&disallowed_author, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::PubkeyNotAllowed)
    );
    assert!(matches!(
        store.admit(&allowed_author, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    let statement = admin
        .prepare("DELETE FROM relay_allowed_pubkey")
        .await
        .unwrap();
    admin.execute(&statement, &[]).await.unwrap();

    let member = signed_event(9, 904, 1, Vec::new(), "closed relay member");
    let statement = admin
        .prepare("UPDATE relay_policy SET closed_membership = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&true]).await.unwrap();
    assert_eq!(
        store.admit(&member, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::NotMember)
    );
    let statement = admin
        .prepare("INSERT INTO relay_member_pubkey (pubkey, note) VALUES ($1, $2)")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&member.pubkey, &"fixture member"])
        .await
        .unwrap();
    assert!(matches!(
        store.admit(&member, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    let statement = admin
        .prepare("UPDATE relay_policy SET closed_membership = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&false]).await.unwrap();

    let oversized = signed_event(10, 905, 1, Vec::new(), "12345");
    let statement = admin
        .prepare("UPDATE relay_policy SET max_content_bytes = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&4_i64]).await.unwrap();
    assert_eq!(
        store.admit(&oversized, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::ContentTooLarge {
            actual_bytes: 5,
            max_bytes: 4,
        })
    );
    admin.execute(&statement, &[&131_072_i64]).await.unwrap();

    let overtagged = signed_event(
        10,
        906,
        1,
        vec![Tag::new(vec!["e".into(), "tag-limit".into()])],
        "tag bound",
    );
    let statement = admin
        .prepare("UPDATE relay_policy SET max_tags = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&0_i32]).await.unwrap();
    assert_eq!(
        store.admit(&overtagged, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::TooManyTags { actual: 1, max: 0 })
    );
    admin.execute(&statement, &[&256_i32]).await.unwrap();

    let future = signed_event(10, NOW + 1, 1, Vec::new(), "future bound");
    let statement = admin
        .prepare("UPDATE relay_policy SET max_future_seconds = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&0_i64]).await.unwrap();
    assert_eq!(
        store.admit(&future, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::TimestampTooFarInFuture {
            created_at: NOW + 1,
            latest_allowed: NOW,
        })
    );
    admin.execute(&statement, &[&900_i64]).await.unwrap();

    let old = signed_event(10, NOW - 2, 1, Vec::new(), "past bound");
    let statement = admin
        .prepare("UPDATE relay_policy SET max_past_seconds = $1 WHERE singleton = TRUE")
        .await
        .unwrap();
    admin.execute(&statement, &[&1_i64]).await.unwrap();
    assert_eq!(
        store.admit(&old, NOW).await.unwrap(),
        AdmissionOutcome::Rejected(AdmissionRejection::TimestampTooOld {
            created_at: NOW - 2,
            earliest_allowed: NOW - 1,
        })
    );
    admin.execute(&statement, &[&0_i64]).await.unwrap();

    let fts = admin
        .prepare(
            "SELECT count(*) FROM nostr_event WHERE search_vector @@ plainto_tsquery('simple', $1)",
        )
        .await
        .unwrap();
    let count = admin
        .query_one(&fts, &[&"searchable"])
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(count, 1);

    drop(admin);
    driver.await.unwrap().unwrap();
}

async fn least_privilege_runtime(database_url: &str) {
    let (admin, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    for sql in [
        "CREATE ROLE immortal_runtime_m2_test LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",
        "GRANT USAGE ON SCHEMA public TO immortal_runtime_m2_test",
        "GRANT SELECT ON schema_migrations TO immortal_runtime_m2_test",
        "GRANT SELECT, INSERT, DELETE ON nostr_event TO immortal_runtime_m2_test",
        "GRANT SELECT, INSERT ON nostr_indexed_tag TO immortal_runtime_m2_test",
        "GRANT SELECT, INSERT, UPDATE ON replaceable_head TO immortal_runtime_m2_test",
        "GRANT SELECT, INSERT ON mkt_immutable_coordinate TO immortal_runtime_m2_test",
        "GRANT SELECT, INSERT, UPDATE ON deletion_tombstone TO immortal_runtime_m2_test",
        "GRANT SELECT ON relay_policy, relay_allowed_pubkey, relay_allowed_kind, relay_member_pubkey, relay_blocked_pubkey, relay_blocked_kind TO immortal_runtime_m2_test",
        "GRANT USAGE, SELECT ON SEQUENCE nostr_event_ingest_seq_seq TO immortal_runtime_m2_test",
    ] {
        let statement = admin.prepare(sql).await.unwrap();
        admin.execute(&statement, &[]).await.unwrap();
    }
    drop(admin);
    driver.await.unwrap().unwrap();

    let runtime_url = format!("{database_url} user=immortal_runtime_m2_test");
    let mut runtime = Store::connect_verified(&runtime_url).await.unwrap();
    let event = signed_event(6, 50, 7, Vec::new(), "least privilege write");
    assert!(matches!(
        runtime.admit(&event, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    assert!(runtime.event_by_id(&event.id, NOW).await.unwrap().is_some());
    let private = signed_event(
        6,
        51,
        39_604,
        vec![Tag::new(vec!["d".into(), "6".repeat(64)])],
        "least privilege immutable write",
    );
    assert!(matches!(
        runtime.admit(&private, NOW).await.unwrap(),
        AdmissionOutcome::Stored { .. }
    ));
    assert!(
        runtime
            .event_by_id(&private.id, NOW)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        runtime.admit(&private, NOW).await.unwrap(),
        AdmissionOutcome::Duplicate
    );
}

async fn migration_hash_drift_fails_closed(database_url: &str) {
    let (admin, connection) = tokio_postgres::connect(database_url, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let statement = admin
        .prepare("UPDATE schema_migrations SET sha256 = $1 WHERE version = $2")
        .await
        .unwrap();
    admin
        .execute(&statement, &[&"0".repeat(64), &1_i64])
        .await
        .unwrap();
    drop(admin);
    driver.await.unwrap().unwrap();

    let error = match Store::connect_verified(database_url).await {
        Ok(_) => panic!("changed migration hash was accepted"),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::MigrationDrift(_)));
}

fn signed_event(
    secret_byte: u8,
    created_at: u64,
    kind: u16,
    mut tags: Vec<Tag>,
    content: &str,
) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let pubkey = keypair.x_only_public_key().0.to_string();
    let content = if (39_604..=39_609).contains(&kind) {
        let session = tags
            .iter()
            .find(|tag| tag.name() == Some("session"))
            .and_then(|tag| tag.0.get(1))
            .cloned()
            .unwrap_or_else(|| {
                let session = format!("{secret_byte:02x}").repeat(32);
                tags.extend([
                    Tag::new(vec!["session".into(), session.clone()]),
                    Tag::new(vec!["profile".into(), "conformance".into(), "1".into()]),
                    Tag::new(vec![
                        "p".into(),
                        "c".repeat(64),
                        String::new(),
                        "provider".into(),
                    ]),
                    Tag::new(vec!["alt".into(), "NIP-MKT store fixture".into()]),
                ]);
                session
            });
        serde_json::json!({
            "schema": "openagents.mkt.v1",
            "profile": "conformance",
            "profile_version": 1,
            "session_id": session,
            "payload": content,
        })
        .to_string()
    } else {
        content.to_owned()
    };
    let mut event = Event {
        id: "0".repeat(64),
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: "0".repeat(128),
    };
    let id_bytes = event.computed_id_bytes().unwrap();
    event.id = event.computed_id().unwrap();
    event.sig = secp
        .sign_schnorr_no_aux_rand(&id_bytes, &keypair)
        .to_string();
    event
}

fn with_alternate_signature(event: &Event, secret_byte: u8) -> Event {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_byte_array([secret_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let mut alternate = event.clone();
    let id_bytes = alternate.computed_id_bytes().unwrap();
    alternate.sig = secp
        .sign_schnorr_with_aux_rand(&id_bytes, &keypair, &[1; 32])
        .to_string();
    alternate
}
