const STORE: &str = include_str!("../src/store.rs");
const MIGRATION: &str = include_str!("../../../migrations/provider/0001_provider_store.sql");
const NO_SPEND: &str = include_str!("../src/no_spend.rs");

#[test]
fn provider_store_schema_has_public_state_and_custody_tripwires() {
    for table in [
        "provider_session_record",
        "provider_session_disposition",
        "provider_exit_package",
        "provider_effect",
        "provider_capacity_bucket",
        "provider_reservation",
        "provider_utxo",
        "provider_watch_job",
        "provider_alert",
    ] {
        assert!(MIGRATION.contains(&format!("CREATE TABLE {table}")));
    }

    assert!(MIGRATION.contains("provider_signed_event_safe"));
    assert!(MIGRATION.contains("provider_public_json_safe"));
    for fragment in [
        "seed",
        "preimage",
        "privatekey",
        "spendkey",
        "claimkey",
        "refundkey",
        "macaroon",
        "credential",
    ] {
        assert!(
            MIGRATION.contains(&format!("position('{fragment}' IN normalized) > 0")),
            "missing normalized custody fragment {fragment}"
        );
    }
    assert!(!MIGRATION.contains("seed text"));
    assert!(!MIGRATION.contains("preimage text"));
    assert!(!MIGRATION.contains("macaroon text"));
    assert!(!MIGRATION.contains("private_key text"));
}

#[test]
fn provider_store_uses_prepared_runtime_statements_and_bounded_queries() {
    assert!(!STORE.contains(".query(\""));
    assert!(!STORE.contains(".query_one(\""));
    assert!(!STORE.contains(".query_opt(\""));
    assert!(!STORE.contains(".execute(\""));
    assert!(STORE.contains("pg_advisory_xact_lock"));
    assert!(STORE.contains("FOR UPDATE SKIP LOCKED LIMIT $3"));
    assert!(STORE.contains("ORDER BY updated_at, job_id LIMIT $1"));
    assert!(STORE.contains("MAX_SESSION_RECORDS"));
    assert!(STORE.contains("provider_session_disposition"));
    assert!(STORE.contains("MAX_RESERVATION_UTXOS"));
    assert!(STORE.contains("MAX_WATCH_CLAIM"));
    assert!(STORE.contains("MAX_ALERT_QUERY"));
}

#[test]
fn no_spend_mode_has_no_provider_database_path() {
    assert!(!NO_SPEND.contains("tokio_postgres"));
    assert!(!NO_SPEND.contains("ProviderStore"));
    assert!(!NO_SPEND.contains("DATABASE_URL"));
}
