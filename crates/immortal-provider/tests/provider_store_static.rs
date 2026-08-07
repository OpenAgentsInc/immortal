const STORE: &str = include_str!("../src/store.rs");
const MIGRATION_V1: &str = include_str!("../../../migrations/provider/0001_provider_store.sql");
const MIGRATION_V2: &str =
    include_str!("../../../migrations/provider/0002_boltz_invoice_binding.sql");
const MIGRATION_V3: &str =
    include_str!("../../../migrations/provider/0003_restore_safe_public_json.sql");
const MIGRATION_V4: &str = include_str!("../../../migrations/provider/0004_ark_reserve_unit.sql");
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
        assert!(MIGRATION_V1.contains(&format!("CREATE TABLE {table}")));
    }
    assert!(MIGRATION_V2.contains("CREATE TABLE provider_boltz_invoice_binding"));
    assert!(MIGRATION_V2.contains("payment_hash text COLLATE \"C\" PRIMARY KEY"));
    assert!(MIGRATION_V2.contains("status_event_id text COLLATE \"C\" NOT NULL UNIQUE"));
    assert!(MIGRATION_V2.contains("provider_boltz_invoice_binding_session"));
    assert!(MIGRATION_V2.contains("provider_boltz_invoice_candidate_session"));
    assert!(!MIGRATION_V2.contains("INSERT INTO provider_boltz_invoice_binding"));
    assert!(
        MIGRATION_V3.contains(
            "CREATE OR REPLACE FUNCTION public.provider_public_json_safe(document jsonb)"
        )
    );
    assert!(MIGRATION_V3.contains("public.provider_public_json_safe(member.value)"));
    assert!(
        MIGRATION_V3.contains(
            "CREATE OR REPLACE FUNCTION public.provider_signed_event_safe(document jsonb)"
        )
    );
    assert!(MIGRATION_V3.contains("RETURN public.provider_public_json_safe(content)"));
    assert!(MIGRATION_V4.contains("CREATE TABLE provider_ark_reserve_unit"));
    assert!(MIGRATION_V4.contains("provider_ark_reserve_unit_blocking"));
    assert!(MIGRATION_V4.contains("WHERE state IN ('active', 'unresolved')"));

    assert!(MIGRATION_V1.contains("provider_signed_event_safe"));
    assert!(MIGRATION_V1.contains("provider_public_json_safe"));
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
            MIGRATION_V1.contains(&format!("position('{fragment}' IN normalized) > 0")),
            "missing normalized custody fragment {fragment}"
        );
    }
    assert!(!MIGRATION_V1.contains("seed text"));
    assert!(!MIGRATION_V1.contains("preimage text"));
    assert!(!MIGRATION_V1.contains("macaroon text"));
    assert!(!MIGRATION_V1.contains("private_key text"));
    assert!(!MIGRATION_V2.contains("preimage"));
    assert!(!MIGRATION_V2.contains("private_key"));
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
    assert!(STORE.contains("SELECT_BOLTZ_INVOICE_BINDING_SQL"));
    assert!(STORE.contains("SELECT_BOLTZ_INVOICE_CANDIDATE_SESSIONS_SQL"));
    assert!(STORE.contains("binding.session_id = record.session_id"));
    assert!(STORE.contains("MAX_STARTUP_INVOICE_RECONCILIATION: usize = 64"));
    assert!(STORE.contains("spawn_invoice_binding_reconciliation"));
    assert!(STORE.contains("persist_validated_invoice_binding"));
    assert!(STORE.contains("BOLT11 and Contract payment hashes differ"));
    assert!(STORE.contains("hold_invoice_ready"));
    assert!(!STORE.contains("bounded_session_records"));
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
