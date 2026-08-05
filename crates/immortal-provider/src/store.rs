//! Durable public provider state for funded operation.

mod migration;

use std::fmt;

use immortal_client::mkt_swp_client::provider_support::reject_custody_material;
use immortal_core::domain::Event;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls, Transaction};

pub use migration::ProviderMigrationReport;

pub(crate) const MAX_SESSION_RECORDS: usize = 512;
pub(crate) const MAX_SESSION_QUERY: usize = 512;
pub(crate) const MAX_ACTIVE_SESSION_RECORD_QUERY: usize = 12 * MAX_SESSION_RECORDS;
pub(crate) const MAX_RESERVATION_UTXOS: usize = 64;
pub(crate) const MAX_WATCH_CLAIM: usize = 64;
pub(crate) const MAX_ALERT_QUERY: usize = 128;
pub(crate) const MAX_JSON_BYTES: usize = 1024 * 1024;
pub(crate) const HEALTH_COUNT_SCAN_LIMIT: i64 = 10_001;

const INSERT_RECORD_SQL: &str = r#"
INSERT INTO provider_session_record
    (event_id, session_id, author_pubkey, kind, created_at, event_sha256, signed_event)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (event_id) DO NOTHING
"#;
const SELECT_RECORD_SQL: &str = "SELECT session_id, event_sha256, signed_event FROM provider_session_record WHERE event_id = $1";
const LOCK_SESSION_ADVISORY_SQL: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended('provider-session:' || $1, 0))";
const COUNT_SESSION_RECORDS_SQL: &str =
    "SELECT count(*) FROM provider_session_record WHERE session_id = $1";
const SELECT_SESSION_RECORDS_SQL: &str = r#"
SELECT signed_event FROM provider_session_record
WHERE session_id = $1 ORDER BY created_at, event_id LIMIT $2
"#;
const HAS_SESSION_RECORDS_SQL: &str = "SELECT EXISTS (SELECT 1 FROM provider_session_record)";
const SELECT_ACTIVE_SESSION_RECORDS_SQL: &str = r#"
SELECT record.session_id, record.signed_event
FROM provider_session_record AS record
WHERE NOT EXISTS (
    SELECT 1 FROM provider_session_disposition AS disposition
    WHERE disposition.session_id = record.session_id
)
ORDER BY record.session_id, record.created_at, record.event_id
LIMIT $1
"#;
const SELECT_BOUNDED_SESSION_RECORDS_SQL: &str = r#"
SELECT session_id, signed_event
FROM provider_session_record
ORDER BY session_id, created_at, event_id
LIMIT $1
"#;
const INSERT_SESSION_DISPOSITION_SQL: &str = r#"
INSERT INTO provider_session_disposition (session_id, reason_code, disposed_at)
VALUES ($1, $2, $3)
ON CONFLICT (session_id) DO NOTHING
"#;
const SELECT_SESSION_DISPOSITION_SQL: &str = r#"
SELECT reason_code FROM provider_session_disposition WHERE session_id = $1
"#;

const UPSERT_EXIT_PACKAGE_SQL: &str = r#"
INSERT INTO provider_exit_package
    (package_id, session_id, order_id, leg_id, path, package_sha256,
     public_package, state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'prepared', $8, $8)
ON CONFLICT (package_id) DO NOTHING
"#;
const SELECT_EXIT_PACKAGE_SQL: &str = r#"
SELECT session_id, order_id, leg_id, path, package_sha256, public_package, state, created_at
FROM provider_exit_package WHERE package_id = $1
"#;
const LOCK_EXIT_PACKAGE_SQL: &str = r#"
SELECT session_id, order_id, leg_id, path, package_sha256, public_package, state, created_at
FROM provider_exit_package WHERE package_id = $1 FOR UPDATE
"#;
const UPDATE_EXIT_PACKAGE_STATE_SQL: &str = r#"
UPDATE provider_exit_package SET state = $2, updated_at = GREATEST(updated_at, $3)
WHERE package_id = $1
"#;

const INSERT_EFFECT_SQL: &str = r#"
INSERT INTO provider_effect
    (effect_id, session_id, operation, request_sha256, public_request,
     state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'pending', $6, $6)
ON CONFLICT (effect_id) DO NOTHING
"#;
const SELECT_EFFECT_SQL: &str = r#"
SELECT session_id, operation, request_sha256, public_request, state,
       result_sha256, public_result, external_reference, created_at
FROM provider_effect WHERE effect_id = $1
"#;
const LOCK_EFFECT_SQL: &str = r#"
SELECT session_id, operation, request_sha256, public_request, state,
       result_sha256, public_result, external_reference, created_at
FROM provider_effect WHERE effect_id = $1 FOR UPDATE
"#;
const COMPLETE_EFFECT_SQL: &str = r#"
UPDATE provider_effect
SET state = 'applied', result_sha256 = $2, public_result = $3,
    external_reference = $4, updated_at = GREATEST(updated_at, $5)
WHERE effect_id = $1
"#;
const MARK_EFFECT_UNRESOLVED_SQL: &str = r#"
UPDATE provider_effect
SET state = 'unresolved', updated_at = GREATEST(updated_at, $2)
WHERE effect_id = $1 AND state = 'pending'
"#;

const UPSERT_BUCKET_SQL: &str = r#"
INSERT INTO provider_capacity_bucket
    (bucket_id, asset_id, total_capacity, allocated_capacity, allocation_sequence, updated_at)
VALUES ($1, $2, $3, 0, 0, $4)
ON CONFLICT (bucket_id) DO UPDATE
SET asset_id = EXCLUDED.asset_id,
    total_capacity = EXCLUDED.total_capacity,
    updated_at = GREATEST(provider_capacity_bucket.updated_at, EXCLUDED.updated_at)
WHERE provider_capacity_bucket.allocated_capacity <= EXCLUDED.total_capacity
  AND provider_capacity_bucket.asset_id = EXCLUDED.asset_id
"#;
const LOCK_BUCKET_ADVISORY_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const LOCK_BUCKET_SQL: &str = r#"
SELECT asset_id, total_capacity, allocated_capacity, allocation_sequence
FROM provider_capacity_bucket WHERE bucket_id = $1 FOR UPDATE
"#;
const SELECT_AVAILABLE_CAPACITY_SQL: &str = r#"
SELECT total_capacity - allocated_capacity
FROM provider_capacity_bucket WHERE bucket_id = $1
"#;
const UPDATE_BUCKET_RESERVE_SQL: &str = r#"
UPDATE provider_capacity_bucket
SET allocated_capacity = allocated_capacity + $2,
    allocation_sequence = allocation_sequence + 1,
    updated_at = GREATEST(updated_at, $3)
WHERE bucket_id = $1
"#;
const UPDATE_BUCKET_RELEASE_SQL: &str = r#"
UPDATE provider_capacity_bucket
SET allocated_capacity = allocated_capacity - $2,
    updated_at = GREATEST(updated_at, $3)
WHERE bucket_id = $1 AND allocated_capacity >= $2
"#;

const UPSERT_UTXO_SQL: &str = r#"
INSERT INTO provider_utxo
    (txid, vout, asset_id, amount, script_pubkey, state, confirmations,
     block_hash, replacement_txid, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (txid, vout) DO UPDATE
SET confirmations = EXCLUDED.confirmations,
    block_hash = EXCLUDED.block_hash,
    replacement_txid = EXCLUDED.replacement_txid,
    observed_at = GREATEST(provider_utxo.observed_at, EXCLUDED.observed_at),
    state = CASE
        WHEN provider_utxo.state = 'reserved' AND EXCLUDED.state = 'available'
            THEN provider_utxo.state
        ELSE EXCLUDED.state
    END
WHERE provider_utxo.asset_id = EXCLUDED.asset_id
  AND provider_utxo.amount = EXCLUDED.amount
  AND provider_utxo.script_pubkey = EXCLUDED.script_pubkey
"#;
const LOCK_UTXO_SQL: &str = r#"
SELECT asset_id, amount, state, reservation_id
FROM provider_utxo WHERE txid = $1 AND vout = $2 FOR UPDATE
"#;
const RESERVE_UTXO_SQL: &str = r#"
UPDATE provider_utxo
SET state = 'reserved', reservation_id = $3,
    observed_at = GREATEST(observed_at, $4)
WHERE txid = $1 AND vout = $2 AND state = 'available' AND reservation_id IS NULL
"#;
const RELEASE_UTXOS_SQL: &str = r#"
UPDATE provider_utxo
SET state = 'available', reservation_id = NULL,
    observed_at = GREATEST(observed_at, $2)
WHERE reservation_id = $1 AND state = 'reserved'
"#;
const SELECT_AVAILABLE_UTXOS_SQL: &str = r#"
SELECT txid, vout, asset_id, amount, script_pubkey, state, confirmations,
       block_hash, replacement_txid, observed_at
FROM provider_utxo
WHERE asset_id = $1 AND state = 'available' AND confirmations >= $2
  AND script_pubkey = ANY($3::text[])
ORDER BY amount DESC, txid, vout LIMIT $4
"#;
const SELECT_RESERVED_UTXOS_SQL: &str = r#"
SELECT txid, vout, asset_id, amount, script_pubkey, state, confirmations,
       block_hash, replacement_txid, observed_at
FROM provider_utxo
WHERE reservation_id = $1 AND state = 'reserved'
ORDER BY txid, vout LIMIT $2
"#;

const LOCK_RESERVATION_SQL: &str = r#"
SELECT reservation_id, effect_id, session_id, bucket_id, asset_id, amount, request_sha256,
       allocation_sequence, expires_at, state, release_cause
FROM provider_reservation WHERE reservation_id = $1 FOR UPDATE
"#;
const SELECT_RESERVATION_SQL: &str = r#"
SELECT reservation_id, effect_id, session_id, bucket_id, asset_id, amount, request_sha256,
       allocation_sequence, expires_at, state, release_cause
FROM provider_reservation WHERE reservation_id = $1
"#;
const INSERT_RESERVATION_SQL: &str = r#"
INSERT INTO provider_reservation
    (reservation_id, effect_id, session_id, bucket_id, asset_id, amount,
     request_sha256, allocation_sequence, expires_at, state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $10)
"#;
const RELEASE_RESERVATION_SQL: &str = r#"
UPDATE provider_reservation
SET state = 'released', release_cause = $2,
    updated_at = GREATEST(updated_at, $3)
WHERE reservation_id = $1 AND state = 'active'
"#;
const MARK_RESERVATION_UNRESOLVED_SQL: &str = r#"
UPDATE provider_reservation
SET state = 'unresolved', release_cause = $2,
    updated_at = GREATEST(updated_at, $3)
WHERE reservation_id = $1 AND state = 'active'
"#;

const INSERT_WATCH_SQL: &str = r#"
INSERT INTO provider_watch_job
    (job_id, session_id, effect_id, job_kind, request_sha256, public_payload,
     state, due_height, due_at, maximum_attempts, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $10)
ON CONFLICT (job_id) DO NOTHING
"#;
const SELECT_WATCH_SQL: &str = r#"
SELECT session_id, effect_id, job_kind, request_sha256, public_payload, state,
       due_height, due_at, attempt_count, maximum_attempts, result_sha256,
       public_result, broadcast_txid, replacement_txid, confirmations,
       observed_block_hash, last_chain_event, page_code
FROM provider_watch_job WHERE job_id = $1
"#;
const LOCK_WATCH_SQL: &str = r#"
SELECT session_id, effect_id, job_kind, request_sha256, public_payload, state,
       due_height, due_at, attempt_count, maximum_attempts, result_sha256,
       public_result, broadcast_txid, replacement_txid, confirmations,
       observed_block_hash, last_chain_event, page_code
FROM provider_watch_job WHERE job_id = $1 FOR UPDATE
"#;
const CLAIM_WATCH_SQL: &str = r#"
SELECT job_id FROM provider_watch_job
WHERE (state = 'pending' OR (state = 'running' AND lease_until <= $2))
  AND (due_height IS NULL OR due_height <= $1)
  AND (due_at IS NULL OR due_at <= $2)
ORDER BY COALESCE(due_height, 9223372036854775807),
         COALESCE(due_at, 9223372036854775807), job_id
FOR UPDATE SKIP LOCKED LIMIT $3
"#;
const MARK_WATCH_RUNNING_SQL: &str = r#"
UPDATE provider_watch_job
SET state = CASE WHEN attempt_count + 1 >= maximum_attempts THEN 'page' ELSE 'running' END,
    attempt_count = attempt_count + 1,
    lease_until = $2,
    page_code = CASE WHEN attempt_count + 1 >= maximum_attempts THEN 'attempts_exhausted' ELSE page_code END,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1
"#;
const RECORD_BROADCAST_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'broadcast', result_sha256 = $2, public_result = $3,
    broadcast_txid = $4, lease_until = NULL,
    updated_at = GREATEST(updated_at, $5)
WHERE job_id = $1
  AND state IN ('pending', 'running', 'broadcast')
"#;
const RECORD_CONFIRMATION_SQL: &str = r#"
UPDATE provider_watch_job
SET state = CASE WHEN $2::integer >= $3::integer THEN 'confirmed' ELSE 'broadcast' END,
    confirmations = $2::integer, observed_block_hash = $4,
    last_chain_event = 'confirmation', lease_until = NULL,
    updated_at = GREATEST(updated_at, $5)
WHERE job_id = $1 AND state IN ('pending', 'running', 'broadcast', 'confirmed')
"#;
const RECORD_REORG_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'pending', confirmations = 0, observed_block_hash = $2,
    last_chain_event = 'reorg', lease_until = NULL,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1 AND state IN ('broadcast', 'confirmed')
"#;
const RECORD_REPLACEMENT_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'pending', replacement_txid = $2, confirmations = 0,
    last_chain_event = 'replacement', lease_until = NULL,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1 AND state IN ('broadcast', 'confirmed')
"#;
const PAGE_WATCH_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'page', page_code = $2, lease_until = NULL,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1
"#;
const MARK_WATCH_UNRESOLVED_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'unresolved', page_code = $2, lease_until = NULL,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1 AND state <> 'completed'
"#;
const COMPLETE_WATCH_SQL: &str = r#"
UPDATE provider_watch_job
SET state = 'completed', last_chain_event = $2, lease_until = NULL,
    updated_at = GREATEST(updated_at, $3)
WHERE job_id = $1
  AND state IN ('pending', 'running', 'broadcast', 'confirmed', 'completed')
"#;
const SELECT_WATCH_OBSERVATION_SQL: &str = r#"
SELECT session_id, effect_id, job_kind, request_sha256, public_payload, state,
       due_height, due_at, attempt_count, maximum_attempts, result_sha256,
       public_result, broadcast_txid, replacement_txid, confirmations,
       observed_block_hash, last_chain_event, page_code, job_id
FROM provider_watch_job
WHERE state IN ('broadcast', 'confirmed')
ORDER BY updated_at, job_id LIMIT $1
"#;

const INSERT_ALERT_SQL: &str = r#"
INSERT INTO provider_alert
    (alert_id, session_id, alert_class, detail_code, public_context, state, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'active', $6, $6)
ON CONFLICT (alert_id) DO UPDATE
SET detail_code = EXCLUDED.detail_code,
    public_context = EXCLUDED.public_context,
    state = 'active',
    updated_at = GREATEST(provider_alert.updated_at, EXCLUDED.updated_at)
"#;
const SELECT_ALERTS_SQL: &str = r#"
SELECT alert_id, session_id, alert_class, detail_code, public_context, state
FROM provider_alert WHERE state <> 'resolved' ORDER BY updated_at, alert_id LIMIT $1
"#;
const SELECT_ALERT_SQL: &str = r#"
SELECT alert_id, session_id, alert_class, detail_code, public_context, state
FROM provider_alert WHERE alert_id = $1
"#;
const SET_ALERT_STATE_SQL: &str = r#"
UPDATE provider_alert SET state = $2, updated_at = GREATEST(updated_at, $3)
WHERE alert_id = $1
"#;
const SELECT_HEALTH_COUNTS_SQL: &str = r#"
SELECT
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_reservation WHERE state = 'active' LIMIT $1
    ) bounded_active_reservations),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_reservation WHERE state = 'unresolved' LIMIT $1
    ) bounded_unresolved_reservations),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_effect WHERE state = 'pending' LIMIT $1
    ) bounded_pending_effects),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_effect WHERE state = 'unresolved' LIMIT $1
    ) bounded_unresolved_effects),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_watch_job WHERE state IN ('pending', 'running') LIMIT $1
    ) bounded_pending_watches),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_watch_job WHERE state = 'unresolved' LIMIT $1
    ) bounded_unresolved_watches),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_watch_job WHERE state = 'page' LIMIT $1
    ) bounded_paged_watches),
    (SELECT count(*) FROM (
        SELECT 1 FROM provider_alert WHERE state <> 'resolved' LIMIT $1
    ) bounded_active_alerts)
"#;

#[derive(Debug)]
pub enum ProviderStoreError {
    Database(tokio_postgres::Error),
    InvalidInput(String),
    Conflict(String),
    NotFound(String),
    MigrationDrift(String),
    ConnectionClosed,
}

impl fmt::Display for ProviderStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "provider database error: {error}"),
            Self::InvalidInput(error) => write!(formatter, "invalid provider store input: {error}"),
            Self::Conflict(error) => write!(formatter, "provider store conflict: {error}"),
            Self::NotFound(error) => write!(formatter, "provider store row missing: {error}"),
            Self::MigrationDrift(error) => write!(formatter, "provider migration drift: {error}"),
            Self::ConnectionClosed => write!(formatter, "provider database connection closed"),
        }
    }
}

impl std::error::Error for ProviderStoreError {}

impl From<tokio_postgres::Error> for ProviderStoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreWriteOutcome {
    Stored,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicExitPackage {
    pub package_id: String,
    pub session_id: String,
    pub order_id: String,
    pub leg_id: String,
    pub path: String,
    pub package_sha256: String,
    pub public_package: Value,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredPublicExitPackage {
    pub package: PublicExitPackage,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicEffectRequest {
    pub effect_id: String,
    pub session_id: String,
    pub operation: String,
    pub request_sha256: String,
    pub public_request: Value,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredPublicEffect {
    pub request: PublicEffectRequest,
    pub state: String,
    pub result_sha256: Option<String>,
    pub public_result: Option<Value>,
    pub external_reference: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PublicEffectResult {
    pub effect_id: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub public_result: Value,
    pub external_reference: String,
    pub completed_at: u64,
}

#[derive(Debug, Clone)]
pub struct UtxoObservation {
    pub outpoint: OutPoint,
    pub asset_id: String,
    pub amount: u64,
    pub script_pubkey: String,
    pub state: String,
    pub confirmations: u32,
    pub block_hash: Option<String>,
    pub replacement_txid: Option<String>,
    pub observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUtxo {
    pub outpoint: OutPoint,
    pub asset_id: String,
    pub amount: u64,
    pub script_pubkey: String,
    pub state: String,
    pub confirmations: u32,
    pub block_hash: Option<String>,
    pub replacement_txid: Option<String>,
    pub observed_at: u64,
}

#[derive(Debug, Clone)]
pub struct HardReservationRequest {
    pub reservation_id: String,
    pub effect_id: String,
    pub session_id: String,
    pub bucket_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub request_sha256: String,
    pub expected_allocation_sequence: u64,
    pub expires_at: u64,
    pub utxos: Vec<OutPoint>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRecord {
    pub reservation_id: String,
    pub effect_id: String,
    pub session_id: String,
    pub bucket_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub request_sha256: String,
    pub allocation_sequence: u64,
    pub expires_at: u64,
    pub state: String,
    pub release_cause: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationOutcome {
    Reserved(ReservationRecord),
    Replay(ReservationRecord),
    InsufficientCapacity,
    AllocationSequenceMismatch { current: u64 },
    UtxoUnavailable(OutPoint),
}

#[derive(Debug, Clone)]
pub struct WatchJobRequest {
    pub job_id: String,
    pub session_id: String,
    pub effect_id: Option<String>,
    pub job_kind: String,
    pub request_sha256: String,
    pub public_payload: Value,
    pub due_height: Option<u64>,
    pub due_at: Option<u64>,
    pub maximum_attempts: u16,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WatchJob {
    pub job_id: String,
    pub session_id: String,
    pub effect_id: Option<String>,
    pub job_kind: String,
    pub request_sha256: String,
    pub public_payload: Value,
    pub state: String,
    pub due_height: Option<u64>,
    pub due_at: Option<u64>,
    pub attempt_count: u16,
    pub maximum_attempts: u16,
    pub result_sha256: Option<String>,
    pub public_result: Option<Value>,
    pub broadcast_txid: Option<String>,
    pub replacement_txid: Option<String>,
    pub confirmations: u32,
    pub observed_block_hash: Option<String>,
    pub last_chain_event: Option<String>,
    pub page_code: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PublicAlert {
    pub alert_id: String,
    pub session_id: Option<String>,
    pub alert_class: String,
    pub detail_code: String,
    pub public_context: Value,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStoreHealth {
    pub active_reservations: u64,
    pub unresolved_reservations: u64,
    pub pending_effects: u64,
    pub unresolved_effects: u64,
    pub pending_watch_jobs: u64,
    pub unresolved_watch_jobs: u64,
    pub paged_watch_jobs: u64,
    pub active_alerts: u64,
}

#[derive(Debug, Clone)]
pub struct SessionRecordRecovery {
    pub records: Vec<Event>,
    pub has_prior_records: bool,
}

pub struct ProviderStore {
    client: Client,
    connection: JoinHandle<()>,
}

impl ProviderStore {
    pub async fn connect(
        database_url: &str,
    ) -> Result<(Self, ProviderMigrationReport), ProviderStoreError> {
        let (mut client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
        let connection = tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("provider database connection failed: {error}");
            }
        });
        let report = migration::apply(&mut client).await?;
        Ok((Self { client, connection }, report))
    }

    pub async fn connect_verified(database_url: &str) -> Result<Self, ProviderStoreError> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
        let connection = tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("provider database connection failed: {error}");
            }
        });
        migration::verify(&client).await?;
        Ok(Self { client, connection })
    }

    pub fn is_current(&self) -> bool {
        !self.connection.is_finished()
    }

    pub async fn persist_session_record(
        &mut self,
        event: &Event,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        let session_id = exactly_one_tag(event, "session")?;
        validate_hex(&event.id, "event ID")?;
        validate_hex(&event.pubkey, "event author")?;
        let signed_event = serde_json::to_value(event)
            .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))?;
        validate_signed_event(&signed_event)?;
        let event_bytes = bounded_json(&signed_event)?;
        let event_sha256 = digest(&event_bytes);
        let kind = i32::from(event.kind);
        let created_at = database_u64(event.created_at, "event created_at")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_SESSION_ADVISORY_SQL).await?;
        transaction.execute(&lock, &[&session_id]).await?;
        let select = transaction.prepare(SELECT_RECORD_SQL).await?;
        if let Some(row) = transaction.query_opt(&select, &[&event.id]).await? {
            let matches = row.get::<_, String>(0) == session_id
                && row.get::<_, String>(1) == event_sha256
                && row.get::<_, Value>(2) == signed_event;
            transaction.commit().await?;
            return replay_or_conflict(matches, "signed session record");
        }
        let count = transaction.prepare(COUNT_SESSION_RECORDS_SQL).await?;
        let existing_count: i64 = transaction.query_one(&count, &[&session_id]).await?.get(0);
        if existing_count >= i64::try_from(MAX_SESSION_RECORDS).unwrap_or(i64::MAX) {
            return Err(ProviderStoreError::InvalidInput(
                "session record bound reached".to_owned(),
            ));
        }
        let insert = transaction.prepare(INSERT_RECORD_SQL).await?;
        let inserted = transaction
            .execute(
                &insert,
                &[
                    &event.id,
                    &session_id,
                    &event.pubkey,
                    &kind,
                    &created_at,
                    &event_sha256,
                    &signed_event,
                ],
            )
            .await?;
        if inserted == 1 {
            transaction.commit().await?;
            return Ok(StoreWriteOutcome::Stored);
        }
        let row = transaction.query_one(&select, &[&event.id]).await?;
        let matches = row.get::<_, String>(0) == session_id
            && row.get::<_, String>(1) == event_sha256
            && row.get::<_, Value>(2) == signed_event;
        transaction.commit().await?;
        if matches {
            Ok(StoreWriteOutcome::Replay)
        } else {
            Err(ProviderStoreError::Conflict(
                "event ID is bound to different signed bytes".to_owned(),
            ))
        }
    }

    pub async fn session_records(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<Event>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(session_id, "session ID")?;
        let limit = bounded_limit(limit, MAX_SESSION_QUERY)?;
        let statement = self.client.prepare(SELECT_SESSION_RECORDS_SQL).await?;
        self.client
            .query(&statement, &[&session_id, &limit])
            .await?
            .into_iter()
            .map(|row| {
                serde_json::from_value(row.get::<_, Value>(0))
                    .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))
            })
            .collect()
    }

    pub async fn active_session_records(
        &self,
        limit: usize,
    ) -> Result<SessionRecordRecovery, ProviderStoreError> {
        self.ensure_current()?;
        let limit = bounded_limit(limit, MAX_ACTIVE_SESSION_RECORD_QUERY)?;
        let query_limit = limit.checked_add(1).ok_or_else(|| {
            ProviderStoreError::InvalidInput("active session query limit overflows".to_owned())
        })?;
        let prior_statement = self.client.prepare(HAS_SESSION_RECORDS_SQL).await?;
        let has_prior_records = self
            .client
            .query_one(&prior_statement, &[])
            .await?
            .get::<_, bool>(0);
        let active_statement = self
            .client
            .prepare(SELECT_ACTIVE_SESSION_RECORDS_SQL)
            .await?;
        let rows = self
            .client
            .query(&active_statement, &[&query_limit])
            .await?;
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
            return Err(ProviderStoreError::InvalidInput(format!(
                "active session record bound {limit} reached"
            )));
        }
        let records = rows
            .into_iter()
            .map(|row| {
                let stored_session_id: String = row.get(0);
                let event: Event = serde_json::from_value(row.get::<_, Value>(1))
                    .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))?;
                let event_session_id = exactly_one_tag(&event, "session")?;
                if event_session_id != stored_session_id {
                    return Err(ProviderStoreError::MigrationDrift(
                        "stored session record is indexed under another session".to_owned(),
                    ));
                }
                Ok(event)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SessionRecordRecovery {
            records,
            has_prior_records,
        })
    }

    pub async fn bounded_session_records(
        &self,
        limit: usize,
    ) -> Result<Vec<Event>, ProviderStoreError> {
        self.ensure_current()?;
        let limit = bounded_limit(limit, MAX_ACTIVE_SESSION_RECORD_QUERY)?;
        let query_limit = limit.checked_add(1).ok_or_else(|| {
            ProviderStoreError::InvalidInput("session record query limit overflows".to_owned())
        })?;
        let statement = self
            .client
            .prepare(SELECT_BOUNDED_SESSION_RECORDS_SQL)
            .await?;
        let rows = self.client.query(&statement, &[&query_limit]).await?;
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
            return Err(ProviderStoreError::InvalidInput(format!(
                "session record bound {limit} reached"
            )));
        }
        rows.into_iter()
            .map(|row| {
                let stored_session_id: String = row.get(0);
                let event: Event = serde_json::from_value(row.get::<_, Value>(1))
                    .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))?;
                if exactly_one_tag(&event, "session")? != stored_session_id {
                    return Err(ProviderStoreError::MigrationDrift(
                        "stored session record is indexed under another session".to_owned(),
                    ));
                }
                Ok(event)
            })
            .collect()
    }

    pub async fn dispose_session(
        &mut self,
        session_id: &str,
        reason_code: &str,
        disposed_at: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(session_id, "session ID")?;
        validate_identifier(reason_code, "session disposition reason")?;
        if reason_code
            .bytes()
            .next()
            .is_none_or(|byte| !byte.is_ascii_lowercase())
        {
            return Err(ProviderStoreError::InvalidInput(
                "session disposition reason must begin with a lowercase letter".to_owned(),
            ));
        }
        let disposed_at = database_u64(disposed_at, "session disposition time")?;
        let transaction = self.client.transaction().await?;
        let insert = transaction.prepare(INSERT_SESSION_DISPOSITION_SQL).await?;
        let inserted = transaction
            .execute(&insert, &[&session_id, &reason_code, &disposed_at])
            .await?;
        if inserted == 1 {
            transaction.commit().await?;
            return Ok(StoreWriteOutcome::Stored);
        }
        let select = transaction.prepare(SELECT_SESSION_DISPOSITION_SQL).await?;
        let stored_reason: String = transaction.query_one(&select, &[&session_id]).await?.get(0);
        transaction.commit().await?;
        replay_or_conflict(stored_reason == reason_code, "session disposition")
    }

    pub async fn persist_exit_package(
        &self,
        package: &PublicExitPackage,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_exit_package(package)?;
        let statement = self.client.prepare(UPSERT_EXIT_PACKAGE_SQL).await?;
        let created_at = database_u64(package.created_at, "exit package time")?;
        let inserted = self
            .client
            .execute(
                &statement,
                &[
                    &package.package_id,
                    &package.session_id,
                    &package.order_id,
                    &package.leg_id,
                    &package.path,
                    &package.package_sha256,
                    &package.public_package,
                    &created_at,
                ],
            )
            .await?;
        if inserted == 1 {
            return Ok(StoreWriteOutcome::Stored);
        }
        let select = self.client.prepare(SELECT_EXIT_PACKAGE_SQL).await?;
        let row = self
            .client
            .query_one(&select, &[&package.package_id])
            .await?;
        let values_match = row.get::<_, String>(0) == package.session_id
            && row.get::<_, String>(1) == package.order_id
            && row.get::<_, String>(2) == package.leg_id
            && row.get::<_, String>(3) == package.path
            && row.get::<_, String>(4) == package.package_sha256
            && row.get::<_, Value>(5) == package.public_package;
        replay_or_conflict(values_match, "exit package")
    }

    pub async fn set_exit_package_state(
        &mut self,
        package_id: &str,
        state: &str,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(package_id, "exit package ID")?;
        if !matches!(
            state,
            "prepared" | "broadcast" | "confirmed" | "reorged" | "replaced" | "unresolved"
        ) {
            return Err(ProviderStoreError::InvalidInput(
                "exit package state is invalid".to_owned(),
            ));
        }
        let now = database_u64(now, "exit package update time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_EXIT_PACKAGE_SQL).await?;
        let row = transaction
            .query_opt(&lock, &[&package_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(package_id.to_owned()))?;
        let current: String = row.get(6);
        if current == state {
            transaction.commit().await?;
            return Ok(StoreWriteOutcome::Replay);
        }
        if !valid_exit_transition(&current, state) {
            return Err(ProviderStoreError::Conflict(format!(
                "exit package transition {current} -> {state} is invalid"
            )));
        }
        let update = transaction.prepare(UPDATE_EXIT_PACKAGE_STATE_SQL).await?;
        require_updated(
            transaction
                .execute(&update, &[&package_id, &state, &now])
                .await?,
            package_id,
        )?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn exit_package(
        &self,
        package_id: &str,
    ) -> Result<Option<StoredPublicExitPackage>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(package_id, "exit package ID")?;
        let statement = self.client.prepare(SELECT_EXIT_PACKAGE_SQL).await?;
        self.client
            .query_opt(&statement, &[&package_id])
            .await?
            .map(|row| {
                Ok(StoredPublicExitPackage {
                    package: PublicExitPackage {
                        package_id: package_id.to_owned(),
                        session_id: row.get(0),
                        order_id: row.get(1),
                        leg_id: row.get(2),
                        path: row.get(3),
                        package_sha256: row.get(4),
                        public_package: row.get(5),
                        created_at: u64::try_from(row.get::<_, i64>(7)).map_err(|_| {
                            ProviderStoreError::MigrationDrift(
                                "exit package time is negative".to_owned(),
                            )
                        })?,
                    },
                    state: row.get(6),
                })
            })
            .transpose()
    }

    pub async fn persist_effect_request(
        &self,
        request: &PublicEffectRequest,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_effect_request(request)?;
        let statement = self.client.prepare(INSERT_EFFECT_SQL).await?;
        let created_at = database_u64(request.created_at, "effect time")?;
        let inserted = self
            .client
            .execute(
                &statement,
                &[
                    &request.effect_id,
                    &request.session_id,
                    &request.operation,
                    &request.request_sha256,
                    &request.public_request,
                    &created_at,
                ],
            )
            .await?;
        if inserted == 1 {
            return Ok(StoreWriteOutcome::Stored);
        }
        let select = self.client.prepare(SELECT_EFFECT_SQL).await?;
        let row = self
            .client
            .query_one(&select, &[&request.effect_id])
            .await?;
        replay_or_conflict(effect_request_matches(&row, request), "effect request")
    }

    pub async fn complete_effect(
        &mut self,
        result: &PublicEffectResult,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(&result.effect_id, "effect ID")?;
        validate_hex(&result.request_sha256, "effect request digest")?;
        validate_hex(&result.result_sha256, "effect result digest")?;
        validate_public_json(&result.public_result)?;
        validate_reference(&result.external_reference, "external effect reference")?;
        let completed_at = database_u64(result.completed_at, "effect completion time")?;
        let transaction = self.client.transaction().await?;
        let select = transaction.prepare(LOCK_EFFECT_SQL).await?;
        let row = transaction
            .query_opt(&select, &[&result.effect_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(result.effect_id.clone()))?;
        if row.get::<_, String>(2) != result.request_sha256 {
            return Err(ProviderStoreError::Conflict(
                "effect result request digest mismatch".to_owned(),
            ));
        }
        if row.get::<_, String>(4) == "applied" {
            let matches = row.get::<_, Option<String>>(5).as_deref()
                == Some(result.result_sha256.as_str())
                && row.get::<_, Option<Value>>(6).as_ref() == Some(&result.public_result)
                && row.get::<_, Option<String>>(7).as_deref()
                    == Some(result.external_reference.as_str());
            transaction.commit().await?;
            return replay_or_conflict(matches, "effect result");
        }
        if row.get::<_, String>(4) == "unresolved" {
            return Err(ProviderStoreError::Conflict(
                "unresolved effect requires operator reconciliation".to_owned(),
            ));
        }
        let update = transaction.prepare(COMPLETE_EFFECT_SQL).await?;
        transaction
            .execute(
                &update,
                &[
                    &result.effect_id,
                    &result.result_sha256,
                    &result.public_result,
                    &result.external_reference,
                    &completed_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn public_effect(
        &self,
        effect_id: &str,
    ) -> Result<Option<StoredPublicEffect>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(effect_id, "effect ID")?;
        let statement = self.client.prepare(SELECT_EFFECT_SQL).await?;
        self.client
            .query_opt(&statement, &[&effect_id])
            .await?
            .map(|row| {
                Ok(StoredPublicEffect {
                    request: PublicEffectRequest {
                        effect_id: effect_id.to_owned(),
                        session_id: row.get(0),
                        operation: row.get(1),
                        request_sha256: row.get(2),
                        public_request: row.get(3),
                        created_at: u64::try_from(row.get::<_, i64>(8)).map_err(|_| {
                            ProviderStoreError::MigrationDrift("effect time is negative".to_owned())
                        })?,
                    },
                    state: row.get(4),
                    result_sha256: row.get(5),
                    public_result: row.get(6),
                    external_reference: row.get(7),
                })
            })
            .transpose()
    }

    pub async fn mark_effect_unresolved(
        &mut self,
        effect_id: &str,
        detail_code: &str,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(effect_id, "effect ID")?;
        validate_identifier(detail_code, "effect unresolved code")?;
        let now = database_u64(now, "effect unresolved time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_EFFECT_SQL).await?;
        let row = transaction
            .query_opt(&lock, &[&effect_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(effect_id.to_owned()))?;
        if row.get::<_, String>(4) == "unresolved" {
            let alert_id = digest(format!("provider-effect-unresolved\0{effect_id}").as_bytes());
            let select = transaction.prepare(SELECT_ALERT_SQL).await?;
            let alert = transaction
                .query_opt(&select, &[&alert_id])
                .await?
                .ok_or_else(|| {
                    ProviderStoreError::MigrationDrift(
                        "unresolved effect has no durable alert".to_owned(),
                    )
                })?;
            let exact = alert.get::<_, String>(3) == detail_code;
            transaction.commit().await?;
            return replay_or_conflict(exact, "effect unresolved state");
        }
        if row.get::<_, String>(4) != "pending" {
            return Err(ProviderStoreError::Conflict(
                "applied effect cannot become unresolved".to_owned(),
            ));
        }
        let update = transaction.prepare(MARK_EFFECT_UNRESOLVED_SQL).await?;
        require_updated(
            transaction.execute(&update, &[&effect_id, &now]).await?,
            effect_id,
        )?;
        let alert_id = digest(format!("provider-effect-unresolved\0{effect_id}").as_bytes());
        let session_id: String = row.get(0);
        let context = json!({ "effect_id": effect_id });
        let insert = transaction.prepare(INSERT_ALERT_SQL).await?;
        transaction
            .execute(
                &insert,
                &[
                    &alert_id,
                    &Some(session_id),
                    &"effect",
                    &detail_code,
                    &context,
                    &now,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn configure_capacity_bucket(
        &self,
        bucket_id: &str,
        asset_id: &str,
        total_capacity: u64,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.ensure_current()?;
        validate_identifier(bucket_id, "capacity bucket")?;
        validate_asset(asset_id)?;
        let total_capacity = database_u64(total_capacity, "capacity")?;
        let now = database_u64(now, "bucket update time")?;
        let statement = self.client.prepare(UPSERT_BUCKET_SQL).await?;
        if self
            .client
            .execute(&statement, &[&bucket_id, &asset_id, &total_capacity, &now])
            .await?
            != 1
        {
            return Err(ProviderStoreError::Conflict(
                "capacity update changes the asset or drops below allocation".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn available_capacity(&self, bucket_id: &str) -> Result<u64, ProviderStoreError> {
        self.ensure_current()?;
        validate_identifier(bucket_id, "capacity bucket")?;
        let statement = self.client.prepare(SELECT_AVAILABLE_CAPACITY_SQL).await?;
        let available = self
            .client
            .query_opt(&statement, &[&bucket_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(bucket_id.to_owned()))?
            .get::<_, i64>(0);
        u64::try_from(available).map_err(|_| {
            ProviderStoreError::MigrationDrift("available capacity became negative".to_owned())
        })
    }

    pub async fn observe_utxo(
        &self,
        observation: &UtxoObservation,
    ) -> Result<(), ProviderStoreError> {
        self.ensure_current()?;
        validate_utxo(observation)?;
        let statement = self.client.prepare(UPSERT_UTXO_SQL).await?;
        let vout = i32::try_from(observation.outpoint.vout)
            .map_err(|_| ProviderStoreError::InvalidInput("vout exceeds i32".to_owned()))?;
        let amount = database_u64(observation.amount, "UTXO amount")?;
        let confirmations = i32::try_from(observation.confirmations).map_err(|_| {
            ProviderStoreError::InvalidInput("confirmation count exceeds i32".to_owned())
        })?;
        let observed_at = database_u64(observation.observed_at, "UTXO observation time")?;
        if self
            .client
            .execute(
                &statement,
                &[
                    &observation.outpoint.txid,
                    &vout,
                    &observation.asset_id,
                    &amount,
                    &observation.script_pubkey,
                    &observation.state,
                    &confirmations,
                    &observation.block_hash,
                    &observation.replacement_txid,
                    &observed_at,
                ],
            )
            .await?
            != 1
        {
            return Err(ProviderStoreError::Conflict(
                "UTXO immutable public fields changed".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn available_utxos(
        &self,
        asset_id: &str,
        script_pubkeys: &[String],
        minimum_confirmations: u32,
        limit: usize,
    ) -> Result<Vec<StoredUtxo>, ProviderStoreError> {
        self.ensure_current()?;
        validate_asset(asset_id)?;
        if script_pubkeys.is_empty()
            || script_pubkeys.len() > 128
            || limit == 0
            || limit > MAX_RESERVATION_UTXOS
            || script_pubkeys.iter().any(|script| {
                script.is_empty()
                    || script.len() > 20_000
                    || script
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            })
        {
            return Err(ProviderStoreError::InvalidInput(
                "available UTXO query is outside bounds".to_owned(),
            ));
        }
        let minimum_confirmations = i32::try_from(minimum_confirmations).map_err(|_| {
            ProviderStoreError::InvalidInput("confirmation count exceeds i32".to_owned())
        })?;
        let limit = i64::try_from(limit)
            .map_err(|_| ProviderStoreError::InvalidInput("UTXO limit exceeds i64".to_owned()))?;
        let statement = self.client.prepare(SELECT_AVAILABLE_UTXOS_SQL).await?;
        let rows = self
            .client
            .query(
                &statement,
                &[&asset_id, &minimum_confirmations, &script_pubkeys, &limit],
            )
            .await?;
        rows.into_iter().map(stored_utxo_from_row).collect()
    }

    pub async fn reserved_utxos(
        &self,
        reservation_id: &str,
    ) -> Result<Vec<StoredUtxo>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(reservation_id, "reservation ID")?;
        let limit = i64::try_from(MAX_RESERVATION_UTXOS).map_err(|_| {
            ProviderStoreError::MigrationDrift("reservation UTXO bound exceeds i64".to_owned())
        })?;
        let statement = self.client.prepare(SELECT_RESERVED_UTXOS_SQL).await?;
        let rows = self
            .client
            .query(&statement, &[&reservation_id, &limit])
            .await?;
        rows.into_iter().map(stored_utxo_from_row).collect()
    }

    pub async fn reserve(
        &mut self,
        request: &HardReservationRequest,
    ) -> Result<ReservationOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_reservation_request(request)?;
        let mut outpoints = request.utxos.clone();
        sort_outpoints(&mut outpoints);
        let transaction = self.client.transaction().await?;
        lock_bucket(&transaction, &request.bucket_id).await?;
        let existing = select_reservation(&transaction, &request.reservation_id, true).await?;
        if let Some(existing) = existing {
            let effect = transaction.prepare(LOCK_EFFECT_SQL).await?;
            let effect = transaction
                .query_opt(&effect, &[&request.effect_id])
                .await?;
            let exact = reservation_matches(&existing, request)
                && match effect {
                    Some(row) => reserve_effect_matches(
                        &row,
                        request,
                        &outpoints,
                        existing.allocation_sequence,
                    )?,
                    None => false,
                };
            transaction.commit().await?;
            return if exact {
                Ok(ReservationOutcome::Replay(existing))
            } else {
                Err(ProviderStoreError::Conflict(
                    "reservation ID is bound to another request".to_owned(),
                ))
            };
        }
        let bucket_statement = transaction.prepare(LOCK_BUCKET_SQL).await?;
        let bucket = transaction
            .query_opt(&bucket_statement, &[&request.bucket_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(request.bucket_id.clone()))?;
        let bucket_asset: String = bucket.get(0);
        let total: i64 = bucket.get(1);
        let allocated: i64 = bucket.get(2);
        let sequence: i64 = bucket.get(3);
        if bucket_asset != request.asset_id {
            return Err(ProviderStoreError::Conflict(
                "reservation asset differs from capacity bucket".to_owned(),
            ));
        }
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            ProviderStoreError::Conflict("allocation sequence overflow".to_owned())
        })?;
        if database_u64(
            request.expected_allocation_sequence,
            "expected allocation sequence",
        )? != next_sequence
        {
            transaction.commit().await?;
            return Ok(ReservationOutcome::AllocationSequenceMismatch {
                current: u64::try_from(sequence).unwrap_or_default(),
            });
        }
        let amount = database_u64(request.amount, "reservation amount")?;
        if allocated
            .checked_add(amount)
            .is_none_or(|value| value > total)
        {
            transaction.commit().await?;
            return Ok(ReservationOutcome::InsufficientCapacity);
        }
        let lock = transaction.prepare(LOCK_UTXO_SQL).await?;
        let mut selected_utxo_capacity = 0_i64;
        for outpoint in &outpoints {
            let vout = i32::try_from(outpoint.vout)
                .map_err(|_| ProviderStoreError::InvalidInput("vout exceeds i32".to_owned()))?;
            let Some(row) = transaction
                .query_opt(&lock, &[&outpoint.txid, &vout])
                .await?
            else {
                transaction.commit().await?;
                return Ok(ReservationOutcome::UtxoUnavailable(outpoint.clone()));
            };
            if row.get::<_, String>(0) != request.asset_id
                || row.get::<_, String>(2) != "available"
                || row.get::<_, Option<String>>(3).is_some()
            {
                transaction.commit().await?;
                return Ok(ReservationOutcome::UtxoUnavailable(outpoint.clone()));
            }
            selected_utxo_capacity = selected_utxo_capacity
                .checked_add(row.get::<_, i64>(1))
                .ok_or_else(|| {
                    ProviderStoreError::MigrationDrift("selected UTXO capacity overflow".to_owned())
                })?;
        }
        if !outpoints.is_empty() && selected_utxo_capacity < amount {
            transaction.commit().await?;
            return Ok(ReservationOutcome::InsufficientCapacity);
        }
        insert_reserve_effect(&transaction, request, &outpoints).await?;
        let update_bucket = transaction.prepare(UPDATE_BUCKET_RESERVE_SQL).await?;
        let now = database_u64(request.created_at, "reservation time")?;
        transaction
            .execute(&update_bucket, &[&request.bucket_id, &amount, &now])
            .await?;
        let insert = transaction.prepare(INSERT_RESERVATION_SQL).await?;
        let expires_at = database_u64(request.expires_at, "reservation expiry")?;
        transaction
            .execute(
                &insert,
                &[
                    &request.reservation_id,
                    &request.effect_id,
                    &request.session_id,
                    &request.bucket_id,
                    &request.asset_id,
                    &amount,
                    &request.request_sha256,
                    &next_sequence,
                    &expires_at,
                    &now,
                ],
            )
            .await?;
        let reserve_utxo = transaction.prepare(RESERVE_UTXO_SQL).await?;
        for outpoint in &outpoints {
            let vout = i32::try_from(outpoint.vout)
                .map_err(|_| ProviderStoreError::InvalidInput("vout exceeds i32".to_owned()))?;
            if transaction
                .execute(
                    &reserve_utxo,
                    &[&outpoint.txid, &vout, &request.reservation_id, &now],
                )
                .await?
                != 1
            {
                return Err(ProviderStoreError::Conflict(
                    "locked UTXO changed before reservation".to_owned(),
                ));
            }
        }
        let allocation_sequence = u64::try_from(next_sequence).map_err(|_| {
            ProviderStoreError::MigrationDrift(
                "reservation allocation sequence became negative".to_owned(),
            )
        })?;
        let public_result = reserve_public_result(request, allocation_sequence);
        validate_public_json(&public_result)?;
        let result_sha256 = digest(&bounded_json(&public_result)?);
        let complete_effect = transaction.prepare(COMPLETE_EFFECT_SQL).await?;
        require_updated(
            transaction
                .execute(
                    &complete_effect,
                    &[
                        &request.effect_id,
                        &result_sha256,
                        &public_result,
                        &request.reservation_id,
                        &now,
                    ],
                )
                .await?,
            &request.effect_id,
        )?;
        transaction.commit().await?;
        Ok(ReservationOutcome::Reserved(ReservationRecord {
            reservation_id: request.reservation_id.clone(),
            effect_id: request.effect_id.clone(),
            session_id: request.session_id.clone(),
            bucket_id: request.bucket_id.clone(),
            asset_id: request.asset_id.clone(),
            amount: request.amount,
            request_sha256: request.request_sha256.clone(),
            allocation_sequence: request.expected_allocation_sequence,
            expires_at: request.expires_at,
            state: "active".to_owned(),
            release_cause: None,
        }))
    }

    pub async fn reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<ReservationRecord>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(reservation_id, "reservation ID")?;
        let statement = self.client.prepare(SELECT_RESERVATION_SQL).await?;
        self.client
            .query_opt(&statement, &[&reservation_id])
            .await?
            .map(reservation_from_row)
            .transpose()
    }

    pub async fn release_reservation(
        &mut self,
        reservation_id: &str,
        cause: &str,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(reservation_id, "reservation ID")?;
        validate_identifier(cause, "release cause")?;
        let now = database_u64(now, "release time")?;
        let transaction = self.client.transaction().await?;
        let initial = select_reservation(&transaction, reservation_id, false)
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(reservation_id.to_owned()))?;
        lock_bucket(&transaction, &initial.bucket_id).await?;
        let existing = select_reservation(&transaction, reservation_id, true)
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(reservation_id.to_owned()))?;
        if existing.bucket_id != initial.bucket_id {
            return Err(ProviderStoreError::MigrationDrift(
                "reservation bucket changed after insertion".to_owned(),
            ));
        }
        if existing.state == "released" {
            let exact = existing.release_cause.as_deref() == Some(cause);
            transaction.commit().await?;
            return replay_or_conflict(exact, "reservation release");
        }
        if existing.state != "active" {
            return Err(ProviderStoreError::Conflict(
                "unresolved reservation cannot be silently released".to_owned(),
            ));
        }
        let amount = database_u64(existing.amount, "reservation amount")?;
        let release = transaction.prepare(RELEASE_RESERVATION_SQL).await?;
        transaction
            .execute(&release, &[&reservation_id, &cause, &now])
            .await?;
        let bucket = transaction.prepare(UPDATE_BUCKET_RELEASE_SQL).await?;
        if transaction
            .execute(&bucket, &[&existing.bucket_id, &amount, &now])
            .await?
            != 1
        {
            return Err(ProviderStoreError::Conflict(
                "capacity allocation underflow during release".to_owned(),
            ));
        }
        let utxos = transaction.prepare(RELEASE_UTXOS_SQL).await?;
        transaction
            .execute(&utxos, &[&reservation_id, &now])
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn mark_reservation_unresolved(
        &mut self,
        reservation_id: &str,
        detail_code: &str,
        public_context: &Value,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(reservation_id, "reservation ID")?;
        validate_identifier(detail_code, "reservation unresolved code")?;
        validate_public_artifact(public_context)?;
        let now = database_u64(now, "reservation unresolved time")?;
        let transaction = self.client.transaction().await?;
        let initial = select_reservation(&transaction, reservation_id, false)
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(reservation_id.to_owned()))?;
        lock_bucket(&transaction, &initial.bucket_id).await?;
        let existing = select_reservation(&transaction, reservation_id, true)
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(reservation_id.to_owned()))?;
        if existing.state == "unresolved" {
            let alert_id =
                digest(format!("provider-reservation-unresolved\0{reservation_id}").as_bytes());
            let select = transaction.prepare(SELECT_ALERT_SQL).await?;
            let alert = transaction
                .query_opt(&select, &[&alert_id])
                .await?
                .ok_or_else(|| {
                    ProviderStoreError::MigrationDrift(
                        "unresolved reservation has no durable alert".to_owned(),
                    )
                })?;
            let exact = existing.release_cause.as_deref() == Some(detail_code)
                && alert.get::<_, String>(3) == detail_code
                && alert.get::<_, Value>(4) == *public_context;
            transaction.commit().await?;
            return replay_or_conflict(exact, "reservation unresolved state");
        }
        if existing.state != "active" {
            return Err(ProviderStoreError::Conflict(
                "released reservation cannot become unresolved".to_owned(),
            ));
        }
        let update = transaction.prepare(MARK_RESERVATION_UNRESOLVED_SQL).await?;
        require_updated(
            transaction
                .execute(&update, &[&reservation_id, &detail_code, &now])
                .await?,
            reservation_id,
        )?;
        let alert_id =
            digest(format!("provider-reservation-unresolved\0{reservation_id}").as_bytes());
        let insert = transaction.prepare(INSERT_ALERT_SQL).await?;
        transaction
            .execute(
                &insert,
                &[
                    &alert_id,
                    &Some(existing.session_id),
                    &"reservation",
                    &detail_code,
                    &public_context,
                    &now,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn enqueue_watch_job(
        &self,
        request: &WatchJobRequest,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_watch_request(request)?;
        let statement = self.client.prepare(INSERT_WATCH_SQL).await?;
        let due_height = optional_database_u64(request.due_height, "watch due height")?;
        let due_at = optional_database_u64(request.due_at, "watch due time")?;
        let maximum_attempts = i32::from(request.maximum_attempts);
        let created_at = database_u64(request.created_at, "watch creation time")?;
        let inserted = self
            .client
            .execute(
                &statement,
                &[
                    &request.job_id,
                    &request.session_id,
                    &request.effect_id,
                    &request.job_kind,
                    &request.request_sha256,
                    &request.public_payload,
                    &due_height,
                    &due_at,
                    &maximum_attempts,
                    &created_at,
                ],
            )
            .await?;
        if inserted == 1 {
            return Ok(StoreWriteOutcome::Stored);
        }
        let select = self.client.prepare(SELECT_WATCH_SQL).await?;
        let row = self.client.query_one(&select, &[&request.job_id]).await?;
        replay_or_conflict(watch_request_matches(&row, request)?, "watch job")
    }

    pub async fn claim_due_watch_jobs(
        &mut self,
        height: u64,
        now: u64,
        lease_until: u64,
        limit: usize,
    ) -> Result<Vec<WatchJob>, ProviderStoreError> {
        self.ensure_current()?;
        let height = database_u64(height, "watch height")?;
        let now = database_u64(now, "watch time")?;
        let lease_until = database_u64(lease_until, "watch lease")?;
        if lease_until <= now {
            return Err(ProviderStoreError::InvalidInput(
                "watch lease must be in the future".to_owned(),
            ));
        }
        let limit = bounded_limit(limit, MAX_WATCH_CLAIM)?;
        let transaction = self.client.transaction().await?;
        let claim = transaction.prepare(CLAIM_WATCH_SQL).await?;
        let rows = transaction.query(&claim, &[&height, &now, &limit]).await?;
        let update = transaction.prepare(MARK_WATCH_RUNNING_SQL).await?;
        let select = transaction.prepare(SELECT_WATCH_SQL).await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            let job_id: String = row.get(0);
            transaction
                .execute(&update, &[&job_id, &lease_until, &now])
                .await?;
            let row = transaction.query_one(&select, &[&job_id]).await?;
            let job = watch_from_row(job_id.clone(), &row)?;
            if job.state == "page" {
                let alert_id = digest(format!("provider-watch-page\0{job_id}").as_bytes());
                let context = json!({
                    "job_id": job_id,
                    "attempt_count": job.attempt_count,
                    "maximum_attempts": job.maximum_attempts
                });
                let insert = transaction.prepare(INSERT_ALERT_SQL).await?;
                transaction
                    .execute(
                        &insert,
                        &[
                            &alert_id,
                            &Some(job.session_id.clone()),
                            &"watchtower",
                            &"attempts_exhausted",
                            &context,
                            &now,
                        ],
                    )
                    .await?;
            }
            jobs.push(job);
        }
        transaction.commit().await?;
        Ok(jobs)
    }

    pub async fn record_broadcast(
        &mut self,
        job_id: &str,
        request_sha256: &str,
        result_sha256: &str,
        public_result: &Value,
        txid: &str,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_hex(request_sha256, "watch request digest")?;
        validate_hex(result_sha256, "broadcast result digest")?;
        validate_hex(txid, "broadcast transaction ID")?;
        validate_public_json(public_result)?;
        let now = database_u64(now, "broadcast time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_WATCH_SQL).await?;
        let row = transaction
            .query_opt(&lock, &[&job_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(job_id.to_owned()))?;
        if row.get::<_, String>(3) != request_sha256 {
            return Err(ProviderStoreError::Conflict(
                "broadcast request digest mismatch".to_owned(),
            ));
        }
        if row.get::<_, Option<String>>(10).is_some() {
            let exact = row.get::<_, Option<String>>(10).as_deref() == Some(result_sha256)
                && row.get::<_, Option<Value>>(11).as_ref() == Some(public_result)
                && row.get::<_, Option<String>>(12).as_deref() == Some(txid);
            if !exact {
                return Err(ProviderStoreError::Conflict(
                    "broadcast result replay changed immutable bytes".to_owned(),
                ));
            }
            let state: String = row.get(5);
            if matches!(state.as_str(), "pending" | "running") {
                let update = transaction.prepare(RECORD_BROADCAST_SQL).await?;
                require_updated(
                    transaction
                        .execute(
                            &update,
                            &[&job_id, &result_sha256, &public_result, &txid, &now],
                        )
                        .await?,
                    job_id,
                )?;
                transaction.commit().await?;
                return Ok(StoreWriteOutcome::Stored);
            }
            if !matches!(state.as_str(), "broadcast" | "confirmed") {
                return Err(ProviderStoreError::Conflict(
                    "paged or unresolved watch job cannot broadcast".to_owned(),
                ));
            }
            transaction.commit().await?;
            return Ok(StoreWriteOutcome::Replay);
        }
        let update = transaction.prepare(RECORD_BROADCAST_SQL).await?;
        require_updated(
            transaction
                .execute(
                    &update,
                    &[&job_id, &result_sha256, &public_result, &txid, &now],
                )
                .await?,
            job_id,
        )?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn record_confirmation(
        &self,
        job_id: &str,
        confirmations: u32,
        required_confirmations: u32,
        block_hash: &str,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_hex(block_hash, "observed block hash")?;
        let confirmations = i32::try_from(confirmations).map_err(|_| {
            ProviderStoreError::InvalidInput("confirmation count exceeds i32".to_owned())
        })?;
        let required = i32::try_from(required_confirmations).map_err(|_| {
            ProviderStoreError::InvalidInput("required confirmations exceeds i32".to_owned())
        })?;
        if required == 0 {
            return Err(ProviderStoreError::InvalidInput(
                "required confirmations must be positive".to_owned(),
            ));
        }
        let now = database_u64(now, "confirmation time")?;
        let statement = self.client.prepare(RECORD_CONFIRMATION_SQL).await?;
        require_updated(
            self.client
                .execute(
                    &statement,
                    &[&job_id, &confirmations, &required, &block_hash, &now],
                )
                .await?,
            job_id,
        )
    }

    pub async fn record_reorg(
        &self,
        job_id: &str,
        new_tip: &str,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.watch_chain_rollback(RECORD_REORG_SQL, job_id, new_tip, now)
            .await
    }

    pub async fn record_replacement(
        &self,
        job_id: &str,
        replacement_txid: &str,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.watch_chain_rollback(RECORD_REPLACEMENT_SQL, job_id, replacement_txid, now)
            .await
    }

    pub async fn page_watch_job(
        &mut self,
        job_id: &str,
        page_code: &str,
        public_context: &Value,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_identifier(page_code, "page code")?;
        validate_public_artifact(public_context)?;
        let now = database_u64(now, "page time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_WATCH_SQL).await?;
        let job = transaction
            .query_opt(&lock, &[&job_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(job_id.to_owned()))?;
        let alert_id = digest(format!("provider-watch-page\0{job_id}").as_bytes());
        if job.get::<_, String>(5) == "page" {
            if job.get::<_, Option<String>>(17).as_deref() != Some(page_code) {
                return Err(ProviderStoreError::Conflict(
                    "watch job is already paged with another code".to_owned(),
                ));
            }
            let select = transaction.prepare(SELECT_ALERT_SQL).await?;
            let alert = transaction
                .query_opt(&select, &[&alert_id])
                .await?
                .ok_or_else(|| {
                    ProviderStoreError::MigrationDrift(
                        "paged watch job has no durable alert".to_owned(),
                    )
                })?;
            let exact = alert.get::<_, String>(3) == page_code
                && alert.get::<_, Value>(4) == *public_context;
            transaction.commit().await?;
            return replay_or_conflict(exact, "watch page");
        }
        let update = transaction.prepare(PAGE_WATCH_SQL).await?;
        require_updated(
            transaction
                .execute(&update, &[&job_id, &page_code, &now])
                .await?,
            job_id,
        )?;
        let session_id: String = job.get(0);
        let insert = transaction.prepare(INSERT_ALERT_SQL).await?;
        transaction
            .execute(
                &insert,
                &[
                    &alert_id,
                    &Some(session_id),
                    &"watchtower",
                    &page_code,
                    &public_context,
                    &now,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn mark_watch_unresolved(
        &mut self,
        job_id: &str,
        detail_code: &str,
        public_context: &Value,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_identifier(detail_code, "watch unresolved code")?;
        validate_public_artifact(public_context)?;
        let now = database_u64(now, "watch unresolved time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_WATCH_SQL).await?;
        let job = transaction
            .query_opt(&lock, &[&job_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(job_id.to_owned()))?;
        let alert_id = digest(format!("provider-watch-unresolved\0{job_id}").as_bytes());
        if job.get::<_, String>(5) == "unresolved" {
            if job.get::<_, Option<String>>(17).as_deref() != Some(detail_code) {
                return Err(ProviderStoreError::Conflict(
                    "watch job is unresolved with another code".to_owned(),
                ));
            }
            let select = transaction.prepare(SELECT_ALERT_SQL).await?;
            let alert = transaction
                .query_opt(&select, &[&alert_id])
                .await?
                .ok_or_else(|| {
                    ProviderStoreError::MigrationDrift(
                        "unresolved watch job has no durable alert".to_owned(),
                    )
                })?;
            let exact = alert.get::<_, String>(3) == detail_code
                && alert.get::<_, Value>(4) == *public_context;
            transaction.commit().await?;
            return replay_or_conflict(exact, "watch unresolved state");
        }
        let update = transaction.prepare(MARK_WATCH_UNRESOLVED_SQL).await?;
        require_updated(
            transaction
                .execute(&update, &[&job_id, &detail_code, &now])
                .await?,
            job_id,
        )?;
        let session_id: String = job.get(0);
        let insert = transaction.prepare(INSERT_ALERT_SQL).await?;
        transaction
            .execute(
                &insert,
                &[
                    &alert_id,
                    &Some(session_id),
                    &"watchtower",
                    &detail_code,
                    &public_context,
                    &now,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn complete_watch_job(
        &mut self,
        job_id: &str,
        completion_code: &str,
        now: u64,
    ) -> Result<StoreWriteOutcome, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_identifier(completion_code, "watch completion code")?;
        let now = database_u64(now, "watch completion time")?;
        let transaction = self.client.transaction().await?;
        let lock = transaction.prepare(LOCK_WATCH_SQL).await?;
        let row = transaction
            .query_opt(&lock, &[&job_id])
            .await?
            .ok_or_else(|| ProviderStoreError::NotFound(job_id.to_owned()))?;
        let state: String = row.get(5);
        let prior_code: Option<String> = row.get(16);
        if state == "completed" {
            transaction.commit().await?;
            return replay_or_conflict(
                prior_code.as_deref() == Some(completion_code),
                "watch completion",
            );
        }
        if matches!(state.as_str(), "unresolved" | "page") {
            return Err(ProviderStoreError::Conflict(
                "unresolved or paged watch job cannot complete".to_owned(),
            ));
        }
        let update = transaction.prepare(COMPLETE_WATCH_SQL).await?;
        require_updated(
            transaction
                .execute(&update, &[&job_id, &completion_code, &now])
                .await?,
            job_id,
        )?;
        transaction.commit().await?;
        Ok(StoreWriteOutcome::Stored)
    }

    pub async fn watch_job(&self, job_id: &str) -> Result<Option<WatchJob>, ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        let select = self.client.prepare(SELECT_WATCH_SQL).await?;
        self.client
            .query_opt(&select, &[&job_id])
            .await?
            .map(|row| watch_from_row(job_id.to_owned(), &row))
            .transpose()
    }

    pub async fn watch_jobs_for_observation(
        &self,
        limit: usize,
    ) -> Result<Vec<WatchJob>, ProviderStoreError> {
        self.ensure_current()?;
        let limit = bounded_limit(limit, MAX_WATCH_CLAIM)?;
        let select = self.client.prepare(SELECT_WATCH_OBSERVATION_SQL).await?;
        self.client
            .query(&select, &[&limit])
            .await?
            .into_iter()
            .map(|row| {
                let job_id: String = row.get(18);
                watch_from_row(job_id, &row)
            })
            .collect()
    }

    pub async fn active_alerts(
        &self,
        limit: usize,
    ) -> Result<Vec<PublicAlert>, ProviderStoreError> {
        self.ensure_current()?;
        let limit = bounded_limit(limit, MAX_ALERT_QUERY)?;
        let statement = self.client.prepare(SELECT_ALERTS_SQL).await?;
        Ok(self
            .client
            .query(&statement, &[&limit])
            .await?
            .into_iter()
            .map(|row| PublicAlert {
                alert_id: row.get(0),
                session_id: row.get(1),
                alert_class: row.get(2),
                detail_code: row.get(3),
                public_context: row.get(4),
                state: row.get(5),
            })
            .collect())
    }

    pub async fn set_alert_state(
        &self,
        alert_id: &str,
        state: &str,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(alert_id, "alert ID")?;
        if !matches!(state, "active" | "acknowledged" | "resolved") {
            return Err(ProviderStoreError::InvalidInput(
                "alert state is invalid".to_owned(),
            ));
        }
        let now = database_u64(now, "alert update time")?;
        let statement = self.client.prepare(SET_ALERT_STATE_SQL).await?;
        require_updated(
            self.client
                .execute(&statement, &[&alert_id, &state, &now])
                .await?,
            alert_id,
        )
    }

    pub async fn health_counts(&self) -> Result<ProviderStoreHealth, ProviderStoreError> {
        self.ensure_current()?;
        let statement = self.client.prepare(SELECT_HEALTH_COUNTS_SQL).await?;
        let row = self
            .client
            .query_one(&statement, &[&HEALTH_COUNT_SCAN_LIMIT])
            .await?;
        Ok(ProviderStoreHealth {
            active_reservations: count_u64(row.get(0), "active reservations")?,
            unresolved_reservations: count_u64(row.get(1), "unresolved reservations")?,
            pending_effects: count_u64(row.get(2), "pending effects")?,
            unresolved_effects: count_u64(row.get(3), "unresolved effects")?,
            pending_watch_jobs: count_u64(row.get(4), "pending watch jobs")?,
            unresolved_watch_jobs: count_u64(row.get(5), "unresolved watch jobs")?,
            paged_watch_jobs: count_u64(row.get(6), "paged watch jobs")?,
            active_alerts: count_u64(row.get(7), "active alerts")?,
        })
    }

    fn ensure_current(&self) -> Result<(), ProviderStoreError> {
        if self.is_current() {
            Ok(())
        } else {
            Err(ProviderStoreError::ConnectionClosed)
        }
    }

    async fn watch_chain_rollback(
        &self,
        sql: &str,
        job_id: &str,
        value: &str,
        now: u64,
    ) -> Result<(), ProviderStoreError> {
        self.ensure_current()?;
        validate_hex(job_id, "watch job ID")?;
        validate_hex(value, "watch chain reference")?;
        let now = database_u64(now, "watch rollback time")?;
        let statement = self.client.prepare(sql).await?;
        require_updated(
            self.client
                .execute(&statement, &[&job_id, &value, &now])
                .await?,
            job_id,
        )
    }
}

impl Drop for ProviderStore {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

async fn lock_bucket(
    transaction: &Transaction<'_>,
    bucket_id: &str,
) -> Result<(), ProviderStoreError> {
    let statement = transaction.prepare(LOCK_BUCKET_ADVISORY_SQL).await?;
    transaction.execute(&statement, &[&bucket_id]).await?;
    Ok(())
}

async fn select_reservation(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    lock: bool,
) -> Result<Option<ReservationRecord>, ProviderStoreError> {
    let sql = if lock {
        LOCK_RESERVATION_SQL
    } else {
        SELECT_RESERVATION_SQL
    };
    let statement = transaction.prepare(sql).await?;
    transaction
        .query_opt(&statement, &[&reservation_id])
        .await?
        .map(reservation_from_row)
        .transpose()
}

async fn insert_reserve_effect(
    transaction: &Transaction<'_>,
    request: &HardReservationRequest,
    outpoints: &[OutPoint],
) -> Result<(), ProviderStoreError> {
    let public_request = reserve_public_request(request, outpoints);
    validate_public_json(&public_request)?;
    let statement = transaction.prepare(INSERT_EFFECT_SQL).await?;
    let created_at = database_u64(request.created_at, "reserve effect time")?;
    if transaction
        .execute(
            &statement,
            &[
                &request.effect_id,
                &request.session_id,
                &"reserve",
                &request.request_sha256,
                &public_request,
                &created_at,
            ],
        )
        .await?
        != 1
    {
        let select = transaction.prepare(LOCK_EFFECT_SQL).await?;
        let row = transaction
            .query_one(&select, &[&request.effect_id])
            .await?;
        let candidate = PublicEffectRequest {
            effect_id: request.effect_id.clone(),
            session_id: request.session_id.clone(),
            operation: "reserve".to_owned(),
            request_sha256: request.request_sha256.clone(),
            public_request,
            created_at: request.created_at,
        };
        if !effect_request_matches(&row, &candidate) {
            return Err(ProviderStoreError::Conflict(
                "reserve effect ID is bound to another request".to_owned(),
            ));
        }
    }
    Ok(())
}

fn effect_request_matches(row: &tokio_postgres::Row, request: &PublicEffectRequest) -> bool {
    row.get::<_, String>(0) == request.session_id
        && row.get::<_, String>(1) == request.operation
        && row.get::<_, String>(2) == request.request_sha256
        && row.get::<_, Value>(3) == request.public_request
}

fn reserve_effect_matches(
    row: &tokio_postgres::Row,
    request: &HardReservationRequest,
    outpoints: &[OutPoint],
    allocation_sequence: u64,
) -> Result<bool, ProviderStoreError> {
    let public_result = reserve_public_result(request, allocation_sequence);
    let result_sha256 = digest(&bounded_json(&public_result)?);
    Ok(row.get::<_, String>(0) == request.session_id
        && row.get::<_, String>(1) == "reserve"
        && row.get::<_, String>(2) == request.request_sha256
        && row.get::<_, Value>(3)
            == reserve_public_request_with_sequence(request, outpoints, allocation_sequence)
        && row.get::<_, String>(4) == "applied"
        && row.get::<_, Option<String>>(5).as_deref() == Some(result_sha256.as_str())
        && row.get::<_, Option<Value>>(6).as_ref() == Some(&public_result)
        && row.get::<_, Option<String>>(7).as_deref() == Some(request.reservation_id.as_str()))
}

fn reserve_public_request(request: &HardReservationRequest, outpoints: &[OutPoint]) -> Value {
    reserve_public_request_with_sequence(request, outpoints, request.expected_allocation_sequence)
}

fn reserve_public_request_with_sequence(
    request: &HardReservationRequest,
    outpoints: &[OutPoint],
    allocation_sequence: u64,
) -> Value {
    json!({
        "reservation_id":request.reservation_id,
        "bucket_id":request.bucket_id,
        "asset_id":request.asset_id,
        "amount":request.amount.to_string(),
        "expected_allocation_sequence":allocation_sequence.to_string(),
        "expires_at":request.expires_at,
        "utxos":outpoints.iter().map(|outpoint| {
            json!({"txid":outpoint.txid,"vout":outpoint.vout})
        }).collect::<Vec<_>>()
    })
}

fn reserve_public_result(request: &HardReservationRequest, allocation_sequence: u64) -> Value {
    json!({
        "reservation_id":request.reservation_id,
        "allocation_sequence":allocation_sequence.to_string(),
        "state":"reserved"
    })
}

fn watch_request_matches(
    row: &tokio_postgres::Row,
    request: &WatchJobRequest,
) -> Result<bool, ProviderStoreError> {
    Ok(row.get::<_, String>(0) == request.session_id
        && row.get::<_, Option<String>>(1) == request.effect_id
        && row.get::<_, String>(2) == request.job_kind
        && row.get::<_, String>(3) == request.request_sha256
        && row.get::<_, Value>(4) == request.public_payload
        && optional_u64(row.get::<_, Option<i64>>(6), "watch due height")? == request.due_height
        && optional_u64(row.get::<_, Option<i64>>(7), "watch due time")? == request.due_at
        && u16::try_from(row.get::<_, i32>(9)).ok() == Some(request.maximum_attempts))
}

fn stored_utxo_from_row(row: tokio_postgres::Row) -> Result<StoredUtxo, ProviderStoreError> {
    Ok(StoredUtxo {
        outpoint: OutPoint {
            txid: row.get(0),
            vout: u32::try_from(row.get::<_, i32>(1)).map_err(|_| {
                ProviderStoreError::MigrationDrift("UTXO vout is outside u32".to_owned())
            })?,
        },
        asset_id: row.get(2),
        amount: positive_u64(row.get(3), "UTXO amount")?,
        script_pubkey: row.get(4),
        state: row.get(5),
        confirmations: u32::try_from(row.get::<_, i32>(6)).map_err(|_| {
            ProviderStoreError::MigrationDrift("UTXO confirmations are outside u32".to_owned())
        })?,
        block_hash: row.get(7),
        replacement_txid: row.get(8),
        observed_at: u64::try_from(row.get::<_, i64>(9)).map_err(|_| {
            ProviderStoreError::MigrationDrift("UTXO observed time is negative".to_owned())
        })?,
    })
}

fn reservation_from_row(row: tokio_postgres::Row) -> Result<ReservationRecord, ProviderStoreError> {
    Ok(ReservationRecord {
        reservation_id: row.get(0),
        effect_id: row.get(1),
        session_id: row.get(2),
        bucket_id: row.get(3),
        asset_id: row.get(4),
        amount: positive_u64(row.get(5), "reservation amount")?,
        request_sha256: row.get(6),
        allocation_sequence: positive_u64(row.get(7), "allocation sequence")?,
        expires_at: positive_u64(row.get(8), "reservation expiry")?,
        state: row.get(9),
        release_cause: row.get(10),
    })
}

fn watch_from_row(
    job_id: String,
    row: &tokio_postgres::Row,
) -> Result<WatchJob, ProviderStoreError> {
    Ok(WatchJob {
        job_id,
        session_id: row.get(0),
        effect_id: row.get(1),
        job_kind: row.get(2),
        request_sha256: row.get(3),
        public_payload: row.get(4),
        state: row.get(5),
        due_height: optional_u64(row.get(6), "watch due height")?,
        due_at: optional_u64(row.get(7), "watch due time")?,
        attempt_count: u16::try_from(row.get::<_, i32>(8)).map_err(|_| {
            ProviderStoreError::MigrationDrift("watch attempts out of range".to_owned())
        })?,
        maximum_attempts: u16::try_from(row.get::<_, i32>(9)).map_err(|_| {
            ProviderStoreError::MigrationDrift("watch maximum attempts out of range".to_owned())
        })?,
        result_sha256: row.get(10),
        public_result: row.get(11),
        broadcast_txid: row.get(12),
        replacement_txid: row.get(13),
        confirmations: u32::try_from(row.get::<_, i32>(14)).map_err(|_| {
            ProviderStoreError::MigrationDrift("watch confirmations out of range".to_owned())
        })?,
        observed_block_hash: row.get(15),
        last_chain_event: row.get(16),
        page_code: row.get(17),
    })
}

fn reservation_matches(existing: &ReservationRecord, request: &HardReservationRequest) -> bool {
    existing.effect_id == request.effect_id
        && existing.session_id == request.session_id
        && existing.bucket_id == request.bucket_id
        && existing.asset_id == request.asset_id
        && existing.amount == request.amount
        && existing.request_sha256 == request.request_sha256
        && existing.expires_at == request.expires_at
}

fn validate_exit_package(package: &PublicExitPackage) -> Result<(), ProviderStoreError> {
    validate_hex(&package.package_id, "exit package ID")?;
    validate_hex(&package.session_id, "exit package session")?;
    validate_hex(&package.order_id, "exit package order")?;
    validate_identifier(&package.leg_id, "exit package leg")?;
    if !matches!(package.path.as_str(), "claim" | "refund") {
        return Err(ProviderStoreError::InvalidInput(
            "exit package path must be claim or refund".to_owned(),
        ));
    }
    validate_hex(&package.package_sha256, "exit package digest")?;
    validate_public_json(&package.public_package)
}

fn validate_effect_request(request: &PublicEffectRequest) -> Result<(), ProviderStoreError> {
    validate_hex(&request.effect_id, "effect ID")?;
    validate_hex(&request.session_id, "effect session")?;
    validate_identifier(&request.operation, "effect operation")?;
    validate_hex(&request.request_sha256, "effect request digest")?;
    validate_public_json(&request.public_request)
}

fn validate_utxo(observation: &UtxoObservation) -> Result<(), ProviderStoreError> {
    validate_hex(&observation.outpoint.txid, "UTXO txid")?;
    validate_asset(&observation.asset_id)?;
    if observation.amount == 0
        || observation.script_pubkey.is_empty()
        || observation.script_pubkey.len() > 20_000
        || observation
            .script_pubkey
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        || !matches!(
            observation.state.as_str(),
            "available" | "spent" | "reorged" | "replaced" | "unresolved"
        )
    {
        return Err(ProviderStoreError::InvalidInput(
            "UTXO public observation is invalid".to_owned(),
        ));
    }
    if let Some(hash) = &observation.block_hash {
        validate_hex(hash, "UTXO block hash")?;
    }
    if let Some(txid) = &observation.replacement_txid {
        validate_hex(txid, "UTXO replacement txid")?;
    }
    Ok(())
}

fn validate_reservation_request(
    request: &HardReservationRequest,
) -> Result<(), ProviderStoreError> {
    validate_hex(&request.reservation_id, "reservation ID")?;
    validate_hex(&request.effect_id, "reservation effect ID")?;
    validate_hex(&request.session_id, "reservation session")?;
    validate_identifier(&request.bucket_id, "capacity bucket")?;
    validate_asset(&request.asset_id)?;
    validate_hex(&request.request_sha256, "reservation request digest")?;
    if request.amount == 0
        || request.expected_allocation_sequence == 0
        || request.expires_at <= request.created_at
        || request.utxos.len() > MAX_RESERVATION_UTXOS
    {
        return Err(ProviderStoreError::InvalidInput(
            "reservation amount, sequence, expiry, or UTXO bound is invalid".to_owned(),
        ));
    }
    let mut outpoints = request.utxos.clone();
    sort_outpoints(&mut outpoints);
    if outpoints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProviderStoreError::InvalidInput(
            "reservation repeats a UTXO".to_owned(),
        ));
    }
    for outpoint in outpoints {
        validate_hex(&outpoint.txid, "reservation UTXO txid")?;
    }
    Ok(())
}

fn validate_watch_request(request: &WatchJobRequest) -> Result<(), ProviderStoreError> {
    validate_hex(&request.job_id, "watch job ID")?;
    validate_hex(&request.session_id, "watch session")?;
    if let Some(effect_id) = &request.effect_id {
        validate_hex(effect_id, "watch effect")?;
    }
    validate_identifier(&request.job_kind, "watch job kind")?;
    validate_hex(&request.request_sha256, "watch request digest")?;
    validate_public_json(&request.public_payload)?;
    if request.due_height.is_none() && request.due_at.is_none() {
        return Err(ProviderStoreError::InvalidInput(
            "watch job requires a height or time deadline".to_owned(),
        ));
    }
    if !(1..=100).contains(&request.maximum_attempts) {
        return Err(ProviderStoreError::InvalidInput(
            "watch maximum attempts must be 1-100".to_owned(),
        ));
    }
    Ok(())
}

fn validate_signed_event(value: &Value) -> Result<(), ProviderStoreError> {
    validate_public_json(value)?;
    let content = value
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderStoreError::InvalidInput("event content is absent".to_owned()))?;
    let content: Value = serde_json::from_str(content).map_err(|_| {
        ProviderStoreError::InvalidInput("provider records require JSON content".to_owned())
    })?;
    validate_public_json(&content)
}

fn validate_public_json(value: &Value) -> Result<(), ProviderStoreError> {
    reject_custody_material(value)
        .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))?;
    bounded_json(value).map(|_| ())
}

fn validate_public_artifact(value: &Value) -> Result<(), ProviderStoreError> {
    validate_public_json(value)
}

fn sort_outpoints(outpoints: &mut [OutPoint]) {
    outpoints.sort_by(|left, right| {
        left.txid
            .cmp(&right.txid)
            .then_with(|| left.vout.cmp(&right.vout))
    });
}

fn valid_exit_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("prepared", "broadcast")
            | ("prepared", "unresolved")
            | ("broadcast", "confirmed")
            | ("broadcast", "reorged")
            | ("broadcast", "replaced")
            | ("broadcast", "unresolved")
            | ("confirmed", "reorged")
            | ("confirmed", "replaced")
            | ("confirmed", "unresolved")
            | ("reorged", "broadcast")
            | ("reorged", "replaced")
            | ("reorged", "unresolved")
            | ("replaced", "broadcast")
            | ("replaced", "unresolved")
    )
}

fn bounded_json(value: &Value) -> Result<Vec<u8>, ProviderStoreError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ProviderStoreError::InvalidInput(error.to_string()))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(ProviderStoreError::InvalidInput(
            "public JSON exceeds its byte bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn exactly_one_tag<'a>(event: &'a Event, name: &'a str) -> Result<&'a str, ProviderStoreError> {
    let values = event.tag_values(name).collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(ProviderStoreError::InvalidInput(format!(
            "event requires exactly one {name} tag"
        )));
    }
    validate_hex(values[0], name)?;
    Ok(values[0])
}

fn validate_hex(value: &str, label: &str) -> Result<(), ProviderStoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderStoreError::InvalidInput(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), ProviderStoreError> {
    let mut bytes = value.bytes();
    if value.len() > 64
        || bytes
            .next()
            .is_none_or(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit())
        || bytes.any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && !matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ProviderStoreError::InvalidInput(format!(
            "{label} is not a bounded identifier"
        )));
    }
    Ok(())
}

fn validate_asset(value: &str) -> Result<(), ProviderStoreError> {
    if !value.starts_with("swp:1:") || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ProviderStoreError::InvalidInput(
            "asset ID is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_reference(value: &str, label: &str) -> Result<(), ProviderStoreError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ProviderStoreError::InvalidInput(format!(
            "{label} is empty or unbounded"
        )));
    }
    Ok(())
}

fn database_u64(value: u64, label: &str) -> Result<i64, ProviderStoreError> {
    i64::try_from(value)
        .map_err(|_| ProviderStoreError::InvalidInput(format!("{label} exceeds bigint")))
}

fn optional_database_u64(
    value: Option<u64>,
    label: &str,
) -> Result<Option<i64>, ProviderStoreError> {
    value.map(|value| database_u64(value, label)).transpose()
}

fn positive_u64(value: i64, label: &str) -> Result<u64, ProviderStoreError> {
    u64::try_from(value).map_err(|_| {
        ProviderStoreError::MigrationDrift(format!("{label} is negative or out of range"))
    })
}

fn count_u64(value: i64, label: &str) -> Result<u64, ProviderStoreError> {
    u64::try_from(value).map_err(|_| {
        ProviderStoreError::MigrationDrift(format!("{label} count is negative or out of range"))
    })
}

fn optional_u64(value: Option<i64>, label: &str) -> Result<Option<u64>, ProviderStoreError> {
    value.map(|value| positive_u64(value, label)).transpose()
}

fn bounded_limit(limit: usize, maximum: usize) -> Result<i64, ProviderStoreError> {
    if limit == 0 || limit > maximum {
        return Err(ProviderStoreError::InvalidInput(format!(
            "query limit must be 1-{maximum}"
        )));
    }
    i64::try_from(limit)
        .map_err(|_| ProviderStoreError::InvalidInput("query limit exceeds bigint".to_owned()))
}

fn replay_or_conflict(exact: bool, subject: &str) -> Result<StoreWriteOutcome, ProviderStoreError> {
    if exact {
        Ok(StoreWriteOutcome::Replay)
    } else {
        Err(ProviderStoreError::Conflict(format!(
            "{subject} replay changed immutable bytes"
        )))
    }
}

fn require_updated(rows: u64, subject: &str) -> Result<(), ProviderStoreError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(ProviderStoreError::NotFound(subject.to_owned()))
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
