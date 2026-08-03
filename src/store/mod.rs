//! Postgres-backed event admission and reads.
//!
//! Runtime data statements are prepared once when a [`Store`] connects.
//! Versioned, compile-time migration DDL is the sole `batch_execute` use and
//! is applied under one transaction and advisory lock.

mod error;
mod migration;
mod statements;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_postgres::{AsyncMessage, Client, NoTls, Row, types::ToSql};

use crate::domain::{
    DeletionRequest, DeletionTombstone, Event, EventClass, Filter, ReplacementDecision,
    compare_replacement_order,
};

pub use error::StoreError;
pub use migration::MigrationReport;
use statements::Statements;

const EVENT_CHANNEL: &str = "immortal_event";
const EPHEMERAL_CHANNEL: &str = "immortal_ephemeral";
const LISTEN_EVENT_SQL: &str = "LISTEN immortal_event";
const LISTEN_EPHEMERAL_SQL: &str = "LISTEN immortal_ephemeral";
const EPHEMERAL_CHUNK_BYTES: usize = 3_500;
const EPHEMERAL_MAX_BYTES: usize = 1_048_576;
const EPHEMERAL_MAX_ASSEMBLIES: usize = 256;

/// A successfully committed admission or a protocol-level refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Stored { ingest_seq: i64 },
    Duplicate,
    Ephemeral,
    Rejected(AdmissionRejection),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRejection {
    BlockedPubkey(String),
    BlockedKind(String),
    PubkeyNotAllowed,
    KindNotAllowed,
    NotMember,
    ContentTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    TooManyTags {
        actual: usize,
        max: usize,
    },
    TimestampTooFarInFuture {
        created_at: u64,
        latest_allowed: u64,
    },
    TimestampTooOld {
        created_at: u64,
        earliest_allowed: u64,
    },
    AuthEvent,
    Deleted,
    Superseded,
}

/// The operator-owned limits that the gateway advertises in NIP-11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPolicy {
    pub closed_membership: bool,
    pub max_content_bytes: usize,
    pub max_tags: usize,
    pub max_future_seconds: u64,
    pub max_past_seconds: u64,
}

/// A committed durable position or a validated ephemeral event delivered
/// through Postgres `NOTIFY` without ever entering a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreNotification {
    Stored(i64),
    Ephemeral(Event),
}

/// A decoded stored event and its relay-local monotonic position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub event: Event,
    pub ingest_seq: i64,
}

/// One database connection and its complete prepared-statement set.
///
/// The M3 gateway can create a small fixed set of these workers; M2 does not
/// add a pool or another service.
pub struct Store {
    client: Client,
    statements: Statements,
    connection_current: Arc<AtomicBool>,
    connection_task: JoinHandle<()>,
}

impl Store {
    pub async fn connect(config: &str) -> Result<Self, StoreError> {
        let (store, _) = Self::connect_with_report(config).await?;
        Ok(store)
    }

    pub async fn connect_with_report(config: &str) -> Result<(Self, MigrationReport), StoreError> {
        let (mut client, connection_current, connection_task) = open_client(config).await?;
        let migration_report = migration::apply(&mut client).await?;
        let statements = Statements::prepare(&client).await?;
        Ok((
            Self {
                client,
                statements,
                connection_current,
                connection_task,
            },
            migration_report,
        ))
    }

    /// Connect with a runtime role that may read the migration ledger but has
    /// no schema-creation privileges. This fails closed on missing, changed,
    /// or unknown migration versions.
    pub async fn connect_verified(config: &str) -> Result<Self, StoreError> {
        let (client, connection_current, connection_task) = open_client(config).await?;
        migration::verify(&client).await?;
        let statements = Statements::prepare(&client).await?;
        Ok(Self {
            client,
            statements,
            connection_current,
            connection_task,
        })
    }

    pub fn is_current(&self) -> bool {
        self.connection_current.load(Ordering::Acquire)
    }

    fn ensure_current(&self) -> Result<(), StoreError> {
        if self.is_current() {
            Ok(())
        } else {
            Err(StoreError::ConnectionClosed)
        }
    }

    /// Validate and atomically admit one event. A `Stored` result is returned
    /// only after the transaction, including its `NOTIFY`, has committed.
    pub async fn admit(&mut self, event: &Event, now: u64) -> Result<AdmissionOutcome, StoreError> {
        self.ensure_current()?;
        event.validate_structure()?;
        event.validate_crypto()?;
        if event.kind == 22_242 {
            return Ok(AdmissionOutcome::Rejected(AdmissionRejection::AuthEvent));
        }
        if let Some(expiration) = event.expiration()
            && expiration <= now
        {
            return Err(crate::domain::DomainError::ExpiredEvent { expiration, now }.into());
        }

        let created_at = pg_i64(event.created_at, "created_at")?;
        let expires_at = event
            .expiration()
            .map(|value| pg_i64(value, "expiration"))
            .transpose()?;
        let kind = i32::from(event.kind);
        let replacement = event.replacement_address();
        let deletion = if event.kind == 5 {
            Some(DeletionRequest::from_event(event)?)
        } else {
            None
        };
        let lock_keys = admission_lock_keys(event, replacement.as_ref(), deletion.as_ref());
        let statements = self.statements.clone();
        let transaction = self.client.transaction().await?;

        if transaction
            .query_opt(&statements.duplicate, &[&event.id])
            .await?
            .is_some()
        {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Duplicate);
        }

        let policy_row = transaction
            .query_opt(&statements.policy, &[])
            .await?
            .ok_or_else(|| StoreError::InvalidPolicy("singleton row is missing".to_owned()))?;
        let policy = AdmissionPolicy::from_row(&policy_row)?;

        if let Some(row) = transaction
            .query_opt(&statements.blocked_pubkey, &[&event.pubkey])
            .await?
        {
            let reason = row.get::<_, String>(0);
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::BlockedPubkey(reason),
            ));
        }
        if let Some(row) = transaction
            .query_opt(&statements.blocked_kind, &[&kind])
            .await?
        {
            let reason = row.get::<_, String>(0);
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(AdmissionRejection::BlockedKind(
                reason,
            )));
        }
        let pubkey_allowed = transaction
            .query_one(&statements.allowed_pubkey, &[&event.pubkey])
            .await?
            .get::<_, bool>(0);
        if !pubkey_allowed {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::PubkeyNotAllowed,
            ));
        }
        let kind_allowed = transaction
            .query_one(&statements.allowed_kind, &[&kind])
            .await?
            .get::<_, bool>(0);
        if !kind_allowed {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::KindNotAllowed,
            ));
        }
        if policy.closed_membership
            && transaction
                .query_opt(&statements.member, &[&event.pubkey])
                .await?
                .is_none()
        {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(AdmissionRejection::NotMember));
        }
        if event.content.len() > policy.max_content_bytes {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::ContentTooLarge {
                    actual_bytes: event.content.len(),
                    max_bytes: policy.max_content_bytes,
                },
            ));
        }
        if event.tags.len() > policy.max_tags {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::TooManyTags {
                    actual: event.tags.len(),
                    max: policy.max_tags,
                },
            ));
        }
        let latest_allowed = now.saturating_add(policy.max_future_seconds);
        if event.created_at > latest_allowed {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Rejected(
                AdmissionRejection::TimestampTooFarInFuture {
                    created_at: event.created_at,
                    latest_allowed,
                },
            ));
        }
        if policy.max_past_seconds > 0 {
            let earliest_allowed = now.saturating_sub(policy.max_past_seconds);
            if event.created_at < earliest_allowed {
                transaction.commit().await?;
                return Ok(AdmissionOutcome::Rejected(
                    AdmissionRejection::TimestampTooOld {
                        created_at: event.created_at,
                        earliest_allowed,
                    },
                ));
            }
        }

        for lock_key in lock_keys {
            transaction
                .query_one(&statements.advisory_lock, &[&lock_key])
                .await?;
        }

        // A conflicting process may have committed while this transaction
        // waited for an address or event lock.
        if transaction
            .query_opt(&statements.duplicate, &[&event.id])
            .await?
            .is_some()
        {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Duplicate);
        }

        if event.kind != 5 {
            let replacement_identifier = replacement
                .as_ref()
                .map(|address| address.identifier.as_str());
            let params: &[&(dyn ToSql + Sync)] = &[
                &event.id,
                &event.pubkey,
                &kind,
                &replacement_identifier,
                &created_at,
            ];
            let deleted = transaction
                .query_one(&statements.tombstone_match, params)
                .await?
                .get::<_, bool>(0);
            if deleted {
                transaction.commit().await?;
                return Ok(AdmissionOutcome::Rejected(AdmissionRejection::Deleted));
            }
        }

        let mut replaced_event_id = None;
        if let Some(address) = &replacement {
            let address_kind = i32::from(address.kind);
            let params: &[&(dyn ToSql + Sync)] =
                &[&address_kind, &address.pubkey, &address.identifier];
            if let Some(row) = transaction.query_opt(&statements.head, params).await? {
                let current_id = row.get::<_, String>(0);
                let current_created_at = row.get::<_, i64>(1);
                let current_created_at = u64::try_from(current_created_at).map_err(|_| {
                    StoreError::CorruptRow("replaceable head has negative timestamp".to_owned())
                })?;
                match compare_replacement_order(
                    current_created_at,
                    &current_id,
                    event.created_at,
                    &event.id,
                ) {
                    ReplacementDecision::KeepCurrent => {
                        transaction.commit().await?;
                        return Ok(AdmissionOutcome::Rejected(AdmissionRejection::Superseded));
                    }
                    ReplacementDecision::Duplicate => {
                        transaction.commit().await?;
                        return Ok(AdmissionOutcome::Duplicate);
                    }
                    ReplacementDecision::ReplaceCurrent => {
                        replaced_event_id = Some(current_id);
                    }
                }
            }
        }

        if event.class() == EventClass::Ephemeral {
            notify_ephemeral(&transaction, &statements, event).await?;
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Ephemeral);
        }

        // Serialize sequence allocation and commit order across processes.
        // This makes an `ingest_seq` high-water mark a safe EOSE boundary.
        transaction.query_one(&statements.ingest_lock, &[]).await?;

        let tags_json = serde_json::to_string(&event.tags)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let replacement_identifier = replacement
            .as_ref()
            .map(|address| address.identifier.as_str());
        let insert_params: &[&(dyn ToSql + Sync)] = &[
            &event.id,
            &event.pubkey,
            &created_at,
            &kind,
            &tags_json,
            &event.content,
            &event.sig,
            &replacement_identifier,
            &expires_at,
        ];
        let Some(row) = transaction
            .query_opt(&statements.insert_event, insert_params)
            .await?
        else {
            transaction.commit().await?;
            return Ok(AdmissionOutcome::Duplicate);
        };
        let ingest_seq = row.get::<_, i64>(0);

        for (tag_name, tag_value) in event.indexed_tags() {
            let tag_name = tag_name.to_string();
            let params: &[&(dyn ToSql + Sync)] = &[&event.id, &tag_name, &tag_value, &created_at];
            transaction.execute(&statements.insert_tag, params).await?;
        }

        if let Some(address) = &replacement {
            let address_kind = i32::from(address.kind);
            let params: &[&(dyn ToSql + Sync)] = &[
                &address_kind,
                &address.pubkey,
                &address.identifier,
                &event.id,
                &created_at,
            ];
            transaction.execute(&statements.upsert_head, params).await?;
            if let Some(old_id) = replaced_event_id {
                transaction
                    .execute(&statements.delete_event, &[&old_id])
                    .await?;
            }
        }

        if let Some(request) = deletion {
            apply_deletion(&transaction, &statements, &request).await?;
        }

        let payload = ingest_seq.to_string();
        transaction
            .query_one(&statements.notify, &[&payload])
            .await?;
        transaction.commit().await?;
        Ok(AdmissionOutcome::Stored { ingest_seq })
    }

    pub async fn event_by_id(&self, id: &str, now: u64) -> Result<Option<StoredEvent>, StoreError> {
        self.ensure_current()?;
        let now = pg_i64(now, "now")?;
        self.client
            .query_opt(&self.statements.event_by_id, &[&id, &now])
            .await?
            .map(decode_event_row)
            .transpose()
    }

    pub async fn latest_ingest_seq(&self) -> Result<i64, StoreError> {
        self.ensure_current()?;
        Ok(self
            .client
            .query_one(&self.statements.latest_ingest, &[])
            .await?
            .get(0))
    }

    pub async fn relay_policy(&self) -> Result<RelayPolicy, StoreError> {
        self.ensure_current()?;
        let row = self
            .client
            .query_opt(&self.statements.policy, &[])
            .await?
            .ok_or_else(|| StoreError::InvalidPolicy("singleton row is missing".to_owned()))?;
        Ok(AdmissionPolicy::from_row(&row)?.into())
    }

    pub async fn event_by_ingest_seq(
        &self,
        ingest_seq: i64,
        now: u64,
    ) -> Result<Option<StoredEvent>, StoreError> {
        self.ensure_current()?;
        let now = pg_i64(now, "now")?;
        self.client
            .query_opt(&self.statements.event_by_ingest, &[&ingest_seq, &now])
            .await?
            .map(decode_event_row)
            .transpose()
    }

    /// Read a bounded, stable catch-up page through a previously sampled
    /// high-water mark.
    pub async fn events_after(
        &self,
        after: i64,
        through: i64,
        now: u64,
        limit: usize,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.ensure_current()?;
        let now = pg_i64(now, "now")?;
        let limit = pg_limit(limit)?;
        let rows = self
            .client
            .query(
                &self.statements.events_after,
                &[&after, &through, &now, &limit],
            )
            .await?;
        rows.into_iter().map(decode_event_row).collect()
    }

    /// Execute one bounded NIP-01 filter with one immutable prepared query.
    pub async fn query_filter(
        &self,
        filter: &Filter,
        now: u64,
        max_results: usize,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.query_filter_through(filter, now, max_results, i64::MAX)
            .await
    }

    /// Execute a historical filter through a stable durable high-water mark.
    pub async fn query_filter_through(
        &self,
        filter: &Filter,
        now: u64,
        max_results: usize,
        through: i64,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.query_filter_inner(filter, now, max_results, through, None)
            .await
    }

    /// As [`Store::query_filter_through`], but issue a Postgres cancellation
    /// request when the owning client disconnects or replaces the REQ.
    pub async fn query_filter_cancellable(
        &self,
        filter: &Filter,
        now: u64,
        max_results: usize,
        through: i64,
        cancel: watch::Receiver<bool>,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.query_filter_inner(filter, now, max_results, through, Some(cancel))
            .await
    }

    async fn query_filter_inner(
        &self,
        filter: &Filter,
        now: u64,
        max_results: usize,
        through: i64,
        mut cancel: Option<watch::Receiver<bool>>,
    ) -> Result<Vec<StoredEvent>, StoreError> {
        self.ensure_current()?;
        filter.validate()?;
        let now = pg_i64(now, "now")?;
        let requested_limit = filter.limit.unwrap_or(max_results).min(max_results);
        let limit = pg_limit(requested_limit)?;
        let ids = filter.ids.clone();
        let authors = filter.authors.clone();
        let kinds = filter.kinds.as_ref().map(|values| {
            values
                .iter()
                .map(|value| i32::from(*value))
                .collect::<Vec<_>>()
        });
        let since = filter
            .since
            .map(|value| pg_i64(value, "since"))
            .transpose()?;
        let until = filter
            .until
            .map(|value| pg_i64(value, "until"))
            .transpose()?;
        let tag_map = filter
            .tags
            .iter()
            .map(|(key, values)| (key.to_string(), values))
            .collect::<BTreeMap<_, _>>();
        let tags_json = serde_json::to_string(&tag_map)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[
            &ids, &authors, &kinds, &since, &until, &tags_json, &now, &limit, &through,
        ];
        let rows = if let Some(cancel) = &mut cancel {
            if *cancel.borrow() {
                return Err(StoreError::QueryCancelled);
            }
            let query = self.client.query(&self.statements.query_filter, params);
            tokio::pin!(query);
            tokio::select! {
                result = &mut query => result?,
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        self.client.cancel_token().cancel_query(NoTls).await?;
                        return Err(StoreError::QueryCancelled);
                    }
                    query.await?
                }
            }
        } else {
            self.client
                .query(&self.statements.query_filter, params)
                .await?
        };
        rows.into_iter().map(decode_event_row).collect()
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.connection_task.abort();
    }
}

/// Dedicated bounded durable and ephemeral notification connection. A
/// malformed payload, incomplete protocol state, driver failure, or full
/// local queue marks it not current so the gateway can fail closed.
pub struct NotificationListener {
    receiver: mpsc::Receiver<StoreNotification>,
    connection_current: Arc<AtomicBool>,
    _client: Client,
    connection_task: JoinHandle<()>,
}

impl NotificationListener {
    pub async fn connect(config: &str, capacity: usize) -> Result<Self, StoreError> {
        let (client, mut connection) = tokio_postgres::connect(config, NoTls).await?;
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let connection_current = Arc::new(AtomicBool::new(true));
        let task_current = Arc::clone(&connection_current);
        let connection_task = tokio::spawn(async move {
            let mut assemblies = HashMap::new();
            loop {
                match poll_fn(|context| connection.poll_message(context)).await {
                    Some(Ok(AsyncMessage::Notification(notification)))
                        if notification.channel() == EVENT_CHANNEL =>
                    {
                        let Ok(ingest_seq) = notification.payload().parse::<i64>() else {
                            break;
                        };
                        if ingest_seq <= 0
                            || sender
                                .try_send(StoreNotification::Stored(ingest_seq))
                                .is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(AsyncMessage::Notification(notification)))
                        if notification.channel() == EPHEMERAL_CHANNEL =>
                    {
                        match accept_ephemeral_chunk(notification.payload(), &mut assemblies) {
                            Ok(Some(event)) => {
                                if sender
                                    .try_send(StoreNotification::Ephemeral(event))
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(()) => break,
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            task_current.store(false, Ordering::Release);
        });

        let listen = client.prepare(LISTEN_EVENT_SQL).await?;
        client.execute(&listen, &[]).await?;
        let listen_ephemeral = client.prepare(LISTEN_EPHEMERAL_SQL).await?;
        client.execute(&listen_ephemeral, &[]).await?;
        Ok(Self {
            receiver,
            connection_current,
            _client: client,
            connection_task,
        })
    }

    pub fn is_current(&self) -> bool {
        self.connection_current.load(Ordering::Acquire)
    }

    pub async fn recv(&mut self) -> Option<i64> {
        loop {
            match self.receiver.recv().await? {
                StoreNotification::Stored(ingest_seq) => return Some(ingest_seq),
                StoreNotification::Ephemeral(_) => {}
            }
        }
    }

    pub async fn recv_notification(&mut self) -> Option<StoreNotification> {
        self.receiver.recv().await
    }
}

impl Drop for NotificationListener {
    fn drop(&mut self) {
        self.connection_task.abort();
    }
}

async fn open_client(
    config: &str,
) -> Result<(Client, Arc<AtomicBool>, JoinHandle<()>), StoreError> {
    let (client, connection) = tokio_postgres::connect(config, NoTls).await?;
    let connection_current = Arc::new(AtomicBool::new(true));
    let task_current = Arc::clone(&connection_current);
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
        task_current.store(false, Ordering::Release);
    });
    Ok((client, connection_current, connection_task))
}

fn admission_lock_keys(
    event: &Event,
    replacement: Option<&crate::domain::ReplacementAddress>,
    deletion: Option<&DeletionRequest>,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    keys.insert(format!("event:{}:{}", event.pubkey, event.id));
    if let Some(address) = replacement {
        keys.insert(format!("address:{address}"));
    }
    if let Some(request) = deletion {
        keys.extend(
            request
                .event_ids
                .iter()
                .map(|id| format!("event:{}:{id}", request.author)),
        );
        keys.extend(
            request
                .addresses
                .iter()
                .map(|address| format!("address:{address}")),
        );
    }
    keys
}

async fn notify_ephemeral(
    transaction: &tokio_postgres::Transaction<'_>,
    statements: &Statements,
    event: &Event,
) -> Result<(), StoreError> {
    let bytes =
        serde_json::to_vec(event).map_err(|error| StoreError::Serialization(error.to_string()))?;
    if bytes.len() > EPHEMERAL_MAX_BYTES {
        return Err(StoreError::EphemeralTooLarge(bytes.len()));
    }
    let total = bytes.len().div_ceil(EPHEMERAL_CHUNK_BYTES);
    for (index, chunk) in bytes.chunks(EPHEMERAL_CHUNK_BYTES).enumerate() {
        let payload = format!("{}:{index}:{total}:{}", event.id, encode_hex(chunk));
        transaction
            .query_one(&statements.notify_ephemeral, &[&payload])
            .await?;
    }
    Ok(())
}

struct EphemeralAssembly {
    chunks: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

fn accept_ephemeral_chunk(
    payload: &str,
    assemblies: &mut HashMap<String, EphemeralAssembly>,
) -> Result<Option<Event>, ()> {
    let mut parts = payload.splitn(4, ':');
    let event_id = parts.next().ok_or(())?;
    let index = parts.next().ok_or(())?.parse::<usize>().map_err(|_| ())?;
    let total = parts.next().ok_or(())?.parse::<usize>().map_err(|_| ())?;
    let encoded = parts.next().ok_or(())?;
    let max_chunks = EPHEMERAL_MAX_BYTES.div_ceil(EPHEMERAL_CHUNK_BYTES);
    if event_id.len() != 64
        || !event_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || total == 0
        || total > max_chunks
        || index >= total
        || encoded.len() > EPHEMERAL_CHUNK_BYTES * 2
    {
        return Err(());
    }
    let chunk = decode_hex(encoded)?;
    if assemblies.len() >= EPHEMERAL_MAX_ASSEMBLIES && !assemblies.contains_key(event_id) {
        return Err(());
    }
    let assembly = assemblies
        .entry(event_id.to_owned())
        .or_insert_with(|| EphemeralAssembly {
            chunks: vec![None; total],
            bytes: 0,
        });
    if assembly.chunks.len() != total || assembly.chunks[index].is_some() {
        return Err(());
    }
    assembly.bytes = assembly.bytes.checked_add(chunk.len()).ok_or(())?;
    if assembly.bytes > EPHEMERAL_MAX_BYTES {
        return Err(());
    }
    assembly.chunks[index] = Some(chunk);
    if assembly.chunks.iter().any(Option::is_none) {
        return Ok(None);
    }

    let assembly = assemblies.remove(event_id).ok_or(())?;
    let mut bytes = Vec::with_capacity(assembly.bytes);
    for chunk in assembly.chunks {
        bytes.extend(chunk.ok_or(())?);
    }
    let event = serde_json::from_slice::<Event>(&bytes).map_err(|_| ())?;
    event.validate_structure().map_err(|_| ())?;
    event.validate_crypto().map_err(|_| ())?;
    if event.id != event_id || event.class() != EventClass::Ephemeral || event.kind == 22_242 {
        return Err(());
    }
    Ok(Some(event))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

async fn apply_deletion(
    transaction: &tokio_postgres::Transaction<'_>,
    statements: &Statements,
    request: &DeletionRequest,
) -> Result<(), StoreError> {
    for tombstone in request.tombstones() {
        match tombstone {
            DeletionTombstone::Event {
                event_id,
                author,
                request_id,
            } => {
                let params: &[&(dyn ToSql + Sync)] = &[&event_id, &author, &request_id];
                transaction
                    .execute(&statements.insert_event_tombstone, params)
                    .await?;
                transaction
                    .execute(&statements.delete_event_target, &[&event_id, &author])
                    .await?;
            }
            DeletionTombstone::Address {
                address,
                through,
                request_id,
            } => {
                let kind = i32::from(address.kind);
                let through = pg_i64(through, "deletion timestamp")?;
                let params: &[&(dyn ToSql + Sync)] = &[
                    &kind,
                    &address.pubkey,
                    &address.identifier,
                    &through,
                    &request_id,
                ];
                transaction
                    .execute(&statements.insert_address_tombstone, params)
                    .await?;
                let delete_params: &[&(dyn ToSql + Sync)] =
                    &[&kind, &address.pubkey, &address.identifier, &through];
                transaction
                    .execute(&statements.delete_address_target, delete_params)
                    .await?;
            }
        }
    }
    Ok(())
}

fn decode_event_row(row: Row) -> Result<StoredEvent, StoreError> {
    let created_at = row.get::<_, i64>(2);
    let created_at = u64::try_from(created_at)
        .map_err(|_| StoreError::CorruptRow("negative created_at".to_owned()))?;
    let kind = row.get::<_, i32>(3);
    let kind = u16::try_from(kind)
        .map_err(|_| StoreError::CorruptRow("kind outside NIP-01 range".to_owned()))?;
    let tags_json = row.get::<_, String>(4);
    let tags = serde_json::from_str(&tags_json)
        .map_err(|error| StoreError::CorruptRow(format!("invalid tags JSON: {error}")))?;
    let event = Event {
        id: row.get(0),
        pubkey: row.get(1),
        created_at,
        kind,
        tags,
        content: row.get(5),
        sig: row.get(6),
    };
    event
        .validate_structure()
        .map_err(|error| StoreError::CorruptRow(error.to_string()))?;
    event
        .validate_crypto()
        .map_err(|error| StoreError::CorruptRow(error.to_string()))?;
    Ok(StoredEvent {
        event,
        ingest_seq: row.get(7),
    })
}

struct AdmissionPolicy {
    closed_membership: bool,
    max_content_bytes: usize,
    max_tags: usize,
    max_future_seconds: u64,
    max_past_seconds: u64,
}

impl AdmissionPolicy {
    fn from_row(row: &Row) -> Result<Self, StoreError> {
        let max_content_bytes = row.get::<_, i64>(1);
        let max_tags = row.get::<_, i32>(2);
        let max_future_seconds = row.get::<_, i64>(3);
        let max_past_seconds = row.get::<_, i64>(4);
        Ok(Self {
            closed_membership: row.get(0),
            max_content_bytes: usize::try_from(max_content_bytes).map_err(|_| {
                StoreError::InvalidPolicy("max_content_bytes is outside usize range".to_owned())
            })?,
            max_tags: usize::try_from(max_tags).map_err(|_| {
                StoreError::InvalidPolicy("max_tags is outside usize range".to_owned())
            })?,
            max_future_seconds: u64::try_from(max_future_seconds).map_err(|_| {
                StoreError::InvalidPolicy("max_future_seconds is negative".to_owned())
            })?,
            max_past_seconds: u64::try_from(max_past_seconds).map_err(|_| {
                StoreError::InvalidPolicy("max_past_seconds is negative".to_owned())
            })?,
        })
    }
}

impl From<AdmissionPolicy> for RelayPolicy {
    fn from(policy: AdmissionPolicy) -> Self {
        Self {
            closed_membership: policy.closed_membership,
            max_content_bytes: policy.max_content_bytes,
            max_tags: policy.max_tags,
            max_future_seconds: policy.max_future_seconds,
            max_past_seconds: policy.max_past_seconds,
        }
    }
}

fn pg_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::TimestampOutOfRange { field, value })
}

fn pg_limit(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidLimit(value))
}
