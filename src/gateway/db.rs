use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::{
    domain::{Event, Filter, RelaySigner},
    store::{AdmissionOutcome, ManagementRequest, Store, StoreError, StoredEvent},
};

use super::GatewayError;

#[derive(Clone)]
pub struct DbPool {
    inner: Arc<DbPoolInner>,
}

struct DbPoolInner {
    workers: Vec<mpsc::Sender<DbRequest>>,
    next: AtomicUsize,
}

enum DbRequest {
    Admit {
        event: Event,
        now: u64,
        response: oneshot::Sender<Result<AdmissionOutcome, StoreError>>,
    },
    History {
        filters: Vec<Filter>,
        now: u64,
        max_results: usize,
        cancel: watch::Receiver<bool>,
        read_pubkeys: Vec<String>,
        response: oneshot::Sender<Result<HistoryResult, StoreError>>,
    },
    Count {
        filters: Vec<Filter>,
        now: u64,
        max_count: usize,
        read_pubkeys: Vec<String>,
        response: oneshot::Sender<Result<Option<usize>, StoreError>>,
    },
    Manage {
        authorization_id: String,
        authorization_pubkey: String,
        request: ManagementRequest,
        now: u64,
        response: oneshot::Sender<Result<serde_json::Value, StoreError>>,
    },
    CatchUp {
        after: i64,
        through: i64,
        now: u64,
        limit: usize,
        response: oneshot::Sender<Result<CatchUpResult, StoreError>>,
    },
}

#[derive(Debug)]
pub struct HistoryResult {
    pub high_water: i64,
    pub events: Vec<StoredEvent>,
}

#[derive(Debug)]
pub struct CatchUpResult {
    pub latest: i64,
    pub events: Vec<StoredEvent>,
}

impl DbPool {
    pub async fn start(
        database_url: &str,
        workers: usize,
        queue_capacity: usize,
        shutdown: watch::Sender<bool>,
        shutdown_receiver: watch::Receiver<bool>,
        current: Arc<AtomicBool>,
        relay_signer: Option<RelaySigner>,
    ) -> Result<(Self, Vec<JoinHandle<()>>), GatewayError> {
        let mut stores = Vec::with_capacity(workers);
        for _ in 0..workers {
            stores.push(Store::connect_verified(database_url).await?);
        }

        let mut senders = Vec::with_capacity(workers);
        let mut tasks = Vec::with_capacity(workers);
        for mut store in stores {
            let (sender, mut receiver) = mpsc::channel(queue_capacity.max(1));
            senders.push(sender);
            let mut worker_shutdown = shutdown_receiver.clone();
            let failure_shutdown = shutdown.clone();
            let worker_current = Arc::clone(&current);
            let relay_signer = relay_signer.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        changed = worker_shutdown.changed() => {
                            if changed.is_err() || *worker_shutdown.borrow() {
                                break;
                            }
                        }
                        request = receiver.recv() => {
                            let Some(request) = request else { break };
                            let fatal = handle_request(&mut store, request, relay_signer.as_ref()).await;
                            if fatal || !store.is_current() {
                                worker_current.store(false, Ordering::Release);
                                let _ = failure_shutdown.send(true);
                                break;
                            }
                        }
                    }
                }
            }));
        }
        Ok((
            Self {
                inner: Arc::new(DbPoolInner {
                    workers: senders,
                    next: AtomicUsize::new(0),
                }),
            },
            tasks,
        ))
    }

    pub async fn admit(&self, event: Event, now: u64) -> Result<AdmissionOutcome, StoreError> {
        let (response, result) = oneshot::channel();
        self.send(DbRequest::Admit {
            event,
            now,
            response,
        })?;
        result.await.map_err(|_| StoreError::ConnectionClosed)?
    }

    pub async fn history(
        &self,
        filters: Vec<Filter>,
        now: u64,
        max_results: usize,
        cancel: watch::Receiver<bool>,
        read_pubkeys: Vec<String>,
    ) -> Result<HistoryResult, StoreError> {
        let (response, result) = oneshot::channel();
        self.send(DbRequest::History {
            filters,
            now,
            max_results,
            cancel,
            read_pubkeys,
            response,
        })?;
        result.await.map_err(|_| StoreError::ConnectionClosed)?
    }

    pub async fn count(
        &self,
        filters: Vec<Filter>,
        now: u64,
        max_count: usize,
        read_pubkeys: Vec<String>,
    ) -> Result<Option<usize>, StoreError> {
        let (response, result) = oneshot::channel();
        self.send(DbRequest::Count {
            filters,
            now,
            max_count,
            read_pubkeys,
            response,
        })?;
        result.await.map_err(|_| StoreError::ConnectionClosed)?
    }

    pub async fn manage(
        &self,
        authorization_id: String,
        authorization_pubkey: String,
        request: ManagementRequest,
        now: u64,
    ) -> Result<serde_json::Value, StoreError> {
        let (response, result) = oneshot::channel();
        self.send(DbRequest::Manage {
            authorization_id,
            authorization_pubkey,
            request,
            now,
            response,
        })?;
        result.await.map_err(|_| StoreError::ConnectionClosed)?
    }

    pub async fn catch_up(
        &self,
        after: i64,
        through: i64,
        now: u64,
        limit: usize,
    ) -> Result<CatchUpResult, StoreError> {
        let (response, result) = oneshot::channel();
        self.send(DbRequest::CatchUp {
            after,
            through,
            now,
            limit,
            response,
        })?;
        result.await.map_err(|_| StoreError::ConnectionClosed)?
    }

    fn send(&self, request: DbRequest) -> Result<(), StoreError> {
        let start = self.inner.next.fetch_add(1, Ordering::Relaxed) % self.inner.workers.len();
        let mut request = request;
        for offset in 0..self.inner.workers.len() {
            let index = (start + offset) % self.inner.workers.len();
            match self.inner.workers[index].try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(returned)) => request = returned,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(StoreError::ConnectionClosed);
                }
            }
        }
        Err(StoreError::WorkQueueFull)
    }
}

async fn handle_request(
    store: &mut Store,
    request: DbRequest,
    relay_signer: Option<&RelaySigner>,
) -> bool {
    match request {
        DbRequest::Admit {
            event,
            now,
            response,
        } => {
            let result = store.admit_with_signer(&event, now, relay_signer).await;
            let fatal = result.as_ref().is_err_and(is_fatal);
            let _ = response.send(result);
            fatal
        }
        DbRequest::History {
            filters,
            now,
            max_results,
            cancel,
            read_pubkeys,
            response,
        } => {
            let result =
                query_history(store, filters, now, max_results, cancel, read_pubkeys).await;
            let fatal = result.as_ref().is_err_and(is_fatal);
            let _ = response.send(result);
            fatal
        }
        DbRequest::Count {
            filters,
            now,
            max_count,
            read_pubkeys,
            response,
        } => {
            let result = store
                .count_filters(&filters, now, max_count, &read_pubkeys)
                .await;
            let fatal = result.as_ref().is_err_and(is_fatal);
            let _ = response.send(result);
            fatal
        }
        DbRequest::Manage {
            authorization_id,
            authorization_pubkey,
            request,
            now,
            response,
        } => {
            let result = store
                .manage(
                    &authorization_id,
                    &authorization_pubkey,
                    request,
                    now,
                    relay_signer,
                )
                .await;
            let fatal = result.as_ref().is_err_and(is_fatal);
            let _ = response.send(result);
            fatal
        }
        DbRequest::CatchUp {
            after,
            through,
            now,
            limit,
            response,
        } => {
            let result = catch_up(store, after, through, now, limit).await;
            let fatal = result.as_ref().is_err_and(is_fatal);
            let _ = response.send(result);
            fatal
        }
    }
}

async fn catch_up(
    store: &Store,
    after: i64,
    through: i64,
    now: u64,
    limit: usize,
) -> Result<CatchUpResult, StoreError> {
    let latest = store.latest_ingest_seq().await?;
    let events = store.events_after(after, through, now, limit).await?;
    Ok(CatchUpResult { latest, events })
}

async fn query_history(
    store: &Store,
    filters: Vec<Filter>,
    now: u64,
    max_results: usize,
    cancel: watch::Receiver<bool>,
    read_pubkeys: Vec<String>,
) -> Result<HistoryResult, StoreError> {
    if *cancel.borrow() {
        return Err(StoreError::QueryCancelled);
    }
    let high_water = store.latest_ingest_seq().await?;
    let search_order = filters.iter().any(|filter| filter.search.is_some());
    let mut events = HashMap::new();
    let mut order = Vec::new();
    let per_filter = max_results.div_ceil(filters.len().max(1));
    for filter in filters {
        let rows = store
            .query_filter_for(
                &filter,
                now,
                per_filter,
                high_water,
                cancel.clone(),
                &read_pubkeys,
            )
            .await?;
        for stored in rows {
            let id = stored.event.id.clone();
            if let std::collections::hash_map::Entry::Vacant(entry) = events.entry(id.clone()) {
                order.push(id);
                entry.insert(stored);
            }
        }
    }
    let mut events = if search_order {
        order
            .into_iter()
            .filter_map(|id| events.remove(&id))
            .collect::<Vec<_>>()
    } else {
        events.into_values().collect::<Vec<_>>()
    };
    if !search_order {
        events.sort_by(|left, right| {
            right
                .event
                .created_at
                .cmp(&left.event.created_at)
                .then_with(|| left.event.id.cmp(&right.event.id))
        });
    }
    events.truncate(max_results);
    Ok(HistoryResult { high_water, events })
}

fn is_fatal(error: &StoreError) -> bool {
    !matches!(
        error,
        StoreError::Domain(_)
            | StoreError::QueryCancelled
            | StoreError::WorkQueueFull
            | StoreError::TimestampOutOfRange { .. }
            | StoreError::InvalidLimit(_)
            | StoreError::Serialization(_)
            | StoreError::EphemeralTooLarge(_)
            | StoreError::Management(_)
    )
}
