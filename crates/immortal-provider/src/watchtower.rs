use crate::{
    bitcoind::{BitcoindClient, BitcoindError, PollBackoff, RpcRequestId},
    health::{AlertEndpoint, ProviderAlert, ProviderHealth, send_alert},
    store::{ProviderStore, ProviderStoreError, WatchJob},
};
use immortal_core::mkt_swp_verify::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const WATCH_PAYLOAD_SCHEMA: &str = "openagents.immortal.provider-watch.v1";
pub(crate) const MAX_RAW_TRANSACTION_BYTES: usize = 1_000_000;
pub(crate) const MAX_WATCH_INPUTS: usize = 4_096;
pub(crate) const MAX_DUE_JOBS: usize = 32;
pub(crate) const MAX_OBSERVATION_JOBS: usize = 64;
pub(crate) const MAX_ALERTS: usize = 64;
pub(crate) const MAX_MEMPOOL_TRANSACTIONS: usize = 1_000_000;
pub(crate) const WATCH_LEASE_SECONDS: u64 = 30;
pub(crate) const MAX_POLL_FAILURES: u32 = 8;

#[derive(Debug)]
pub enum WatchtowerError {
    InvalidPayload(&'static str),
    Clock,
    Chain(BitcoindError),
    Store(ProviderStoreError),
    ChainStale,
    PollExhausted,
}

impl fmt::Display for WatchtowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayload(message) => write!(formatter, "invalid watch payload: {message}"),
            Self::Clock => formatter.write_str("provider watchtower clock is unavailable"),
            Self::Chain(error) => write!(formatter, "provider chain watcher failed: {error}"),
            Self::Store(error) => write!(formatter, "provider watchtower store failed: {error}"),
            Self::ChainStale => formatter.write_str("provider chain watcher became stale"),
            Self::PollExhausted => {
                formatter.write_str("provider chain watcher exhausted its bounded retry budget")
            }
        }
    }
}

impl std::error::Error for WatchtowerError {}

impl From<BitcoindError> for WatchtowerError {
    fn from(error: BitcoindError) -> Self {
        Self::Chain(error)
    }
}

impl From<ProviderStoreError> for WatchtowerError {
    fn from(error: ProviderStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchedOutPoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReleaseEvidence {
    pub payment_hash: String,
    pub settled_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastWatchPayload {
    pub schema: String,
    pub raw_transaction: String,
    pub expected_txid: String,
    pub inputs: Vec<WatchedOutPoint>,
    pub claim_release: Option<ClaimReleaseEvidence>,
}

impl BroadcastWatchPayload {
    pub fn refund(raw_transaction: String) -> Result<Self, WatchtowerError> {
        Self::validated(raw_transaction, None)
    }

    pub fn released_claim(
        raw_transaction: String,
        evidence: ClaimReleaseEvidence,
    ) -> Result<Self, WatchtowerError> {
        validate_hash(&evidence.payment_hash)?;
        if evidence.settled_at == 0 {
            return Err(WatchtowerError::InvalidPayload(
                "claim release evidence has no settlement time",
            ));
        }
        Self::validated(raw_transaction, Some(evidence))
    }

    fn validated(
        raw_transaction: String,
        claim_release: Option<ClaimReleaseEvidence>,
    ) -> Result<Self, WatchtowerError> {
        let bytes = decode_bounded_hex(&raw_transaction, MAX_RAW_TRANSACTION_BYTES)?;
        let transaction = Transaction::parse(&bytes)
            .map_err(|_| WatchtowerError::InvalidPayload("transaction is invalid"))?;
        let expected_txid = lower_hex(&transaction.txid().map_err(|_| {
            WatchtowerError::InvalidPayload("transaction ID could not be computed")
        })?);
        if transaction.inputs.len() > MAX_WATCH_INPUTS {
            return Err(WatchtowerError::InvalidPayload(
                "transaction input count exceeds the watch bound",
            ));
        }
        let inputs = transaction
            .inputs
            .iter()
            .map(|input| {
                let mut display_txid = input.previous_txid;
                display_txid.reverse();
                WatchedOutPoint {
                    txid: lower_hex(&display_txid),
                    vout: input.previous_output,
                }
            })
            .collect();
        Ok(Self {
            schema: WATCH_PAYLOAD_SCHEMA.to_owned(),
            raw_transaction,
            expected_txid,
            inputs,
            claim_release,
        })
    }

    pub fn request_sha256(&self) -> Result<String, WatchtowerError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| WatchtowerError::InvalidPayload("payload is not serializable"))?;
        Ok(lower_hex(&Sha256::digest(bytes)))
    }

    pub fn public_value(&self) -> Result<Value, WatchtowerError> {
        serde_json::to_value(self)
            .map_err(|_| WatchtowerError::InvalidPayload("payload is not serializable"))
    }

    fn validate_for_job(&self, job: &WatchJob) -> Result<(), WatchtowerError> {
        if self.schema != WATCH_PAYLOAD_SCHEMA
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_WATCH_INPUTS
            || self.request_sha256()? != job.request_sha256
        {
            return Err(WatchtowerError::InvalidPayload(
                "payload schema, input count, or digest does not match",
            ));
        }
        validate_hash(&self.expected_txid)?;
        for input in &self.inputs {
            validate_hash(&input.txid)?;
        }
        match job.job_kind.as_str() {
            "refund_broadcast" if self.claim_release.is_none() => {}
            "claim_broadcast" if self.claim_release.is_some() => {}
            "refund_broadcast" | "claim_broadcast" => {
                return Err(WatchtowerError::InvalidPayload(
                    "claim release evidence does not match the job kind",
                ));
            }
            _ => {
                return Err(WatchtowerError::InvalidPayload(
                    "watch job kind is unsupported",
                ));
            }
        }
        let rebuilt = Self::validated(self.raw_transaction.clone(), self.claim_release.clone())?;
        if rebuilt.expected_txid != self.expected_txid || rebuilt.inputs != self.inputs {
            return Err(WatchtowerError::InvalidPayload(
                "raw transaction does not match its public bindings",
            ));
        }
        Ok(())
    }
}

pub struct Watchtower {
    store: ProviderStore,
    bitcoind: BitcoindClient,
    health: Arc<ProviderHealth>,
    alert_endpoint: Option<AlertEndpoint>,
    poll_interval: Duration,
    stale_after: Duration,
    minimum_confirmations: u32,
}

impl Watchtower {
    pub fn new(
        store: ProviderStore,
        bitcoind: BitcoindClient,
        health: Arc<ProviderHealth>,
        alert_endpoint: Option<AlertEndpoint>,
        poll_interval: Duration,
        stale_after: Duration,
        minimum_confirmations: u32,
    ) -> Result<Self, WatchtowerError> {
        if poll_interval.is_zero()
            || poll_interval > Duration::from_secs(300)
            || stale_after <= poll_interval
            || stale_after > Duration::from_secs(3_600)
            || minimum_confirmations == 0
            || minimum_confirmations > 144
        {
            return Err(WatchtowerError::InvalidPayload(
                "watch policy is outside its bounds",
            ));
        }
        Ok(Self {
            store,
            bitcoind,
            health,
            alert_endpoint,
            poll_interval,
            stale_after,
            minimum_confirmations,
        })
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), WatchtowerError> {
        let mut backoff = PollBackoff::new(
            self.poll_interval,
            Duration::from_secs(300),
            MAX_POLL_FAILURES,
        )?;
        let mut last_success = unix_now()?;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let now = unix_now()?;
            match self.poll_once(now).await {
                Ok(()) => {
                    backoff.record_success();
                    last_success = now;
                }
                Err(error) => {
                    self.health.mark_not_ready();
                    let failures = self.health.record_chain_failure();
                    self.send_system_alert("chain_poller_failure", now, failures)
                        .await;
                    if now.saturating_sub(last_success) >= self.stale_after.as_secs() {
                        self.send_system_alert("chain_poller_stale", now, failures)
                            .await;
                        return Err(WatchtowerError::ChainStale);
                    }
                    let Some(delay) = backoff.record_failure() else {
                        return Err(WatchtowerError::PollExhausted);
                    };
                    eprintln!(
                        "immortal-provider: chain poll failed ({error}); retrying in {}s ({failures}/{MAX_POLL_FAILURES})",
                        delay.as_secs()
                    );
                    if wait_or_shutdown(delay, &mut shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            }
            if wait_or_shutdown(self.poll_interval, &mut shutdown).await {
                return Ok(());
            }
        }
    }

    async fn poll_once(&mut self, now: u64) -> Result<(), WatchtowerError> {
        let tip_hash = self
            .bitcoind
            .best_block_hash(&request_id("best-block", now, 0)?)
            .await?;
        let tip_header = self
            .bitcoind
            .block_header(&request_id("best-header", now, 0)?, &tip_hash, true)
            .await?;
        let tip_height = tip_header.get("height").and_then(Value::as_u64).ok_or(
            WatchtowerError::InvalidPayload("best block header has no height"),
        )?;
        let mempool = self
            .bitcoind
            .raw_mempool(&request_id("mempool", now, 0)?, false)
            .await?;
        validate_mempool(&mempool)?;
        let lease_until = now
            .checked_add(WATCH_LEASE_SECONDS)
            .ok_or(WatchtowerError::Clock)?;
        let due = self
            .store
            .claim_due_watch_jobs(tip_height, now, lease_until, MAX_DUE_JOBS)
            .await?;
        for job in due {
            if job.state == "page" {
                continue;
            }
            if let Err(error) = self.broadcast_job(&job, now).await {
                if should_page_job(&error) {
                    self.page_job(&job, "broadcast_failed", now).await?;
                    eprintln!(
                        "immortal-provider: watch job {} broadcast failed permanently: {error}",
                        job.job_id
                    );
                } else {
                    return Err(error);
                }
            }
        }

        let observations = self
            .store
            .watch_jobs_for_observation(MAX_OBSERVATION_JOBS)
            .await?;
        for job in observations {
            if let Err(error) = self.observe_job(&job, &tip_hash, now).await {
                if should_page_job(&error) {
                    self.page_job(&job, "observation_failed", now).await?;
                    eprintln!(
                        "immortal-provider: watch job {} observation failed permanently: {error}",
                        job.job_id
                    );
                } else {
                    return Err(error);
                }
            }
        }

        self.deliver_alerts(now).await?;
        let counts = self.store.health_counts().await?;
        self.health.set_ledger_counts(
            counts.active_reservations,
            counts.pending_effects,
            counts.unresolved_effects,
            counts.pending_watch_jobs,
            counts
                .unresolved_reservations
                .saturating_add(counts.unresolved_watch_jobs)
                .saturating_add(counts.paged_watch_jobs)
                .saturating_add(counts.active_alerts),
        );
        self.health
            .record_chain_success(i64::try_from(tip_height).unwrap_or(i64::MAX), now);
        if counts.unresolved_reservations == 0
            && counts.pending_effects == 0
            && counts.unresolved_effects == 0
            && counts.unresolved_watch_jobs == 0
            && counts.paged_watch_jobs == 0
            && counts.active_alerts == 0
        {
            self.health.mark_ready();
        } else {
            self.health.mark_not_ready();
        }
        Ok(())
    }

    async fn broadcast_job(&mut self, job: &WatchJob, now: u64) -> Result<(), WatchtowerError> {
        let payload = decode_job_payload(job)?;
        let broadcast_request_id = request_id("broadcast", now, job.attempt_count)?;
        let transaction_id = match self
            .bitcoind
            .broadcast(&broadcast_request_id, &payload.raw_transaction, None)
            .await
        {
            Ok(transaction_id) => transaction_id,
            Err(BitcoindError::Rpc { code: -27 }) => {
                self.bitcoind
                    .raw_transaction(
                        &request_id("broadcast-replay", now, job.attempt_count)?,
                        &payload.expected_txid,
                        false,
                    )
                    .await?;
                payload.expected_txid.clone()
            }
            Err(error) => {
                if self
                    .store
                    .watch_job(&job.job_id)
                    .await?
                    .is_some_and(|current| current.state == "completed")
                {
                    return Ok(());
                }
                return Err(error.into());
            }
        };
        if transaction_id != payload.expected_txid {
            return Err(WatchtowerError::InvalidPayload(
                "bitcoind returned another transaction ID",
            ));
        }
        if self
            .store
            .watch_job(&job.job_id)
            .await?
            .is_some_and(|current| current.state == "completed")
        {
            return Ok(());
        }
        let (result, result_sha256) = match (&job.public_result, &job.result_sha256) {
            (Some(result), Some(result_sha256)) => (result.clone(), result_sha256.clone()),
            (None, None) => {
                let result = json!({"txid":transaction_id,"accepted_at":now});
                let result_sha256 = value_digest(&result)?;
                (result, result_sha256)
            }
            _ => {
                return Err(WatchtowerError::InvalidPayload(
                    "watch broadcast result is partially persisted",
                ));
            }
        };
        self.store
            .record_broadcast(
                &job.job_id,
                &job.request_sha256,
                &result_sha256,
                &result,
                &payload.expected_txid,
                now,
            )
            .await?;
        Ok(())
    }

    async fn observe_job(
        &mut self,
        job: &WatchJob,
        current_tip: &str,
        now: u64,
    ) -> Result<(), WatchtowerError> {
        let payload = decode_job_payload(job)?;
        let first_input = payload
            .inputs
            .first()
            .ok_or(WatchtowerError::InvalidPayload(
                "watch payload has no input",
            ))?;
        let first_input_unspent = self
            .bitcoind
            .transaction_output(
                &request_id("input-status", now, 0)?,
                &first_input.txid,
                first_input.vout,
                true,
            )
            .await?
            .is_some();
        let transaction = self
            .bitcoind
            .raw_transaction(
                &request_id("observe", now, job.attempt_count)?,
                &payload.expected_txid,
                true,
            )
            .await;
        match transaction {
            Ok(transaction) => {
                let object = transaction
                    .as_object()
                    .ok_or(WatchtowerError::InvalidPayload(
                        "transaction observation is not an object",
                    ))?;
                let confirmations = object
                    .get("confirmations")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if confirmations == 0 {
                    if job.confirmations > 0 {
                        self.store
                            .record_reorg(&job.job_id, current_tip, now)
                            .await?;
                    }
                    return Ok(());
                }
                let confirmations = u32::try_from(confirmations).map_err(|_| {
                    WatchtowerError::InvalidPayload("confirmation count exceeds u32")
                })?;
                let block_hash = object.get("blockhash").and_then(Value::as_str).ok_or(
                    WatchtowerError::InvalidPayload("confirmed transaction has no block hash"),
                )?;
                validate_hash(block_hash)?;
                if job
                    .observed_block_hash
                    .as_deref()
                    .is_some_and(|previous| previous != block_hash)
                {
                    self.store
                        .record_reorg(&job.job_id, current_tip, now)
                        .await?;
                }
                self.store
                    .record_confirmation(
                        &job.job_id,
                        confirmations,
                        self.minimum_confirmations,
                        block_hash,
                        now,
                    )
                    .await?;
                Ok(())
            }
            Err(BitcoindError::Rpc { code: -5 }) => {
                if first_input_unspent && self.inputs_are_unspent(&payload, now).await? {
                    self.store
                        .record_reorg(&job.job_id, current_tip, now)
                        .await?;
                    self.broadcast_job(job, now).await?;
                    return Ok(());
                }
                if let Some(replacement) = self.find_replacement(&payload, now).await? {
                    self.store
                        .record_replacement(&job.job_id, &replacement, now)
                        .await?;
                    return Ok(());
                }
                if job.observed_block_hash.is_some() {
                    self.store
                        .record_reorg(&job.job_id, current_tip, now)
                        .await?;
                    return Ok(());
                }
                Err(WatchtowerError::InvalidPayload(
                    "broadcast transaction disappeared without a replacement",
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn inputs_are_unspent(
        &self,
        payload: &BroadcastWatchPayload,
        now: u64,
    ) -> Result<bool, WatchtowerError> {
        for (index, input) in payload.inputs.iter().enumerate() {
            let attempt = u16::try_from(index).unwrap_or(u16::MAX);
            if self
                .bitcoind
                .transaction_output(
                    &request_id("input-recheck", now, attempt)?,
                    &input.txid,
                    input.vout,
                    true,
                )
                .await?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn find_replacement(
        &self,
        payload: &BroadcastWatchPayload,
        now: u64,
    ) -> Result<Option<String>, WatchtowerError> {
        let outpoints = payload
            .inputs
            .iter()
            .map(|input| json!({"txid":input.txid,"vout":input.vout}))
            .collect::<Vec<_>>();
        let result = self
            .bitcoind
            .call(
                &request_id("replacement", now, 0)?,
                "gettxspendingprevout",
                json!([outpoints]),
            )
            .await?;
        replacement_from_response(&result, &payload.expected_txid)
    }

    async fn page_job(
        &mut self,
        job: &WatchJob,
        page_code: &str,
        now: u64,
    ) -> Result<(), WatchtowerError> {
        let context = json!({
            "job_id":job.job_id,
            "expected_txid":job.broadcast_txid,
            "attempt_count":job.attempt_count,
        });
        self.store
            .page_watch_job(&job.job_id, page_code, &context, now)
            .await?;
        Ok(())
    }

    async fn deliver_alerts(&self, now: u64) -> Result<(), WatchtowerError> {
        let Some(endpoint) = self.alert_endpoint.as_ref() else {
            return Ok(());
        };
        for alert in self.store.active_alerts(MAX_ALERTS).await? {
            let body = ProviderAlert::new(
                &alert.alert_class,
                alert.session_id.as_deref(),
                now,
                &alert.detail_code,
            );
            if send_alert(endpoint, &body).await.is_ok() {
                self.store
                    .set_alert_state(&alert.alert_id, "acknowledged", now)
                    .await?;
            }
        }
        Ok(())
    }

    async fn send_system_alert(&self, alert_type: &str, now: u64, failures: u32) {
        let Some(endpoint) = self.alert_endpoint.as_ref() else {
            return;
        };
        let detail = format!("consecutive_failures_{failures}");
        let alert = ProviderAlert::new(alert_type, None, now, &detail);
        if let Err(error) = send_alert(endpoint, &alert).await {
            eprintln!("immortal-provider: alert delivery failed: {error}");
        }
    }
}

fn decode_job_payload(job: &WatchJob) -> Result<BroadcastWatchPayload, WatchtowerError> {
    let payload: BroadcastWatchPayload = serde_json::from_value(job.public_payload.clone())
        .map_err(|_| WatchtowerError::InvalidPayload("watch payload shape is invalid"))?;
    payload.validate_for_job(job)?;
    Ok(payload)
}

fn should_page_job(error: &WatchtowerError) -> bool {
    matches!(error, WatchtowerError::InvalidPayload(_))
}

fn validate_mempool(value: &Value) -> Result<(), WatchtowerError> {
    let transactions = value.as_array().ok_or(WatchtowerError::InvalidPayload(
        "raw mempool response is not an array",
    ))?;
    if transactions.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err(WatchtowerError::InvalidPayload(
            "raw mempool response exceeds its transaction bound",
        ));
    }
    for transaction_id in transactions {
        let transaction_id = transaction_id
            .as_str()
            .ok_or(WatchtowerError::InvalidPayload(
                "raw mempool transaction ID is not a string",
            ))?;
        validate_hash(transaction_id)?;
    }
    Ok(())
}

fn replacement_from_response(
    result: &Value,
    original_txid: &str,
) -> Result<Option<String>, WatchtowerError> {
    let entries = result.as_array().ok_or(WatchtowerError::InvalidPayload(
        "replacement response is not an array",
    ))?;
    let mut replacement = None;
    for entry in entries {
        let Some(transaction_id) = entry.get("spendingtxid").and_then(Value::as_str) else {
            continue;
        };
        validate_hash(transaction_id)?;
        if transaction_id == original_txid {
            continue;
        }
        if replacement
            .as_deref()
            .is_some_and(|existing| existing != transaction_id)
        {
            return Err(WatchtowerError::InvalidPayload(
                "inputs were replaced by multiple transactions",
            ));
        }
        replacement = Some(transaction_id.to_owned());
    }
    Ok(replacement)
}

async fn wait_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

fn request_id(prefix: &str, now: u64, attempt: u16) -> Result<RpcRequestId, WatchtowerError> {
    RpcRequestId::new(format!("{prefix}:{now}:{attempt}")).map_err(WatchtowerError::Chain)
}

fn value_digest(value: &Value) -> Result<String, WatchtowerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| WatchtowerError::InvalidPayload("result is not serializable"))?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn validate_hash(value: &str) -> Result<(), WatchtowerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WatchtowerError::InvalidPayload(
            "hash is not 32 lowercase-hex bytes",
        ));
    }
    Ok(())
}

fn decode_bounded_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, WatchtowerError> {
    if value.is_empty() || value.len() > maximum_bytes.saturating_mul(2) || value.len() % 2 != 0 {
        return Err(WatchtowerError::InvalidPayload(
            "raw transaction is not bounded hexadecimal",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0]).ok_or(WatchtowerError::InvalidPayload(
            "raw transaction is not lowercase hexadecimal",
        ))?;
        let low = hex_value(pair[1]).ok_or(WatchtowerError::InvalidPayload(
            "raw transaction is not lowercase hexadecimal",
        ))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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

fn unix_now() -> Result<u64, WatchtowerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WatchtowerError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use immortal_core::mkt_swp_verify::{TransactionInput, TransactionOutput};

    #[test]
    fn refund_payload_binds_transaction_id_and_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let raw = test_transaction()?;
        let payload = BroadcastWatchPayload::refund(raw)?;
        assert_eq!(payload.inputs.len(), 1);
        assert_eq!(payload.inputs[0].vout, 2);
        assert_eq!(payload.inputs[0].txid, "11".repeat(32));
        assert_eq!(payload.expected_txid.len(), 64);
        assert!(payload.claim_release.is_none());
        Ok(())
    }

    #[test]
    fn claim_payload_requires_public_release_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let raw = test_transaction()?;
        assert!(
            BroadcastWatchPayload::released_claim(
                raw.clone(),
                ClaimReleaseEvidence {
                    payment_hash: "22".repeat(32),
                    settled_at: 0,
                }
            )
            .is_err()
        );
        let payload = BroadcastWatchPayload::released_claim(
            raw,
            ClaimReleaseEvidence {
                payment_hash: "22".repeat(32),
                settled_at: 100,
            },
        )?;
        assert!(payload.claim_release.is_some());
        assert!(!payload.public_value()?.to_string().contains("preimage"));
        Ok(())
    }

    #[test]
    fn replacement_response_is_single_and_bound() -> Result<(), Box<dyn std::error::Error>> {
        let original = "33".repeat(32);
        let replacement = "44".repeat(32);
        assert_eq!(
            replacement_from_response(
                &json!([{"spendingtxid":original},{"spendingtxid":replacement}]),
                &original,
            )?,
            Some(replacement)
        );
        assert!(
            replacement_from_response(
                &json!([
                    {"spendingtxid":"44".repeat(32)},
                    {"spendingtxid":"55".repeat(32)}
                ]),
                &original,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn only_permanent_job_errors_page_immediately() {
        assert!(should_page_job(&WatchtowerError::InvalidPayload("fixture")));
        assert!(!should_page_job(&WatchtowerError::Chain(
            BitcoindError::ConnectionFailed
        )));
        assert!(!should_page_job(&WatchtowerError::ChainStale));
    }

    #[test]
    fn raw_mempool_is_bounded_and_hash_only() {
        assert!(validate_mempool(&json!(["11".repeat(32)])).is_ok());
        assert!(validate_mempool(&json!({})).is_err());
        assert!(validate_mempool(&json!(["not-a-hash"])).is_err());
    }

    fn test_transaction() -> Result<String, Box<dyn std::error::Error>> {
        let transaction = Transaction::new(
            2,
            vec![TransactionInput {
                previous_txid: [0x11; 32],
                previous_output: 2,
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            vec![TransactionOutput {
                value_sat: 50_000,
                script_pubkey: vec![0x51],
            }],
            100,
        );
        Ok(lower_hex(&transaction.serialize(false)?))
    }
}
