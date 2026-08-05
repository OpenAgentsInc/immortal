//! Persisted lab state: identity, discovery snapshot, and session records.
//!
//! Every record is a plain JSON file under one state directory so a killed
//! harness can be restarted and resume from persisted records (the substrate
//! for the #18 doomsday drill). Writes are temp-file-plus-rename so a crash
//! mid-write never leaves a torn record.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use immortal_client::{domain::Event, market::MarketSigner, mkt_swp_client::provider_support};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::util::{lower_hex, parse_hex_32, random_secret};

pub const IDENTITY_WARNING: &str =
    "dev-only lab identity for loopback regtest sessions; never fund or reuse";

/// Layout of the lab state directory.
#[derive(Debug, Clone)]
pub struct LabPaths {
    root: PathBuf,
}

impl LabPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_env() -> Self {
        let root = std::env::var("IMMORTAL_LAB_STATE_DIR")
            .unwrap_or_else(|_| "target/lab-state".to_owned());
        Self::new(root)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.json")
    }

    pub fn discovery(&self) -> PathBuf {
        self.root.join("discovery.json")
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    pub fn session(&self, session_id: &str) -> PathBuf {
        self.sessions_dir().join(format!("{session_id}.json"))
    }

    pub fn current_session(&self) -> PathBuf {
        self.root.join("current-session")
    }

    pub fn funded_run_id(&self) -> PathBuf {
        self.root.join("funded-run-id")
    }

    pub fn funded_checkpoint(&self) -> PathBuf {
        self.root.join("funded-checkpoint.json")
    }

    pub fn funded_journey_checkpoint(&self, journey: &str) -> PathBuf {
        self.root.join(format!("funded-{journey}-checkpoint.json"))
    }

    pub fn funded_continue(&self) -> PathBuf {
        self.root.join("funded-continue")
    }

    pub fn funded_injection(&self) -> PathBuf {
        self.root.join("funded-injection.json")
    }

    pub fn funded_injection_proof(&self) -> PathBuf {
        self.root.join("funded-injection-proof.json")
    }

    pub fn funded_snapshot(&self, journey: &str) -> PathBuf {
        self.root.join(format!("funded-{journey}-session.json"))
    }

    pub fn funded_deliveries(&self, journey: &str) -> PathBuf {
        self.root.join(format!("funded-{journey}-deliveries.json"))
    }

    pub fn funded_secret(&self, journey: &str) -> PathBuf {
        self.root.join(format!("funded-{journey}-secret"))
    }

    pub fn funded_signed_exit(&self, journey: &str) -> PathBuf {
        self.root.join(format!("funded-{journey}-signed-exit.hex"))
    }

    pub fn boltz_adapter_control(&self, client: &str, phase: &str) -> PathBuf {
        self.root.join(format!("boltz-{client}-{phase}.json"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoltzAdapterPrepared {
    pub schema: String,
    pub client: String,
    pub session_id: String,
    pub invoice: String,
    pub refund_public_key: String,
    pub raw_transaction_hex: String,
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoltzAdapterFinalizeRequest {
    pub schema: String,
    pub client: String,
    pub session_id: String,
    pub finalize_path: String,
    pub raw_transaction_hex: String,
    pub funding_transaction_sha256: String,
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoltzAdapterApproval {
    pub schema: String,
    pub client: String,
    pub session_id: String,
    pub finalize_path: String,
    pub funding_transaction_sha256: String,
    pub output_index: u32,
    pub requester_contract_event_id: String,
    pub provider_contract_event_id: String,
    pub exit_package_sha256: String,
    pub exit_package_mode: String,
    pub authorization_snapshot_sha256: String,
    pub exit_package_persisted: bool,
    pub script_path_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoltzAdapterBroadcast {
    pub schema: String,
    pub client: String,
    pub session_id: String,
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundedCheckpoint {
    pub schema: String,
    pub run_id: String,
    pub journey: String,
    pub label: String,
    pub safe_to_stop: bool,
    pub updated_at: u64,
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundedInjectionRequest {
    pub schema: String,
    pub run_id: String,
    pub journey: String,
    pub checkpoint: String,
    pub injection: String,
    pub requested_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub secret_hex: String,
    pub pubkey: String,
    pub warning: String,
}

impl Identity {
    pub fn signer(&self) -> Result<MarketSigner, String> {
        let secret = parse_hex_32(&self.secret_hex)
            .map_err(|error| format!("persisted lab identity is invalid: {error}"))?;
        let signer = MarketSigner::from_secret_bytes(secret)?;
        if signer.pubkey() != self.pubkey {
            return Err("persisted lab identity pubkey does not match its secret".to_owned());
        }
        Ok(signer)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredOffering {
    pub address: String,
    pub distinct: String,
    pub status: String,
    pub event_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredProvider {
    pub pubkey: String,
    pub profile_event_id: String,
    pub status: String,
    pub offerings: Vec<DiscoveredOffering>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub relay_url: String,
    pub discovered_at: u64,
    pub providers: Vec<DiscoveredProvider>,
}

/// One lab swap session. Steps append to this record; nothing is rewritten
/// or discarded, so a restart can replay exactly what was persisted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub session_id: String,
    pub created_at: u64,
    pub relay_url: String,
    pub swap_type: String,
    pub provider_pubkey: String,
    pub offering_address: String,
    /// Last completed step: rfq_sent, quote_received, verified, or
    /// verification_failed.
    pub step: String,
    pub rfq: Option<Event>,
    pub quote: Option<Event>,
    #[serde(default)]
    pub quote_wrap: Option<Event>,
    #[serde(default)]
    pub quote_observed_at: Option<u64>,
    pub verification: Option<Value>,
}

pub fn load_or_create_identity(paths: &LabPaths) -> Result<Identity, String> {
    if paths.identity().exists() {
        return read_json(&paths.identity());
    }
    let secret = random_secret()?;
    let signer = MarketSigner::from_secret_bytes(secret)?;
    let identity = Identity {
        secret_hex: lower_hex(&secret),
        pubkey: signer.pubkey().to_owned(),
        warning: IDENTITY_WARNING.to_owned(),
    };
    write_json(&paths.identity(), &identity)?;
    restrict_permissions(&paths.identity())?;
    Ok(identity)
}

pub fn load_identity(paths: &LabPaths) -> Result<Identity, String> {
    if !paths.identity().exists() {
        return Err("no lab identity exists yet; run `immortal-lab rfq` first".to_owned());
    }
    read_json(&paths.identity())
}

pub fn store_discovery(paths: &LabPaths, discovery: &Discovery) -> Result<(), String> {
    write_json(&paths.discovery(), discovery)
}

pub fn load_discovery(paths: &LabPaths) -> Result<Discovery, String> {
    if !paths.discovery().exists() {
        return Err("no discovery snapshot exists; run `immortal-lab discover` first".to_owned());
    }
    read_json(&paths.discovery())
}

pub fn store_session(paths: &LabPaths, session: &SessionRecord) -> Result<(), String> {
    write_json(&paths.session(&session.session_id), session)
}

pub fn load_session(paths: &LabPaths, session_id: &str) -> Result<SessionRecord, String> {
    let path = paths.session(session_id);
    if !path.exists() {
        return Err(format!("no persisted session {session_id}"));
    }
    read_json(&path)
}

pub fn list_sessions(paths: &LabPaths) -> Result<Vec<SessionRecord>, String> {
    let directory = paths.sessions_dir();
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut sessions = Vec::new();
    let entries = fs::read_dir(&directory)
        .map_err(|error| format!("could not list {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("could not read session entry: {error}"))?;
        if entry.path().extension().is_some_and(|ext| ext == "json") {
            sessions.push(read_json::<SessionRecord>(&entry.path())?);
        }
    }
    sessions.sort_by_key(|session| session.created_at);
    Ok(sessions)
}

pub fn set_current_session(paths: &LabPaths, session_id: &str) -> Result<(), String> {
    write_bytes(&paths.current_session(), session_id.as_bytes())
}

/// Resolve the session id to act on: `IMMORTAL_LAB_SESSION` wins, then the
/// persisted current-session pointer.
pub fn resolve_session_id(paths: &LabPaths) -> Result<String, String> {
    if let Ok(session_id) = std::env::var("IMMORTAL_LAB_SESSION") {
        return Ok(session_id);
    }
    let pointer = paths.current_session();
    if !pointer.exists() {
        return Err("no current session; run `immortal-lab rfq` first".to_owned());
    }
    let session_id = fs::read_to_string(&pointer)
        .map_err(|error| format!("could not read {}: {error}", pointer.display()))?;
    Ok(session_id.trim().to_owned())
}

pub fn load_or_create_funded_run_id(paths: &LabPaths) -> Result<String, String> {
    if let Ok(run_id) = std::env::var("IMMORTAL_LAB_RUN_ID") {
        validate_run_id(&run_id)?;
        return Ok(run_id);
    }
    if paths.funded_run_id().exists() {
        let run_id = fs::read_to_string(paths.funded_run_id()).map_err(|error| {
            format!(
                "could not read {}: {error}",
                paths.funded_run_id().display()
            )
        })?;
        let run_id = run_id.trim().to_owned();
        validate_run_id(&run_id)?;
        return Ok(run_id);
    }
    let run_id = lower_hex(&random_secret()?);
    write_bytes(&paths.funded_run_id(), run_id.as_bytes())?;
    Ok(run_id)
}

pub fn store_funded_checkpoint(
    paths: &LabPaths,
    checkpoint: &FundedCheckpoint,
) -> Result<(), String> {
    validate_funded_checkpoint(checkpoint)?;
    write_json(&paths.funded_checkpoint(), checkpoint)
}

fn validate_funded_checkpoint(checkpoint: &FundedCheckpoint) -> Result<(), String> {
    if checkpoint.schema != "openagents.immortal.lab-checkpoint.v1"
        || validate_run_id(&checkpoint.run_id).is_err()
        || checkpoint.journey.is_empty()
        || checkpoint.journey.len() > 32
        || !checkpoint
            .journey
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || checkpoint.label.is_empty()
        || checkpoint.label.len() > 64
        || !checkpoint
            .label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("funded checkpoint identity is invalid or unbounded".to_owned());
    }
    provider_support::reject_custody_material(&checkpoint.details)
        .map_err(|error| format!("funded checkpoint rejected custody material: {error}"))?;
    Ok(())
}

pub fn store_funded_journey_checkpoint(
    paths: &LabPaths,
    checkpoint: &FundedCheckpoint,
) -> Result<(), String> {
    validate_funded_checkpoint(checkpoint)?;
    write_json(
        &paths.funded_journey_checkpoint(&checkpoint.journey),
        checkpoint,
    )
}

pub fn store_funded_injection(
    paths: &LabPaths,
    request: &FundedInjectionRequest,
) -> Result<(), String> {
    if request.schema != "openagents.immortal.lab-injection.v1"
        || validate_run_id(&request.run_id).is_err()
        || request.journey.is_empty()
        || request.journey.len() > 32
        || !request
            .journey
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || request.checkpoint.is_empty()
        || request.checkpoint.len() > 128
        || request.injection.is_empty()
        || request.injection.len() > 32
    {
        return Err("funded injection request is invalid or unbounded".to_owned());
    }
    write_json(&paths.funded_injection(), request)
}

pub fn store_funded_injection_proof(paths: &LabPaths, proof: &Value) -> Result<(), String> {
    provider_support::reject_custody_material(proof)
        .map_err(|error| format!("funded injection proof rejected custody material: {error}"))?;
    let encoded = serde_json::to_vec(proof)
        .map_err(|error| format!("could not encode funded injection proof: {error}"))?;
    if encoded.is_empty() || encoded.len() > 4_096 {
        return Err("funded injection proof is empty or unbounded".to_owned());
    }
    write_bytes(&paths.funded_injection_proof(), &encoded)
}

pub fn load_funded_injection_proof(paths: &LabPaths) -> Result<Option<Value>, String> {
    let path = paths.funded_injection_proof();
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() > 4_096 {
        return Err("funded injection proof is empty or unbounded".to_owned());
    }
    let proof: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("funded injection proof is invalid JSON: {error}"))?;
    provider_support::reject_custody_material(&proof)
        .map_err(|error| format!("funded injection proof contains custody material: {error}"))?;
    Ok(Some(proof))
}

pub fn store_funded_snapshot(
    paths: &LabPaths,
    journey: &str,
    snapshot: &[u8],
) -> Result<(), String> {
    if !journey
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("funded journey name is invalid".to_owned());
    }
    write_bytes(&paths.funded_snapshot(journey), snapshot)
}

pub fn store_funded_deliveries(
    paths: &LabPaths,
    journey: &str,
    deliveries: &Value,
) -> Result<(), String> {
    if !journey
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || !deliveries.is_array()
    {
        return Err("funded delivery archive is invalid".to_owned());
    }
    provider_support::reject_custody_material(deliveries)
        .map_err(|error| format!("funded delivery archive contains custody material: {error}"))?;
    let bytes = serde_json::to_vec(deliveries)
        .map_err(|error| format!("could not encode funded delivery archive: {error}"))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("funded delivery archive exceeds its bound".to_owned());
    }
    write_json(&paths.funded_deliveries(journey), deliveries)
}

pub fn load_funded_deliveries(paths: &LabPaths, journey: &str) -> Result<Option<Value>, String> {
    let path = paths.funded_deliveries(journey);
    if !path.exists() {
        return Ok(None);
    }
    let value: Value = read_json(&path)?;
    if !value.is_array() {
        return Err("persisted funded delivery archive is not an array".to_owned());
    }
    provider_support::reject_custody_material(&value)
        .map_err(|error| format!("persisted funded delivery archive is unsafe: {error}"))?;
    Ok(Some(value))
}

pub fn store_funded_secret(
    paths: &LabPaths,
    journey: &str,
    secret: &[u8; 32],
) -> Result<(), String> {
    if !journey
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("funded journey name is invalid".to_owned());
    }
    write_bytes(&paths.funded_secret(journey), secret)
}

pub fn load_funded_secret(paths: &LabPaths, journey: &str) -> Result<[u8; 32], String> {
    let bytes = fs::read(paths.funded_secret(journey)).map_err(|error| {
        format!(
            "could not read private {} custody record: {error}",
            paths.funded_secret(journey).display()
        )
    })?;
    bytes
        .try_into()
        .map_err(|_| "private funded custody record is not 32 bytes".to_owned())
}

pub fn remove_funded_secret(paths: &LabPaths, journey: &str) -> Result<(), String> {
    let path = paths.funded_secret(journey);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("could not remove private {}: {error}", path.display()))?;
    }
    Ok(())
}

pub fn store_funded_signed_exit(
    paths: &LabPaths,
    journey: &str,
    transaction: &str,
) -> Result<(), String> {
    if transaction.is_empty()
        || transaction.len() > 800_000
        || transaction.len() % 2 != 0
        || !transaction.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("signed exit transaction is not bounded hexadecimal".to_owned());
    }
    write_bytes(&paths.funded_signed_exit(journey), transaction.as_bytes())
}

pub fn load_funded_signed_exit(paths: &LabPaths, journey: &str) -> Result<String, String> {
    let path = paths.funded_signed_exit(journey);
    let transaction = fs::read_to_string(&path).map_err(|error| {
        format!(
            "could not read private signed exit {}: {error}",
            path.display()
        )
    })?;
    let transaction = transaction.trim().to_owned();
    if transaction.is_empty()
        || transaction.len() > 800_000
        || transaction.len() % 2 != 0
        || !transaction.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("persisted signed exit transaction is not bounded hexadecimal".to_owned());
    }
    Ok(transaction)
}

pub fn load_funded_checkpoint(paths: &LabPaths) -> Result<Option<FundedCheckpoint>, String> {
    if paths.funded_checkpoint().exists() {
        let checkpoint = read_json(&paths.funded_checkpoint())?;
        validate_funded_checkpoint(&checkpoint)?;
        Ok(Some(checkpoint))
    } else {
        Ok(None)
    }
}

pub fn clear_boltz_adapter_controls(paths: &LabPaths, client: &str) -> Result<(), String> {
    validate_boltz_adapter_client(client)?;
    for phase in [
        "prepared",
        "finalize-request",
        "approval",
        "broadcast",
        "complete",
    ] {
        let path = paths.boltz_adapter_control(client, phase);
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("could not remove {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

pub fn store_boltz_adapter_prepared(
    paths: &LabPaths,
    value: &BoltzAdapterPrepared,
) -> Result<(), String> {
    validate_boltz_adapter_client(&value.client)?;
    write_json(
        &paths.boltz_adapter_control(&value.client, "prepared"),
        value,
    )
}

pub fn load_boltz_adapter_finalize_request(
    paths: &LabPaths,
    client: &str,
) -> Result<BoltzAdapterFinalizeRequest, String> {
    validate_boltz_adapter_client(client)?;
    read_json(&paths.boltz_adapter_control(client, "finalize-request"))
}

pub fn store_boltz_adapter_approval(
    paths: &LabPaths,
    value: &BoltzAdapterApproval,
) -> Result<(), String> {
    validate_boltz_adapter_client(&value.client)?;
    write_json(
        &paths.boltz_adapter_control(&value.client, "approval"),
        value,
    )
}

pub fn load_boltz_adapter_broadcast(
    paths: &LabPaths,
    client: &str,
) -> Result<BoltzAdapterBroadcast, String> {
    validate_boltz_adapter_client(client)?;
    read_json(&paths.boltz_adapter_control(client, "broadcast"))
}

pub fn store_boltz_adapter_complete(
    paths: &LabPaths,
    value: &BoltzAdapterBroadcast,
) -> Result<(), String> {
    validate_boltz_adapter_client(&value.client)?;
    write_json(
        &paths.boltz_adapter_control(&value.client, "complete"),
        value,
    )
}

fn validate_boltz_adapter_client(client: &str) -> Result<(), String> {
    if matches!(client, "go" | "web") {
        Ok(())
    } else {
        Err("IMMORTAL_LAB_BOLTZ_ADAPTER_CLIENT must be go or web".to_owned())
    }
}

pub fn load_funded_journey_checkpoint(
    paths: &LabPaths,
    journey: &str,
) -> Result<Option<FundedCheckpoint>, String> {
    let path = paths.funded_journey_checkpoint(journey);
    if path.exists() {
        let checkpoint = read_json(&path)?;
        validate_funded_checkpoint(&checkpoint)?;
        Ok(Some(checkpoint))
    } else {
        Ok(None)
    }
}

fn validate_run_id(run_id: &str) -> Result<(), String> {
    if (1..=128).contains(&run_id.len())
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err("IMMORTAL_LAB_RUN_ID must be 1-128 ASCII letters, digits, '-' or '_'".to_owned())
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not a valid record: {error}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not serialize {}: {error}", path.display()))?;
    write_bytes(path, &bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    restrict_directory_permissions(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = open_private_file(&temporary)?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    file.sync_all()
        .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("could not commit {}: {error}", path.display()))?;
    restrict_permissions(path)
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn open_private_file(path: &Path) -> Result<fs::File, String> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| format!("could not open {}: {error}", path.display()))
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> LabPaths {
        let root = std::env::temp_dir().join(format!(
            "immortal-lab-state-test-{label}-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("stale scratch state should be removable");
        }
        LabPaths::new(root)
    }

    fn sample_session(session_id: &str, created_at: u64) -> SessionRecord {
        SessionRecord {
            session_id: session_id.to_owned(),
            created_at,
            relay_url: "ws://127.0.0.1:18080".to_owned(),
            swap_type: "submarine".to_owned(),
            provider_pubkey: "ab".repeat(32),
            offering_address: format!("39601:{}:lab", "ab".repeat(32)),
            step: "rfq_sent".to_owned(),
            rfq: None,
            quote: None,
            quote_wrap: None,
            quote_observed_at: None,
            verification: Some(serde_json::json!({"overall": "pending"})),
        }
    }

    #[test]
    fn identity_persists_and_reloads_the_same_signer() {
        let paths = scratch("identity");
        let created = load_or_create_identity(&paths).expect("identity should be created");
        let reloaded = load_or_create_identity(&paths).expect("identity should reload");
        assert_eq!(created, reloaded);
        assert_eq!(
            reloaded.signer().expect("signer should load").pubkey(),
            reloaded.pubkey
        );
        assert_eq!(reloaded.warning, IDENTITY_WARNING);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(paths.identity())
                .expect("identity metadata should exist")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "identity file must be mode 0600");
        }
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn session_record_round_trips_through_the_store() {
        let paths = scratch("session");
        let mut session = sample_session(&"11".repeat(32), 100);
        store_session(&paths, &session).expect("session should persist");
        let loaded = load_session(&paths, &session.session_id).expect("session should reload");
        assert_eq!(session, loaded);

        session.step = "quote_received".to_owned();
        session.verification = Some(serde_json::json!({"overall": "pass", "checks": []}));
        store_session(&paths, &session).expect("session update should persist");
        let updated =
            load_session(&paths, &session.session_id).expect("updated session should reload");
        assert_eq!(session, updated);
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn funded_checkpoint_is_private_and_round_trips() {
        let paths = scratch("funded-checkpoint");
        let checkpoint = FundedCheckpoint {
            schema: "openagents.immortal.lab-checkpoint.v1".to_owned(),
            run_id: "run-1".to_owned(),
            journey: "submarine".to_owned(),
            label: "funding_authorized".to_owned(),
            safe_to_stop: true,
            updated_at: 10,
            details: serde_json::json!({"order_id": "ab".repeat(32)}),
        };
        store_funded_checkpoint(&paths, &checkpoint).expect("checkpoint should persist");
        store_funded_journey_checkpoint(&paths, &checkpoint)
            .expect("journey checkpoint should persist");
        assert_eq!(
            load_funded_checkpoint(&paths).expect("checkpoint should load"),
            Some(checkpoint.clone())
        );
        assert_eq!(
            load_funded_journey_checkpoint(&paths, "submarine")
                .expect("journey checkpoint should load"),
            Some(checkpoint)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(paths.funded_checkpoint())
                .expect("checkpoint metadata should exist")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn funded_checkpoint_fixture_matches_the_persisted_schema() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/lab/funded-checkpoints-v1.json"
        ))
        .expect("funded checkpoint fixture should parse");
        assert_eq!(
            fixture.get("schema").and_then(Value::as_str),
            Some("openagents.immortal.lab-checkpoint-manifest.v2")
        );
        let forbidden = fixture
            .get("forbidden_checkpoint_members")
            .and_then(Value::as_array)
            .expect("fixture should name forbidden checkpoint members");
        let checkpoint = serde_json::to_value(FundedCheckpoint {
            schema: "openagents.immortal.lab-checkpoint.v1".to_owned(),
            run_id: "fixture".to_owned(),
            journey: "reverse".to_owned(),
            label: "funding_authorized".to_owned(),
            safe_to_stop: true,
            updated_at: 1,
            details: serde_json::json!({"session_id": "ab".repeat(32)}),
        })
        .expect("checkpoint should serialize");
        for member in forbidden {
            let member = member.as_str().expect("forbidden member should be text");
            assert!(checkpoint.get(member).is_none());
        }
    }

    #[test]
    fn funded_checkpoint_rejects_custody_material_recursively() {
        let paths = scratch("funded-checkpoint-custody");
        let checkpoint = FundedCheckpoint {
            schema: "openagents.immortal.lab-checkpoint.v1".to_owned(),
            run_id: "run-1".to_owned(),
            journey: "reverse".to_owned(),
            label: "funding_execution_ready".to_owned(),
            safe_to_stop: true,
            updated_at: 10,
            details: serde_json::json!({"nested": {"preimage": "00".repeat(32)}}),
        };
        let error = store_funded_checkpoint(&paths, &checkpoint)
            .expect_err("custody-bearing checkpoint must fail closed");
        assert!(error.contains("swp_secret_material_forbidden"));
        assert!(!paths.funded_checkpoint().exists());
        if paths.root().exists() {
            fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
        }
    }

    #[test]
    fn signed_exit_round_trips_as_a_private_bounded_artifact() {
        let paths = scratch("funded-signed-exit");
        let transaction = "00".repeat(64);
        store_funded_signed_exit(&paths, "reverse", &transaction)
            .expect("signed exit should persist");
        assert_eq!(
            load_funded_signed_exit(&paths, "reverse").expect("signed exit should load"),
            transaction
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(paths.funded_signed_exit("reverse"))
                .expect("signed exit metadata should exist")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn funded_delivery_provenance_round_trips_without_custody_material() {
        let paths = scratch("funded-deliveries");
        let archive = serde_json::json!([{
            "event_id":"11".repeat(32),
            "raw_signed_event":[123,125],
            "raw_wrap_event":null,
            "wrap_event_id":null,
            "sender_pubkey":"22".repeat(32),
            "observed_at":10,
            "provenance":"locally_signed"
        }]);
        store_funded_deliveries(&paths, "submarine", &archive)
            .expect("delivery provenance should persist");
        assert_eq!(
            load_funded_deliveries(&paths, "submarine").expect("delivery provenance should load"),
            Some(archive)
        );
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn discovery_round_trips_and_sessions_list_in_creation_order() {
        let paths = scratch("discovery");
        let discovery = Discovery {
            relay_url: "ws://127.0.0.1:18080".to_owned(),
            discovered_at: 7,
            providers: vec![DiscoveredProvider {
                pubkey: "cd".repeat(32),
                profile_event_id: "ef".repeat(32),
                status: "active".to_owned(),
                offerings: vec![DiscoveredOffering {
                    address: format!("39601:{}:lab", "cd".repeat(32)),
                    distinct: "lab".to_owned(),
                    status: "active".to_owned(),
                    event_id: "01".repeat(32),
                }],
            }],
        };
        store_discovery(&paths, &discovery).expect("discovery should persist");
        assert_eq!(
            load_discovery(&paths).expect("discovery should reload"),
            discovery
        );

        store_session(&paths, &sample_session(&"22".repeat(32), 200))
            .expect("later session should persist");
        store_session(&paths, &sample_session(&"33".repeat(32), 150))
            .expect("earlier session should persist");
        let sessions = list_sessions(&paths).expect("sessions should list");
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.created_at)
                .collect::<Vec<_>>(),
            vec![150, 200]
        );
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }

    #[test]
    fn current_session_pointer_round_trips() {
        let paths = scratch("pointer");
        let session_id = "44".repeat(32);
        set_current_session(&paths, &session_id).expect("pointer should persist");
        // Note: resolve_session_id consults IMMORTAL_LAB_SESSION first; tests
        // rely on the harness never setting it globally.
        if std::env::var("IMMORTAL_LAB_SESSION").is_err() {
            assert_eq!(
                resolve_session_id(&paths).expect("pointer should resolve"),
                session_id
            );
        }
        fs::remove_dir_all(paths.root()).expect("scratch state should be removable");
    }
}
