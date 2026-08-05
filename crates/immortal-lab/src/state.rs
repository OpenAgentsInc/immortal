//! Persisted lab state: identity, discovery snapshot, and session records.
//!
//! Every record is a plain JSON file under one state directory so a killed
//! harness can be restarted and resume from persisted records (the substrate
//! for the #18 doomsday drill). Writes are temp-file-plus-rename so a crash
//! mid-write never leaves a torn record.

use std::{
    fs,
    path::{Path, PathBuf},
};

use immortal_client::{domain::Event, market::MarketSigner};
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
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("could not commit {}: {error}", path.display()))
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
