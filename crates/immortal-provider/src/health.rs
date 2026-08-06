use serde::Serialize;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::timeout,
};

pub(crate) const MAX_HEALTH_CONNECTIONS: usize = 16;
pub(crate) const MAX_HTTP_REQUEST_BYTES: usize = 4_096;
pub(crate) const MAX_ALERT_RESPONSE_BYTES: usize = 64 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthError {
    InvalidAlertEndpoint,
    Bind,
    Accept,
    Io,
    Timeout,
    ResponseTooLarge,
    AlertStatus(u16),
}

impl fmt::Display for HealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlertEndpoint => formatter
                .write_str("alert URL must be bounded plaintext HTTP on a private numeric address"),
            Self::Bind => formatter.write_str("provider health endpoint could not bind"),
            Self::Accept => formatter.write_str("provider health endpoint could not accept"),
            Self::Io => formatter.write_str("provider operational HTTP I/O failed"),
            Self::Timeout => formatter.write_str("provider operational HTTP timed out"),
            Self::ResponseTooLarge => {
                formatter.write_str("provider alert response exceeded its byte bound")
            }
            Self::AlertStatus(status) => {
                write!(
                    formatter,
                    "provider alert endpoint returned HTTP status {status}"
                )
            }
        }
    }
}

impl std::error::Error for HealthError {}

#[derive(Default)]
pub struct ProviderHealth {
    ready: AtomicBool,
    draining: AtomicBool,
    active_sessions: AtomicU64,
    chain_height: AtomicI64,
    last_chain_success: AtomicU64,
    consecutive_chain_failures: AtomicU32,
    active_reservations: AtomicU64,
    pending_effects: AtomicU64,
    unresolved_effects: AtomicU64,
    pending_watch_jobs: AtomicU64,
    unresolved_watch_jobs: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderHealthSnapshot {
    pub ready: bool,
    pub draining: bool,
    pub active_sessions: u64,
    pub chain_height: i64,
    pub last_chain_success: u64,
    pub consecutive_chain_failures: u32,
    pub active_reservations: u64,
    pub pending_effects: u64,
    pub unresolved_effects: u64,
    pub pending_watch_jobs: u64,
    pub unresolved_watch_jobs: u64,
}

impl ProviderHealth {
    pub fn mark_ready(&self) {
        if !self.is_draining() {
            self.ready.store(true, Ordering::Release);
        }
    }

    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
        self.mark_not_ready();
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn set_active_sessions(&self, active_sessions: usize) -> Result<(), HealthError> {
        let active_sessions = u64::try_from(active_sessions).map_err(|_| HealthError::Io)?;
        self.active_sessions
            .store(active_sessions, Ordering::Release);
        Ok(())
    }

    pub fn record_chain_success(&self, height: i64, observed_at: u64) {
        self.chain_height.store(height, Ordering::Release);
        self.last_chain_success
            .store(observed_at, Ordering::Release);
        self.consecutive_chain_failures.store(0, Ordering::Release);
    }

    pub fn record_chain_failure(&self) -> u32 {
        self.consecutive_chain_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    pub fn set_ledger_counts(
        &self,
        reservations: u64,
        pending_effects: u64,
        unresolved_effects: u64,
        pending_watch_jobs: u64,
        unresolved_watch_jobs: u64,
    ) {
        self.active_reservations
            .store(reservations, Ordering::Release);
        self.pending_effects
            .store(pending_effects, Ordering::Release);
        self.unresolved_effects
            .store(unresolved_effects, Ordering::Release);
        self.pending_watch_jobs
            .store(pending_watch_jobs, Ordering::Release);
        self.unresolved_watch_jobs
            .store(unresolved_watch_jobs, Ordering::Release);
    }

    pub fn snapshot(&self) -> ProviderHealthSnapshot {
        ProviderHealthSnapshot {
            ready: self.ready.load(Ordering::Acquire),
            draining: self.draining.load(Ordering::Acquire),
            active_sessions: self.active_sessions.load(Ordering::Acquire),
            chain_height: self.chain_height.load(Ordering::Acquire),
            last_chain_success: self.last_chain_success.load(Ordering::Acquire),
            consecutive_chain_failures: self.consecutive_chain_failures.load(Ordering::Acquire),
            active_reservations: self.active_reservations.load(Ordering::Acquire),
            pending_effects: self.pending_effects.load(Ordering::Acquire),
            unresolved_effects: self.unresolved_effects.load(Ordering::Acquire),
            pending_watch_jobs: self.pending_watch_jobs.load(Ordering::Acquire),
            unresolved_watch_jobs: self.unresolved_watch_jobs.load(Ordering::Acquire),
        }
    }
}

impl ProviderHealthSnapshot {
    fn health_body(self) -> &'static str {
        if self.ready
            && !self.draining
            && self.pending_effects == 0
            && self.unresolved_effects == 0
            && self.unresolved_watch_jobs == 0
        {
            "ready\n"
        } else {
            "not ready\n"
        }
    }

    fn health_status(self) -> &'static str {
        if self.ready
            && !self.draining
            && self.pending_effects == 0
            && self.unresolved_effects == 0
            && self.unresolved_watch_jobs == 0
        {
            "200 OK"
        } else {
            "503 Service Unavailable"
        }
    }

    fn metrics(self) -> String {
        format!(
            concat!(
                "immortal_provider_ready {}\n",
                "immortal_provider_draining {}\n",
                "immortal_provider_sessions_active {}\n",
                "immortal_provider_chain_height {}\n",
                "immortal_provider_last_chain_success_seconds {}\n",
                "immortal_provider_chain_failures_consecutive {}\n",
                "immortal_provider_reservations_active {}\n",
                "immortal_provider_effects_pending {}\n",
                "immortal_provider_effects_unresolved {}\n",
                "immortal_provider_watch_jobs_pending {}\n",
                "immortal_provider_watch_jobs_unresolved {}\n"
            ),
            u8::from(self.ready),
            u8::from(self.draining),
            self.active_sessions,
            self.chain_height,
            self.last_chain_success,
            self.consecutive_chain_failures,
            self.active_reservations,
            self.pending_effects,
            self.unresolved_effects,
            self.pending_watch_jobs,
            self.unresolved_watch_jobs,
        )
    }
}

pub async fn serve_health(
    bind: SocketAddr,
    health: Arc<ProviderHealth>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), HealthError> {
    if !private_or_loopback(bind.ip()) {
        return Err(HealthError::Bind);
    }
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| HealthError::Bind)?;
    let permits = Arc::new(Semaphore::new(MAX_HEALTH_CONNECTIONS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|_| HealthError::Accept)?;
                if !private_or_loopback(peer.ip()) {
                    continue;
                }
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let health = health.clone();
                drop(tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_health_connection(stream, &health).await {
                        eprintln!("immortal-provider: health request failed: {error}");
                    }
                }));
            }
        }
    }
}

async fn handle_health_connection(
    mut stream: TcpStream,
    health: &ProviderHealth,
) -> Result<(), HealthError> {
    let mut request = [0_u8; MAX_HTTP_REQUEST_BYTES];
    let read = timeout(HTTP_TIMEOUT, stream.read(&mut request))
        .await
        .map_err(|_| HealthError::Timeout)?
        .map_err(|_| HealthError::Io)?;
    let first_line = request
        .get(..read)
        .and_then(|bytes| bytes.split(|byte| *byte == b'\n').next())
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim_end)
        .unwrap_or("");
    let snapshot = health.snapshot();
    let (status, content_type, body) = match first_line {
        "GET /healthz HTTP/1.0" | "GET /healthz HTTP/1.1" => (
            snapshot.health_status(),
            "text/plain; charset=utf-8",
            snapshot.health_body().to_owned(),
        ),
        "GET /metrics HTTP/1.0" | "GET /metrics HTTP/1.1" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            snapshot.metrics(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_owned(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(HTTP_TIMEOUT, stream.write_all(response.as_bytes()))
        .await
        .map_err(|_| HealthError::Timeout)?
        .map_err(|_| HealthError::Io)?;
    stream.shutdown().await.map_err(|_| HealthError::Io)
}

#[derive(Clone, PartialEq, Eq)]
pub struct AlertEndpoint {
    address: SocketAddr,
    authority: String,
    path: String,
}

impl fmt::Debug for AlertEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlertEndpoint")
            .field("address", &self.address)
            .field("path", &self.path)
            .finish()
    }
}

impl AlertEndpoint {
    pub fn parse(url: String) -> Result<Self, HealthError> {
        if url.len() > 2_048 || !url.starts_with("http://") {
            return Err(HealthError::InvalidAlertEndpoint);
        }
        let remainder = url
            .strip_prefix("http://")
            .ok_or(HealthError::InvalidAlertEndpoint)?;
        let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
        if authority.is_empty()
            || authority.contains('@')
            || path.contains(['?', '#'])
            || path.as_bytes().iter().any(u8::is_ascii_control)
        {
            return Err(HealthError::InvalidAlertEndpoint);
        }
        let address = parse_numeric_authority(authority)?;
        if !private_or_loopback(address.ip()) {
            return Err(HealthError::InvalidAlertEndpoint);
        }
        Ok(Self {
            address,
            authority: authority.to_owned(),
            path: format!("/{path}"),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAlert<'a> {
    pub schema: &'static str,
    pub alert_type: &'a str,
    pub session_id: Option<&'a str>,
    pub observed_at: u64,
    pub detail: &'a str,
}

impl<'a> ProviderAlert<'a> {
    pub fn new(
        alert_type: &'a str,
        session_id: Option<&'a str>,
        observed_at: u64,
        detail: &'a str,
    ) -> Self {
        Self {
            schema: "openagents.immortal.provider-alert.v1",
            alert_type,
            session_id,
            observed_at,
            detail,
        }
    }
}

pub async fn send_alert(
    endpoint: &AlertEndpoint,
    alert: &ProviderAlert<'_>,
) -> Result<(), HealthError> {
    let body = serde_json::to_vec(alert).map_err(|_| HealthError::Io)?;
    let mut stream = timeout(HTTP_TIMEOUT, TcpStream::connect(endpoint.address))
        .await
        .map_err(|_| HealthError::Timeout)?
        .map_err(|_| HealthError::Io)?;
    let peer = stream.peer_addr().map_err(|_| HealthError::Io)?;
    if peer != endpoint.address || !private_or_loopback(peer.ip()) {
        return Err(HealthError::InvalidAlertEndpoint);
    }
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    );
    timeout(HTTP_TIMEOUT, async {
        stream.write_all(request.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| HealthError::Timeout)?
    .map_err(|_| HealthError::Io)?;

    let mut response = Vec::with_capacity(1_024);
    let mut chunk = [0_u8; 1_024];
    loop {
        let read = timeout(HTTP_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| HealthError::Timeout)?
            .map_err(|_| HealthError::Io)?;
        if read == 0 {
            break;
        }
        if response.len().saturating_add(read) > MAX_ALERT_RESPONSE_BYTES {
            return Err(HealthError::ResponseTooLarge);
        }
        response.extend_from_slice(&chunk[..read]);
    }
    let status = parse_http_status(&response)?;
    if !(200..300).contains(&status) {
        return Err(HealthError::AlertStatus(status));
    }
    Ok(())
}

fn parse_numeric_authority(authority: &str) -> Result<SocketAddr, HealthError> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Ok(address);
    }
    let ip = authority
        .parse::<IpAddr>()
        .map_err(|_| HealthError::InvalidAlertEndpoint)?;
    Ok(SocketAddr::new(ip, 80))
}

fn parse_http_status(response: &[u8]) -> Result<u16, HealthError> {
    let line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or(HealthError::Io)?;
    let mut fields = line.split_ascii_whitespace();
    match (fields.next(), fields.next()) {
        (Some("HTTP/1.0" | "HTTP/1.1"), Some(status)) => {
            status.parse::<u16>().map_err(|_| HealthError::Io)
        }
        _ => Err(HealthError::Io),
    }
}

pub fn private_or_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.octets()[..2] == [169, 254]
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn operational_addresses_are_private() {
        assert!(private_or_loopback(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST
        )));
        assert!(private_or_loopback(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!private_or_loopback(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(AlertEndpoint::parse("http://127.0.0.1:9000/page".to_owned()).is_ok());
        assert!(AlertEndpoint::parse("https://127.0.0.1/page".to_owned()).is_err());
        assert!(AlertEndpoint::parse("http://8.8.8.8/page".to_owned()).is_err());
        assert!(AlertEndpoint::parse("http://localhost/page".to_owned()).is_err());
    }

    #[test]
    fn health_becomes_unready_for_unresolved_money() {
        let health = ProviderHealth::default();
        assert_eq!(health.snapshot().health_status(), "503 Service Unavailable");
        health.mark_ready();
        assert_eq!(health.snapshot().health_status(), "200 OK");
        health.set_active_sessions(2).unwrap();
        assert_eq!(health.snapshot().active_sessions, 2);
        health.begin_drain();
        assert_eq!(health.snapshot().health_status(), "503 Service Unavailable");
        assert!(health.snapshot().draining);
        assert!(!health.snapshot().ready);
        health.draining.store(false, Ordering::Release);
        health.mark_ready();
        health.set_ledger_counts(1, 0, 0, 0, 1);
        assert_eq!(health.snapshot().health_status(), "503 Service Unavailable");
        health.set_ledger_counts(1, 1, 0, 0, 0);
        assert_eq!(health.snapshot().health_status(), "503 Service Unavailable");
    }

    #[test]
    fn metrics_have_fixed_names_and_no_labels() {
        let health = ProviderHealth::default();
        health.record_chain_success(101, 1_700_000_000);
        let metrics = health.snapshot().metrics();
        assert!(metrics.contains("immortal_provider_chain_height 101\n"));
        assert!(!metrics.contains('{'));
    }
}
