use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use crate::domain::RelaySigner;

use super::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayLimits {
    pub max_frame_bytes: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_limit: usize,
    pub max_query_cost: usize,
    pub events_per_minute_ip: u32,
    pub events_per_minute_pubkey: u32,
    pub observer_events_per_second_ip: u32,
    pub observer_events_per_second_agent: u32,
    pub req_per_minute_ip: u32,
    pub media_per_minute_ip: u32,
    pub media_per_minute_pubkey: u32,
    pub max_connections_per_ip: usize,
    pub send_queue_capacity: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 131_072,
            max_subscriptions: 32,
            max_filters: 16,
            max_limit: 1_000,
            max_query_cost: 100_000,
            events_per_minute_ip: 120,
            events_per_minute_pubkey: 60,
            observer_events_per_second_ip: 200,
            observer_events_per_second_agent: 100,
            req_per_minute_ip: 120,
            media_per_minute_ip: 30,
            media_per_minute_pubkey: 15,
            max_connections_per_ip: 20,
            send_queue_capacity: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaConfig {
    pub root: PathBuf,
    pub cloud_base_url: Option<String>,
    pub max_blob_bytes: usize,
    pub max_bytes_per_pubkey: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIdentity {
    pub name: String,
    pub description: Option<String>,
    pub contact: Option<String>,
    pub pubkey: Option<String>,
}

impl Default for RelayIdentity {
    fn default() -> Self {
        Self {
            name: "immortal".to_owned(),
            description: None,
            contact: None,
            pubkey: None,
        }
    }
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub relay_url: Option<String>,
    pub auth_required: bool,
    pub management_pubkey: Option<String>,
    pub relay_signer: Option<RelaySigner>,
    pub trust_proxy: bool,
    pub db_connections: usize,
    pub shutdown_grace: Duration,
    pub expiration_sweep: Duration,
    pub import_nostr_effect: bool,
    pub legacy_import_sweep: Duration,
    pub media: Option<MediaConfig>,
    pub limits: GatewayLimits,
    pub identity: RelayIdentity,
    pub log_level: String,
}

impl GatewayConfig {
    pub fn new(database_url: String, bind_addr: SocketAddr) -> Self {
        Self {
            database_url,
            bind_addr,
            relay_url: None,
            auth_required: false,
            management_pubkey: None,
            relay_signer: None,
            trust_proxy: false,
            db_connections: 4,
            shutdown_grace: Duration::from_secs(10),
            expiration_sweep: Duration::from_secs(60),
            import_nostr_effect: false,
            legacy_import_sweep: Duration::from_secs(10),
            media: None,
            limits: GatewayLimits::default(),
            identity: RelayIdentity::default(),
            log_level: "info".to_owned(),
        }
    }

    pub fn from_env() -> Result<Self, GatewayError> {
        let database_url = database_config_from_env()?;
        let bind_ip = parse_or("IMMORTAL_BIND_ADDR", "127.0.0.1")?;
        let port = match env::var("PORT") {
            Ok(value) => parse_value("PORT", &value)?,
            Err(env::VarError::NotPresent) => parse_or("IMMORTAL_PORT", "8080")?,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(config("PORT is not valid UTF-8"));
            }
        };
        let mut config = Self::new(database_url, SocketAddr::new(bind_ip, port));
        config.relay_url = optional_string("IMMORTAL_RELAY_URL")?;
        config.auth_required = parse_bool("IMMORTAL_AUTH_REQUIRED", false)?;
        config.management_pubkey = optional_string("IMMORTAL_MANAGEMENT_PUBKEY")?;
        config.relay_signer = optional_string("IMMORTAL_RELAY_SECRET_KEY")?
            .map(|secret| RelaySigner::from_secret_hex(&secret))
            .transpose()
            .map_err(|error| GatewayError::Config(error.to_string()))?;
        config.trust_proxy = parse_bool("IMMORTAL_TRUST_PROXY", false)?;
        config.db_connections = parse_or("IMMORTAL_DB_CONNECTIONS", "4")?;
        config.shutdown_grace =
            Duration::from_secs(parse_or("IMMORTAL_SHUTDOWN_GRACE_SECONDS", "10")?);
        config.expiration_sweep =
            Duration::from_secs(parse_or("IMMORTAL_EXPIRATION_SWEEP_SECONDS", "60")?);
        config.import_nostr_effect = parse_bool("IMMORTAL_IMPORT_NOSTR_EFFECT", false)?;
        config.legacy_import_sweep =
            Duration::from_secs(parse_or("IMMORTAL_LEGACY_IMPORT_SWEEP_SECONDS", "10")?);
        let media_root = optional_string("IMMORTAL_MEDIA_ROOT")?;
        let cloud_base_url = optional_string("IMMORTAL_MEDIA_CLOUD_BASE_URL")?;
        let max_blob_bytes = parse_or("IMMORTAL_MEDIA_MAX_BLOB_BYTES", "10485760")?;
        let max_bytes_per_pubkey = parse_or("IMMORTAL_MEDIA_MAX_BYTES_PER_PUBKEY", "1073741824")?;
        config.media = match media_root {
            Some(root) => Some(MediaConfig {
                root: PathBuf::from(root),
                cloud_base_url,
                max_blob_bytes,
                max_bytes_per_pubkey,
            }),
            None if cloud_base_url.is_some() => {
                return Err(GatewayError::Config(
                    "IMMORTAL_MEDIA_ROOT is required with IMMORTAL_MEDIA_CLOUD_BASE_URL".to_owned(),
                ));
            }
            None => None,
        };
        config.limits = GatewayLimits {
            max_frame_bytes: parse_or("IMMORTAL_MAX_FRAME_BYTES", "131072")?,
            max_subscriptions: parse_or("IMMORTAL_MAX_SUBSCRIPTIONS", "32")?,
            max_filters: parse_or("IMMORTAL_MAX_FILTERS", "16")?,
            max_limit: parse_or("IMMORTAL_MAX_LIMIT", "1000")?,
            max_query_cost: parse_or("IMMORTAL_MAX_QUERY_COST", "100000")?,
            events_per_minute_ip: parse_or("IMMORTAL_RATE_EVENTS_PER_MIN_IP", "120")?,
            events_per_minute_pubkey: parse_or("IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY", "60")?,
            observer_events_per_second_ip: parse_or("IMMORTAL_RATE_OBSERVER_PER_SEC_IP", "200")?,
            observer_events_per_second_agent: parse_or(
                "IMMORTAL_RATE_OBSERVER_PER_SEC_AGENT",
                "100",
            )?,
            req_per_minute_ip: parse_or("IMMORTAL_RATE_REQ_PER_MIN_IP", "120")?,
            media_per_minute_ip: parse_or("IMMORTAL_RATE_MEDIA_PER_MIN_IP", "30")?,
            media_per_minute_pubkey: parse_or("IMMORTAL_RATE_MEDIA_PER_MIN_PUBKEY", "15")?,
            max_connections_per_ip: parse_or("IMMORTAL_MAX_CONNECTIONS_PER_IP", "20")?,
            send_queue_capacity: parse_or("IMMORTAL_SEND_QUEUE_CAPACITY", "256")?,
        };
        config.identity = RelayIdentity {
            name: env::var("IMMORTAL_RELAY_NAME").unwrap_or_else(|_| "immortal".to_owned()),
            description: optional_string("IMMORTAL_RELAY_DESCRIPTION")?,
            contact: optional_string("IMMORTAL_RELAY_CONTACT")?,
            pubkey: optional_string("IMMORTAL_RELAY_PUBKEY")?,
        };
        if let Some(signer) = &config.relay_signer {
            if config
                .identity
                .pubkey
                .as_ref()
                .is_some_and(|pubkey| pubkey != signer.pubkey())
            {
                return Err(GatewayError::Config(
                    "IMMORTAL_RELAY_PUBKEY does not match IMMORTAL_RELAY_SECRET_KEY".to_owned(),
                ));
            }
            config.identity.pubkey = Some(signer.pubkey().to_owned());
        }
        config.log_level = env::var("IMMORTAL_LOG_LEVEL").unwrap_or_else(|_| "info".to_owned());
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), GatewayError> {
        if self.database_url.trim().is_empty() {
            return Err(config("database connection settings are empty"));
        }
        if !(1..=64).contains(&self.db_connections) {
            return Err(config("IMMORTAL_DB_CONNECTIONS must be between 1 and 64"));
        }
        if self.shutdown_grace.is_zero() {
            return Err(config("IMMORTAL_SHUTDOWN_GRACE_SECONDS must be positive"));
        }
        if self.expiration_sweep.is_zero() || self.expiration_sweep > Duration::from_secs(86_400) {
            return Err(config(
                "IMMORTAL_EXPIRATION_SWEEP_SECONDS must be between 1 and 86400",
            ));
        }
        if self.legacy_import_sweep.is_zero()
            || self.legacy_import_sweep > Duration::from_secs(3_600)
        {
            return Err(config(
                "IMMORTAL_LEGACY_IMPORT_SWEEP_SECONDS must be between 1 and 3600",
            ));
        }
        if !(1_024..=16_777_216).contains(&self.limits.max_frame_bytes) {
            return Err(config(
                "IMMORTAL_MAX_FRAME_BYTES must be between 1024 and 16777216",
            ));
        }
        for (name, value, maximum) in [
            (
                "IMMORTAL_MAX_SUBSCRIPTIONS",
                self.limits.max_subscriptions,
                1_024,
            ),
            ("IMMORTAL_MAX_FILTERS", self.limits.max_filters, 256),
            ("IMMORTAL_MAX_LIMIT", self.limits.max_limit, 100_000),
            (
                "IMMORTAL_MAX_QUERY_COST",
                self.limits.max_query_cost,
                1_000_000_000,
            ),
            (
                "IMMORTAL_MAX_CONNECTIONS_PER_IP",
                self.limits.max_connections_per_ip,
                4_096,
            ),
            (
                "IMMORTAL_SEND_QUEUE_CAPACITY",
                self.limits.send_queue_capacity,
                65_536,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(config(format!("{name} must be between 1 and {maximum}")));
            }
        }
        if self.limits.send_queue_capacity < 8 {
            return Err(config("IMMORTAL_SEND_QUEUE_CAPACITY must be at least 8"));
        }
        for (name, value) in [
            (
                "IMMORTAL_RATE_EVENTS_PER_MIN_IP",
                self.limits.events_per_minute_ip,
            ),
            (
                "IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY",
                self.limits.events_per_minute_pubkey,
            ),
            (
                "IMMORTAL_RATE_OBSERVER_PER_SEC_IP",
                self.limits.observer_events_per_second_ip,
            ),
            (
                "IMMORTAL_RATE_OBSERVER_PER_SEC_AGENT",
                self.limits.observer_events_per_second_agent,
            ),
            (
                "IMMORTAL_RATE_REQ_PER_MIN_IP",
                self.limits.req_per_minute_ip,
            ),
            (
                "IMMORTAL_RATE_MEDIA_PER_MIN_IP",
                self.limits.media_per_minute_ip,
            ),
            (
                "IMMORTAL_RATE_MEDIA_PER_MIN_PUBKEY",
                self.limits.media_per_minute_pubkey,
            ),
        ] {
            if value == 0 {
                return Err(config(format!("{name} must be positive")));
            }
        }
        if self.identity.name.is_empty() || self.identity.name.chars().count() > 128 {
            return Err(config(
                "IMMORTAL_RELAY_NAME must contain 1 to 128 characters",
            ));
        }
        if self
            .identity
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 16_384)
            || self
                .identity
                .contact
                .as_ref()
                .is_some_and(|value| value.len() > 2_048)
        {
            return Err(config("relay identity field exceeds its configured bound"));
        }
        if let Some(pubkey) = &self.identity.pubkey {
            if pubkey.len() != 64 || !is_lower_hex(pubkey) {
                return Err(config(
                    "IMMORTAL_RELAY_PUBKEY must be 64 lowercase hexadecimal characters",
                ));
            }
        }
        if let Some(pubkey) = &self.management_pubkey {
            if pubkey.len() != 64 || !is_lower_hex(pubkey) {
                return Err(config(
                    "IMMORTAL_MANAGEMENT_PUBKEY must be 64 lowercase hexadecimal characters",
                ));
            }
            if self.relay_url.is_none() {
                return Err(config(
                    "IMMORTAL_RELAY_URL is required when management is enabled",
                ));
            }
        }
        if let Some(relay_url) = &self.relay_url {
            if !relay_url.starts_with("ws://") && !relay_url.starts_with("wss://")
                || relay_url.len() > 2_048
                || relay_url.chars().any(char::is_whitespace)
            {
                return Err(config(
                    "IMMORTAL_RELAY_URL must be a valid ws:// or wss:// URL",
                ));
            }
        }
        if self.auth_required && self.relay_url.is_none() {
            return Err(config(
                "IMMORTAL_RELAY_URL is required when IMMORTAL_AUTH_REQUIRED is true",
            ));
        }
        if let Some(media) = &self.media {
            if !media.root.is_absolute() {
                return Err(config("IMMORTAL_MEDIA_ROOT must be an absolute path"));
            }
            if self.relay_url.is_none() {
                return Err(config(
                    "IMMORTAL_RELAY_URL is required when media storage is enabled",
                ));
            }
            if !(1_024..=1_073_741_824).contains(&media.max_blob_bytes) {
                return Err(config(
                    "IMMORTAL_MEDIA_MAX_BLOB_BYTES must be between 1024 and 1073741824",
                ));
            }
            if media.max_bytes_per_pubkey < media.max_blob_bytes as u64
                || media.max_bytes_per_pubkey > 1_099_511_627_776
            {
                return Err(config(
                    "IMMORTAL_MEDIA_MAX_BYTES_PER_PUBKEY must be at least the blob limit and at most 1099511627776",
                ));
            }
            if let Some(base) = &media.cloud_base_url {
                let authority = base
                    .strip_prefix("http://")
                    .or_else(|| base.strip_prefix("https://"))
                    .and_then(|rest| rest.split('/').next());
                if authority.is_none_or(str::is_empty)
                    || base.len() > 2_048
                    || base.chars().any(char::is_whitespace)
                    || base.contains('?')
                    || base.contains('#')
                {
                    return Err(config(
                        "IMMORTAL_MEDIA_CLOUD_BASE_URL must be a valid http:// or https:// base URL",
                    ));
                }
            }
        }
        if !matches!(self.log_level.as_str(), "error" | "warn" | "info" | "debug") {
            return Err(config(
                "IMMORTAL_LOG_LEVEL must be error, warn, info, or debug",
            ));
        }
        Ok(())
    }

    pub(crate) fn absolute_http_url(&self, path: &str) -> Result<String, GatewayError> {
        let relay_url = self
            .relay_url
            .as_deref()
            .ok_or_else(|| GatewayError::Config("public relay URL is missing".into()))?;
        let http_url = relay_url
            .strip_prefix("wss://")
            .map(|rest| format!("https://{rest}"))
            .or_else(|| {
                relay_url
                    .strip_prefix("ws://")
                    .map(|rest| format!("http://{rest}"))
            })
            .ok_or_else(|| GatewayError::Config("invalid public relay URL".into()))?;
        let scheme_end = http_url.find("://").unwrap_or(0) + 3;
        let authority_end = http_url[scheme_end..]
            .find('/')
            .map(|offset| offset + scheme_end)
            .unwrap_or(http_url.len());
        Ok(format!("{}{}", &http_url[..authority_end], path))
    }
}

fn database_config_from_env() -> Result<String, GatewayError> {
    match env::var("DATABASE_URL") {
        Ok(value) if !value.trim().is_empty() => return Ok(value),
        Ok(_) => return Err(config("DATABASE_URL is empty")),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(config("DATABASE_URL is not valid UTF-8"));
        }
        Err(env::VarError::NotPresent) => {}
    }

    let mut fields = Vec::new();
    for (variable, keyword) in [
        ("PGHOST", "host"),
        ("PGPORT", "port"),
        ("PGUSER", "user"),
        ("PGPASSWORD", "password"),
        ("PGDATABASE", "dbname"),
    ] {
        match env::var(variable) {
            Ok(value) => fields.push(format!("{keyword}={}", quote_pg_value(&value))),
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(config(format!("{variable} is not valid UTF-8")));
            }
        }
    }
    if fields.is_empty() {
        return Err(config(
            "set DATABASE_URL or at least one libpq-style PG environment variable",
        ));
    }
    Ok(fields.join(" "))
}

fn quote_pg_value(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

fn optional_string(name: &str) -> Result<Option<String>, GatewayError> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(config(format!("{name} is not valid UTF-8"))),
    }
}

fn parse_bool(name: &str, default: bool) -> Result<bool, GatewayError> {
    match env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => Err(config(format!("{name} must be true or false"))),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(config(format!("{name} is not valid UTF-8"))),
    }
}

fn parse_or<T>(name: &str, default: &str) -> Result<T, GatewayError>
where
    T: FromStr,
{
    match env::var(name) {
        Ok(value) => parse_value(name, &value),
        Err(env::VarError::NotPresent) => parse_value(name, default),
        Err(env::VarError::NotUnicode(_)) => Err(config(format!("{name} is not valid UTF-8"))),
    }
}

fn parse_value<T>(name: &str, value: &str) -> Result<T, GatewayError>
where
    T: FromStr,
{
    value
        .parse()
        .map_err(|_| config(format!("{name} has invalid value {value:?}")))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn config(reason: impl Into<String>) -> GatewayError {
    GatewayError::Config(reason.into())
}
