use std::{env, net::SocketAddr, str::FromStr, time::Duration};

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
    pub req_per_minute_ip: u32,
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
            req_per_minute_ip: 120,
            max_connections_per_ip: 20,
            send_queue_capacity: 256,
        }
    }
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
    pub trust_proxy: bool,
    pub db_connections: usize,
    pub shutdown_grace: Duration,
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
            trust_proxy: false,
            db_connections: 4,
            shutdown_grace: Duration::from_secs(10),
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
        config.trust_proxy = parse_bool("IMMORTAL_TRUST_PROXY", false)?;
        config.db_connections = parse_or("IMMORTAL_DB_CONNECTIONS", "4")?;
        config.shutdown_grace =
            Duration::from_secs(parse_or("IMMORTAL_SHUTDOWN_GRACE_SECONDS", "10")?);
        config.limits = GatewayLimits {
            max_frame_bytes: parse_or("IMMORTAL_MAX_FRAME_BYTES", "131072")?,
            max_subscriptions: parse_or("IMMORTAL_MAX_SUBSCRIPTIONS", "32")?,
            max_filters: parse_or("IMMORTAL_MAX_FILTERS", "16")?,
            max_limit: parse_or("IMMORTAL_MAX_LIMIT", "1000")?,
            max_query_cost: parse_or("IMMORTAL_MAX_QUERY_COST", "100000")?,
            events_per_minute_ip: parse_or("IMMORTAL_RATE_EVENTS_PER_MIN_IP", "120")?,
            events_per_minute_pubkey: parse_or("IMMORTAL_RATE_EVENTS_PER_MIN_PUBKEY", "60")?,
            req_per_minute_ip: parse_or("IMMORTAL_RATE_REQ_PER_MIN_IP", "120")?,
            max_connections_per_ip: parse_or("IMMORTAL_MAX_CONNECTIONS_PER_IP", "20")?,
            send_queue_capacity: parse_or("IMMORTAL_SEND_QUEUE_CAPACITY", "256")?,
        };
        config.identity = RelayIdentity {
            name: env::var("IMMORTAL_RELAY_NAME").unwrap_or_else(|_| "immortal".to_owned()),
            description: optional_string("IMMORTAL_RELAY_DESCRIPTION")?,
            contact: optional_string("IMMORTAL_RELAY_CONTACT")?,
            pubkey: optional_string("IMMORTAL_RELAY_PUBKEY")?,
        };
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
                "IMMORTAL_RATE_REQ_PER_MIN_IP",
                self.limits.req_per_minute_ip,
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
        if let Some(pubkey) = &self.identity.pubkey
            && (pubkey.len() != 64 || !is_lower_hex(pubkey))
        {
            return Err(config(
                "IMMORTAL_RELAY_PUBKEY must be 64 lowercase hexadecimal characters",
            ));
        }
        if let Some(relay_url) = &self.relay_url
            && (!relay_url.starts_with("ws://") && !relay_url.starts_with("wss://")
                || relay_url.len() > 2_048
                || relay_url.chars().any(char::is_whitespace))
        {
            return Err(config(
                "IMMORTAL_RELAY_URL must be a valid ws:// or wss:// URL",
            ));
        }
        if self.auth_required && self.relay_url.is_none() {
            return Err(config(
                "IMMORTAL_RELAY_URL is required when IMMORTAL_AUTH_REQUIRED is true",
            ));
        }
        if !matches!(self.log_level.as_str(), "error" | "warn" | "info" | "debug") {
            return Err(config(
                "IMMORTAL_LOG_LEVEL must be error, warn, info, or debug",
            ));
        }
        Ok(())
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
