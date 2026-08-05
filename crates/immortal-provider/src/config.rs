use std::{env, fmt, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::{
    bitcoind::{BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindLimits},
    boltz::{BoltzConfig, BoltzConfigError},
    cln::{ClnClient, ClnEndpoint, ClnLimits},
    health::{AlertEndpoint, private_or_loopback},
    lightning::{ClnLightningRail, LightningRail},
    pricing::{PricingConfig, PricingConfigError, ReservationTier},
    relay_actor,
    wallet::{BitcoinNetwork, ProviderWallet},
};

const MAX_DATABASE_URL_BYTES: usize = 4_096;
const MAX_RELAY_URL_BYTES: usize = 2_048;
const MIN_POLL_SECONDS: u64 = 1;
const MAX_POLL_SECONDS: u64 = 300;
const MIN_STALE_SECONDS: u64 = 5;
const MAX_STALE_SECONDS: u64 = 3_600;
const MIN_CONFIRMATIONS: u32 = 1;
const MAX_CONFIRMATIONS: u32 = 144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    Bitcoind,
    Cln,
    Lnd,
    Wallet,
    Alert,
    Boltz(BoltzConfigError),
    Pricing(PricingConfigError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(formatter, "required provider setting {name} is missing"),
            Self::Invalid(name) => write!(formatter, "provider setting {name} is invalid"),
            Self::Bitcoind => formatter.write_str("bitcoind settings are invalid"),
            Self::Cln => formatter.write_str("CLN settings are invalid"),
            Self::Lnd => formatter.write_str("LND settings are invalid"),
            Self::Wallet => formatter.write_str("provider wallet settings are invalid"),
            Self::Alert => formatter.write_str("provider alert endpoint is invalid"),
            Self::Boltz(error) => write!(formatter, "provider Boltz API {error}"),
            Self::Pricing(error) => write!(formatter, "provider {error}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Boltz(error) => Some(error),
            Self::Pricing(error) => Some(error),
            _ => None,
        }
    }
}

struct DatabaseUrl(String);

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseUrl([REDACTED])")
    }
}

pub struct FundedProviderConfig {
    database_url: DatabaseUrl,
    pub relay_url: String,
    pub bitcoind: BitcoindClient,
    pub lightning: Arc<dyn LightningRail>,
    pub wallet: ProviderWallet,
    pub network: BitcoinNetwork,
    pub health_bind: SocketAddr,
    pub alert_endpoint: Option<AlertEndpoint>,
    pub chain_poll_interval: Duration,
    pub chain_stale_after: Duration,
    pub minimum_confirmations: u32,
    pub reorg_safety_blocks: u32,
    pub pricing: PricingConfig,
    pub boltz: Option<BoltzConfig>,
}

impl fmt::Debug for FundedProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FundedProviderConfig")
            .field("database_url", &self.database_url)
            .field("relay_url", &self.relay_url)
            .field("bitcoind", &self.bitcoind)
            .field("lightning", &self.lightning)
            .field("wallet", &self.wallet)
            .field("network", &self.network)
            .field("health_bind", &self.health_bind)
            .field("alert_endpoint", &self.alert_endpoint)
            .field("chain_poll_interval", &self.chain_poll_interval)
            .field("chain_stale_after", &self.chain_stale_after)
            .field("minimum_confirmations", &self.minimum_confirmations)
            .field("reorg_safety_blocks", &self.reorg_safety_blocks)
            .field("pricing", &self.pricing)
            .field("boltz", &self.boltz)
            .finish()
    }
}

impl FundedProviderConfig {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let database_url = required("IMMORTAL_PROVIDER_DATABASE_URL")?;
        validate_database_url(&database_url)?;
        let relay_url = required("IMMORTAL_PROVIDER_RELAY_URL")?;
        validate_relay_url(&relay_url)?;
        relay_actor::validate_relay_url(&relay_url, "funded")
            .map_err(|_| ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_URL"))?;
        let network = parse_network(&required("IMMORTAL_PROVIDER_BITCOIN_NETWORK")?)?;

        let bitcoind_host = required("IMMORTAL_PROVIDER_BITCOIND_HOST")?;
        let bitcoind_port = parse_number::<u16>(
            "IMMORTAL_PROVIDER_BITCOIND_PORT",
            &required("IMMORTAL_PROVIDER_BITCOIND_PORT")?,
        )?;
        let bitcoind = BitcoindClient::new(
            BitcoindEndpoint::new(bitcoind_host, bitcoind_port)
                .map_err(|_| ConfigError::Bitcoind)?,
            BitcoindAuth::new(
                required("IMMORTAL_PROVIDER_BITCOIND_RPC_USER")?,
                required("IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD")?,
            )
            .map_err(|_| ConfigError::Bitcoind)?,
            BitcoindLimits::default(),
        )
        .map_err(|_| ConfigError::Bitcoind)?;

        let lightning = lightning_from_environment()?;
        let wallet =
            ProviderWallet::load_from_environment(network).map_err(|_| ConfigError::Wallet)?;

        let health_bind = optional("IMMORTAL_PROVIDER_HEALTH_BIND")
            .unwrap_or_else(|| "127.0.0.1:9091".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("IMMORTAL_PROVIDER_HEALTH_BIND"))?;
        if !private_or_loopback(health_bind.ip()) {
            return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_HEALTH_BIND"));
        }
        let alert_endpoint = optional("IMMORTAL_PROVIDER_ALERT_URL")
            .map(AlertEndpoint::parse)
            .transpose()
            .map_err(|_| ConfigError::Alert)?;

        let poll_seconds = optional_number(
            "IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS",
            5_u64,
            MIN_POLL_SECONDS..=MAX_POLL_SECONDS,
        )?;
        let stale_seconds = optional_number(
            "IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS",
            30_u64,
            MIN_STALE_SECONDS..=MAX_STALE_SECONDS,
        )?;
        if stale_seconds <= poll_seconds {
            return Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS",
            ));
        }
        let minimum_confirmations = optional_number(
            "IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS",
            1_u32,
            MIN_CONFIRMATIONS..=MAX_CONFIRMATIONS,
        )?;
        let reorg_safety_blocks = optional_number(
            "IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS",
            6_u32,
            MIN_CONFIRMATIONS..=MAX_CONFIRMATIONS,
        )?;
        let pricing = PricingConfig::from_env().map_err(ConfigError::Pricing)?;
        if pricing.reservation_tier != ReservationTier::Hard {
            return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RESERVATION_TIER"));
        }
        let boltz = BoltzConfig::from_environment().map_err(ConfigError::Boltz)?;

        Ok(Self {
            database_url: DatabaseUrl(database_url),
            relay_url,
            bitcoind,
            lightning,
            wallet,
            network,
            health_bind,
            alert_endpoint,
            chain_poll_interval: Duration::from_secs(poll_seconds),
            chain_stale_after: Duration::from_secs(stale_seconds),
            minimum_confirmations,
            reorg_safety_blocks,
            pricing,
            boltz,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url.0
    }
}

fn lightning_from_environment() -> Result<Arc<dyn LightningRail>, ConfigError> {
    match optional("IMMORTAL_PROVIDER_LIGHTNING_RAIL").as_deref() {
        None | Some("cln") => {
            let client = ClnClient::new(
                ClnEndpoint::new(PathBuf::from(required("IMMORTAL_PROVIDER_CLN_RPC_PATH")?))
                    .map_err(|_| ConfigError::Cln)?,
                ClnLimits::default(),
            )
            .map_err(|_| ConfigError::Cln)?;
            Ok(Arc::new(ClnLightningRail::new(client)))
        }
        Some("lnd") => lnd_from_environment(),
        Some(_) => Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LIGHTNING_RAIL")),
    }
}

#[cfg(feature = "lnd")]
fn lnd_from_environment() -> Result<Arc<dyn LightningRail>, ConfigError> {
    use crate::{
        lightning::LndLightningRail,
        lnd::{LndClient, LndEndpoint, LndLimits, LndMacaroon, LndMacaroons},
    };

    let port = parse_number::<u16>(
        "IMMORTAL_PROVIDER_LND_PORT",
        &required("IMMORTAL_PROVIDER_LND_PORT")?,
    )?;
    let client = LndClient::new(
        LndEndpoint::new(required("IMMORTAL_PROVIDER_LND_HOST")?, port)
            .map_err(|_| ConfigError::Lnd)?,
        &PathBuf::from(required("IMMORTAL_PROVIDER_LND_TLS_CERT_FILE")?),
        LndMacaroons::new(
            LndMacaroon::load(&PathBuf::from(required(
                "IMMORTAL_PROVIDER_LND_READONLY_MACAROON_FILE",
            )?))
            .map_err(|_| ConfigError::Lnd)?,
            LndMacaroon::load(&PathBuf::from(required(
                "IMMORTAL_PROVIDER_LND_INVOICE_MACAROON_FILE",
            )?))
            .map_err(|_| ConfigError::Lnd)?,
            LndMacaroon::load(&PathBuf::from(required(
                "IMMORTAL_PROVIDER_LND_ROUTER_MACAROON_FILE",
            )?))
            .map_err(|_| ConfigError::Lnd)?,
        )
        .map_err(|_| ConfigError::Lnd)?,
        LndLimits::default(),
    )
    .map_err(|_| ConfigError::Lnd)?;
    Ok(Arc::new(LndLightningRail::new(client)))
}

#[cfg(not(feature = "lnd"))]
fn lnd_from_environment() -> Result<Arc<dyn LightningRail>, ConfigError> {
    Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LIGHTNING_RAIL"))
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    optional(name).ok_or(ConfigError::Missing(name))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && !value.as_bytes().iter().any(u8::is_ascii_control))
}

fn parse_network(value: &str) -> Result<BitcoinNetwork, ConfigError> {
    match value {
        "mainnet" => Ok(BitcoinNetwork::Mainnet),
        "testnet" => Ok(BitcoinNetwork::Testnet),
        "signet" => Ok(BitcoinNetwork::Signet),
        "regtest" => Ok(BitcoinNetwork::Regtest),
        _ => Err(ConfigError::Invalid("IMMORTAL_PROVIDER_BITCOIN_NETWORK")),
    }
}

fn validate_database_url(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_DATABASE_URL_BYTES
        || !(value.starts_with("postgres://") || value.starts_with("postgresql://"))
    {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_DATABASE_URL"));
    }
    Ok(())
}

fn validate_relay_url(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_RELAY_URL_BYTES || !value.starts_with("ws://") || value.contains('@') {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_URL"));
    }
    Ok(())
}

fn parse_number<T>(name: &'static str, value: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    value.parse::<T>().map_err(|_| ConfigError::Invalid(name))
}

fn optional_number<T>(
    name: &'static str,
    default: T,
    range: std::ops::RangeInclusive<T>,
) -> Result<T, ConfigError>
where
    T: Copy + Ord + std::str::FromStr,
{
    let value = match optional(name) {
        Some(value) => parse_number(name, &value)?,
        None => default,
    };
    if !range.contains(&value) {
        return Err(ConfigError::Invalid(name));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_and_relay_urls_are_bounded_and_scheme_pinned() {
        assert!(validate_database_url("postgresql://127.0.0.1/provider").is_ok());
        assert!(validate_database_url("https://127.0.0.1/provider").is_err());
        assert!(validate_relay_url("ws://127.0.0.1:7777").is_ok());
        assert!(validate_relay_url("wss://relay.example").is_err());
    }

    #[test]
    fn network_parser_has_no_implicit_default() {
        assert_eq!(parse_network("regtest"), Ok(BitcoinNetwork::Regtest));
        assert!(parse_network("bitcoin").is_err());
    }

    #[test]
    fn debug_output_redacts_database_credentials() {
        let database = DatabaseUrl("postgres://operator:password@localhost/provider".to_owned());
        let rendered = format!("{database:?}");
        assert!(!rendered.contains("password"));
        assert!(!rendered.contains("operator"));
    }

    #[test]
    fn pricing_configuration_error_keeps_the_operator_action() {
        let error = ConfigError::Pricing(PricingConfigError(
            "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB must be between 1 and 2000".to_owned(),
        ));
        assert_eq!(
            error.to_string(),
            "provider pricing config error: IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB must be between 1 and 2000"
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}
