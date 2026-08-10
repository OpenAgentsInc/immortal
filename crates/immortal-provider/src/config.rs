use std::{env, fmt, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use immortal_core::liquid::{LiquidAssetId, LiquidNetworkId};

use crate::{
    arkd::{ArkdClient, ArkdEndpoint, ArkdExpectedOperator, ArkdLimits},
    bitcoind::{BitcoindAuth, BitcoindClient, BitcoindEndpoint, BitcoindLimits},
    boltz::{BoltzConfig, BoltzConfigError},
    cln::{ClnClient, ClnEndpoint, ClnLimits},
    contract::arkd_provider_conformance_sha256,
    elementsd::{ElementsdClient, ElementsdWalletName},
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
const MAX_BITCOIN_SUPPLY_SAT: u64 = 2_100_000_000_000_000;
pub(crate) const PRODUCTION_HOLD_INVOICE_EXPIRY_SECONDS: u32 = 604_800;
pub(crate) const REGTEST_ADVERSARIAL_QUOTE_EXPIRY_SECONDS: u64 = 3;
pub(crate) const REGTEST_ADVERSARIAL_HOLD_INVOICE_EXPIRY_SECONDS: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabTimeoutProfile {
    quote_expiry_seconds: u64,
    hold_invoice_expiry_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    Bitcoind,
    Arkd,
    Elementsd,
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
            Self::Arkd => formatter.write_str("arkd settings are invalid"),
            Self::Elementsd => formatter.write_str("elementsd settings are invalid"),
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
    pub relay_urls: Vec<String>,
    pub relay_auth_urls: Vec<String>,
    pub bitcoind: BitcoindClient,
    pub arkd: Option<ArkdClient>,
    pub elementsd: Option<ElementsdClient>,
    pub lightning: Arc<dyn LightningRail>,
    pub wallet: ProviderWallet,
    pub network: BitcoinNetwork,
    pub health_bind: SocketAddr,
    pub direct_recovery_bind: Option<SocketAddr>,
    pub alert_endpoint: Option<AlertEndpoint>,
    pub chain_poll_interval: Duration,
    pub chain_stale_after: Duration,
    pub minimum_confirmations: u32,
    pub reorg_safety_blocks: u32,
    pub pricing: PricingConfig,
    pub price_feed_file: Option<PathBuf>,
    pub force_fallback_feerate: bool,
    pub hold_invoice_expiry_seconds: u32,
    pub cooperative_signing: bool,
    pub zero_conf: Option<ZeroConfConfig>,
    pub boltz: Option<BoltzConfig>,
}

pub struct ArkTransferConfig {
    database_url: DatabaseUrl,
    pub arkd: ArkdClient,
}

impl fmt::Debug for ArkTransferConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArkTransferConfig")
            .field("database_url", &self.database_url)
            .field("arkd", &self.arkd)
            .finish()
    }
}

impl ArkTransferConfig {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let database_url = required("IMMORTAL_PROVIDER_DATABASE_URL")?;
        validate_database_url(&database_url)?;
        let network = parse_network(&required("IMMORTAL_PROVIDER_BITCOIN_NETWORK")?)?;
        let profile = lab_timeout_profile_from_lookup(network, optional)?;
        let arkd = arkd_from_lookup(network, profile, optional)?
            .ok_or(ConfigError::Missing("IMMORTAL_PROVIDER_ARKD_ENABLED"))?;
        Ok(Self {
            database_url: DatabaseUrl(database_url),
            arkd,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroConfConfig {
    pub submarine: bool,
    pub chain: bool,
    pub max_swap_sat: u64,
    pub max_in_flight_sat: u64,
}

impl fmt::Debug for FundedProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FundedProviderConfig")
            .field("database_url", &self.database_url)
            .field("relay_urls", &self.relay_urls)
            .field("relay_auth_urls", &self.relay_auth_urls)
            .field("bitcoind", &self.bitcoind)
            .field("arkd", &self.arkd)
            .field("elementsd", &self.elementsd)
            .field("lightning", &self.lightning)
            .field("wallet", &self.wallet)
            .field("network", &self.network)
            .field("health_bind", &self.health_bind)
            .field("direct_recovery_bind", &self.direct_recovery_bind)
            .field("alert_endpoint", &self.alert_endpoint)
            .field("chain_poll_interval", &self.chain_poll_interval)
            .field("chain_stale_after", &self.chain_stale_after)
            .field("minimum_confirmations", &self.minimum_confirmations)
            .field("reorg_safety_blocks", &self.reorg_safety_blocks)
            .field("pricing", &self.pricing)
            .field("price_feed_file", &self.price_feed_file)
            .field("force_fallback_feerate", &self.force_fallback_feerate)
            .field(
                "hold_invoice_expiry_seconds",
                &self.hold_invoice_expiry_seconds,
            )
            .field("cooperative_signing", &self.cooperative_signing)
            .field("zero_conf", &self.zero_conf)
            .field("boltz", &self.boltz)
            .finish()
    }
}

impl FundedProviderConfig {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let database_url = required("IMMORTAL_PROVIDER_DATABASE_URL")?;
        validate_database_url(&database_url)?;
        let relay_urls = provider_relay_urls_from_lookup(optional)?;
        for relay_url in &relay_urls {
            validate_relay_url(relay_url)?;
            relay_actor::validate_relay_url(relay_url, "funded")
                .map_err(|_| ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_URLS"))?;
        }
        let relay_auth_urls = provider_relay_auth_urls_from_lookup(&relay_urls, optional)?;
        let network = parse_network(&required("IMMORTAL_PROVIDER_BITCOIN_NETWORK")?)?;
        let lab_timeout_profile = lab_timeout_profile_from_lookup(network, optional)?;
        let cooperative_signing = cooperative_signing_from_lookup(lab_timeout_profile, optional)?;
        let zero_conf = zero_conf_from_lookup(optional)?;

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
        let elementsd = elementsd_from_lookup(optional)?;
        let arkd = arkd_from_lookup(network, lab_timeout_profile, optional)?;

        let lightning = lightning_from_environment(lab_timeout_profile)?;
        let wallet =
            ProviderWallet::load_from_environment(network).map_err(|_| ConfigError::Wallet)?;

        let health_bind = optional("IMMORTAL_PROVIDER_HEALTH_BIND")
            .unwrap_or_else(|| "127.0.0.1:9091".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("IMMORTAL_PROVIDER_HEALTH_BIND"))?;
        if !private_or_loopback(health_bind.ip()) {
            return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_HEALTH_BIND"));
        }
        let direct_recovery_bind = direct_recovery_bind_from_lookup(optional)?;
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
        let mut pricing = PricingConfig::from_env().map_err(ConfigError::Pricing)?;
        let price_feed_file = price_feed_file_from_lookup(optional)?;
        let force_fallback_feerate = lab_forces_fallback_feerate(lab_timeout_profile, &pricing)?
            || regtest_forces_fallback_feerate(network, &pricing, optional)?;
        let hold_invoice_expiry_seconds = match lab_timeout_profile {
            Some(profile) => {
                pricing.quote_expiry_seconds = profile.quote_expiry_seconds;
                profile.hold_invoice_expiry_seconds
            }
            None => PRODUCTION_HOLD_INVOICE_EXPIRY_SECONDS,
        };
        if pricing.reservation_tier != ReservationTier::Hard {
            return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RESERVATION_TIER"));
        }
        let boltz = BoltzConfig::from_environment().map_err(ConfigError::Boltz)?;

        Ok(Self {
            database_url: DatabaseUrl(database_url),
            relay_urls,
            relay_auth_urls,
            bitcoind,
            arkd,
            elementsd,
            lightning,
            wallet,
            network,
            health_bind,
            direct_recovery_bind,
            alert_endpoint,
            chain_poll_interval: Duration::from_secs(poll_seconds),
            chain_stale_after: Duration::from_secs(stale_seconds),
            minimum_confirmations,
            reorg_safety_blocks,
            pricing,
            price_feed_file,
            force_fallback_feerate,
            hold_invoice_expiry_seconds,
            cooperative_signing,
            zero_conf,
            boltz,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url.0
    }
}

fn price_feed_file_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<PathBuf>, ConfigError> {
    let Some(value) = lookup("IMMORTAL_PROVIDER_PRICE_FEED_FILE") else {
        return Ok(None);
    };
    if value.is_empty() || value.len() > 4_096 {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_PRICE_FEED_FILE"));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_PRICE_FEED_FILE"));
    }
    Ok(Some(path))
}

fn arkd_from_lookup(
    network: BitcoinNetwork,
    profile: Option<LabTimeoutProfile>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ArkdClient>, ConfigError> {
    const SETTINGS: [&str; 4] = [
        "IMMORTAL_PROVIDER_ARKD_HOST",
        "IMMORTAL_PROVIDER_ARKD_PORT",
        "IMMORTAL_PROVIDER_ARKD_OPERATOR_FILE",
        "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256",
    ];
    match lookup("IMMORTAL_PROVIDER_ARKD_ENABLED").as_deref() {
        None => {
            if SETTINGS.iter().any(|name| lookup(name).is_some()) {
                return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_ARKD_ENABLED"));
            }
            return Ok(None);
        }
        Some("true") => {}
        Some(_) => return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_ARKD_ENABLED")),
    }
    if network != BitcoinNetwork::Regtest || profile.is_none() {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_ARKD_ENABLED"));
    }
    let required = |name: &'static str| lookup(name).ok_or(ConfigError::Missing(name));
    let conformance = required("IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256")?;
    if conformance != arkd_provider_conformance_sha256() {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256",
        ));
    }
    let port = parse_number::<u16>(
        "IMMORTAL_PROVIDER_ARKD_PORT",
        &required("IMMORTAL_PROVIDER_ARKD_PORT")?,
    )?;
    let expected = ArkdExpectedOperator::load_document(&PathBuf::from(required(
        "IMMORTAL_PROVIDER_ARKD_OPERATOR_FILE",
    )?))
    .map_err(|_| ConfigError::Arkd)?;
    let client = ArkdClient::new(
        ArkdEndpoint::plaintext_regtest(required("IMMORTAL_PROVIDER_ARKD_HOST")?, port)
            .map_err(|_| ConfigError::Arkd)?,
        expected,
        ArkdLimits::default(),
    )
    .map_err(|_| ConfigError::Arkd)?;
    Ok(Some(client))
}

fn zero_conf_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ZeroConfConfig>, ConfigError> {
    let submarine = explicit_true(
        "IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE",
        lookup("IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE"),
    )?;
    let chain = explicit_true(
        "IMMORTAL_PROVIDER_ZERO_CONF_CHAIN",
        lookup("IMMORTAL_PROVIDER_ZERO_CONF_CHAIN"),
    )?;
    let max_swap = lookup("IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT");
    let max_in_flight = lookup("IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT");
    if !submarine && !chain {
        if max_swap.is_some() || max_in_flight.is_some() {
            return Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT",
            ));
        }
        return Ok(None);
    }
    let max_swap_sat = parse_number::<u64>(
        "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT",
        max_swap.as_deref().ok_or(ConfigError::Missing(
            "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT",
        ))?,
    )?;
    let max_in_flight_sat = parse_number::<u64>(
        "IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT",
        max_in_flight.as_deref().ok_or(ConfigError::Missing(
            "IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT",
        ))?,
    )?;
    if max_swap_sat == 0
        || max_in_flight_sat == 0
        || max_swap_sat > MAX_BITCOIN_SUPPLY_SAT
        || max_in_flight_sat > MAX_BITCOIN_SUPPLY_SAT
        || max_swap_sat > max_in_flight_sat
    {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT",
        ));
    }
    Ok(Some(ZeroConfConfig {
        submarine,
        chain,
        max_swap_sat,
        max_in_flight_sat,
    }))
}

fn explicit_true(name: &'static str, value: Option<String>) -> Result<bool, ConfigError> {
    match value.as_deref() {
        None => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigError::Invalid(name)),
    }
}

fn elementsd_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<ElementsdClient>, ConfigError> {
    const SETTINGS: [&str; 7] = [
        "IMMORTAL_PROVIDER_ELEMENTSD_HOST",
        "IMMORTAL_PROVIDER_ELEMENTSD_PORT",
        "IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER",
        "IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD",
        "IMMORTAL_PROVIDER_ELEMENTSD_WALLET",
        "IMMORTAL_PROVIDER_LIQUID_NETWORK_ID",
        "IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET",
    ];
    let enabled = lookup("IMMORTAL_PROVIDER_LIQUID_ENABLED");
    match enabled.as_deref() {
        None => {
            if SETTINGS.iter().any(|name| lookup(name).is_some()) {
                return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LIQUID_ENABLED"));
            }
            return Ok(None);
        }
        Some("true") => {}
        Some(_) => return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LIQUID_ENABLED")),
    }
    let required = |name: &'static str| lookup(name).ok_or(ConfigError::Missing(name));
    let port = parse_number::<u16>(
        "IMMORTAL_PROVIDER_ELEMENTSD_PORT",
        &required("IMMORTAL_PROVIDER_ELEMENTSD_PORT")?,
    )?;
    let client = ElementsdClient::new(
        BitcoindEndpoint::new(required("IMMORTAL_PROVIDER_ELEMENTSD_HOST")?, port)
            .map_err(|_| ConfigError::Elementsd)?,
        BitcoindAuth::new(
            required("IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER")?,
            required("IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD")?,
        )
        .map_err(|_| ConfigError::Elementsd)?,
        BitcoindLimits::default(),
        ElementsdWalletName::new(required("IMMORTAL_PROVIDER_ELEMENTSD_WALLET")?)
            .map_err(|_| ConfigError::Elementsd)?,
        LiquidNetworkId::parse(&required("IMMORTAL_PROVIDER_LIQUID_NETWORK_ID")?)
            .map_err(|_| ConfigError::Elementsd)?,
        LiquidAssetId::parse(&required("IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET")?)
            .map_err(|_| ConfigError::Elementsd)?,
    )
    .map_err(|_| ConfigError::Elementsd)?;
    Ok(Some(client))
}

fn cooperative_signing_from_lookup(
    profile: Option<LabTimeoutProfile>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<bool, ConfigError> {
    let production = lookup("IMMORTAL_PROVIDER_COOPERATIVE_SIGNING");
    let lab = lookup("IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING");
    if production.is_some() && lab.is_some() {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING",
        ));
    }
    if let Some(value) = production {
        if value != "true" {
            return Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING",
            ));
        }
        return Ok(true);
    }
    let Some(value) = lab else {
        return Ok(false);
    };
    if value != "true" || profile.is_none() {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING",
        ));
    }
    Ok(true)
}

fn direct_recovery_bind_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<SocketAddr>, ConfigError> {
    let Some(value) = lookup("IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND") else {
        return Ok(None);
    };
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::Invalid("IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND"))?;
    if !private_or_loopback(address.ip()) {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND",
        ));
    }
    Ok(Some(address))
}

fn lightning_from_environment(
    lab_timeout_profile: Option<LabTimeoutProfile>,
) -> Result<Arc<dyn LightningRail>, ConfigError> {
    match optional("IMMORTAL_PROVIDER_LIGHTNING_RAIL").as_deref() {
        None | Some("cln") => {
            let client = ClnClient::new(
                ClnEndpoint::new(PathBuf::from(required("IMMORTAL_PROVIDER_CLN_RPC_PATH")?))
                    .map_err(|_| ConfigError::Cln)?,
                ClnLimits::default(),
            )
            .map_err(|_| ConfigError::Cln)?;
            let rail = if lab_timeout_profile.is_some() {
                ClnLightningRail::with_immortal_regtest_policy(client)
            } else {
                ClnLightningRail::new(client)
            };
            Ok(Arc::new(rail))
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

fn lab_timeout_profile_from_lookup(
    network: BitcoinNetwork,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<LabTimeoutProfile>, ConfigError> {
    let Some(profile) = lookup("IMMORTAL_PROVIDER_LAB_PROFILE") else {
        return Ok(None);
    };
    if profile != "regtest_adversarial" || network != BitcoinNetwork::Regtest {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LAB_PROFILE"));
    }
    Ok(Some(LabTimeoutProfile {
        quote_expiry_seconds: REGTEST_ADVERSARIAL_QUOTE_EXPIRY_SECONDS,
        hold_invoice_expiry_seconds: REGTEST_ADVERSARIAL_HOLD_INVOICE_EXPIRY_SECONDS,
    }))
}

fn lab_forces_fallback_feerate(
    profile: Option<LabTimeoutProfile>,
    pricing: &PricingConfig,
) -> Result<bool, ConfigError> {
    if profile.is_some() && pricing.fallback_feerate_sat_per_vb.is_none() {
        return Err(ConfigError::Missing(
            "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB",
        ));
    }
    Ok(profile.is_some())
}

fn regtest_forces_fallback_feerate(
    network: BitcoinNetwork,
    pricing: &PricingConfig,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<bool, ConfigError> {
    let Some(value) = lookup("IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE") else {
        return Ok(false);
    };
    if value != "true" || network != BitcoinNetwork::Regtest {
        return Err(ConfigError::Invalid(
            "IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE",
        ));
    }
    if pricing.fallback_feerate_sat_per_vb.is_none() {
        return Err(ConfigError::Missing(
            "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB",
        ));
    }
    Ok(true)
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

fn provider_relay_urls_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>, ConfigError> {
    match lookup("IMMORTAL_PROVIDER_RELAY_URLS") {
        Some(value) => parse_relay_csv(&value, "IMMORTAL_PROVIDER_RELAY_URLS", 2),
        None => {
            Ok(vec![lookup("IMMORTAL_PROVIDER_RELAY_URL").ok_or(
                ConfigError::Missing("IMMORTAL_PROVIDER_RELAY_URL"),
            )?])
        }
    }
}

fn provider_relay_auth_urls_from_lookup(
    relay_urls: &[String],
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>, ConfigError> {
    let auth_urls = match lookup("IMMORTAL_PROVIDER_RELAY_AUTH_URLS") {
        Some(value) => parse_relay_auth_csv(&value, relay_urls.len())?,
        None if relay_urls.len() == 1 => vec![
            lookup("IMMORTAL_PROVIDER_RELAY_AUTH_URL").unwrap_or_else(|| relay_urls[0].clone()),
        ],
        None => relay_urls.to_vec(),
    };
    if auth_urls.len() != relay_urls.len() {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_AUTH_URLS"));
    }
    for auth_url in &auth_urls {
        validate_relay_auth_url(auth_url)?;
    }
    Ok(auth_urls)
}

fn parse_relay_auth_csv(value: &str, expected: usize) -> Result<Vec<String>, ConfigError> {
    let values = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if values.len() != expected
        || values
            .iter()
            .any(|value| value.is_empty() || value.trim() != value)
    {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_AUTH_URLS"));
    }
    Ok(values)
}

fn parse_relay_csv(
    value: &str,
    name: &'static str,
    minimum: usize,
) -> Result<Vec<String>, ConfigError> {
    let values = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if !(minimum..=8).contains(&values.len())
        || values
            .iter()
            .any(|value| value.is_empty() || value.trim() != value)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ConfigError::Invalid(name));
    }
    Ok(values)
}

fn validate_relay_auth_url(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_RELAY_URL_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_AUTH_URL"));
    }
    let authority = value
        .strip_prefix("ws://")
        .or_else(|| value.strip_prefix("wss://"))
        .and_then(|remainder| remainder.strip_suffix('/').or(Some(remainder)))
        .filter(|remainder| {
            !remainder.is_empty()
                && !remainder.contains('/')
                && remainder.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                })
        })
        .ok_or(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_AUTH_URL"))?;
    if authority.starts_with(':') || authority.ends_with(':') {
        return Err(ConfigError::Invalid("IMMORTAL_PROVIDER_RELAY_AUTH_URL"));
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
        assert!(validate_relay_auth_url("wss://relay.example").is_ok());
        assert!(validate_relay_auth_url("ws://127.0.0.1:7777").is_ok());
        assert!(validate_relay_auth_url("https://relay.example").is_err());
        assert!(validate_relay_auth_url("wss://relay.example/path").is_err());
        assert!(validate_relay_auth_url("wss://user@relay.example").is_err());
        assert!(validate_relay_auth_url("wss://relay.example?query").is_err());
        assert!(validate_relay_auth_url("wss://relay.example#fragment").is_err());
        assert!(validate_relay_auth_url("wss://relay example").is_err());
    }

    #[test]
    fn provider_relay_set_is_bounded_sorted_and_keeps_legacy_single_url() {
        let plural = provider_relay_urls_from_lookup(|name| {
            (name == "IMMORTAL_PROVIDER_RELAY_URLS")
                .then(|| "ws://127.0.0.1:7001,ws://127.0.0.1:7002".to_owned())
        })
        .unwrap();
        assert_eq!(plural.len(), 2);
        assert!(
            provider_relay_urls_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_RELAY_URLS")
                    .then(|| "ws://127.0.0.1:7002,ws://127.0.0.1:7001".to_owned())
            })
            .is_err()
        );
        assert_eq!(
            provider_relay_urls_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_RELAY_URL").then(|| "ws://127.0.0.1:7001".to_owned())
            })
            .unwrap(),
            vec!["ws://127.0.0.1:7001"]
        );
        let auth = provider_relay_auth_urls_from_lookup(&plural, |_| None).unwrap();
        assert_eq!(auth, plural);
        let positional_auth = provider_relay_auth_urls_from_lookup(&plural, |name| {
            (name == "IMMORTAL_PROVIDER_RELAY_AUTH_URLS")
                .then(|| "wss://auth-b.example,wss://auth-a.example".to_owned())
        })
        .unwrap();
        assert_eq!(
            positional_auth,
            vec!["wss://auth-b.example", "wss://auth-a.example"]
        );
    }

    #[test]
    fn network_parser_has_no_implicit_default() {
        assert_eq!(parse_network("regtest"), Ok(BitcoinNetwork::Regtest));
        assert!(parse_network("bitcoin").is_err());
    }

    #[test]
    fn price_feed_file_is_optional_and_requires_an_absolute_path() {
        assert_eq!(price_feed_file_from_lookup(|_| None), Ok(None));
        assert_eq!(
            price_feed_file_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_PRICE_FEED_FILE")
                    .then(|| "/run/immortal/provider-price-feed.json".to_owned())
            }),
            Ok(Some(PathBuf::from(
                "/run/immortal/provider-price-feed.json"
            )))
        );
        assert_eq!(
            price_feed_file_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_PRICE_FEED_FILE")
                    .then(|| "provider-price-feed.json".to_owned())
            }),
            Err(ConfigError::Invalid("IMMORTAL_PROVIDER_PRICE_FEED_FILE"))
        );
    }

    #[test]
    fn fixed_feerate_gate_is_explicit_and_regtest_only() {
        let pricing = PricingConfig::from_lookup(|name| {
            (name == "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB").then(|| "20".to_owned())
        })
        .expect("fallback pricing");
        let enabled = |name: &str| {
            (name == "IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE").then(|| "true".to_owned())
        };
        assert_eq!(
            regtest_forces_fallback_feerate(BitcoinNetwork::Regtest, &pricing, enabled),
            Ok(true)
        );
        assert_eq!(
            regtest_forces_fallback_feerate(BitcoinNetwork::Mainnet, &pricing, enabled),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_REGTEST_FIXED_FEERATE"
            ))
        );
        assert_eq!(
            regtest_forces_fallback_feerate(BitcoinNetwork::Regtest, &pricing, |_| None),
            Ok(false)
        );
        let no_fallback = PricingConfig::from_lookup(|_| None).expect("default pricing");
        assert_eq!(
            regtest_forces_fallback_feerate(BitcoinNetwork::Regtest, &no_fallback, enabled),
            Err(ConfigError::Missing(
                "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB"
            ))
        );
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

    #[test]
    fn adversarial_lab_profile_is_fixture_bound_and_regtest_only() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/lab/adversarial-v1.json"
        ))
        .expect("adversarial lab fixture parses");
        let profile = &fixture["lab_profile"];
        assert_eq!(profile["environment"], "IMMORTAL_PROVIDER_LAB_PROFILE");
        assert_eq!(profile["value"], "regtest_adversarial");
        assert_eq!(profile["pricing"]["source"], "configured_fallback_only");

        let timeout = lab_timeout_profile_from_lookup(BitcoinNetwork::Regtest, |name| {
            (name
                == profile["environment"]
                    .as_str()
                    .expect("profile environment"))
            .then(|| profile["value"].as_str().expect("profile value").to_owned())
        })
        .expect("regtest profile validates")
        .expect("regtest profile is active");
        assert_eq!(
            timeout.quote_expiry_seconds,
            profile["tiny_quote_expiry_seconds"]
                .as_u64()
                .expect("quote expiry")
        );
        assert_eq!(
            u64::from(timeout.hold_invoice_expiry_seconds),
            profile["tiny_hold_invoice_expiry_seconds"]
                .as_u64()
                .expect("hold expiry")
        );
        let pricing = PricingConfig::from_lookup(|name| {
            (name == "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB").then(|| {
                profile["pricing"]["sat_per_vbyte"]
                    .as_u64()
                    .expect("lab feerate")
                    .to_string()
            })
        })
        .expect("fixture fallback pricing validates");
        assert_eq!(
            lab_forces_fallback_feerate(Some(timeout), &pricing),
            Ok(true)
        );
        let no_fallback = PricingConfig::from_lookup(|_| None).expect("default pricing");
        assert_eq!(
            lab_forces_fallback_feerate(Some(timeout), &no_fallback),
            Err(ConfigError::Missing(
                "IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB"
            ))
        );

        for network in [
            BitcoinNetwork::Mainnet,
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
        ] {
            assert_eq!(
                lab_timeout_profile_from_lookup(network, |name| {
                    (name == "IMMORTAL_PROVIDER_LAB_PROFILE")
                        .then(|| "regtest_adversarial".to_owned())
                }),
                Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LAB_PROFILE"))
            );
        }
        assert_eq!(
            lab_timeout_profile_from_lookup(BitcoinNetwork::Regtest, |name| {
                (name == "IMMORTAL_PROVIDER_LAB_PROFILE").then(|| "unknown".to_owned())
            }),
            Err(ConfigError::Invalid("IMMORTAL_PROVIDER_LAB_PROFILE"))
        );
    }

    #[test]
    fn production_timeout_policy_is_unchanged_without_the_lab_profile() {
        assert_eq!(
            lab_timeout_profile_from_lookup(BitcoinNetwork::Mainnet, |_| None),
            Ok(None)
        );
        assert_eq!(PRODUCTION_HOLD_INVOICE_EXPIRY_SECONDS, 604_800);
        assert_eq!(cooperative_signing_from_lookup(None, |_| None), Ok(false));
        assert_eq!(
            cooperative_signing_from_lookup(None, |name| {
                (name == "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING").then(|| "true".to_owned())
            }),
            Ok(true)
        );
        let pricing = PricingConfig::from_lookup(|_| None).expect("default pricing validates");
        assert_eq!(pricing.quote_expiry_seconds, 300);
        assert!(
            PricingConfig {
                quote_expiry_seconds: 1,
                ..pricing
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn cooperative_signing_requires_the_explicit_validated_regtest_lab_gate() {
        let profile = lab_timeout_profile_from_lookup(BitcoinNetwork::Regtest, |name| {
            (name == "IMMORTAL_PROVIDER_LAB_PROFILE").then(|| "regtest_adversarial".to_owned())
        })
        .expect("regtest profile validates");
        assert_eq!(
            cooperative_signing_from_lookup(profile, |_| None),
            Ok(false)
        );
        assert_eq!(
            cooperative_signing_from_lookup(profile, |name| {
                (name == "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING").then(|| "true".to_owned())
            }),
            Ok(true)
        );
        assert_eq!(
            cooperative_signing_from_lookup(None, |name| {
                (name == "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING").then(|| "true".to_owned())
            }),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING"
            ))
        );
        assert_eq!(
            cooperative_signing_from_lookup(profile, |name| {
                (name == "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING").then(|| "false".to_owned())
            }),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING"
            ))
        );
        assert_eq!(
            cooperative_signing_from_lookup(profile, |name| {
                match name {
                    "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING"
                    | "IMMORTAL_PROVIDER_LAB_COOPERATIVE_SIGNING" => Some("true".to_owned()),
                    _ => None,
                }
            }),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING"
            ))
        );
        assert_eq!(
            cooperative_signing_from_lookup(None, |name| {
                (name == "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING").then(|| "false".to_owned())
            }),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_COOPERATIVE_SIGNING"
            ))
        );
        for network in [
            BitcoinNetwork::Mainnet,
            BitcoinNetwork::Testnet,
            BitcoinNetwork::Signet,
        ] {
            assert!(
                lab_timeout_profile_from_lookup(network, |name| {
                    (name == "IMMORTAL_PROVIDER_LAB_PROFILE")
                        .then(|| "regtest_adversarial".to_owned())
                })
                .is_err()
            );
        }
    }

    #[test]
    fn direct_recovery_is_optional_and_private_only() {
        assert_eq!(direct_recovery_bind_from_lookup(|_| None), Ok(None));
        assert_eq!(
            direct_recovery_bind_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND")
                    .then(|| "127.0.0.1:9191".to_owned())
            }),
            Ok(Some("127.0.0.1:9191".parse().expect("socket address")))
        );
        assert_eq!(
            direct_recovery_bind_from_lookup(|_| Some("192.0.2.1:9191".to_owned())),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_DIRECT_RECOVERY_BIND"
            ))
        );
    }

    #[test]
    fn liquid_configuration_is_explicit_and_complete() {
        assert!(
            elementsd_from_lookup(|_| None)
                .expect("disabled Liquid config")
                .is_none()
        );
        assert!(
            elementsd_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_ELEMENTSD_HOST").then(|| "127.0.0.1".to_owned())
            })
            .is_err()
        );
        let configured = elementsd_from_lookup(|name| {
            let value = match name {
                "IMMORTAL_PROVIDER_LIQUID_ENABLED" => "true",
                "IMMORTAL_PROVIDER_ELEMENTSD_HOST" => "127.0.0.1",
                "IMMORTAL_PROVIDER_ELEMENTSD_PORT" => "18884",
                "IMMORTAL_PROVIDER_ELEMENTSD_RPC_USER" => "elements-user",
                "IMMORTAL_PROVIDER_ELEMENTSD_RPC_PASSWORD" => "elements-password",
                "IMMORTAL_PROVIDER_ELEMENTSD_WALLET" => "provider-liquid",
                "IMMORTAL_PROVIDER_LIQUID_NETWORK_ID" => "bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "IMMORTAL_PROVIDER_LIQUID_PEGGED_ASSET" => {
                    "1111111111111111111111111111111111111111111111111111111111111111"
                }
                _ => return None,
            };
            Some(value.to_owned())
        })
        .expect("complete Liquid config");
        assert!(configured.is_some());
    }

    #[test]
    fn arkd_configuration_is_digest_gated_and_regtest_lab_only() {
        assert!(
            arkd_from_lookup(BitcoinNetwork::Regtest, None, |_| None)
                .expect("disabled arkd configuration")
                .is_none()
        );
        assert!(matches!(
            arkd_from_lookup(BitcoinNetwork::Regtest, None, |name| {
                (name == "IMMORTAL_PROVIDER_ARKD_HOST").then(|| "127.0.0.1".to_owned())
            }),
            Err(ConfigError::Invalid("IMMORTAL_PROVIDER_ARKD_ENABLED"))
        ));
        let profile = lab_timeout_profile_from_lookup(BitcoinNetwork::Regtest, |name| {
            (name == "IMMORTAL_PROVIDER_LAB_PROFILE").then(|| "regtest_adversarial".to_owned())
        })
        .expect("regtest lab profile");
        let operator_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/provider/arkd-operator-regtest-v1.json")
            .canonicalize()
            .expect("operator fixture path")
            .to_string_lossy()
            .into_owned();
        let conformance = arkd_provider_conformance_sha256();
        let lookup = |name: &str| {
            let value = match name {
                "IMMORTAL_PROVIDER_ARKD_ENABLED" => "true".to_owned(),
                "IMMORTAL_PROVIDER_ARKD_HOST" => "127.0.0.1".to_owned(),
                "IMMORTAL_PROVIDER_ARKD_PORT" => "17070".to_owned(),
                "IMMORTAL_PROVIDER_ARKD_OPERATOR_FILE" => operator_path.clone(),
                "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256" => conformance.clone(),
                _ => return None,
            };
            Some(value)
        };
        let configured = arkd_from_lookup(BitcoinNetwork::Regtest, profile, lookup)
            .expect("complete arkd configuration")
            .expect("enabled arkd client");
        assert_eq!(
            configured.operator_identity_sha256(),
            "2d66cea26a24fc3f91b81559d83b9ddd456a71947e27249a389eb216f66fb4f9"
        );
        assert!(matches!(
            arkd_from_lookup(BitcoinNetwork::Mainnet, profile, lookup),
            Err(ConfigError::Invalid("IMMORTAL_PROVIDER_ARKD_ENABLED"))
        ));
        assert!(matches!(
            arkd_from_lookup(BitcoinNetwork::Regtest, profile, |name| {
                if name == "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256" {
                    Some("00".repeat(32))
                } else {
                    lookup(name)
                }
            }),
            Err(ConfigError::Invalid(
                "IMMORTAL_PROVIDER_ARKD_CONFORMANCE_SHA256"
            ))
        ));
    }

    #[test]
    fn zero_conf_is_off_by_default_and_requires_bounded_caps() {
        assert_eq!(zero_conf_from_lookup(|_| None), Ok(None));
        let configured = zero_conf_from_lookup(|name| {
            let value = match name {
                "IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE" => "true",
                "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT" => "100000",
                "IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT" => "250000",
                _ => return None,
            };
            Some(value.to_owned())
        })
        .expect("bounded zero-conf configuration");
        assert_eq!(
            configured,
            Some(ZeroConfConfig {
                submarine: true,
                chain: false,
                max_swap_sat: 100_000,
                max_in_flight_sat: 250_000,
            })
        );
        assert!(
            zero_conf_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE").then(|| "true".to_owned())
            })
            .is_err()
        );
        assert!(
            zero_conf_from_lookup(|name| {
                let value = match name {
                    "IMMORTAL_PROVIDER_ZERO_CONF_CHAIN" => "true",
                    "IMMORTAL_PROVIDER_ZERO_CONF_MAX_SWAP_SAT" => "251",
                    "IMMORTAL_PROVIDER_ZERO_CONF_MAX_IN_FLIGHT_SAT" => "250",
                    _ => return None,
                };
                Some(value.to_owned())
            })
            .is_err()
        );
        assert!(
            zero_conf_from_lookup(|name| {
                (name == "IMMORTAL_PROVIDER_ZERO_CONF_SUBMARINE").then(|| "false".to_owned())
            })
            .is_err()
        );
    }
}
