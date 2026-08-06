use crate::{
    bitcoind::RpcRequestId,
    boltz::{BoltzApi, serve_boltz},
    config::FundedProviderConfig,
    funded_mode::{FundedMode, FundedModePolicy, signer_from_environment},
    health::{ProviderHealth, serve_health},
    liquid::LiquidProviderRail,
    relay_actor::run_with_mode,
    store::ProviderStore,
    wallet::{BitcoinNetwork, WalletPath},
    watchtower::Watchtower,
};
use serde_json::{Value, json};
use std::{env, fmt, sync::Arc, thread};
use tokio::{
    runtime::Builder,
    sync::{oneshot, watch},
};

#[derive(Debug)]
enum FundedError {
    Configuration(String),
    Runtime,
    Database(String),
    Bitcoind(String),
    Elementsd(String),
    Lightning(String),
    Wallet(String),
    Health(String),
    Watchtower(String),
    Boltz(String),
    Shutdown,
}

impl fmt::Display for FundedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => {
                write!(formatter, "provider configuration failed: {error}")
            }
            Self::Runtime => formatter.write_str("provider async runtime could not start"),
            Self::Database(error) => write!(formatter, "provider database startup failed: {error}"),
            Self::Bitcoind(error) => write!(formatter, "provider bitcoind startup failed: {error}"),
            Self::Elementsd(error) => {
                write!(formatter, "provider elementsd startup failed: {error}")
            }
            Self::Lightning(error) => {
                write!(formatter, "provider Lightning startup failed: {error}")
            }
            Self::Wallet(error) => write!(formatter, "provider wallet startup failed: {error}"),
            Self::Health(error) => write!(formatter, "provider health server failed: {error}"),
            Self::Watchtower(error) => write!(formatter, "provider watchtower failed: {error}"),
            Self::Boltz(error) => write!(formatter, "provider Boltz API failed: {error}"),
            Self::Shutdown => formatter.write_str("provider shutdown signal failed"),
        }
    }
}

pub fn run() -> Result<(), String> {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name("immortal-provider")
        .build()
        .map_err(|_| FundedError::Runtime.to_string())?;
    runtime
        .block_on(run_async())
        .map_err(|error| error.to_string())
}

pub fn receive_address() -> Result<String, String> {
    let network = match env::var("IMMORTAL_PROVIDER_BITCOIN_NETWORK").as_deref() {
        Ok("mainnet") => BitcoinNetwork::Mainnet,
        Ok("testnet") => BitcoinNetwork::Testnet,
        Ok("signet") => BitcoinNetwork::Signet,
        Ok("regtest") => BitcoinNetwork::Regtest,
        _ => {
            return Err(
                "IMMORTAL_PROVIDER_BITCOIN_NETWORK must be mainnet, testnet, signet, or regtest"
                    .to_owned(),
            );
        }
    };
    let wallet = crate::wallet::ProviderWallet::load_from_environment(network)
        .map_err(|error| format!("provider wallet startup failed: {error}"))?;
    wallet
        .derive_address(
            WalletPath::new(0, false, 0).map_err(|error| format!("wallet path failed: {error}"))?,
        )
        .map(|address| address.address)
        .map_err(|error| format!("provider wallet startup failed: {error}"))
}

async fn run_async() -> Result<(), FundedError> {
    let config = FundedProviderConfig::from_environment()
        .map_err(|error| FundedError::Configuration(error.to_string()))?;
    let signer = signer_from_environment().map_err(FundedError::Configuration)?;
    verify_bitcoind(&config).await?;
    if let Some(elementsd) = &config.elementsd {
        elementsd
            .startup_probe("provider-startup:liquid")
            .await
            .map_err(|error| FundedError::Elementsd(error.to_string()))?;
    }
    config
        .lightning
        .probe("provider-startup")
        .await
        .map_err(|error| FundedError::Lightning(error.to_string()))?;
    verify_lightning(&config).await?;
    config
        .wallet
        .derive_address(
            WalletPath::new(0, false, 0).map_err(|error| FundedError::Wallet(error.to_string()))?,
        )
        .map_err(|error| FundedError::Wallet(error.to_string()))?;

    let (provider_store, migration) = ProviderStore::connect(config.database_url())
        .await
        .map_err(|error| FundedError::Database(error.to_string()))?;
    if !migration.applied_versions.is_empty() {
        println!(
            "immortal-provider: applied provider database migrations {:?}",
            migration.applied_versions
        );
    }
    let watch_store = ProviderStore::connect_verified(config.database_url())
        .await
        .map_err(|error| FundedError::Database(error.to_string()))?;
    let boltz_store = if config.boltz.is_some() {
        Some(
            ProviderStore::connect_verified(config.database_url())
                .await
                .map_err(|error| FundedError::Database(error.to_string()))?,
        )
    } else {
        None
    };
    let relay_url = config.relay_url.clone();
    let mode_bitcoind = config.bitcoind.clone();
    let mode_liquid = liquid_provider_rail(config.elementsd.clone());
    let watch_bitcoind = config.bitcoind.clone();
    let mode_lightning = config.lightning.clone();
    let boltz_bitcoind = config.bitcoind.clone();
    let boltz_lightning = config.lightning.clone();
    let network = config.network;
    let health_bind = config.health_bind;
    let direct_recovery_bind = config.direct_recovery_bind;
    let alert_endpoint = config.alert_endpoint.clone();
    let chain_poll_interval = config.chain_poll_interval;
    let chain_stale_after = config.chain_stale_after;
    let minimum_confirmations = config.minimum_confirmations;
    let reorg_safety_blocks = config.reorg_safety_blocks;
    let pricing = config.pricing;
    let lab_forces_fallback_feerate = config.lab_forces_fallback_feerate;
    let hold_invoice_expiry_seconds = config.hold_invoice_expiry_seconds;
    let cooperative_signing = config.cooperative_signing;
    let boltz_pricing = pricing.clone();
    let boltz_config = config.boltz;
    let wallet = config.wallet;
    let mode = FundedMode::new(
        tokio::runtime::Handle::current(),
        provider_store,
        wallet,
        mode_bitcoind,
        mode_lightning,
        mode_liquid,
        FundedModePolicy {
            network,
            cooperative_signing,
            minimum_confirmations,
            reorg_safety_blocks,
            pricing,
            lab_forces_fallback_feerate,
            hold_invoice_expiry_seconds,
        },
    );
    let health = Arc::new(ProviderHealth::default());
    let watchtower = Watchtower::new(
        watch_store,
        watch_bitcoind,
        health.clone(),
        alert_endpoint,
        chain_poll_interval,
        chain_stale_after,
        minimum_confirmations,
    )
    .map_err(|error| FundedError::Watchtower(error.to_string()))?;
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut health_task = tokio::spawn(serve_health(
        health_bind,
        health.clone(),
        shutdown_receiver.clone(),
    ));
    let mut watchtower_task = tokio::spawn(watchtower.run(shutdown_receiver.clone()));
    let mut boltz_task = match (boltz_config, boltz_store) {
        (Some(boltz_config), Some(boltz_store)) => {
            let api = BoltzApi::new(
                boltz_store,
                boltz_bitcoind,
                boltz_lightning,
                boltz_pricing,
                network,
                boltz_config.allowed_origin,
                health.clone(),
            );
            Some(tokio::spawn(serve_boltz(
                boltz_config.bind,
                api,
                shutdown_receiver,
            )))
        }
        (None, None) => None,
        _ => {
            return Err(FundedError::Boltz(
                "listener configuration was incomplete".to_owned(),
            ));
        }
    };
    let (relay_sender, mut relay_receiver) = oneshot::channel();
    let relay_health = health.clone();
    let relay_thread = thread::Builder::new()
        .name("immortal-provider-relay".to_owned())
        .spawn(move || {
            let result = run_with_mode(relay_url, signer, mode, direct_recovery_bind, relay_health);
            if relay_sender.send(result).is_err() {
                eprintln!("immortal-provider: relay result receiver closed during shutdown");
            }
        })
        .map_err(|_| FundedError::Runtime)?;

    println!(
        "immortal-provider: funded rails ready network={} health={}",
        network_name(network),
        health_bind
    );
    let drain_signal = tokio::select! {
        signal = wait_for_drain_signal() => signal?,
        result = &mut health_task => {
            return match result {
                Ok(Ok(())) => Err(FundedError::Health("health server stopped before shutdown".to_owned())),
                Ok(Err(error)) => Err(FundedError::Health(error.to_string())),
                Err(_) => Err(FundedError::Health("health server task failed".to_owned())),
            };
        }
        result = &mut watchtower_task => {
            return match result {
                Ok(Ok(())) => Err(FundedError::Watchtower("watchtower stopped before shutdown".to_owned())),
                Ok(Err(error)) => Err(FundedError::Watchtower(error.to_string())),
                Err(_) => Err(FundedError::Watchtower("watchtower task failed".to_owned())),
            };
        }
        result = &mut relay_receiver => {
            return match result {
                Ok(Ok(())) => Err(FundedError::Shutdown),
                Ok(Err(error)) => Err(FundedError::Configuration(error)),
                Err(_) => Err(FundedError::Shutdown),
            };
        }
        result = wait_for_boltz_failure(&mut boltz_task) => {
            return match result {
                Ok(Ok(())) => Err(FundedError::Boltz("listener stopped before shutdown".to_owned())),
                Ok(Err(error)) => Err(FundedError::Boltz(error.to_string())),
                Err(_) => Err(FundedError::Boltz("listener task failed".to_owned())),
            };
        }
    };
    health.begin_drain();
    println!(
        "immortal-provider: drain started signal={} active_sessions={}",
        drain_signal,
        health.snapshot().active_sessions
    );
    match relay_receiver.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(FundedError::Configuration(error)),
        Err(_) => return Err(FundedError::Shutdown),
    }
    relay_thread.join().map_err(|_| FundedError::Shutdown)?;
    shutdown_sender
        .send(true)
        .map_err(|_| FundedError::Shutdown)?;
    await_shutdown(health_task, "health").await?;
    await_shutdown(watchtower_task, "watchtower").await?;
    if let Some(task) = boltz_task {
        await_boltz_shutdown(task).await?;
    }
    Ok(())
}

fn liquid_provider_rail(
    elementsd: Option<crate::elementsd::ElementsdClient>,
) -> Option<LiquidProviderRail> {
    elementsd.map(LiquidProviderRail::new)
}

#[cfg(unix)]
async fn wait_for_drain_signal() -> Result<&'static str, FundedError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).map_err(|_| FundedError::Shutdown)?;
    let mut user_defined =
        signal(SignalKind::user_defined1()).map_err(|_| FundedError::Shutdown)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|_| FundedError::Shutdown)?;
            Ok("interrupt")
        }
        received = terminate.recv() => {
            received.ok_or(FundedError::Shutdown)?;
            Ok("terminate")
        }
        received = user_defined.recv() => {
            received.ok_or(FundedError::Shutdown)?;
            Ok("user_defined_1")
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_drain_signal() -> Result<&'static str, FundedError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|_| FundedError::Shutdown)?;
    Ok("interrupt")
}

async fn wait_for_boltz_failure(
    task: &mut Option<tokio::task::JoinHandle<Result<(), crate::boltz::BoltzServerError>>>,
) -> Result<Result<(), crate::boltz::BoltzServerError>, tokio::task::JoinError> {
    match task {
        Some(task) => task.await,
        None => std::future::pending().await,
    }
}

async fn await_boltz_shutdown(
    task: tokio::task::JoinHandle<Result<(), crate::boltz::BoltzServerError>>,
) -> Result<(), FundedError> {
    match task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(FundedError::Boltz(error.to_string())),
        Err(_) => Err(FundedError::Boltz("listener task failed".to_owned())),
    }
}

async fn verify_bitcoind(config: &FundedProviderConfig) -> Result<(), FundedError> {
    let request_id = RpcRequestId::new("provider-startup:chain")
        .map_err(|error| FundedError::Bitcoind(error.to_string()))?;
    let chain = config
        .bitcoind
        .call(&request_id, "getblockchaininfo", json!([]))
        .await
        .map_err(|error| FundedError::Bitcoind(error.to_string()))?;
    let actual_network = chain.get("chain").and_then(Value::as_str).ok_or_else(|| {
        FundedError::Bitcoind("chain info did not identify its network".to_owned())
    })?;
    let expected_network = match config.network {
        BitcoinNetwork::Mainnet => "main",
        BitcoinNetwork::Testnet => "test",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    };
    if actual_network != expected_network {
        return Err(FundedError::Bitcoind(
            "bitcoind network differs from provider configuration".to_owned(),
        ));
    }
    let replacement_probe = config
        .bitcoind
        .call(
            &RpcRequestId::new("provider-startup:replacement")
                .map_err(|error| FundedError::Bitcoind(error.to_string()))?,
            "gettxspendingprevout",
            json!([[{"txid":"00".repeat(32),"vout":0}]]),
        )
        .await
        .map_err(|error| FundedError::Bitcoind(error.to_string()))?;
    if !replacement_probe.is_array() {
        return Err(FundedError::Bitcoind(
            "bitcoind replacement probe returned an invalid shape".to_owned(),
        ));
    }
    Ok(())
}

async fn verify_lightning(config: &FundedProviderConfig) -> Result<(), FundedError> {
    let info = config
        .lightning
        .node_info("provider-startup:getinfo")
        .await
        .map_err(|error| FundedError::Lightning(error.to_string()))?;
    if info.network != network_name(config.network) {
        return Err(FundedError::Lightning(
            "Lightning network differs from provider configuration".to_owned(),
        ));
    }
    Ok(())
}

async fn await_shutdown<T>(
    task: tokio::task::JoinHandle<Result<T, impl fmt::Display>>,
    name: &str,
) -> Result<(), FundedError> {
    match task.await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(match name {
            "health" => FundedError::Health(error.to_string()),
            _ => FundedError::Watchtower(error.to_string()),
        }),
        Err(_) => Err(match name {
            "health" => FundedError::Health("health server task failed".to_owned()),
            _ => FundedError::Watchtower("watchtower task failed".to_owned()),
        }),
    }
}

fn network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "mainnet",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use immortal_core::liquid::{LiquidAssetId, LiquidNetworkId};

    use crate::{
        bitcoind::{BitcoindAuth, BitcoindEndpoint, BitcoindLimits},
        elementsd::{ElementsdClient, ElementsdWalletName},
    };

    use super::liquid_provider_rail;

    #[test]
    fn elementsd_configuration_is_passed_into_the_funded_mode_rail() {
        assert!(liquid_provider_rail(None).is_none());
        let network = LiquidNetworkId::parse("bip122:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixture Liquid network");
        let asset = LiquidAssetId::parse(&"11".repeat(32)).expect("fixture Liquid asset");
        let elementsd = ElementsdClient::new(
            BitcoindEndpoint::new("127.0.0.1", 18884).expect("fixture endpoint"),
            BitcoindAuth::new("fixture-user", "fixture-password").expect("fixture auth"),
            BitcoindLimits::default(),
            ElementsdWalletName::new("provider-liquid").expect("fixture wallet"),
            network.clone(),
            asset,
        )
        .expect("fixture elementsd");
        let rail = liquid_provider_rail(Some(elementsd)).expect("enabled Liquid rail");
        assert_eq!(rail.network_id(), network.as_str());
        assert_eq!(rail.pegged_asset_id(), "11".repeat(32));
    }
}
