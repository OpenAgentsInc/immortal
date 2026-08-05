use crate::{
    bitcoind::RpcRequestId,
    config::FundedProviderConfig,
    funded_mode::{FundedMode, FundedModePolicy, signer_from_environment},
    health::{ProviderHealth, serve_health},
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
    Cln(String),
    Wallet(String),
    Health(String),
    Watchtower(String),
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
            Self::Cln(error) => write!(formatter, "provider CLN startup failed: {error}"),
            Self::Wallet(error) => write!(formatter, "provider wallet startup failed: {error}"),
            Self::Health(error) => write!(formatter, "provider health server failed: {error}"),
            Self::Watchtower(error) => write!(formatter, "provider watchtower failed: {error}"),
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
    config
        .cln
        .probe_required_capabilities("provider-startup")
        .await
        .map_err(|error| FundedError::Cln(error.to_string()))?;
    verify_cln(&config).await?;
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
    let relay_url = config.relay_url.clone();
    let mode_bitcoind = config.bitcoind.clone();
    let watch_bitcoind = config.bitcoind.clone();
    let mode_cln = config.cln.clone();
    let network = config.network;
    let health_bind = config.health_bind;
    let alert_endpoint = config.alert_endpoint.clone();
    let chain_poll_interval = config.chain_poll_interval;
    let chain_stale_after = config.chain_stale_after;
    let minimum_confirmations = config.minimum_confirmations;
    let reorg_safety_blocks = config.reorg_safety_blocks;
    let pricing = config.pricing;
    let wallet = config.wallet;
    let mode = FundedMode::new(
        tokio::runtime::Handle::current(),
        provider_store,
        wallet,
        mode_bitcoind,
        mode_cln,
        FundedModePolicy {
            network,
            minimum_confirmations,
            reorg_safety_blocks,
            pricing,
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
    let mut health_task =
        tokio::spawn(serve_health(health_bind, health, shutdown_receiver.clone()));
    let mut watchtower_task = tokio::spawn(watchtower.run(shutdown_receiver));
    let (relay_sender, mut relay_receiver) = oneshot::channel();
    let _relay_thread = thread::Builder::new()
        .name("immortal-provider-relay".to_owned())
        .spawn(move || {
            let result = run_with_mode(relay_url, signer, mode);
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
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|_| FundedError::Shutdown)?;
        }
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
    }
    shutdown_sender
        .send(true)
        .map_err(|_| FundedError::Shutdown)?;
    await_shutdown(health_task, "health").await?;
    await_shutdown(watchtower_task, "watchtower").await
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

async fn verify_cln(config: &FundedProviderConfig) -> Result<(), FundedError> {
    let info = config
        .cln
        .node_info(
            &crate::cln::ClnRequestId::new("provider-startup:getinfo")
                .map_err(|error| FundedError::Cln(error.to_string()))?,
        )
        .await
        .map_err(|error| FundedError::Cln(error.to_string()))?;
    if info.network != cln_network_name(config.network) {
        return Err(FundedError::Cln(
            "CLN network differs from provider configuration".to_owned(),
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

fn cln_network_name(network: BitcoinNetwork) -> &'static str {
    match network {
        BitcoinNetwork::Mainnet => "bitcoin",
        BitcoinNetwork::Testnet => "testnet",
        BitcoinNetwork::Signet => "signet",
        BitcoinNetwork::Regtest => "regtest",
    }
}
