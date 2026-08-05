//! Immortal's transport-neutral provider engine and runnable daemon.

#![forbid(unsafe_code)]

pub mod pricing;
pub mod session;

#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod wallet;

#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod bitcoind;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod cln;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod config;
#[cfg(all(
    any(feature = "funded", feature = "no-spend"),
    not(target_arch = "wasm32")
))]
pub mod contract;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod cooperative;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod funded;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub(crate) mod funded_mode;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod funding;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod health;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod lightning;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod liquidity;
#[cfg(all(feature = "lnd", not(target_arch = "wasm32")))]
pub mod lnd;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod quote;
#[cfg(all(
    any(feature = "funded", feature = "no-spend"),
    not(target_arch = "wasm32")
))]
pub(crate) mod relay_actor;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod settlement;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod store;
#[cfg(all(feature = "funded", not(target_arch = "wasm32")))]
pub mod watchtower;

#[cfg(all(feature = "no-spend", not(target_arch = "wasm32")))]
pub mod no_spend;

pub use session::{
    MktPublicSigningRequest, ProviderDiscoveryFactory, ProviderEffectKind, ProviderEffectReceipt,
    ProviderEffectRequest, ProviderSession, ReservationConfirmation, ReservationReleaseCause,
    ReservationRequest,
};

#[cfg(all(target_arch = "wasm32", feature = "mkt-swp-fixture-probe"))]
pub fn mkt_swp_fixture_probe() -> u32 {
    if session::fixture_replay::replay_embedded_manifest().is_ok() {
        0
    } else {
        1
    }
}
