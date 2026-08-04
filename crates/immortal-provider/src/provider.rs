//! Immortal's transport-neutral provider engine and runnable daemon.

#![forbid(unsafe_code)]

pub mod session;

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
