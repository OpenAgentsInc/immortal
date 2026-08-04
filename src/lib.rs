//! Immortal's protocol and relay implementation.

#![forbid(unsafe_code)]

pub mod client;
#[cfg(feature = "server")]
pub mod contract;
#[cfg(feature = "server")]
pub mod dev_market;
pub mod domain;
#[cfg(feature = "server")]
pub mod gateway;
pub mod market;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_client;
#[cfg(feature = "server")]
pub mod mkt_swp_coordination;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_verify;
pub mod nip44;
#[cfg(feature = "server")]
pub mod store;
pub mod tbdex;

#[cfg(all(target_arch = "wasm32", feature = "mkt-swp-fixture-probe"))]
pub fn mkt_swp_fixture_probe() -> u32 {
    match mkt_swp_client::fixture_replay::replay_embedded_manifest() {
        Ok(_) => 0,
        Err(failure) => failure.code(),
    }
}
