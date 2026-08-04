//! Transport-neutral Immortal client engines.

#![forbid(unsafe_code)]

#[cfg(feature = "mkt-swp-verify")]
pub use immortal_core::mkt_swp_verify;
pub use immortal_core::{domain, market, nip44};

pub mod client;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_client;
pub mod tbdex;

#[cfg(all(target_arch = "wasm32", feature = "mkt-swp-fixture-probe"))]
pub fn mkt_swp_fixture_probe() -> u32 {
    match mkt_swp_client::fixture_replay::replay_embedded_manifest() {
        Ok(_) => 0,
        Err(failure) => failure.code(),
    }
}
