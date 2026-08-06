//! Transport-neutral Immortal client engines.

#![forbid(unsafe_code)]

#[cfg(feature = "mkt-swp-verify")]
pub use immortal_core::mkt_swp_verify;
pub use immortal_core::{domain, market, nip44};

pub mod client;
#[cfg(feature = "mkt-swp-verify")]
pub mod liquid;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_client;
pub mod tbdex;

#[cfg(all(target_arch = "wasm32", feature = "mkt-swp-fixture-probe"))]
pub fn mkt_swp_fixture_probe() -> u32 {
    match mkt_swp_client::fixture_replay::replay_embedded_manifest()
        .and_then(|_| mkt_swp_client::fixture_replay::replay_requester_api_fixture())
    {
        Ok(()) => 0,
        Err(failure) => failure.code(),
    }
}
