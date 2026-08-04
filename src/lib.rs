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
#[cfg(feature = "server")]
pub mod mkt_swp_coordination;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_client;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_verify;
pub mod nip44;
#[cfg(feature = "server")]
pub mod store;
pub mod tbdex;
