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
pub mod nip44;
#[cfg(feature = "server")]
pub mod store;
