//! Immortal's protocol and relay implementation.

#![forbid(unsafe_code)]

pub mod client;
#[cfg(feature = "server")]
pub mod contract;
pub mod domain;
#[cfg(feature = "server")]
pub mod gateway;
#[cfg(feature = "server")]
pub mod store;
