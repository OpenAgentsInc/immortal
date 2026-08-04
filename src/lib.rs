//! Immortal's protocol and relay implementation.

#![forbid(unsafe_code)]

pub mod client;
pub mod domain;
#[cfg(feature = "server")]
pub mod gateway;
#[cfg(feature = "server")]
pub mod store;
