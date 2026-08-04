//! Immortal's relay implementation.

#![forbid(unsafe_code)]

pub use immortal_core::{domain, market, mkt_swp_verify, nip44};

pub mod contract;
pub mod dev_market;
pub mod gateway;
pub mod mkt_swp_coordination;
pub mod store;
