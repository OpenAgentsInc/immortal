//! Immortal's relay implementation.

#![forbid(unsafe_code)]

pub use immortal_core::{boltz_compat, domain, market, mkt_swp_verify, nip44};

pub mod boltz_facade;
pub mod contract;
pub mod dev_market;
pub mod dev_work;
pub mod gateway;
pub mod mkt_swp_coordination;
pub mod store;
