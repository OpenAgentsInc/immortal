//! Pure protocol and verification primitives shared by Immortal products.

#![forbid(unsafe_code)]

pub mod boltz_compat;
pub mod domain;
#[cfg(feature = "mkt-swp-verify")]
pub mod liquid;
pub mod market;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_verify;
pub mod nip44;
