//! Pure protocol and verification primitives shared by Immortal products.

#![forbid(unsafe_code)]

pub mod domain;
pub mod market;
#[cfg(feature = "mkt-swp-verify")]
pub mod mkt_swp_verify;
pub mod nip44;
