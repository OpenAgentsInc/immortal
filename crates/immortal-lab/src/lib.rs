//! Dev-only wallet-side lab harness for the adversarial regtest lab
//! (immortal#32, consumed by immortal#18).
//!
//! This crate is lab tooling. It is never deployed, never part of a product
//! binary, and never a dependency of a shipped crate. It drives the real
//! client engine from `immortal-client` against a loopback dev relay.

#![forbid(unsafe_code)]

pub mod adversarial;
pub mod browser_demo;
pub mod cli;
pub mod funded;
pub mod relay;
pub mod state;
pub mod steps;
pub mod util;
