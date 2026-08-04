//! Bounded NIP-01 WebSocket and NIP-11 HTTP gateway.

mod auth;
mod config;
mod db;
mod error;
mod management;
mod rate;
mod server;
mod socket;
mod subscription;
mod wire;

pub use config::{GatewayConfig, GatewayLimits, RelayIdentity};
pub use error::GatewayError;
pub use server::{Gateway, ShutdownHandle};
