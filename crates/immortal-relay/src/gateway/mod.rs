//! Bounded NIP-01 WebSocket and NIP-11 HTTP gateway.

mod auth;
mod boltz;
mod config;
mod db;
mod error;
mod management;
mod media;
mod rate;
mod server;
mod socket;
mod subscription;
mod wire;

pub use config::{
    GatewayConfig, GatewayLimits, MediaConfig, MktSwpCoordinationConfig, RelayIdentity,
};
pub use error::GatewayError;
pub use server::{
    Gateway, MKT_GIFT_WRAP_RECIPIENT_RATE_EXCEEDED, MKT_PRIVATE_REQUIRES_GIFT_WRAP, ShutdownHandle,
};
