//! Nostr protocol primitives owned by Immortal.
//!
//! These types implement the pinned NIP specifications in `nips/`. They do
//! not perform storage or network I/O, which keeps protocol decisions
//! deterministic and fixture-testable.

mod deletion;
mod error;
mod event;
mod expanded;
mod filter;
mod hex;
mod replacement;
mod timestamp;

pub use deletion::{DeletionRequest, DeletionTombstone};
pub use error::DomainError;
pub use event::{Event, Tag};
pub use expanded::{
    GroupAction, GroupMetadata, HttpAuth, RelaySigner, parse_http_authorization,
    parse_http_authorization_hash,
};
pub use filter::{Filter, matches_any, search_terms};
pub use replacement::{
    EventClass, ReplacementAddress, ReplacementDecision, compare_replacement,
    compare_replacement_order,
};
pub use timestamp::TimestampPolicy;
