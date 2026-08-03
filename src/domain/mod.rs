//! Nostr protocol primitives owned by Immortal.
//!
//! These types implement the pinned NIP specifications in `nips/`. They do
//! not perform storage or network I/O, which keeps protocol decisions
//! deterministic and fixture-testable.

mod deletion;
mod error;
mod event;
mod filter;
mod hex;
mod replacement;
mod timestamp;

pub use deletion::{DeletionRequest, DeletionTombstone};
pub use error::DomainError;
pub use event::{Event, Tag};
pub use filter::{Filter, matches_any};
pub use replacement::{
    EventClass, ReplacementAddress, ReplacementDecision, compare_replacement,
    compare_replacement_order,
};
pub use timestamp::TimestampPolicy;
