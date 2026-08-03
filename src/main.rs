//! Immortal — a hardened Nostr relay. One Rust binary, one Postgres.
//!
//! Pre-implementation skeleton. Module layout per AGENTS.md:
//!   domain/  — NIP-01 primitives: event, tags, filters, canonical ID,
//!              replacement addresses, deletion semantics (owned, no
//!              third-party Nostr crate)
//!   store/   — Postgres: admission transaction, ingest_seq, indexes,
//!              LISTEN/NOTIFY fanout
//!   gateway/ — WebSocket protocol server: NIP-01 framing, NIP-11, NIP-42,
//!              subscription index, EOSE handoff, ephemeral lane

fn main() {
    println!(
        "immortal {} — pre-implementation skeleton (see README.md)",
        env!("CARGO_PKG_VERSION")
    );
}
