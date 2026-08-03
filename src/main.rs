//! Immortal — a hardened Nostr relay. One Rust binary, one Postgres.
//!
//! Server skeleton. The M1 domain and M2 store libraries are implemented;
//! remaining layout:
//!   domain/  — NIP-01 primitives: event, tags, filters, canonical ID,
//!              replacement addresses, deletion semantics (owned, no
//!              third-party Nostr crate)
//!   store/   — Postgres: admission transaction, ingest_seq, indexes,
//!              LISTEN/NOTIFY fanout
//!   gateway/ — WebSocket protocol server: NIP-01 framing, NIP-11, NIP-42,
//!              subscription index, EOSE handoff, ephemeral lane

fn main() {
    println!(
        "immortal {} — domain and store milestones complete; relay server not implemented (see README.md)",
        env!("CARGO_PKG_VERSION")
    );
}
