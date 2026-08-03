# Immortal

A hardened Nostr relay. One Rust binary and one Postgres database. Nothing
else.

License: CC0-1.0. Public domain.

## What Immortal is

Immortal is a relay for the Nostr protocol. It runs as one program. It keeps
all data in one Postgres database. It does not need other services.

You can run it on one small server. You can also run many relay processes
against one database. The design is the same in both cases.

## Architecture

```text
Nostr clients  <=>  immortal (one binary: WebSocket + NIP-11 HTTP)
                        |
                    Postgres
                    events, tag indexes, replaceable heads,
                    deletion tombstones, policy, full-text search,
                    LISTEN/NOTIFY, ingest sequence
```

Postgres does all the storage work:

- It stores events.
- It indexes tags for queries.
- It keeps the current replaceable-event heads.
- It keeps deletion tombstones.
- It does full-text search with a generated column and a GIN index.
- It tells all relay processes about new events with `LISTEN/NOTIFY`.
- It gives each event a sequence number (`ingest_seq`).

Event admission is one database transaction. The relay sends `OK` to the
client only after the commit.

A relay process uses the sequence number to find events it did not see. If
a process cannot become current, it closes its connections. Clients
reconnect. This is safe in the Nostr protocol.

Ephemeral events (kinds 20000–29999) do not go to storage.

TLS is the job of the reverse proxy (nginx or Caddy).

## Design rules

1. **Standard.** Rust, tokio, and Postgres only.
2. **Hardened.** Prepared SQL statements only. Limits on frame size,
   subscriptions, filters, and query cost. Rate limits per IP and per
   pubkey. Fail closed.
3. **Simple.** One crate. One binary. Seven direct dependencies (see
   `AGENTS.md`).
4. **Easy to deploy.** A new Debian server, Postgres from the package
   manager, and this binary make a relay in minutes.

## Status

M1 (the protocol domain) and M2 (the Postgres store) are implemented with
pinned fixtures and a disposable-Postgres contract suite. The binary is still
a server skeleton: the WebSocket gateway begins in M3. See
`docs/ROADMAP.md`.

## Provenance

AI agents write this repository under human direction. `PROVENANCE.md`
records which agent does what, and the trailer rules for commits.

## License

CC0-1.0. Public domain. No permission is necessary.
