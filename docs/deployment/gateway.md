# Gateway Runtime

M3 turns the domain and store libraries into the single Immortal relay binary.
The binary validates every environment value, migrates and verifies Postgres,
opens a fixed set of database workers plus one notification connection, and
only then binds its TCP listener. A startup failure therefore exposes no
partially current relay.

## HTTP and WebSocket

One listener serves all paths consistently:

- `GET /health` reports whether the process is current;
- a GET with `Accept: application/nostr+json` returns NIP-11 with CORS headers;
- a valid WebSocket upgrade enters the NIP-01 connection state machine; and
- other GET requests receive `426 Upgrade Required`.

Public TLS stays at Caddy, nginx, or the cloud edge. The binary speaks plain
HTTP and WebSocket on its private bind address.

Each WebSocket has one unpredictable NIP-42 challenge and a set of pubkeys
authenticated for the life of that connection. Setting
`IMMORTAL_AUTH_REQUIRED=true` gates both EVENT and REQ until at least one valid
kind-22242 event matches the challenge, configured relay URL, signature, and
ten-minute timestamp window. Authentication events are never published,
stored, or broadcast.

## Subscriptions and EOSE

The subscription hub has indexes for exact event ID, author, kind, and indexed
single-letter tag values. Live fanout unions only the buckets named by an
event, then applies the complete filters to those candidates. A time-only or
empty filter uses the explicit broad bucket; the gateway never walks every
subscription to find candidates.

An accepted REQ enters buffering before its database job begins. The job
samples a durable `ingest_seq` high-water mark and reads history only through
that point. The hub sends unique history, EOSE, then buffered durable events
above the boundary and buffered ephemeral events. Replaced REQs and CLOSE
cancel the old Postgres query and make late results harmless through a
connection-local generation number.

## Cross-process delivery

Stored admissions notify their committed `ingest_seq`; each process fetches
that exact validated row and applies its local subscription index. Admission
serializes sequence allocation immediately before insert, so sequence order is
commit order and the EOSE boundary is stable.

Ephemeral events are validated and policy-checked in the same admission
transaction but never inserted. After commit they enter the publisher's local
hub immediately. Their signed JSON also travels as bounded hexadecimal chunks
on the `immortal_ephemeral` Postgres notification channel. Other processes
reassemble and revalidate it in memory. A bounded recent-ID window removes the
publisher process's notification echo.

## Resource bounds and failure behavior

The gateway enforces the advertised frame, event, subscription, filter,
result, query-cost, and connection limits. Fixed-window rate limits apply per
IP to EVENT/AUTH and REQ and per pubkey to EVENT/AUTH. Database work uses only the fixed
`IMMORTAL_DB_CONNECTIONS` workers; connection send queues, EOSE buffers,
notification queues, command queues, handshake headers, WebSocket buffers,
and recent ephemeral IDs are all bounded.

A client disconnect, CLOSE, or replacement REQ cancels its historical query.
A full connection queue closes that connection. A failed database worker,
failed notification stream, malformed cross-process payload, or notification overflow
makes the whole process non-current: health changes, every connection closes,
and the binary exits non-zero so the service manager can restart it. SIGINT or
SIGTERM stops accept, cancels queries, closes connections, and drains within
`IMMORTAL_SHUTDOWN_GRACE_SECONDS`.
