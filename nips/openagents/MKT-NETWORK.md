# NIP-MKT-NETWORK

## Relay-set operation and provider key rotation

`draft` `optional`

Version 1 removes a single relay URL and a single provider key as implicit
network authorities. It defines two public, immutable, provider-signed events
and the deterministic rules used by clients and providers while a market
session is in flight.

This revision does not create a coordinator, quorum service, wallet, or
settlement authority. Relays transport the same signed bytes. Provider keys
sign market claims; they do not hold principal by protocol.

## Identity and allocation

- Parent protocol: NIP-MKT
- Relay-set schema: `openagents.mkt.relay-set.v1`, version `1`
- Key-rotation schema: `openagents.mkt.key-rotation.v1`, version `1`
- Initially adopted profile: `mkt-swp` version `1`

| Kind  | Name                  | Publication              |
| ----- | --------------------- | ------------------------ |
| 39614 | Provider Key Rotation | public, immutable digest |
| 39615 | Provider Relay Set    | public, immutable digest |

Both events are addressable and use a unique content-derived `d`. A changed
body necessarily has a different `d`, so an ordinary NIP-01 addressable head
cannot replace prior signed history at the same coordinate. Deletion is not
rotation or relay-set revocation. Kinds `39616-39619` remain unallocated.

## Provider Relay Set (`kind:39615`)

A relay-set event is signed by the provider key active at `created_at`. Its
complete content is:

```json
{
  "effective_at": 1786291200,
  "generation": 1,
  "previous_relay_set_event_id": null,
  "provider_id": "<genesis provider pubkey>",
  "publish_minimum": 1,
  "read_minimum": 1,
  "relay_set_id": "<64-lower-hex>",
  "relays": [
    "wss://relay-a.example",
    "wss://relay-b.example"
  ],
  "schema": "openagents.mkt.relay-set.v1",
  "version": 1
}
```

Content is RFC 8785 canonical JSON. `relay_set_id` is lowercase SHA-256 of
the canonical content object with `relay_set_id` omitted. Required tags are:

- `d`, equal to `relay_set_id`;
- `provider`, equal to the stable `provider_id`;
- `generation`, equal to the content decimal;
- `effective_at`, equal to the content decimal;
- `alt`, exactly `MKT Provider Relay Set`; and
- for generations after one, one `e` reference marked `previous-relay-set`.

There are `2..=8` distinct relay URLs, sorted by their exact canonical bytes.
Only lower-case `wss://` origins are valid: no user information, query,
fragment, path other than `/`, IP-literal ambiguity, or trailing slash.
`publish_minimum` and `read_minimum` are each `1..=number of relays`.
Generation one has no predecessor and later generations increment by one,
reference the exact prior event, retain `provider_id`, and have strictly
increasing effective times.

A client chooses the highest complete generation effective at its observation
time. Two valid successors for one generation are an ambiguous fork and fail
closed. A missing predecessor is incomplete, not a reason to guess a set.

## Provider Key Rotation (`kind:39614`)

A rotation event is signed by the old key and links exactly one successor:

```json
{
  "effective_at": 1786294800,
  "generation": 1,
  "new_pubkey": "<64-lower-hex>",
  "old_pubkey": "<64-lower-hex>",
  "previous_rotation_event_id": null,
  "provider_id": "<genesis provider pubkey>",
  "rotation_id": "<64-lower-hex>",
  "schema": "openagents.mkt.key-rotation.v1",
  "version": 1
}
```

Content is canonical JSON. `rotation_id` is lowercase SHA-256 of the content
object with `rotation_id` omitted. Required tags are:

- `d`, equal to `rotation_id`;
- `provider`, equal to the stable `provider_id`;
- `generation`, equal to the content decimal;
- `effective_at`, equal to the content decimal;
- one `p` containing `new_pubkey`, an empty relay hint, and role `successor`;
- `alt`, exactly `MKT Provider Key Rotation`; and
- after generation one, one `e` reference marked `previous-rotation`.

The event `pubkey` MUST equal `old_pubkey`, `new_pubkey` MUST differ, and
`created_at <= effective_at`. Generation one has `provider_id == old_pubkey`
and no predecessor. Each next event increments generation, references the
exact prior event, uses its `new_pubkey` as `old_pubkey`, retains
`provider_id`, and has a strictly later effective time.

Two valid successors from one old key/generation are an ambiguous fork and
fail closed. A missing predecessor is incomplete. Signatures, IDs, canonical
content, tags, and every chain link are verified before any successor is
honored.

For a provider-authored market event at time `t`, the authorized signer is
the last successor whose rotation `effective_at <= t`, or `provider_id` when
none is effective. At the boundary instant the new key is required. Event
arrival time and relay order do not affect this result. Sessions keep their
stable `provider_id`; rotation changes only the provider signing key.

## Multi-relay transport

Clients and providers open independent subscriptions to every relay in the
selected effective set and publish the exact same signed event to every
reachable relay. They never re-sign per relay.

- Publication succeeds after `publish_minimum` distinct relays acknowledge
  the exact event ID. Remaining relay failures are reported as degraded.
- A read set is available after `read_minimum` distinct relay subscriptions
  reach end-of-stored-events. One failed relay cannot block progress when the
  configured threshold still holds.
- Incoming events are merged by event ID only after normal ID and signature
  verification. Exact signed bytes are delivered once. Different signed bytes
  claiming the same ID are a typed invalid conflict and are never selected by
  arrival order.
- Each relay reconnects independently with bounded backoff. A dead relay does
  not tear down healthy subscriptions or publisher connections.
- History gaps remain incomplete. A threshold is availability policy, not a
  claim that missing events do not exist.

An implementation MUST support operation with any one configured relay down.
For the minimum two-relay set this means the version-1 thresholds are one.
Operators may configure stricter thresholds, but a client MUST NOT silently
weaken the signed values.

## Mid-session rotation

A client that begins a session under the old key retains the stable
`provider_id` and verifies each later provider event against the key active at
that event's `created_at`. An old-key event created before the boundary remains
valid when delivered afterward. An old-key event created at or after the
boundary is invalid. A new-key event created before the boundary is invalid.

Outstanding effectful intent idempotency scopes use stable `provider_id`, not
the currently active key, so rotation cannot permit a second external-effect
attempt. Response-encryption keys remain transport authority only. Re-drive
continues to return the original signed bytes across the rotation boundary.

## Event-only verification and limits

Relay-set history, rotation history, and provider-event signer selection are
verifiable from exact signed events alone. A verifier reports one of
`complete`, `incomplete`, `invalid`, or `ambiguous`; it never fills a missing
generation from a mutable API, DNS, configuration text, or natural language.

Public network events contain relay origins and public signing keys only.
They contain no secret key, credential, invoice, preimage, payment hash, raw
transaction, address, script, route, wallet material, or custody data. Each
content body is at most 8 KiB and each chain is bounded to 64 generations per
verification call.

## Conformance

Required fixtures cover canonical relay-set and rotation events, digest/tag
binding, invalid origins and thresholds, predecessor gaps, generation gaps,
forks, old/new signer selection on both sides of the effective instant,
mid-session rotation, exact event-ID deduplication, conflicting bytes for one
ID, stable idempotency scope across rotation, and one-relay-down publication
and subscription.
