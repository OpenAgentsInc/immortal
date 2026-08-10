# MKT-SWP revision-2 hardening

Immortal adopts `nips/openagents/MKT-HARDENING.md` as the revisioned network
failure contract for MKT-SWP. Revision-2 inner events use
`openagents.mkt.v2` plus `protocol_rev: 2`; revision-1 records keep their
existing meaning and never receive acknowledgment or replay guarantees by
inference.

The relay treats `kind:39611` Intent Acknowledgment and `kind:39612` Re-drive
Intent exactly like every other private MKT signed record: immutable internal
admission, no bare public publication, no search vector, no broad query or
live fanout, and opaque persistent NIP-59 delivery. It can verify inner grammar
only on an authorized visible/internal path. It cannot see a wrapped nonce,
response key, acknowledgment, or outcome.

The provider owns the effect boundary. Before one accepted Order can reach an
external rail, it durably records the scoped idempotency binding and the exact
provider-signed acknowledgment. Exact replay returns that acknowledgment and
recorded outcomes. A key or nonce conflict fails typed. A Re-drive is always
read-only: it returns exact durable signed events and cannot create a reserve,
wallet, rail, settlement, or retry effect.

Response encryption is deliberately separate from identity. The signed Order
author remains the only requester authority. The optional response pubkey is
an x-only Nostr key used only as the NIP-59 recipient for provider responses;
the acknowledgment still binds the requester identity and provider identity.

The fixed reference window is 300 seconds past and 60 seconds future at
provider observation, with nonce retention of at least 24 hours. The signed
client deadlines are bounded to 1-60 seconds for acknowledgment and from that
value through 86,400 seconds for outcome. Runtime policy may be stricter but
must not widen those limits.

No invariant changes custody or settlement authority: the relay holds no
funds, the provider performs at most one attempt for an accepted intent, and
events prove only signatures, bytes, correlation, and recorded claims.
