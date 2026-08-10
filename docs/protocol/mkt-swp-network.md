# MKT-SWP relay-set and key-rotation boundary

The normative format is
[NIP-MKT-NETWORK](../../nips/openagents/MKT-NETWORK.md). It assigns public,
immutable digest kinds 39614 and 39615 to typed provider key-rotation and
relay-set events.

Clients and the provider use the selected effective relay set as one logical
transport: subscribe independently to every relay, publish identical signed
bytes to every reachable relay, and merge valid inputs by event ID. A failed
relay produces typed degraded state; it does not stop the remaining healthy
paths when the signed availability threshold still holds.

Provider identity is the genesis `provider_id`. A signed rotation chain maps
that stable identity to the signing key active at each event's `created_at`.
An in-flight session crosses the effective instant without changing its
idempotency scope, accepted terms, response authority, or external-effect
budget. Old-key events remain valid only when created before the boundary.

Network history is event-verifiable. Missing generations are incomplete,
invalid links fail closed, and competing successors are ambiguous. Mutable
HTTP state, DNS, relay arrival order, and natural-language announcements never
repair or choose a signed chain.

Neither event adds custody or settlement authority. Relay URLs and public
keys are public metadata; secrets and rail artifacts remain prohibited.
