# MKT-SWP settlement receipt boundary

The normative format is [NIP-MKT-RECEIPT](../../nips/openagents/MKT-RECEIPT.md).
It adds private kind 39613 and the closed `openagents.mkt.receipt.v1` object to
the revision-2 MKT-SWP intent chain.

The conformance boundary is event-only: exact signed Order, acknowledgment,
Quote, terminal Close, Settlement Receipt, and optional requester confirmation.
Implementations verify IDs, signatures, authors, references, session/profile
agreement, canonical JSON, receipt digest, bounds, amounts, outcome, and typed
failure code without consulting a relay database or provider API.

The provider persists one canonical signed receipt with a terminal Close.
Duplicate delivery, restart, and Re-drive return the original bytes. The relay
stores persistent NIP-59 wrappers and enforces the same private-kind search,
live-fanout, and immutable-coordinate policy as other MKT-SWP records. It does
not see or validate encrypted inner receipt claims.

Passing event-chain conformance does not prove external execution. Bitcoin,
Lightning, Liquid, Ark, and every other rail retain their native evidence and
finality authorities. Missing external proof is reported as missing; a
provider signature never upgrades it to verified settlement.
