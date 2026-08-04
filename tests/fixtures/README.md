# Domain Fixture Corpus

These fixtures test the pinned specifications under `nips/`. Each directory
names the NIP that owns the behavior.

## Provenance

- `nip01/events.json` contains the signed `hello world` event and canonical
  ID vector from `scsibug/nostr-rs-relay`, commit
  `b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4`, `src/event.rs`, MIT license.
  Its `tags: null` compatibility input was normalized to the NIP-01 wire form
  `tags: []`; the canonical bytes, ID, and signature are unchanged.
- `nip01/filters.json` adapts the filter-matching cases from the same commit's
  `src/subscription.rs`. Immortal changes the old prefix cases to assert exact
  matching because the pinned NIP-01 no longer allows prefix matching.
- `nip01/replacement.json`, `nip09/deletion.json`, and
  `nip40/expiration.json` were written for Immortal directly from the pinned
  NIP-01, NIP-09, and NIP-40 text.
- `nip01/gateway_messages.json`, `nip11/document.json`, and
  `nip42/auth.json` were written for Immortal directly from the pinned NIP-01,
  NIP-11, and NIP-42 texts. They pin gateway message shape, relay information,
  limit metadata, and canonical authentication acceptance boundaries. The M3
  live contract separately checks NIP-11 CORS behavior.
- `nip17/routing.json`, `nip29/groups.json`, `nip45/count.json`,
  `nip50/search.json`, `nip65/relay-list.json`, `nip70/protected.json`,
  `nip86/management.json`, `nip94/metadata.json`, `nip98/http-auth.json`,
  and `nipb7/servers.json`
  were written for Immortal from the corresponding pinned official texts.
  They pin M6 validation, routing, group action, COUNT, search, protected
  publishing, and HTTP-authentication boundaries. The live Postgres gateway
  contract checks the associated storage, access-control, signing, sweep,
  management, media metadata/server-list, and wire behavior.
- `nipoa/attestation.json`, `nipaa/auth.json`, `nipao/observer.json`, and
  `nipam/turn-metrics.json` pin the Block agent ownership, agent-authentication,
  ephemeral observer, and private turn-metric envelopes against Buzz commit
  `027a74a61c8643a1d1086d3e8307fad89d7735f7`.
- `nipotpg/project-read.json` was written for Immortal from the pinned
  OpenAgents NIP-OT and NIP-PG texts at upstream commit
  `d3bb7c51219e2473965ff6f576c1492b2aa99d31`. It pins the four Phase 0
  project-read kinds, invalid-tag boundaries, and the browser-neutral client
  EOSE/reconnect/fail-closed contract.
- `nipmkt/public-heads.json` was written for Immortal from the pinned
  OpenAgents NIP-MKT text at upstream commit
  `b839dd43bad7915a35639b562d4d7ebf7d51c3f6`. It pins the relay-observable
  required tags, identifier and enum boundaries, and content limits for the
  four public discovery kinds without treating relay acceptance as proof of
  provider capacity or settlement.
- `nipmkt/immutability.json` pins the NIP-MKT private-kind allocation, exact
  replay, changed-ID and changed-signature conflict outcomes, stable gateway
  reason, and bounded-model action space. The corresponding model exhausts
  admission, deletion, expiration, and restart histories without using the
  implementation transition as its oracle.
- `nipmkt/common-grammar.json` pins the profile-neutral grammar, recursive
  duplicate-JSON rejection, envelope agreement, reference/tag failures,
  inclusive bounds, stable validation error codes, the empty executable-profile
  posture, and a synthetic profile contract used only to prove profile-aware
  fail-closed behavior and authoritative raw-byte retention.
  `tests/mkt_common_fixtures.rs` labels relay-visible, raw client/handler, and
  profile-aware assertions rather than claiming the relay can inspect an
  encrypted NIP-59 payload.
- `nipmkt/gateway-policy.json` pins the bare-private refusal, authenticated
  self-scoped gift-wrap reads, all five read surfaces, and rate dimensions.
  It names the signed kind-1059 pubkey as the outer wrapper pubkey because the
  logical inner sender is encrypted and relay-opaque.
- `nipmkt/relay-closing.json` closes the relay-observable M10 corpus across
  malformed grammar, duplicate JSON, profile scope, immutable changed bytes,
  rewrapped transport, inclusive expiration, bare-private refusal, rate keys,
  and the complete `39600-39699` classification. `nipmkt/client-only-cases.json`
  is the structured M11 consumer manifest for supersession, reservation,
  sequence, wrapper/inner, evidence, recovery, authorization, expiry, and
  settlement cases that Immortal deliberately does not claim to enforce.
- `nipmkt/swp-verification.json` pins the MKT-SWP client/handler verification
  foundation to primary BIP-341, BIP-327, and BOLT-11 vectors plus bounded
  transaction, preimage, and timelock cases. The module verifies public
  artifacts only and never accepts wallet keys, preimages for storage, node
  credentials, or broadcast authority.
- `nipmkt/swp-profile-v1.json` pins the relay-observable MKT-SWP v1 adoption
  at OpenAgents commit `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`:
  Offering grammar, kind-39610 profile binding and immutable wrapped
  publication, typed evidence references, receipt outcomes, custody-material
  tripwires, and the exact 70-case upstream client/handler manifest. Digest
  enforcement here is lower-hex shape plus tag/body equality; RFC 8785
  recomputation, bilateral agreement, lifecycle, funding, exit, and doomsday
  execution remain client/handler cases.
- `nipae/`, `nipap/`, `niper/`, `nipmp/`, `nippl/`, `nipia/`, `nipdv/`,
  `nipwp/`, `nipcw/`, `niprs/`, and `nipgs/` each contain a committed server
  contract derived from the corresponding pinned Block text. They cover
  private-data ACLs, validators, relay commands and snapshots, safe query
  degradation, race-free standard relay semantics, the no-relay-handler Git
  signature case, and NIP-PL's fail-closed unadvertised executor posture.

Fixture data is committed rather than generated so a specification or
implementation change produces a reviewable diff.

Run the complete fixture layer manually with
`cargo test --locked --all-targets`. `docs/conformance/README.md` maps every
M1–M7 contract to its fixture, unit, live-Postgres, or process-level proof.
GitHub workflows and GitHub-billed automation are prohibited.
