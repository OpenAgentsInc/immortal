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
  transaction, preimage, and timelock cases. It also fixes the one permitted
  post-Order Quote-to-Contract resolution: a submarine requester adds the
  exact source funding transaction, digest, and output index while every
  quoted script, amount, other verifier, and other leg byte stays frozen. The
  module verifies public artifacts only and never accepts wallet keys,
  preimages for storage, node credentials, or broadcast authority.
- `provider/settlement-construction-v1.json` is a synthetic public provider
  authoring vector, not operator custody material. It binds the pinned
  BIP-341/342 and BOLT-11/payment-hash source boundary and fixes claim/refund
  unsigned bytes, signature messages, sighashes, deterministic signatures,
  witnesses, signed bytes, transaction IDs, fees, weights, and virtual sizes.
  The provider contract exports its exact digest.
- `lab/provisioning-v1.json` pins the non-secret #18 machine allocation: the
  shared regtest Bitcoin helpers including explicit RBF replacement, two
  provider-owned CLN nodes with required hold RPCs, a separate wallet CLN
  node, two relay/provider identities, balanced channel edges, teardown
  ownership checks, the digest-checked funded-smoke CLN-plus-hold image build,
  and hook-only LND/elementsd/arkd extension boundaries.
  It contains no node credentials or custody material and does not claim the
  owning rail issues are implemented.
- `nipmkt/swp-profile-v1.json` pins the relay-observable MKT-SWP v1 adoption
  at OpenAgents commit `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`:
  Offering grammar, kind-39610 profile binding and immutable wrapped
  publication, typed evidence references, receipt outcomes, custody-material
  tripwires, and the exact 70-case upstream client/handler manifest. Digest
  enforcement here is lower-hex shape plus tag/body equality; RFC 8785
  recomputation, bilateral agreement, lifecycle, funding, exit, and doomsday
  execution remain client/handler cases.
- `nipmkt/pfi-profile-v1.json` pins the relay-observable MKT-PFI v1 adoption
  at the same OpenAgents revision: closed public kind-39630 Qualification
  Policies, Offering asset/market/limit/policy/risk/rail grammar, redacted
  public receipts, and bounded commitment/evidence/dispute/recourse shapes.
  It exports all 41 upstream cases while keeping credential, rail, guarantee,
  reserve, dispute, external-effect, and recovery authority client-only.
- `nipmkt/mint-profile-v1.json` pins the relay-observable MKT-MINT v1
  adoption at OpenAgents revision `006b35b1f4`: Offering NIP-87
  cross-reference, rail, market, side, operation, protocol-revision, and
  mandatory custody-disclosure grammar; immutable wrapped kind-39640 Route
  Contracts; bounded evidence references with provenance overclaim floors;
  and bearer/discovery tripwires. It exports all 29 upstream cases while
  keeping wallet proof verification, native quote/payment verification,
  gateway selection, replay, expiry, recovery, and loss authority
  client-only.
- `nipmkt/p2p-profile-v1.json` pins the relay-observable MKT-P2P v1 adoption
  at OpenAgents commit `006b35b1f428a2e2a18931ff1546e5a09a8f8961`: Offering
  registry-asset/side/amount/payment-method/bridge/custody/bond grammar,
  immutable wrapped kind-39620 Resolutions with the exact role, previous,
  recipient, decision, scope, and evidence grammar, the closed NIP-69/Mostro
  source-reference mapping without signature upgrade, the admitted Status
  states, redacted public receipts, and per-trade-key non-linkage proofs.
  It exports all 26 upstream cases while keeping bond payment, hold-invoice
  and fiat verification, price-feed reproduction, solver/appeal admission,
  coordinator-independent recovery, and chargeback loss accounting
  client-only.
- `nipmkt/lsp-profile-v1.json` pins the relay-observable MKT-LSP v1 adoption
  at OpenAgents commit `006b35b1f428a2e2a18931ff1546e5a09a8f8961`: Offering
  node/network/lsps/market/side/channel-type/zero-conf/lease/payment-method/
  custody/reservation-class grammar, immutable wrapped kind-39650 Service
  Contracts with the exact causal, digest, signer, and firm-versus-indicative
  grammar, the closed LSPS0/1/2 source-reference mapping without signature
  upgrade, the admitted Status states, visible custody-class agreement, and
  recursive custody-material plus public invoice/SCID refusal. It exports all
  30 upstream cases while keeping LSPS execution, fee-promise and price-feed
  reproduction, reservation-proof accounting, funding and replacement
  verification, preimage-release discipline, unilateral close, recovery, and
  reorg loss accounting client-only.
- `nipmkt/swp-client-engine-v1.json` pins the transport-neutral requester
  engine: exact externally signed records, bilateral canonical contract
  binding, distinct submarine/reverse/chain funding and exit topology, Quote
  expiry and bounded Order selection, BOLT-11 expiry/final-CLTV checks, exact
  hashlock/CLTV/CSV execution, local post-broadcast Bitcoin observation,
  per-signer sequencing, wallet-owned claim/refund signing, idempotent external
  effects, rail-ordered crash recovery, keyless pre-signed broadcast, and
  recursive custody tripwires. It adds no relay-handler or settlement claim.
- `nipmkt/tbdex-legacy.json` adapts the field vocabulary and parse-vector
  shapes from `TBD54566975/tbdex` protocol 1.0 at commit
  `7546a079bb860e7ede8125739b7970810a2df314`, Apache-2.0. It records the
  exact upstream schema/vector paths and SHA-256 digests while replacing
  example values with non-sensitive Immortal fixtures. The exact Apache-2.0
  source bytes are pinned separately under `nipmkt/tbdex-upstream/schemas/`
  and `nipmkt/tbdex-upstream/vectors/` for test-only, byte-for-byte replay;
  they are client-scoped in the exported manifest and never compiled into the
  product binary. The corpus proves
  loss-accounted, non-executable projection audits, DID/JOSE refusal, and the
  RFQ detached-private-data commitment pattern without copying source
  credentials or payment details into the binary or relay state.
- `nipmkt/swp-coordination-v1.json` pins the optional noncustodial handler:
  exact-digest activation, signed capacity bounds, covenant reserve as the
  strongest hard proof class, attributable over-allocation/forks, dense
  Status gaps/forks, reservation-only timeout release, public Bitcoin
  observations labeled observation-not-authority, custody tripwires, and the
  two-process/one-Postgres proof.
- `nipae/`, `nipap/`, `niper/`, `nipmp/`, `nippl/`, `nipia/`, `nipdv/`,
  `nipwp/`, `nipcw/`, `niprs/`, and `nipgs/` each contain a committed server
  contract derived from the corresponding pinned Block text. They cover
  private-data ACLs, validators, relay commands and snapshots, safe query
  degradation, race-free standard relay semantics, the no-relay-handler Git
  signature case, and NIP-PL's fail-closed unadvertised executor posture.

- `bip327/` holds byte-exact copies of all eight official BIP-327 MuSig2
  vector files pinned at `bitcoin/bips`
  `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`. The complete valid and invalid
  corpus executes against the hand-written implementation, including key
  sorting, optional nonce inputs, infinity handling, deterministic signing,
  mixed tweaks, and final aggregation. `bip327/README.md` carries provenance,
  per-file digests, and replay details. These vectors are client-scoped in the
  exported manifest and never compiled into a product binary.

- `nipwk/work-records.json` pins NIP-WK (kinds 32170-32173) and NIP-PI
  (kind 32200) structural validation: required tags, the
  `<work_ref>:evt:<seq>` and `<work_ref>:obj:<revision>` address grammars,
  canonical decimals, the owner/actor principal markers, open state/domain/
  event vocabularies with preserved unknown tags, and the closed Issue
  priority list. Authority-key resolution is a client rule and is
  intentionally absent. Consumed by
  `crates/immortal-core/tests/allwork_fixtures.rs`.

Fixture data is committed rather than generated so a specification or
implementation change produces a reviewable diff.

Run the complete fixture layer manually with
`cargo test --locked --all-targets`. `docs/conformance/README.md` maps every
M1–M7 contract to its fixture, unit, live-Postgres, or process-level proof.
GitHub workflows and GitHub-billed automation are prohibited.
