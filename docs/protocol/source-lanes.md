# NIP Source-Lane Decisions

These decisions apply to the exact upstream commits in `nips/manifest.json`.
The official lane wins any identifier conflict unless the owner records an
exception. No M6 exception was approved. The table is the historical M6
deployment snapshot; the 2026-08-04 directive below supersedes its earlier
deferrals as future-scope decisions without pretending the runtime already
implements them.

| Lane | Decision for M6 |
| --- | --- |
| `official` | Implement the pinned NIP-17, NIP-29, NIP-40, NIP-45, NIP-50, NIP-65, NIP-70, NIP-86, and NIP-98 behavior described in `nip-expansion.md`. Watch NIP-77 without implementing it. NIP-91 is absent from this pinned lane, so do not advertise or implement it. |
| `block` | Owner adoption on 2026-08-03 pulled all 15 pinned custom specifications forward: NIP-AA, AE, AM, AO, AP, CW, DV, ER, GS, IA, MP, OA, PL, RS, and WP. The exact server contract and deliberate non-advertisement cases are in `block-nips.md`; no identifier conflicts with the official lane were introduced. |
| `openagents` | Owner direction on 2026-08-03 lifted the upstream postponement note for NIP-AC, DS, LBR, SA, SKL, and TRN. Operation Diamond Hands issue #1 adopted NIP-OT Organization kind `32100` and NIP-PG Project/Status/Update kinds `32222`, `32223`, and `32226` as a client read projection, with `nipotpg` fixtures. Other OpenAgents NIPs were not yet adopted in the M6 runtime snapshot. These proposal identifiers are not numeric official NIP numbers and therefore add nothing to NIP-11 `supported_nips`. |

The source files remain pinned protocol inputs, not claims of current runtime
support. A future implementation packet must name the exact lane and
identifier, add a fixture, and update NIP-11 only when it corresponds to a
numeric NIP-11 identifier and the implementation passes the local conformance
gate.

## 2026-08-04 full-lane directive

The owner has now adopted **every pinned specification in the official,
Block, and OpenAgents lanes as an implementation target**. This includes
NIP-PL's configured executor profile, NIP-CW's optional query surface, all
OpenAgents hardening families, and NIP-BT after the first liquidity slice.
“Not yet implemented,” “not advertised,” and prior postponements remain
accurate current-state facts only. They are not permanent scope boundaries.

Complete adoption covers the role actually specified: relay/server handlers,
transport-neutral native/browser client behavior, and bounded operator,
provider, or executor behavior as applicable. Deprecated or unrecommended
texts receive compatibility implementations and fixtures; they do not force
new design onto obsolete envelopes. Missing noncustodial market primitives
will be authored as focused OpenAgents NIPs and then enter the same pin,
fixture, implementation, and conformance process.

## M7 decision

The official lane's pinned NIP-B7, NIP-94, and NIP-98 drive M7. NIP-B7 points
outside the NIP repository for the Blossom HTTP contract, so the reviewed
external input is recorded separately in `media.md` at an exact commit. The
roadmap's NIP-98 choice wins over current Blossom BUD-11 kind-24242
authorization. M7 itself created no identifier-precedence exception. The later
owner-directed Block adoption is recorded above; OpenAgents specifications
remain parked.

## M10 decision (2026-08-04)

The 2026-08-04 sync advanced the `openagents` lane: it now pins NIP-MKT
(`MKT.md`, the negotiated-market base on kinds `39600-39609` with
`39610-39699` reserved) and `NIP90-MIGRATION.md` (the upstream NIP-90
unrecommended status and the compatibility freeze annotated into AC, CN, DS,
LBR, SA, SKL, and TRN). The `block` lane repinned with no spec content
changes.

Owner direction on 2026-08-04 selects NIP-MKT from the `openagents` lane as
the **first implementation slice** of the full-lane directive above, ahead
of the other lane items and ahead of M8/M9 — see the M10 and M11 milestones
in `docs/ROADMAP.md`. The adoption discipline is unchanged: the
implementation lands with its fixture corpus, the `39600-39699` collision
review is repeated at the pinned commits before any kind is treated as
allocated, and NIP-11 advertises NIP-MKT only after the local conformance
gate passes. The NIP-90 freeze means no new NIP-90 job kinds or semantics
are implemented in any lane; existing NIP-90 material is read-compatibility
only. The remaining `openagents` specifications stay implementation targets
under the full-lane directive and enter the runtime through their own
sequenced packets, each with the same fixture and conformance gate.

### M10 collision re-review

Before implementing the public discovery heads, the complete
`39600-39699` range was reviewed again against each exact source commit in
`nips/manifest.json` and the upstream registry-of-kinds:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No assignment in `39600-39699`; pinned NIP-B0 assigns `39701`. |
| Block NIPs | `feccf4eabc23fdba94ce3537a194357ed17b197c` | No assignment in `39600-39699`. |
| OpenAgents NIPs | `b839dd43bad7915a35639b562d4d7ebf7d51c3f6` | Only NIP-MKT claims the range: `39600-39609` for the base and `39610-39699` reserved and unallocated. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` | No entry in `39600-39699`; the nearest higher entry is `39701`. |

The review found no collision. Immortal therefore admits NIP-MKT public kinds
`39600-39603` under their pinned domain rules. It does not allocate any kind
in `39610-39699`. The registry result is a review input, not a new pinned
source lane; future profile allocations still require a fresh review.

### M10 adoption completion

M10 implements the NIP-MKT base at OpenAgents commit
`b839dd43bad7915a35639b562d4d7ebf7d51c3f6`. Kinds `39600-39603` are public
discovery heads; `39604-39609` are immutable signed records transported only
inside recipient-gated NIP-59 kind-1059 wraps; `39610-39699` remain reserved
and unallocated. The server contract is
[`nip-mkt-validation.md`](nip-mkt-validation.md), and the relay plus
client-only fixture manifests live under `tests/fixtures/nipmkt/`.

Immortal validates only public data, visible internal records, and outer
transport metadata. It cannot inspect encrypted inner terms or prove profile
execution, reservation, evidence, recovery, or settlement. Its executable
profile set is empty, and the NIP-90 freeze remains in force. No identifier
precedence exception was created. After the full local M10 conformance gate
passed, NIP-11 began advertising the nonnumeric `nip-mkt` extension only when
`IMMORTAL_RELAY_URL` enables NIP-42 recipient authentication. That extension
means base discovery and wrapped transport, not an executable profile.

## M12 verification decision (2026-08-04)

The pre-profile sync at Immortal commit `553ef643e122a58a24603fe14d1b5c62b6868e27`
advances the OpenAgents lane to `f62eab5569d9e8a7b807a78094dd51bc36a4d31b`
and NIP-MKT v0.1. Immortal adopts its profile-neutral vocabulary rules for
asset-ID pairs, decimal-string amounts, disabled sides, fee promises, pinned
price feeds, future EVM-leg terms, and covenant reserve proof classes as input
to the MKT-SWP/MKT-PFI drafts. The sync allocates no profile kind, enables no
executable profile, and changes no NIP-11 advertisement. The generated
contract and fixture manifest record the new source revision.

Issue #10 adopts verification algorithms and vectors directly from BIP-340,
BIP-341, BIP-342, BIP-327, and BOLT-11. They are primary rail specifications,
not a fourth NIP source lane and not an allocation in `39610-39699`.

Immortal implements the bounded, public-data subset needed to verify a future
MKT-SWP profile: transaction and swap-script structure, Taproot commitments,
MuSig2 aggregate keys and final signatures, invoice signatures and hash
coupling, and timelock relations. Wallet signing, secret nonces, preimage
custody, node credentials, chain indexing, broadcast, payment, and finality
remain with external wallets and rail authorities. The feature does not change
NIP-11 advertisement and does not make an MKT-SWP revision executable; that
adoption waits for its upstream profile, collision review, fixtures, and local
conformance gate.

## M12 MKT-SWP adoption decision (2026-08-04)

The issue #11 sync advances the pinned lanes to official
`c53877571f96eb423661fc23c620d629d37b8f19`, Block
`540b58920cef205b838da8be8442aae62bceaaa5`, and OpenAgents
`a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`. The OpenAgents revision adds
MKT-SWP v1 and MKT-PFI v1; this packet adopts only the relay-observable
MKT-SWP surface. MKT-PFI remains pinned input for issue #17.

Before allocating `kind:39610`, fresh clones of all three lanes and the Nostr
kind registry were reviewed at these exact revisions:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No semantic assignment in `39610-39699`; search hits were unrelated hexadecimal fixture substrings. |
| Block NIPs | `540b58920cef205b838da8be8442aae62bceaaa5` | No semantic assignment in `39610-39699`; search hits were unrelated hexadecimal fixture substrings. |
| OpenAgents NIPs | `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682` | NIP-MKT assigns private immutable `39610` to the MKT-SWP Swap Contract and public `39630` to MKT-PFI; all other matches are the same reservation and profile text. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` | No entry in `39610-39699`. |

The review found no collision and creates no lane-precedence exception.
Immortal therefore allocates `39610` as an addressable,
immutable-by-contract signed record that is accepted only inside recipient-
gated NIP-59 transport. Kinds `39611-39629` and `39631-39699` remain
unallocated here; `39630` is not adopted by this packet.

The runtime validates MKT-SWP v1 Offering grammar, exact asset/network and
decimal-string bounds, side-disable and fee laws, typed evidence references,
public receipt outcomes, Swap Contract tags and digest agreement, and custody-
material tripwires on records visible to an authorized profile consumer. The
transport relay still cannot decrypt arbitrary gift wraps and does not claim
to verify lifecycle execution, capacity, funding, exits, or settlement. The
exported contract therefore lists `mkt-swp:1` as `relay_observable_only` and
keeps the executable-profile set empty.

After the active local Postgres and conformance gate passes, NIP-11 advertises
`mkt-swp:1` only when `IMMORTAL_RELAY_URL` enables authenticated recipient
transport. That extension identifies the relay-observable v1 wire surface; it
is not a client-engine, coordination-handler, wallet, or settlement claim.

## M12 tbDEX compatibility decision (2026-08-04)

Issue #16 harvests the hosted JSON schemas and protocol parse vectors from
`TBD54566975/tbdex` protocol 1.0 at exact commit
`7546a079bb860e7ede8125739b7970810a2df314`, Apache-2.0. This archived donor is
not a fourth NIP source lane. The fixture record preserves the exact upstream
paths and source-byte SHA-256 digests; the test-only fixture tree pins and
replays those exact bytes while adapted cases use non-sensitive placeholder
values. The pinned donor bytes remain client-only and are not compiled into
the binary or admitted to relay state.

Immortal adopts the balance, Cancel, Close, Offering, Order,
OrderInstructions, OrderStatus, Quote, RFQ, and detached-RFQ field vocabulary
as a transport-neutral compatibility audit. It does not adopt tbDEX DID, JOSE,
HTTP, DWN, credential, custody, or settlement authority. Every harvested
message has DID/JOSE authority that cannot become a NIP-01 signature, so the
translator returns a deterministic non-executable audit with
`tbdex_unrepresentable_authority`, a source digest, mapping revision, and
complete dropped/defaulted/ambiguous-field lists. Balance, OrderInstructions,
OrderStatus, and Close also carry `tbdex_unrepresentable_state` where the base
cannot represent authority, sequence, evidence, or terminal truth. No target
event, target signature, reservation, custody fact, or settlement fact is
created.

The adopted Cancel projection defaults only to `action=request`; a legacy
request never becomes effective cancellation. OrderInstructions remains a
distinct provider step, represented only as a candidate
`Status state=funding_required`: instruction bytes stay in a direct protected
channel while an executable profile must bind their digest, expiry,
correlation, exact Order reference, sequence, and signer. The RFQ privacy
fixture follows the protocol README's Digests/privateData rule: JCS over the
JSON array `[salt, value]`, then SHA-256 and unpadded base64url. The independent
implementation record is `TBD54566975/tbdex-rs` commit
`c3d49855b4099fa663ca14c5c79e8b1e6cd8bc65`,
`crates/tbdex/src/messages/rfq.rs::digest_private_data`, which constructs the
same array and passes it through `serde_jcs`. The fixture verifies that shape
as a positive/negative pair, rejects attached private data with no verified
commitment, and accepts the deliberate detached form only after validating the
full public envelope without persisting cleartext. This in-repo parser
deliberately rejects private JSON
numbers until it has a complete RFC 8785 number encoder; it fails closed
instead of approximating JCS.

This client-only compatibility surface allocates no event kind, changes no
relay admission or Postgres state, adds no dependency, and changes no NIP-11
advertisement. Its fixture is exported in the deterministic contract manifest
for downstream SDK consumers.

## M12 MKT-PFI adoption decision (2026-08-04)

Issue #17 adopts the relay-observable subset of MKT-PFI v1 from the already
pinned OpenAgents commit `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`.
Before allocating `kind:39630`, fresh clones of the three NIP lanes and the
kind registry were reviewed again:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No assignment in `39630-39639`. |
| Block NIPs | `540b58920cef205b838da8be8442aae62bceaaa5` | No assignment in `39630-39639`. |
| OpenAgents NIPs | `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682` | MKT-PFI assigns public Qualification Policy `39630`; `39631-39639` remain reserved and unallocated. All other hits are the profile specification or NIP-MKT reservation. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` | No entry in `39630-39639`. |

The review found no collision and creates no lane-precedence exception.
Immortal therefore admits `39630` as an ordinary public addressable
replacement head. Kinds `39631-39639` and all other unadopted profile kinds
remain unallocated.

The relay validates the policy's exact tags, content-byte digest, closed
nested shape, bounds, and public privacy tripwires. It also validates
MKT-PFI Offering asset pairs, market digest, decimal-string limits, disabled
sides, fee cap, exact policy references, discovery risk/rail vocabulary, and
closed custody labels. An authorized profile consumer can apply bounded
shapes to credential commitments, evidence references, risk, dispute, and
recourse after decryption. Credential and evidence bytes, bearer references,
bank instructions, and custody material remain forbidden.

The 41-case upstream manifest is exported without claiming the client-only
credential, rail, guarantee, reserve, dispute, external-effect, or recovery
cases as relay enforcement. Those authorities remain external. The contract
lists `mkt-pfi:1` as `relay_observable_only`, keeps executable profiles empty,
and advertises `nip-mkt-pfi:1` only under the authenticated relay URL gate
after the complete local relay-observable conformance gate passes.

## M12 coordination-handler decision (2026-08-04)

Issue #13 adopts MKT-SWP v1 section 5 reservation accounting, section 9.5
Status gap/fork surfacing, and section 11 evidence authority for an optional
handler in the existing relay binary. The exact OpenAgents source remains
`a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`. NIP-32 from the pinned official
lane supplies the relay-signed public observation label. The Satora review
adds covenant reserve as the strongest `hard` proof class and rejects an
on-relay orderbook of price-welded outputs.

The base commitment keeps total capacity private. The separately advertised
handler extension therefore adopts one private nested member,
`reservation_terms.handler_committed_capacity`, as a provider-signed canonical
decimal used only for the section 5 inequality. This is an extension contract,
not a change to the pinned MKT-SWP schema. Its exact bytes and behavior are
pinned by the coordination fixture and activation digest.

This adoption allocates no event kind in `39610-39699`, so it does not trigger
a new kind allocation or collision exception. Private coordination arrives as
an additional handler-addressed kind-1059 delivery; public observations use
the already assigned official kind 1985. The active handler advertises
`mkt-swp-coordination:1` and NIP-32 only after its compiled fixture/migration/
configuration digest exactly matches operator configuration and the local
two-process Postgres conformance gate passes.

The handler owns accounting observations, not participant or rail authority.
It stores bounded signed identifiers and hashes, releases only reservation
state on timeout, and cannot sign participant transitions, hold custody
material, operate a wallet or node, or assert payment/finality. Its complete
boundary is [`mkt-swp-coordination.md`](mkt-swp-coordination.md). No source-
lane precedence exception was created.

## M12 MKT-SWP client execution decision (2026-08-04)

Issue #12 consumes the already pinned OpenAgents MKT-SWP v1 text at
`a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`. It allocates no new kind and
therefore does not repeat or alter issue #11's three-lane and registry
collision result: `39610` remains the sole adopted Swap Contract kind and
`39611-39629` plus `39631-39699` remain unallocated here.

The transport-neutral client now constructs the six private base records and
bilateral Swap Contracts through exact external signing requests. It binds
both signers to RFC 8785-compatible contract terms, projects independent
Status streams without hiding gaps or forks, and implements submarine,
reverse, and chain verification with the issue-#10 Bitcoin/Lightning
primitives. Funding authority exists only after that verification and an
embedding-wallet callback succeed. Restored snapshots always return to the
unverified state.

The requester flow is frozen per rail: submarine broadcasts `source` Bitcoin
funding and retains a CLTV refund, reverse pays `lightning` and retains the
`destination` hashlock claim, and chain broadcasts `source`, retains its CSV
refund, and claims `destination`. Quote expiry is checked at Order acceptance;
Order selection is limited to the four upstream-selectable fields. BOLT-11
expiry and minimum-final-CLTV are parsed and bound before payment. Bitcoin
confirmation, replacement, and competing-spend observations enter through an
explicit local adapter after template authorization.

Exit packages bind each executable claim or refund path and its public
verification requirements. Their package digest commits the execution fields
but excludes the two Swap Contract IDs and shared contract digest to avoid a
circular event-ID commitment. The complete package still carries and
revalidates those exact bilateral bindings. Wallet and external-signer
callbacks own all signatures. Hashlock, CLTV, and CSV leaves are executed
against exact witness and transaction conditions; only timeout exits may be
pre-signed. A complete pre-signed timeout exit can also produce a keyless
public Esplora broadcast request for the doomsday path. Chain recovery follows
destination-then-source rail state and never effect-ID ordering.

This adoption adds deterministic fixtures and machine-contract metadata but
no dependency, server handler, database state, custody material, rail
credential, or settlement authority. It does not change NIP-11: the relay's
`mkt-swp:1` claim stays observable-only and its executable-profile set remains
empty until issue #13 passes its active-configuration conformance gate.

The final #12 audit keeps invalid Status claims and their descendants visible
without advancing them; binds effective cancellation to separate requester
request and provider-accept references; and derives the irreversible boundary
from signed Status history as well as the persisted effect ledger. Close
evidence must name the exact contract artifact or persisted result digest and
use the contract-pinned local or external verifier authority. Failure,
dispute, and unresolved outcomes retain their distinct section-15 accounting
bases.

The closing audit also requires the incoming base `state` to match the
profile `swp_state`, evaluates Close ancestry only on the Close signer's
stream, and permits either consenting participant to author the effective
Cancel. Snapshot schema v2 persists every typed effect request beside its
result row. Rail and Lightning-disposition evidence therefore requires an
exact durable funding effect while remaining crash-restorable before a signed
terminal record cites it. Unknown failure accounting can cover only its
contract-bounded fee capacity and cannot hide principal; reverse destination
refund recovery branches on the observed Lightning disposition instead of
claiming counterparty completion.

The exported client corpus was narrowed from descriptive proxy names to 62
closed-world cases that invoke production validators and actions, backed by
exact serialized sessions. It covers all six terminal flows, all bounded
verify-before-fund refusals, the two-stage reverse gate, sequencing, both
orphan-effect crash windows, cancellation, loss, and recovery. Twenty custody
tripwires separately invoke the recursive production validator. No source-lane
precedence exception, kind allocation, dependency, or relay advertisement was
added.

Client transport now exposes typed callback requests for event signing and
NIP-44 encryption/decryption for both the participant and one-time NIP-59
wrapper identity. This is an API adoption of the existing M10 transport lane,
not a new protocol source: browser and GPUI identity services can fulfill the
plan without exporting raw secret bytes, while `MarketSigner` remains the
deterministic fixture/development adapter.

## M12 MKT-SWP provider-session decision (2026-08-04)

Issue #14 implements the provider role of the same pinned OpenAgents MKT-SWP
v1 text at `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682`. It allocates no kind and
does not change the collision result from issue #11: `39610` remains the sole
Swap Contract kind, with the rest of the reserved ranges unallocated here.

The provider engine shares the requester engine's complete Quote and Swap
Contract validators. It creates indicative, soft-reserved, and hard-reserved
Quotes; a hard Quote cannot be signed until an embedding reservation callback
returns an exact durable confirmation. Reserve and release requests have
stable effect IDs and replay bindings. Signed session ingestion requires one
immutable RFQ, Quote, and Order, one contract per participant with identical
terms, signer-local lifecycle claims, and exact no-spend loss accounting.
Status gaps, forks, and invalid transitions remain visible without becoming
authority.

The executable `immortal-provider --no-spend` mode is a persistent NIP-59
actor for loopback development. It recovers provider-addressed self-wraps,
reconstructs bounded sessions, and completes submarine, reverse, and chain
negotiations through mutual cancellation and a zero-loss Close. It has no
funding, wallet, rail, node, database, or settlement capability. The funded
rail process and its deterministic provider contract export remain issue #25.

This packet adds no dependency to the relay, changes no relay CLI or contract
JSON, does not advertise a new NIP-11 extension, and leaves the relay's
executable-profile set unchanged. Provider fixture scope is recorded
separately in the shared fixture manifest. No source-lane precedence
exception was created.

## M13 MKT-MINT adoption decision (2026-08-05)

Issue #22 adopts the relay-observable subset of MKT-MINT v1 from the freshly
synced OpenAgents commit `006b35b1f428a2e2a18931ff1546e5a09a8f8961`. Before
admitting `kind:39640`, fresh clones of the three NIP lanes and the kind
registry were reviewed again:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No assignment in `39640-39649`. |
| Block NIPs | `8342dfcc5890b81a269a8ec3db73a8a56f76ce79` | No assignment in `39640-39649`; the only textual hits are hex-encoded fixture blobs. |
| OpenAgents NIPs | `006b35b1f428a2e2a18931ff1546e5a09a8f8961` | MKT-MINT assigns private immutable `39640` to the Mint Route Contract; `39641-39649` remain reserved and unallocated. All other hits are the profile specification and NIP-MKT reservation text. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` | No entry in `39640-39649`; the nearest registered `39xxx` kinds are `39000-39003`, `39089`, `39092`, and `39701`. |

The review found no collision and creates no lane-precedence exception.
Immortal therefore admits `39640` as an eighth private immutable NIP-59-only
kind bound to exactly `mkt-mint` v1. Kinds `39641-39649` and all other
unadopted profile kinds remain unallocated.

The adoption is deliberately thin. Official NIP-87 remains the discovery
authority: every MKT-MINT Offering must cross-reference exactly one
`kind:38172` (Cashu) or `kind:38173` (Fedimint) announcement by exact
address and event ID, a `kind:38000` recommendation is refused as authority,
and members that copy a mint URL, federation invite code, NUT list, module
list, or operator claim into a new discovery authority are refused as
`mkt_mint_discovery_duplication`. Cashu NUTs and the Fedimint protocol
remain the rail authority; the relay never verifies a keyset, proof, quote,
federation configuration, gateway, payment, or consensus fact.

Custody disclosure is a relay admission check wherever it is observable. The
profile discloses exactly two custody classes — `a3-mint` for a Cashu route
and `a2-federation` for a Fedimint route — and the validator requires the
Offering `custody_class` (and any custody class visible to an authorized
profile consumer) to equal the rail's class. There is no admissible spelling
under which a mint-custodial or federation-custodial route presents itself
as noncustodial; the local admission code
`mkt_mint_custody_disclosure_mismatch` records that refusal, and the spec's
error vocabulary otherwise maps onto the exported `mkt_mint_*` codes.
Evidence references carry the seven provenance labels with two overclaim
floors the relay can see: a quote-typed receipt cannot claim `paid`,
`issued`, `refunded`, or `settled`, and payment evidence cannot claim
`issued`.

The 29-case upstream manifest is exported without claiming the client-only
wallet-verification, keyset/configuration pinning, price-feed, gateway
selection, replay, expiry, privacy-wrap, recovery, or loss cases as relay
enforcement. Those authorities remain external. The contract lists
`mkt-mint:1` as `relay_observable_only`, keeps executable profiles empty,
and advertises `nip-mkt-mint:1` only under the authenticated relay URL gate
after the local relay-observable conformance gate passes. The optional
`cdk-mintd` lab leg for issue #18 remains future work and is not part of
this packet.

## M13 MKT-P2P adoption decision (2026-08-04)

Issue #21 adopts the relay-observable subset of MKT-P2P v1 from the
2026-08-04 lane sync at OpenAgents commit
`006b35b1f428a2e2a18931ff1546e5a09a8f8961` (MKT.md v0.3 and `MKT-P2P.md`).
Before allocating `kind:39620`, fresh clones of the three NIP lanes and the
kind registry were reviewed again:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No assignment in `39620-39629`. |
| Block NIPs | `8342dfcc5890b81a269a8ec3db73a8a56f76ce79` | No assignment in `39620-39629`; the only `3962x` byte match is inside a NIP-OA hex example. |
| OpenAgents NIPs | `006b35b1f428a2e2a18931ff1546e5a09a8f8961` | MKT.md v0.3 assigns private immutable `39620` to the MKT-P2P Resolution; `39621-39629` remain reserved and unallocated. All other hits are the profile specification or reservation text. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` (current HEAD at review time) | No entry in `39620-39629`; the nearest higher registered kind is `39701`. |

The review found no collision and creates no lane-precedence exception.
Immortal therefore admits `39620` as a private immutable NIP-59-only kind
under the same store/gateway rules as `39610` (migration 0012). Kinds
`39621-39629` and all other unadopted profile kinds remain unallocated.

The relay validates MKT-P2P Offering registry asset pairs, the explicit
buy/sell disable law, canonical decimal amounts, payment-method identifier
bounds, the amount-mode vocabulary, a bounded NIP-69 source declaration, the
exact `a1-coordinated-hold` custody class, the bond-policy summary shape, the
dispute-policy digest shape, and public PII/private-material refusal on
Offerings and receipts. An authorized profile consumer can apply the exact
Resolution grammar (role, order/previous consistency, recipient roles,
decision and scope vocabularies, evidence provenance), the closed
NIP-69/Mostro source-reference mapping, and the admitted Status-state set
after decryption. NIP-69 and Mostro source events stay canonical for their
own meaning: the mapping proves only the reference and never upgrades the
source signature, escrow, reputation, payment, or dispute authority.

The 26-case upstream manifest is exported without claiming the client-only
bond, hold-invoice, fiat-payment, price-feed, solver-set, appeal,
coordinator-independent-recovery, replay-side-effect, or chargeback-loss
cases as relay enforcement. Per-trade key rotation is respected: the
fixtures prove two sessions under distinct trade keys validate with no
identity-linkage member, and public records refuse trade-key-linkage members
outright. The contract lists `mkt-p2p:1` as `relay_observable_only`, keeps
executable profiles empty, and advertises `nip-mkt-p2p:1` only under the
authenticated relay URL gate after the complete local relay-observable
conformance gate passes.

## M13 MKT-LSP adoption decision (2026-08-04)

Issue #23 adopts the relay-observable subset of MKT-LSP v1 from the
2026-08-04 lane sync at OpenAgents commit
`006b35b1f428a2e2a18931ff1546e5a09a8f8961` (MKT.md v0.3 and `MKT-LSP.md`,
aligned with bLIP-50 LSPS0, bLIP-51 LSPS1, and bLIP-52 LSPS2 at
`lightning/blips` revision `ca04f374d03001ddbed60ff109da58bd9c390c9a`).
Before allocating `kind:39650`, fresh copies of the three NIP lanes and the
kind registry were reviewed again:

| Source | Reviewed revision | Result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | No assignment in `39650-39659`; the only `3965x` byte match is inside a NIP-26 signature example. |
| Block NIPs | `8342dfcc5890b81a269a8ec3db73a8a56f76ce79` | No assignment in `39650-39659`; the only byte match is inside a NIP-OA hex example. |
| OpenAgents NIPs | `006b35b1f428a2e2a18931ff1546e5a09a8f8961` | MKT.md v0.3 assigns private immutable `39650` to the MKT-LSP Service Contract; `39651-39659` remain reserved and unallocated. All other hits are the profile specification, README, PROPOSED, and NIP90-MIGRATION reservation text. |
| [`nostr-protocol/registry-of-kinds`](https://github.com/nostr-protocol/registry-of-kinds) `schema.yaml` | `2483e752146d171524dcb10dffd06de2aa271bf3` (current HEAD at review time) | No entry in `39650-39659`; the nearest higher registered kind is `39701`. |

The review found no collision and creates no lane-precedence exception.
Immortal therefore admits `39650` as a private immutable NIP-59-only kind
under the same store/gateway rules as `39610` and `39620` (migration 0013).
Kinds `39651-39659` and all other unadopted profile kinds remain
unallocated.

The relay validates the MKT-LSP Offering's exact compressed secp256k1
`lsp_node_id`, collision-resistant registry `network_id` and asset-ID pair
(bare `BTC`/`sat`/`mainnet` labels rejected), bounded `lsps` revision
declaration, the explicit channel-purchase/jit-inbound disable law with
canonical decimal amounts, bounded channel-type identifiers, the
zero-conf-policy vocabulary, bounded decimal lease bounds, the exact
`bolt11`/`bolt12`/`onchain` payment-method set, the exact
`a1-coordinated-hold` custody class, the five-class reservation-proof
vocabulary, and recursive custody-material plus public
invoice/payment-hash/SCID/channel-plan refusal on Offerings and receipts. An
authorized profile consumer can apply the exact Service Contract grammar
(complementary requester/provider signers, causal Quote/Order/Status
binding, `x`/`contract_sha256` equality, the closed 11-member contract
object, no NIP-40 expiration), the closed LSPS0/1/2 source-reference
mapping, the visible custody-class rule, and the admitted Status-state set
after decryption. LSPS messages over BOLT8 stay canonical for their own
execution: the mapping proves only the reference and never upgrades the
source signature, order, promise, channel, or payment authority.

The 30-case upstream manifest is exported without claiming the client-only
LSPS-substitution, fee-promise, price-feed, reservation-proof,
double-reservation, funding-output, replacement, channel-ready-depth,
preimage-release, prepaid-refund, unilateral-close, recovery, or chain-reorg
cases as relay enforcement. The channel-purchase and JIT lifecycles execute
on external Bitcoin/Lightning rails; the relay coordinates, it does not
operate channels. The contract lists `mkt-lsp:1` as `relay_observable_only`,
keeps executable profiles empty, and advertises `nip-mkt-lsp:1` only under
the authenticated relay URL gate after the complete local relay-observable
conformance gate passes.
## M12 funded provider-runtime decision (2026-08-04)

Issue #25 executes the provider side of OpenAgents MKT-SWP v1, originally
adopted at `a7f5522c0a7430f9f5b1cfa09477dae2d16d3682` and clarified by
`f091fd7242651eba5e3eb38c358d0d89d6a78368` as recorded in the post-provider
sync review below. It allocates no event kind, changes no source-lane
precedence, and leaves the issue #11 collision result unchanged. The relay
contract, relay Postgres schema, NIP-11 document, and relay
executable-profile set are unaffected.

The #25 `immortal-provider` funded-mode packet adopts Bitcoin Core JSON-RPC
over bounded loopback HTTP/1.1 and Core Lightning JSON-RPC over a bounded Unix
socket. Bitcoin state is polled with bounded backoff; ZMQ is not adopted.
Core Lightning is the only v1 Lightning implementation, with the Boltz hold
plugin declared as an operator prerequisite. LND and its TLS dependency chain
remain deferred. Dynamic Bitcoin/Lightning Quotes require no external price
feed: submarine RFQs carry the requester invoice, while reverse Quotes carry
the provider-created hold invoice and its digest. A reverse Quote derives its
minimum acceptable shortest incoming-HTLC expiry from CLN's synchronized
`getinfo.blockheight` plus the invoice's minimum final CLTV delta; the payer
may construct a later expiry. Bitcoind remains the chain and refund authority.
The provider does not construct a Quote if CLN reports either sync warning,
names another network, is ahead of bitcoind, or lags it by more than the signed
reorg-safety margin. A temporary height or sync-warning mismatch defers Quote
construction through bounded polling instead of rejecting the RFQ. BOLT11
wall-clock expiry bounds payment initiation while the observed incoming HTLC's
CLTV independently bounds settlement and cancellation.

Provider wallet construction uses the existing in-repo BIP-341/342 verifier
and the pinned `secp256k1` Schnorr primitive. Wallet funding inputs use a
locktime-enabled non-RBF sequence matching the signed `rbf=reject` and
`replacement=reject` policy. Settlement is script-path only in v1; MuSig2
cooperative key-path execution is not claimed. Hard chain reservations bind
controlled UTXOs, hard Lightning reservations bind observed node capacity,
and both are durable before a firm Quote is signed. Reserved UTXOs,
transactions, public commitments, watch jobs, and rail result digests may be
persisted; seeds, private keys, unreleased preimages, and node credentials may
not.

The reverse hard-Quote callback first durably reserves exact controlled UTXOs,
then constructs the signed funding transaction and binds its complete bytes,
digest, output index, and recomputed verifier digest into the Quote. Bilateral
contracts therefore commit to the transaction before requester authorization.
The provider rebuilds the transaction from its recovered reserve immediately
before broadcast and refuses any byte change; subsequent bitcoind observations
must return the same committed transaction and output. The funded external
actor reconstructs both contracts with the production client engine, parses
the requester `ExitPackage`, completes verify-before-fund, and accepts each
provider terminal Close before a journey can finish.

The provider does not publish `lightning_htlcs_held` until every observed HTLC
is accepted, the bounded set sums to the bilateral amount, and its shortest
expiry satisfies both the signed minimum and live recovery margin. A
deterministically invalid pre-funding hold follows the durable
`invoice_cancel_pending` → `invoice_cancelled` → `expired` path and releases
capacity only after cancellation. If the invalid invoice has already settled,
the reservation and session remain unresolved for operator recovery.

Signed chain heights are exclusive action deadlines: reaching the exact
funding, claim, or reverse-lock height stops the irreversible action. A final
cooperative reverse claim settles or reconciles the hold invoice and retires
the competing refund watch with `claim_settled`; provider refund and
replacement transactions remain on the refund branch. Provider-authored
`completed`, `refunded`, and effective-cancellation paths end in signer-local
Close records and durable reservation release. Counterparty terminal records
do not terminate the provider actor or its recovery state.

The provider has its own migration ledger, database, deterministic contract,
and fixture manifest. Its contract names exact commands, configuration
bounds, rail methods, operational scopes, custody exclusions, and v1
limitations. The local funded gate runs the normal binary against disposable
regtest bitcoind, two CLN nodes, the hold plugin, a relay, and separate
provider/relay Postgres databases. Its prerequisite runtime fixture replays
held-HTLC amount/state/expiry rejection, exact and one-past signed deadline
behavior, held-invoice cancellation, and cooperative refund-watch retirement
through production helpers; the provider contract binds its exact digest. The
process gate proves submarine claim, reverse claim, and noncooperative reverse
refund while retaining only public transaction and invoice-state evidence. On
2026-08-04 it completed locally on macOS 26.4 arm64 with
`test-provider-funded: submarine, reverse, and noncooperative refund passed`.
This is local regtest conformance, not Debian or deployment evidence. No GitHub
workflow or billed automation is added.

## M12 provider pricing decision (2026-08-04)

Issue #28 changes no source specification, event kind, relay admission rule,
or NIP-11 advertisement. The funded provider uses Bitcoin Core's conservative
two-block `estimatesmartfee` result when available and converts its JSON
decimal BTC/kvB value to an upward-rounded integer sat/vB without floating
point. A bounded operator fallback is explicit and unset by default; the
regtest gate sets it because regtest has no fee history.

The pricing engine shares the production claim/refund script constructors and
binds their measured worst-case weights: 155 vB claim, 139 vB refund, 155 vB
provider lockup, 294 vB reverse lockup-plus-refund, and 310 vB chain worst
case. Configured spread, routing budget, quote expiry, and unallocated durable
capacity derive the accepted amount and fee terms. Those terms are rebound
into the signed Quote, and reverse funding recovers its exact feerate from the
signed miner budget. Bitcoin/Lightning-only Quotes keep `price_feed` null; no
outbound price-feed authority is adopted. The deterministic pricing corpus is
bound by both the M11 fixture manifest and the provider contract.

## Post-provider source sync review (2026-08-05)

The post-#25 sync records these current inputs in `nips/manifest.json`:

| Lane | Current revision | Review result |
| --- | --- | --- |
| Official NIPs | `c53877571f96eb423661fc23c620d629d37b8f19` | The revision and 99 Markdown files are unchanged; only `synced_at` advanced. |
| Block NIPs | `8342dfcc5890b81a269a8ec3db73a8a56f76ce79` | The branch tip advanced from `540b58920cef205b838da8be8442aae62bceaaa5` by 24 unrelated Buzz commits. The upstream compare contains no `docs/nips/` path. All 15 Markdown path, Git blob SHA, and size tuples are byte-identical at both revisions; the sorted tuple listing has SHA-256 `820b4746d1f33f55dc51291235c475c9c253cd520a26b3337b7f52ab588ec240` at each pin. No Block specification bytes changed. |
| OpenAgents NIPs | `c579a75bcba6d799941efff4dfbf82bd090e88c1` | The lane contains the four M13 drafts from `33eb9ad428e83f3da877204fe710dcfff00f4f8d`, the MKT-SWP hold-expiry correction from `f091fd7242651eba5e3eb38c358d0d89d6a78368`, and the submarine funding-resolution correction at the pinned tip. Comparing the preceding Immortal pin `cad192988c0deba1fd4181370242e5d579bc863c` with this revision changes only `docs/nips/MKT-SWP.md`, adding the 14-line funding-resolution rule. |

The `f091fd7242` MKT-SWP correction makes
`timeout_ladder.hold_expiry_height`, written as `H_hold_expiry`, the signed
minimum acceptable value of the shortest incoming Lightning HTLC expiry. It
is not the provider's observation. Before funding a reverse-swap chain lock,
the provider observes the complete held-payment part set, computes
`H_observed_shortest`, and requires
`H_observed_shortest >= H_hold_expiry`. Equality and greater-than are positive
fixture boundaries; a below-minimum observation keeps funding disabled and
reports `swp_timeout_ladder_unsafe`. This meaning matches the #25 provider
decision above: the Quote signs the minimum and the live CLN observation may
be later.

The `c579a75bcb` MKT-SWP correction permits one fail-closed Quote-to-Contract
resolution. A submarine requester chooses its source-chain inputs and change
after Order, so the Quote may omit `funding_transaction`,
`funding_transaction_sha256`, and `output_index` from that requester-funded
source verifier. The bilateral Contract adds exactly those fields, proves the
decoded transaction digest and quoted output amount/script, and changes only
the matching source-leg verifier digest. Immortal adopts this correction with
one positive vector and eight mutation refusals. Reverse, chain,
provider-funded, non-source, reordered, and additional-field changes remain
invalid.

The pinned M13 files remain drafts and optional protocol inputs. MKT-P2P,
MKT-MINT, and MKT-LSP were subsequently adopted for their relay-observable
subsets under the fresh collision reviews recorded above; their client and
rail authorities remain external. MKT-INTENT and `39660-39669` remain
unadopted and unallocated. Advancing the source pin for the two MKT-SWP
corrections changes none of those three adoption decisions and adds no new
kind allocation or NIP-11 advertisement.

## M12 MuSig2 cooperative-signing decision (2026-08-05)

Issue #26 changes no NIP source pin, event-kind allocation, relay admission
rule, Postgres schema, or NIP-11 advertisement. It adopts BIP-327 1.0.3 at
Bitcoin BIPs commit `e7263a4cfe500c89e4269889244606953691ca33` as a primary
rail input. The complete eight-file official corpus is pinned at its last
content commit, `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`, with byte
digests and BSD-3-Clause provenance recorded in the fixture directory.
BIP-327 is not a fourth NIP source lane.

The dependency decision retains pinned `secp256k1` 0.31.1 and the per-crate
allowlists. Immortal implements BIP-327 key sorting and aggregation, optional
nonce inputs, nonce aggregation with the extended infinity encoding, one-use
nonce handling, scalar arithmetic, tweak accumulation, partial signing and
verification, deterministic last-signer signing, and final aggregation
in-repo over the crate's exposed point/tweak operations. No dependency
exception is created. Every valid and invalid case in the official corpus is
executable; secret-nonce buffers are redacted and explicitly overwritten on
consumption/drop, and a second signing attempt fails closed.

MKT-SWP Status carries the exact cooperative transcript inside its existing
recipient-gated NIP-59 transport. The context binds the Order, bilateral
contract digest, deterministic `cooperative_sign` effect ID, leg, complete
unsigned transaction and prevouts, BIP-341 `SIGHASH_DEFAULT`, ordered
requester/provider keys, tweaks, aggregate key, unilateral exit-package
digest, and latest safe height. Commitment, nonce reveal, partial signature,
final signature, and abort shapes are closed and fixture-pinned. An abort
selects only the already-verified script path; cooperation never removes or
delays the unilateral exit beyond its signed safe height.

The provider foundation exposes an ephemeral cooperative signer that derives
the exact quoted wallet key, verifies the transaction, fee, destination,
prevout, aggregate key, counterparty nonce commitment, every partial, and the
final signature. The signed actor accepts only byte-identical Status Events
already stored in `ProviderSession`; it binds the exact provider exit package
and settlement template before nonce allocation, preflights signed transcript
state before consuming the nonce, and withholds final transaction bytes until
the final provider Status is signed and stored. Restart recovery creates a
bounded script-path abort without restoring a nonce. The provider database and
public effect records receive no secret nonce or spend key.

This adoption decision keeps the funded Quote and provider contract flags
`musig2_key_path=false` and `musig2_key_path_signer=false`. Funded-mode actor
ownership, rail broadcast, and capability advertisement remain gated on the
#18 process lab, so the actor packet is not a deployment claim.
