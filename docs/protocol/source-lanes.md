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
