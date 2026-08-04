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
