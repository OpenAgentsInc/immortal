# M6 NIP Source-Lane Decisions

These decisions apply to the exact upstream commits in `nips/manifest.json`.
The official lane wins any identifier conflict unless the owner records an
exception. No M6 exception was approved.

| Lane | Decision for M6 |
| --- | --- |
| `official` | Implement the pinned NIP-17, NIP-29, NIP-40, NIP-45, NIP-50, NIP-65, NIP-70, NIP-86, and NIP-98 behavior described in `nip-expansion.md`. Watch NIP-77 without implementing it. NIP-91 is absent from this pinned lane, so do not advertise or implement it. |
| `block` | Park all 15 custom specifications (NIP-AA, AE, AM, AO, AP, CW, DV, ER, GS, IA, MP, OA, PL, RS, and WP). None is required by M6 and the owner approved no identifier or precedence exception. |
| `openagents` | Keep NIP-AC, DS, LBR, SA, SKL, and TRN postponed under the owner direction recorded in that lane's README. The lane does not drive new runtime work until the owner pulls it forward. |

The source files remain pinned protocol inputs, not claims of runtime support.
A future adoption decision must name the exact lane and identifier, add a
fixture, and update NIP-11 only after the implementation passes the local
conformance gate.
