# Arkade OS ecosystem

## Source

| Field | Value |
| --- | --- |
| Organization | <https://github.com/arkade-os> ("an open execution engine for Bitcoin") |
| Local review set | `~/work/projects/arkade/repos/` (19 non-archived public repositories) |
| `arkd` | `8b34e352` (MIT) |
| `arkade-unilateral-exit` | `d9c949d` (MIT) |
| `solver` | `914079b` (no license file) |
| `solver-registry` | `e21bd63` (no license file) |
| `skill` | `ef366da` (no license file) |
| `ts-sdk` | `dfa1af44` (no license file) |
| Adjacent lanes | `~/work/projects/ark/` (ark-bitcoin "bark", no license file), `~/work/projects/mostro/` (mostro `94e736a`, MIT), `~/work/projects/cashu/` (nuts `3bc8b6d` MIT, cdk `26d68d94` Apache-2.0) |
| Review date | 2026-08-04 |

Repositories without a license file are ideas-only reference. MIT and Apache
material may be adapted with source, commit, path, and license recorded. No
code is copied by this review. The full analysis lives in the OpenAgents
monorepo at
`docs/teardowns/2026-08-04-ark-solver-mostro-cashu-rails-teardown.md`.

## What it is

Arkade OS is the Ark implementation the Satora stack speaks to: `arkd` is
the operator server (Go, alpha) batching VTXO-based off-chain Bitcoin
transactions with strict fund-control boundaries, surrounded by SDKs in
five languages, an experimental Arkade Script compiler, an agent swap
skill, and an intent/solver market: makers fund covenant-enforced standing
swap offers, `solver` daemons watching the arkd stream fill them, and
`solver-registry` publishes markets as a git-repo of JSON cards reduced by
CI — the token-list pattern, deliberately key-free in v0 with signed live
quotes specced as "v1, dormant." Arkade's Lightning ramps run through
Boltz submarine swaps, making it a third surface exposed to the Boltz
outage class. This is a different implementation from ark-bitcoin's
"bark" (`projects/ark/`); both stay pinned because the protocol is young
and they diverge.

## Borrow

| Item | Upstream location | How we adapt it |
| --- | --- | --- |
| Discovery field vocabulary | `solver-registry/docs/arkade-discovery-spec.md` (ideas only) | Into the MKT profile drafts (openagents#9311/#9312): market identity is the asset-id pair, never tickers; amounts as canonical decimal strings; explicit side-disable semantics; fee as a fill promise; pinned price-feed URL + RFC 6901 pointer schema when a feed is part of terms |
| Convergence evidence | Same spec: "v1, dormant" adds signed quote events | Their v1 converges toward NIP-MKT's v0 — validation that signed-event discovery is the destination; their v0 shows what covenant enforcement lets a rail defer |
| Pre-signed exit packages | `arkade-unilateral-exit` (MIT) | The doomsday drill's implementation shape: the client engine (#12) persists an exit package beside its signed records, provable via a keyless executor with only an Esplora endpoint — no operator, coordinator, or relay alive |
| Covenant-enforced offers | `solver` model (ideas only) | Working example of the covenant-reserve proof class for `hard` reservations (#13); the maker-funded any-filler intent shape is a recorded profile design decision (openagents#9312), not silently folded into the base |
| Ark rail constructs | `arkd` (MIT), protocol docs, both implementations | VTXO trees, operator/exit verification, and covenant checks for the Ark leg (#20), implementation-neutral where possible, custody model always disclosed |
| Agent swap skill shape | `skill` (ideas only) | Evidence for the agent-markets thesis: agents already consume swap capability as a packaged skill; the OpenAgents SDK exposes the same capability against the open network instead of one operator |
| Regtest presence | satora `regtest-devenv` topology (arkd + wallet) | The lab (#18) external-node matrix already includes an arkd node |

## Reject

| Item | Reason |
| --- | --- |
| Git-repo registry as the primary market wire | Honest curation, but its own roadmap adds keys and events; NIP-MKT starts there. A forkable curated overlay is already covered by NIP-51 lists |
| CI/forge as protocol infrastructure | The reducer runs on GitHub Actions; this repository prohibits GitHub-billed automation, and a market index requiring a specific forge is a gatekeeper in disguise |
| Unlicensed repos as code donors | `solver`, `solver-registry`, `skill`, `ts-sdk`, `bark`: laws and vocabulary only |
| Operator trust by default | `arkd` is alpha with an operator role; Ark routes disclose operator/exit custody like every other rail — the custody gradient is unchanged |

## Follow-ups

1. openagents#9311/#9312: land the discovery-spec vocabulary in the
   profile drafts; decide the intent-market shape in #9312.
2. #12: adopt the pre-signed exit-package shape for the doomsday drill.
3. #20: Ark rail leg with both-implementation awareness and exit-package
   proof in the lab.
4. Recorded: Arkade's Lightning ramps depend on Boltz — third exposed
   surface, strengthening the M12 replacement case.
