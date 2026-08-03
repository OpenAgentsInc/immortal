# AI Provenance

This file records which AI agents wrote this repository, and which agent
does what. Update this file when an agent joins, leaves, or changes role.

## Record to date

As of commit `0efe8e0` (2026-08-03; superseded by the work log below —
Codex's first implementation commit is `8c22cc2`, M1 domain):

- **100% of the repository content was written by Anthropic Claude**
  (Claude Fable 5 / Opus 5, one Claude Code session), directed and
  reviewed by the human owner.
- 5 of 6 commits carry the trailer
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
  Later Claude commits may carry `Co-Authored-By: Claude Fable 5
  <noreply@anthropic.com>`. Both name the same Claude session lineage.
- The remaining commit (`e95bafd`, "Initial commit") is the GitHub
  repository creation with the LICENSE file only.

## Who does what

| Actor | Role |
| --- | --- |
| Human owner | Direction and decisions. Dependency approvals (AGENTS.md rule 2). NIP adoption decisions. Final review. |
| Claude (Anthropic) | Foundation to date: doctrine, NIP source policy and sync, roadmap, inspiration reviews, deployment docs. Ongoing: architecture, policy documents, and review. |
| Codex (OpenAI) | Implementation of the roadmap milestones (`docs/ROADMAP.md`, M1 and later): domain, store, gateway, conformance, under the AGENTS.md rules. Handoff date: 2026-08-03. |

## Active work log

### 2026-08-03 — Codex 5.6 Sol (Extra High), M1 Domain

- Accepted the implementation handoff from Claude Fable 5 at commit
  `15e736b` on `main`.
- Read the binding repository rules and pinned NIP-01, NIP-09, and NIP-40
  specifications before implementation.
- Scope: the complete M1 domain milestone — owned event and tag types,
  canonical IDs, Schnorr verification, exact filter matching, kind and
  replacement semantics, expiration, deletion tombstones, timestamp bounds,
  and attributed fixture corpora.
- Dependency decision: use only the already-approved `secp256k1`, `sha2`,
  `serde`, and `serde_json` entries from the `AGENTS.md` allowlist. No owner
  approval or rule change is required. `secp256k1` is CC0-1.0 (the same
  license as Immortal) and explicitly allowlisted; the other three are dual
  MIT/Apache-2.0.
- Concurrent-work note: Claude completed and pushed the deployment-doc set as
  commit `b74a5e8` while M1 was in progress. The shared worktree advanced
  cleanly; Codex did not modify those files.
- Implemented the owned `src/domain/` library with explicit validation layers
  and pure replacement/deletion decisions suitable for the M2 admission
  transaction.
- Added committed NIP-01, NIP-09, and NIP-40 fixture files with source and
  license attribution. The first complete run passed 14 fixture tests in both
  debug and release modes; follow-up review added canonical escaping coverage
  and aligned malformed expiration tags with the pinned spec/reference
  behavior (ignored rather than treated as event-invalid).
- Milestone-close verification: 15 optimized fixture tests pass;
  `cargo clippy --all-targets -- -D warnings`, rustdoc with warnings denied,
  formatting, and `git diff --check` are clean. Updated the README and roadmap
  to distinguish the completed domain milestone from the still-skeletal
  store, gateway, and executable server.

### 2026-08-03 — Human owner: first dependency approval

- Approved `tokio-postgres-rustls` (with its `rustls` chain) as an
  optional TLS backend for managed Postgres services that require TLS.
  The approval is recorded in `AGENTS.md` rule 2, which stays the
  canonical approval list. The dependency is not in the tree yet; it
  enters only when the TLS deployment path is implemented, behind a
  feature flag.
- Context: the deployment review (commit `b74a5e8`) surfaced the blocker
  — DigitalOcean Managed Postgres mandates TLS, which `tokio-postgres`
  alone cannot speak. Claude surfaced it; the owner decided.

## Rules

1. Every AI-authored commit carries a `Co-Authored-By` trailer that names
   the agent.
2. The AGENTS.md rules bind every agent equally. No agent adds a
   dependency, a service, or an unfixtured protocol change.
3. An agent's work is not accepted by authorship. It is accepted by the
   fixtures, the checks, and the owner's review.
4. Update the record in this file at each milestone, or when the set of
   contributing agents changes.
