# AI Provenance

This file records which AI agents wrote this repository, and which agent
does what. Update this file when an agent joins, leaves, or changes role.

## Record to date

As of commit `0efe8e0` (2026-08-03):

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

## Rules

1. Every AI-authored commit carries a `Co-Authored-By` trailer that names
   the agent.
2. The AGENTS.md rules bind every agent equally. No agent adds a
   dependency, a service, or an unfixtured protocol change.
3. An agent's work is not accepted by authorship. It is accepted by the
   fixtures, the checks, and the owner's review.
4. Update the record in this file at each milestone, or when the set of
   contributing agents changes.
