# NIP Sources

This directory holds our copies of the Nostr protocol specifications
(NIPs). These copies are the source of truth for the Rust implementation
in this repository.

## The three sources

| Lane | Upstream | Content |
| --- | --- | --- |
| `nips/official/` | [nostr-protocol/nips](https://github.com/nostr-protocol/nips) | The standard NIPs |
| `nips/block/` | [block/buzz](https://github.com/block/buzz/tree/main/docs/nips) | The Buzz extension NIPs |
| `nips/openagents/` | [OpenAgentsInc/openagents](https://github.com/OpenAgentsInc/openagents/tree/main/docs/nips) | The OpenAgents NIPs |

`nips/manifest.json` records the exact upstream commit for each lane, with
a `tree_url` link to browse that commit. Use those links to see the
upstream history for any file.

A lane may carry a repo-owned `README.md` that summarizes its specs when
the upstream does not publish one (currently `nips/block/README.md`).
The sync script preserves that file, and an upstream-provided README
(the `openagents` lane) always replaces the local copy. The manifest
file count records upstream files only.

## How the sync works

1. Run `./scripts/sync-nips.sh`.
2. The script clones each upstream at its current head, copies the
   specification files into the lane directory, and writes the upstream
   commit hashes to `nips/manifest.json`.
3. Review the diff. A specification change is a protocol policy change.
   Do not commit a sync without reading what changed.
4. Commit the sync as its own commit.

Run the sync at a regular interval and before each new NIP
implementation starts.

## How we verify

1. We implement each NIP from the specification text in this directory,
   from scratch, in Rust.
2. Each implemented NIP gets a fixture corpus in this repository. A
   protocol change without a fixture update is not complete (AGENTS.md,
   rule 8).
3. Where the state space is small and the property matters, we add formal
   verification and keep the model next to the fixtures.
4. A synced upstream change becomes normative for the implementation only
   after review and a fixture update. The sync itself never changes the
   implementation.

## Precedence

The lanes stay separate. The implementation tracks each NIP by lane and
identifier. If the same identifier exists in more than one lane, the
`official` lane wins unless the build plan names an exact exception.
