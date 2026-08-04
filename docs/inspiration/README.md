# Inspiration Reviews

This folder holds our reviews of external projects that we borrow from.
One file per project. This document is the standard for those reviews.

## The rules

1. **A review is not adoption.** Borrowed ideas still pass the AGENTS.md
   rules: the dependency allowlist, the single-service rule, and the
   fixture requirement.
2. **Prefer re-implementation from understanding.** Read the source, learn
   the technique, write our own code against our own fixtures.
3. **Direct copies need provenance.** If we copy code or fixture data, the
   license must permit it, the copied section gets a comment with the
   source repo, commit, path, and license, and the review's Borrow table
   records it. This repository is CC0; MIT, Apache, and BSD sources are
   acceptable with attribution.
4. **Pin the commit.** Every review names the exact upstream commit it
   read. Re-review before you borrow from a newer version.
5. **Record rejections.** What we choose not to take, and why, is as
   useful as what we take.

## Review format

Each review has these sections, in this order:

1. **Source** — repo URL, pinned commit, license, version, review date.
2. **What it is** — two or three sentences.
3. **Borrow** — a table: item, upstream location, how we adapt it.
4. **Reject** — a table: item, reason.
5. **Follow-ups** — concrete actions this review creates (fixtures to
   port, techniques to test, questions for the owner).

## Reviews

| Project | File | Pinned commit |
| --- | --- | --- |
| nostr-rs-relay | [`nostr-rs-relay.md`](nostr-rs-relay.md) | `b5c1f642e4` |
| Block Buzz | [`buzz.md`](buzz.md) | `027a74a61c` |
| Boltz ecosystem | [`boltz.md`](boltz.md) | primary pins recorded per repository |
| tbDEX | [`tbdex.md`](tbdex.md) | `62c466774f` |

## Liquidity Market reading order

Read [`tbdex.md`](tbdex.md) for the provider-neutral negotiation grammar, then
[`boltz.md`](boltz.md) for the strongest atomic Bitcoin settlement profile.
Together they define the intended split: Immortal owns noncustodial discovery,
private negotiation, reservation, coordination, evidence, recovery, and
compatibility surfaces; independent clients, providers, and underlying rails
retain funds, spend authority, secrets, and final settlement truth.
