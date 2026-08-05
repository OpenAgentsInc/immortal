# NIP-WK / NIP-PI structural validation

Adopted from the pinned OpenAgents lane drafts `nips/openagents/WK.md`
(kinds 32170-32173) and `nips/openagents/PI.md` (kind 32200) for
immortal#33. This is the base-validation adoption only; the rest of the All
Work program stays drafted in `nips/openagents/PROPOSED.md`.

## What the relay enforces

`validate_openagents_work_event` in
`crates/immortal-core/src/domain/allwork.rs` runs on the public admission
path for these kinds. It validates structure only:

- Bounds: at most 64 tags and 16384 content bytes.
- Kind 32170 Work Record: required `d`, `org`, `domain`, `state`, positive
  canonical `revision`, exactly one `p` tag marked `owner` with a valid
  pubkey, and `published_at`. Optional `title` (bounded display text, at
  most 256 bytes) and `class`.
- Kind 32171 Work Event: `d` grammar `<work_ref>:evt:<seq>`, `work` equal
  to the `d` work_ref, positive `seq` equal to the `d` sequence, an `event`
  kind label, exactly one `p` tag marked `actor`, `occurred_at`, and
  `admitted_at`. Dense-sequence reconstruction and gap surfacing stay
  client-side; the relay cannot see the whole stream at admission.
- Kind 32172 Work Objective: `d` grammar `<work_ref>:obj:<revision>`,
  `work` and positive `revision` matching the `d` value, a 64-hex `x`
  digest, and `published_at`. The digest is not recomputed because private
  objectives bind plaintext bytes the relay never sees.
- Kind 32173 Outcome Record: required `d`; when present, `work` must equal
  `d`, `state` must be a bounded label, and `revision` must be positive.
- Kind 32200 Issue Projection: required `d`, `org`, `team`,
  `identifier` (`<TEAM-KEY>-<number>`), `state`, positive `revision`, and
  `published_at`, plus a `title` tag or non-empty (encrypted) content.
  Optional `priority` (closed list), canonical `estimate`/`due`/
  `archived_at`, `label` refs, and `identifier_alias` values.
- All five kinds: `p` values are pubkeys, `e` and `x` values are 64-hex,
  `a` values parse as addressable coordinates.

## Open vocabularies and unknown tags

State, domain, and event-kind vocabularies are open per the drafts: the
baseline lists are exported (`WORK_BASELINE_STATES`,
`WORK_BASELINE_DOMAINS`, `WORK_BASELINE_EVENT_KINDS`,
`WORK_OUTCOME_STATES`) but any bounded lowercase label passes. Unknown tag
names are preserved, never rejected.

## What the relay never decides

Kinds 32170-32173 and 32200 are canonical only when signed by the
Organization's declared NIP-OT authority key. That resolution is a
client/consumer rule. The relay validates structure, and relay acceptance
is transport evidence only: it proves neither organizational authority nor
completion.

## The `work` tag index

The PI rendering contract enumerates a Work's event stream with
`{"kinds":[32171],"#work":["<work_ref>"]}`. Migration
`0014_wk_work_tag_index.sql` extends the tag index to the `work` tag name
(with backfill), and `EXTENDED_INDEXED_TAG_NAMES` in `immortal-core`
declares it; single-letter NIP-01 indexing is unchanged.

## Fixtures and dev seed

- Corpus: `tests/fixtures/nipwk/work-records.json` with
  `crates/immortal-core/tests/allwork_fixtures.rs`.
- Dev seed: `scripts/dev-work-seed.sh` signs Work Records, Issue
  Projections, and `created` Work Events from the public-safe
  `scripts/dev-work-items.json` snapshot and publishes them to the local
  dev relay (default) or `wss://relay.openagents.com` behind
  `--publish-openagents`. The pinned dev authority pubkey lives in
  `scripts/dev-work-authority.md`.
