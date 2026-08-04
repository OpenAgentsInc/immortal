# Domain Fixture Corpus

These fixtures test the pinned specifications under `nips/`. Each directory
names the NIP that owns the behavior.

## Provenance

- `nip01/events.json` contains the signed `hello world` event and canonical
  ID vector from `scsibug/nostr-rs-relay`, commit
  `b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4`, `src/event.rs`, MIT license.
  Its `tags: null` compatibility input was normalized to the NIP-01 wire form
  `tags: []`; the canonical bytes, ID, and signature are unchanged.
- `nip01/filters.json` adapts the filter-matching cases from the same commit's
  `src/subscription.rs`. Immortal changes the old prefix cases to assert exact
  matching because the pinned NIP-01 no longer allows prefix matching.
- `nip01/replacement.json`, `nip09/deletion.json`, and
  `nip40/expiration.json` were written for Immortal directly from the pinned
  NIP-01, NIP-09, and NIP-40 text.
- `nip01/gateway_messages.json`, `nip11/document.json`, and
  `nip42/auth.json` were written for Immortal directly from the pinned NIP-01,
  NIP-11, and NIP-42 texts. They pin gateway message shape, relay information,
  limit metadata, and canonical authentication acceptance boundaries. The M3
  live contract separately checks NIP-11 CORS behavior.
- `nip17/routing.json`, `nip29/groups.json`, `nip45/count.json`,
  `nip50/search.json`, `nip65/relay-list.json`, `nip70/protected.json`,
  `nip86/management.json`, `nip94/metadata.json`, `nip98/http-auth.json`,
  and `nipb7/servers.json`
  were written for Immortal from the corresponding pinned official texts.
  They pin M6 validation, routing, group action, COUNT, search, protected
  publishing, and HTTP-authentication boundaries. The live Postgres gateway
  contract checks the associated storage, access-control, signing, sweep,
  management, media metadata/server-list, and wire behavior.

Fixture data is committed rather than generated so a specification or
implementation change produces a reviewable diff.

Run the complete fixture layer manually with
`cargo test --locked --all-targets`. `docs/conformance/README.md` maps every
M1–M7 contract to its fixture, unit, live-Postgres, or process-level proof.
GitHub workflows and GitHub-billed automation are prohibited.
