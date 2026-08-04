# OpenAgents Project Read Contract

Operation Diamond Hands Phase 0 is a client read path, not a relay-side API.
The browser opens `wss://relay.openagents.com` itself and sends the NIP-01
subscription produced by `immortal::client::ProjectClient`. Immortal does not
add an HTTP data endpoint, a relay proxy, a second database, or another
service.

## Adopted protocol subset

The exact normative inputs are the pinned `nips/openagents/OT.md` and
`nips/openagents/PG.md` files at the OpenAgents commit recorded in
`nips/manifest.json`. Phase 0 adopts these authority-signed records only:

| Record | Kind | Client use |
| --- | ---: | --- |
| Organization | `32100` | name, pinned authority, founder and relay hints |
| Project | `32222` | name, organization, status address, principals, dates and projected progress |
| Project Status | `32223` | configured lifecycle name/category/position |
| Project Update | `32226` | authored report body, author, health, freshness and optional exact-body digest |

The project authority pubkey and stable Organization/Project refs are
deployment configuration. They are the out-of-band trust root described by
NIP-OT. Phase 0 accepts the initial pinned-authority record; two-sided key
rotation is deliberately deferred until a complete rotation fixture and UI
are present. Events from another signer never become project truth.

NIP-OT and NIP-PG are proposal names, not numeric official NIP identifiers.
The relay therefore does not add them to NIP-11 `supported_nips`. NIP-BT is
postponed and outside this contract.

## Subscription and bounds

One REQ contains four bounded filters: the configured Organization, the
configured Project, Organization Project Status definitions, and recent
events carrying the exact Project `a` address. The default product
configuration caps the retained corpus and activity list; the library rejects
zero or excessive limits and frames larger than 262,144 bytes.

The final `#a` filter intentionally has no kind restriction. A future project
activity kind can therefore be displayed as an unknown verified event instead
of silently disappearing. Unknown events still require a canonical ID, valid
BIP-340 signature, and the exact configured project address. Known OT/PG kinds
must pass their complete shape and authority contract.

## Snapshot truth

Events received before `EOSE` are provisional. At `EOSE`, the pending bounded
set atomically replaces the prior completed set and produces the visible
snapshot. Subsequent events fold into that snapshot live. Duplicate IDs are
ignored; addressable versions use newest `created_at` and then the NIP-01
lexically-lowest-ID tie break.

On disconnect, the client retains the last completed snapshot and marks it
reconnecting. A partial reconnect never mixes into visible truth; only the
next `EOSE` replaces the snapshot. A quiet live connection can be marked stale
by the host's clock. `CLOSED` makes the connection unavailable while retaining
the last completed data for an explicit stale/error presentation.

Malformed JSON returns an error without mutating truth. Invalid event shape,
ID, signature, authority, tag cardinality, enum, address, or content digest is
diagnosed and excluded. Diagnostic storage is itself bounded.

## Packaging and transports

The Cargo package defaults to the `server` feature and builds the ordinary
relay binary unchanged. Native or browser consumers use the library without
default features:

```toml
immortal = { git = "https://github.com/OpenAgentsInc/immortal", rev = "<pin>", default-features = false }
```

The core deliberately performs no I/O. Native applications may adapt their
existing socket runtime; browser applications adapt the browser WebSocket
available through their GPUI web renderer. That separation makes the same
state machine testable on both targets without allowing a server-only runtime
into the wasm closure.

Run both target checks manually:

```sh
./scripts/test-project-client.sh
```

Zig is used only as the C compiler for the already-approved `secp256k1`
backend on `wasm32-unknown-unknown`; Apple clang does not ship that target.
No GitHub workflow or GitHub-billed automation is used.
