# OpenAgents Project Read Contract

Operation Diamond Hands Phase 0 is a client read path, not a relay-side API.
The browser first fetches `https://relay.openagents.com` with the NIP-11 media
type, validates the document's relay pubkey and subscription limits against
its pinned configuration, then opens `wss://relay.openagents.com` itself and
sends the NIP-01 subscription produced by `immortal::client::ProjectClient`.
Immortal does not add an HTTP data endpoint, a relay proxy, a second database,
or another service.

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

The core deliberately performs no I/O. It derives the HTTPS NIP-11 URL and
validates the bounded response, but the host performs that fetch. Native
applications may adapt their existing socket runtime; browser applications
adapt browser fetch and WebSocket primitives available through their GPUI web
renderer. That separation makes the same state machine testable on both
targets without allowing a server-only runtime into the wasm closure.

Run both target checks manually:

```sh
./scripts/test-project-client.sh
```

Zig is used only as the C compiler for the already-approved `secp256k1`
backend on `wasm32-unknown-unknown`; Apple clang does not ship that target.
No GitHub workflow or GitHub-billed automation is used.

## Bounded operator signing

The one Immortal binary also exposes a manual signing boundary for initial and
replacement OT/PG records:

```sh
IMMORTAL_RELAY_SECRET_KEY=<protected-environment-value> \
  immortal sign-openagents-project-events < unsigned-events.json \
  > signed-events.json
```

The command accepts one JSON array of 1–32 unsigned records, caps stdin at
65,536 bytes, admits only kinds `32100`, `32222`, `32223`, and `32226`, signs
with the relay key supplied through the environment, and runs the complete
OT/PG validator before emitting anything. It does not accept a secret in argv,
connect to the network, start another service, or write a database. Operators
publish the signed result through an ordinary Nostr client and wait for the
relay's post-commit `OK` response.

When the protected key is a Google Secret Manager value, the manual helper
`scripts/sign-openagents-project-events-gcloud.sh` retrieves it into one shell
variable, checks its shape, passes it only in the signer process environment,
and unsets it on exit. The helper writes signed public events to stdout and
never writes or prints the private key:

```sh
scripts/sign-openagents-project-events-gcloud.sh \
  <gcp-project> <secret-name> ./target/release/immortal unsigned-events.json \
  > signed-events.json
```
