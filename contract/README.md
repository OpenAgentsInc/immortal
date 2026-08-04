# Immortal machine contract

`immortal-contract.json` is the deterministic descriptor printed by
`immortal contract`. `immortal-fixtures.json` hashes the exact committed
fixture bytes consumed by downstream SDK conformance.

Regenerate both artifacts after a protocol sync or adoption change:

```sh
./scripts/export-contract.sh
git diff -- contract/
```

Verify an unchanged tree without rewriting the artifacts:

```sh
./scripts/export-contract.sh --check
```

The artifact identifies the Immortal crate version and all three pinned NIP
source commits. It describes relay-observable behavior and marks encrypted
NIP-MKT client checks separately. The MKT-SWP section records its v1 Offering,
evidence, kind-39610, privacy, and complete fixture-manifest contract. Its
coordination subsection pins the off-by-default handler activation digest,
bounds, proof-class ordering, timer law, observation authority, and Postgres
consistency model while keeping `executable_profiles` empty. Its client-engine
subsection records the transport-neutral requester surface. The client-scoped
fixture set also includes the fail-closed tbDEX 1.0 legacy translation audit
and its exact
test-only nine-schema/ten-vector source replay. That audit emits no Nostr event
and grants no source record NIP-MKT authority.

## Consumers

- `OpenAgentsInc/openagents/packages/nip-mkt` generates Effect Schema codecs
  from the pinned descriptor and replays the exact fixture bytes. Its Nostr
  transport extends the workspace `nostr-effect` package.
- `apps/openagents.com` consumes that package for the local market demo. Relay
  `OK` remains transport acceptance, not execution or settlement proof.
- Omega pins this crate without the `server` feature and reuses the
  transport-neutral Rust domain validation. Its GPUI surface owns WebSocket
  transport and does not embed the relay server.

Consumers pin both JSON files together. A contract identity or fixture digest
change requires regeneration and a reviewed diff.
