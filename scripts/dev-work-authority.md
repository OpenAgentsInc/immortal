# Dev work authority (NIP-WK / NIP-PI seed)

The dev work-item seed (`scripts/dev-work-seed.sh`, immortal#33) signs
kind-32170 Work Records, kind-32200 Issue Projections, and kind-32171 Work
Events with a **throwaway development authority keypair**. Consumers that
render the seeded planning graph (the openagents.com work-items demo,
omega#245) pin this pubkey:

```text
4d68446035e6e087d6398bfd3e741598823c6e5060697499e07e4b290a2633ac
```

Facts about this key:

- It is a dev-only placeholder. It is **not** the NIP-OT declared authority
  of any Organization, and events signed by it carry no organizational
  authority. Relay acceptance is transport evidence only.
- The secret is not in this repository (repository rule: no secrets). It
  lives in the owner's local secret store as
  `IMMORTAL_DEV_WORK_AUTHORITY_SECRET`. Publishing the canonical seed to
  `wss://relay.openagents.com` (`scripts/dev-work-seed.sh
  --publish-openagents`) requires that variable.
- Local runs never need it: without the variable the seeder generates a
  fresh throwaway keypair per run (the dev-market-seed convention) and
  reports its pubkey in the trace output.
- Rotating the key is cheap: generate a new keypair, update this file, run
  the seed against the relay, and repin the consumer.

Seed data source: `scripts/dev-work-items.json`, a public-safe snapshot of
the open `OpenAgentsInc/omega` issues (titles, states, labels, and issue
URLs only — never issue bodies). Refresh it with:

```sh
gh issue list -R OpenAgentsInc/omega --state open \
  --json number,title,state,labels,url
```

normalized into the `openagents.immortal.dev-work-items.v1` shape, then
rebuild and re-run `scripts/dev-work-seed.sh`.
