# immortal-lab

Dev-only wallet-side harness for the adversarial regtest lab (immortal#32,
consumed by immortal#18). **Lab tooling only: this binary is never deployed,
never part of the shipped product set, and nothing in the product crates may
depend on it.**

It drives the real client engine from `crates/immortal-client`
(`SwapRecordFactory`, the MKT-SWP validators, the NIP-59 wrap/unwrap
primitives) against a loopback dev relay — the same wire
`scripts/dev-relay.sh` and `scripts/dev-market-provider.sh` use.

## Commands

| Step | What it does |
| --- | --- |
| `discover` | Queries the relay for Provider Profiles (39600) and Offerings (39601), validates them with `validate_mkt_public_event`, persists a discovery snapshot. Needs no authentication. |
| `rfq` | Creates (or reloads) the persisted lab identity, opens a session, builds an MKT-SWP RFQ through `SwapRecordFactory` from the pinned full-session fixture profile (`tests/fixtures/nipmkt/swp-full-sessions-v1.json`), signs it, gift-wraps it twice (counterparty + recovery), and publishes both wraps. `--swap-type submarine|reverse|chain`. |
| `quote` | NIP-42-authenticates, reads the recipient-gated kind-1059 subscription (stored history first, then a bounded live wait), unwraps with `unwrap_mkt_record`, and persists the session's Quote. Safe to re-run until the Quote arrives. |
| `verify` | The verify-before-fund gate rendered from the engine's real verification output: structural revalidation of the signed Quote bytes, quote/reservation/expiration tag grammar, staleness, `validate_quote_profile`, and `validate_quote_against_rfq`. Prints a JSON verdict; a failing gate exits non-zero and marks the session `verification_failed`. |
| `fund` | Runs a funded submarine session through bilateral contract verification, a persisted engine funding authorization, exact regtest transaction broadcast, and locally verified terminal Close. |
| `claim` | Runs a reverse session, persists its wallet-only preimage before RFQ publication, pays the provider hold invoice, and broadcasts the requester script-path claim. |
| `refund` | Runs the noncooperative reverse lane until the provider's script-path refund and cancelled hold invoice are locally verified. |
| `funded-smoke` | Runs all three funded journeys and writes the private evidence consumed by `scripts/test-provider-funded.sh`. |
| `status` | Prints the persisted state (identity pubkey, discovery summary, sessions and their steps). |
| `run --to <step>` | Runs the no-spend preflight through `verify`, or funded submarine → reverse claim → reverse refund journeys through the selected funded step. |

## Persistence (the doomsday-drill substrate)

All state lives under one directory (`IMMORTAL_LAB_STATE_DIR`, default
`target/lab-state`):

- `identity.json` — throwaway dev-only lab identity secret, written mode
  0600. It signs loopback regtest records only; never fund or reuse it.
- `discovery.json` — last discovery snapshot.
- `sessions/<session_id>.json` — one append-style record per session:
  RFQ, Quote, verification verdict, and the last completed step.
- `current-session` — pointer used when `IMMORTAL_LAB_SESSION` is unset.
- `funded-run-id` — stable identifier that prevents a restarted process from
  creating a timestamp fork in the same journey.
- `funded-<journey>-session.json` — the client engine's custody-free v2
  snapshot, persisted before the first rail effect and after every accepted
  record or external-effect ledger update.
- `funded-<journey>-secret` — 0600 wallet-only reverse preimage record. It is
  never placed in the engine snapshot, checkpoint, evidence, relay, provider,
  or provider database and is removed at terminal Close.
- `funded-checkpoint.json` — the current labeled restart boundary. Checkpoint
  details contain record IDs and snapshot paths, never custody material.

Every file and directory is mode 0600/0700 on Unix and every write is
sync-plus-temp-file rename. `IMMORTAL_LAB_STOP_AFTER=<journey>:funding_authorized`
exits after the authorized engine snapshot exists and before a rail call.
Re-running the same command restores the snapshot with
`resume_funding_authorized` and continues the same signed session. For a
scripted provider/relay injection without stopping the harness, set
`IMMORTAL_LAB_INJECT_AT` to that label; the harness waits a bounded interval
for the state directory's `funded-continue` file.

## Safety rails

- Only `ws://` loopback relay URLs are accepted (same refusal as
  `dev-market-seed`), so throwaway traffic cannot reach a production relay.
- Dependency allowlist: the workspace's seven pinned crates. The harness also
  reuses the in-repo `immortal-client`, `immortal-core`, and
  `immortal-provider` rail/wallet libraries; shipped products do not depend on
  the lab crate.

## Typical loop

```sh
./scripts/dev-relay.sh                                   # terminal 1
IMMORTAL_PROVIDER_IDENTITY_SECRET=$(printf '02%.0s' $(seq 32)) \
  ./scripts/dev-market-provider.sh                       # terminal 2
cargo run -p immortal-lab -- run --to verify             # terminal 3
cargo run -p immortal-lab -- status
```

The regtest node fixtures are provisioned by `scripts/lab-bitcoind.sh` and
`scripts/lab-cln.sh`;
`scripts/lab-topology.sh` prints the port/datadir/identity manifest.
