# immortal-lab

Dev-only wallet-side harness for the adversarial regtest lab (immortal#32,
consumed by immortal#18). **Lab tooling only: this binary is never deployed,
never part of the shipped product set, and nothing in the product crates may
depend on it.**

It drives the real client engine from `crates/immortal-client`
(`SwapRecordFactory`, the MKT-SWP validators, the NIP-59 wrap/unwrap
primitives) against a loopback dev relay — the same wire
`scripts/dev-relay.sh` and `scripts/dev-market-provider.sh` use.

## Implemented

| Step | What it does |
| --- | --- |
| `discover` | Queries the relay for Provider Profiles (39600) and Offerings (39601), validates them with `validate_mkt_public_event`, persists a discovery snapshot. Needs no authentication. |
| `rfq` | Creates (or reloads) the persisted lab identity, opens a session, builds an MKT-SWP RFQ through `SwapRecordFactory` from the pinned full-session fixture profile (`tests/fixtures/nipmkt/swp-full-sessions-v1.json`), signs it, gift-wraps it twice (counterparty + recovery), and publishes both wraps. `--swap-type submarine|reverse|chain`. |
| `quote` | NIP-42-authenticates, reads the recipient-gated kind-1059 subscription (stored history first, then a bounded live wait), unwraps with `unwrap_mkt_record`, and persists the session's Quote. Safe to re-run until the Quote arrives. |
| `verify` | The verify-before-fund gate rendered from the engine's real verification output: structural revalidation of the signed Quote bytes, quote/reservation/expiration tag grammar, staleness, `validate_quote_profile`, and `validate_quote_against_rfq`. Prints a JSON verdict; a failing gate exits non-zero and marks the session `verification_failed`. |
| `status` | Prints the persisted state (identity pubkey, discovery summary, sessions and their steps). |
| `run --to <step>` | Runs discover → rfq → quote → verify in order up to `<step>`. |

## Stubbed — blocked on immortal#25

`fund`, `claim`, and `refund` exit with code 2 and an explicit message. They
cannot exist before the funded provider rails (bitcoind RPC, CLN unix-socket,
wallet, script-path settlement, watchtower) land in #25. The Order/contract
exchange and the funded doomsday drill land with them.

## Persistence (the doomsday-drill substrate)

All state lives under one directory (`IMMORTAL_LAB_STATE_DIR`, default
`target/lab-state`):

- `identity.json` — throwaway dev-only lab identity secret, written mode
  0600. It signs loopback regtest records only; never fund or reuse it.
- `discovery.json` — last discovery snapshot.
- `sessions/<session_id>.json` — one append-style record per session:
  RFQ, Quote, verification verdict, and the last completed step.
- `current-session` — pointer used when `IMMORTAL_LAB_SESSION` is unset.

Every write is temp-file-plus-rename, so the harness can be killed at any
step and restarted; each step reloads exactly what was persisted. The full
kill/restart drill matrix is #18 scope.

## Safety rails

- Only `ws://` loopback relay URLs are accepted (same refusal as
  `dev-market-seed`), so throwaway traffic cannot reach a production relay.
- Dependency allowlist: the workspace's seven pinned crates; currently only
  `tokio-tungstenite` (for its blocking `tungstenite` re-export), `serde`,
  `serde_json`, and `sha2` are used, plus `immortal-client`.

## Typical loop

```sh
./scripts/dev-relay.sh                                   # terminal 1
IMMORTAL_PROVIDER_IDENTITY_SECRET=$(printf '02%.0s' $(seq 32)) \
  ./scripts/dev-market-provider.sh                       # terminal 2
cargo run -p immortal-lab -- run --to verify             # terminal 3
cargo run -p immortal-lab -- status
```

The regtest node fixtures (bitcoind, CLN) that the funded steps will need are
provisioned by `scripts/lab-bitcoind.sh` and `scripts/lab-cln.sh`;
`scripts/lab-topology.sh` prints the port/datadir/identity manifest.
