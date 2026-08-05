# Boltz released-client adapters

These clean-room CC0 seams adapt the pinned Go and web client sources to the
`openagents.mkt-swp.boltz-released-client.v2` profile. They copy no Boltz
source. The inspected upstream commits and Git blob identities are fixed in
`tests/fixtures/nipmkt/boltz-client-adapters-v1.json`.

Both implementations expose the same funding boundary:

1. the seam accepts a session, address, and amount without Contract IDs;
2. the embedding wallet prepares raw transaction bytes without broadcasting;
3. the seam derives the exact transaction SHA-256 and output index;
4. the finalize callback receives the concrete session-scoped
   `/v2/swap/submarine/<id>/finalize` path, and the embedding Immortal client
   engine verifies both signed Swap Contracts, binds them to those exact
   bytes/output, persists the script-path exit package, and restores the
   funding-authorization snapshot;
5. the seam compares the provider finalize response with that local approval;
6. the seam permits broadcast of the unchanged prepared transaction.

The approval callback is a trust boundary, not an HTTP response from the
provider. It must be backed by the transport-neutral `immortal-client` engine
or a generated SDK implementation of the same exported contract. Contract
event IDs are callback outputs, not preparation inputs. Event IDs, funding
digest/output, exit-package digest, authorization-snapshot digest, persistence
result, and script-path-only mode are checked again at the seam before
broadcast.

## Go integration

`boltz-client-go/adapter.go` replaces the pinned daemon's one-shot wallet send
branch. The adapted build must split wallet funding into `PrepareFunding` and
`BroadcastPreparedFunding`, wire `FinalizeSubmarineAndPersistExit` to the
Immortal client engine and provider exchange, and construct the gate with all
three stock paths disabled. It must not run the full initialization that reads
chain pairs or starts Liquid listeners. Its WebSocket endpoint is an explicit
provider `ws://` or `wss://` `/v2/ws` URL.

## Web integration

`boltz-web-app/adapter.mjs` replaces the stock external-wallet handoff for the
Bitcoin submarine flow. An embedding wallet must provide raw prepared bytes;
an address/BIP21 launch cannot satisfy this profile. The adapted build also
suppresses chain-pair reads and cooperative helpers, and injects the explicit
provider WebSocket endpoint instead of deriving it from the relay HTTP URL.

Run the dependency-free source and unit gate with:

```sh
./scripts/test-boltz-client-adapters.sh
```

These files are clean-room extracted seams shaped from the pinned call
inventory. They are not patches to, or builds of, the pinned upstream Go
daemon and web application. `scripts/test-provider-funded.sh` runs each seam
against the provider listener with a separate fresh Rust client-engine session
and proves the causal prepare/finalize/authorize/broadcast sequence. The fresh
Go process also holds its provider WebSocket for more than 31 seconds across
the web JSON ping/pong and Go control ping/pong before receiving a status
update. The 19/19 count is route coverage for the inspected dependent-call
union.
