# Boltz released-client adapters

These clean-room CC0 seams adapt the pinned Go and web client sources to the
`openagents.mkt-swp.boltz-released-client.v2` profile. They copy no Boltz
source. The inspected upstream commits and Git blob identities are fixed in
`tests/fixtures/nipmkt/boltz-client-adapters-v1.json`.

Both implementations expose the same funding boundary:

1. the embedding wallet prepares raw transaction bytes without broadcasting;
2. the seam derives the exact transaction SHA-256 and output index;
3. the finalize callback receives the concrete session-scoped
   `/v2/swap/submarine/<id>/finalize` path, and the embedding Immortal client
   engine verifies both signed Swap Contracts, binds them to those exact
   bytes/output, and persists the script-path exit package;
4. the seam permits broadcast of the unchanged prepared transaction.

The approval callback is a trust boundary, not an HTTP response from the
provider. It must be backed by the transport-neutral `immortal-client` engine
or a generated SDK implementation of the same exported contract. Event IDs,
funding digest/output, exit-package digest, persistence result, and
script-path-only mode are checked again at the seam before broadcast.

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

This packet supplies buildable client seams and static/unit evidence. It does
not implement the provider HTTP/WebSocket listener and therefore changes
neither the 0/53 endpoint result nor the 0/19 dependent-call result. The
provider process replay remains the next #15 packet.
