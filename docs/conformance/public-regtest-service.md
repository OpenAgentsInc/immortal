# Public regtest shared-service qualification

Public NIP-11 advertises NIP-59 because the relays accept and recipient-gate
kind-1059 gift wraps for private swap negotiation. A public browser must fail
closed when this transport capability is absent from the relay identity.

This packet turns the persistent topology and capability gateway into a
bounded, single-operator public regtest service. Its executable contract is
`tests/fixtures/lab/public-regtest-service-v1.json`. It is not a mainnet,
custodial API, production SLA, or independent-provider claim.

## Admission and capacity

The gateway refuses session creation unless a mode-0600 operator readiness
record is present, no more than 30 seconds old, names the exact deployed
revision/provider set and three Lightning nodes, and reports no failure. A
maintenance marker, unwritable receipt store, stale controller, unhealthy
topology, depleted Lightning side, low disk, leaked state, or exceeded value
bound therefore stops new sessions. The gateway independently recounts its
durable state and enforces 16 active sessions, 32 TCP connections, 5,000,000
outstanding sats, two effects per session, 1,000,000 sats per effect, a
one-hour lifetime ceiling, and persistent IP/session request windows.

`GET /healthz` proves only process and receipt-store liveness. `GET /readyz`
is the strict admission view. `GET /metrics` returns public-safe counters; it
never returns capabilities, destinations, raw transactions, invoices,
preimages, credentials, or rail endpoints.

## Private operator loop

`scripts/public-regtest-operator.sh loop` runs beside the loopback gateway.
It reuses the topology's private Compose authority to inspect both chain tips,
both providers/relays, all three Lightning nodes and channel balances, disk,
session exposure, and receipt storage. It atomically publishes only the
bounded readiness record. It mines at most six blocks in one pass, and only
when an admitted public effect exists and the private regtest mempool is not
empty. Miner RPC is never public.

The same loop launches at most one worker per pending capability-bound
dynamic request. Workers run asynchronously so the controller can continue
mining, use a session-specific requester state directory, and retain a PID
lock that is recovered after operator replacement. The worker executes the
ordinary two-provider protocol path; the loop neither rewrites the request
nor receives a generic wallet/RPC method.

The same loop watches capability-owned `demo-input-request.json` records. It
runs the fixed wallet-driver allocation command inside the private acceptance
network, writes one mode-0600 response, and never grants the gateway a Docker
socket, CLN RPC, Bitcoin RPC, wallet seed, or arbitrary method surface.
The worker runs as the host state owner's UID:GID. Its only supplemental group
is the CLN container socket group, so files remain readable by the separate
gateway process without granting that public process Docker or rail authority.

Each Lightning node must retain at least 250,000,000 msat on both sides and
the aggregate capacity bound is 10,000,000,000 msat. Depletion first makes
readiness false. With no active session or outstanding effect, the controller
may rebalance 100,000,000-msat chunks between a provider and requester node;
it never rebalances across active customer state.

Receipt-bearing terminal sessions are retained for seven days; empty expired
sessions are retained for one day. Cleanup removes a session only when every
durable admission has a matching receipt. An unresolved effect is retained
for recovery, regardless of age.

## Qualification

Run `scripts/test-public-regtest-service.sh`. It validates the closed service
contract and operator policy, then runs the real gateway process fault gate.
Rust tests additionally prove stale and maintenance refusal, five concurrent
active session records, and 50 sequential create/revoke cycles. The live
funded two-provider journeys remain covered by
`scripts/test-dynamic-funded-topology.sh`.

The final public acceptance receipt belongs to the remote Bazaar deployment:
it must record the exact Immortal/Bazaar revisions and digests, public HTTPS
and both WSS authorities, five-overlapping-session evidence, 50 sequential
funded terminal journeys, fault/restart results, and the explicit
single-operator/regtest-only claim boundary. Browser proof is intentionally
not fabricated by this repository's host-side gate.
