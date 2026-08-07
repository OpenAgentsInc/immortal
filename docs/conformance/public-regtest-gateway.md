# Public-regtest capability gateway

`immortal-public-regtest-gateway` is the public HTTP boundary between an
untrusted Bazaar browser and the private funded-regtest worker. It is a new
mode; the loopback-only `browser-demo-adapter` remains unchanged.

## Authority boundary

The gateway binds only to numeric IPv4 loopback and is published through an
operator TLS proxy. It accepts one configured exact `https://` Origin. The
proxy must overwrite `X-Immortal-Client-IP` with the numeric peer address;
the gateway refuses a non-loopback proxy peer, a missing/ambiguous header, or
a capability replayed from another client address.

The public runtime image and crate contain only the closed gateway entrypoint
plus shared pure protocol primitives. The crate dependency graph has
`immortal-core`, `serde`, `serde_json`, and `sha2`; it does not link the lab,
client engine, provider, async runtime, or database client. It has
no bitcoind, Lightning, shell, database-query, destination-host, filesystem-
path, or arbitrary RPC HTTP operation. Its writable mount contains only:

- bounded session metadata and SHA-256 capability digests;
- one mode-0600 private dynamic request pending semantic validation, deleted
  immediately after a terminal public projection is durable;
- redacted effect authorizations emitted by the private requester worker;
- exact admitted redacted requests and public-safe effect receipts;
- bounded IP/session quota state, operator readiness, public-safe counters,
  and atomic lock directories.

The signing key is a separate mode-0600 read-only file. Wallet seeds, raw
transactions, preimages, node credentials, and rail endpoints are not mounted
or serialized. A submitted address or invoice is never logged, returned,
signed, or copied into the public manifest; it exists only in the fixed private
handoff until the funded worker validates and retires it. The funded worker
still compares the admitted
redacted request with its complete in-memory `FundingAuthorizationRequest`
before the existing wallet/rail code runs.

## Session and capability contract

`POST /v1/public-regtest/sessions` accepts a closed requester identity and
client nonce. It returns a 256-bit random capability once and stores only its
SHA-256 digest. The response also contains a NIP-01-shaped Schnorr-signed
manifest whose event content is recursively key-sorted canonical JSON and is
bound to:

- the exact Origin, client IP policy, sandbox session, requester identity,
  expiry, regtest network, source revision, requester-contract digest, and
  browser ABI version;
- the private worker's distinct requester-engine identity after semantic
  request admission, so an effect signed by either a visitor identity or a
  different sandbox worker fails closed;
- the configured and authorization-observed provider set;
- fixed request/effect/amount quotas and the two allowed effect methods;
- each authorized engine session, Order, provider, effect ID, complete
  idempotency digest, method, amount, and durable receipt state.

Authenticated `GET` reads that state. Authenticated `DELETE` revokes the
session. `POST .../requests` accepts one bounded, capability/session-bound
dynamic request with exact idempotent replay; a changed replay conflicts. The
private worker validates network, encoding, amount, expiry, invoice features,
and destination commitment before publishing only the redacted view.
`POST .../effects` accepts only the exact authorization already
written by the private worker. A changed sandbox/engine session, Order,
provider, network, amount, method, effect ID, or digest fails before worker
dispatch.

`POST .../inputs` is the public-demo convenience boundary. It accepts only a
session-bound `reverse|submarine` plus an amount inside the existing funded
range. A private requester-rail worker allocates one deterministic `bcrt1`
destination or one amount-bearing, three-hour `lnbcrt` invoice and returns it
only to the authenticated browser request. The three-hour Lightning rail
expiry outlives the funded Quote, funding, and confirmation timeout ladder;
the allocation response itself remains usable for only ten minutes. The
public gateway still has no
wallet or node credential. Exact retries return the same allocation; changed
amounts or directions conflict, and an accepted swap request permanently
closes allocation for that session. This endpoint is not a general faucet,
wallet, invoice, mining, or RPC API.

The initial contract permits at most two effects and 1,000,000 sats per
effect, with one in-flight effect per session. Sessions expire in at most one
hour. Persistent IP and session windows return typed `rate_limited` responses
with retry guidance. Other
typed terminal/refusal codes distinguish origin, IP, capability, expiry,
revocation, conflict, framing, bound, timeout, and unavailable-state errors.

## Replay and recovery

Admission and receipts use fixed, mode-0600 paths under a per-session
directory. An atomic per-session lock serializes competing requests. The
admission uses create-new semantics; exact duplicates wait for or replay the
one durable receipt, while changed duplicates fail. Killing the gateway after
admission cannot revoke or duplicate the private worker effect. A replacement
gateway reopens the same bounded state and returns the prior serialized
receipt bytes. After successfully taking the one loopback listener, a
replacement waits one second for any short private-worker lock and then
removes only validated stale lock directories left by a dead process.

Abandoned/expired sessions cannot authorize new effects. Their already-
admitted effects remain visible to the private worker so it can report the
truthful rail outcome rather than pretending revocation undid an external
effect. The shared-service controller retains receipt-bearing terminal state
for seven days, empty expired state for one day, and deletes it only when
every admission has a receipt. See
[`public-regtest-service.md`](public-regtest-service.md).

## Configuration

Required gateway environment:

```text
IMMORTAL_PUBLIC_REGTEST_GATEWAY_STATE_DIR=/var/lib/immortal-public-regtest-gateway
IMMORTAL_PUBLIC_REGTEST_GATEWAY_BIND=127.0.0.1:19337
IMMORTAL_PUBLIC_REGTEST_ORIGIN=https://bazaar.example
IMMORTAL_PUBLIC_REGTEST_SIGNING_KEY_FILE=/run/immortal-private/gateway-signing-key
IMMORTAL_PUBLIC_REGTEST_SOURCE_REVISION=<40-lower-hex-git-commit>
IMMORTAL_PUBLIC_REGTEST_REQUESTER_CONTRACT_DIGEST=<64-lower-hex>
IMMORTAL_PUBLIC_REGTEST_PROVIDER_SET=<provider-a-pubkey>,<provider-b-pubkey>
```

Optional bounded controls are
`IMMORTAL_PUBLIC_REGTEST_SESSION_LIFETIME_SECONDS` (1–3,600; default 900)
and `IMMORTAL_PUBLIC_REGTEST_EFFECT_TIMEOUT_SECONDS` (1–900; default 180).
Use the gateway block in `deploy/public-regtest/Caddyfile.example` and expose
only TLS, never port 19337.

## Verification and claims

Run:

```sh
scripts/test-public-regtest-gateway.sh
```

The process gate creates a real gateway process, validates its signed
manifest/capability contract, proves the raw capability is absent from disk,
proves exact dynamic-request replay and changed-request refusal,
replaces the gateway between admission and receipt, returns exact receipt
bytes under concurrent replay, and refuses foreign origins, foreign IPs,
changed providers, duplicate JSON, revocation replay, and custody-bearing
public output. Unit tests cover expiry, invalid methods/networks, unknown
members, and cryptographic manifest verification.

This is public regtest authorization infrastructure, not a mainnet wallet
API. The private `public-regtest-dynamic-worker-once` command consumes the
request through the ordinary two-provider RFQ/Quote/Order/Contract path,
cancels the unselected reservation, waits for exact browser effect admission,
and publishes requester-verified Bitcoin and Lightning references separately
from provider Status. Destination semantics are qualified in
[`dynamic-public-regtest.md`](dynamic-public-regtest.md).
Shared-service bounds and host fault gates are qualified separately in
[`public-regtest-service.md`](public-regtest-service.md); remote TLS/browser
acceptance is emitted by the deployed Bazaar packet.
