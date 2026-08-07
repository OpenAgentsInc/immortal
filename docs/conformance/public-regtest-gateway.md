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
- redacted effect authorizations emitted by the private requester worker;
- exact admitted redacted requests and public-safe effect receipts;
- bounded IP/session quota state and atomic lock directories.

The signing key is a separate mode-0600 read-only file. Wallet seeds, raw
transactions, invoices, preimages, node credentials, and rail endpoints are
not mounted or serialized. The funded worker still compares the admitted
redacted request with its complete in-memory `FundingAuthorizationRequest`
before the existing wallet/rail code runs.

## Session and capability contract

`POST /v1/public-regtest/sessions` accepts a closed requester identity and
client nonce. It returns a 256-bit random capability once and stores only its
SHA-256 digest. The response also contains a NIP-01-shaped Schnorr-signed
manifest bound to:

- the exact Origin, client IP policy, sandbox session, requester identity,
  expiry, regtest network, source revision, requester-contract digest, and
  browser ABI version;
- the configured and authorization-observed provider set;
- fixed request/effect/amount quotas and the two allowed effect methods;
- each authorized engine session, Order, provider, effect ID, complete
  idempotency digest, method, amount, and durable receipt state.

Authenticated `GET` reads that state. Authenticated `DELETE` revokes the
session. `POST .../effects` accepts only the exact authorization already
written by the private worker. A changed sandbox/engine session, Order,
provider, network, amount, method, effect ID, or digest fails before worker
dispatch.

The initial contract permits at most two effects and 1,000,000 sats per
effect, with one in-flight effect per session. Sessions expire in at most one hour. Persistent IP and session
windows return typed `rate_limited` responses with retry guidance. Other
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
effect. Retention and automated cleanup policy are qualified in issue #44.

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
replaces the gateway between admission and receipt, returns exact receipt
bytes under concurrent replay, and refuses foreign origins, foreign IPs,
changed providers, duplicate JSON, revocation replay, and custody-bearing
public output. Unit tests cover expiry, invalid methods/networks, unknown
members, and cryptographic manifest verification.

This is public regtest authorization infrastructure, not a mainnet wallet
API. Dynamic destinations, two-Quote selection, and production session
negotiation remain issue #43; shared-service load and remote TLS acceptance
remain issue #44.
