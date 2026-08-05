# Boltz compatibility handoff

The relay has an off-by-default, digest-gated handoff for a bounded Boltz v2
released-client profile. It does not implement the provider API. Every
recognized request receives `307 Temporary Redirect` to an independently
deployed `immortal-provider` endpoint. The redirect preserves the method and
body, and the relay responds from the HTTP head without reading or persisting
the body. The funded provider implements the corresponding off-by-default
HTTP/WebSocket API from signed native MKT-SWP sessions.

This split follows the workspace custody boundary in `docs/MONOREPO.md`.
Wallet, preimage, signing, broadcast, Lightning-node, and rail effects belong
to the provider or client products. The relay crate continues to depend on
`immortal-core` and never links `immortal-client` or `immortal-provider`.

The source pins are:

| Project | Commit |
| --- | --- |
| `boltz-backend` | `4d131ef8562eea25ab687bcc75a17ce899110b66` |
| `boltz-client` | `746f73c5ecbd3621f628f60108a404ef26f0de95` |
| `boltz-web-app` | `dd9c2df26db54a2554dc1e628b095ce856c0d9de` |

No Boltz source was copied. The fixture records observable routes and the
configuration contract derived from those pinned revisions.

## Activation

Both variables are required:

- `IMMORTAL_BOLTZ_FACADE_CONFORMANCE_SHA256` must equal
  `.mkt.mkt_swp.boltz_facade.conformance_sha256` in `immortal contract`.
- `IMMORTAL_BOLTZ_FACADE_PROVIDER_BASE_URL` is an HTTPS origin, or an HTTP
  loopback origin for local development. Userinfo, paths, queries, fragments,
  whitespace, backslashes, and trailing slashes are rejected. When the relay
  public URL is configured, the provider origin must differ so redirects
  cannot loop back into the relay.

The façade is absent when both variables are absent. Configuring only one,
using a stale digest, or using plaintext HTTP to a non-loopback provider fails
startup. It is never advertised in NIP-11. Handoffs share the bounded relay
request rate and connection limit. Unsafe origin-form paths and traversal
spellings fail closed before a `Location` header is constructed.

The provider listener independently requires all three values:

- `IMMORTAL_PROVIDER_BOLTZ_BIND` is a private or loopback numeric socket;
- `IMMORTAL_PROVIDER_BOLTZ_CONFORMANCE_SHA256` equals
  `operations.boltz_compatibility.conformance_sha256` in
  `immortal-provider contract`; and
- `IMMORTAL_PROVIDER_BOLTZ_ALLOWED_ORIGIN` is one exact bounded HTTP(S)
browser origin, without wildcard, credentials, path, query, or fragment.

All three absent disables the listener. A partial profile, stale digest,
public bind, or invalid origin fails startup. Supplied browser origins must
match exactly; native clients may omit `Origin`. The API applies 64 concurrent
connection permits, 120 requests per minute per source address, bounded HTTP
heads/bodies and WebSocket frames/subscriptions, and a bounded signed-record
scan. It is never advertised in NIP-11.

Submarine finalize returns the exact signed exit-package commitment mode with
its SHA-256. `presigned` means a keyless package; `wallet_sign` means the
persisted package still names the wallet signing callback. The compatibility
response never treats those modes as equivalent, and each adapted client
checks the returned mode and digest against its persisted package before
broadcast.

The external provider endpoint must be reachable by the client. A loopback
provider URL is suitable only when the client is on that host. WebSocket
libraries do not consistently follow HTTP redirects during upgrade, so the
released profile gives the client the provider WebSocket URL directly; the
relay's `/v2/ws` response is a discovery handoff, not a WebSocket proxy.

## Released-client profile

`bitcoin-lightning-script-path-v1` has these non-negotiable settings:

- Bitcoin and Lightning only; Liquid, EVM, Ark, commitment, BOLT12, rescue,
  and DEX quote paths are disabled.
- `boltz-web-app` sets `cooperativeDisabled=true`.
- `boltz-client` sets `Api.DisablePartialSignatures=true`; the released daemon
  needs an adapter because the pinned `boltzd` does not wire that field
  itself. The library's disabled-partial-signature branch also fails a
  submarine refund instead of constructing the script-path refund.
- The Go adapter must avoid the full daemon initialization path, which fetches
  chain pairs and starts Liquid-oriented listeners, and inserts the finalize
  handoff before funding broadcast. The stock wallet `SendToAddress` method
  broadcasts immediately and exposes no such callback.
- The web adapter must suppress its unconditional chain-pairs read and the
  preliminary submarine claim-details read that remains even with
  `cooperativeDisabled=true`. Its stock `PayOnchain` path hands an address or
  BIP21 URI to an external wallet and never observes the raw funding
  transaction needed by finalization.
- Both adapters receive the provider WebSocket URL explicitly. The stock web
  client derives it from the HTTP API origin, which would point at the relay
  handoff instead of the provider WebSocket.
- The client owns preimages, funding inputs, change, claim/refund keys, and
  unilateral exit packages.
- Provider-local helpers own released-preimage lookup, public raw-transaction
  lookup, and session-bound broadcast. Their bodies never traverse the relay.
- Recovery uses signed MKT-SWP records and the client snapshot, not operator
  metadata or restore storage.

An unmodified URL-only stock client is not compatible with submarine swaps.
After accepting a Quote it constructs the funding transaction, then calls:

```text
POST /v2/swap/submarine/:id/finalize
```

The provider verifies that the lowercase raw transaction, SHA-256, and output
index resolve exactly the requester-funded source verifier without changing
any other Quote term. Both participants then sign matching `kind:39610` Swap
Contracts. The client may broadcast only after both Contracts are present and
its local verifier has rechecked the funding output and persisted its exit
package. The handoff does not weaken MKT-SWP section 4.1 and does not give the
relay wallet authority.

Reverse flow may start from the provider-funded transaction already bound by
the signed Quote and bilateral Contracts. Script-path claim and refund remain
the v1 recovery paths; cooperative MuSig2 helpers are excluded.

### Adapted-client source gate

The clean-room CC0 seams under `adapters/` are built independently of Cargo
and add no Rust dependency:

- `boltz-client-go/adapter.go` is a Go-standard-library funding gate for the
  pinned daemon integration.
- `boltz-web-app/adapter.mjs` is a browser/Node-standard-library funding gate
  for the pinned web integration.

Both enforce the fixture sequence: prepare raw funding without broadcast,
derive its exact SHA-256 and output index, require the requester and provider
Contract event IDs plus a persisted script-path exit package from the local
Immortal client engine, then broadcast the unchanged prepared bytes. The
constructors require explicit partial/cooperative-helper and chain-pair
disablement plus a direct provider WebSocket URL. Static tests exclude those
stock calls, the one-shot wallet method, and the external-wallet handoff from
the production adapter sources. An upstream build must integrate these seams
at the pinned call sites; a configuration flag alone is insufficient.

`tests/fixtures/nipmkt/boltz-client-adapters-v1.json` pins the upstream source
and blob identities, the 13-call Go subset, the 15-call web subset, and their
exact 19-call union. `scripts/test-boltz-client-adapters.sh` runs both
dependency-free unit suites. The funded smoke also runs both adapter processes
against the provider listener and the same signed sessions used for its native
rail journeys.

## Endpoint matrix

The denominator is the 53 routes registered by the pinned backend's Swap,
Chain, Referral, Info, Nodes, and Commitment v2 routers. A relay redirect is
not `emulated`. Rows marked `emulated` or `emulated-degraded` are served by the
external provider and covered by its process conformance gate. `refused` and
`not-applicable-single-operator` are product decisions.

| Endpoint | Disposition | Reason or MKT equivalent |
| --- | --- | --- |
| `GET /v2/version` | emulated | Provider reports the compiled mapping revision, released profile, and implementation version. |
| `GET /v2/infos` | not-applicable-single-operator | Provider Profile `39600` and Offering `39601`. |
| `GET /v2/warnings` | not-applicable-single-operator | Signed provider discovery and Status records. |
| `GET /v2/swap/submarine` | emulated | Provider projects configured pricing and live rail capacity. |
| `POST /v2/swap/submarine` | emulated | Request names an existing signed RFQ/Quote session; the API signs nothing for the requester. |
| `PATCH /v2/swap/:id/metadata` | refused | Recovery metadata remains client-local or in private signed records. |
| `POST /v2/swap/submarine/:id/invoice` | refused | The released profile supplies the invoice at creation. |
| `GET /v2/swap/submarine/:id/invoice/amount` | deferred | Provider-local session helper. |
| `GET /v2/swap/submarine/:id/transaction` | emulated | Returns the exact bilaterally committed funding transaction. |
| `GET /v2/swap/submarine/:id/preimage` | emulated | Extracts the hash-bound value only from the public provider claim transaction. |
| `GET /v2/swap/submarine/:id/refund` | deferred | EVM refund shape waits for an adopted EVM profile. |
| `POST /v2/swap/submarine/:id/refund` | refused | Cooperative partial signatures are disabled. |
| `POST /v2/swap/submarine/refund` | refused | Deprecated cooperative signing route. |
| `POST /v2/swap/submarine/:id/refund/ark` | deferred | Ark waits for its adopted profile. |
| `GET /v2/swap/submarine/:id/claim` | refused | Cooperative claim helper is outside script-path mode. |
| `POST /v2/swap/submarine/:id/claim` | refused | Cooperative partial signatures are disabled. |
| `GET /v2/swap/reverse` | emulated | Provider projects configured pricing and live rail capacity. |
| `POST /v2/swap/reverse` | emulated | Existing signed RFQ/Quote and bilateral Contract material binds the response. |
| `GET /v2/swap/reverse/expiry` | deferred | Provider-local hold-expiry policy. |
| `GET /v2/swap/reverse/:id/transaction` | emulated | Returns the exact provider funding transaction committed by both Contracts. |
| `POST /v2/swap/reverse/:id/claim` | refused | Cooperative partial signatures are disabled; v1 claims through the script path and the chain broadcast route. |
| `POST /v2/swap/reverse/claim` | refused | Deprecated unscoped custody-bearing route. |
| `GET /v2/swap/reverse/:invoice/bip21` | emulated-degraded | BIP21 binds the signed invoice and output; `signature` is the signed Status Nostr signature because there is no single-operator BIP322 authority. |
| `GET /v2/swap/chain` | deferred | Chain compatibility waits for the provider route and the #27 rail packet. |
| `POST /v2/swap/chain` | deferred | Chain compatibility waits for the provider route and the #27 rail packet. |
| `GET /v2/swap/chain/:id/transactions` | deferred | Provider-local public transaction helper. |
| `GET /v2/swap/chain/:id/claim` | refused | Cooperative partial signatures are disabled. |
| `POST /v2/swap/chain/:id/claim` | refused | Cooperative partial signatures are disabled. |
| `GET /v2/swap/chain/:id/refund` | deferred | EVM refund shape waits for an adopted EVM profile. |
| `POST /v2/swap/chain/:id/refund` | refused | Cooperative partial signatures are disabled. |
| `POST /v2/swap/chain/:id/refund/ark` | deferred | Ark waits for its adopted profile. |
| `GET /v2/swap/chain/:id/quote` | deferred | Provider-signed renegotiation Quote. |
| `POST /v2/swap/chain/:id/quote` | deferred | Provider-side exact Quote acceptance. |
| `GET /v2/swap/status` | emulated | Bounded batch projects dense signed Status; gaps and forks fail closed. |
| `GET /v2/swap/:id` | emulated | Latest dense signed Status is projected to the released vocabulary. |
| `GET /v2/chain/fees` | emulated | Live bitcoind estimate or explicit bounded provider fallback. |
| `GET /v2/chain/heights` | deferred | Provider-local rail observation. |
| `GET /v2/chain/contracts` | deferred | EVM contracts wait for an adopted EVM profile. |
| `GET /v2/chain/:currency/fee` | emulated | BTC only; live bitcoind estimate or explicit bounded fallback. |
| `GET /v2/chain/:currency/height` | emulated | BTC only; live bitcoind chain tip. |
| `GET /v2/chain/:currency/transaction/:id` | emulated | BTC only; bounded public raw-transaction lookup. |
| `POST /v2/chain/:currency/transaction` | emulated | BTC only; exact committed funding or verified reverse script-path claim, idempotent by public txid. |
| `GET /v2/chain/:currency/contracts` | deferred | EVM contracts wait for an adopted EVM profile. |
| `GET /v2/commitment/:currency/details` | deferred | Requires an adopted reservation-class decision. |
| `POST /v2/commitment/:currency` | deferred | Requires an adopted reservation-class decision. |
| `POST /v2/commitment/:currency/refund` | deferred | Requires an adopted reservation-class decision. |
| `GET /v2/nodes` | deferred | Provider-scoped node projection, never market-wide authority. |
| `GET /v2/nodes/stats` | emulated-degraded | Provider reports its live Lightning capacity; channel, peer, and market-age totals are unavailable in the narrow rail interface. |
| `GET /v2/nodes/:currency/:node/hints` | not-applicable-single-operator | Provider endpoints are signed in discovery; routing is client-owned. |
| `GET /v2/referral` | not-applicable-single-operator | No market-wide referral authority. |
| `GET /v2/referral/fees` | not-applicable-single-operator | Fees are signed in each Offering and Quote. |
| `GET /v2/referral/stats` | not-applicable-single-operator | No referral accounting authority. |
| `GET /v2/referral/stats/extra` | not-applicable-single-operator | No referral accounting authority. |

Endpoint-surface coverage is **17/53 (32.08%) emulated**. The relay redirect is
not counted. The remaining routes are refused, single-operator-only, or
deferred to named rail/profile work; raising this percentage by recreating
Boltz operator authority is not a goal.

## Dependent-call gate

Mapping revision `openagents.mkt-swp.boltz-released-client.v2` contains exactly
19 route shapes:

| # | Route | Released-profile caller |
| ---: | --- | --- |
| 1 | `GET /v2/version` | Go |
| 2 | `GET /v2/swap/submarine` | Go, web |
| 3 | `POST /v2/swap/submarine` | Go, web |
| 4 | `POST /v2/swap/submarine/:id/finalize` | Go adapter, web adapter |
| 5 | `GET /v2/swap/reverse` | Go, web |
| 6 | `POST /v2/swap/reverse` | Go, web |
| 7 | `GET /v2/swap/:id` | web |
| 8 | `GET /v2/swap/status?ids=...` | web, up to 64 lowercase 32-byte identifiers |
| 9 | `GET /v2/ws` | Go, web discovery handoff |
| 10 | `GET /v2/swap/submarine/:id/transaction` | Go, web |
| 11 | `GET /v2/swap/reverse/:id/transaction` | web |
| 12 | `GET /v2/swap/submarine/:id/preimage` | Go, web |
| 13 | `GET /v2/swap/reverse/:invoice/bip21` | web; `:invoice` must parse as BOLT11 |
| 14 | `GET /v2/chain/fees` | web |
| 15 | `GET /v2/chain/BTC/fee` | Go |
| 16 | `GET /v2/chain/BTC/height` | Go |
| 17 | `GET /v2/chain/BTC/transaction/:txid` | Go |
| 18 | `POST /v2/chain/BTC/transaction` | Go, web |
| 19 | `GET /v2/nodes/stats` | web |

Legacy `/swapstatus` and `/streamswapstatus`, generic node inventory,
cooperative claim/refund helpers, reverse-expiry, and invoice-amount reads are
outside this released profile. Chain-swap calls join a later profile only
after #27; they are not counted here.

The classifier accepts the web client's 64-identifier batch despite its
request target exceeding the general 2,048-byte cap, but only for the exact
bounded `ids=` grammar. The reverse BIP21 route accepts ordinary-length BOLT11
invoices only after parsing them. Other request targets retain the global
cap and unsafe origin forms remain rejected.

Dependent-call coverage is **19/19 (100%) emulated**. The completion gate runs
the adapted Go and web clients against the separate funded provider daemon and
proves all 19 calls, including direct provider WebSocket status, submarine
finalization, unchanged-byte idempotent broadcast, reverse creation, and
public-claim release. This is separate from the **17/53 endpoint-surface**
result above. A relay `307`, `404`, or configuration promise earns no coverage.

The process result makes the profile eligible for #18 replacement scenarios.
Public replacement remains gated on #18 and #19 deployment evidence.
