# Funded browser-demo adapter

Issue #36 adds a development-only bridge between a browser host and the
existing funded Immortal lab. It does not add a production wallet API. The
browser still uses `immortal-client` directly for signed session state; the
bridge exists only for external Bitcoin and Lightning effects that browser
JavaScript cannot safely perform itself.

## Boundary

`immortal-lab browser-demo-adapter` binds to `127.0.0.1:19336` by default and
accepts exactly one configured origin, `http://127.0.0.1:3000` by default. The
bind and origin must both be numeric IPv4 loopback HTTP authorities. Wildcard,
LAN, public, credential-bearing, and path-bearing values fail before startup.

The adapter has no bitcoind, CLN, LND, wallet-seed, shell, or general
filesystem interface. It shares only the lab state directory with the funded
wallet harness. The closed HTTP surface is:

| Request | Result |
| --- | --- |
| `GET /v1/session` | The bounded public-safe manifest. |
| `POST /v1/effects` | Admit one exact pending engine effect and wait for its durable receipt. |
| `OPTIONS /v1/session` and `OPTIONS /v1/effects` | Exact-origin CORS preflight. |

The only effect methods are `broadcast_bitcoin_funding` for a submarine swap
and `pay_lightning_invoice` for a reverse swap. The amount must be in
`1..=1,000,000` sats and the network is fixed to Bitcoin regtest
`bip122:0f9188f13cb7b2c9e5c72a6b65eeada4`. Requests are capped at 16 KiB and
the wait is capped at 900 seconds. There is no RPC-method parameter.

## Effect and evidence flow

The funded harness first runs production requester verification and obtains
its typed `FundingAuthorizationRequest`. It exposes only:

- journey, session ID, Order ID, and provider coordinates;
- engine-issued effect ID;
- SHA-256 of the complete typed external-effect request;
- one closed method and its bounded amount.

Raw transactions, invoices, preimages, keys, credentials, and node endpoints
are not placed in the browser manifest. A matching `POST /v1/effects` writes a
mode-0600 request into the private lab state. The wallet harness compares
every field with its in-memory engine request before broadcasting the prepared
Bitcoin transaction or initiating the bound Lightning payment. After the
engine durably records the effect, the harness writes an exact receipt with
the request, external identifier, and result digest.

The receipt filename is keyed by the engine effect ID. Exact retries return
that prior receipt, including after the HTTP adapter is replaced. A changed
session, Order, effect ID, digest, method, network, or amount fails before a
rail call. The funded harness also asks bitcoind or CLN about an
already-admitted operation before a wallet-process retry, so neither layer
treats an HTTP retry as permission to pay or broadcast again.

The manifest deliberately separates:

- `provider_status_claim`: the counterparty's signed lifecycle assertion;
- `requester_verification.independent_rail_evidence`: the local
  `immortal-client`-admitted Bitcoin and Lightning view;
- `presentation.settled_allowed`: false until the funded harness verifies the
  terminal Close against the required local rail evidence.

This is a watch/authorize demo. The browser origin never receives general
wallet authority, even though the observed regtest transfers are real.

The executable contract is
`tests/fixtures/lab/browser-demo-v1.json`. The full process proof is:

```sh
scripts/test-browser-demo-funded.sh
```

It provisions the existing disposable Bitcoin Core, CLN, relay, provider, and
Postgres topology; drives one submarine and one reverse swap through the HTTP
boundary; proves pre-terminal presentation refusal; restarts the adapter;
proves exact receipt replay and changed-digest, mainnet, foreign-origin, and
unknown-method refusal; completes the normal reverse-refund lane; reruns the
Boltz Go/web process proofs; and removes only its owned resources.

For an external Bazaar client, `scripts/dev-funded-browser-demo.sh` starts the
same topology and adapter, prints the session URL and allowed origin, waits for
the browser to admit the submarine and reverse effects, and holds the terminal
manifest for inspection until Ctrl-C.

## macOS start-to-teardown recipe

Prerequisites are the same as the funded provider smoke: Rust, Node, Go,
`curl`, `jq`, Python 3, and a running Docker Desktop or Podman Compose service.
Nothing is published beyond loopback.

For the repeatable end-to-end qualification:

```sh
cd ~/work/immortal
scripts/test-browser-demo-funded.sh
```

For manual inspection or a Bazaar client on port 3000, run:

```sh
cd ~/work/immortal
scripts/dev-funded-browser-demo.sh
```

The launcher owns topology startup and teardown. It pauses the funded harness
until the external browser admits each pending effect, then keeps terminal
evidence available until Ctrl-C. The sanitized manifest is retained only in
the disposable private directory and removed on success or failure. A custom
embedding must configure the same exact numeric loopback origin in the
harness and adapter; never bind this adapter to a LAN or public address.

An interrupt triggers the same ownership-checked cleanup. If the container
runtime cannot remove an owned resource, the gate fails and reports the phase
instead of claiming teardown succeeded.

## Claims

This proves local funded Bitcoin/Lightning regtest capability and the narrow
browser boundary. It does not establish a production wallet API, mainnet
safety, live deployment, public replacement, or custody by Bazaar, the relay,
or the adapter.
