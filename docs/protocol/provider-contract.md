# Provider machine contract

The provider runtime exports its machine-readable v1 surface separately from
the relay contract. The canonical artifact is
`tests/fixtures/provider/provider-contract-v1.json`; its provider-only source
fixtures include `provider-runtime-v1.json` and
`settlement-construction-v1.json`; the optional LND wire surface is pinned by
`lnd-rest-v1.json`, and the optional Liquid rail is pinned by
`liquid-rail-v1.json` together with the provider-only
`liquid-runtime-v1.json`.

That runtime fixture is executable, not descriptive metadata. Provider unit
tests replay its held-HTLC amount/state/expiry refusals, signed exclusive
height boundary, cancelled hold state, and cooperative reverse refund-watch
retirement through the production transition helpers. The exported contract
binds the fixture's exact byte length and SHA-256 digest.

The settlement fixture is a labeled synthetic public protocol vector, not
operator custody material. It pins its BIP-341/342 source revisions and the
existing BOLT-11/payment-hash fixture boundary, then checks production claim
and refund authoring byte-for-byte: unsigned transaction, Taproot signature
message and sighash, deterministic Schnorr signature, witness, signed bytes,
txid, wtxid, fee, weight, and virtual size. Mutated preimages, paths, control
blocks, timelocks, fees, dust outputs, and weight limits fail closed.

The v1 relay transport is a bounded `ws://` URL whose resolved and connected
peer is loopback. Both funded and no-spend modes reject public or TLS relay
URLs before entering their run loops; TLS relay support would require the
conditionally approved TLS dependency path. The CLN surface records `help` as
the startup probe plus the ten exact methods whose presence it verifies. The
feature-gated LND surface records its bounded HTTPS REST methods, exact
operator-pinned certificate policy, three least-privilege macaroon scopes,
loopback-only DNS/peer checks, and native hold-invoice operations.
`getinfo` must name the configured network and carry no bitcoind or lightningd
sync warning; its height anchors the minimum acceptable shortest incoming-HTLC
expiry in reverse Quotes.

The optional elementsd surface records the sole explicit activation value,
loopback-only bounded HTTP/1.1 JSON-RPC transport, exact genesis-derived
BIP-122 network and pegged-asset checks, wallet-scoped own-output unblinding,
and byte-identical already-known replay. Its confidential authority is
`local_elementsd_unblind_own_outputs_only`; the contract keeps independent
range-proof and surjection-proof verification false. Liquid sides, quoting,
effects, and recovery are absent when the selector is unset or incomplete.
Startup proves the configured wallet and the complete production RPC surface,
including bounded UTXO discovery, descriptor/address derivation, PSBT funding,
wallet signing, finalization, unblinding, observation, and broadcast. When
enabled, the runtime fixture binds durable full-request funding and exit
effects, the one-confirmed-output Liquid reservation bound, the fixture-pinned
1,700-vbyte confidential-funding and 300-vbyte claim/refund weights, exact
reserved inputs, the node-reported fee and unique fee output under the signed
maximum, exact already-known byte comparison, restart replay
without repeated rail I/O, changed-request conflicts, and terminal finality
regression to `unresolved`. A confirmed observation requires a block hash;
mempool state requires zero confirmations and no block hash.

The artifact records commands and modes, external prerequisites, exact rail
methods, configuration names and bounds, closed nonzero relay/session/rail/
store/watchtower/health/quote limits, terminal and failure vocabulary, custody
exclusions, operational network scopes, settlement capabilities, v1
exclusions, and exact fixture digests. Its identity binds the provider crate
version and all three pinned NIP source-lane commits from `nips/manifest.json`.
The operations section also pins the bounded drain contract: SIGUSR1, SIGTERM,
and SIGINT pause discovery and reject new native and compatibility sessions,
while existing sessions, relay retries, and the watchtower continue until the
public active-session count reaches zero. The deployment service therefore has
no relay-unit dependency or forced-stop timeout.
The adversarial regtest profile additionally pins quote pricing to the
configured fallback feerate and requires that setting; production remains
live-estimate-first.
The MuSig2 capability flags describe the available submarine signer/runtime;
`musig2_key_path_enabled_by_default=false` records the production opt-in. The
Liquid capability flags similarly describe the optional provider/client
runtime and preserve `liquid_enabled_by_default=false`. Neither capability
alters relay NIP-11.
`immortal-provider address`
is a read-only BIP86 receive-address
operation: it reads the selected network and mode-0600 seed file but does not
open the provider database or contact either rail. `immortal-provider
contract` reads neither configuration nor custody material.

Configuration values are never exported. Secret-bearing environment names
are marked as secret, and the generator rejects configured values and
custody-material object keys.

`swap-network-migration-v1.json` is included in the provider fixture set. It
pins the immutable client provider-route tuple, the seven-route GET-only
shadow surface, provider drain laws, and new-session-only cutover and rollback.
It changes neither the relay contract nor NIP-11.

Regenerate the artifact or verify it byte-for-byte with:

```sh
./scripts/export-provider-contract.sh
./scripts/export-provider-contract.sh --check
cargo test --locked -p immortal-provider --lib provider_runtime_fixture
cargo test --locked -p immortal-provider --test provider_settlement
```

This exporter does not invoke or modify `scripts/export-contract.sh`, the
relay contract artifacts, or NIP-11. Runtime integration can call
`provider_contract_value`, `provider_contract_bytes`, or
`provider_contract_sha256` from the native provider contract module.
