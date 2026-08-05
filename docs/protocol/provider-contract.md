# Provider machine contract

The provider runtime exports its machine-readable v1 surface separately from
the relay contract. The canonical artifact is
`tests/fixtures/provider/provider-contract-v1.json`; its provider-only source
fixtures include `provider-runtime-v1.json` and
`settlement-construction-v1.json`.

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
the startup probe plus the ten exact methods whose presence it verifies.
`getinfo` must name the configured network and carry no bitcoind or lightningd
sync warning; its height anchors the minimum acceptable shortest incoming-HTLC
expiry in reverse Quotes.

The artifact records commands and modes, external prerequisites, exact rail
methods, configuration names and bounds, closed nonzero relay/session/rail/
store/watchtower/health/quote limits, terminal and failure vocabulary, custody
exclusions, operational network scopes, settlement capabilities, v1
exclusions, and exact fixture digests. Its identity binds the provider crate
version and all three pinned NIP source-lane commits from `nips/manifest.json`.
`immortal-provider address`
is a read-only BIP86 receive-address
operation: it reads the selected network and mode-0600 seed file but does not
open the provider database or contact either rail. `immortal-provider
contract` reads neither configuration nor custody material.

Configuration values are never exported. Secret-bearing environment names
are marked as secret, and the generator rejects configured values and
custody-material object keys.

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
