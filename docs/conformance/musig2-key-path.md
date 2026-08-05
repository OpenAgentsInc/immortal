# MuSig2 key-path conformance

The pinned one-input, one-output native Taproot settlement fixture measures
the cooperative BIP-327 key path at **111 vB**. The same transaction policy
uses **155 vB** for the unilateral hashlock claim and **138 vB** for the
unilateral timelock refund. The cooperative path saves 44 vB against the
claim path and 27 vB against the refund path.

`crates/immortal-provider/tests/provider_settlement.rs` constructs both
participants' nonces and partial signatures through the provider wallet
boundary, verifies the aggregate signature, parses the final transaction,
and pins the one-item key-path witness. The same test drops a live signing
round and then completes the unchanged script-path claim, proving that abort
does not consume or weaken the unilateral exit.

`tests/fixtures/nipmkt/swp-cooperative-signing-v1.json` pins the wire action
shapes, refusal cases, custody boundary, and these footprint values. This is
deterministic local conformance evidence. Runtime advertisement and public
replacement claims remain gated on the funded #18 lab and live deployment
evidence, respectively.

## Specification conformance

The MuSig2 primitives themselves are checked against the specification's own
vectors, not only against Immortal fixtures. `tests/fixtures/bip327/` holds
upstream-exact copies of all seven `bitcoin/bips` `bip-0327/vectors/` files.
`crates/immortal-core/tests/musig2_bip327.rs` replays every class reachable
through the public API — key aggregation, ordinary and x-only tweaks, nonce
generation, partial-signature verification, and signature aggregation, with
their invalid-contribution, out-of-range, and point-at-infinity error cases.
The `#[cfg(test)]` module in `crates/immortal-core/src/mkt_swp_verify.rs`
replays the classes that require a caller-fixed secret nonce or the exact
aggregate-nonce serialization; no production entry point accepts either.

Two gaps are recorded rather than approximated: BIP-327's optional
`DeterministicSign` algorithm is not implemented, and the `NonceGen` case with
every optional input absent has no representable argument because
`musig2_nonce_gen` requires all of them. `tests/fixtures/bip327/README.md`
carries the provenance, digests, and the full replay/gap table.
