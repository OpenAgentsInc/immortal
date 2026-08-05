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

`tests/fixtures/bip327/` pins all eight official BIP-327 1.0.3 vector files
at Bitcoin BIPs commit `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`.
The Rust replay executes every valid and invalid case across key sorting and
aggregation, optional nonce inputs, nonce aggregation including infinity,
signing and partial verification, mixed tweaks, deterministic last-signer
signing, and final signature aggregation. The checked-in README records the
upstream license and each file digest.

`tests/fixtures/nipmkt/swp-cooperative-signing-v1.json` pins the wire action
shapes, refusal cases, custody boundary, and these footprint values. This is
deterministic local conformance evidence. Runtime advertisement and public
replacement claims remain gated on the funded #18 lab and live deployment
evidence, respectively.
