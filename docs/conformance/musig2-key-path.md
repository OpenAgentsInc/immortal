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
shapes, refusal cases, custody boundary, actor ingress, stable Status `d`
tokens, and these footprint values. `immortal-provider` accepts actor input
only as a byte-identical signed Event already retained by `ProviderSession`.
Before wallet nonce allocation, the actor binds the context to the bilateral
contract, its cooperative effect, the provider's exact committed unilateral
exit package, and the settlement template. A partial is released only after
both signed nonce Status records are stored. Final transaction bytes remain
withheld until the provider's final-signature Status is signed and stored.

A restart never restores or persists a secret nonce. It produces a bounded
abort Status and retains the committed script-path exit. This is deterministic
local conformance evidence.

`FundedMode` now owns the inactive runtime path. A process-gated submarine
Quote pins the provider's public exit destination, signer reference,
claim-height window, and `cooperative_sign` effect intent. After both Swap
Contracts bind the effect and commit the exact provider exit package, the
daemon persists that public package plus the exact `cooperative_sign` and
`chain_claim` requests before allocating a nonce. Every requester input is
routed only after its signed Status is in `ProviderSession`. The signed final
Status completes the signing effect, then releases bytes into the existing
durable claim watch-before-broadcast path; restart can reconstruct the one-item
key-path witness from that signed Status without a nonce. Exact package/effect
reads are covered across Postgres restart. The production constructor still
sets the process gate to false, and the exported `musig2_key_path` and
`musig2_key_path_signer` flags remain false.

Activation still requires #18 evidence from two independently keyed provider
processes for cooperative completion and mid-transcript abort to script-path
claim. Reverse cooperative settlement remains disabled until the protocol
binds preimage release for settling the held Lightning invoice; a key-path
spend alone does not disclose that preimage. Public replacement claims remain
gated on live deployment evidence.
