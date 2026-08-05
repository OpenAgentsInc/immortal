# BIP-327 official test vectors

These files are byte-exact copies of the complete MuSig2 vector corpus that
ships with BIP-327 1.0.3.

## Provenance

- Upstream repository: `bitcoin/bips` (<https://github.com/bitcoin/bips>)
- Upstream path: `bip-0327/vectors/`
- Pinned corpus commit: `1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439`
- License: BSD-3-Clause, matching BIP-327
- No value was renamed, reordered, reformatted, or lowercased. Immortal's
  harness adapts to the vectors; the vectors are not adapted to Immortal.

| File | SHA-256 |
| --- | --- |
| `det_sign_vectors.json` | `3d4fdb64b24e31762f20830036dc0c59d39fa896649131b54b87906ffdc6e9e8` |
| `key_agg_vectors.json` | `03c02a97e4ef3f2edfbc8e6013c127496dfcfd5889cfca60ddf009a4e9091cab` |
| `key_sort_vectors.json` | `2389fa0c146cfd7455c643ca240ec32835dcfc916f430f50dd94d0b49c9ea16c` |
| `nonce_agg_vectors.json` | `8409e87b81ea769759598ad3ce53b277a78afffb3a490a86ce02c4d69984524b` |
| `nonce_gen_vectors.json` | `2e823580fc072427f0db0f000212cc9124ad2b9dca2b58357eb65088aee4358d` |
| `sig_agg_vectors.json` | `15f14c034fb2a5739d7ce638be94c5b37ea675a2e01159092dd93b59d69c3439` |
| `sign_verify_vectors.json` | `692eecc101f3e515c29137f05031935e1210d2a01bab91e674eb0234f095c15c` |
| `tweak_vectors.json` | `80ce6385ce062644ad1f4edcb9d4797f70ddb0b74769e4099f51b3c9e6ab4aff` |

`contract/immortal-fixtures.json` records the same JSON digests and scopes
this directory `client`. The files are test-only and are not compiled into a
product binary.

## Replay coverage

`crates/immortal-core/tests/musig2_bip327.rs` drives the public API. The
`#[cfg(test)]` module in `mkt_swp_verify.rs` inspects exact secret-nonce bytes
and aggregate-nonce serialization without exposing caller-supplied secret
nonces in production.

Every official case executes:

- key sorting and aggregation, including malformed keys and tweak failures;
- all four nonce-generation shapes, including every optional input absent;
- nonce aggregation, including the extended point-at-infinity encoding;
- partial signing and verification, invalid contributions, and mixed tweaks;
- deterministic last-signer signing, with and without auxiliary randomness;
- partial-signature aggregation and final BIP-340 verification.

Three malformed-aggregate-nonce signing cases are also replayed through the
per-signer nonce boundary because the normal signing API derives the aggregate
nonce itself. The same bytes are rejected before a partial signature can be
released. Production secret nonces remain opaque, redacted, one-use, and
erased on consumption or drop.
