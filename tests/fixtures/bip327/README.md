# BIP-327 Official Test Vectors

Upstream, unmodified copies of the MuSig2 reference vectors that BIP-327
ships with its specification text.

## Provenance

- Upstream repository: `bitcoin/bips` (<https://github.com/bitcoin/bips>)
- Upstream path: `bip-0327/vectors/`
- Upstream branch: `master`
- Fetched: 2026-08-05
- Retrieved with
  `curl -sSfL -O https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327/vectors/<file>`
- Bytes are upstream-exact. No value was renamed, reordered, reformatted, or
  lowercased. Immortal's harness adapts to the vectors; the vectors are never
  adapted to Immortal.
- BIP text is public domain (BIP-327 is licensed BSD-2-Clause / CC0-compatible
  per `bip-0327/README`), which is compatible with this repository's CC0-1.0.

SHA-256 of the fetched bytes:

| File | SHA-256 |
| --- | --- |
| `det_sign_vectors.json` | `3d4fdb64b24e31762f20830036dc0c59d39fa896649131b54b87906ffdc6e9e8` |
| `key_agg_vectors.json` | `03c02a97e4ef3f2edfbc8e6013c127496dfcfd5889cfca60ddf009a4e9091cab` |
| `nonce_agg_vectors.json` | `8409e87b81ea769759598ad3ce53b277a78afffb3a490a86ce02c4d69984524b` |
| `nonce_gen_vectors.json` | `2e823580fc072427f0db0f000212cc9124ad2b9dca2b58357eb65088aee4358d` |
| `sig_agg_vectors.json` | `15f14c034fb2a5739d7ce638be94c5b37ea675a2e01159092dd93b59d69c3439` |
| `sign_verify_vectors.json` | `692eecc101f3e515c29137f05031935e1210d2a01bab91e674eb0234f095c15c` |
| `tweak_vectors.json` | `80ce6385ce062644ad1f4edcb9d4797f70ddb0b74769e4099f51b3c9e6ab4aff` |

`contract/immortal-fixtures.json` records the same digests and scopes this
directory `client`. These vectors are test-only material; they are never
compiled into the relay, client, or provider binary.

## Why these are here

`crates/immortal-core/src/mkt_swp_verify.rs` implements BIP-327 MuSig2
in-repo over the allowlisted `secp256k1` point and tweak operations, per the
MuSig2 decision recorded in `AGENTS.md` (2026-08-05). Hand-written
multi-signature code that signs real value must be checked against the
specification's own adversarial vectors, not only against fixtures the
implementation's author invented.

## What replays where

Public-API replay lives in `crates/immortal-core/tests/musig2_bip327.rs`.
Vectors whose inputs are not reachable through the public API — a caller-fixed
secret nonce, and the exact aggregate-nonce serialization — replay from the
`#[cfg(test)]` module inside `crates/immortal-core/src/mkt_swp_verify.rs`,
which can see the private fields. No production entry point was widened, and
in particular no public API accepts a caller-supplied secret nonce.

| File | Replayed | Not replayed |
| --- | --- | --- |
| `key_agg_vectors.json` | 4 valid, 5 error | — |
| `tweak_vectors.json` | 5 valid (verify and sign), 1 error | — |
| `nonce_gen_vectors.json` | 3 of 4 cases | case 4 (`sk`, `aggpk`, `msg`, `extra_in` all absent) |
| `nonce_agg_vectors.json` | 2 valid, 3 error | — |
| `sign_verify_vectors.json` | 6 valid (verify and sign), 3 verify-fail, 2 verify-error, 6 sign-error | — |
| `sig_agg_vectors.json` | 4 valid, 1 error | — |
| `det_sign_vectors.json` | none | all 9 cases |

Recorded gaps, with reasons:

- `nonce_gen_vectors.json` case 4 exercises BIP-327 `NonceGen` with every
  optional input absent. `musig2_nonce_gen` deliberately requires a secret
  key, an aggregate key, a message, and an extra-input slice, so the "input
  absent" branches of the `NonceGen` serialization have no representable
  argument. This is a narrower contract than the BIP, not a disagreement with
  it.
- `det_sign_vectors.json` covers BIP-327's optional `DeterministicSign`
  algorithm, which this repository does not implement. The vectors are pinned
  here so that adding `DeterministicSign` later starts from upstream bytes
  rather than a fresh fetch, and so the gap is reviewable. The harness parses
  the file and asserts its case counts so a silent upstream change is caught.
- Three `sign_verify_vectors.json` `sign_error_test_cases` name a malformed
  *aggregate* nonce. Immortal's signing API takes per-signer public nonces and
  aggregates them itself, so there is no aggregate-nonce parameter to corrupt.
  The harness replays those three byte strings as per-signer public nonces
  instead and asserts each is rejected. That adaptation is labelled in the
  test.
