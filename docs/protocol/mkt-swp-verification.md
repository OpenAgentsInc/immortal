# MKT-SWP Verification Primitives

The `mkt-swp-verify` feature exposes a transport-neutral verification module
for clients and server-side public-evidence handlers. It is disabled unless an
embedding build selects it and adds no dependency outside the repository
allowlist.

The module parses bounded legacy and segregated-witness Bitcoin transactions,
round-trips their consensus serialization, and computes txid/wtxid. Its script
parser accepts pushes and only the opcode subset used by hashlock, signature,
CLTV, CSV, and Taproot swap leaves. It does not execute Script or decide chain
finality.

Taproot support implements the BIP-340 tagged-hash construction and BIP-341
TapLeaf, TapBranch, TapTweak, and control-block commitments through the
allowlisted `secp256k1` x-only APIs. MuSig2 support implements BIP-327 key
aggregation and verifies the resulting BIP-340 final signature. Nonce creation,
partial signing, secret-key handling, and wallet policy stay in the embedding
wallet.

The BOLT-11 reader checks the Bech32 checksum, bounded tagged fields, canonical
amount and integer forms, payment hash and secret, description choice, and the
recoverable secp256k1 signature. It returns verification data; it cannot pay an
invoice or reach a Lightning node.

Preimage, CLTV, CSV, and strictly increasing timeout-ladder checks are pure.
Callers provide candidate bytes and observations and must not pass custody
material to the Immortal binary or persist it in relay state.

The fixture corpus attributes primary Bitcoin BIP and Lightning BOLT vectors.
The transaction and timeout cases are deterministic local inputs. Live regtest
funding, reorg, replacement, claim, and refund evidence belongs to the M12 lab,
where external Bitcoin and Lightning nodes own all custody and broadcast work.

Run the packet gate with:

```sh
./scripts/test-swp-verification.sh
```
