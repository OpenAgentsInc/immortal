# tbDEX Legacy Translation Boundary

Immortal's transport-neutral client library audits archived tbDEX protocol
1.0 messages without upgrading their authority. The source is
`TBD54566975/tbdex` commit
`7546a079bb860e7ede8125739b7970810a2df314`, Apache-2.0. The test-only fixture
tree pins the exact nine hosted schemas and all ten hosted parse vectors,
including both attached and detached RFQ forms. Tests verify their source-byte
digests and replay every `input` string against its exact `output`. The source
vectors are never compiled into the product binary.

`translate_tbdex_message` accepts at most 64 KiB of duplicate-free JSON and
requires an exact supported kind and protocol `1.0` field vocabulary. Its
output names:

- source protocol and exact revision;
- mapping version `immortal.tbdex-to-nip-mkt.v1`;
- SHA-256 of the exact source bytes;
- candidate NIP-MKT kind and field mappings;
- every dropped, defaulted, and ambiguous field; and
- all authority and state refusals.

The output is always `executable=false`. tbDEX messages authenticate DID
identities with JOSE. Those fields produce
`tbdex_unrepresentable_authority`; Immortal does not resolve a DID, verify or
emulate JOSE, select a Nostr key on its behalf, or manufacture a NIP-01
signature. The audit contains no target event or profile body, so it cannot be
published accidentally as an authorized NIP-MKT record.

## Kind mappings

| tbDEX kind | Candidate NIP-MKT surface | Required loss boundary |
| --- | --- | --- |
| Balance | none | A provider-held balance is custody state, not independently proved capacity. |
| Offering | Offering `39601` | Currency codes remain ambiguous labels until a profile supplies collision-resistant asset IDs; rate, claims, and method schemas need profile terms. |
| RFQ | RFQ `39604` | `offeringId` is not an exact Nostr address. Private values stay off relay; only commitments may enter profile content. |
| Quote | Quote `39605` | The candidate defaults to indicative/no reservation. It lacks an exact RFQ event, asset IDs, custody dimensions, and evidence authority. |
| Order | Order `39606` | `exchangeId` is not an exact accepted Quote event ID. |
| OrderInstructions | Status `39607`, candidate `funding_required` | Instruction bytes stay in a protected direct channel. A profile must bind digest, expiry, correlation, exact Order, sequence, and signer before use. |
| OrderStatus | Status `39607` | A source status has no per-author sequence chain or rail evidence. Settlement/refund labels cannot advance verified state. |
| Cancel | Cancel `39608`, candidate `action=request` | A request has no immediate effect and cannot reverse an external action. |
| Close | Close `39609` | `success` and free text cannot prove an exact terminal outcome, finality, recovery, or loss accounting. |

Balance, OrderInstructions, OrderStatus, and Close add
`tbdex_unrepresentable_state` to the authority refusal. The other candidate
mappings remain non-executable because authority is still unrepresentable.

## Detached RFQ private data

`validate_tbdex_rfq_private_data` verifies the tbDEX commitment construction:
SHA-256 over the RFC 8785 representation of `[salt, private_value]`, encoded as
unpadded base64url. This is the rule in the pinned protocol README's Digests
and privateData sections. It is also implemented by
`TBD54566975/tbdex-rs` commit
`c3d49855b4099fa663ca14c5c79e8b1e6cd8bc65` in
`crates/tbdex/src/messages/rfq.rs::digest_private_data`, which constructs
`[salt, value]` and serializes it with `serde_jcs`. Claims, pay-in details, and
payout details must each be present with their matching commitment or absent
together. Attached private data must verify at least one commitment. A mismatch
fails with `tbdex_private_data_mismatch`.

The detached form is valid: commitments may remain when `privateData` has
been removed. Immortal returns only `Detached` or the names of verified
commitments; it never returns or stores the private values. The bounded
implementation supports the string, boolean, null, array, and object shapes
used by the harvested vector. JSON numbers fail closed because approximating
RFC 8785 number serialization would make a false commitment claim.

Both entry points validate closed metadata, data, payment-method, quote,
instruction, and private-data shapes before returning a projection or
`Detached`. Optional `updatedAt` and `externalId` values are included in the
loss report. This compatibility module performs no network, database, wallet, signing,
credential, payment, or settlement operation. It changes no relay behavior or
NIP-11 advertisement.
