# NIP-MKT Validation Boundary

Immortal implements the profile-neutral NIP-MKT base grammar, the relay-
observable subsets of MKT-SWP v1 and MKT-PFI v1, and an optional configured
noncustodial coordination handler. The handler boundary is documented in
[`mkt-swp-coordination.md`](mkt-swp-coordination.md). It does not implement an
executable PFI profile: credential, rail, guarantee, reserve, escrow, dispute,
wallet, and settlement authority remain external.

## Kind and publication contract

| Kinds | Meaning | NIP-01 class | Public gateway rule |
| --- | --- | --- | --- |
| `39600-39603` | Provider Profile, Offering, Profile Descriptor, Public Market Receipt | addressable | public head, admitted only after the kind-specific grammar |
| `39604-39609` | RFQ, Quote, Order, Status, Cancel, Close | addressable with an immutable-coordinate override | bare publication refused; signed records travel inside kind-1059 gift wraps |
| `39610` | MKT-SWP v1 Swap Contract | addressable with an immutable-coordinate override | bare publication refused; signed record travels inside kind-1059 gift wraps |
| `39630` | MKT-PFI v1 Qualification Policy | addressable | public replacement head, admitted only after closed-shape, digest, and public-privacy validation |
| `39611-39629`, `39631-39699` | reserved profile allocation block | addressable | unallocated by this runtime packet |

The public heads use ordinary NIP-01 replacement ordering. The seven adopted
private kinds bind `(pubkey, kind, d)` to one exact event ID and signature in the
internal store: exact replay is idempotent, while changed bytes fail with
`invalid: idempotency-conflict`. Deletion and expiration never release that
binding. This internal path supports trusted import and future in-binary
handlers; generic gateway reads hide every bare private row, including rows
created by an older release or legacy import.

## Observable validation surfaces

| Surface | What Immortal can validate |
| --- | --- |
| Public kinds `39600-39603` | Required discovery tags, identifier/version grammar, enums, content byte limits, duplicate-free JSON-object content, and common collection caps. The private session envelope does not apply to public content. |
| Visible/internal signed kinds `39604-39610` | The store enforces immutable-coordinate replay, then the profile-neutral common tags, envelope agreement, duplicate-free JSON at every nesting depth, compact serialized size, references, and collection caps. Kind `39610` is bound to exactly `mkt-swp` v1. Existing immutable bindings are checked first so validator upgrades cannot change a prior replay result. The gateway separately measures the exact raw EVENT-object bytes before deserialization. Gateway acceptance policy is defined separately and does not belong to the durable/internal store contract. |
| MKT-SWP Offering and authorized visible record | The profile validator checks public Offering network/asset IDs, side networks and ordered rail pairs against the advertised networks/swap types, canonical decimal amounts, explicit side-disable semantics, fee bounds, script/proof/confirmation classes, evidence class/rail compatibility, receipt outcomes and named-field privacy tripwires, Swap Contract tag/body digest agreement, complementary counterparty roles, and the v1 null/absent EVM extension rule. Custody-member scanning covers the complete parsed profile envelope. It checks digest shape and `x`/body equality; RFC 8785 recomputation and bilateral semantic agreement belong to the client or configured handler. |
| MKT-PFI Qualification Policy and Offering | The validator checks the public `39630` policy's exact profile/version/status/version/published/digest/alt tags, exact content-byte SHA-256, closed nested requirement and retention shapes, ISO jurisdiction and bounded identifier/URL rules, and recursively named PII/bearer tripwires. Offerings bind canonical ISO-4217/CAIP-19 asset IDs to the market digest, policy address/event pins, enabled direction tags, atomic-unit limits, fee cap, risk and rail sets, jurisdictions, and closed public custody labels. |
| MKT-PFI authorized visible record | After an authorized endpoint decrypts an inner record, the profile validator permits only commitments for credential presentations and bounded non-bearer evidence references. It applies closed shapes to named credential commitment, evidence, dispute, and recourse objects and rejects unknown risk/evidence classes. It does not fetch or verify the credential, external evidence, rail action, guarantee, reserve, dispute, or settlement. |
| Raw client/handler record | `validate_mkt_private_raw` checks the exact received byte length, one complete duplicate-free event object with no unknown outer members, event structure and signature, base grammar, and an explicit caller-supplied profile registry. It returns the authoritative raw signed bytes with the decoded event and envelope. This is the exact 32 KiB client/future-handler path; reserializing an `Event` can only bound its compact in-memory form. |
| Explicit profile consumer | `validate_mkt_private_with_profiles` additionally requires a caller-supplied `MktProfileSupport` with an exact ID/version and rejects profile-declared critical members that the consumer does not understand. Unknown noncritical members remain in the returned body. |
| NIP-59 gift wrap at the transport relay | The inner signed record is encrypted and opaque. The relay can validate and recipient-gate the outer wrap, but cannot claim it checked inner MKT grammar, signer roles, terms, or profile semantics. |
| Handler-addressed NIP-59 copy | Only when exact-digest coordination is configured, the relay signer decrypts its own additional wrap, applies the explicit MKT-SWP registry and custody tripwires in memory, then persists bounded identifiers, accounting fields, and hashes without decrypted content. |

The no-server client library implements bounded NIP-44 v2 and NIP-59
wrap/unwrap primitives. A private MKT record is validated and signed first;
the rumor carries those exact signed bytes and binds the inner author, kind,
timestamp, and recipient. Unwrapping verifies the outer signature, seal
signature, rumor ID, layer-to-layer signer/recipient agreement, and the exact
inner signature before applying the caller's explicit profile registry.
Applications create independent outer material for the counterparty and the
sender's recovery copy. The committed NIP-44 vector and NIP-MKT client
transport fixture are part of the exported SDK conformance manifest.

The public gateway refuses bare `39604-39610` publication with the stable
reason `restricted: mkt-private-requires-gift-wrap` before database, keyed-rate,
or store work, after consuming only the generic IP attempt budget. The internal
store path remains available for trusted import and future in-binary handlers,
but existing/internal `39604-39610` rows are unconditionally hidden by SQL,
search indexing, and live fanout. Explicit kind-1059 REQ and COUNT filters require an
authenticated recipient and nonempty `#p` selectors containing only that
recipient's authenticated identities. SQL result gating still protects broad,
ID-only, and search filters, while the live fanout gate independently checks
the wrap recipient. Migration 0009 makes kind 1059 search vectors NULL.

Every structurally valid EVENT attempt consumes the generic IP limit once.
Only after signature verification can a discovery publication consume its
signed event-author limit, or a gift wrap consume its outer wrapper event
pubkey and recipient limits. A forged wrapper therefore cannot exhaust a
victim's keyed quota. Recipient exhaustion returns the stable reason
`rate-limited: gift-wrap recipient rate exceeded`. The outer wrapper pubkey is
randomized transport metadata and is never described as the logical sender of
the encrypted MKT record; that inner sender is opaque to the relay.

Expiration is inclusive. A public MKT event or outer gift wrap with
`expiration <= now` is refused. Inner expiration is client-only because the
transport relay cannot decrypt it. Two independently signed outer wraps may
carry the same inner record; the relay stores both deliveries and cannot
deduplicate the logical record. Clients deduplicate by the verified inner
event ID while retaining delivery provenance.

The stable MKT gateway reasons are:

- `restricted: mkt-private-requires-gift-wrap` for bare private publication;
- `invalid: idempotency-conflict` for changed bytes at an immutable internal
  coordinate; and
- `rate-limited: gift-wrap recipient rate exceeded` for recipient quota
  exhaustion.

Gift-wrap REQ and COUNT filter refusals retain the existing NIP-42 strings:
`auth-required: gift-wrap reads require recipient authentication` and
`restricted: gift-wrap reads must be scoped to #p self`.

The exported executable-profile set remains empty. Separate relay-profile
entries identify the observable MKT-SWP v1 and MKT-PFI v1 schemas. The optional
handler has its own exact-digest `mkt-swp-coordination:1` advertisement and is
not a client or wallet execution claim. Profile-aware base fixtures use the
synthetic ID `conformance`; it exists only to test fail-closed API behavior.
Consumers supply contracts pinned to profile authorities and revisions. No
wire-level `critical` member was invented: which members are critical comes
from the selected profile contract. Grammar validation by the durable store is
not a claim that Immortal can execute the profile. Client and future-handler
entry points fail closed unless the caller supplies an exact supported profile
and version.

## Bounds and counting

- Content limits count UTF-8 bytes. Public Profile, Offering, and Descriptor
  content is at most 16 KiB; Receipt content is at most 4 KiB.
- A raw private signed record is at most 32 KiB. The base `Event` validator
  also checks its compact Serde serialization for locally constructed records.
- The 64-tag cap counts every tag before detailed validation. The `p` cap
  counts every `p` tag, including unrelated or malformed extensions. The
  32-reference cap counts every `e` causal/evidence tag. The 16-profile cap
  counts every `profile` tag.
- The eight-hint cap counts every `relay` tag and every nonempty standard
  relay-hint slot at index 2 on a `p`, `e`, or `a` tag. Descriptor `r` is a
  retrieval URL, not a relay hint, and is not counted.

NIP-MKT requires an `alt` description but does not assign exact literal text
per private kind. The base validator therefore requires one nonempty,
control-free, bounded `alt` tag without inventing literals.

## Client and handler checks

The transport-only relay cannot prove session randomness, whether a visible
counterparty has the expected business role, profile terms, signer authority,
causal availability, quote supersession, reservation conflicts, Status
sequence gaps/forks, settlement evidence, or disclosure consent. These remain
client/profile-handler checks and enter the M11 exported corpus. Relay
acceptance remains transport evidence only.

The committed client-only manifests additionally pin quote supersession,
double reservation, per-signer Status gaps and forks, wrapper/inner signer,
kind and recipient mismatch, evidence mismatch, recovery loss, expired Order,
unauthorized Status/Cancel/Close, rewrapped replay, and settlement overclaim.
Those cases are inputs for SDK conformance; none is advertised as relay
enforcement.
The MKT-SWP manifest carries all 70 upstream case names, including lifecycle,
timeout, verify-before-fund, reservation-fork, exit-package, privacy, reorg,
and doomsday cases. Only its named relay-observable subset is enforced here.
Evidence references enforce class/rail compatibility and canonical payment-
hash, transaction-ID, and Bitcoin `txid:vout` forms for the classes whose v1
wire shape fixes those identifiers. Reservation, reorg, replacement, and
covenant-reserve references remain bounded opaque identifiers until their
client or coordination packets adopt the corresponding proof semantics.
Public-field and custody scanners reject only the recursively encountered,
exact member names exported in the contract; they do not claim to identify
secrets from arbitrary values.

The MKT-PFI manifest carries all 41 upstream case names. Relay conformance
enforces only policy, Offering, and receipt admission; base private transport
and immutability; and bounded shapes visible to an authorized profile
consumer. Credential verification, price-feed execution, risk proof, reserve
and guarantee verification, external-effect idempotency, transitions, and
recovery drills remain client or configured-adapter cases.

`immortal dev-market-seed` uses the synthetic `local-dev` profile only for a
loopback smoke. It drives RFQ, Quote, Order, completed Status, and Close with
two throwaway actors and validates both deliveries of every record. Its final
state is a coordination claim, not a relay or settlement capability claim.

## NIP-11 advertisement

NIP-MKT has no numeric NIP-11 identifier. When `IMMORTAL_RELAY_URL` is
configured so NIP-42 recipient authentication is available, Immortal adds
`nip-mkt`, `mkt-swp:1`, and `nip-mkt-pfi:1` to `supported_extensions`. The
profile extensions mean only the relay-observable v1 grammar described on
this page. The executable-profile set remains empty; credential and external
authority, reservation accounting, lifecycle execution, wallet authority,
and settlement proof are not advertised.
