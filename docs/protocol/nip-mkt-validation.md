# NIP-MKT Validation Boundary

Immortal implements the profile-neutral NIP-MKT base grammar. It does not
currently implement or advertise an executable market profile. In particular,
the `mkt-swp` example in the pinned NIP is not a runtime capability claim.

## Kind and publication contract

| Kinds | Meaning | NIP-01 class | Public gateway rule |
| --- | --- | --- | --- |
| `39600-39603` | Provider Profile, Offering, Profile Descriptor, Public Market Receipt | addressable | public head, admitted only after the kind-specific grammar |
| `39604-39609` | RFQ, Quote, Order, Status, Cancel, Close | addressable with an immutable-coordinate override | bare publication refused; signed records travel inside kind-1059 gift wraps |
| `39610-39699` | reserved profile allocation block | addressable | unallocated; no NIP-MKT handler or capability claim |

The public heads use ordinary NIP-01 replacement ordering. The six private
kinds bind `(pubkey, kind, d)` to one exact event ID and signature in the
internal store: exact replay is idempotent, while changed bytes fail with
`invalid: idempotency-conflict`. Deletion and expiration never release that
binding. This internal path supports trusted import and future in-binary
handlers; generic gateway reads hide every bare private row, including rows
created by an older release or legacy import.

## Observable validation surfaces

| Surface | What Immortal can validate |
| --- | --- |
| Public kinds `39600-39603` | Required discovery tags, identifier/version grammar, enums, content byte limits, duplicate-free JSON-object content, and common collection caps. The private session envelope does not apply to public content. |
| Visible/internal signed kinds `39604-39609` | The store enforces immutable-coordinate replay, then the profile-neutral common tags, envelope agreement, duplicate-free JSON at every nesting depth, compact serialized size, references, and collection caps. Existing immutable bindings are checked first so validator upgrades cannot change a prior replay result. The gateway separately measures the exact raw EVENT-object bytes before deserialization. Gateway acceptance policy is defined separately and does not belong to the durable/internal store contract. |
| Raw client/handler record | `validate_mkt_private_raw` checks the exact received byte length, one complete duplicate-free event object with no unknown outer members, event structure and signature, base grammar, and an explicit caller-supplied profile registry. It returns the authoritative raw signed bytes with the decoded event and envelope. This is the exact 32 KiB client/future-handler path; reserializing an `Event` can only bound its compact in-memory form. |
| Explicit profile consumer | `validate_mkt_private_with_profiles` additionally requires a caller-supplied `MktProfileSupport` with an exact ID/version and rejects profile-declared critical members that the consumer does not understand. Unknown noncritical members remain in the returned body. |
| NIP-59 gift wrap at the transport relay | The inner signed record is encrypted and opaque. The relay can validate and recipient-gate the outer wrap, but cannot claim it checked inner MKT grammar, signer roles, terms, or profile semantics. |

The no-server client library implements bounded NIP-44 v2 and NIP-59
wrap/unwrap primitives. A private MKT record is validated and signed first;
the rumor carries those exact signed bytes and binds the inner author, kind,
timestamp, and recipient. Unwrapping verifies the outer signature, seal
signature, rumor ID, layer-to-layer signer/recipient agreement, and the exact
inner signature before applying the caller's explicit profile registry.
Applications create independent outer material for the counterparty and the
sender's recovery copy. The committed NIP-44 vector and NIP-MKT client
transport fixture are part of the exported SDK conformance manifest.

The public gateway refuses bare `39604-39609` publication with the stable
reason `restricted: mkt-private-requires-gift-wrap` before database, keyed-rate,
or store work, after consuming only the generic IP attempt budget. The internal
store path remains available for trusted import and future in-binary handlers,
but existing/internal `39604-39609` rows are unconditionally hidden by SQL,
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

The exported executable-profile set is empty. Profile-aware fixtures use the
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

The committed client-only manifest additionally pins quote supersession,
double reservation, per-signer Status gaps and forks, wrapper/inner signer,
kind and recipient mismatch, evidence mismatch, recovery loss, expired Order,
unauthorized Status/Cancel/Close, rewrapped replay, and settlement overclaim.
Those cases are inputs for SDK conformance; none is advertised as relay
enforcement.

`immortal dev-market-seed` uses the synthetic `local-dev` profile only for a
loopback smoke. It drives RFQ, Quote, Order, completed Status, and Close with
two throwaway actors and validates both deliveries of every record. Its final
state is a coordination claim, not a relay or settlement capability claim.

## NIP-11 advertisement

NIP-MKT has no numeric NIP-11 identifier. Immortal adds only `nip-mkt` to
`supported_extensions`, and only when `IMMORTAL_RELAY_URL` is configured so
NIP-42 recipient authentication is available for wrapped reads. The extension
means the base public discovery and recipient-gated transport contract on this
page. It does not advertise `mkt-swp`, another executable profile, decrypted
inner validation, reservation accounting, execution, or settlement proof.
