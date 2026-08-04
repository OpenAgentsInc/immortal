# NIP-MKT Validation Boundary

Immortal implements the profile-neutral NIP-MKT base grammar. It does not
currently implement or advertise an executable market profile. In particular,
the `mkt-swp` example in the pinned NIP is not a runtime capability claim.

## Observable validation surfaces

| Surface | What Immortal can validate |
| --- | --- |
| Public kinds `39600-39603` | Required discovery tags, identifier/version grammar, enums, content byte limits, duplicate-free JSON-object content, and common collection caps. The private session envelope does not apply to public content. |
| Visible/internal signed kinds `39604-39609` | The store enforces immutable-coordinate replay, then the profile-neutral common tags, envelope agreement, duplicate-free JSON at every nesting depth, compact serialized size, references, and collection caps. Existing immutable bindings are checked first so validator upgrades cannot change a prior replay result. The gateway separately measures the exact raw EVENT-object bytes before deserialization. Gateway acceptance policy is defined separately and does not belong to the durable/internal store contract. |
| Raw client/handler record | `validate_mkt_private_raw` checks the exact received byte length, one complete duplicate-free event object with no unknown outer members, event structure and signature, base grammar, and an explicit caller-supplied profile registry. It returns the authoritative raw signed bytes with the decoded event and envelope. This is the exact 32 KiB client/future-handler path; reserializing an `Event` can only bound its compact in-memory form. |
| Explicit profile consumer | `validate_mkt_private_with_profiles` additionally requires a caller-supplied `MktProfileSupport` with an exact ID/version and rejects profile-declared critical members that the consumer does not understand. Unknown noncritical members remain in the returned body. |
| NIP-59 gift wrap at the transport relay | The inner signed record is encrypted and opaque. The relay can validate and recipient-gate the outer wrap, but cannot claim it checked inner MKT grammar, signer roles, terms, or profile semantics. |

The public gateway refuses bare `39604-39609` publication with the stable
reason `restricted: mkt-private-requires-gift-wrap` before database, rate, or
store work, after consuming only the generic IP attempt budget. The internal
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
