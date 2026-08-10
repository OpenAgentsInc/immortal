# NIP-MKT-RECEIPT

## Signed settlement receipts

`draft` `optional`

Version 1 defines a provider-signed, standalone settlement receipt for a
revision-2 MKT-SWP Order. A receipt binds the intent, acknowledgment, quote,
terminal outcome, amounts, rails, fees, and times in one canonical signed
event. It is private by default. A redacted kind-39603 Public Market Receipt
remains an optional projection and is not this record.

## Identity and allocation

- Parent protocol: NIP-MKT
- Wire envelope: `openagents.mkt.v2`, protocol revision `2`
- Receipt schema: `openagents.mkt.receipt.v1`, receipt version `1`
- Initially adopted profile: `mkt-swp` version `1`
- Event kind: `39613`, Settlement Receipt
- Publication: private signed record, persistent NIP-59 only

Kind 39613 is addressable with a unique `d`, immutable-by-contract, and uses
the already collision-reviewed MKT-SWP revision block. The receipt author is
the provider that signed the referenced acknowledgment and quote. A completed,
failed, cancelled, expired, refunded, disputed, or unresolved terminal Close
produces one receipt.

## Tags

A Settlement Receipt has exactly the common private tags plus:

- `d`: the 64-lowercase-hex receipt ID;
- `profile`: `mkt-swp`, `1`;
- one role-marked `p` for the requester;
- `alt`: `MKT-SWP Settlement Receipt`;
- one `e` reference marked `intent` to the revision-2 Order;
- one `e` reference marked `ack` to its provider acknowledgment;
- one `e` reference marked `quote` to the accepted Quote;
- one `e` reference marked `outcome` to the terminal Close;
- optionally one `e` reference marked `client-confirmation` to a requester-
  signed event for the same Order;
- `outcome`: the receipt outcome; and
- `receipt`: `1`.

The `d`, reference, outcome, profile, session, author, and counterparty values
MUST agree with content and with the referenced signed events. Receipt IDs are
never reused for changed signed bytes.

## Content

The complete content is:

```json
{
  "profile": "mkt-swp",
  "profile_version": 1,
  "protocol_rev": 2,
  "receipt": {
    "acknowledgment_event_id": "<64-lower-hex>",
    "client_confirmation_event_id": null,
    "failure_code": null,
    "fees": [
      {
        "amount": "1000",
        "asset_id": "swp:1:bip122:00000000000000000000000000000000:btc:chain",
        "fee_id": "provider-fee",
        "payer_role": "requester",
        "rail": "bitcoin",
        "recipient_role": "provider"
      }
    ],
    "finished_at": 1786291500,
    "intent_event_id": "<64-lower-hex>",
    "legs": [
      {
        "asset_id": "swp:1:bip122:00000000000000000000000000000000:btc:chain",
        "direction": "provider-receives",
        "gross_amount": "100000",
        "leg_id": "source",
        "net_amount": "100000",
        "rail": "bitcoin"
      }
    ],
    "outcome": "completed",
    "outcome_event_id": "<64-lower-hex>",
    "quote_event_id": "<64-lower-hex>",
    "receipt_id": "<64-lower-hex>",
    "schema": "openagents.mkt.receipt.v1",
    "started_at": 1786291200,
    "version": 1
  },
  "schema": "openagents.mkt.v2",
  "session_id": "<64-lower-hex>"
}
```

Content MUST be the RFC 8785 canonical serialization of that closed object.
This profile uses only strings, null, non-negative integers, arrays, and
objects, so implementations need not accept floating-point values. Every
object key is sorted by Unicode code point, there is no insignificant
whitespace, and canonical JSON string escaping applies.

The receipt ID is lowercase SHA-256 of the canonical UTF-8 serialization of
the `receipt` object with its `receipt_id` member omitted. This makes the
identifier stable across relays and transports while binding every receipt
claim. The `d` tag and content `receipt_id` MUST equal that digest.

## Closed receipt grammar

`outcome` is one of `completed`, `cancelled`, `expired`, `failed`, `refunded`,
`disputed`, or `unresolved`. `failure_code` is null only for `completed`; all
other outcomes use one of `rail-failed`, `expired`, `cancelled`, `refunded`,
`verification-failed`, `provider-internal`, `disputed`, or `unresolved`.
Natural-language failure detail is not carried on the wire.

`started_at` and `finished_at` are Unix seconds and
`started_at <= finished_at`. There are `1..=8` legs and `0..=16` fees. IDs are
bounded NIP-MKT identifiers and unique within their arrays. Amounts are
canonical non-negative atomic-unit decimal strings. A leg contains:

- `leg_id`, `asset_id`, and `rail`;
- `direction`: `provider-receives` or `provider-sends`; and
- `gross_amount` and `net_amount`.

A fee contains `fee_id`, `asset_id`, `rail`, `amount`, `payer_role`, and
`recipient_role`; roles are `requester`, `provider`, or `external`. No secret,
credential, invoice, preimage, payment hash, raw transaction, address, script,
route, or custody material is admitted.

The optional client-confirmation reference is null when absent. When present,
the referenced event MUST be signed by the Order author and MUST reference the
same Order. It records the requester's independently signed view; it does not
turn either signer into the settlement authority.

## Event-only chain verification

Given only exact signed inner events, a verifier can validate:

1. every Nostr event ID and signature;
2. the Order's explicit revision-2 envelope and Quote reference;
3. the provider acknowledgment's author and exact Order reference;
4. the terminal Close's exact Order reference;
5. the receipt's canonical serialization, content digest, author, requester,
   profile, session, outcome, and exact Order/Ack/Quote/Close references; and
6. when supplied, the requester signature and Order reference on the optional
   client-confirmation event.

The relay is not an authority in this proof. It may omit, delay, duplicate, or
reorder records, but it cannot change signed bytes undetectably. A verifier
reports a missing link as incomplete, never as failed or settled.

The receipt proves what its signer claimed, not external settlement. Events
alone do not prove that a Bitcoin transaction confirmed, a Lightning payment
settled, an off-Nostr rail transferred value, a fee was economically correct,
or an external verifier was honest. Profiles may attach independently
verifiable evidence, but an unsupported or missing proof caps the display at
`provider-signed`. Receipt aggregation, scoring, and track records are out of
scope.

## Emission, replay, and retention

The provider persists and emits the receipt with the terminal Close. An exact
terminal replay returns the original receipt bytes. Restart and Re-drive return
the same durable receipt; they never sign a replacement claim or attempt the
effect again. Failure to persist a receipt leaves receipt emission incomplete
and MUST NOT be reported as a completed receipt.

The signed receipt is gift-wrapped separately to the requester, its selected
response key when applicable, the provider recovery key, and any explicitly
authorized auditor. Relays retain and serve the persistent wrappers under the
existing NIP-59 recipient authorization and ordinary storage rules. Bare
kind-39613 publication is refused. No database or relay custody role is added.
