# NIP-MKT-HARDENING

## Acknowledged, idempotent market intents

`draft` `optional`

Revision 2 hardens effectful NIP-MKT flows against lost delivery, duplicate
execution, stale replay, and response-key coupling. It adds two private signed
record kinds and a revisioned envelope for effectful intents. Revision 1
records remain valid under their original rules; they do not silently acquire
revision-2 guarantees.

This revision is transport-neutral. Records normally travel as persistent
NIP-59 gift wraps, but every law below applies to the signed inner events.

## Identity and allocation

- Parent protocol: NIP-MKT
- Wire schema: `openagents.mkt.v2`
- Protocol revision: `2`
- Initially adopted profile: `mkt-swp` version `1`

| Kind  | Name                  | Publication                        |
| ----- | --------------------- | ---------------------------------- |
| 39611 | Intent Acknowledgment | private signed record, NIP-59 only |
| 39612 | Re-drive Intent       | private signed record, NIP-59 only |

Both kinds are addressable with a unique `d`, immutable-by-contract, and
subject to the NIP-MKT 32 KiB signed-record and collection bounds. They use
the already collision-reviewed `39611-39619` MKT-SWP revision reservation.

## Revision-2 envelope

A revision-2 Order (`kind:39606`), Intent Acknowledgment (`kind:39611`), or
Re-drive Intent (`kind:39612`) contains:

```json
{
  "schema": "openagents.mkt.v2",
  "protocol_rev": 2,
  "profile": "mkt-swp",
  "profile_version": 1,
  "session_id": "<64-lower-hex>",
  "intent": {}
}
```

An implementation that does not support revision 2 MUST fail with the typed
`unsupported_protocol_revision` boundary; it MUST NOT interpret the record as
revision 1. Unknown critical intent members fail closed.

## Effectful intent grammar

A revision-2 Order is an effectful intent. It retains every NIP-MKT and
MKT-SWP Order field and adds exactly one each of these signed tags:

- `intent`, with value `effectful`;
- `nonce`, 32 random bytes as 64 lowercase hexadecimal characters;
- `nonce_at`, a canonical Unix-second decimal;
- optional `response`, a 32-byte x-only response-encryption public key; and
- `d`, the client-supplied idempotency key.

Its `intent` object is:

```json
{
  "idempotency_key": "<same as d>",
  "nonce": "<same as nonce tag>",
  "nonce_at": 1786291200,
  "response_pubkey": "<same as response tag, or requester identity key>",
  "ack_deadline_seconds": 30,
  "outcome_deadline_seconds": 300
}
```

`ack_deadline_seconds` is `1..=60`; `outcome_deadline_seconds` is
`ack_deadline_seconds..=86400`. A response key MAY differ from the event
author. It is transport authority only. The requester identity signature
continues to authorize the Order, and no response key can sign, cancel,
re-drive, fund, or settle for that identity.

Providers validate `nonce_at` against their observed wall clock. The accepted
window is 300 seconds before through 60 seconds after observation. A nonce is
retained for at least 24 hours within the idempotency scope. An exact signed
event replay is a duplicate; the same nonce on different signed bytes is
`mkt-v2-replay`. A timestamp outside the window is `mkt-v2-nonce-window`.

## Idempotency scope and single-attempt law

The idempotency scope is:

```text
(provider identity, requester identity, profile id, idempotency key)
```

The provider durably binds the signed intent ID, exact signed bytes,
acknowledgment, and every outcome event before or with the associated effect
record. The binding is retained at least as long as the session and every
receipt derived from it.

- Exact duplicate signed bytes return the original signed acknowledgment and
  every already-recorded outcome. They never execute again.
- Reusing the key for different bytes is `mkt-v2-idempotency-conflict`.
- The provider performs at most one external-effect attempt for one accepted
  intent. Transport retry, process restart, relay replay, and re-drive do not
  create another attempt.
- The acknowledgment is persisted before the effect begins. An inability to
  persist it is a failure to accept the intent.
- A failed attempt becomes a typed Status/Close outcome. Retrying the business
  effect requires a new user-authorized effectful intent and new idempotency
  key; a re-drive cannot retry it.

## Intent Acknowledgment (`kind:39611`)

The provider signs one acknowledgment for each syntactically valid revision-2
effectful or re-drive intent. Required tags are the common private tags plus:

- one `e` reference marked `intent` to the exact Order or Re-drive event;
- `ack`: `accepted` or `rejected`;
- `response`: the intent's selected response pubkey; and
- `expiration` no earlier than the intent's outcome deadline.

Content includes:

```json
{
  "schema": "openagents.mkt.v2",
  "protocol_rev": 2,
  "profile": "mkt-swp",
  "profile_version": 1,
  "session_id": "<session>",
  "ack": {
    "intent_event_id": "<64-lower-hex>",
    "idempotency_key": "<64-lower-hex>",
    "disposition": "accepted",
    "accepted_at": 1786291201,
    "error_code": null
  }
}
```

An exact duplicate replays the original acknowledgment bytes; it is not a
newly signed acknowledgment whose content says duplicate. `rejected` uses one
of the closed error codes `mkt-v2-idempotency-conflict`, `mkt-v2-replay`,
`mkt-v2-nonce-window`, `mkt-v2-unsupported-revision`, or
`mkt-v2-intent-invalid`. An acknowledgment proves only provider receipt and
disposition. It is not an outcome or settlement proof.

The provider wraps the exact acknowledgment separately to the response key
and to its own recovery key. The signed acknowledgment retains a requester
identity `p` tag so authorization and audit correlation do not depend on the
throwaway key.

## Re-drive Intent (`kind:39612`)

A re-drive asks the provider to restate durable state. It never authorizes a
new external effect. It is requester-signed and requires:

- the common private tags;
- `intent` value `redrive`;
- a new client-supplied `d`, `nonce`, and `nonce_at` under the same rules;
- exactly one `order` reference and one `ack` reference;
- optional `status` or `close` reference to the requester's last known event;
  and
- the same optional response-key mechanism.

Its `intent` object additionally contains `order_event_id`, `ack_event_id`,
and `last_known_event_id`, which is null when the request has no last-known
Status or Close. The provider first acknowledges the
re-drive, then returns the original signed Order acknowledgment and every
exact durable Status, Close, and Receipt it has for the Order. Missing records
remain missing; the provider MUST NOT synthesize history from current database
or rail state.

## Timeout behavior

- Before the acknowledgment deadline, the client waits or republishes the
  exact same signed intent in a fresh wrap.
- If the acknowledgment deadline passes, the client still MUST NOT assume
  rejection or issue a second business intent. It continues exact replay and
  may query authorized inboxes.
- Once an accepted acknowledgment exists, a missing outcome at the signed
  outcome deadline permits a new Re-drive Intent. Re-drive only acknowledges
  and restates.
- A missing re-drive acknowledgment is handled by exact re-drive replay.
- Typed rejection ends that intent. A new business attempt requires a fresh
  user authorization, idempotency key, and nonce.

## Verification and limits

A verifier checks event IDs and signatures, exact references, profile/schema
agreement, tag/body equality, identity roles, nonce grammar, deadlines, and
the absence of conflicting idempotency bindings. Relay storage proves only
availability of signed bytes. External rail evidence remains authoritative
for funding, payment, refund, and settlement.

The reference provider retains at most 512 intent bindings and 128 outcome
records per session. Bounds exhaustion fails closed; it never evicts a live
binding to admit a new effect.

## Conformance

Required fixtures cover accepted intent, exact duplicate, changed-byte key
conflict, nonce reuse, stale and future nonce, response-key routing without
authorization transfer, missing-ack retry, accepted-ack missing-outcome
re-drive, process restore, and proof that re-drive cannot increment an
external-effect attempt counter.
