# Existing Relay Migration

This runbook maps an incumbent relay's policy onto Immortal, runs Immortal on
a private address beside that relay, and compares bounded read responses before
hostname cutover. The shadow tool sends only `REQ` and `COUNT`; it never sends
`EVENT`, `AUTH`, or a management command.

## 1. Capture the incumbent policy

Record the incumbent software version, configuration digest, export watermark,
and each row below. Do not infer a rule from a NIP-11 claim alone: inspect the
configuration and test its accept/refuse boundary with signed disposable
events.

| Incumbent rule | Immortal mapping | Reconciliation gate |
| --- | --- | --- |
| Explicit blocked pubkeys | M2 `relay_blocked_pubkey`; ordinary changes use NIP-86 `banpubkey`/`unbanpubkey` | Exact pubkey and reason set from `listbannedpubkeys` |
| Pubkey allowlist | M2 `relay_allowed_pubkey`; NIP-86 `allowpubkey`/`unallowpubkey` | An empty Immortal table permits every pubkey; compare the complete set before removing its last row |
| Kind allowlist | M2 `relay_allowed_kind`; NIP-86 `allowkind`/`disallowkind` | An empty table permits every kind; test one admitted and one refused kind |
| Explicit blocked kinds | M2 `relay_blocked_kind` | Bootstrap/recovery database packet; there is no current public management method for this table |
| Closed membership and members | `relay_policy.closed_membership` plus `relay_member_pubkey` | Bootstrap/recovery database packet; NIP-29 group membership is separate and cannot substitute |
| Content bytes, tag count, future/past time | The singleton `relay_policy` row | Values must match the incumbent's inclusive/exclusive boundaries; zero past seconds disables only the past bound |
| Authentication required for writes | `IMMORTAL_AUTH_REQUIRED=true` with the exact `IMMORTAL_RELAY_URL` | Signed NIP-42 success, missing-auth refusal, wrong-relay refusal |
| Frame, filter, result, connection, and rate limits | Matching enforced `IMMORTAL_MAX_*` and `IMMORTAL_RATE_*` variables | NIP-11 values and live boundary tests agree |
| Private-message visibility | Immortal NIP-17 and NIP-MKT recipient-gated read pipeline | Prove `REQ`, IDs, `COUNT`, search, history, and live fanout with authorized and unauthorized clients |
| IP, ASN, geography, proof-of-work, payment, invite, regex/content, or plugin rule | No M2 equivalent unless a row above describes the same semantics | Cutover blocker; do not approximate it with a different rule or a discovery claim |

NIP-86 covers ordinary allow/block-pubkey and allow-kind changes. The scalar
policy, direct relay membership, and explicit blocked-kind table are
database-owner bootstrap/recovery surfaces. Treat their initial population as
a reviewed migration packet executed while the candidate is stopped; retain a
pre-change backup and query the exact committed sets afterward. Do not edit a
historical migration file or point the incumbent and candidate binaries at the
same database.

For every incumbent rule, record one of `exact`, `stricter`, `looser`, or
`unmapped`. A `looser` or `unmapped` write/admission rule blocks transparent
replacement. A deliberately stricter rule needs an owner decision and client
impact record; it is not parity.

## 2. Import at a fixed watermark

Create the signed-event export in source admission order and record its final
source sequence/time watermark and SHA-256. Stop the candidate, then follow
[`import-jsonl.md`](import-jsonl.md). Reconcile the import report before
starting the candidate on a loopback or private address. Do not route client
writes to it during shadowing.

## 3. Prepare the read workload

The committed workload at
`tests/fixtures/migration/relay-shadow-v1.json` covers public basic records,
public NIP-MKT discovery heads, and exact NIP-45 market-head count. Copy it for
the migration and add bounded filters observed in production. Each file must
keep this closed shape:

```json
{
  "schema": "openagents.immortal.relay-shadow-workload.v1",
  "queries": [
    {"name": "public-basic-events", "type": "req", "filters": [{"kinds": [0, 1], "limit": 1000}]}
  ]
}
```

Use at most 64 named queries, 16 filters per query, and result limits that keep
every response below 10,000 unique events. Pin `since`/`until` values to the
import watermark for an active incumbent; otherwise a write between the two
reads can produce a valid but noisy difference. Private/authenticated queries
require their released-client proof and are outside this unauthenticated
public shadow tool.

## 4. Compare the relays

```sh
python3 scripts/relay-readonly-shadow.py \
  --incumbent wss://relay.example.com/ \
  --candidate ws://127.0.0.1:18080/ \
  --workload migration-shadow.json \
  --output relay-shadow-result.json
```

The dependency-free client validates the WebSocket upgrade, bounds every
frame, canonicalizes complete event objects, rejects conflicting bytes for one
event ID, and sorts by event ID before hashing. It exits zero only when every
event set and count matches. The output includes the workload digest and no
event content.

- `only_incumbent` usually means an incomplete export/import, a candidate
  query/policy refusal, or an event that expired between reads.
- `only_candidate` usually means a watermark mistake, source export drift, or
  different expiration policy.
- `changed` means the same signed event ID arrived with different fields. Stop
  the migration and investigate corruption; canonical signed events cannot
  legitimately differ that way.
- A count mismatch with equal bounded event results means the workload limit
  hid the difference. Narrow the filter until both the set and count reconcile.

Rerun after fixing each difference. Retain at least one quiet-window result and
one result while normal incumbent writes continue, both with the source
watermark and import-report digest. A local same-database conformance run proves
the tool, not production parity.

## 5. Cut over or roll back

Proceed only when the policy ledger has no unapproved `looser`/`unmapped`
rules, import accounting reconciles, the configured NIP-11 document matches
the intended discovery contract, public shadows match, and authenticated
client cases pass. Follow the hostname, health, signed publish/read, backup,
schema-aware rollback, and DNS/TLS steps in
[`runbook-debian-vps.md`](runbook-debian-vps.md). Keep the incumbent read-only
and recoverable until the acceptance window closes.
