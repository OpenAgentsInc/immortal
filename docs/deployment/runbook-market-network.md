# Market relay-set and provider-key runbook

This runbook operates NIP-MKT-NETWORK version 1 without adding a service or
database. Read `AGENTS.md`, `INVARIANTS.md`,
`../protocol/mkt-swp-network.md`, and the product runbook first.

The signed public network events name `wss://` origins. The funded provider
still connects only to bounded `ws://` loopback endpoints. Put one
operator-owned TLS/proxy path for each public relay in front of those local
endpoints; never widen the provider's runtime allowlist to make a remote relay
directly reachable.

## Observe the current chain

Collect exact signed kind-39614 and kind-39615 events from at least two relays.
Run `verify_mkt_key_rotation_chain` from the trusted genesis `provider_id`,
then `verify_mkt_relay_set_chain` with that result. Continue only when both
chains are complete, have no competing successor, and the candidate event is
signed by the key active at its `created_at`.

Record the event IDs, generations, effective times, canonical content
digests, and relay acknowledgments in the change ticket. A dashboard, DNS
record, prose announcement, or provider API is not chain evidence.

## Add or replace a relay

1. Provision the relay through the normal relay runbook and verify NIP-01,
   NIP-11, NIP-42, persistent NIP-59 storage, backups, and health independently.
2. Configure its operator-owned local provider proxy. Confirm the provider
   sees only a loopback `ws://` endpoint.
3. Shadow the new relay. Publish exact signed test bytes to every current and
   candidate endpoint and confirm event IDs agree. Read the same history from
   each path and reconcile missing IDs; never copy mutable projections.
4. Build the next canonical `openagents.mkt.relay-set.v1` event. Increment
   `generation` once, reference the exact prior event, retain `provider_id`,
   sort `2..=8` distinct public `wss://` origins, set an explicit future
   `effective_at`, and keep both version-1 thresholds at one unless a stricter
   signed policy is intentional.
5. Sign once with the provider key active at the event's `created_at`. Publish
   those exact bytes to every old and new relay. Do not re-sign per relay.
6. Before the boundary, configure the provider's sorted local endpoints:

   ```text
   IMMORTAL_PROVIDER_RELAY_URLS=ws://127.0.0.1:18080,ws://127.0.0.1:18081
   IMMORTAL_PROVIDER_RELAY_AUTH_URLS=wss://relay-a.example,wss://relay-b.example
   ```

   The auth list is positional and must match the relay count. The legacy
   singular variables remain a one-relay compatibility path, not a signed-set
   deployment.
7. Restart the existing provider binary. Confirm its readiness log reports the
   expected reachable/declared relay count. Stop one relay and prove new
   request/response records still complete through the other, then restore it
   and confirm independent reconnect catches up exact history.
8. After `effective_at`, clients select the new generation. Keep the retired
   relay readable through the rollback/evidence retention window.

Rollback publishes another forward generation restoring the prior origin set.
Never delete or replace the failed generation.

## Rotate the provider key

1. Generate the new secret in the normal secret manager. Export only its
   x-only public key. Never place either secret or secret-manager reference in
   a Nostr event, issue, log, fixture, repository, or provider database.
2. Choose an effective time after the planned rollout window. Build canonical
   `openagents.mkt.key-rotation.v1` content: stable genesis `provider_id`, next
   generation, exact prior rotation event ID, current `old_pubkey`, proposed
   `new_pubkey`, and the future effective time.
3. With the old key, sign one kind-39614 event. Verify its ID, signature,
   content digest, tags, predecessor, and active-old-key rule locally. Publish
   the exact bytes to the complete current relay set and record acknowledgments.
4. Distribute the new secret to the existing provider service. Drain or stop
   the old process immediately before the boundary and restart the same binary
   with the new identity secret at the boundary. Do not run two signing keys
   for the same effective interval.
5. Query every relay for the exact rotation event. Verify that an old-key
   event created before the boundary remains valid, an old-key event at the
   boundary fails, and a new-key event at the boundary succeeds.
6. Exercise a session opened before rotation: its stable provider identity,
   Order/Acknowledgment idempotency scope, and already-signed history do not
   change. Verify its later provider event and Settlement Receipt with
   `verify_mkt_receipt_chain_with_provider_keys`.
7. Retain the old public key and signed history indefinitely. Retire the old
   secret through the secret-manager procedure only after rollback and
   outstanding-signature needs expire.

There is no backward key mutation. If the successor cannot operate, the
current active key signs a later forward rotation generation. A missing old
key or ambiguous fork is an incident and fails closed; natural-language
operator intent cannot repair it.

## Health checks

- Provider readiness reports at least one read/write relay and explicitly
  reports degraded endpoints.
- One endpoint down does not interrupt a session; all endpoints down makes the
  transport unavailable without retrying an external market effect.
- Recovered endpoints receive exact stored bytes; duplicates do not advance a
  session.
- Client chain results are `complete`, `incomplete`, `invalid`, or
  `ambiguous`; missing history never appears as settled.
- Relay and provider logs contain no private inner content, identity secret,
  response key secret, rail credential, preimage, invoice, or wallet material.
