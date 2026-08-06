# Runbook: migrate a Boltz-class dependent service

This runbook stands up the Bitcoin/Lightning replacement capability and moves
new sessions to it without moving an in-flight session between providers. The
wire boundary is the pinned MKT-SWP NIP and contract corpus. An
`immortal-provider` process is the reference provider implementation; another
implementation is interoperable when it passes the same wire fixtures.

The local completion proof uses the #18 regtest lab and a read-only comparison
against the public Boltz API. It does not establish live liquidity, independent
operation, or a public replacement claim.

## 1. Required roles

A live network needs all of the following:

- two operator-independent relays, each with its own identity, database,
  backups, and failure domain;
- two independently operated and keyed providers, each with its own Postgres,
  Bitcoin node, Lightning node, inventory, custody files, and TLS origin; and
- a client that verifies the signed MKT-SWP session, persists its unilateral
  exit, and pins the selected provider route before its first request.

The local lab supplies two keyed providers, two relays, separate provider
databases and seed mounts, and two peered Bitcoin nodes. They remain one local
operator and therefore do not prove operator independence.

## 2. Freeze and identify the release

Record the exact Git commit, both machine contracts, fixture digests, relay
set, provider public keys, Offering addresses, HTTP/WebSocket origins, and the
client selection-policy digest. Do not use a branch name as a release
identity.

```sh
git rev-parse HEAD
./target/release/immortal contract >relay-contract.json
./target/release/immortal-provider contract >provider-contract.json
sha256sum relay-contract.json provider-contract.json
```

Regenerate and review both artifacts before adoption:

```sh
./scripts/export-contract.sh --check
./scripts/export-provider-contract.sh --check
```

The provider route persisted with each client session is the exact tuple:

```text
provider_pubkey
Offering address
HTTP origin
WebSocket origin
selection_policy_sha256
```

Changing any member creates a new route for a new session. It is never a
failover instruction for an existing session.

## 3. Stand up the relays and providers

Deploy each relay with
[`runbook-debian-vps.md`](runbook-debian-vps.md). Enable authenticated market
transport with its public `wss://` relay URL. Enable the coordination handler
only with the exact compiled conformance digest. Fetch NIP-11 from every relay
and require `nip-mkt`, `mkt-swp:1`, and, when configured,
`mkt-swp-coordination:1`.

```sh
curl -fsS -H 'Accept: application/nostr+json' https://relay.example.com/ \
  | jq '.supported_extensions'
```

Deploy each provider with
[`runbook-provider-debian.md`](runbook-provider-debian.md). Install the
committed systemd, environment, backup, and TLS-proxy assets. A provider must
not have a systemd `Requires=` or `BindsTo=` relationship with a relay: relay
loss is a recovery case, and the watchtower must continue independently.

The compatibility listener remains private and off by default. When needed,
enable it with its exact provider-contract digest and expose it only through
the provider's TLS proxy. The relay may issue an optional bounded `307`
handoff, but clients connect to the provider WebSocket directly. Neither
surface is a relay NIP-11 extension.

Before funding, require both provider health endpoints to be ready, both
backup timers to be active, and a tested restore of each provider database.
Custody backups are separate operator procedures; the provider database dump
must not contain wallet seeds, node credentials, macaroons, claim/refund keys,
or unreleased preimages.

## 4. Read-only shadow

The shadow recorder performs only these seven public requests against both the
existing dependency and a funded regtest candidate:

```text
GET /v2/version
GET /v2/swap/submarine
GET /v2/swap/reverse
GET /v2/chain/fees
GET /v2/chain/BTC/fee
GET /v2/chain/BTC/height
GET /v2/nodes/stats
```

It sends no body or authentication, follows no redirect, opens no WebSocket,
uses no swap identifier, creates no swap, and records response digests and
JSON shapes instead of response values. Run it while the disposable funded
provider is live:

```sh
IMMORTAL_PROVIDER_FUNDED_SHADOW_REFERENCE_ORIGIN=https://api.boltz.exchange \
IMMORTAL_PROVIDER_FUNDED_SHADOW_OUTPUT=docs/conformance/records/<DATE>-boltz-readonly-shadow-<COMMIT>.json \
  ./scripts/test-provider-funded.sh
```

A shape divergence is a report item, not permission to broaden the
compatibility profile. Review every divergence against
[`boltz-facade.md`](../protocol/boltz-facade.md). The candidate must still pass
the adapted-client 19/19 process gate before cutover.

## 5. Cut over new sessions

1. Keep the old endpoint available for every in-flight session.
2. Confirm the new relay set, both candidate providers, backups, alerts, and
   public-only metrics are healthy.
3. Confirm the #18 record has 33 unique passing cases and retains false claims
   for live deployment, operator independence, and public replacement.
4. Complete one submarine session, one reverse session, and the unilateral
   refund drill against the candidate.
5. Atomically change the dependent service's default route for **new**
   sessions. Persist the selected provider tuple before the first request.
6. Keep status and recovery traffic for every existing session on its pinned
   origin. A transport failure surfaces as recovery/unavailable state; it does
   not select another provider.
7. Require dense signed Status progression, a client-accepted terminal Close,
   and zero active reservations, effects, and unresolved watch jobs before
   declaring a session complete.

Run the fixture-backed rehearsal after the live shadow and fresh-Debian receipt
exist:

```sh
./scripts/test-swap-network-migration.sh \
  --lab-record docs/conformance/records/2026-08-05-adversarial-regtest-67efec7.json \
  --shadow-record docs/conformance/records/<SHADOW>.json \
  --debian-record docs/conformance/records/<DEBIAN>.json \
  --output docs/conformance/records/<CUTOVER>.json
```

## 6. Drain a provider

Start a planned drain without killing rail recovery:

```sh
sudo systemctl kill --signal=SIGUSR1 immortal-provider.service
curl -fsS http://127.0.0.1:9091/metrics \
  | grep -E 'immortal_provider_(draining|sessions_active|reservations_active|effects_pending|effects_unresolved|watch_jobs_pending|watch_jobs_unresolved)'
```

The provider publishes paused discovery, rejects new native RFQs and new
compatibility creates, and continues existing sessions and watchtower work.
It exits successfully only when its active-session count reaches zero.
`systemctl stop` sends SIGTERM and starts the same sequence. The committed unit
has no forced stop timeout or SIGKILL fallback; do not override that while
money is on a timelock.

After exit, require all active, pending, and unresolved metrics to be zero,
take and restore-test a final database backup, then remove inventory according
to the operator's wallet and Lightning-node procedures.

## 7. Roll back

Rollback changes the default route only for sessions that have not started.
Sessions opened after cutover remain pinned to the candidate; sessions opened
before cutover remain pinned to the old provider. Keep both origins available
until their own sessions terminate or recover.

If the candidate applied no unknown provider migration, switch the default
route back and keep draining it. If it applied a migration unknown to the old
binary, restore the pre-upgrade database together with that binary. Never point
an old binary at a database whose migration ledger it rejects.

Rollback triggers include an invalid contract digest, readiness failure,
Status gap/fork, inability to reconstruct the unilateral exit, failed backup
restore, unresolved provider effect, or any custody material in a report.

## 8. Claim boundary

Passing this runbook establishes replacement capability for the pinned
Bitcoin/Lightning profile: noncustodial negotiation, verified client funding,
provider diversity in the local failure matrix, script-path recovery, and a
bounded compatibility surface. Providers remain responsible for liquidity,
spend authority, node operation, and final settlement.

A public replacement claim additionally requires current live evidence for
two operator-independent relays, two independently operated and funded
providers, a released client surface, successful live sessions, backup/restore
receipts, and observed failure recovery. The local #18 record, a read-only
Boltz shadow, or an OpenAgents-operated pair cannot satisfy that gate alone.

## 9. Recorded local execution

The closing run passed at source commit
`764d119736035134c3cb0e0e5fc4fe803d946bf6` with these immutable records:

- [fresh Debian provider](../conformance/records/2026-08-05-debian-provider-764d119.json), SHA-256 `0eb67e7abf06f820e8f4cd9cfd77ab109972f69f40b2705563da9aa0998d373a`;
- [live Boltz read-only shadow](../conformance/records/2026-08-05-boltz-readonly-shadow-764d119.json), SHA-256 `84766826654f3279721aa1998190fcadb71f3f242e62ab65e9eef6bf041ba42f`;
- [cutover rehearsal](../conformance/records/2026-08-05-swap-network-cutover-764d119.json), SHA-256 `50b2803f6c16676ab351cd5baaa5b11f57598d947e8483b4f44b5fac04bc24a5`.

All seven reference and candidate reads returned bounded JSON. Two shapes
matched exactly. The five recorded divergences are the candidate's explicit
profile/version fields, Boltz's additional Ark/Liquid pair inventory, its
additional chain-fee assets, and different node-stat group names. No
divergence changed the released Bitcoin/Lightning compatibility profile.

The rehearsal consumed the retained 33/33 #18 lab record and proved fresh
Debian provider operation, drain, immutable routes, atomic new-session cutover,
and rollback. Its `replacement_capability_after_local_gates` claim is true;
`live_deployment`, `operator_independence`, and `public_replacement` remain
false.
