# Postgres Store and Roles

Immortal uses one Postgres database. The M2 store owns migrations, event
admission, policy checks, indexed reads, process notification, and gap
recovery. No cache, broker, or second database participates.

## Schema

`migrations/0001_store.sql` creates:

- `nostr_event`: validated durable events, generated `ingest_seq`, optional
  expiration, and a generated full-text-search vector;
- `nostr_indexed_tag`: the first value of each single-letter ASCII tag;
- `replaceable_head`: the current event for each NIP-01 replacement address;
- `deletion_tombstone`: durable NIP-09 event and address deletions, including
  deletion-before-event;
- `relay_policy`, allow/block lists for pubkeys and kinds, and
  `relay_member_pubkey`: operator admission policy state; and
- `schema_migrations`: applied version, name, SHA-256, and timestamp.

The database independently rejects malformed identity widths, negative or
out-of-range protocol numbers, ephemeral kinds, inconsistent replacement
identifiers, and malformed tombstone shapes. Indexed access paths cover IDs,
authors, kinds, author-plus-kind, timestamps, tags, ingest sequence, expiry,
and full-text search.

## Migrations

Migration files are compiled into the binary. `Store::connect_with_report`
takes a database advisory lock, applies every pending file in one transaction,
and records its SHA-256. A changed historical file, an unknown database
version, or a mismatched name is a startup error. Concurrent processes wait
for the same lock and then verify the resulting ledger.

Do not execute `migrations/*.sql` directly with `psql`: that bypasses the
hash ledger and makes the database unverifiable. M2 exposes the embedded
runner through `Store::connect_with_report`; M3 invokes it during process
startup before binding the network listener.

Migration DDL is the only use of `batch_execute`: it is immutable SQL loaded
with `include_str!`, never SQL assembled at run time. Every runtime data
statement is prepared once through `tokio-postgres` and uses typed parameters.

`Store::connect_verified` is the hardened runtime path. It checks that all
known migration names and hashes are current without requesting DDL
privileges. Gateway startup runs migrations once, then creates its fixed set of
verified runtime workers and the dedicated notification connection before the
network listener binds.

## Admission transaction

One transaction performs duplicate and policy checks, takes deterministic
transaction-scoped advisory locks, checks tombstones, compares replacement
heads, inserts the event and indexed tags, applies deletion tombstones and
deletes superseded rows, updates the head, allocates `ingest_seq`, and calls
`pg_notify`. A stored result is returned only after commit.

The advisory-lock keys serialize every conflicting event ID and replacement
address across relay processes. Keys are sorted before acquisition, avoiding
deadlocks when one deletion request names several targets. This closes the
race where a deletion and its target arrive on different processes at the
same time.

Ephemeral kinds pass signature, timestamp, policy, and tombstone checks, but
the schema rejects them and the store never inserts them. After commit the
gateway fans them out locally and sends bounded hexadecimal chunks through the
`immortal_ephemeral` Postgres notification channel for other relay processes.
Listeners validate and reassemble the signed event in memory; no ephemeral
payload enters a table.

Durable admissions take a short global advisory lock immediately before
allocating `ingest_seq`. Conflicting event/replacement locks have already been
taken at that point. This makes durable sequence order equal commit order, so
the gateway can use a sampled high-water mark as a race-free historical/live
EOSE boundary.

Each gateway establishes `LISTEN` before sampling its durable cursor. A later
notification jump is recovered with the prepared, bounded `events_after`
query, so a missed individual notification does not lose delivery. Gaps larger
than 4,096 sequence positions, a cursor beyond the database high-water mark,
or a failed catch-up make the process non-current and close its clients.

## Admission policy

The singleton `relay_policy` row configures closed-membership mode, maximum
UTF-8 content bytes, maximum tag count, and future and past timestamp bounds.
A `max_past_seconds` value of zero disables the past bound. The schema rejects
negative limits and a zero content limit.

The `relay_allowed_pubkey` and `relay_allowed_kind` tables are optional
allowlists: an empty table permits every value, while a non-empty table permits
only listed values. `relay_blocked_pubkey` and `relay_blocked_kind` always deny
matching values and take precedence over the allowlists. When
`closed_membership` is true, the author must also exist in
`relay_member_pubkey`. Operators update these rows through the database owner;
each admission transaction reads the current committed policy.

## Roles

### Simple single-box role

The Debian runbook's `immortal` role owns only the `immortal` database and is
not a superuser, replication role, role creator, or database creator. This is
the supported minimal deployment. It may apply migrations and run the relay.

### Split migration and runtime roles

For a stricter production installation, create the database with a migration
owner and a separate login used by the running relay:

```sql
CREATE ROLE immortal_migrator LOGIN PASSWORD '<MIGRATION_PASSWORD>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE immortal_runtime LOGIN PASSWORD '<RUNTIME_PASSWORD>'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE immortal OWNER immortal_migrator;
```

Connect as `immortal_migrator`, run the embedded migrations, then grant only
the runtime operations M2 uses:

```sql
GRANT CONNECT ON DATABASE immortal TO immortal_runtime;
GRANT USAGE ON SCHEMA public TO immortal_runtime;

GRANT SELECT ON schema_migrations TO immortal_runtime;
GRANT SELECT, INSERT, DELETE ON nostr_event TO immortal_runtime;
GRANT SELECT, INSERT ON nostr_indexed_tag TO immortal_runtime;
GRANT SELECT, INSERT, UPDATE ON replaceable_head TO immortal_runtime;
GRANT SELECT, INSERT, UPDATE ON deletion_tombstone TO immortal_runtime;
GRANT SELECT ON relay_policy, relay_allowed_pubkey, relay_allowed_kind,
    relay_member_pubkey, relay_blocked_pubkey, relay_blocked_kind
    TO immortal_runtime;
GRANT USAGE, SELECT ON SEQUENCE nostr_event_ingest_seq_seq
    TO immortal_runtime;
```

The running process connects as `immortal_runtime` and uses
`Store::connect_verified`. Operators change policy and apply future migrations
through `immortal_migrator`; the public relay process cannot grant itself
rights or alter the schema. Each future migration must explicitly grant its
new runtime operations.

Never put either password in this repository or a command-line argument.
