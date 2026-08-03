use tokio_postgres::{Client, Statement};

use super::StoreError;

const DUPLICATE_SQL: &str = "SELECT 1 FROM nostr_event WHERE id = $1";
const POLICY_SQL: &str = r#"
SELECT closed_membership, max_content_bytes, max_tags,
       max_future_seconds, max_past_seconds
FROM relay_policy
WHERE singleton = TRUE
"#;
const ALLOWED_PUBKEY_SQL: &str = r#"
SELECT NOT EXISTS (SELECT 1 FROM relay_allowed_pubkey)
    OR EXISTS (SELECT 1 FROM relay_allowed_pubkey WHERE pubkey = $1)
"#;
const ALLOWED_KIND_SQL: &str = r#"
SELECT NOT EXISTS (SELECT 1 FROM relay_allowed_kind)
    OR EXISTS (SELECT 1 FROM relay_allowed_kind WHERE kind = $1)
"#;
const MEMBER_SQL: &str = "SELECT 1 FROM relay_member_pubkey WHERE pubkey = $1";
const BLOCKED_PUBKEY_SQL: &str = "SELECT reason FROM relay_blocked_pubkey WHERE pubkey = $1";
const BLOCKED_KIND_SQL: &str = "SELECT reason FROM relay_blocked_kind WHERE kind = $1";
const ADVISORY_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const TOMBSTONE_MATCH_SQL: &str = r#"
SELECT EXISTS (
    SELECT 1
    FROM deletion_tombstone
    WHERE tombstone_type = 'event'
      AND event_id = $1
      AND author_pubkey = $2
) OR EXISTS (
    SELECT 1
    FROM deletion_tombstone
    WHERE tombstone_type = 'address'
      AND kind = $3
      AND author_pubkey = $2
      AND identifier = $4
      AND deleted_through >= $5
)
"#;
const HEAD_SQL: &str = r#"
SELECT event_id, created_at
FROM replaceable_head
WHERE kind = $1 AND pubkey = $2 AND identifier = $3
FOR UPDATE
"#;
const INSERT_EVENT_SQL: &str = r#"
INSERT INTO nostr_event (
    id, pubkey, created_at, kind, tags, content, sig,
    replacement_identifier, expires_at
) VALUES ($1, $2, $3, $4, $5::text::jsonb, $6, $7, $8, $9)
ON CONFLICT (id) DO NOTHING
RETURNING ingest_seq
"#;
const INSERT_TAG_SQL: &str = r#"
INSERT INTO nostr_indexed_tag (event_id, tag_name, tag_value, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
"#;
const UPSERT_HEAD_SQL: &str = r#"
INSERT INTO replaceable_head (
    kind, pubkey, identifier, event_id, created_at
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (kind, pubkey, identifier) DO UPDATE
SET event_id = EXCLUDED.event_id, created_at = EXCLUDED.created_at
"#;
const DELETE_EVENT_SQL: &str = "DELETE FROM nostr_event WHERE id = $1";
const INSERT_EVENT_TOMBSTONE_SQL: &str = r#"
INSERT INTO deletion_tombstone (
    tombstone_type, event_id, author_pubkey, deletion_event_id
) VALUES ('event', $1, $2, $3)
ON CONFLICT (event_id, author_pubkey)
    WHERE tombstone_type = 'event'
DO NOTHING
"#;
const INSERT_ADDRESS_TOMBSTONE_SQL: &str = r#"
INSERT INTO deletion_tombstone (
    tombstone_type, kind, author_pubkey, identifier,
    deleted_through, deletion_event_id
) VALUES ('address', $1, $2, $3, $4, $5)
ON CONFLICT (kind, author_pubkey, identifier)
    WHERE tombstone_type = 'address'
DO UPDATE SET
    deletion_event_id = CASE
        WHEN EXCLUDED.deleted_through > deletion_tombstone.deleted_through
        THEN EXCLUDED.deletion_event_id
        ELSE deletion_tombstone.deletion_event_id
    END,
    deleted_through = GREATEST(
        deletion_tombstone.deleted_through,
        EXCLUDED.deleted_through
    )
"#;
const DELETE_EVENT_TARGET_SQL: &str = r#"
DELETE FROM nostr_event
WHERE id = $1 AND pubkey = $2 AND kind <> 5
"#;
const DELETE_ADDRESS_TARGET_SQL: &str = r#"
DELETE FROM nostr_event
WHERE kind = $1
  AND pubkey = $2
  AND replacement_identifier = $3
  AND created_at <= $4
"#;
const NOTIFY_SQL: &str = "SELECT pg_notify('immortal_event', $1)";
const EVENT_BY_ID_SQL: &str = r#"
SELECT id, pubkey, created_at, kind, tags::text, content, sig, ingest_seq
FROM nostr_event
WHERE id = $1 AND (expires_at IS NULL OR expires_at > $2)
"#;
const LATEST_INGEST_SQL: &str = "SELECT COALESCE(MAX(ingest_seq), 0) FROM nostr_event";
const EVENTS_AFTER_SQL: &str = r#"
SELECT id, pubkey, created_at, kind, tags::text, content, sig, ingest_seq
FROM nostr_event
WHERE ingest_seq > $1
  AND ingest_seq <= $2
  AND (expires_at IS NULL OR expires_at > $3)
ORDER BY ingest_seq ASC
LIMIT $4
"#;
const QUERY_FILTER_SQL: &str = r#"
SELECT e.id, e.pubkey, e.created_at, e.kind, e.tags::text,
       e.content, e.sig, e.ingest_seq
FROM nostr_event e
WHERE ($1::text[] IS NULL OR e.id = ANY($1))
  AND ($2::text[] IS NULL OR e.pubkey = ANY($2))
  AND ($3::integer[] IS NULL OR e.kind = ANY($3))
  AND ($4::bigint IS NULL OR e.created_at >= $4)
  AND ($5::bigint IS NULL OR e.created_at <= $5)
  AND (e.expires_at IS NULL OR e.expires_at > $7)
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_each($6::text::jsonb) requested(tag_name, tag_values)
      WHERE NOT EXISTS (
          SELECT 1
          FROM nostr_indexed_tag indexed
          WHERE indexed.event_id = e.id
            AND indexed.tag_name = requested.tag_name
            AND indexed.tag_value IN (
                SELECT jsonb_array_elements_text(requested.tag_values)
            )
      )
  )
ORDER BY e.created_at DESC, e.id ASC
LIMIT $8
"#;

#[derive(Clone)]
pub(crate) struct Statements {
    pub duplicate: Statement,
    pub policy: Statement,
    pub allowed_pubkey: Statement,
    pub allowed_kind: Statement,
    pub member: Statement,
    pub blocked_pubkey: Statement,
    pub blocked_kind: Statement,
    pub advisory_lock: Statement,
    pub tombstone_match: Statement,
    pub head: Statement,
    pub insert_event: Statement,
    pub insert_tag: Statement,
    pub upsert_head: Statement,
    pub delete_event: Statement,
    pub insert_event_tombstone: Statement,
    pub insert_address_tombstone: Statement,
    pub delete_event_target: Statement,
    pub delete_address_target: Statement,
    pub notify: Statement,
    pub event_by_id: Statement,
    pub latest_ingest: Statement,
    pub events_after: Statement,
    pub query_filter: Statement,
}

impl Statements {
    pub async fn prepare(client: &Client) -> Result<Self, StoreError> {
        Ok(Self {
            duplicate: client.prepare(DUPLICATE_SQL).await?,
            policy: client.prepare(POLICY_SQL).await?,
            allowed_pubkey: client.prepare(ALLOWED_PUBKEY_SQL).await?,
            allowed_kind: client.prepare(ALLOWED_KIND_SQL).await?,
            member: client.prepare(MEMBER_SQL).await?,
            blocked_pubkey: client.prepare(BLOCKED_PUBKEY_SQL).await?,
            blocked_kind: client.prepare(BLOCKED_KIND_SQL).await?,
            advisory_lock: client.prepare(ADVISORY_LOCK_SQL).await?,
            tombstone_match: client.prepare(TOMBSTONE_MATCH_SQL).await?,
            head: client.prepare(HEAD_SQL).await?,
            insert_event: client.prepare(INSERT_EVENT_SQL).await?,
            insert_tag: client.prepare(INSERT_TAG_SQL).await?,
            upsert_head: client.prepare(UPSERT_HEAD_SQL).await?,
            delete_event: client.prepare(DELETE_EVENT_SQL).await?,
            insert_event_tombstone: client.prepare(INSERT_EVENT_TOMBSTONE_SQL).await?,
            insert_address_tombstone: client.prepare(INSERT_ADDRESS_TOMBSTONE_SQL).await?,
            delete_event_target: client.prepare(DELETE_EVENT_TARGET_SQL).await?,
            delete_address_target: client.prepare(DELETE_ADDRESS_TARGET_SQL).await?,
            notify: client.prepare(NOTIFY_SQL).await?,
            event_by_id: client.prepare(EVENT_BY_ID_SQL).await?,
            latest_ingest: client.prepare(LATEST_INGEST_SQL).await?,
            events_after: client.prepare(EVENTS_AFTER_SQL).await?,
            query_filter: client.prepare(QUERY_FILTER_SQL).await?,
        })
    }
}
