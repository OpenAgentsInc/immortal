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
const AGENT_OWNER_SQL: &str =
    "SELECT 1 FROM agent_owner WHERE agent_pubkey = $1 AND owner_pubkey = $2";
const INSERT_AGENT_OWNER_SQL: &str = r#"
INSERT INTO agent_owner (agent_pubkey, owner_pubkey)
VALUES ($1, $2)
ON CONFLICT DO NOTHING
"#;
const BLOCKED_PUBKEY_SQL: &str = "SELECT reason FROM relay_blocked_pubkey WHERE pubkey = $1";
const BLOCKED_KIND_SQL: &str = "SELECT reason FROM relay_blocked_kind WHERE kind = $1";
const ADVISORY_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
const INGEST_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(1229802831, 1229866836)";
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
const MKT_IMMUTABLE_COORDINATE_SQL: &str = r#"
SELECT event_id, sig
FROM mkt_immutable_coordinate
WHERE pubkey = $1 AND kind = $2 AND identifier = $3
"#;
const INSERT_MKT_IMMUTABLE_COORDINATE_SQL: &str = r#"
INSERT INTO mkt_immutable_coordinate (pubkey, kind, identifier, event_id, sig)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING
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
const NOTIFY_EPHEMERAL_SQL: &str = "SELECT pg_notify('immortal_ephemeral', $1)";
const EVENT_BY_ID_SQL: &str = r#"
SELECT id, pubkey, created_at, kind, tags::text, content, sig, ingest_seq
FROM nostr_event
WHERE id = $1 AND (expires_at IS NULL OR expires_at > $2)
"#;
const LATEST_INGEST_SQL: &str = "SELECT COALESCE(MAX(ingest_seq), 0) FROM nostr_event";
const EVENT_BY_INGEST_SQL: &str = r#"
SELECT id, pubkey, created_at, kind, tags::text, content, sig, ingest_seq
FROM nostr_event
WHERE ingest_seq = $1 AND (expires_at IS NULL OR expires_at > $2)
"#;
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
  AND e.ingest_seq <= $9
  AND e.kind NOT BETWEEN 39604 AND 39613
  AND e.kind <> 39620
  AND e.kind <> 39650
  AND (
      e.kind NOT IN (1059, 24200, 30174, 30175, 30178, 30300, 30350, 30622, 44200)
      OR (
          e.kind IN (1059, 24200, 30622, 44200)
          AND $10::text[] IS NOT NULL
          AND (
              SELECT count(*) FROM nostr_indexed_tag recipient_count
              WHERE recipient_count.event_id = e.id
                AND recipient_count.tag_name = 'p'
          ) = 1
          AND EXISTS (
              SELECT 1 FROM nostr_indexed_tag recipient
              WHERE recipient.event_id = e.id
                AND recipient.tag_name = 'p'
                AND recipient.tag_value = ANY($10)
          )
      )
      OR (
          e.kind IN (30300, 30350)
          AND $10::text[] IS NOT NULL
          AND e.pubkey = ANY($10)
      )
      OR (
          e.kind = 30174
          AND $10::text[] IS NOT NULL
          AND (
              e.pubkey = ANY($10)
              OR EXISTS (
                  SELECT 1 FROM nostr_indexed_tag owner
                  WHERE owner.event_id = e.id
                    AND owner.tag_name = 'p'
                    AND owner.tag_value = ANY($10)
              )
          )
      )
      OR (
          e.kind IN (30175, 30178)
          AND (
              ($10::text[] IS NOT NULL AND e.pubkey = ANY($10))
              OR e.tags @> '[["shared","true"]]'::jsonb
          )
      )
  )
  AND (
      $11::text IS NULL
      OR e.search_vector @@ plainto_tsquery('simple'::regconfig, $11)
  )
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
ORDER BY
    CASE WHEN $11::text IS NOT NULL
         THEN ts_rank(e.search_vector, plainto_tsquery('simple'::regconfig, $11))
    END DESC NULLS LAST,
    e.created_at DESC, e.id ASC
LIMIT $8
"#;

const QUERY_FILTER_IDS_SQL: &str = r#"
SELECT e.id
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
  AND e.kind NOT BETWEEN 39604 AND 39613
  AND e.kind <> 39620
  AND e.kind <> 39650
  AND (
      e.kind NOT IN (1059, 24200, 30174, 30175, 30178, 30300, 30350, 30622, 44200)
      OR (
          e.kind IN (1059, 24200, 30622, 44200)
          AND $8::text[] IS NOT NULL
          AND (
              SELECT count(*) FROM nostr_indexed_tag recipient_count
              WHERE recipient_count.event_id = e.id
                AND recipient_count.tag_name = 'p'
          ) = 1
          AND EXISTS (
              SELECT 1 FROM nostr_indexed_tag recipient
              WHERE recipient.event_id = e.id
                AND recipient.tag_name = 'p'
                AND recipient.tag_value = ANY($8)
          )
      )
      OR (
          e.kind IN (30300, 30350)
          AND $8::text[] IS NOT NULL
          AND e.pubkey = ANY($8)
      )
      OR (
          e.kind = 30174
          AND $8::text[] IS NOT NULL
          AND (
              e.pubkey = ANY($8)
              OR EXISTS (
                  SELECT 1 FROM nostr_indexed_tag owner
                  WHERE owner.event_id = e.id
                    AND owner.tag_name = 'p'
                    AND owner.tag_value = ANY($8)
              )
          )
      )
      OR (
          e.kind IN (30175, 30178)
          AND (
              ($8::text[] IS NOT NULL AND e.pubkey = ANY($8))
              OR e.tags @> '[["shared","true"]]'::jsonb
          )
      )
  )
  AND (
      $9::text IS NULL
      OR e.search_vector @@ plainto_tsquery('simple'::regconfig, $9)
  )
ORDER BY e.id
LIMIT $10
"#;

const DELETE_EXPIRED_SQL: &str =
    "DELETE FROM nostr_event WHERE expires_at IS NOT NULL AND expires_at <= $1";
const GROUP_SQL: &str = r#"
SELECT name, about, picture, closed, supported_kinds, pins::text
FROM relay_group WHERE id = $1 FOR UPDATE
"#;
const GROUP_MEMBER_SQL: &str =
    "SELECT roles FROM relay_group_member WHERE group_id = $1 AND pubkey = $2";
const GROUP_MEMBERS_SQL: &str =
    "SELECT pubkey, roles FROM relay_group_member WHERE group_id = $1 ORDER BY pubkey";
const GROUP_INVITE_SQL: &str = "SELECT 1 FROM relay_group_invite WHERE group_id = $1 AND code = $2";
const GROUP_RECENT_IDS_SQL: &str = r#"
SELECT e.id
FROM nostr_event e
JOIN nostr_indexed_tag scope
  ON scope.event_id = e.id AND scope.tag_name = 'h' AND scope.tag_value = $1
WHERE e.pubkey <> $2
  AND (e.expires_at IS NULL OR e.expires_at > $3)
ORDER BY e.ingest_seq DESC
LIMIT 50
"#;
const PUT_GROUP_MEMBER_SQL: &str = r#"
INSERT INTO relay_group_member (group_id, pubkey, roles)
VALUES ($1, $2, $3)
ON CONFLICT (group_id, pubkey) DO UPDATE SET roles = EXCLUDED.roles
"#;
const REMOVE_GROUP_MEMBER_SQL: &str =
    "DELETE FROM relay_group_member WHERE group_id = $1 AND pubkey = $2";
const UPDATE_GROUP_METADATA_SQL: &str = r#"
UPDATE relay_group SET name = $2, about = $3, picture = $4,
    closed = $5, supported_kinds = $6, updated_at = clock_timestamp()
WHERE id = $1
"#;
const UPDATE_GROUP_PINS_SQL: &str = r#"
UPDATE relay_group SET pins = $2::text::jsonb, updated_at = clock_timestamp()
WHERE id = $1
"#;
const CREATE_GROUP_INVITE_SQL: &str = r#"
INSERT INTO relay_group_invite (group_id, code) VALUES ($1, $2)
ON CONFLICT DO NOTHING
"#;
const DELETE_GROUP_EVENT_SQL: &str = r#"
DELETE FROM nostr_event e
WHERE e.id = $1
  AND EXISTS (
      SELECT 1 FROM nostr_indexed_tag tag
      WHERE tag.event_id = e.id AND tag.tag_name = 'h' AND tag.tag_value = $2
  )
"#;
const CREATE_GROUP_SQL: &str = r#"
INSERT INTO relay_group (id, name, about, picture, closed, supported_kinds)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING
"#;
const DELETE_GROUP_SQL: &str = "DELETE FROM relay_group WHERE id = $1";
const LIST_GROUPS_SQL: &str = r#"
SELECT id, name, about, picture, closed, supported_kinds
FROM relay_group ORDER BY id LIMIT 1000
"#;
const ACCEPT_MANAGEMENT_SQL: &str = r#"
INSERT INTO management_request (event_id, pubkey) VALUES ($1, $2)
ON CONFLICT DO NOTHING RETURNING event_id
"#;
const BAN_PUBKEY_SQL: &str = r#"
INSERT INTO relay_blocked_pubkey (pubkey, reason) VALUES ($1, $2)
ON CONFLICT (pubkey) DO UPDATE SET reason = EXCLUDED.reason
"#;
const UNBAN_PUBKEY_SQL: &str = "DELETE FROM relay_blocked_pubkey WHERE pubkey = $1";
const LIST_BANNED_PUBKEYS_SQL: &str =
    "SELECT pubkey, reason FROM relay_blocked_pubkey ORDER BY pubkey LIMIT 10000";
const ALLOW_PUBKEY_MUTATION_SQL: &str = r#"
INSERT INTO relay_allowed_pubkey (pubkey, reason) VALUES ($1, $2)
ON CONFLICT (pubkey) DO UPDATE SET reason = EXCLUDED.reason
"#;
const UNALLOW_PUBKEY_SQL: &str = "DELETE FROM relay_allowed_pubkey WHERE pubkey = $1";
const LIST_ALLOWED_PUBKEYS_SQL: &str =
    "SELECT pubkey, reason FROM relay_allowed_pubkey ORDER BY pubkey LIMIT 10000";
const ALLOW_KIND_MUTATION_SQL: &str = r#"
INSERT INTO relay_allowed_kind (kind) VALUES ($1) ON CONFLICT DO NOTHING
"#;
const DISALLOW_KIND_SQL: &str = "DELETE FROM relay_allowed_kind WHERE kind = $1";
const LIST_ALLOWED_KINDS_SQL: &str =
    "SELECT kind FROM relay_allowed_kind ORDER BY kind LIMIT 65536";
const ACCEPT_MEDIA_AUTH_SQL: &str = r#"
INSERT INTO media_auth_request (event_id, pubkey, action) VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING RETURNING event_id
"#;
const MEDIA_BLOB_SQL: &str = r#"
SELECT sha256, size, media_type, uploaded_at, storage_key
FROM media_blob WHERE sha256 = $1 AND ready = TRUE
"#;
const MEDIA_BLOB_ANY_SQL: &str = r#"
SELECT sha256, size, media_type, uploaded_at, storage_key
FROM media_blob WHERE sha256 = $1
"#;
const MEDIA_OWNER_SQL: &str = "SELECT 1 FROM media_owner WHERE sha256 = $1 AND pubkey = $2";
const MEDIA_OWNER_BYTES_SQL: &str = r#"
SELECT COALESCE(SUM(blob.size), 0)::bigint
FROM media_owner owner_row
JOIN media_blob blob ON blob.sha256 = owner_row.sha256
WHERE owner_row.pubkey = $1
"#;
const INSERT_MEDIA_BLOB_SQL: &str = r#"
INSERT INTO media_blob (sha256, storage_key, size, media_type, uploaded_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING RETURNING sha256
"#;
const INSERT_MEDIA_OWNER_SQL: &str = r#"
INSERT INTO media_owner (sha256, pubkey) VALUES ($1, $2)
ON CONFLICT DO NOTHING
"#;
const FINALIZE_MEDIA_BLOB_SQL: &str =
    "UPDATE media_blob SET ready = TRUE WHERE sha256 = $1 RETURNING sha256";
const DELETE_MEDIA_OWNER_SQL: &str = r#"
DELETE FROM media_owner WHERE sha256 = $1 AND pubkey = $2 RETURNING sha256
"#;
const MEDIA_HAS_OWNER_SQL: &str = "SELECT EXISTS (SELECT 1 FROM media_owner WHERE sha256 = $1)";
const DELETE_MEDIA_BLOB_SQL: &str = "DELETE FROM media_blob WHERE sha256 = $1 RETURNING sha256";
const ACCEPT_BLOCK_COMMAND_SQL: &str = r#"
INSERT INTO block_command (event_id, pubkey, kind)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING
RETURNING event_id
"#;
const WORKSPACE_ICON_SQL: &str = "SELECT icon FROM workspace_profile WHERE singleton = TRUE";
const SET_WORKSPACE_ICON_SQL: &str = r#"
UPDATE workspace_profile
SET icon = $1, command_event_id = $2, updated_at = clock_timestamp()
WHERE singleton = TRUE
"#;
const UPSERT_ARCHIVED_IDENTITY_SQL: &str = r#"
INSERT INTO archived_identity (
    pubkey, reason, replaced_by, consent, actor_pubkey, request_event_id
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (pubkey) DO NOTHING
RETURNING pubkey
"#;
const DELETE_ARCHIVED_IDENTITY_SQL: &str =
    "DELETE FROM archived_identity WHERE pubkey = $1 RETURNING pubkey";
const LIST_ARCHIVED_IDENTITIES_SQL: &str =
    "SELECT pubkey FROM archived_identity ORDER BY pubkey LIMIT 10000";
const INSERT_DM_HIDDEN_SQL: &str = r#"
INSERT INTO dm_hidden (viewer_pubkey, group_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING
RETURNING group_id
"#;
const DELETE_DM_HIDDEN_SQL: &str = r#"
DELETE FROM dm_hidden WHERE viewer_pubkey = $1 AND group_id = $2
RETURNING group_id
"#;
const LIST_DM_HIDDEN_SQL: &str =
    "SELECT group_id FROM dm_hidden WHERE viewer_pubkey = $1 ORDER BY group_id LIMIT 10000";
const RECORD_NOSTR_EFFECT_IMPORT_SQL: &str = r#"
INSERT INTO nostr_effect_import_ledger (event_id, outcome)
VALUES ($1, $2)
ON CONFLICT (event_id) DO UPDATE
SET outcome = EXCLUDED.outcome, processed_at = clock_timestamp()
"#;
const MKT_SWP_RESERVATION_OUTCOME_SQL: &str = r#"
SELECT decision, active, expires_at, released_at
FROM mkt_swp_reservation_claim
WHERE quote_event_id = $1
"#;
const MKT_SWP_RESERVATION_FORK_SQL: &str = r#"
SELECT
  EXISTS (
    SELECT 1
    FROM mkt_swp_reservation_claim
    WHERE provider_pubkey = $1
      AND quote_event_id <> $5
      AND reservation_id = $4
  ) AS idempotency_conflict,
  EXISTS (
    SELECT 1
    FROM mkt_swp_reservation_claim
    WHERE provider_pubkey = $1
      AND quote_event_id <> $5
      AND capacity_bucket_id = $2
      AND (
          allocation_sequence >= $3
          OR capacity_commitment_sha256 = $6
      )
  ) AS allocation_fork
"#;
const MKT_SWP_RESERVATION_CAPACITY_SQL: &str = r#"
SELECT (
    SELECT COUNT(*)
    FROM mkt_swp_reservation_claim bucket_claim
    WHERE bucket_claim.provider_pubkey = $1
      AND bucket_claim.capacity_bucket_id = $2
      AND bucket_claim.active
      AND bucket_claim.expires_at > $7::bigint
) < $4::bigint
   AND COALESCE(SUM(asset_claim.reserved_amount), 0) <= ($5::bigint - $6::bigint)
FROM mkt_swp_reservation_claim asset_claim
WHERE asset_claim.provider_pubkey = $1
  AND asset_claim.capacity_bucket_id = $2
  AND asset_claim.reserved_asset_id = $3
  AND asset_claim.active
  AND asset_claim.expires_at > $7::bigint
"#;
const MKT_SWP_COVENANT_REUSE_SQL: &str = r#"
SELECT EXISTS (
    SELECT 1
    FROM mkt_swp_reservation_claim
    WHERE proof_class = 'covenant_reserve'
      AND reserve_unit_sha256 = $1
      AND active
      AND expires_at > $2
)
"#;
const INSERT_MKT_SWP_RESERVATION_SQL: &str = r#"
INSERT INTO mkt_swp_reservation_claim (
    quote_event_id, wrap_event_id, provider_pubkey, session_id,
    rfq_event_id, reservation_id, capacity_bucket_id, reserved_asset_id,
    reservation_class, reserved_amount, handler_committed_capacity,
    allocation_sequence, proof_class, proof_strength, proof_ref_sha256,
    reserve_unit_sha256, capacity_commitment_sha256, expires_at, decision, active
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
    $12, $13, $14, $15, $16, $17, $18, $19, $20
)
ON CONFLICT (quote_event_id) DO NOTHING
"#;
const RELEASE_MKT_SWP_RESERVATION_SQL: &str = r#"
UPDATE mkt_swp_reservation_claim
SET active = FALSE,
    released_at = $2,
    release_reason = 'expired'
WHERE quote_event_id = $1 AND active AND expires_at <= $2
"#;
const RELEASE_EXPIRED_MKT_SWP_RESERVATIONS_SQL: &str = r#"
WITH due AS (
    SELECT quote_event_id
    FROM mkt_swp_reservation_claim
    WHERE active AND expires_at <= $1
    ORDER BY expires_at, quote_event_id
    LIMIT 1000
    FOR UPDATE SKIP LOCKED
)
UPDATE mkt_swp_reservation_claim reservation
SET active = FALSE,
    released_at = $1,
    release_reason = 'expired'
FROM due
WHERE reservation.quote_event_id = due.quote_event_id
"#;
const MKT_SWP_STATUS_EXISTS_SQL: &str =
    "SELECT 1 FROM mkt_swp_status_claim WHERE status_event_id = $1";
const MKT_SWP_STATUS_FORK_COUNT_SQL: &str = r#"
SELECT COUNT(*)
FROM mkt_swp_status_claim
WHERE session_id = $1
  AND order_event_id = $2
  AND author_pubkey = $3
  AND sequence = $4
"#;
const INSERT_MKT_SWP_STATUS_SQL: &str = r#"
INSERT INTO mkt_swp_status_claim (
    status_event_id, wrap_event_id, author_pubkey, author_role,
    counterparty_pubkey, session_id, order_event_id, sequence,
    previous_event_id, state, swp_state
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (status_event_id) DO NOTHING
"#;
const MKT_SWP_STATUS_STREAM_SQL: &str = r#"
SELECT sequence, status_event_id
FROM mkt_swp_status_claim
WHERE session_id = $1
  AND order_event_id = $2
  AND author_pubkey = $3
ORDER BY sequence, status_event_id
LIMIT $4
"#;
const MKT_SWP_OBSERVATION_SQL: &str = r#"
SELECT observation_event_id
FROM mkt_swp_evidence_observation
WHERE source_event_id = $1 AND artifact_sha256 = $2
"#;
const INSERT_MKT_SWP_OBSERVATION_SQL: &str = r#"
INSERT INTO mkt_swp_evidence_observation (
    source_event_id, artifact_sha256, observation_event_id,
    evidence_class, rail_reference, view_sha256
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (source_event_id, artifact_sha256) DO NOTHING
"#;

#[derive(Clone)]
pub(crate) struct Statements {
    pub duplicate: Statement,
    pub policy: Statement,
    pub allowed_pubkey: Statement,
    pub allowed_kind: Statement,
    pub member: Statement,
    pub agent_owner: Statement,
    pub insert_agent_owner: Statement,
    pub blocked_pubkey: Statement,
    pub blocked_kind: Statement,
    pub advisory_lock: Statement,
    pub ingest_lock: Statement,
    pub tombstone_match: Statement,
    pub head: Statement,
    pub mkt_immutable_coordinate: Statement,
    pub insert_mkt_immutable_coordinate: Statement,
    pub insert_event: Statement,
    pub insert_tag: Statement,
    pub upsert_head: Statement,
    pub delete_event: Statement,
    pub insert_event_tombstone: Statement,
    pub insert_address_tombstone: Statement,
    pub delete_event_target: Statement,
    pub delete_address_target: Statement,
    pub notify: Statement,
    pub notify_ephemeral: Statement,
    pub event_by_id: Statement,
    pub event_by_ingest: Statement,
    pub latest_ingest: Statement,
    pub events_after: Statement,
    pub query_filter: Statement,
    pub query_filter_ids: Statement,
    pub delete_expired: Statement,
    pub group: Statement,
    pub group_member: Statement,
    pub group_members: Statement,
    pub group_invite: Statement,
    pub group_recent_ids: Statement,
    pub put_group_member: Statement,
    pub remove_group_member: Statement,
    pub update_group_metadata: Statement,
    pub update_group_pins: Statement,
    pub create_group_invite: Statement,
    pub delete_group_event: Statement,
    pub create_group: Statement,
    pub delete_group: Statement,
    pub list_groups: Statement,
    pub accept_management: Statement,
    pub ban_pubkey: Statement,
    pub unban_pubkey: Statement,
    pub list_banned_pubkeys: Statement,
    pub allow_pubkey_mutation: Statement,
    pub unallow_pubkey: Statement,
    pub list_allowed_pubkeys: Statement,
    pub allow_kind_mutation: Statement,
    pub disallow_kind: Statement,
    pub list_allowed_kinds: Statement,
    pub accept_media_auth: Statement,
    pub media_blob: Statement,
    pub media_blob_any: Statement,
    pub media_owner: Statement,
    pub media_owner_bytes: Statement,
    pub insert_media_blob: Statement,
    pub insert_media_owner: Statement,
    pub finalize_media_blob: Statement,
    pub delete_media_owner: Statement,
    pub media_has_owner: Statement,
    pub delete_media_blob: Statement,
    pub accept_block_command: Statement,
    pub workspace_icon: Statement,
    pub set_workspace_icon: Statement,
    pub upsert_archived_identity: Statement,
    pub delete_archived_identity: Statement,
    pub list_archived_identities: Statement,
    pub insert_dm_hidden: Statement,
    pub delete_dm_hidden: Statement,
    pub list_dm_hidden: Statement,
    pub record_nostr_effect_import: Statement,
    pub mkt_swp_reservation_outcome: Statement,
    pub mkt_swp_reservation_fork: Statement,
    pub mkt_swp_reservation_capacity: Statement,
    pub mkt_swp_covenant_reuse: Statement,
    pub insert_mkt_swp_reservation: Statement,
    pub release_mkt_swp_reservation: Statement,
    pub release_expired_mkt_swp_reservations: Statement,
    pub mkt_swp_status_exists: Statement,
    pub mkt_swp_status_fork_count: Statement,
    pub insert_mkt_swp_status: Statement,
    pub mkt_swp_status_stream: Statement,
    pub mkt_swp_observation: Statement,
    pub insert_mkt_swp_observation: Statement,
}

impl Statements {
    pub async fn prepare(client: &Client) -> Result<Self, StoreError> {
        Ok(Self {
            duplicate: client.prepare(DUPLICATE_SQL).await?,
            policy: client.prepare(POLICY_SQL).await?,
            allowed_pubkey: client.prepare(ALLOWED_PUBKEY_SQL).await?,
            allowed_kind: client.prepare(ALLOWED_KIND_SQL).await?,
            member: client.prepare(MEMBER_SQL).await?,
            agent_owner: client.prepare(AGENT_OWNER_SQL).await?,
            insert_agent_owner: client.prepare(INSERT_AGENT_OWNER_SQL).await?,
            blocked_pubkey: client.prepare(BLOCKED_PUBKEY_SQL).await?,
            blocked_kind: client.prepare(BLOCKED_KIND_SQL).await?,
            advisory_lock: client.prepare(ADVISORY_LOCK_SQL).await?,
            ingest_lock: client.prepare(INGEST_LOCK_SQL).await?,
            tombstone_match: client.prepare(TOMBSTONE_MATCH_SQL).await?,
            head: client.prepare(HEAD_SQL).await?,
            mkt_immutable_coordinate: client.prepare(MKT_IMMUTABLE_COORDINATE_SQL).await?,
            insert_mkt_immutable_coordinate: client
                .prepare(INSERT_MKT_IMMUTABLE_COORDINATE_SQL)
                .await?,
            insert_event: client.prepare(INSERT_EVENT_SQL).await?,
            insert_tag: client.prepare(INSERT_TAG_SQL).await?,
            upsert_head: client.prepare(UPSERT_HEAD_SQL).await?,
            delete_event: client.prepare(DELETE_EVENT_SQL).await?,
            insert_event_tombstone: client.prepare(INSERT_EVENT_TOMBSTONE_SQL).await?,
            insert_address_tombstone: client.prepare(INSERT_ADDRESS_TOMBSTONE_SQL).await?,
            delete_event_target: client.prepare(DELETE_EVENT_TARGET_SQL).await?,
            delete_address_target: client.prepare(DELETE_ADDRESS_TARGET_SQL).await?,
            notify: client.prepare(NOTIFY_SQL).await?,
            notify_ephemeral: client.prepare(NOTIFY_EPHEMERAL_SQL).await?,
            event_by_id: client.prepare(EVENT_BY_ID_SQL).await?,
            event_by_ingest: client.prepare(EVENT_BY_INGEST_SQL).await?,
            latest_ingest: client.prepare(LATEST_INGEST_SQL).await?,
            events_after: client.prepare(EVENTS_AFTER_SQL).await?,
            query_filter: client.prepare(QUERY_FILTER_SQL).await?,
            query_filter_ids: client.prepare(QUERY_FILTER_IDS_SQL).await?,
            delete_expired: client.prepare(DELETE_EXPIRED_SQL).await?,
            group: client.prepare(GROUP_SQL).await?,
            group_member: client.prepare(GROUP_MEMBER_SQL).await?,
            group_members: client.prepare(GROUP_MEMBERS_SQL).await?,
            group_invite: client.prepare(GROUP_INVITE_SQL).await?,
            group_recent_ids: client.prepare(GROUP_RECENT_IDS_SQL).await?,
            put_group_member: client.prepare(PUT_GROUP_MEMBER_SQL).await?,
            remove_group_member: client.prepare(REMOVE_GROUP_MEMBER_SQL).await?,
            update_group_metadata: client.prepare(UPDATE_GROUP_METADATA_SQL).await?,
            update_group_pins: client.prepare(UPDATE_GROUP_PINS_SQL).await?,
            create_group_invite: client.prepare(CREATE_GROUP_INVITE_SQL).await?,
            delete_group_event: client.prepare(DELETE_GROUP_EVENT_SQL).await?,
            create_group: client.prepare(CREATE_GROUP_SQL).await?,
            delete_group: client.prepare(DELETE_GROUP_SQL).await?,
            list_groups: client.prepare(LIST_GROUPS_SQL).await?,
            accept_management: client.prepare(ACCEPT_MANAGEMENT_SQL).await?,
            ban_pubkey: client.prepare(BAN_PUBKEY_SQL).await?,
            unban_pubkey: client.prepare(UNBAN_PUBKEY_SQL).await?,
            list_banned_pubkeys: client.prepare(LIST_BANNED_PUBKEYS_SQL).await?,
            allow_pubkey_mutation: client.prepare(ALLOW_PUBKEY_MUTATION_SQL).await?,
            unallow_pubkey: client.prepare(UNALLOW_PUBKEY_SQL).await?,
            list_allowed_pubkeys: client.prepare(LIST_ALLOWED_PUBKEYS_SQL).await?,
            allow_kind_mutation: client.prepare(ALLOW_KIND_MUTATION_SQL).await?,
            disallow_kind: client.prepare(DISALLOW_KIND_SQL).await?,
            list_allowed_kinds: client.prepare(LIST_ALLOWED_KINDS_SQL).await?,
            accept_media_auth: client.prepare(ACCEPT_MEDIA_AUTH_SQL).await?,
            media_blob: client.prepare(MEDIA_BLOB_SQL).await?,
            media_blob_any: client.prepare(MEDIA_BLOB_ANY_SQL).await?,
            media_owner: client.prepare(MEDIA_OWNER_SQL).await?,
            media_owner_bytes: client.prepare(MEDIA_OWNER_BYTES_SQL).await?,
            insert_media_blob: client.prepare(INSERT_MEDIA_BLOB_SQL).await?,
            insert_media_owner: client.prepare(INSERT_MEDIA_OWNER_SQL).await?,
            finalize_media_blob: client.prepare(FINALIZE_MEDIA_BLOB_SQL).await?,
            delete_media_owner: client.prepare(DELETE_MEDIA_OWNER_SQL).await?,
            media_has_owner: client.prepare(MEDIA_HAS_OWNER_SQL).await?,
            delete_media_blob: client.prepare(DELETE_MEDIA_BLOB_SQL).await?,
            accept_block_command: client.prepare(ACCEPT_BLOCK_COMMAND_SQL).await?,
            workspace_icon: client.prepare(WORKSPACE_ICON_SQL).await?,
            set_workspace_icon: client.prepare(SET_WORKSPACE_ICON_SQL).await?,
            upsert_archived_identity: client.prepare(UPSERT_ARCHIVED_IDENTITY_SQL).await?,
            delete_archived_identity: client.prepare(DELETE_ARCHIVED_IDENTITY_SQL).await?,
            list_archived_identities: client.prepare(LIST_ARCHIVED_IDENTITIES_SQL).await?,
            insert_dm_hidden: client.prepare(INSERT_DM_HIDDEN_SQL).await?,
            delete_dm_hidden: client.prepare(DELETE_DM_HIDDEN_SQL).await?,
            list_dm_hidden: client.prepare(LIST_DM_HIDDEN_SQL).await?,
            record_nostr_effect_import: client.prepare(RECORD_NOSTR_EFFECT_IMPORT_SQL).await?,
            mkt_swp_reservation_outcome: client.prepare(MKT_SWP_RESERVATION_OUTCOME_SQL).await?,
            mkt_swp_reservation_fork: client.prepare(MKT_SWP_RESERVATION_FORK_SQL).await?,
            mkt_swp_reservation_capacity: client.prepare(MKT_SWP_RESERVATION_CAPACITY_SQL).await?,
            mkt_swp_covenant_reuse: client.prepare(MKT_SWP_COVENANT_REUSE_SQL).await?,
            insert_mkt_swp_reservation: client.prepare(INSERT_MKT_SWP_RESERVATION_SQL).await?,
            release_mkt_swp_reservation: client.prepare(RELEASE_MKT_SWP_RESERVATION_SQL).await?,
            release_expired_mkt_swp_reservations: client
                .prepare(RELEASE_EXPIRED_MKT_SWP_RESERVATIONS_SQL)
                .await?,
            mkt_swp_status_exists: client.prepare(MKT_SWP_STATUS_EXISTS_SQL).await?,
            mkt_swp_status_fork_count: client.prepare(MKT_SWP_STATUS_FORK_COUNT_SQL).await?,
            insert_mkt_swp_status: client.prepare(INSERT_MKT_SWP_STATUS_SQL).await?,
            mkt_swp_status_stream: client.prepare(MKT_SWP_STATUS_STREAM_SQL).await?,
            mkt_swp_observation: client.prepare(MKT_SWP_OBSERVATION_SQL).await?,
            insert_mkt_swp_observation: client.prepare(INSERT_MKT_SWP_OBSERVATION_SQL).await?,
        })
    }
}
