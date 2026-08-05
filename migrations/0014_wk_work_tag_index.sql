-- Index the NIP-WK `work` tag so Work Events (kind 32171) are enumerable
-- through the rendering-contract filter {"kinds":[32171],"#work":[...]}.
-- Single-letter NIP-01 tag indexing is unchanged; `work` is the first
-- extended indexed tag name (EXTENDED_INDEXED_TAG_NAMES in immortal-core).

ALTER TABLE nostr_indexed_tag
    DROP CONSTRAINT nostr_indexed_tag_name;
ALTER TABLE nostr_indexed_tag
    ADD CONSTRAINT nostr_indexed_tag_name CHECK (
        (octet_length(tag_name) = 1 AND tag_name ~ '^[A-Za-z]$')
        OR tag_name = 'work'
    );

-- Backfill `work` index rows for events stored before this migration.
INSERT INTO nostr_indexed_tag (event_id, tag_name, tag_value, created_at)
SELECT e.id, 'work', tag_element ->> 1, e.created_at
FROM nostr_event e,
     jsonb_array_elements(e.tags) AS tag_element
WHERE tag_element ->> 0 = 'work'
  AND tag_element ->> 1 IS NOT NULL
ON CONFLICT DO NOTHING;
