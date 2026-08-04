-- Adopt the MKT-SWP private immutable Swap Contract without exposing legacy rows.

ALTER TABLE mkt_immutable_coordinate
    DROP CONSTRAINT mkt_immutable_kind_range;
ALTER TABLE mkt_immutable_coordinate
    ADD CONSTRAINT mkt_immutable_kind_range CHECK (
        kind BETWEEN 39604 AND 39610
    );

INSERT INTO mkt_immutable_coordinate (pubkey, kind, identifier, event_id, sig)
SELECT pubkey, kind, replacement_identifier, id, sig
FROM nostr_event
WHERE kind = 39610;

DELETE FROM replaceable_head
WHERE kind = 39610;

DROP INDEX nostr_event_search_idx;
ALTER TABLE nostr_event DROP COLUMN search_vector;
ALTER TABLE nostr_event ADD COLUMN search_vector tsvector GENERATED ALWAYS AS (
    CASE
        WHEN kind = 1059
          OR kind BETWEEN 39604 AND 39610
          OR kind IN (30078, 30174, 30175, 30178, 30300, 30350, 30622, 44200)
        THEN NULL::tsvector
        ELSE to_tsvector('simple'::regconfig, content)
    END
) STORED;
CREATE INDEX nostr_event_search_idx
    ON nostr_event USING gin (search_vector);
