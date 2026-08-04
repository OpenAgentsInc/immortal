-- Durable NIP-MKT idempotency coordinates survive event deletion and expiry.

CREATE TABLE mkt_immutable_coordinate (
    pubkey text COLLATE "C" NOT NULL,
    kind integer NOT NULL,
    identifier text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL UNIQUE,
    sig text COLLATE "C" NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (pubkey, kind, identifier),
    CONSTRAINT mkt_immutable_pubkey_shape CHECK (
        pubkey ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT mkt_immutable_kind_range CHECK (
        kind BETWEEN 39604 AND 39609
    ),
    CONSTRAINT mkt_immutable_event_id_shape CHECK (
        event_id ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT mkt_immutable_sig_shape CHECK (
        sig ~ '^[0-9a-f]{128}$'
    )
);

INSERT INTO mkt_immutable_coordinate (pubkey, kind, identifier, event_id, sig)
SELECT pubkey, kind, replacement_identifier, id, sig
FROM nostr_event
WHERE kind BETWEEN 39604 AND 39609;

DELETE FROM replaceable_head
WHERE kind BETWEEN 39604 AND 39609;
