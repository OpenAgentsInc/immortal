CREATE TABLE provider_boltz_invoice_binding (
    payment_hash text COLLATE "C" PRIMARY KEY,
    invoice text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL UNIQUE,
    status_event_id text COLLATE "C" NOT NULL UNIQUE
        REFERENCES provider_session_record (event_id),
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_boltz_invoice_payment_hash CHECK (
        payment_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_boltz_invoice_value CHECK (
        octet_length(invoice) BETWEEN 1 AND 2048
        AND invoice = lower(invoice)
    ),
    CONSTRAINT provider_boltz_invoice_session CHECK (
        session_id ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_boltz_invoice_status CHECK (
        status_event_id ~ '^[0-9a-f]{64}$'
    )
);

CREATE INDEX provider_boltz_invoice_binding_session
    ON provider_boltz_invoice_binding (session_id, payment_hash);

CREATE INDEX provider_boltz_invoice_candidate_session
    ON provider_session_record (session_id)
    WHERE kind = 39607;
