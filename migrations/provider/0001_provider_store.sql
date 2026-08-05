CREATE OR REPLACE FUNCTION provider_public_json_safe(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    member record;
    normalized text;
BEGIN
    IF jsonb_typeof(document) = 'object' THEN
        FOR member IN SELECT key, value FROM jsonb_each(document) LOOP
            normalized := regexp_replace(lower(member.key), '[^a-z0-9]', '', 'g');
            IF (NOT (normalized = ANY (ARRAY[
                    'preimagerecoveryref', 'credentialexposure'
                ])) AND (
                position('seed' IN normalized) > 0
                OR position('preimage' IN normalized) > 0
                OR position('privatekey' IN normalized) > 0
                OR position('spendkey' IN normalized) > 0
                OR position('claimkey' IN normalized) > 0
                OR position('refundkey' IN normalized) > 0
                OR position('macaroon' IN normalized) > 0
                OR position('credential' IN normalized) > 0
            ))
                OR normalized = ANY (ARRAY[
                'mnemonic', 'xprv', 'claimsecret', 'refundsecret',
                'nwc', 'nwcstring',
                'nwcconnectionstring', 'nwcuri', 'bearertoken',
                'walletrpcpayload', 'musigsecretnonce',
                'privkey', 'secretkey', 'secretnonce', 'signingnonce'
            ]) THEN
                RETURN false;
            END IF;
            IF NOT provider_public_json_safe(member.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'array' THEN
        FOR member IN SELECT value FROM jsonb_array_elements(document) LOOP
            IF NOT provider_public_json_safe(member.value) THEN
                RETURN false;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'string' THEN
        normalized := document #>> '{}';
        IF normalized LIKE 'xprv%'
            OR normalized LIKE 'tprv%'
            OR normalized LIKE 'nostr+walletconnect://%'
        THEN
            RETURN false;
        END IF;
    END IF;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION provider_signed_event_safe(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    content jsonb;
BEGIN
    IF jsonb_typeof(document) <> 'object'
        OR jsonb_typeof(document -> 'content') <> 'string'
        OR NOT provider_public_json_safe(document)
    THEN
        RETURN false;
    END IF;
    BEGIN
        content := (document ->> 'content')::jsonb;
    EXCEPTION WHEN others THEN
        RETURN false;
    END;
    RETURN provider_public_json_safe(content);
END;
$$;

CREATE TABLE provider_session_record (
    event_id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C" NOT NULL,
    author_pubkey text COLLATE "C" NOT NULL,
    kind integer NOT NULL,
    created_at bigint NOT NULL,
    event_sha256 text COLLATE "C" NOT NULL,
    signed_event jsonb NOT NULL,
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_session_record_event_id CHECK (event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_session_record_session_id CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_session_record_author CHECK (author_pubkey ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_session_record_kind CHECK (kind BETWEEN 39604 AND 39699),
    CONSTRAINT provider_session_record_created_at CHECK (created_at >= 0),
    CONSTRAINT provider_session_record_digest CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_session_record_public CHECK (provider_signed_event_safe(signed_event))
);

CREATE INDEX provider_session_record_session_order
    ON provider_session_record (session_id, created_at, event_id);

CREATE TABLE provider_session_disposition (
    session_id text COLLATE "C" PRIMARY KEY,
    reason_code text COLLATE "C" NOT NULL,
    disposed_at bigint NOT NULL,
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_session_disposition_session CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_session_disposition_reason CHECK (
        reason_code ~ '^[a-z][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT provider_session_disposition_time CHECK (disposed_at >= 0)
);

CREATE TABLE provider_exit_package (
    package_id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C" NOT NULL,
    order_id text COLLATE "C" NOT NULL,
    leg_id text COLLATE "C" NOT NULL,
    path text COLLATE "C" NOT NULL,
    package_sha256 text COLLATE "C" NOT NULL,
    public_package jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'prepared',
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_exit_package_id CHECK (package_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_exit_package_session CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_exit_package_order CHECK (order_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_exit_package_leg CHECK (leg_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CONSTRAINT provider_exit_package_path CHECK (path IN ('claim', 'refund')),
    CONSTRAINT provider_exit_package_digest CHECK (package_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_exit_package_state CHECK (
        state IN ('prepared', 'broadcast', 'confirmed', 'reorged', 'replaced', 'unresolved')
    ),
    CONSTRAINT provider_exit_package_time CHECK (created_at >= 0 AND updated_at >= created_at),
    CONSTRAINT provider_exit_package_public CHECK (provider_public_json_safe(public_package))
);

CREATE INDEX provider_exit_package_session
    ON provider_exit_package (session_id, package_id);

CREATE TABLE provider_effect (
    effect_id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C" NOT NULL,
    operation text COLLATE "C" NOT NULL,
    request_sha256 text COLLATE "C" NOT NULL,
    public_request jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'pending',
    result_sha256 text COLLATE "C",
    public_result jsonb,
    external_reference text COLLATE "C",
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_effect_id CHECK (effect_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_effect_session CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_effect_operation CHECK (operation ~ '^[a-z][a-z0-9._-]{0,63}$'),
    CONSTRAINT provider_effect_request_digest CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_effect_state CHECK (state IN ('pending', 'applied', 'unresolved')),
    CONSTRAINT provider_effect_result_pair CHECK (
        (result_sha256 IS NULL AND public_result IS NULL)
        OR (result_sha256 ~ '^[0-9a-f]{64}$' AND public_result IS NOT NULL)
    ),
    CONSTRAINT provider_effect_time CHECK (created_at >= 0 AND updated_at >= created_at),
    CONSTRAINT provider_effect_request_public CHECK (provider_public_json_safe(public_request)),
    CONSTRAINT provider_effect_result_public CHECK (
        public_result IS NULL OR provider_public_json_safe(public_result)
    )
);

CREATE INDEX provider_effect_session ON provider_effect (session_id, effect_id);

CREATE TABLE provider_capacity_bucket (
    bucket_id text COLLATE "C" PRIMARY KEY,
    asset_id text COLLATE "C" NOT NULL,
    total_capacity bigint NOT NULL,
    allocated_capacity bigint NOT NULL DEFAULT 0,
    allocation_sequence bigint NOT NULL DEFAULT 0,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_capacity_bucket_id CHECK (bucket_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CONSTRAINT provider_capacity_bucket_asset CHECK (asset_id LIKE 'swp:1:%'),
    CONSTRAINT provider_capacity_bucket_amount CHECK (
        total_capacity >= 0
        AND allocated_capacity >= 0
        AND allocated_capacity <= total_capacity
    ),
    CONSTRAINT provider_capacity_bucket_sequence CHECK (allocation_sequence >= 0),
    CONSTRAINT provider_capacity_bucket_time CHECK (updated_at >= 0)
);

CREATE TABLE provider_reservation (
    reservation_id text COLLATE "C" PRIMARY KEY,
    effect_id text COLLATE "C" NOT NULL UNIQUE REFERENCES provider_effect(effect_id),
    session_id text COLLATE "C" NOT NULL UNIQUE,
    bucket_id text COLLATE "C" NOT NULL REFERENCES provider_capacity_bucket(bucket_id),
    asset_id text COLLATE "C" NOT NULL,
    amount bigint NOT NULL,
    request_sha256 text COLLATE "C" NOT NULL,
    allocation_sequence bigint NOT NULL,
    expires_at bigint NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'active',
    release_cause text COLLATE "C",
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_reservation_id CHECK (reservation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_reservation_session CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_reservation_asset CHECK (asset_id LIKE 'swp:1:%'),
    CONSTRAINT provider_reservation_amount CHECK (amount > 0),
    CONSTRAINT provider_reservation_digest CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_reservation_sequence CHECK (allocation_sequence > 0),
    CONSTRAINT provider_reservation_expiry CHECK (expires_at > created_at),
    CONSTRAINT provider_reservation_state CHECK (state IN ('active', 'released', 'unresolved')),
    CONSTRAINT provider_reservation_release CHECK (
        (state = 'active' AND release_cause IS NULL)
        OR (state <> 'active' AND release_cause IS NOT NULL)
    ),
    CONSTRAINT provider_reservation_time CHECK (created_at >= 0 AND updated_at >= created_at)
);

CREATE INDEX provider_reservation_bucket_state
    ON provider_reservation (bucket_id, state, expires_at, reservation_id);
CREATE INDEX provider_reservation_state
    ON provider_reservation (state, reservation_id);

CREATE TABLE provider_utxo (
    txid text COLLATE "C" NOT NULL,
    vout integer NOT NULL,
    asset_id text COLLATE "C" NOT NULL,
    amount bigint NOT NULL,
    script_pubkey text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL,
    reservation_id text COLLATE "C" REFERENCES provider_reservation(reservation_id),
    confirmations integer NOT NULL DEFAULT 0,
    block_hash text COLLATE "C",
    replacement_txid text COLLATE "C",
    observed_at bigint NOT NULL,
    PRIMARY KEY (txid, vout),
    CONSTRAINT provider_utxo_txid CHECK (txid ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_utxo_vout CHECK (vout >= 0),
    CONSTRAINT provider_utxo_asset CHECK (asset_id LIKE 'swp:1:%'),
    CONSTRAINT provider_utxo_amount CHECK (amount > 0),
    CONSTRAINT provider_utxo_script CHECK (
        script_pubkey ~ '^[0-9a-f]+$' AND length(script_pubkey) <= 20000
    ),
    CONSTRAINT provider_utxo_state CHECK (
        state IN ('available', 'reserved', 'spent', 'reorged', 'replaced', 'unresolved')
    ),
    CONSTRAINT provider_utxo_reservation CHECK (
        (state = 'reserved' AND reservation_id IS NOT NULL)
        OR (state <> 'reserved')
    ),
    CONSTRAINT provider_utxo_confirmations CHECK (confirmations >= 0),
    CONSTRAINT provider_utxo_block_hash CHECK (
        block_hash IS NULL OR block_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_utxo_replacement CHECK (
        replacement_txid IS NULL OR replacement_txid ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_utxo_observed CHECK (observed_at >= 0)
);

CREATE INDEX provider_utxo_state_asset
    ON provider_utxo (state, asset_id, amount, txid, vout);
CREATE INDEX provider_utxo_reservation
    ON provider_utxo (reservation_id, txid, vout)
    WHERE reservation_id IS NOT NULL;

CREATE TABLE provider_watch_job (
    job_id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C" NOT NULL,
    effect_id text COLLATE "C",
    job_kind text COLLATE "C" NOT NULL,
    request_sha256 text COLLATE "C" NOT NULL,
    public_payload jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'pending',
    due_height bigint,
    due_at bigint,
    lease_until bigint,
    attempt_count integer NOT NULL DEFAULT 0,
    maximum_attempts integer NOT NULL,
    result_sha256 text COLLATE "C",
    public_result jsonb,
    broadcast_txid text COLLATE "C",
    replacement_txid text COLLATE "C",
    confirmations integer NOT NULL DEFAULT 0,
    observed_block_hash text COLLATE "C",
    last_chain_event text COLLATE "C",
    page_code text COLLATE "C",
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_watch_job_id CHECK (job_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_watch_job_session CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_watch_job_effect CHECK (
        effect_id IS NULL OR effect_id ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_watch_job_kind CHECK (job_kind ~ '^[a-z][a-z0-9._-]{0,63}$'),
    CONSTRAINT provider_watch_job_request CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_watch_job_state CHECK (
        state IN ('pending', 'running', 'broadcast', 'confirmed', 'completed', 'unresolved', 'page')
    ),
    CONSTRAINT provider_watch_job_due CHECK (due_height IS NOT NULL OR due_at IS NOT NULL),
    CONSTRAINT provider_watch_job_attempts CHECK (
        attempt_count >= 0 AND maximum_attempts BETWEEN 1 AND 100
    ),
    CONSTRAINT provider_watch_job_result_pair CHECK (
        (result_sha256 IS NULL AND public_result IS NULL)
        OR (result_sha256 ~ '^[0-9a-f]{64}$' AND public_result IS NOT NULL)
    ),
    CONSTRAINT provider_watch_job_txid CHECK (
        broadcast_txid IS NULL OR broadcast_txid ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_watch_job_replacement CHECK (
        replacement_txid IS NULL OR replacement_txid ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_watch_job_confirmations CHECK (confirmations >= 0),
    CONSTRAINT provider_watch_job_block CHECK (
        observed_block_hash IS NULL OR observed_block_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_watch_job_time CHECK (created_at >= 0 AND updated_at >= created_at),
    CONSTRAINT provider_watch_job_payload_public CHECK (provider_public_json_safe(public_payload)),
    CONSTRAINT provider_watch_job_result_public CHECK (
        public_result IS NULL OR provider_public_json_safe(public_result)
    )
);

CREATE INDEX provider_watch_job_due
    ON provider_watch_job (state, due_height, due_at, job_id);

CREATE TABLE provider_alert (
    alert_id text COLLATE "C" PRIMARY KEY,
    session_id text COLLATE "C",
    alert_class text COLLATE "C" NOT NULL,
    detail_code text COLLATE "C" NOT NULL,
    public_context jsonb NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'active',
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_alert_id CHECK (alert_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_alert_session CHECK (
        session_id IS NULL OR session_id ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_alert_class CHECK (alert_class ~ '^[a-z][a-z0-9._-]{0,63}$'),
    CONSTRAINT provider_alert_detail CHECK (detail_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    CONSTRAINT provider_alert_state CHECK (state IN ('active', 'acknowledged', 'resolved')),
    CONSTRAINT provider_alert_time CHECK (created_at >= 0 AND updated_at >= created_at),
    CONSTRAINT provider_alert_context_public CHECK (provider_public_json_safe(public_context))
);

CREATE INDEX provider_alert_active
    ON provider_alert (state, updated_at, alert_id);
