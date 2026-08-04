-- Optional MKT-SWP coordination claims. These rows contain signed-record
-- identifiers and bounded accounting metadata, never decrypted record bytes.

CREATE TABLE mkt_swp_reservation_claim (
    quote_event_id text COLLATE "C" PRIMARY KEY,
    wrap_event_id text COLLATE "C" NOT NULL,
    provider_pubkey text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    rfq_event_id text COLLATE "C" NOT NULL,
    reservation_id text COLLATE "C" NOT NULL,
    capacity_bucket_id text COLLATE "C",
    reserved_asset_id text COLLATE "C",
    reservation_class text COLLATE "C" NOT NULL,
    reserved_amount bigint NOT NULL,
    handler_committed_capacity bigint NOT NULL,
    allocation_sequence bigint,
    proof_class text COLLATE "C",
    proof_strength smallint NOT NULL,
    proof_ref_sha256 text COLLATE "C",
    reserve_unit_sha256 text COLLATE "C",
    capacity_commitment_sha256 text COLLATE "C",
    expires_at bigint,
    decision text COLLATE "C" NOT NULL,
    active boolean NOT NULL,
    released_at bigint,
    release_reason text COLLATE "C",
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT mkt_swp_reservation_quote_shape CHECK (quote_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_wrap_shape CHECK (wrap_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_provider_shape CHECK (provider_pubkey ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_session_shape CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_rfq_shape CHECK (rfq_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_id_shape CHECK (reservation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_reservation_bucket_shape CHECK (
        capacity_bucket_id IS NULL
        OR capacity_bucket_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT mkt_swp_reservation_asset_shape CHECK (
        reserved_asset_id IS NULL
        OR reserved_asset_id ~ '^swp:1:bip122:[0-9a-f]{32}:btc:(chain|lightning)$'
    ),
    CONSTRAINT mkt_swp_reservation_class CHECK (reservation_class IN ('none', 'soft', 'hard')),
    CONSTRAINT mkt_swp_reservation_amount_bounds CHECK (
        reserved_amount >= 0 AND handler_committed_capacity >= 0
        AND reserved_amount <= handler_committed_capacity
    ),
    CONSTRAINT mkt_swp_reservation_sequence_bounds CHECK (
        allocation_sequence IS NULL OR allocation_sequence >= 0
    ),
    CONSTRAINT mkt_swp_reservation_expiration_bounds CHECK (
        expires_at IS NULL OR expires_at >= 0
    ),
    CONSTRAINT mkt_swp_reservation_proof_class CHECK (
        proof_class IS NULL OR proof_class IN (
            'provider_signed', 'handler_accounted', 'utxo_control',
            'lightning_liquidity', 'funded_htlc', 'covenant_reserve',
            'third_party_guarantee'
        )
    ),
    CONSTRAINT mkt_swp_reservation_proof_strength_bounds CHECK (
        (proof_class IS NULL AND proof_strength = 0)
        OR (proof_class = 'provider_signed' AND proof_strength = 10)
        OR (proof_class = 'handler_accounted' AND proof_strength = 20)
        OR (proof_class = 'third_party_guarantee' AND proof_strength = 40)
        OR (proof_class = 'lightning_liquidity' AND proof_strength = 50)
        OR (proof_class = 'utxo_control' AND proof_strength = 60)
        OR (proof_class = 'funded_htlc' AND proof_strength = 80)
        OR (proof_class = 'covenant_reserve' AND proof_strength = 100)
    ),
    CONSTRAINT mkt_swp_reservation_proof_ref_shape CHECK (
        proof_ref_sha256 IS NULL OR proof_ref_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT mkt_swp_reservation_reserve_unit_shape CHECK (
        (
            proof_class = 'covenant_reserve'
            AND reserve_unit_sha256 IS NOT NULL
            AND reserve_unit_sha256 ~ '^[0-9a-f]{64}$'
        )
        OR (proof_class IS DISTINCT FROM 'covenant_reserve' AND reserve_unit_sha256 IS NULL)
    ),
    CONSTRAINT mkt_swp_reservation_commitment_shape CHECK (
        capacity_commitment_sha256 IS NULL
        OR capacity_commitment_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT mkt_swp_reservation_decision CHECK (decision IN (
        'mkt_swp_reservation_none', 'mkt_swp_reservation_active',
        'swp_reservation_expired', 'swp_reservation_overallocated',
        'swp_reservation_fork', 'swp_idempotency_conflict',
        'swp_reservation_proof_invalid',
        'swp_covenant_reserve_invalid'
    )),
    CONSTRAINT mkt_swp_reservation_release_shape CHECK (
        (active AND released_at IS NULL AND release_reason IS NULL)
        OR (
            NOT active
            AND (
                (released_at IS NULL AND release_reason IS NULL)
                OR (released_at >= 0 AND release_reason = 'expired')
            )
        )
    ),
    CONSTRAINT mkt_swp_reservation_active_decision CHECK (
        (
            decision = 'mkt_swp_reservation_active'
            AND (
                active
                OR (
                    NOT active AND released_at IS NOT NULL
                    AND release_reason = 'expired'
                )
            )
        )
        OR (decision <> 'mkt_swp_reservation_active' AND NOT active)
    ),
    CONSTRAINT mkt_swp_reservation_none_shape CHECK (
        reservation_class <> 'none'
        OR (
            capacity_bucket_id IS NULL AND reserved_asset_id IS NULL
            AND reserved_amount = 0 AND handler_committed_capacity = 0
            AND allocation_sequence IS NULL AND proof_class IS NULL
            AND proof_strength = 0 AND proof_ref_sha256 IS NULL
            AND reserve_unit_sha256 IS NULL
            AND capacity_commitment_sha256 IS NULL AND expires_at IS NULL
            AND NOT active
        )
    ),
    CONSTRAINT mkt_swp_reservation_active_shape CHECK (
        reservation_class = 'none'
        OR (
            capacity_bucket_id IS NOT NULL AND reserved_asset_id IS NOT NULL
            AND reserved_amount > 0 AND handler_committed_capacity > 0
            AND allocation_sequence IS NOT NULL AND proof_class IS NOT NULL
            AND proof_strength > 0 AND proof_ref_sha256 IS NOT NULL
            AND capacity_commitment_sha256 IS NOT NULL AND expires_at IS NOT NULL
        )
    )
);

CREATE INDEX mkt_swp_reservation_active_bucket_idx
    ON mkt_swp_reservation_claim (
        provider_pubkey, capacity_bucket_id, reserved_asset_id, expires_at
    )
    WHERE active;
CREATE INDEX mkt_swp_reservation_sequence_idx
    ON mkt_swp_reservation_claim (
        provider_pubkey, capacity_bucket_id, allocation_sequence
    );
CREATE INDEX mkt_swp_reservation_id_idx
    ON mkt_swp_reservation_claim (provider_pubkey, reservation_id);
CREATE INDEX mkt_swp_reservation_proof_idx
    ON mkt_swp_reservation_claim (provider_pubkey, proof_class, proof_ref_sha256)
    WHERE active;
CREATE INDEX mkt_swp_reservation_reserve_unit_idx
    ON mkt_swp_reservation_claim (reserve_unit_sha256)
    WHERE active AND proof_class = 'covenant_reserve';

CREATE TABLE mkt_swp_status_claim (
    status_event_id text COLLATE "C" PRIMARY KEY,
    wrap_event_id text COLLATE "C" NOT NULL,
    author_pubkey text COLLATE "C" NOT NULL,
    author_role text COLLATE "C" NOT NULL,
    counterparty_pubkey text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    order_event_id text COLLATE "C" NOT NULL,
    sequence bigint NOT NULL,
    previous_event_id text COLLATE "C",
    state text COLLATE "C" NOT NULL,
    swp_state text COLLATE "C" NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT mkt_swp_status_event_shape CHECK (status_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_wrap_shape CHECK (wrap_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_author_shape CHECK (author_pubkey ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_role CHECK (author_role IN ('requester', 'provider')),
    CONSTRAINT mkt_swp_status_counterparty_shape CHECK (counterparty_pubkey ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_distinct_parties CHECK (author_pubkey <> counterparty_pubkey),
    CONSTRAINT mkt_swp_status_session_shape CHECK (session_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_order_shape CHECK (order_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_status_sequence_bounds CHECK (sequence BETWEEN 0 AND 4095),
    CONSTRAINT mkt_swp_status_previous_shape CHECK (
        (sequence = 0 AND previous_event_id IS NULL)
        OR (sequence > 0 AND previous_event_id ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT mkt_swp_status_state_bound CHECK (
        state ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
        AND swp_state ~ '^[a-z0-9][a-z0-9._-]{0,95}$'
    )
);

CREATE INDEX mkt_swp_status_stream_idx
    ON mkt_swp_status_claim (
        session_id, order_event_id, author_pubkey, sequence, status_event_id
    );

CREATE TABLE mkt_swp_evidence_observation (
    source_event_id text COLLATE "C" NOT NULL,
    artifact_sha256 text COLLATE "C" NOT NULL,
    observation_event_id text COLLATE "C" NOT NULL UNIQUE,
    evidence_class text COLLATE "C" NOT NULL,
    rail_reference text COLLATE "C" NOT NULL,
    view_sha256 text COLLATE "C" NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (source_event_id, artifact_sha256),
    CONSTRAINT mkt_swp_observation_source_shape CHECK (source_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_observation_artifact_shape CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_observation_event_shape CHECK (observation_event_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mkt_swp_observation_class CHECK (evidence_class = 'bitcoin_transaction'),
    CONSTRAINT mkt_swp_observation_reference_bound CHECK (
        rail_reference ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT mkt_swp_observation_view_shape CHECK (view_sha256 ~ '^[0-9a-f]{64}$')
);
