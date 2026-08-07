CREATE TABLE provider_ark_reserve_unit (
    reservation_id text COLLATE "C" PRIMARY KEY REFERENCES provider_reservation(reservation_id),
    reserve_unit text COLLATE "C" NOT NULL,
    protocol_family text COLLATE "C" NOT NULL,
    operator_identity_sha256 text COLLATE "C" NOT NULL,
    vtxo_txid text COLLATE "C" NOT NULL,
    vout integer NOT NULL,
    proof_sha256 text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL DEFAULT 'active',
    release_cause text COLLATE "C",
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT provider_ark_reserve_unit_family CHECK (
        protocol_family IN ('arkade', 'bark')
    ),
    CONSTRAINT provider_ark_reserve_unit_operator CHECK (
        operator_identity_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT provider_ark_reserve_unit_txid CHECK (vtxo_txid ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_ark_reserve_unit_vout CHECK (vout >= 0),
    CONSTRAINT provider_ark_reserve_unit_proof CHECK (proof_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT provider_ark_reserve_unit_identity CHECK (
        reserve_unit = 'ark:' || protocol_family || ':' || operator_identity_sha256
            || ':' || vtxo_txid || ':' || vout::text
    ),
    CONSTRAINT provider_ark_reserve_unit_state CHECK (
        state IN ('active', 'released', 'unresolved')
    ),
    CONSTRAINT provider_ark_reserve_unit_release CHECK (
        (state = 'active' AND release_cause IS NULL)
        OR (state <> 'active' AND release_cause IS NOT NULL)
    ),
    CONSTRAINT provider_ark_reserve_unit_time CHECK (
        created_at >= 0 AND updated_at >= created_at
    )
);

CREATE UNIQUE INDEX provider_ark_reserve_unit_blocking
    ON provider_ark_reserve_unit (reserve_unit)
    WHERE state IN ('active', 'unresolved');

CREATE INDEX provider_ark_reserve_unit_state
    ON provider_ark_reserve_unit (state, reserve_unit, reservation_id);
