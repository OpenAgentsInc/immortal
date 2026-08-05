\set ON_ERROR_STOP on

PREPARE funded_smoke_durable_evidence(text, text, text, integer) AS
WITH requested(journey_name, order_id) AS (
    VALUES
        ('submarine', $1),
        ('reverse', $2),
        ('reverse_refund', $3)
),
resolved AS (
    SELECT
        requested.journey_name,
        CASE
            WHEN count(DISTINCT record.session_id) = 1
                THEN min(record.session_id)
            ELSE NULL
        END AS session_id,
        count(DISTINCT record.session_id)::integer AS matched_session_count
    FROM requested
    LEFT JOIN provider_session_record AS record
        ON record.event_id = requested.order_id
       AND record.kind = 39606
    GROUP BY requested.journey_name
),
journey_rows AS (
    SELECT
        resolved.journey_name,
        jsonb_build_object(
            'matched_session_count', resolved.matched_session_count,
            'session_disposition', COALESCE((
                SELECT min(disposition.reason_code)
                FROM provider_session_disposition AS disposition
                WHERE disposition.session_id = resolved.session_id
            ), ''),
            'reservations', jsonb_build_object(
                'total', (
                    SELECT count(*)
                    FROM provider_reservation AS reservation
                    WHERE reservation.session_id = resolved.session_id
                ),
                'terminal', (
                    SELECT count(*)
                    FROM provider_reservation AS reservation
                    WHERE reservation.session_id = resolved.session_id
                      AND reservation.state = 'released'
                      AND reservation.release_cause = 'terminal_close'
                ),
                'pending', (
                    SELECT count(*)
                    FROM provider_reservation AS reservation
                    WHERE reservation.session_id = resolved.session_id
                      AND reservation.state = 'active'
                ),
                'unresolved', (
                    SELECT count(*)
                    FROM provider_reservation AS reservation
                    WHERE reservation.session_id = resolved.session_id
                      AND reservation.state = 'unresolved'
                )
            ),
            'effects', jsonb_build_object(
                'total', (
                    SELECT count(*)
                    FROM provider_effect AS effect
                    WHERE effect.session_id = resolved.session_id
                ),
                'terminal', (
                    SELECT count(*)
                    FROM provider_effect AS effect
                    WHERE effect.session_id = resolved.session_id
                      AND effect.state = 'applied'
                ),
                'pending', (
                    SELECT count(*)
                    FROM provider_effect AS effect
                    WHERE effect.session_id = resolved.session_id
                      AND effect.state = 'pending'
                ),
                'unresolved', (
                    SELECT count(*)
                    FROM provider_effect AS effect
                    WHERE effect.session_id = resolved.session_id
                      AND effect.state = 'unresolved'
                )
            )
        ) AS evidence
    FROM resolved
),
watch_rows AS (
    SELECT
        resolved.journey_name,
        jsonb_build_object(
            'job_kind', 'refund_broadcast',
            'total', count(watch.job_id),
            'completed', count(watch.job_id) FILTER (WHERE watch.state = 'completed'),
            'confirmed', count(watch.job_id) FILTER (WHERE watch.state = 'confirmed'),
            'pending', count(watch.job_id) FILTER (
                WHERE watch.state IN ('pending', 'running')
            ),
            'unresolved', count(watch.job_id) FILTER (
                WHERE watch.state IN ('unresolved', 'page')
            ),
            'disposition', COALESCE(min(watch.last_chain_event), ''),
            'confirmations', COALESCE(min(watch.confirmations), 0)
        ) AS evidence
    FROM resolved
    LEFT JOIN provider_watch_job AS watch
        ON watch.session_id = resolved.session_id
       AND watch.job_kind = 'refund_broadcast'
    WHERE resolved.journey_name IN ('reverse', 'reverse_refund')
    GROUP BY resolved.journey_name
),
selected_sessions AS (
    SELECT DISTINCT session_id
    FROM resolved
    WHERE session_id IS NOT NULL
)
SELECT jsonb_build_object(
    'schema', 'openagents.immortal.provider-funded-smoke-durable-evidence.v1',
    'terminal_confirmations', $4,
    'session_summary', jsonb_build_object(
        'selected', (SELECT count(*) FROM resolved WHERE session_id IS NOT NULL),
        'distinct', (SELECT count(*) FROM selected_sessions),
        'terminal', (
            SELECT count(*)
            FROM selected_sessions AS selected
            JOIN provider_session_disposition AS disposition
                ON disposition.session_id = selected.session_id
        ),
        'pending', (
            SELECT count(*)
            FROM selected_sessions AS selected
            LEFT JOIN provider_session_disposition AS disposition
                ON disposition.session_id = selected.session_id
            WHERE disposition.session_id IS NULL
        ),
        'unresolved', (
            SELECT count(*)
            FROM selected_sessions AS selected
            JOIN provider_session_disposition AS disposition
                ON disposition.session_id = selected.session_id
            WHERE disposition.reason_code LIKE '%unresolved%'
        )
    ),
    'journeys', (
        SELECT jsonb_object_agg(journey_name, evidence ORDER BY journey_name)
        FROM journey_rows
    ),
    'watches', (
        SELECT jsonb_object_agg(journey_name, evidence ORDER BY journey_name)
        FROM watch_rows
    )
);

EXECUTE funded_smoke_durable_evidence(
    :'submarine_order_id',
    :'reverse_order_id',
    :'reverse_refund_order_id',
    :'terminal_confirmations'
);

DEALLOCATE funded_smoke_durable_evidence;
