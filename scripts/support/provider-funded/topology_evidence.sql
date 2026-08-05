\set ON_ERROR_STOP on

PREPARE funded_topology_evidence(text, text, text, text, text, text) AS
WITH requested(role, order_id) AS (
    VALUES
        ('selected', $1),
        ('unselected', $2)
),
resolved AS (
    SELECT
        requested.role,
        min(record.session_id) AS session_id,
        count(DISTINCT record.session_id)::integer AS matched_session_count
    FROM requested
    LEFT JOIN provider_session_record AS record
        ON record.event_id = requested.order_id
       AND record.kind = 39606
    GROUP BY requested.role
),
matched AS (
    SELECT * FROM resolved WHERE matched_session_count = 1
)
SELECT jsonb_build_object(
    'schema', 'openagents.immortal.lab-funded-topology-provider-db.v1',
    'matched_role_count', (SELECT count(*) FROM matched),
    'allocated_capacity', COALESCE((SELECT sum(allocated_capacity) FROM provider_capacity_bucket), 0),
    'roles', COALESCE((
        SELECT jsonb_object_agg(
            role,
            jsonb_build_object(
                'session_id', session_id,
                'disposition', COALESCE((
                    SELECT min(reason_code)
                    FROM provider_session_disposition
                    WHERE provider_session_disposition.session_id = matched.session_id
                ), ''),
                'reservation_total', (
                    SELECT count(*) FROM provider_reservation
                    WHERE provider_reservation.session_id = matched.session_id
                ),
                'reservation_released', (
                    SELECT count(*) FROM provider_reservation
                    WHERE provider_reservation.session_id = matched.session_id
                      AND state = 'released'
                ),
                'reservation_active', (
                    SELECT count(*) FROM provider_reservation
                    WHERE provider_reservation.session_id = matched.session_id
                      AND state = 'active'
                ),
                'reservation_unresolved', (
                    SELECT count(*) FROM provider_reservation
                    WHERE provider_reservation.session_id = matched.session_id
                      AND state = 'unresolved'
                ),
                'release_cause', COALESCE((
                    SELECT min(release_cause) FROM provider_reservation
                    WHERE provider_reservation.session_id = matched.session_id
                ), ''),
                'effect_total', (
                    SELECT count(*) FROM provider_effect
                    WHERE provider_effect.session_id = matched.session_id
                ),
                'effect_pending', (
                    SELECT count(*) FROM provider_effect
                    WHERE provider_effect.session_id = matched.session_id
                      AND state = 'pending'
                ),
                'effect_unresolved', (
                    SELECT count(*) FROM provider_effect
                    WHERE provider_effect.session_id = matched.session_id
                      AND state = 'unresolved'
                ),
                'watch_total', (
                    SELECT count(*) FROM provider_watch_job
                    WHERE provider_watch_job.session_id = matched.session_id
                ),
                'watch_pending', (
                    SELECT count(*) FROM provider_watch_job
                    WHERE provider_watch_job.session_id = matched.session_id
                      AND state IN ('pending', 'running')
                ),
                'watch_unresolved', (
                    SELECT count(*) FROM provider_watch_job
                    WHERE provider_watch_job.session_id = matched.session_id
                      AND state IN ('unresolved', 'page')
                ),
                'cancel_record_count', (
                    SELECT count(*) FROM provider_session_record
                    WHERE provider_session_record.session_id = matched.session_id
                      AND provider_session_record.event_id IN ($3, $4, $5, $6)
                )
            )
            ORDER BY role
        ) FROM matched
    ), '{}'::jsonb)
);

EXECUTE funded_topology_evidence(
    :'selected_order_id',
    :'unselected_order_id',
    :'cancel_request_id',
    :'cancel_accepted_id',
    :'cancel_effective_id',
    :'cancel_close_id'
);

DEALLOCATE funded_topology_evidence;
