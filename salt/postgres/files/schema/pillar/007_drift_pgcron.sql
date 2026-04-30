-- Drift detection + retention via pg_cron. Optional — the schema_pillar.sls
-- state guards this file behind the postgres:so_pillar:drift_check_enabled
-- pillar flag because pg_cron may not be loaded on every install.

CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Retention: trim pillar_entry_history older than a year. Adjustable via the
-- so_pillar.history_retention_days GUC (default 365 if unset).
CREATE OR REPLACE FUNCTION so_pillar.fn_history_retain()
RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE
    v_days int := COALESCE(current_setting('so_pillar.history_retention_days', true)::int, 365);
BEGIN
    DELETE FROM so_pillar.pillar_entry_history
     WHERE changed_at < (now() - (v_days::text || ' days')::interval);
END
$fn$;

-- Drift retention: keep two weeks of drift_log.
CREATE OR REPLACE FUNCTION so_pillar.fn_drift_retain()
RETURNS void LANGUAGE plpgsql AS $fn$
BEGIN
    DELETE FROM so_pillar.drift_log
     WHERE detected_at < (now() - interval '14 days');
END
$fn$;

-- pg_cron schedules (idempotent — unschedule any existing same-named job first).
DO $$
DECLARE
    v_jobid bigint;
BEGIN
    SELECT jobid INTO v_jobid FROM cron.job WHERE jobname = 'so_pillar_history_retain';
    IF v_jobid IS NOT NULL THEN PERFORM cron.unschedule(v_jobid); END IF;
    PERFORM cron.schedule('so_pillar_history_retain', '15 3 * * *',
                          'SELECT so_pillar.fn_history_retain();');

    SELECT jobid INTO v_jobid FROM cron.job WHERE jobname = 'so_pillar_drift_retain';
    IF v_jobid IS NOT NULL THEN PERFORM cron.unschedule(v_jobid); END IF;
    PERFORM cron.schedule('so_pillar_drift_retain', '20 3 * * *',
                          'SELECT so_pillar.fn_drift_retain();');
END
$$;
