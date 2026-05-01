-- pg_notify-driven change fan-out for so_pillar.pillar_entry.
--
-- Two layers:
--   1. so_pillar.change_queue          — durable, drained by the salt-master
--                                        engine. Survives engine downtime,
--                                        de-duplicated by id, processed once.
--   2. pg_notify('so_pillar_change')   — wakeup signal. Payload is the
--                                        change_queue row id and locator
--                                        (no secret data — channels are
--                                        snoopable by anyone with LISTEN).
--
-- The salt-master engine LISTENs on the channel for low-latency wakeup,
-- then SELECTs unprocessed change_queue rows so a missed notification
-- (engine restart, network blip) self-heals on the next event.

CREATE TABLE IF NOT EXISTS so_pillar.change_queue (
    id            bigserial PRIMARY KEY,
    scope         text        NOT NULL,
    role_name     text,
    minion_id     text,
    pillar_path   text        NOT NULL,
    op            text        NOT NULL CHECK (op IN ('INSERT','UPDATE','DELETE')),
    enqueued_at   timestamptz NOT NULL DEFAULT now(),
    processed_at  timestamptz
);

-- Hot index for the engine's drain query.
CREATE INDEX IF NOT EXISTS ix_change_queue_unprocessed
    ON so_pillar.change_queue (id)
    WHERE processed_at IS NULL;

-- Retention index: pg_cron job in 007 sweeps processed rows older than 7d.
CREATE INDEX IF NOT EXISTS ix_change_queue_processed_at
    ON so_pillar.change_queue (processed_at)
    WHERE processed_at IS NOT NULL;

CREATE OR REPLACE FUNCTION so_pillar.fn_pillar_entry_notify()
    RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    v_row record;
    v_id  bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := OLD;
    ELSE
        v_row := NEW;
    END IF;

    INSERT INTO so_pillar.change_queue
        (scope, role_name, minion_id, pillar_path, op)
    VALUES
        (v_row.scope, v_row.role_name, v_row.minion_id, v_row.pillar_path, TG_OP)
    RETURNING id INTO v_id;

    -- Payload is the queue id + locator only. Engine joins back to
    -- pillar_entry if it needs the data — keeps secrets off the wire.
    PERFORM pg_notify('so_pillar_change', json_build_object(
        'queue_id',    v_id,
        'scope',       v_row.scope,
        'role_name',   v_row.role_name,
        'minion_id',   v_row.minion_id,
        'pillar_path', v_row.pillar_path,
        'op',          TG_OP
    )::text);

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tg_pillar_entry_notify ON so_pillar.pillar_entry;
CREATE TRIGGER tg_pillar_entry_notify
    AFTER INSERT OR UPDATE OR DELETE
    ON so_pillar.pillar_entry
    FOR EACH ROW
    EXECUTE FUNCTION so_pillar.fn_pillar_entry_notify();
