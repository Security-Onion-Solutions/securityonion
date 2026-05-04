-- Roles + Row-Level Security policies for the so_pillar schema.
-- Three roles:
--   so_pillar_master         — connected by salt-master ext_pillar. Read-only.
--                              RLS forces it to skip is_secret rows; reads
--                              encrypted secrets only via fn_pillar_secrets().
--   so_pillar_writer         — connected by so-yaml dual-write and the SOC
--                              PostgresConfigstore. Read+write on pillar_entry,
--                              minion, role_member.
--   so_pillar_secret_owner   — owns the master encryption key GUC; sole role
--                              allowed to call fn_set_secret directly. Other
--                              writers reach this function only via grants.
--
-- The existing app role so_postgres_user (created by init-users.sh) is granted
-- INTO so_pillar_writer so SOC keeps using its existing connection but inherits
-- pillar-write capability.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'so_pillar_master') THEN
        CREATE ROLE so_pillar_master NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'so_pillar_writer') THEN
        CREATE ROLE so_pillar_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'so_pillar_secret_owner') THEN
        CREATE ROLE so_pillar_secret_owner NOLOGIN;
    END IF;
END
$$;

-- USAGE on the schema is the bare minimum needed to reference its tables.
-- CONNECT on the database is needed before the role can establish a session
-- at all (default privileges on a new DB grant CONNECT to PUBLIC, but if the
-- securityonion database is restricted that grant has to be explicit).
-- Password + LOGIN privileges are set later in schema_pillar.sls because
-- the password lives in pillar (secrets:pillar_master_pass) and plain SQL
-- can't substitute pillar values.
GRANT CONNECT ON DATABASE securityonion TO so_pillar_master, so_pillar_writer, so_pillar_secret_owner;
GRANT USAGE ON SCHEMA so_pillar TO so_pillar_master, so_pillar_writer, so_pillar_secret_owner;

-- Read access for ext_pillar through the views only.
GRANT SELECT ON so_pillar.v_pillar_global,
                so_pillar.v_pillar_role,
                so_pillar.v_pillar_minion
    TO so_pillar_master;
GRANT EXECUTE ON FUNCTION so_pillar.fn_pillar_secrets(text) TO so_pillar_master;

-- (change_queue grants live in 008_change_notify.sql alongside the table itself,
-- since the table doesn't exist until 008 runs.)

-- Writer needs CRUD on pillar_entry/minion/role_member plus access to seed tables.
GRANT SELECT, INSERT, UPDATE, DELETE
    ON so_pillar.pillar_entry,
       so_pillar.minion,
       so_pillar.role_member
    TO so_pillar_writer;
GRANT SELECT ON so_pillar.role, so_pillar.scope TO so_pillar_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON so_pillar.drift_log TO so_pillar_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA so_pillar TO so_pillar_writer;
GRANT SELECT ON so_pillar.pillar_entry_history TO so_pillar_writer;

-- Secret owner can call fn_set_secret directly; writer goes through it via the
-- function's SECURITY DEFINER attribute, which executes as the function owner.
GRANT EXECUTE ON FUNCTION so_pillar.fn_set_secret(text,text,text,text,jsonb,text)
    TO so_pillar_writer, so_pillar_secret_owner;

-- so_postgres_user (SOC's existing app user, created by init-users.sh) inherits
-- writer privilege so the PostgresConfigstore in SOC can mutate pillars without
-- a second connection pool. Inheritance is per-PG default (NOINHERIT must be
-- explicit), so this just works.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_setting('so_pillar.app_role', true))
    THEN
        EXECUTE format('GRANT so_pillar_writer TO %I',
                       current_setting('so_pillar.app_role', true));
    ELSIF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'so_postgres_user') THEN
        GRANT so_pillar_writer TO so_postgres_user;
    END IF;
END
$$;

-- RLS on pillar_entry: master sees only non-secret rows. Writer sees all
-- (it must, to UPDATE secret rows when so-yaml replaces them). Secret rows
-- still require fn_decrypt_jsonb to read plaintext.
ALTER TABLE so_pillar.pillar_entry ENABLE ROW LEVEL SECURITY;
ALTER TABLE so_pillar.pillar_entry FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pillar_entry_master_read    ON so_pillar.pillar_entry;
DROP POLICY IF EXISTS pillar_entry_writer_all     ON so_pillar.pillar_entry;
DROP POLICY IF EXISTS pillar_entry_owner_all      ON so_pillar.pillar_entry;

CREATE POLICY pillar_entry_master_read ON so_pillar.pillar_entry
    FOR SELECT TO so_pillar_master
    USING (NOT is_secret);

CREATE POLICY pillar_entry_writer_all ON so_pillar.pillar_entry
    FOR ALL TO so_pillar_writer
    USING (true)
    WITH CHECK (true);

CREATE POLICY pillar_entry_owner_all ON so_pillar.pillar_entry
    FOR ALL TO so_pillar_secret_owner
    USING (true)
    WITH CHECK (true);

-- minion / role_member do not need RLS — they hold no secrets.
