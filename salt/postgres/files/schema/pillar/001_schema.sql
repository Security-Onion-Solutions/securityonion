-- so_pillar schema: queryable, versioned, audited pillar config store.
-- Replaces flat-file Salt pillar consumed via salt.pillar.postgres ext_pillar.
-- Idempotent. Run via salt/postgres/schema_pillar.sls inside the so-postgres container.

CREATE SCHEMA IF NOT EXISTS so_pillar;

CREATE TABLE IF NOT EXISTS so_pillar.scope (
    scope_kind   text PRIMARY KEY,
    precedence   int  NOT NULL,
    description  text
);

INSERT INTO so_pillar.scope(scope_kind, precedence, description) VALUES
    ('global', 100, 'Applies to every minion'),
    ('role',   200, 'Applies to minions whose minion_id matches a top.sls compound role match'),
    ('minion', 300, 'Applies only to a single minion (per-minion overlay)')
ON CONFLICT (scope_kind) DO NOTHING;

CREATE TABLE IF NOT EXISTS so_pillar.role (
    role_name      text PRIMARY KEY,
    match_kind     text NOT NULL CHECK (match_kind IN ('compound','grain','glob','list')),
    match_expr     text NOT NULL,
    description    text
);

CREATE TABLE IF NOT EXISTS so_pillar.minion (
    minion_id     text PRIMARY KEY,
    node_type     text,
    hostname      text,
    extra_roles   text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS so_pillar.role_member (
    role_name   text NOT NULL REFERENCES so_pillar.role(role_name) ON DELETE CASCADE,
    minion_id   text NOT NULL REFERENCES so_pillar.minion(minion_id) ON DELETE CASCADE,
    source      text NOT NULL DEFAULT 'computed' CHECK (source IN ('computed','manual','imported')),
    PRIMARY KEY (role_name, minion_id)
);

CREATE INDEX IF NOT EXISTS ix_role_member_minion ON so_pillar.role_member(minion_id);

-- pillar_entry holds the actual data. as_json=True ext_pillar reads `data` directly.
CREATE TABLE IF NOT EXISTS so_pillar.pillar_entry (
    id              bigserial PRIMARY KEY,
    scope           text NOT NULL REFERENCES so_pillar.scope(scope_kind),
    role_name       text REFERENCES so_pillar.role(role_name) ON DELETE CASCADE,
    minion_id       text REFERENCES so_pillar.minion(minion_id) ON DELETE CASCADE,
    pillar_path     text NOT NULL,
    data            jsonb NOT NULL,
    is_secret       boolean NOT NULL DEFAULT false,
    sort_key        int NOT NULL DEFAULT 0,
    version         int NOT NULL DEFAULT 1,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text NOT NULL DEFAULT current_user,
    change_reason   text,
    CONSTRAINT pillar_entry_scope_target CHECK (
           (scope='global' AND role_name IS NULL AND minion_id IS NULL)
        OR (scope='role'   AND role_name IS NOT NULL AND minion_id IS NULL)
        OR (scope='minion' AND role_name IS NULL AND minion_id IS NOT NULL)
    ),
    -- Reserved namespaces that MUST stay rendered from SLS (mine-driven). Nothing
    -- under these prefixes is allowed in the database; the merge logic relies on
    -- ext_pillar leaving these subtrees alone.
    CONSTRAINT pillar_entry_reserved_paths CHECK (
        pillar_path NOT LIKE 'elasticsearch.nodes%'
        AND pillar_path NOT LIKE 'redis.nodes%'
        AND pillar_path NOT LIKE 'kafka.nodes%'
        AND pillar_path NOT LIKE 'hypervisor.nodes%'
        AND pillar_path NOT LIKE 'logstash.nodes%'
        AND pillar_path NOT LIKE 'node_data.ips%'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_pillar_entry_global ON so_pillar.pillar_entry(pillar_path)
    WHERE scope = 'global';
CREATE UNIQUE INDEX IF NOT EXISTS ux_pillar_entry_role ON so_pillar.pillar_entry(role_name, pillar_path)
    WHERE scope = 'role';
CREATE UNIQUE INDEX IF NOT EXISTS ux_pillar_entry_minion ON so_pillar.pillar_entry(minion_id, pillar_path)
    WHERE scope = 'minion';

CREATE INDEX IF NOT EXISTS ix_pillar_entry_minion_hot ON so_pillar.pillar_entry(minion_id)
    WHERE scope = 'minion';
CREATE INDEX IF NOT EXISTS ix_pillar_entry_role_hot ON so_pillar.pillar_entry(role_name)
    WHERE scope = 'role';

-- Append-only audit log for every change to pillar_entry. No FK to entry so DELETE
-- history survives the row removal.
CREATE TABLE IF NOT EXISTS so_pillar.pillar_entry_history (
    history_id     bigserial PRIMARY KEY,
    entry_id       bigint,
    op             text NOT NULL CHECK (op IN ('INSERT','UPDATE','DELETE')),
    scope          text NOT NULL,
    role_name      text,
    minion_id      text,
    pillar_path    text NOT NULL,
    old_data       jsonb,
    new_data       jsonb,
    is_secret      boolean,
    version        int,
    changed_at     timestamptz NOT NULL DEFAULT now(),
    changed_by     text NOT NULL DEFAULT current_user,
    change_reason  text
);

CREATE INDEX IF NOT EXISTS ix_pillar_history_entry  ON so_pillar.pillar_entry_history(entry_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS ix_pillar_history_minion ON so_pillar.pillar_entry_history(minion_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS ix_pillar_history_role   ON so_pillar.pillar_entry_history(role_name,  changed_at DESC);

-- Drift watch — populated by a pg_cron job that re-renders the on-disk SLS files
-- and compares them to pillar_entry. Cleared once cutover completes.
CREATE TABLE IF NOT EXISTS so_pillar.drift_log (
    id              bigserial PRIMARY KEY,
    scope           text NOT NULL,
    role_name       text,
    minion_id       text,
    pillar_path     text NOT NULL,
    disk_data       jsonb,
    db_data         jsonb,
    detected_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_drift_log_detected ON so_pillar.drift_log(detected_at DESC);
