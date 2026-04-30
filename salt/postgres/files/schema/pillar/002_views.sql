-- Views consumed by the Salt master's salt.pillar.postgres ext_pillar with
-- as_json=True. Each view exposes data ordered by (sort_key, pillar_path) so
-- the deep-merge in ext_pillar resolves precedence deterministically.
--
-- ext_pillar always binds exactly one parameter to the query: (minion_id,).
-- Master-config queries reference these views and add WHERE clauses, e.g.:
--   SELECT data FROM so_pillar.v_pillar_role WHERE minion_id = %s
--   SELECT data FROM so_pillar.v_pillar_minion WHERE minion_id = %s
-- For v_pillar_global the binding is satisfied with `WHERE %s IS NOT NULL`.

CREATE OR REPLACE VIEW so_pillar.v_pillar_global AS
    SELECT pillar_path, sort_key, data
      FROM so_pillar.pillar_entry
     WHERE scope = 'global'
       AND is_secret = false
     ORDER BY sort_key, pillar_path;

-- Role view exposes minion_id so the master-config WHERE clause can filter to
-- the rows that apply to the requesting minion. JOIN to role_member fans out
-- one row per (role assignment, pillar entry) tuple.
CREATE OR REPLACE VIEW so_pillar.v_pillar_role AS
    SELECT rm.minion_id,
           pe.role_name,
           pe.pillar_path,
           pe.sort_key,
           pe.data
      FROM so_pillar.pillar_entry pe
      JOIN so_pillar.role_member rm ON rm.role_name = pe.role_name
     WHERE pe.scope = 'role'
       AND pe.is_secret = false;

CREATE OR REPLACE VIEW so_pillar.v_pillar_minion AS
    SELECT minion_id,
           pillar_path,
           sort_key,
           data
      FROM so_pillar.pillar_entry
     WHERE scope = 'minion'
       AND is_secret = false;

-- v_pillar_secrets is filled in by 004_secrets.sql once pgcrypto is available;
-- placeholder here returns no rows so initial schema deploy succeeds even on a
-- container that has not yet loaded pgcrypto.
CREATE OR REPLACE VIEW so_pillar.v_pillar_secrets AS
    SELECT NULL::text AS minion_id,
           NULL::text AS pillar_path,
           NULL::int  AS sort_key,
           '{}'::jsonb AS data
     WHERE false;
