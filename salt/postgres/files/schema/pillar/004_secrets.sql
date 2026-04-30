-- pgcrypto-backed secret storage for pillar_entry rows where is_secret = true.
-- The plaintext value is encrypted with a symmetric key held in a server-side
-- GUC (so_pillar.master_key) which is set per-role via ALTER ROLE so the key
-- never touches a flat file readable by Salt itself.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- Encrypt a JSONB value using the configured master key. Stored as a JSONB
-- envelope {"_enc": "<armored ciphertext>"} so the same column type is reused.
CREATE OR REPLACE FUNCTION so_pillar.fn_encrypt_jsonb(p_value jsonb)
RETURNS jsonb LANGUAGE plpgsql AS $fn$
DECLARE
    v_key text := current_setting('so_pillar.master_key', true);
BEGIN
    IF v_key IS NULL OR v_key = '' THEN
        RAISE EXCEPTION 'so_pillar.master_key GUC not configured';
    END IF;
    RETURN jsonb_build_object(
        '_enc',
        encode(pgp_sym_encrypt(p_value::text, v_key), 'base64')
    );
END
$fn$;

-- Decrypt the envelope produced by fn_encrypt_jsonb. SECURITY DEFINER so callers
-- with no direct access to pgcrypto/master_key can still pull plaintext via the
-- v_pillar_secrets view.
CREATE OR REPLACE FUNCTION so_pillar.fn_decrypt_jsonb(p_envelope jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER AS $fn$
DECLARE
    v_key text := current_setting('so_pillar.master_key', true);
    v_ct  text;
BEGIN
    IF v_key IS NULL OR v_key = '' THEN
        RAISE EXCEPTION 'so_pillar.master_key GUC not configured';
    END IF;
    v_ct := p_envelope->>'_enc';
    IF v_ct IS NULL THEN
        RETURN p_envelope;          -- not encrypted; pass through
    END IF;
    RETURN pgp_sym_decrypt(decode(v_ct, 'base64'), v_key)::jsonb;
END
$fn$;

REVOKE ALL ON FUNCTION so_pillar.fn_decrypt_jsonb(jsonb) FROM PUBLIC;

-- Secrets view consumed by ext_pillar. Decrypts at the boundary so Salt sees
-- plaintext JSONB. Filters the rows to those that apply to the requesting
-- minion via current_setting, since views can't take parameters and ext_pillar
-- can only bind one parameter per query.
--
-- Master-config query: SELECT data FROM so_pillar.v_pillar_secrets WHERE %s IS NOT NULL
-- The %s satisfies the bound parameter; the view itself reads the minion_id
-- from a session GUC set by a small wrapper function (see fn_pillar_secrets).
CREATE OR REPLACE FUNCTION so_pillar.fn_pillar_secrets(p_minion_id text)
RETURNS TABLE(data jsonb)
LANGUAGE sql STABLE SECURITY DEFINER AS $fn$
    SELECT so_pillar.fn_decrypt_jsonb(pe.data)
      FROM so_pillar.pillar_entry pe
     WHERE pe.is_secret = true
       AND ( pe.scope = 'global'
          OR (pe.scope = 'role'
              AND pe.role_name IN (
                  SELECT role_name FROM so_pillar.role_member
                   WHERE minion_id = p_minion_id))
          OR (pe.scope = 'minion' AND pe.minion_id = p_minion_id))
     ORDER BY pe.sort_key, pe.pillar_path;
$fn$;

-- Replace the placeholder view from 002 with a parameterised version. Master
-- config query becomes:
--   SELECT data FROM so_pillar.fn_pillar_secrets(%s) AS s
DROP VIEW IF EXISTS so_pillar.v_pillar_secrets;
CREATE OR REPLACE VIEW so_pillar.v_pillar_secrets AS
    SELECT NULL::text AS minion_id,
           NULL::text AS pillar_path,
           NULL::int  AS sort_key,
           '{}'::jsonb AS data
     WHERE false;
COMMENT ON VIEW so_pillar.v_pillar_secrets IS
    'Deprecated placeholder; use SELECT data FROM so_pillar.fn_pillar_secrets(minion_id) instead';

-- Convenience helper for so-yaml.py and the importer to set a secret without
-- ever exposing the master_key to the caller. SECURITY DEFINER means the
-- caller does not need read access to so_pillar.master_key.
CREATE OR REPLACE FUNCTION so_pillar.fn_set_secret(
    p_scope         text,
    p_role_name     text,
    p_minion_id     text,
    p_pillar_path   text,
    p_value         jsonb,
    p_change_reason text DEFAULT NULL
) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $fn$
DECLARE
    v_envelope jsonb := so_pillar.fn_encrypt_jsonb(p_value);
    v_id       bigint;
BEGIN
    PERFORM set_config('so_pillar.change_reason',
                       COALESCE(p_change_reason, 'fn_set_secret'),
                       true);

    INSERT INTO so_pillar.pillar_entry(
        scope, role_name, minion_id, pillar_path, data, is_secret, change_reason)
    VALUES (p_scope, p_role_name, p_minion_id, p_pillar_path, v_envelope, true, p_change_reason)
    ON CONFLICT (pillar_path) WHERE scope='global' DO UPDATE
       SET data = EXCLUDED.data, is_secret = true, change_reason = EXCLUDED.change_reason
       RETURNING id INTO v_id;

    IF v_id IS NULL THEN
        UPDATE so_pillar.pillar_entry
           SET data = v_envelope, is_secret = true, change_reason = p_change_reason
         WHERE scope = p_scope
           AND COALESCE(role_name,'') = COALESCE(p_role_name,'')
           AND COALESCE(minion_id,'') = COALESCE(p_minion_id,'')
           AND pillar_path = p_pillar_path
         RETURNING id INTO v_id;

        IF v_id IS NULL THEN
            INSERT INTO so_pillar.pillar_entry(
                scope, role_name, minion_id, pillar_path, data, is_secret, change_reason)
            VALUES (p_scope, p_role_name, p_minion_id, p_pillar_path, v_envelope, true, p_change_reason)
            RETURNING id INTO v_id;
        END IF;
    END IF;

    RETURN v_id;
END
$fn$;

REVOKE ALL ON FUNCTION so_pillar.fn_set_secret(text,text,text,text,jsonb,text) FROM PUBLIC;
