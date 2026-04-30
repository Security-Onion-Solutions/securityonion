-- Audit trigger: every INSERT/UPDATE/DELETE on so_pillar.pillar_entry writes a
-- row to pillar_entry_history. Captures the actor (current_user), reason
-- (passed via SET LOCAL so_pillar.change_reason), and full before/after data.

CREATE OR REPLACE FUNCTION so_pillar.fn_pillar_entry_audit() RETURNS trigger
LANGUAGE plpgsql AS $fn$
DECLARE
    v_reason text := current_setting('so_pillar.change_reason', true);
BEGIN
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO so_pillar.pillar_entry_history(
            entry_id, op, scope, role_name, minion_id, pillar_path,
            old_data, new_data, is_secret, version, changed_by, change_reason)
        VALUES (NEW.id, 'INSERT', NEW.scope, NEW.role_name, NEW.minion_id, NEW.pillar_path,
                NULL, NEW.data, NEW.is_secret, NEW.version, NEW.updated_by, v_reason);
        RETURN NEW;
    ELSIF (TG_OP = 'UPDATE') THEN
        IF OLD.data IS DISTINCT FROM NEW.data
           OR OLD.is_secret IS DISTINCT FROM NEW.is_secret THEN
            INSERT INTO so_pillar.pillar_entry_history(
                entry_id, op, scope, role_name, minion_id, pillar_path,
                old_data, new_data, is_secret, version, changed_by, change_reason)
            VALUES (NEW.id, 'UPDATE', NEW.scope, NEW.role_name, NEW.minion_id, NEW.pillar_path,
                    OLD.data, NEW.data, NEW.is_secret, NEW.version, NEW.updated_by, v_reason);
        END IF;
        RETURN NEW;
    ELSIF (TG_OP = 'DELETE') THEN
        INSERT INTO so_pillar.pillar_entry_history(
            entry_id, op, scope, role_name, minion_id, pillar_path,
            old_data, new_data, is_secret, version, changed_by, change_reason)
        VALUES (OLD.id, 'DELETE', OLD.scope, OLD.role_name, OLD.minion_id, OLD.pillar_path,
                OLD.data, NULL, OLD.is_secret, OLD.version, current_user, v_reason);
        RETURN OLD;
    END IF;
    RETURN NULL;
END
$fn$;

DROP TRIGGER IF EXISTS pillar_entry_audit ON so_pillar.pillar_entry;
CREATE TRIGGER pillar_entry_audit
    AFTER INSERT OR UPDATE OR DELETE ON so_pillar.pillar_entry
    FOR EACH ROW EXECUTE FUNCTION so_pillar.fn_pillar_entry_audit();

-- updated_at + version maintenance: bump version on every UPDATE that changes data.
CREATE OR REPLACE FUNCTION so_pillar.fn_pillar_entry_versioning() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF (TG_OP = 'UPDATE') THEN
        IF OLD.data IS DISTINCT FROM NEW.data
           OR OLD.is_secret IS DISTINCT FROM NEW.is_secret THEN
            NEW.version := OLD.version + 1;
            NEW.updated_at := now();
        ELSE
            NEW.version := OLD.version;
            NEW.updated_at := OLD.updated_at;
        END IF;
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS pillar_entry_versioning ON so_pillar.pillar_entry;
CREATE TRIGGER pillar_entry_versioning
    BEFORE UPDATE ON so_pillar.pillar_entry
    FOR EACH ROW EXECUTE FUNCTION so_pillar.fn_pillar_entry_versioning();

-- Recompute role_member rows for a minion based on node_type.
-- Compound matchers in pillar/top.sls are pure suffix patterns of the form
-- '*_<rolename>' plus the special multi-role 'manager/managersearch/managerhype'
-- bucket. node_type is split on common dashes/underscores; any token that
-- matches a known role_name produces a role_member row.
CREATE OR REPLACE FUNCTION so_pillar.fn_recompute_role_members(p_minion_id text)
RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE
    v_node_type text;
    v_extra     text[];
    v_role      text;
BEGIN
    SELECT node_type, extra_roles INTO v_node_type, v_extra
      FROM so_pillar.minion WHERE minion_id = p_minion_id;

    IF v_node_type IS NULL THEN
        RETURN;
    END IF;

    DELETE FROM so_pillar.role_member
     WHERE minion_id = p_minion_id AND source = 'computed';

    -- Main role from node_type.
    IF EXISTS (SELECT 1 FROM so_pillar.role WHERE role_name = lower(v_node_type)) THEN
        INSERT INTO so_pillar.role_member(role_name, minion_id, source)
        VALUES (lower(v_node_type), p_minion_id, 'computed')
        ON CONFLICT DO NOTHING;
    END IF;

    -- Extra roles supplied by the importer / reactor for compound matchers
    -- that need to apply multiple buckets (e.g. managersearch also gets the
    -- 'manager' bucket per top.sls line 36 grouping).
    FOREACH v_role IN ARRAY COALESCE(v_extra, '{}'::text[]) LOOP
        IF EXISTS (SELECT 1 FROM so_pillar.role WHERE role_name = v_role) THEN
            INSERT INTO so_pillar.role_member(role_name, minion_id, source)
            VALUES (v_role, p_minion_id, 'computed')
            ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION so_pillar.fn_minion_after_change() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM so_pillar.fn_recompute_role_members(COALESCE(NEW.minion_id, OLD.minion_id));
    RETURN COALESCE(NEW, OLD);
END
$fn$;

DROP TRIGGER IF EXISTS minion_role_sync ON so_pillar.minion;
CREATE TRIGGER minion_role_sync
    AFTER INSERT OR UPDATE OF node_type, extra_roles ON so_pillar.minion
    FOR EACH ROW EXECUTE FUNCTION so_pillar.fn_minion_after_change();
