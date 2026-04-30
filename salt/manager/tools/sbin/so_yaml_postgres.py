# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

"""
so_yaml_postgres — Postgres-backed dual-write helpers for so-yaml.py.

so-yaml.py writes YAML pillar files on disk; this module mirrors those
writes into so_pillar.* in so-postgres so ext_pillar and the SOC
PostgresConfigstore see the same data. During the postsalt transition
disk is canonical; PG writes are best-effort and never fail the disk
operation.

Connection: shells out to `docker exec so-postgres psql -U postgres -d
securityonion`. Same pattern so-pillar-import uses; avoids needing a
separate DSN config at install time. Performance is fine because so-yaml
is invoked from infrequent code paths (setup scripts, so-minion,
so-firewall); SOC's hot path uses the in-process pgxpool in
PostgresConfigstore, not so-yaml.

Path-to-row mapping mirrors PostgresConfigstore.locateSetting in
securityonion-soc:

  /opt/so/saltstack/local/pillar/<section>/soc_<section>.sls
        -> scope=global, pillar_path=<section>.soc_<section>
  /opt/so/saltstack/local/pillar/<section>/adv_<section>.sls
        -> scope=global, pillar_path=<section>.adv_<section>
  /opt/so/saltstack/local/pillar/minions/<id>.sls
        -> scope=minion, minion_id=<id>, pillar_path=minions.<id>
  /opt/so/saltstack/local/pillar/minions/adv_<id>.sls
        -> scope=minion, minion_id=<id>, pillar_path=minions.adv_<id>

Files outside that mapping (notably secrets.sls, postgres/auth.sls,
elasticsearch/nodes.sls, etc.) are skipped — they stay disk-only forever
or render dynamically and don't belong in PG.
"""

import json
import os
import shlex
import subprocess
import sys

DOCKER_CONTAINER = os.environ.get("SO_PILLAR_PG_CONTAINER", "so-postgres")
PG_DATABASE = os.environ.get("SO_PILLAR_PG_DATABASE", "securityonion")
PG_USER = os.environ.get("SO_PILLAR_PG_USER", "postgres")

# File paths whose mutations stay disk-only forever. Mirrors EXCLUDE_*
# in so-pillar-import.
DISK_ONLY_PATHS = (
    "/opt/so/saltstack/local/pillar/secrets.sls",
    "/opt/so/saltstack/local/pillar/postgres/auth.sls",
    "/opt/so/saltstack/local/pillar/elasticsearch/auth.sls",
    "/opt/so/saltstack/local/pillar/kibana/secrets.sls",
)
DISK_ONLY_FRAGMENTS = (
    "/elasticsearch/nodes.sls",
    "/redis/nodes.sls",
    "/kafka/nodes.sls",
    "/hypervisor/nodes.sls",
    "/logstash/nodes.sls",
    "/node_data/ips.sls",
    "/top.sls",
)


class SkipPath(Exception):
    """Raised when a file path is intentionally not mirrored to PG."""


def _is_enabled():
    """PG dual-write only fires if so-postgres is reachable. Cheap probe.
    Returns True when docker exec succeeds, False otherwise. We never
    want a PG hiccup to fail a disk write on a manager whose Postgres is
    momentarily unreachable."""
    try:
        proc = subprocess.run(
            ["docker", "exec", DOCKER_CONTAINER,
             "pg_isready", "-h", "127.0.0.1", "-U", PG_USER, "-q"],
            capture_output=True, timeout=5, check=False,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def locate(path):
    """Translate a so-yaml file path to (scope, role_name, minion_id, pillar_path).
    Raises SkipPath when the file is not part of the PG-managed surface."""
    norm = os.path.normpath(path)

    if norm in DISK_ONLY_PATHS:
        raise SkipPath(f"{path}: explicit disk-only allowlist")
    for frag in DISK_ONLY_FRAGMENTS:
        if frag in norm:
            raise SkipPath(f"{path}: matches disk-only fragment {frag}")

    parent = os.path.basename(os.path.dirname(norm))
    grandparent = os.path.basename(os.path.dirname(os.path.dirname(norm)))
    name = os.path.basename(norm)
    if not name.endswith(".sls"):
        raise SkipPath(f"{path}: not a .sls file")
    stem = name[:-4]

    if parent == "minions":
        if stem.startswith("adv_"):
            mid = stem[4:]
            return ("minion", None, mid, f"minions.adv_{mid}")
        return ("minion", None, stem, f"minions.{stem}")

    # /local/pillar/<section>/<file>.sls
    if grandparent == "pillar" and parent and parent != "":
        if stem.startswith("soc_") or stem.startswith("adv_"):
            return ("global", None, None, f"{parent}.{stem}")
        raise SkipPath(f"{path}: <section>/{stem}.sls is not a soc_/adv_ file")

    raise SkipPath(f"{path}: unrecognised pillar layout")


def _pg_str(s):
    if s is None:
        return "NULL"
    return "'" + str(s).replace("'", "''") + "'"


def _docker_psql(sql):
    """Run sql via docker exec ... psql. Returns stdout. Caller catches
    exceptions and downgrades to a warning."""
    proc = subprocess.run(
        ["docker", "exec", "-i", DOCKER_CONTAINER,
         "psql", "-U", PG_USER, "-d", PG_DATABASE,
         "-tA", "-q", "-v", "ON_ERROR_STOP=1"],
        input=sql.encode(), capture_output=True, check=False, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace") or
                           f"docker exec psql exit {proc.returncode}")
    return proc.stdout.decode(errors="replace")


def _conflict_target(scope):
    if scope == "global":
        return "(pillar_path) WHERE scope='global'"
    if scope == "role":
        return "(role_name, pillar_path) WHERE scope='role'"
    if scope == "minion":
        return "(minion_id, pillar_path) WHERE scope='minion'"
    raise ValueError(f"unknown scope {scope!r}")


def write_yaml(path, content_dict, *, reason="so-yaml dual-write"):
    """Mirror the disk write at `path` (whose content was just rendered as
    `content_dict`) into so_pillar.pillar_entry. Best-effort: any failure
    is swallowed so the caller (so-yaml.py) does not see it as a fatal."""
    if not _is_enabled():
        return False, "postgres unreachable"
    try:
        scope, role, minion_id, pillar_path = locate(path)
    except SkipPath as e:
        return False, str(e)

    data_json = json.dumps(content_dict if content_dict is not None else {})
    role_sql = _pg_str(role)
    minion_sql = _pg_str(minion_id)
    reason_sql = _pg_str(reason)
    conflict = _conflict_target(scope)

    sql_parts = []
    if scope == "minion":
        # FK requires the minion row before pillar_entry can reference it.
        sql_parts.append(
            f"INSERT INTO so_pillar.minion (minion_id) VALUES ({minion_sql}) "
            "ON CONFLICT (minion_id) DO NOTHING;"
        )
    sql_parts.append(
        "BEGIN;\n"
        f"SELECT set_config('so_pillar.change_reason', {reason_sql}, true);\n"
        "INSERT INTO so_pillar.pillar_entry "
        "(scope, role_name, minion_id, pillar_path, data, change_reason) "
        f"VALUES ({_pg_str(scope)}, {role_sql}, {minion_sql}, "
        f"{_pg_str(pillar_path)}, {_pg_str(data_json)}::jsonb, {reason_sql}) "
        f"ON CONFLICT {conflict} DO UPDATE "
        "SET data = EXCLUDED.data, change_reason = EXCLUDED.change_reason;\n"
        "COMMIT;\n"
    )

    try:
        _docker_psql("\n".join(sql_parts))
    except Exception as e:
        return False, f"pg write failed: {e}"
    return True, "ok"


def purge_yaml(path, *, reason="so-yaml purge"):
    """Mirror the disk file deletion at `path` by deleting the matching
    pillar_entry rows. For minion files also deletes the so_pillar.minion
    row (CASCADE removes pillar_entry + role_member rows)."""
    if not _is_enabled():
        return False, "postgres unreachable"
    try:
        scope, role, minion_id, pillar_path = locate(path)
    except SkipPath as e:
        return False, str(e)

    reason_sql = _pg_str(reason)
    parts = ["BEGIN;",
             f"SELECT set_config('so_pillar.change_reason', {reason_sql}, true);"]

    if scope == "minion":
        # If both <id>.sls and adv_<id>.sls are gone the trigger / CASCADE
        # cleans up role_member; otherwise we just remove this one row.
        parts.append(
            f"DELETE FROM so_pillar.pillar_entry "
            f"WHERE scope='minion' AND minion_id={_pg_str(minion_id)} "
            f"AND pillar_path={_pg_str(pillar_path)};"
        )
        parts.append(
            f"DELETE FROM so_pillar.minion WHERE minion_id={_pg_str(minion_id)} "
            "AND NOT EXISTS (SELECT 1 FROM so_pillar.pillar_entry "
            f"WHERE minion_id={_pg_str(minion_id)});"
        )
    else:
        parts.append(
            f"DELETE FROM so_pillar.pillar_entry "
            f"WHERE scope={_pg_str(scope)} AND pillar_path={_pg_str(pillar_path)};"
        )

    parts.append("COMMIT;")

    try:
        _docker_psql("\n".join(parts))
    except Exception as e:
        return False, f"pg purge failed: {e}"
    return True, "ok"


# CLI for diagnostics. Not exercised by so-yaml.py itself.
def _main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=("locate", "ping"))
    ap.add_argument("path", nargs="?")
    args = ap.parse_args(argv)

    if args.op == "ping":
        ok = _is_enabled()
        print("ok" if ok else "unreachable")
        return 0 if ok else 1
    if args.op == "locate":
        if not args.path:
            ap.error("locate requires PATH")
        try:
            scope, role, minion_id, pillar_path = locate(args.path)
            print(f"scope={scope} role={role} minion_id={minion_id} pillar_path={pillar_path}")
            return 0
        except SkipPath as e:
            print(f"SKIP: {e}", file=sys.stderr)
            return 2

    return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
