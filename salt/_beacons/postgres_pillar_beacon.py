# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Custom salt beacon that watches the SOC audit_settings table in postgres for
# new settings changes and emits a beacon event per new row. This replaces the
# inotify watch on /opt/so/saltstack/local/pillar -- instead of monitoring pillar
# files on disk, we monitor the securityonion.audit_settings table that SOC writes to.
#
# Detection is poll-based with a monotonic `id` watermark persisted to
# WATERMARK_FILE: each pass selects rows with id greater than the last id seen,
# which makes it self-healing (a missed poll simply catches up on the next one).
#
# Each emitted event carries setting_id and node_id; the push_pillar reactor maps
# setting_id -> app via pillar_push_map.yaml and writes a push intent, after which
# the existing so-push-drainer / orch.push_batch pipeline takes over unchanged.

import logging
import os
import subprocess

log = logging.getLogger(__name__)

WATERMARK_FILE = '/opt/so/state/postgres_pillar_beacon_watch.id'
CONTAINER = 'so-postgres'
DATABASE = 'securityonion'

# Unaligned, tuples-only psql output with a field separator that cannot appear in
# an id/setting_id/node_id, so we can split each row reliably.
FIELD_SEP = '\x1f'


def __virtual__():
    return True


def validate(config):
    return True, 'valid'


def _read_watermark():
    # Returns the last processed id, or None if the watermark has not been seeded.
    try:
        with open(WATERMARK_FILE, 'r') as f:
            return int((f.read() or '').strip())
    except (IOError, ValueError):
        return None


def _write_watermark(value):
    try:
        os.makedirs(os.path.dirname(WATERMARK_FILE), exist_ok=True)
        tmp = WATERMARK_FILE + '.tmp'
        with open(tmp, 'w') as f:
            f.write(str(int(value)))
        os.rename(tmp, WATERMARK_FILE)
    except OSError:
        log.exception('postgres_pillar_beacon: failed to persist watermark to %s', WATERMARK_FILE)


def _query(sql):
    # Run a query against securityonion inside the so-postgres container over the unix
    # socket (trust auth, no password). Returns stdout on success, or None on any
    # failure so the caller can no-op and retry on the next interval.
    cmd = [
        'docker', 'exec', CONTAINER,
        'psql', '-U', 'postgres', '-d', DATABASE,
        '-tA', '-F', FIELD_SEP, '-c', sql,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log.warning('postgres_pillar_beacon: psql timed out')
        return None
    except Exception:
        log.exception('postgres_pillar_beacon: failed to exec psql')
        return None
    if result.returncode != 0:
        log.warning('postgres_pillar_beacon: psql failed (rc=%s): %s',
                    result.returncode, (result.stderr or '').strip())
        return None
    return result.stdout


def beacon(config):
    retval = []

    watermark = _read_watermark()

    # First run / missing watermark: seed to the current MAX(id) and emit nothing
    # so we never replay the entire settings history into a fleetwide push.
    if watermark is None:
        seed = _query('SELECT COALESCE(MAX(id), 0) FROM audit_settings;')
        if seed is None:
            return retval  # postgres not ready yet; retry next interval
        try:
            _write_watermark(int((seed or '0').strip() or 0))
        except ValueError:
            log.warning('postgres_pillar_beacon: could not parse MAX(id) seed: %r', seed)
        return retval

    rows = _query(
        "SELECT id, setting_id, COALESCE(node_id, '') FROM audit_settings "
        "WHERE id > %d ORDER BY id;" % watermark
    )
    if rows is None:
        return retval

    max_id = watermark
    for line in rows.splitlines():
        # Do NOT str.strip() the whole line: Python treats the \x1f field
        # separator (and \x1c-\x1e) as whitespace, so stripping would eat an
        # empty trailing node_id field and make the row look malformed.
        if not line.strip():
            continue
        parts = line.split(FIELD_SEP)
        if len(parts) < 3:
            log.warning('postgres_pillar_beacon: skipping malformed row: %r', line)
            continue
        try:
            row_id = int(parts[0])
        except ValueError:
            log.warning('postgres_pillar_beacon: skipping row with non-int id: %r', line)
            continue
        setting_id = parts[1]
        node_id = parts[2]
        retval.append({
            'tag': 'audit_settings',
            'id': row_id,
            'setting_id': setting_id,
            'node_id': node_id,
        })
        if row_id > max_id:
            max_id = row_id

    if max_id > watermark:
        _write_watermark(max_id)
        log.info('postgres_pillar_beacon: emitted %d change(s), watermark %d -> %d',
                 len(retval), watermark, max_id)

    return retval
