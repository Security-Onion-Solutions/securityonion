# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# -*- coding: utf-8 -*-

"""
pg_notify_pillar — Salt master engine that bridges so_pillar.change_queue
into the Salt event bus.

Architecture (see 008_change_notify.sql):
  pillar_entry  -- AFTER trigger -->  change_queue (durable)
                                       + pg_notify('so_pillar_change') (wakeup)
                                                                |
                                       LISTEN <-- this engine <-+
                                       SELECT/UPDATE change_queue
                                                                |
                                       fire_event('so/pillar/changed', ...)
                                                                |
                                       reactor matches tag --> orch

Why a queue + notify rather than just notify: pg_notify is fire-and-forget
within a session. If the engine is down or the LISTEN connection is broken
when a write happens, the notification is lost forever. The change_queue
lets us recover — on (re)connect, we drain everything still flagged
processed_at IS NULL.

Debounce: bulk operations (so-pillar-import, fresh installs) can fire
hundreds of notifications per second. The engine collects whatever lands in
a short window and emits one event per (scope, role, minion) tuple so the
reactor isn't stampeded.
"""

import json
import logging
import os
import select
import time

import salt.utils.event

log = logging.getLogger(__name__)

__virtualname__ = 'pg_notify_pillar'

DEFAULT_CHANNEL = 'so_pillar_change'
DEFAULT_DEBOUNCE_MS = 500
DEFAULT_RECONNECT_BACKOFF = 5
DEFAULT_BACKLOG_INTERVAL = 30
DEFAULT_BATCH_LIMIT = 500

EVENT_TAG = 'so/pillar/changed'


def __virtual__():
    try:
        import psycopg2  # noqa: F401
        return __virtualname__
    except ImportError:
        return False, 'pg_notify_pillar engine requires psycopg2'


def start(dsn=None,
          host='127.0.0.1',
          port=5432,
          dbname='securityonion',
          user='so_pillar_master',
          password=None,
          channel=DEFAULT_CHANNEL,
          debounce_ms=DEFAULT_DEBOUNCE_MS,
          reconnect_backoff=DEFAULT_RECONNECT_BACKOFF,
          backlog_interval=DEFAULT_BACKLOG_INTERVAL,
          batch_limit=DEFAULT_BATCH_LIMIT,
          password_file=None):
    """
    Run the change-queue bridge until the master shuts the engine down.

    Either pass a full ``dsn`` string, or supply discrete kwargs. The
    password may also be read from ``password_file`` (mode 0400) so the
    engine config in ``/etc/salt/master.d/`` doesn't have to embed it
    inline — only the file path.
    """
    import psycopg2
    import psycopg2.extensions

    if dsn is None:
        if password is None and password_file:
            try:
                with open(password_file, 'r') as fh:
                    password = fh.read().strip()
            except (IOError, OSError) as exc:
                log.error('pg_notify_pillar: cannot read password_file %s: %s',
                          password_file, exc)
                return
        dsn = _build_dsn(host=host, port=port, dbname=dbname,
                         user=user, password=password)

    bus = salt.utils.event.get_master_event(
        __opts__, __opts__['sock_dir'], listen=False)

    log.info('pg_notify_pillar: starting (channel=%s debounce=%dms)',
             channel, debounce_ms)

    while True:
        conn = None
        try:
            conn = psycopg2.connect(dsn)
            conn.set_isolation_level(
                psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            cur = conn.cursor()
            cur.execute('LISTEN {0}'.format(channel))
            log.info('pg_notify_pillar: connected; LISTEN %s', channel)

            _drain(cur, bus, batch_limit)

            while True:
                ready, _, _ = select.select([conn], [], [], backlog_interval)
                if not ready:
                    _drain(cur, bus, batch_limit)
                    continue

                conn.poll()
                _consume_notifies(conn)

                if debounce_ms > 0:
                    time.sleep(debounce_ms / 1000.0)
                    conn.poll()
                    _consume_notifies(conn)

                _drain(cur, bus, batch_limit)

        except Exception as exc:  # psycopg2.Error subclasses + OS errors
            log.error('pg_notify_pillar: %s; reconnecting in %ds',
                      exc, reconnect_backoff)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        time.sleep(reconnect_backoff)


def _build_dsn(host, port, dbname, user, password):
    parts = ['host={0}'.format(host),
             'port={0}'.format(port),
             'dbname={0}'.format(dbname),
             'user={0}'.format(user)]
    if password:
        parts.append('password={0}'.format(password))
    return ' '.join(parts)


def _consume_notifies(conn):
    # We don't use the payload directly — the queue table is the source of
    # truth, and draining it covers any notifications we missed. So just
    # discard them; their presence already proved there's something to drain.
    while conn.notifies:
        conn.notifies.pop(0)


def _drain(cur, bus, batch_limit):
    """Mark unprocessed change_queue rows processed and emit one event per
    (scope, role_name, minion_id) group. SKIP LOCKED so multiple masters
    sharing a Postgres don't double-process."""
    cur.execute("""
        UPDATE so_pillar.change_queue
           SET processed_at = now()
         WHERE id IN (
             SELECT id FROM so_pillar.change_queue
              WHERE processed_at IS NULL
              ORDER BY id
              FOR UPDATE SKIP LOCKED
              LIMIT %s)
        RETURNING id, scope, role_name, minion_id, pillar_path, op
    """, (batch_limit,))
    rows = cur.fetchall()
    if not rows:
        return

    groups = {}
    for row_id, scope, role_name, minion_id, pillar_path, op in rows:
        key = (scope, role_name, minion_id)
        groups.setdefault(key, []).append({
            'queue_id':    row_id,
            'pillar_path': pillar_path,
            'op':          op,
        })

    for (scope, role_name, minion_id), changes in groups.items():
        payload = {
            'scope':     scope,
            'role_name': role_name,
            'minion_id': minion_id,
            'changes':   changes,
        }
        log.debug('pg_notify_pillar: firing %s for %s',
                  EVENT_TAG, payload)
        bus.fire_event(payload, EVENT_TAG)
