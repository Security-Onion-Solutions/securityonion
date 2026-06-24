#!py

# Reactor invoked by the inotify beacon on rule file changes under
# /opt/so/saltstack/local/salt/strelka/rules/compiled/.
#
# Writes (or updates) a push intent at /opt/so/state/push_pending/rules_strelka.json
# and returns {}. The so-push-drainer schedule picks up ready intents, dedupes
# across pending files, and dispatches orch.push_batch. Reactors never dispatch
# directly -- see plan /home/mreeves/.claude/plans/goofy-marinating-hummingbird.md.

import fcntl
import json
import logging
import os
import time

from salt.client import Caller

LOG = logging.getLogger(__name__)

PENDING_DIR = '/opt/so/state/push_pending'
LOCK_FILE = os.path.join(PENDING_DIR, '.lock')
MAX_PATHS = 20

# Mirrors GLOBALS.sensor_roles in salt/vars/globals.map.jinja. Sensor-side
# strelka runs on exactly these four roles; so-import gets strelka.manager
# instead, which is not fired on pillar changes.
SENSOR_ROLES = ['so-eval', 'so-heavynode', 'so-sensor', 'so-standalone']


def _sensor_compound():
    return ' or '.join('G@role:{}'.format(r) for r in SENSOR_ROLES)


def _push_enabled():
    try:
        caller = Caller()
        return bool(caller.cmd('pillar.get', 'salt:auto_apply:enabled', True))
    except Exception:
        LOG.exception('push_strelka: pillar.get salt:auto_apply:enabled failed, assuming enabled')
        return True


def _write_intent(key, actions, path):
    now = time.time()
    try:
        os.makedirs(PENDING_DIR, exist_ok=True)
    except OSError:
        LOG.exception('push_strelka: cannot create %s', PENDING_DIR)
        return

    intent_path = os.path.join(PENDING_DIR, '{}.json'.format(key))
    lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        intent = {}
        if os.path.exists(intent_path):
            try:
                with open(intent_path, 'r') as f:
                    intent = json.load(f)
            except (IOError, ValueError):
                intent = {}

        intent.setdefault('first_touch', now)
        intent['last_touch'] = now
        intent['actions'] = actions
        paths = intent.get('paths', [])
        if path and path not in paths:
            paths.append(path)
            paths = paths[-MAX_PATHS:]
        intent['paths'] = paths

        tmp_path = intent_path + '.tmp'
        with open(tmp_path, 'w') as f:
            json.dump(intent, f)
        os.rename(tmp_path, intent_path)
    except Exception:
        LOG.exception('push_strelka: failed to write intent %s', intent_path)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def run():
    if not _push_enabled():
        LOG.info('push_strelka: push disabled, skipping')
        return {}

    path = data.get('path', '')  # noqa: F821 -- data provided by reactor
    actions = [{'state': 'strelka', 'tgt': _sensor_compound()}]
    _write_intent('rules_strelka', actions, path)
    LOG.info('push_strelka: intent updated for path=%s', path)
    return {}
