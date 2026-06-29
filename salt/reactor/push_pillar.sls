#!py

# Reactor invoked by the postgres_pillar_beacon when SOC records settings changes in
# the securityonion.audit_settings table (see salt/_beacons/postgres_pillar_beacon.py). The beacon
# emits one event per new row carrying setting_id and node_id.
#
# Two branches, keyed on node_id:
#   A) node_id populated -> the change is scoped to that one minion. Look up the
#      app in pillar_push_map.yaml and write an intent that runs the app's mapped
#      state(s) targeted to just that node.
#   B) node_id empty -> grid-wide app change. Look up the app in
#      pillar_push_map.yaml and write an intent with the entry's actions as-is.
#
# The app name is the first dotted segment of setting_id (e.g. "telegraf.output"
# -> "telegraf"), which matches the pillar_push_map.yaml keys 1:1.
#
# Reactors never dispatch directly. The so-push-drainer schedule picks up
# ready intents, dedupes across pending files, and dispatches orch.push_batch.

import fcntl
import json
import logging
import os
import time

from salt.client import Caller
import yaml

LOG = logging.getLogger(__name__)

PENDING_DIR = '/opt/so/state/push_pending'
LOCK_FILE = os.path.join(PENDING_DIR, '.lock')
MAX_PATHS = 20

# The pillar_push_map.yaml is shipped via salt:// but the reactor runs on the
# master, which mounts the default saltstack tree at this path.
PUSH_MAP_PATH = '/opt/so/saltstack/default/salt/reactor/pillar_push_map.yaml'

_PUSH_MAP_CACHE = {'mtime': 0, 'data': None}


def _load_push_map():
    try:
        st = os.stat(PUSH_MAP_PATH)
    except OSError:
        LOG.warning('push_pillar: %s not found', PUSH_MAP_PATH)
        return {}
    if _PUSH_MAP_CACHE['mtime'] != st.st_mtime:
        try:
            with open(PUSH_MAP_PATH, 'r') as f:
                _PUSH_MAP_CACHE['data'] = yaml.safe_load(f) or {}
        except Exception:
            LOG.exception('push_pillar: failed to load %s', PUSH_MAP_PATH)
            _PUSH_MAP_CACHE['data'] = {}
        _PUSH_MAP_CACHE['mtime'] = st.st_mtime
    return _PUSH_MAP_CACHE['data'] or {}


def _push_enabled():
    try:
        caller = Caller()
        return bool(caller.cmd('pillar.get', 'salt:auto_apply:enabled', True))
    except Exception:
        LOG.exception('push_pillar: pillar.get salt:auto_apply:enabled failed, assuming enabled')
        return True


def _write_intent(key, actions, path):
    now = time.time()
    try:
        os.makedirs(PENDING_DIR, exist_ok=True)
    except OSError:
        LOG.exception('push_pillar: cannot create %s', PENDING_DIR)
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
        LOG.exception('push_pillar: failed to write intent %s', intent_path)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _app_from_setting(setting_id):
    # setting_id is e.g. 'telegraf.output' -> 'telegraf', 'ntp.config.servers' -> 'ntp'
    if not setting_id:
        return None
    return setting_id.split('.', 1)[0] or None


def _node_actions(entry, node_id):
    # Copy the app's mapped actions but retarget each one to the single node.
    # Preserves the state/highstate selection and any batch/batch_wait overrides.
    actions = []
    for action in entry:
        if not isinstance(action, dict):
            continue
        node_action = dict(action)
        node_action['tgt'] = node_id
        node_action['tgt_type'] = 'glob'
        actions.append(node_action)
    return actions


def run():
    if not _push_enabled():
        LOG.info('push_pillar: push disabled, skipping')
        return {}

    # The postgres_pillar_beacon nests its payload under data['data']; fall back to the
    # top level so the reactor is robust to either shape.
    event = data.get('data', data)  # noqa: F821 -- data provided by reactor
    setting_id = event.get('setting_id', '')
    node_id = (event.get('node_id') or '').strip()

    app = _app_from_setting(setting_id)
    if not app:
        LOG.debug('push_pillar: ignoring event with no app segment: setting_id=%s', setting_id)
        return {}

    push_map = _load_push_map()
    entry = push_map.get(app)
    if not entry:
        LOG.warning(
            'push_pillar: app "%s" is not in pillar_push_map.yaml; change will be '
            'picked up at the next scheduled highstate (setting_id=%s)',
            app, setting_id,
        )
        return {}

    # Branch A: per-node change -> retarget the app's states to just that node.
    if node_id:
        actions = _node_actions(entry, node_id)
        if not actions:
            LOG.warning('push_pillar: no usable actions for app "%s" (setting_id=%s)', app, setting_id)
            return {}
        _write_intent(
            'node_{}_{}'.format(node_id, app), actions,
            'audit:{}@{}'.format(setting_id, node_id),
        )
        LOG.info('push_pillar: per-node intent updated for %s on %s (setting_id=%s)',
                 app, node_id, setting_id)
        return {}

    # Branch B: grid-wide app change -> use the map entry's actions as-is.
    actions = list(entry)  # copy to avoid mutating the cache
    _write_intent('pillar_{}'.format(app), actions, 'audit:{}'.format(setting_id))
    LOG.info('push_pillar: app intent updated for %s (setting_id=%s)', app, setting_id)
    return {}
