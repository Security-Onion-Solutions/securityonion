#!py

# Reactor invoked by the inotify beacon on pillar file changes under
# /opt/so/saltstack/local/pillar/.
#
# Two branches:
#   A) per-minion override under pillar/minions/<id>.sls or adv_<id>.sls
#      -> write an intent that runs state.highstate on just that minion.
#   B) shared app pillar (pillar/<app>/...) -> look up <app> in
#      pillar_push_map.yaml and write an intent with the entry's actions.
#
# Reactors never dispatch directly. The so-push-drainer schedule picks up
# ready intents, dedupes across pending files, and dispatches orch.push_batch.
# See plan /home/mreeves/.claude/plans/goofy-marinating-hummingbird.md.

import fcntl
import json
import logging
import os
import time

import salt.client
import yaml

LOG = logging.getLogger(__name__)

PENDING_DIR = '/opt/so/state/push_pending'
LOCK_FILE = os.path.join(PENDING_DIR, '.lock')
MAX_PATHS = 20

PILLAR_ROOT = '/opt/so/saltstack/local/pillar/'
MINIONS_PREFIX = PILLAR_ROOT + 'minions/'

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
        caller = salt.client.Caller()
        return bool(caller.cmd('pillar.get', 'global:push:enabled', True))
    except Exception:
        LOG.exception('push_pillar: pillar.get global:push:enabled failed, assuming enabled')
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


def _minion_id_from_path(path):
    # path is e.g. /opt/so/saltstack/local/pillar/minions/sensor1.sls
    #          or /opt/so/saltstack/local/pillar/minions/adv_sensor1.sls
    filename = os.path.basename(path)
    if not filename.endswith('.sls'):
        return None
    stem = filename[:-4]
    if stem.startswith('adv_'):
        stem = stem[4:]
    return stem or None


def _app_from_path(path):
    # path is e.g. /opt/so/saltstack/local/pillar/zeek/soc_zeek.sls -> 'zeek'
    remainder = path[len(PILLAR_ROOT):]
    if '/' not in remainder:
        return None
    return remainder.split('/', 1)[0] or None


def run():
    if not _push_enabled():
        LOG.info('push_pillar: push disabled, skipping')
        return {}

    path = data.get('data', {}).get('path', '')  # noqa: F821 -- data provided by reactor
    if not path or not path.startswith(PILLAR_ROOT):
        LOG.debug('push_pillar: ignoring path outside pillar root: %s', path)
        return {}

    # Branch A: per-minion override
    if path.startswith(MINIONS_PREFIX):
        minion_id = _minion_id_from_path(path)
        if not minion_id:
            LOG.debug('push_pillar: ignoring non-sls path under minions/: %s', path)
            return {}
        actions = [{'highstate': True, 'tgt': minion_id, 'tgt_type': 'glob'}]
        _write_intent('minion_{}'.format(minion_id), actions, path)
        LOG.info('push_pillar: per-minion intent updated for %s (path=%s)', minion_id, path)
        return {}

    # Branch B: shared app pillar -> allowlist lookup
    app = _app_from_path(path)
    if not app:
        LOG.debug('push_pillar: ignoring path with no app segment: %s', path)
        return {}

    push_map = _load_push_map()
    entry = push_map.get(app)
    if not entry:
        LOG.warning(
            'push_pillar: pillar dir "%s" is not in pillar_push_map.yaml; '
            'change will be picked up at the next scheduled highstate (path=%s)',
            app, path,
        )
        return {}

    actions = list(entry)  # copy to avoid mutating the cache
    _write_intent('pillar_{}'.format(app), actions, path)
    LOG.info('push_pillar: app intent updated for %s (path=%s)', app, path)
    return {}
