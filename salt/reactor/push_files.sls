#!py

# Reactor invoked by local_files_beacon when a watched directory under
# /opt/so/saltstack/local/salt/ changes. The beacon tag is an app name in
# pillar_push_map.yaml, so file changes and pillar changes route through the same
# table -- see salt/reactor/push_pillar.sls.
#
# The app comes from the event tag, not the payload: salt's beacon loop pops the
# beacon's 'tag' key off the data and appends it to the event tag instead (see
# salt/beacons/__init__.py). The reactor renderer sets both `tag` and `data` as
# module globals.
#
# Reactors never dispatch directly. The so-push-drainer schedule picks up ready
# intents, dedupes across pending files, and dispatches orch.push_batch.

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
        LOG.warning('push_files: %s not found', PUSH_MAP_PATH)
        return {}
    if _PUSH_MAP_CACHE['mtime'] != st.st_mtime:
        try:
            with open(PUSH_MAP_PATH, 'r') as f:
                _PUSH_MAP_CACHE['data'] = yaml.safe_load(f) or {}
        except Exception:
            LOG.exception('push_files: failed to load %s', PUSH_MAP_PATH)
            _PUSH_MAP_CACHE['data'] = {}
        _PUSH_MAP_CACHE['mtime'] = st.st_mtime
    return _PUSH_MAP_CACHE['data'] or {}


def _push_enabled():
    try:
        caller = Caller()
        return bool(caller.cmd('pillar.get', 'salt:auto_apply:enabled', True))
    except Exception:
        LOG.exception('push_files: pillar.get salt:auto_apply:enabled failed, assuming enabled')
        return True


def _write_intent(key, actions, path):
    now = time.time()
    try:
        os.makedirs(PENDING_DIR, exist_ok=True)
    except OSError:
        LOG.exception('push_files: cannot create %s', PENDING_DIR)
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
        LOG.exception('push_files: failed to write intent %s', intent_path)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def run():
    if not _push_enabled():
        LOG.info('push_files: push disabled, skipping')
        return {}

    event = data.get('data', data)  # noqa: F821 -- data provided by reactor
    path = event.get('path', '')
    app = tag.rsplit('/', 1)[-1].strip()  # noqa: F821 -- tag provided by reactor

    if not app:
        LOG.debug('push_files: ignoring event with no app segment: tag=%s', tag)  # noqa: F821
        return {}

    entry = _load_push_map().get(app)
    if not entry:
        LOG.warning(
            'push_files: app "%s" is not in pillar_push_map.yaml; change will be '
            'picked up at the next scheduled highstate (path=%s)',
            app, path,
        )
        return {}

    _write_intent('files_{}'.format(app), list(entry), path)
    LOG.info('push_files: intent updated for %s (path=%s)', app, path)
    return {}
