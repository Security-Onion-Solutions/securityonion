# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Custom salt beacon that watches the suricata/strelka rule directories for changes
# and emits a beacon event per changed directory. This replaces the stock salt
# `inotify` beacon, which leaks a kernel inotify instance every time the minion
# rebuilds the beacon loader's __context__ (orphaning the old pyinotify.Notifier
# without closing it) until fs.inotify.max_user_instances is exhausted and the
# beacon dies with EMFILE. Polling holds zero inotify instances, so the leak is
# impossible, and it keeps firing during state runs (no blackout).
#
# Detection is poll-based with a per-directory fingerprint persisted to
# WATERMARK_DIR: each pass walks the directory and hashes every file's
# (relpath, st_mtime_ns, st_size), which catches content writes, additions,
# moves, and deletions. A change in the digest emits one event; an unchanged
# digest emits nothing. This makes it self-healing (a missed poll simply catches
# up on the next one).
#
# Each emitted event carries the watched directory path under the configured tag
# (e.g. salt/beacon/<minion>/rules_db/suricata); the push_suricata / push_strelka
# reactors write a push intent, after which the existing so-push-drainer /
# orch.push_batch pipeline takes over unchanged.

import hashlib
import logging
import os
import re

log = logging.getLogger(__name__)

WATERMARK_DIR = '/opt/so/state'

# Temp/editor files that should not trigger a push. Mirrors the exclude regexes
# the inotify beacon used. Matched against the full pathname.
EXCLUDES = [
    re.compile(r'\.sw[a-z]$'),
    re.compile(r'~$'),
    re.compile(r'/4913$'),
    re.compile(r'/\.#'),
]


def __virtual__():
    return True


def validate(config):
    return True, 'valid'


def _paths_from_config(config):
    # The beacon config arrives as a list of single-key dicts (salt beacon style).
    # Merge it and return the {dir: tag} mapping under the 'paths' key.
    merged = {}
    if isinstance(config, list):
        for item in config:
            if isinstance(item, dict):
                merged.update(item)
    elif isinstance(config, dict):
        merged = config
    paths = merged.get('paths', {})
    return paths if isinstance(paths, dict) else {}


def _excluded(pathname):
    for pattern in EXCLUDES:
        if pattern.search(pathname):
            return True
    return False


def _fingerprint(directory):
    # Stat-only walk; hash each file's (relpath, mtime_ns, size). Returns a hex
    # digest, or the digest of an empty tree if the directory does not exist.
    h = hashlib.sha1()
    if os.path.isdir(directory):
        entries = []
        for root, _dirs, files in os.walk(directory):
            for name in files:
                full = os.path.join(root, name)
                if _excluded(full):
                    continue
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rel = os.path.relpath(full, directory)
                entries.append('%s\0%d\0%d' % (rel, st.st_mtime_ns, st.st_size))
        for line in sorted(entries):
            h.update(line.encode('utf-8', 'surrogateescape'))
            h.update(b'\n')
    return h.hexdigest()


def _watermark_file(tag):
    return os.path.join(WATERMARK_DIR, 'rules_db_%s.hash' % tag)


def _read_watermark(tag):
    try:
        with open(_watermark_file(tag), 'r') as f:
            return (f.read() or '').strip() or None
    except IOError:
        return None


def _write_watermark(tag, digest):
    path = _watermark_file(tag)
    try:
        os.makedirs(WATERMARK_DIR, exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            f.write(digest)
        os.rename(tmp, path)
    except OSError:
        log.exception('rules_db beacon: failed to persist watermark to %s', path)


def beacon(config):
    retval = []

    for directory, tag in _paths_from_config(config).items():
        digest = _fingerprint(directory)
        previous = _read_watermark(tag)

        # First run / missing watermark: seed the digest and emit nothing so a
        # fresh host does not fire a spurious fleetwide push.
        if previous is None:
            _write_watermark(tag, digest)
            continue

        if digest != previous:
            _write_watermark(tag, digest)
            retval.append({'tag': tag, 'path': directory})
            log.info('rules_db beacon: change detected in %s, emitting %s', directory, tag)

    return retval
