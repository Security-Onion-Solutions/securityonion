#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import os
import pwd
import grp
import re

log = logging.getLogger(__name__)

PILLAR_ROOT = '/opt/so/saltstack/local/pillar/minions/'
_VMNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')


def run():
  vm_name = data.get('kwargs', {}).get('name', '')
  if not _VMNAME_RE.match(str(vm_name)):
    log.error("createEmptyPillar reactor: refusing unsafe vm_name=%r", vm_name)
    return {}

  log.info("createEmptyPillar reactor: vm_name: %s", vm_name)
  pillar_files = ['adv_' + vm_name + '.sls', vm_name + '.sls']

  try:
    socore_uid = pwd.getpwnam('socore').pw_uid
    socore_gid = grp.getgrnam('socore').gr_gid
    pillar_root_real = os.path.realpath(PILLAR_ROOT)

    for f in pillar_files:
      full_path = os.path.join(PILLAR_ROOT, f)
      resolved = os.path.realpath(full_path)
      if os.path.dirname(resolved) != pillar_root_real:
        log.error("createEmptyPillar reactor: refusing path outside pillar root: %s", resolved)
        continue
      if os.path.exists(resolved):
        continue
      os.mknod(resolved)
      os.chown(resolved, socore_uid, socore_gid)
      os.chmod(resolved, 0o640)
      log.info("createEmptyPillar reactor: created %s with socore:socore ownership and mode 0640", f)

  except (KeyError, OSError) as e:
    log.error("createEmptyPillar reactor: Error setting ownership/permissions: %s", e)

  return {}
