#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import os
import pwd
import grp

def run():
  vm_name = data['kwargs']['name']
  logging.error("createEmptyPillar reactor: vm_name: %s" % vm_name)
  pillar_root = '/opt/so/saltstack/local/pillar/minions/'
  pillar_files = ['adv_' + vm_name + '.sls', vm_name + '.sls']

  try:
    # Get socore user and group IDs
    socore_uid = pwd.getpwnam('socore').pw_uid
    socore_gid = grp.getgrnam('socore').gr_gid

    for f in pillar_files:
      full_path = pillar_root + f
      if not os.path.exists(full_path):
        # Create empty file
        os.mknod(full_path)
        # Set ownership to socore:socore
        os.chown(full_path, socore_uid, socore_gid)
        # Set mode to 644 (rw-r--r--)
        os.chmod(full_path, 0o640)
        logging.error("createEmptyPillar reactor: created %s with socore:socore ownership and mode 644" % f)

  except (KeyError, OSError) as e:
    logging.error("createEmptyPillar reactor: Error setting ownership/permissions: %s" % str(e))

  return {}
