#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This reactor will run when a new manager key is accepted through SOC in a grid configuration using a MoM.
# In so-minion, there is a function add_nodegroup_to_minion that fires and event to the MoM that triggers this reactor.

import logging
import os
import pwd
import shutil

def run():
  MINIONID = data['id']
  NODEGROUP = data['data']['nodegroup']
  SALT_ROOT = '/opt/so/saltstack'
  DEFAULT_PILLAR_PATH = os.path.join(SALT_ROOT, 'default/pillar')
  LOCAL_PILLAR_PATH = os.path.join(SALT_ROOT, 'local/pillar')
  NODEGROUP_PATH = os.path.join(LOCAL_PILLAR_PATH, 'nodegroups' , NODEGROUP)
  # the mom will need somewhere to store pillar files to distribute to the nodegroups manager
  NODEGROUP_STATE_PATH = os.path.join(SALT_ROOT, 'local/salt/nodegroups', NODEGROUP)

  logging.info('reactor: create_nodegroup: nodegroup creation of %s requested by %s' % (NODEGROUP, MINIONID))

  # check if the nodegroups pillar directory exists
  if not os.path.isdir(NODEGROUP_STATE_PATH):
    os.mkdir(NODEGROUP_STATE_PATH, 0o755)
    UID, GID = pwd.getpwnam('socore').pw_uid, pwd.getpwnam('socore').pw_uid
    os.chown(NODEGROUP_STATE_PATH, UID, GID)
    # copy all the default pillar directories and files to the nodegroup
    shutil.copytree(DEFAULT_PILLAR_PATH, NODEGROUP_STATE_PATH, dirs_exist_ok=True)

  return {}
