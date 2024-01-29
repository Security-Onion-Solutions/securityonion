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
  SALTSTACK_ROOT = '/opt/so/saltstack'
  DEFAULT_PILLAR_PATH = os.path.join(SALTSTACK_ROOT, 'default/pillar')
  LOCAL_PILLAR_PATH = os.path.join(SALTSTACK_ROOT, 'local/pillar')
  DEFAULT_STATE_PATH = os.path.join(SALTSTACK_ROOT, 'default/salt')
  LOCAL_STATE_PATH = os.path.join(SALTSTACK_ROOT, 'local/salt')
  # the mom will need somewhere to store pillar files to distribute to the nodegroups manager
  NODEGROUPS_PATH = os.path.join(LOCAL_STATE_PATH, 'nodegroups')
  NODEGROUP_PATH = os.path.join(NODEGROUPS_PATH , NODEGROUP)
  NODEGROUP_STATE_PATH = os.path.join(NODEGROUPS_PATH, NODEGROUP, 'salt')
  NODEGROUP_PILLAR_PATH = os.path.join(NODEGROUPS_PATH, NODEGROUP, 'pillar')

  logging.info('reactor: create_nodegroup: nodegroup creation of %s requested by %s' % (NODEGROUP, MINIONID))

  # check if the pillar directory exists for the new manager's nodegroup
  if not os.path.isdir(NODEGROUP_PATH):
    os.makedirs(NODEGROUP_PATH, 0o755)
    UID, GID = str(pwd.getpwnam('socore').pw_uid), str(pwd.getpwnam('socore').pw_uid)
    # copy all the default pillar directories and files to the nodegroup
    shutil.copytree(DEFAULT_PILLAR_PATH, NODEGROUP_PILLAR_PATH, dirs_exist_ok=True)
    # copy /opt/so/saltstack/local/salt/ into /opt/so/saltstack/local/salt/nodegroups/NODEGROUP/salt, but we have to ignore the nodegroups directory
    #shutil.copytree(LOCAL_STATE_PATH, NODEGROUP_STATE_PATH, dirs_exist_ok=True, ignore=shutil.ignore_patterns('*nodegroups*'))
    os.system('chown -R ' + UID + ':' + GID + ' ' + NODEGROUP_PATH)
    logging.info('reactor: create_nodegroup: nodegroup %s created' % NODEGROUP)
  else:
    logging.error('reactor: create_nodegroup: nodegroup %s already exists' % NODEGROUP)

  return {}
