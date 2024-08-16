#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import os

def run():
  vm_name = data['kwargs']['name']
  logging.error("createEmptyPillar reactor: vm_name: %s" % vm_name)
  pillar_root = '/opt/so/saltstack/local/pillar/minions/'
  pillar_files = ['adv_' + vm_name + '.sls', vm_name + '.sls']
  for f in pillar_files:
    if not os.path.exists(pillar_root + f):
      os.mknod(pillar_root + f)

  return {}
