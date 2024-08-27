#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
from subprocess import call
import yaml

def run():
  minionid = data['id']
  DATA = data['data']
  hv_name = DATA['HYPERVISOR_HOST']
  logging.error("sominion_setup reactor: %s " % DATA)

  vm_out_data = {
    'cpu': DATA['CPU'],
    'memory': DATA['MEMORY'],
    'disks': DATA['DISKS'],
    'copper': DATA['COPPER'],
    'sfp': DATA['SFP']
  }

  logging.error("sominion_setup reactor: vm_out_data: %s " % vm_out_data)

  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + minionid + ".sls", 'w') as f:
    yaml.dump(vm_out_data, f, default_flow_style=False)

  rc = call("NODETYPE=" + DATA['NODETYPE'] + " /usr/sbin/so-minion -o=addVirt -m=" + minionid + " -n=" + DATA['MNIC'] + " -i=" + DATA['MAINIP'] + " -a=" + DATA['INTERFACE'] + " -c=" + str(DATA['CORECOUNT'])  + " -d='" + DATA['NODE_DESCRIPTION'] + "'", shell=True)

  logging.error('sominion_setup reactor: rc: %s' % rc)

  return {}
