# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

#!py

import logging
import salt.client
local = salt.client.LocalClient()
from subprocess import call
import yaml

import os

def run():

  def release_compute(hw_type):
    compute = hv_data['hypervisor']['hardware'][hw_type]
    compute.update({'free': compute.get('free') + vm_data.get(hw_type)})
    logging.error("virtReboot reactor: claiming %s compute: %s " % (hw_type,compute))

  def release_pci(hw_type):
    free_hw = hv_data['hypervisor']['hardware'][hw_type]['free']
    for hw in vm_data[hw_type]:
      f_hw = {hw: hv_data['hypervisor']['hardware'][hw_type]['claimed'].pop(hw)}
      free_hw.update(f_hw)
      logging.error("virtReleaseHardware reactor: released %s: %s" % (hw_type, f_hw))



  vm_name = data['name']
  hv_name = 'jppvirt'

  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + vm_name + ".sls") as f:
    try:
      vm_data=yaml.safe_load(f)
      logging.error("virtReleaseHardware reactor: vm_data %s " % vm_data)
      #logging.error(yaml.safe_load(f))
    except yaml.YAMLError as exc:
      logging.error(exc)

  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + hv_name + ".sls") as f:
    try:
      hv_data=yaml.safe_load(f)
      logging.error("virtReleaseHardware reactor: hv_data: %s " % hv_data)
      #logging.error(yaml.safe_load(f))
    except yaml.YAMLError as exc:
      logging.error(exc)

  for hw_type in ['disks', 'copper', 'sfp']:
    release_pci(hw_type)

  for hw_type in ['cpu', 'memory']:
    release_compute(hw_type)

  # update the free hardware for the hypervisor
  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + hv_name + ".sls", 'w') as f:
    yaml.dump(hv_data, f, default_flow_style=False)

  # remove the old vm_data file since the vm has been purged
  os.remove("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + vm_name + ".sls")
  # remove minion pillar files
  os.remove("/opt/so/saltstack/local/pillar/minions/adv_" + vm_name + ".sls")
  os.remove("/opt/so/saltstack/local/pillar/minions/" + vm_name + ".sls")

  return {}
