#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import yaml
import os
import glob

def run():

  def release_compute():
    compute = hv_data['hypervisor']['hardware'][hw_type]
    compute.update({'free': compute.get('free') + vm_data.get(hw_type)})
    logging.error("virtReboot reactor: claiming %s compute: %s " % (hw_type,compute))

  def release_pci():
    free_hw = hv_data['hypervisor']['hardware'][hw_type]['free']
    # this could be 0 if nothing is assigned
    if vm_data[hw_type] != 0:
      for hw in vm_data[hw_type]:
        f_hw = {hw: hv_data['hypervisor']['hardware'][hw_type]['claimed'].pop(hw)}
        free_hw.update(f_hw)
        logging.error("virtReleaseHardware reactor: released %s: %s" % (hw_type, f_hw))

  def get_hypervisor():
    base_dir = '/opt/so/saltstack/local/pillar/hypervisor'
    pattern = os.path.join(base_dir, '**', vm_name + '.sls')
    files = glob.glob(pattern, recursive=True)
    logging.error("virtReleaseHardware reactor: files: %s " % files)
    if files:
      return files[0].split('/')[7]

  vm_name = data['name']
  # since the vm has been destroyed, we can't get the hypervisor_host grain
  hv_name = get_hypervisor()
  logging.error("virtReleaseHardware reactor: hv_name: %s " % hv_name)

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
    release_pci()

  for hw_type in ['cpu', 'memory']:
    release_compute()

  # update the free hardware for the hypervisor
  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + hv_name + ".sls", 'w') as f:
    yaml.dump(hv_data, f, default_flow_style=False)

  # remove the old vm_data file since the vm has been purged
  os.remove("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + vm_name + ".sls")
  # remove minion pillar files
  os.remove("/opt/so/saltstack/local/pillar/minions/adv_" + vm_name + ".sls")
  os.remove("/opt/so/saltstack/local/pillar/minions/" + vm_name + ".sls")

  return {}
