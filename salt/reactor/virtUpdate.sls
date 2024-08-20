#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import salt.client
local = salt.client.LocalClient()
import yaml

def run():

  def claim_compute(hw_type):
    compute = hv_data['hypervisor']['hardware'][hw_type]
    compute.update({'free': compute.get('free') - vm_data.get(hw_type)})
    logging.error("virtUpdate reactor: claiming %s compute: %s " % (hw_type,compute))


  def claim_pci(hw_type):
    claimed_hw = hv_data['hypervisor']['hardware'][hw_type]['claimed']
    # if a list of devices was defined
    if type(vm_data[hw_type]) == list:
      for hw in vm_data[hw_type]:
        try:
          c_hw = {hw: hv_data['hypervisor']['hardware'][hw_type]['free'].pop(hw)}
          claimed_hw.update(c_hw)
          host_devices.append(c_hw[hw])
        except KeyError:
          logging.error("virtUpdate reactor: could not claim %s with key %s " % (hw_type,hw))
          return {'key1': 'val1'}
    # if a number of devices was defined
    else:
      n = vm_data[hw_type]
      vm_data[hw_type] = []
      # grab the first number of devices as defined for the node type
      claiming_hw = list(hv_data['hypervisor']['hardware'][hw_type]['free'].items())[:n]
      logging.error("virtUpdate reactor: claiming %s hardware: %s " % (hw_type,claiming_hw))
      # claiming_hw is a list of tuples containing (numerical_id, pci_id)
      # claiming_hw example: [(1, 'pci_0000_c4_00_0'), (2, 'pci_0000_c4_00_1')]
      for hw in claiming_hw:
        c_hw = {hw[0]: hv_data['hypervisor']['hardware'][hw_type]['free'].pop(hw[0])}
        claimed_hw.update(c_hw)
        vm_data[hw_type].append(hw[0])
        host_devices.append(hw[1])
      logging.error("virtUpdate reactor: claimed_hw: %s " % claimed_hw)

  vm_name = data['name']
  hv_name = local.cmd(vm_name, 'grains.get', ['hypervisor_host'])

  host_devices = []

  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + vm_name + ".sls") as f:
    try:
      vm_data=yaml.safe_load(f)
      logging.error("virtUpdate reactor: vm_data %s " % vm_data)
      #logging.error(yaml.safe_load(f))
    except yaml.YAMLError as exc:
      logging.error(exc)

  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + hv_name + ".sls") as f:
    try:
      hv_data=yaml.safe_load(f)
      logging.error("virtUpdate reactor: hv_data: %s " % hv_data)
      #logging.error(yaml.safe_load(f))
    except yaml.YAMLError as exc:
      logging.error(exc)

  local.cmd(hv_name, 'virt.stop', ['name=' + vm_name])

  for hw_type in ['disks', 'copper', 'sfp']:
    claim_pci(hw_type)

  for hw_type in ['cpu', 'memory']:
    claim_compute(hw_type)

  logging.error("virtUpdate reactor: host_devices: %s " % host_devices)

  # update the claimed hardware for the hypervisor
  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + hv_name + ".sls", 'w') as f:
    yaml.dump(hv_data, f, default_flow_style=False)

  # since the original hw request provided was a count of hw instead of specific pci ids
  # we need to update the vm_data file with the assigned pci ids that were claimed
  # update the vm_data file with the hardware it claimed
  logging.error("virtUpdate reactor: new vm_data: %s " % vm_data)
  with open("/opt/so/saltstack/local/pillar/hypervisor/" + hv_name + "/" + vm_name + ".sls", 'w') as f:
    yaml.dump(vm_data, f, default_flow_style=False)

  mem = vm_data['memory'] * 1024
  r = local.cmd(hv_name, 'virt.update', ['name=' + vm_name, 'mem=' + str(mem), 'cpu=' + str(vm_data['cpu']), 'host_devices=' + str(host_devices)])
  logging.error("virtUpdate reactor: virt.update: %s" % r)

  local.cmd(hv_name, 'virt.start', ['name=' + vm_name])

  return {}
