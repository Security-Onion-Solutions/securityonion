#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
from subprocess import call
import yaml

log = logging.getLogger(__name__)

def run():
  log.info('sominion_setup_reactor: Running')
  minionid = data['id']
  DATA = data['data']
  hv_name = DATA['HYPERVISOR_HOST']
  log.info('sominion_setup_reactor: DATA: %s' % DATA)

  # Build the base command
  cmd = "NODETYPE=" + DATA['NODETYPE'] + " /usr/sbin/so-minion -o=addVM -m=" + minionid + " -n=" + DATA['MNIC'] + " -i=" + DATA['MAINIP'] + " -c=" + str(DATA['CPUCORES']) + " -d='" + DATA['NODE_DESCRIPTION'] + "'"
  
  # Add optional arguments only if they exist in DATA
  if 'CORECOUNT' in DATA:
    cmd += " -C=" + str(DATA['CORECOUNT'])
    
  if 'INTERFACE' in DATA:
    cmd += " -a=" + DATA['INTERFACE']
  
  if 'ES_HEAP_SIZE' in DATA:
    cmd += " -e=" + DATA['ES_HEAP_SIZE']
  
  if 'LS_HEAP_SIZE' in DATA:
    cmd += " -l=" + DATA['LS_HEAP_SIZE']

  if 'LSHOSTNAME' in DATA:
    cmd += " -L=" + DATA['LSHOSTNAME']
  
  log.info('sominion_setup_reactor: Command: %s' % cmd)
  rc = call(cmd, shell=True)

  log.info('sominion_setup_reactor: rc: %s' % rc)

  return {}
