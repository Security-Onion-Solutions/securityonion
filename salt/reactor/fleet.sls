#!py

import fileinput
import sys

def run():
  MINIONID = data['id']
  TIMESTAMP = data['_stamp']
  ACTION = data['action']
  STATICFILE = '/opt/so/saltstack/pillar/static.sls'

#sed -i 's/fleetsetup: 0/fleetsetup: 1/g' /opt/so/saltstack/pillar/static.sls
cp /opt/so/conf/fleet/packages/launcher.* /opt/so/saltstack/salt/launcher/packages/

  if ACTION == 'enablefleet':
    for line in fileinput.input(STATICFILE, inplace=1):
      if 'fleetsetup: 0' in line:
        line = line.replace('fleetsetup: 0', 'fleetsetup: 1')
        



  return {}
