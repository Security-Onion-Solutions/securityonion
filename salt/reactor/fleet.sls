#!py

from time import gmtime, strftime
import fileinput
import logging
import re
import subprocess

def run():
  MINIONID = data['id']
  ACTION = data['data']['action']
  HOSTNAME = data['data']['hostname']
  ROLE = data['data']['role']
  ESECRET = data['data']['enroll-secret']
  MAINIP = data['data']['mainip']

  STATICFILE = '/opt/so/saltstack/pillar/static.sls'
  SECRETSFILE = '/opt/so/saltstack/pillar/secrets.sls'

  if MINIONID.split('_')[-1] in ['master','eval','fleet','mastersearch']:
    if ACTION == 'enablefleet':
      logging.info('so/fleet enablefleet reactor')

      # Enable Fleet
      for line in fileinput.input(STATICFILE, inplace=True):
        if ROLE == 'so-fleet':
          line = re.sub(r'fleet_node: \S*', f"fleet_node: True", line.rstrip())
        else:
          line = re.sub(r'fleet_master: \S*', f"fleet_master: True", line.rstrip())
        print(line) 

      # Update the enroll secret in the secrets pillar
      for line in fileinput.input(SECRETSFILE, inplace=True):
        line = re.sub(r'fleet_enroll-secret: \S*', f"fleet_enroll-secret: {ESECRET}", line.rstrip())
        print(line)      

        # Update the Fleet host in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_hostname: \S*', f"fleet_hostname: {HOSTNAME}", line.rstrip())
        print(line)  

        # Update the Fleet IP in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_ip: \S*', f"fleet_ip: {MAINIP}", line.rstrip())
        print(line)   

    if ACTION == 'genpackages':
      logging.info('so/fleet genpackages reactor')

      PACKAGEVERSION = data['data']['current-package-version']
      MASTER = data['data']['master']
      
      # Increment the package version by 1
      PACKAGEVERSION += 1

      # Run Docker container that will build the packages
      gen_packages = subprocess.run(["docker", "run","--rm", "--mount", "type=bind,source=/opt/so/saltstack/salt/fleet/packages,target=/output", \
         "--mount", "type=bind,source=/etc/ssl/certs/intca.crt,target=/var/launcher/launcher.crt", f"{ MASTER }:5000/soshybridhunter/so-fleet-launcher:HH1.2.1", \
         f"{ESECRET}", f"{HOSTNAME}:8090", f"{PACKAGEVERSION}.1.1"], stdout=subprocess.PIPE, encoding='ascii')  
      
      # Update the 'packages-built' timestamp on the webpage (stored in the static pillar)
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_packages-timestamp: \S*', f"fleet_packages-timestamp: {strftime('%Y-%m-%d-%H:%M', gmtime())}", line.rstrip())
        print(line)

        # Update the Fleet Osquery package version in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_packages-version: \S*', f"fleet_packages-version: {PACKAGEVERSION}", line.rstrip())
        print(line)

      # Copy over newly-built packages
      copy_packages = subprocess.run(["salt-call", "state.apply","fleet"], stdout=subprocess.PIPE, encoding='ascii')      

  return {}
