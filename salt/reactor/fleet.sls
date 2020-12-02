#!py

from time import gmtime, strftime
import fileinput
import logging
import re
import subprocess

def run():
  MINIONID = data['id']
  ACTION = data['data']['action']
  LOCAL_SALT_DIR = "/opt/so/saltstack/local"
  STATICFILE = f"{LOCAL_SALT_DIR}/pillar/global.sls"  
  SECRETSFILE = f"{LOCAL_SALT_DIR}/pillar/secrets.sls"

  if MINIONID.split('_')[-1] in ['manager','eval','fleet','managersearch','standalone']:
    if ACTION == 'enablefleet':
      logging.info('so/fleet enablefleet reactor')

      MAINIP = data['data']['mainip']
      ROLE = data['data']['role']
      HOSTNAME = data['data']['hostname']

      # Enable Fleet
      for line in fileinput.input(STATICFILE, inplace=True):
        if ROLE == 'so-fleet':
          line = re.sub(r'fleet_node: \S*', f"fleet_node: True", line.rstrip())
        else:
          line = re.sub(r'fleet_manager: \S*', f"fleet_manager: True", line.rstrip())
        print(line) 

      # Update the Fleet host in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_hostname: \S*', f"fleet_hostname: '{HOSTNAME}'", line.rstrip())
        print(line)  

      # Update the Fleet IP in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_ip: \S*', f"fleet_ip: '{MAINIP}'", line.rstrip())
        print(line)   

    if ACTION == 'update-enrollsecret':
      logging.info('so/fleet update-enrollsecret reactor')

      ESECRET = data['data']['enroll-secret']

      # Update the enroll secret in the secrets pillar
      if ESECRET != "":
        for line in fileinput.input(SECRETSFILE, inplace=True):
          line = re.sub(r'fleet_enroll-secret: \S*', f"fleet_enroll-secret: {ESECRET}", line.rstrip())
          print(line)


    if ACTION == 'genpackages':
      logging.info('so/fleet genpackages reactor')

      PACKAGEVERSION = data['data']['current-package-version']
      PACKAGEHOSTNAME = data['data']['package-hostname']
      MANAGER = data['data']['manager']
      VERSION = data['data']['version']
      ESECRET = data['data']['enroll-secret']
      IMAGEREPO = data['data']['imagerepo']
      
      # Increment the package version by 1
      PACKAGEVERSION += 1

      # Run Docker container that will build the packages
      gen_packages = subprocess.run(["docker", "run","--rm", "--mount", f"type=bind,source={LOCAL_SALT_DIR}/salt/fleet/packages,target=/output", \
         "--mount", "type=bind,source=/etc/ssl/certs/intca.crt,target=/var/launcher/launcher.crt", f"{ MANAGER }:5000/{ IMAGEREPO }/so-fleet-launcher:{ VERSION }", \
         f"{ESECRET}", f"{PACKAGEHOSTNAME}:8090", f"{PACKAGEVERSION}.1.1"], stdout=subprocess.PIPE, encoding='ascii')  
      
      # Update the 'packages-built' timestamp on the webpage (stored in the static pillar)
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_packages-timestamp: \S*', f"fleet_packages-timestamp: '{strftime('%Y-%m-%d-%H:%M', gmtime())}'", line.rstrip())
        print(line)

        # Update the Fleet Osquery package version in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_packages-version: \S*', f"fleet_packages-version: {PACKAGEVERSION}", line.rstrip())
        print(line)

      # Copy over newly-built packages
      copy_packages = subprocess.run(["salt-call", "state.apply","fleet"], stdout=subprocess.PIPE, encoding='ascii')    

    if ACTION == 'update_custom_hostname':
      logging.info('so/fleet update_custom_hostname reactor')

      CUSTOMHOSTNAME = data['data']['custom_hostname']
      
        # Update the Fleet host in the static pillar
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_custom_hostname:.*\n', f"fleet_custom_hostname: {CUSTOMHOSTNAME}", line.rstrip())
        print(line)  

  return {}
