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
  STATICFILE = '/opt/so/saltstack/pillar/static.sls'
  AUTHFILE = '/opt/so/saltstack/pillar/auth.sls'

  if MINIONID.split('_')[-1] in ['master','eval','fleet']:
    if ACTION == 'enablefleet':
      logging.info('so/fleet enablefleet reactor')
      
      # Enable Fleet
      for line in fileinput.input(STATICFILE, inplace=True):
        if ROLE == 'so-fleet':
          line = re.sub(r'fleet_node: \S*', f"fleet_node: True", line.rstrip())
        else:
          line = re.sub(r'fleet_master: \S*', f"fleet_master: True", line.rstrip())
        print(line) 

      # Update the enroll secret
      for line in fileinput.input(AUTHFILE, inplace=True):
        line = re.sub(r'fleet_enroll-secret: \S*', f"fleet_enroll-secret: {ESECRET}", line.rstrip())
        print(line)       

    if ACTION == 'genpackages':
      logging.info('so/fleet genpackages reactor')

      # Run Docker container that will build the packages
      gen_packages = subprocess.run(["docker", "run","--rm", "--mount", "type=bind,source=/opt/so/saltstack/salt/fleet/packages,target=/output", \
         "--mount", "type=bind,source=/etc/ssl/certs/intca.crt,target=/var/launcher/launcher.crt", "docker.io/soshybridhunter/so-fleet-launcher:HH1.1.0", \
         f"{ESECRET}", f"{HOSTNAME}:8090"], stdout=subprocess.PIPE, encoding='ascii')  
      
      # Update the 'packages-built' timestamp on the webpage (stored in the static pillar)
      for line in fileinput.input(STATICFILE, inplace=True):
        line = re.sub(r'fleet_packages-timestamp: \S*', f"fleet_packages-timestamp: {strftime('%Y-%m-%d-%H:%M', gmtime())}", line.rstrip())
        print(line)  

  return {}
