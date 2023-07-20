from os import path
import subprocess

def check():

  osfam = __grains__['os_family']
  retval = 'False'

  if osfam == 'Ubuntu':
    if path.exists('/var/run/reboot-required'):
      retval = 'True'

  elif 
    cmd = 'needs-restarting -r > /dev/null 2>&1'
    
    try:
      needs_restarting = subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError:
      retval = 'True'

  else:
    retval = 'Unsupported OS: %s' % os

  return retval
