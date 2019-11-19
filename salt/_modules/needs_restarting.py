from os import path
import subprocess

def check():

  os = __grains__['os']
  retval = 'False'

  if os == 'Ubuntu':
    if path.exists('/var/run/reboot-required'):
      retval = 'True'

  elif os == 'CentOS':
    cmd = 'needs-restarting -r > /dev/null 2>&1'
    
    try:
      needs_restarting = subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError:
      retval = 'True'

  else:
    retval = 'Unsupported OS: %s' % os

  return retval
