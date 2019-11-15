from os import path
import subprocess

def check():

  os = __grains__['os']
  cmd = 'needs-restarting -r > /dev/null 2>&1'

  if os == 'Ubuntu':
    if path.exists('/var/run/reboot-required'):
      retval = 'True'
    else:
      retval = 'False'

  elif os == 'CentOS':
    try:
      needs_restarting = subprocess.check_call(cmd.split(), shell=True)
    except subprocess.CalledProcessError:
      retval = 'True'
    retval = 'False'

  else:
    retval = 'Unsupported OS: %s' % os

  return retval
