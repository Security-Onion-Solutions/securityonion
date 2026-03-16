import subprocess

def check():

  retval = 'False'

  cmd = 'needs-restarting -r > /dev/null 2>&1'

  try:
    needs_restarting = subprocess.check_call(cmd, shell=True)
  except subprocess.CalledProcessError:
    retval = 'True'

  return retval
