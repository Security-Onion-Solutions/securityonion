#!py

def status():
  return __salt__['cmd.run']('/sbin/so-status')