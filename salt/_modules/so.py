#!py

def status():
  return __salt__['cmd.run']('/usr/sbin/so-status')