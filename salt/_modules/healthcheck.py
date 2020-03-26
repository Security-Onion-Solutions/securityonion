#!py

import logging
import sys

allowed_functions = ['zeek']
states_to_apply = []


def apply_states():

  if states_to_apply:
    states = ','.join(states_to_apply)
    __salt__['state.apply'](states)


def docker_restart(container, state):
  
  try:
    stopdocker = __salt__['docker.rm'](container, 'stop=True')
  except Exception as e:
    logging.error('healthcheck module: %s' % e)
  

def run(checks):
  if checks:
    checks = checks.split(',')
  else:  
    checks = __salt__['pillar.get']('healthcheck:checks', {})
  
  for check in checks:
    if check in allowed_functions:
      check = getattr(sys.modules[__name__], check)
      check()
    else:
      logging.warning('healthcheck module: attempted to run function %s' % check)


  return checks


def zeek():

  retcode = __salt__['zeekctl.status'](verbose=False)
  logging.info('zeekctl.status retcode: %i' % retcode)
  if retcode:
    docker_restart('so-zeek')
    states_to_apply.append('zeek')
    zeek_restarted = True
  else:
    zeek_restarted = False

  __salt__['telegraf.send']('healthcheck zeek_restarted=%s' % str(zeek_restarted))
  return 'zeek_restarted: %s' % str(zeek_restarted)

apply_states()
