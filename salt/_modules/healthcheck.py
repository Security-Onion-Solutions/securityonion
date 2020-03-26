#!py

import logging
import sys

allowed_functions = ['zeek']
states_to_apply = []


def apply_states(states=''):

  calling_func = sys._getframe().f_back.f_code.co_name
  logging.debug('healthcheck module: apply_states function caller: %s' % calling_func)

  if not states:
    states = ','.join(states_to_apply)
 
  if states: 
    logging.info('healthcheck module: apply_states states: %s' % str(states))
    __salt__['state.apply'](states)


def docker_restart(container):
  
  try:
    stopdocker = __salt__['docker.rm'](container, 'stop=True')
  except Exception as e:
    logging.error('healthcheck module: %s' % e)
  

def run(checks=''):
  
  retval = []
  calling_func = sys._getframe().f_back.f_code.co_name
  logging.debug('healthcheck module: run function caller: %s' % calling_func)
  
  if checks:
    checks = checks.split(',')
  else:  
    checks = __salt__['pillar.get']('healthcheck:checks', {})
  
  logging.debug('healthcheck module: run checks to be run: %s' % str(checks))
  for check in checks:
    if check in allowed_functions:
      retval.append(check)
      check = getattr(sys.modules[__name__], check)
      check()
    else:
      logging.warning('healthcheck module: attempted to run function %s' % check)

  # If you want to apply states at the end of the run,
  # be sure to append the state name to states_to_apply[]
  apply_states()

  return retval


def zeek():

  calling_func = sys._getframe().f_back.f_code.co_name
  logging.debug('healthcheck module: zeek function caller: %s' % calling_func)

  retcode = __salt__['zeekctl.status'](verbose=False)
  logging.debug('zeekctl.status retcode: %i' % retcode)
  if retcode:
    docker_restart('so-zeek')
    states_to_apply.append('zeek')
    zeek_restarted = True
  else:
    zeek_restarted = False

  if calling_func == 'execute':
    apply_states()

  __salt__['telegraf.send']('healthcheck zeek_restarted=%s' % str(zeek_restarted))
  return 'zeek_restarted: %s' % str(zeek_restarted)
