#!py

import logging

def docker_restart(container, state):
  stopdocker = __salt__['docker.rm'](container, 'force=True')
  __salt__['state.apply'](state)
  


def zeek():

  retcode = __salt__['zeekctl.status'](verbose=False)
  logging.info('zeekctl.status retcode: %i' % retcode)
  if retcode:
    docker_restart('so-zeek', 'zeek')
    zeek_restarted = True
  else:
    zeek_restarted = False

  __salt__['telegraf.send']('healthcheck zeek_restarted: %s' % str(zeek_restarted))
  return 'zeek_restarted: %s' % str(zeek_restarted)
