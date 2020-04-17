#!py

import logging
import salt.client
local = salt.client.LocalClient()

def run():
  minionid = data['id']
  zeek_restart = data['data']['zeek_restart']
  
  logging.info('zeek_reactor: zeek_need_restarted:%s on:%s' % (zeek_restart, minionid))
  if zeek_restart:
    local.cmd(minionid, 'healthcheck.docker_stop', ['so-zeek'])
    local.cmd(minionid, 'state.apply', ['zeek'])

#    __salt__['telegraf.send']('healthcheck zeek_restarted=%s' % str(zeek_restarted))

  return {}
