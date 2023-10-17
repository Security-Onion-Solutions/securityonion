# -*- coding: utf-8 -*-

import logging
from time import sleep
import os
import salt.client

log = logging.getLogger(__name__)
local = salt.client.LocalClient()

def start(interval=60):
    def mine_delete(minion, func):
      log.warning('checkmine engine: deleting mine function %s for %s' % (func, minion))
      local.cmd(minion, 'mine.delete', [func])

    def mine_flush(minion):
        log.warning('checkmine engine: flushing mine cache for %s' % minion)
        local.cmd(minion, 'mine.flush')

    def mine_update(minion):
        log.warning('checkmine engine: updating mine cache for %s' % minion)
        local.cmd(minion, 'mine.update')

    log.info("checkmine engine: started")
    cachedir = __opts__['cachedir']
    while True:
        log.debug('checkmine engine: checking which minions are alive')
        manage_alived = __salt__['saltutil.runner']('manage.alived', show_ip=False)
        log.debug('checkmine engine: alive minions: %s' % ' , '.join(manage_alived))

        for minion in manage_alived:
            mine_path = os.path.join(cachedir, 'minions', minion, 'mine.p')
            # it is possible that a minion is alive, but hasn't created a mine file yet
            try:
                mine_size = os.path.getsize(mine_path)
                log.debug('checkmine engine: minion: %s mine_size: %i' % (minion, mine_size))
                # For some reason the mine file can be corrupt and only be 1 byte in size
                if mine_size == 1:
                    log.error('checkmine engine: found %s to be 1 byte' % mine_path)
                    mine_flush(minion)
                    mine_update(minion)
                    continue
            except FileNotFoundError:
                log.warning('checkmine engine: minion: %s %s does not exist' % (minion, mine_path))
                mine_flush(minion)
                mine_update(minion)
                continue

            # Update the mine if the ip in the mine doesn't match returned from manage.alived
            network_ip_addrs = __salt__['saltutil.runner']('mine.get', tgt=minion, fun='network.ip_addrs')
            try:
                mine_ip = network_ip_addrs[minion][0]
                log.debug('checkmine engine: found minion %s has mine_ip: %s' % (minion, mine_ip))
            except IndexError:
                log.error('checkmine engine: found minion %s does\'t have a mine_ip' % (minion))
                mine_delete(minion, 'network.ip_addrs')
                mine_update(minion)

        sleep(interval)
