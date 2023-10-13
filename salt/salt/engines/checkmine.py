# -*- coding: utf-8 -*-

import logging
from time import sleep
import os
import salt.client

log = logging.getLogger(__name__)
local = salt.client.LocalClient()

def start(interval=10):
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
        manage_alived = __salt__['saltutil.runner']('manage.alived', show_ip=True)
        log.debug('checkmine engine: alive minions: %s' % ' , '.join(manage_alived))

        for minion in manage_alived:
            mine_path = os.path.join(cachedir, 'minions', minion, 'mine.p')
            mine_size = os.path.getsize(mine_path)
            log.debug('checkmine engine: minion: %s mine_size: %i' % (minion, mine_size))
            # For some reason the mine file can be corrupt and only be 1 byte in size
            if mine_size == 1:
                log.error('checkmine engine: found %s to be 1 byte' % mine_path)
                mine_flush(minion)
                mine_update(minion)
            # Update the mine if the ip in the mine doesn't match returned from manage.alived
            else:
                network_ip_addrs = __salt__['saltutil.runner']('mine.get', tgt=minion, fun='network.ip_addrs')
                mine_ip = network_ip_addrs[minion][0]
                log.debug('checkmine engine: minion: %s mine_ip: %s' % (minion, mine_ip))
                manage_alived_ip = manage_alived[minion]
                log.debug('checkmine engine: minion: %s managed_alived_ip: %s' % (minion, manage_alived_ip))
                if mine_ip != manage_alived_ip:
                    log.error('checkmine engine: found minion %s has manage_alived_ip %s but a mine_ip of %s' % (minion, manage_alived_ip, mine_ip))
                    mine_flush(minion)
                    mine_update(minion)

        sleep(interval)
