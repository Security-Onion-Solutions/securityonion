# -*- coding: utf-8 -*-

import logging
from time import sleep
from os import remove

log = logging.getLogger(__name__)

def start(interval=30):
  log.info("checkmine engine started")
  minionid = __grains__['id']
  while True:
    try:
      ca_crt = __salt__['saltutil.runner']('mine.get', tgt=minionid, fun='x509.get_pem_entries')[minionid]['/etc/pki/ca.crt']
      log.info('Successfully queried Salt mine for the CA.')
    except:
      log.error('Could not pull CA from the Salt mine.')
      log.info('Removing /var/cache/salt/master/minions/%s/mine.p to force Salt mine to be repopulated.' % minionid)
      try:
        remove('/var/cache/salt/master/minions/%s/mine.p' % minionid)
        log.info('Removed /var/cache/salt/master/minions/%s/mine.p' % minionid)
      except FileNotFoundError:
        log.error('/var/cache/salt/master/minions/%s/mine.p does not exist' % minionid)

      __salt__['mine.send'](name='x509.get_pem_entries', glob_path='/etc/pki/ca.crt')
      log.warning('Salt mine repopulated with /etc/pki/ca.crt')

    sleep(interval)