import logging


def status():

 cmd = "runuser -l zeek -c '/opt/zeek/bin/zeekctl status'"
 retval = __salt__['docker.run']('so-zeek', cmd)
 logging.info('zeekctl_module: zeekctl.status retval: %s' % retval)

 return retval


def beacon(config):

  retval = []

  is_enabled = __salt__['healthcheck.is_enabled']()
  logging.info('zeek_beacon: healthcheck_is_enabled: %s' % is_enabled)

  if is_enabled:
    zeekstatus = status().lower().split(' ')
    logging.info('zeek_beacon: zeekctl.status: %s' % str(zeekstatus))
    if 'stopped' in zeekstatus or 'crashed' in zeekstatus or 'error' in zeekstatus or 'error:' in zeekstatus:
     zeek_restart = True
    else:
     zeek_restart = False

    __salt__['telegraf.send']('healthcheck zeek_restart=%s' % str(zeek_restart))
    retval.append({'zeek_restart': zeek_restart})
    logging.info('zeek_beacon: retval: %s' % str(retval))

  return retval

