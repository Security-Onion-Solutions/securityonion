#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import os
import re
import shlex
import subprocess

log = logging.getLogger(__name__)

SO_MINION = '/usr/sbin/so-minion'

_NODETYPE_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,31}$')
_MINIONID_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')
_HOSTPART_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')
_IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$'
)
_HEAP_RE = re.compile(r'^\d{1,6}[kKmMgG]?$')


def _check(name, value, pattern):
  s = str(value)
  if not pattern.match(s):
    raise ValueError("sominion_setup_reactor: refusing unsafe %s=%r" % (name, value))
  return s


def run():
  log.info('sominion_setup_reactor: Running')
  minionid = data['id']
  DATA = data['data']
  log.info('sominion_setup_reactor: DATA: %s' % DATA)

  nodetype = _check('NODETYPE', DATA['NODETYPE'], _NODETYPE_RE)

  argv = [
    SO_MINION,
    '-o=addVM',
    '-m=' + _check('minionid', minionid,        _MINIONID_RE),
    '-n=' + _check('MNIC',     DATA['MNIC'],    _HOSTPART_RE),
    '-i=' + _check('MAINIP',   DATA['MAINIP'],  _IPV4_RE),
    '-c=' + str(int(DATA['CPUCORES'])),
    '-d=' + str(DATA['NODE_DESCRIPTION']),
  ]

  if 'CORECOUNT' in DATA:
    argv.append('-C=' + str(int(DATA['CORECOUNT'])))

  if 'INTERFACE' in DATA:
    argv.append('-a=' + _check('INTERFACE', DATA['INTERFACE'], _HOSTPART_RE))

  if 'ES_HEAP_SIZE' in DATA:
    argv.append('-e=' + _check('ES_HEAP_SIZE', DATA['ES_HEAP_SIZE'], _HEAP_RE))

  if 'LS_HEAP_SIZE' in DATA:
    argv.append('-l=' + _check('LS_HEAP_SIZE', DATA['LS_HEAP_SIZE'], _HEAP_RE))

  if 'LSHOSTNAME' in DATA:
    argv.append('-L=' + _check('LSHOSTNAME', DATA['LSHOSTNAME'], _HOSTPART_RE))

  env = os.environ.copy()
  env['NODETYPE'] = nodetype

  log.info(
    'sominion_setup_reactor: argv: %s (NODETYPE=%s)',
    ' '.join(shlex.quote(a) for a in argv),
    shlex.quote(nodetype),
  )
  rc = subprocess.call(argv, shell=False, env=env)

  log.info('sominion_setup_reactor: rc: %s' % rc)

  return {}
