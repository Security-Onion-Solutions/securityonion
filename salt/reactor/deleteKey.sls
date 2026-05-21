#!py

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import logging
import re

log = logging.getLogger(__name__)

_VMNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')


def run():
  name = data.get('name', '')
  if not _VMNAME_RE.match(str(name)):
    log.error("deleteKey reactor: refusing unsafe name=%r", name)
    return {}

  log.info("deleteKey reactor: deleted minion key: %s", name)

  return {
    'remove_key': {
      'wheel.key.delete': [
        {'args': [
          {'match': name},
        ]},
      ],
    },
    '%s_pillar_clean' % name: {
      'runner.state.orchestrate': [
        {'args': [
          {'mods': 'orch.vm_pillar_clean'},
          {'pillar': {'vm_name': name}},
        ]},
      ],
    },
  }
