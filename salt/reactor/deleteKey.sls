# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

remove_key:
  wheel.key.delete:
    - args:
      - match: {{ data['name'] }}

{{ data['name'] }}_pillar_clean:
  runner.state.orchestrate:
    - args:
      - mods: orch.vm_pillar_clean
      - pillar:
          vm_name: {{ data['name'] }}

{% do salt.log.info('deleteKey reactor: deleted minion key: %s' % data['name']) %}
