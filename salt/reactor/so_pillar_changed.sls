# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Fires for every event tagged 'so/pillar/changed'. Source of those events
# is the pg_notify_pillar engine on the salt-master, which in turn drains
# so_pillar.change_queue (populated by the AFTER trigger on
# so_pillar.pillar_entry — see 008_change_notify.sql).
#
# All routing logic — which pillar paths reload which services on which
# targets — lives in orch.so_pillar_reload so it stays editable as one
# YAML table without touching reactor wiring.

{% set payload = data.get('data', {}) %}
{% do salt.log.info('so_pillar_changed reactor: %s' % payload) %}

so_pillar_dispatch_reload:
  runner.state.orchestrate:
    - args:
      - mods: orch.so_pillar_reload
      - pillar:
          so_pillar_change:
            scope: {{ payload.get('scope') | json }}
            role_name: {{ payload.get('role_name') | json }}
            minion_id: {{ payload.get('minion_id') | json }}
            changes: {{ payload.get('changes', []) | json }}
