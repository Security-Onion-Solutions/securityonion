# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
include:
  - salt.minion
  - kibana.secrets
  - manager.sync_es_users
  - manager.elasticsearch

socore_own_saltstack:
  file.directory:
    - name: /opt/so/saltstack
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

strelka_yara_update:
  cron.present:
    - user: root
    - name: '/usr/sbin/so-yara-update >> /nsm/strelka/log/yara-update.log 2>&1'
    - hour: '7'
    - minute: '1'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
