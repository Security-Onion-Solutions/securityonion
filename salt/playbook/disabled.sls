# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - playbook.sostatus
  
so-playbook:
  docker_container.absent:
    - force: True

so-playbook_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-playbook$

so-playbook-sync_cron:
  cron.absent:
    - identifier: so-playbook-sync_cron
    - user: root

so-playbook-ruleupdate_cron:
  cron.absent:
    - identifier: so-playbook-ruleupdate_cron
    - user: root

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
