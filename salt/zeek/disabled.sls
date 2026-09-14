# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - zeek.sostatus
  
# Stop first so the entrypoint's SIGTERM trap can archive the final logs; docker_container.absent
# with force is a 'docker rm -f', which never delivers SIGTERM. force stays so the state still
# converges if the stop overruns.
so-zeek_stopped:
  docker_container.stopped:
    - name: so-zeek
    - error_on_absent: False

so-zeek:
  docker_container.absent:
    - force: True
    - require:
      - docker_container: so-zeek_stopped

so-zeek_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-zeek$

zeekpacketlosscron:
  cron.absent:
    - identifier: zeekpacketlosscron
    - user: root

zeekctlcron:
  cron.absent:
    - identifier: zeekctlcron
    - user: root

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
