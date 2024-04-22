# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   import_yaml 'kafka/defaults.yaml' as KAFKADEFAULTS %}

{% set process_x_roles = salt['pillar.get']('kafka:config:server:process_x_roles', KAFKADEFAULTS.kafka.config.server.process_x_roles, merge=true) %}

{# Send an event to the salt master at every highstate. Containing the minions process_x_roles.
    if no value is set for this minion then the default in kafka/defaults.yaml is used #}
push_event_to_master:
  event.send:
    - name: kafka/controllers_update
    - data:
        id: {{ grains['id'] }}
        process_x_roles: {{ process_x_roles }}
{% endif %}
