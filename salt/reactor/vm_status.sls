# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% do salt.log.debug('vm_status_reactor: Running') %}
{% do salt.log.debug('vm_status_reactor: tag: ' ~ tag) %}

{# Remove all the nasty characters that exist in this data #}
{% if tag.startswith('salt/cloud/') and tag.endswith('/deploying') %}

{%   set event_data = {
      "_stamp": data._stamp,
      "event": data.event,
      "kwargs": {
          "cloud_grains": data.kwargs.cloud_grains
      }
} %}

{% else %}

{%   set event_data = data %}

{% endif %}

{% do salt.log.debug('vm_status_reactor: Received data: ' ~ event_data|json|string) %}

update_hypervisor:
  runner.state.orchestrate:
    - args:
      - mods: orch.dyanno_hypervisor
      - pillar:
          tag: {{ tag }}
          data: {{ event_data }}

{% do salt.log.debug('vm_status_reactor: Completed') %}
