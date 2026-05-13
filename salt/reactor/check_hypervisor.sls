# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set hid = data['id'] %}
{% if hid|regex_match('^([A-Za-z0-9._-]{1,253})$')
   and hid.endswith('_hypervisor')
   and data['result'] == True %}

{%   if data['act'] == 'accept' %}
check_and_trigger:
  runner.setup_hypervisor.setup_environment:
    - minion_id: {{ hid }}
{%   endif %}

{%   if data['act'] == 'delete' %}
delete_hypervisor:
  runner.state.orchestrate:
    - args:
      - mods: orch.delete_hypervisor
      - pillar:
          minion_id: {{ hid }}
{%   endif %}

{% endif %}
