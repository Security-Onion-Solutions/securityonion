# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from "hydra/map.jinja" import HYDRAMERGED %}

hydradir:
  file.directory:
    - name: /nsm/hydra
    - user: 928
    - group: 928
    - mode: 700
    - makedirs: True

hydradbdir:
  file.directory:
    - name: /nsm/hydra/db
    - user: 928
    - group: 928
    - mode: 700
    - makedirs: True

hydralogdir:
  file.directory:
    - name: /opt/so/log/hydra
    - user: 928
    - group: 928
    - makedirs: True

hydraconfig:
  file.managed:
    - name: /opt/so/conf/hydra/hydra.yaml
    - source: salt://hydra/files/hydra.yaml.jinja
    - user: 928
    - group: 928
    - mode: 600
    - template: jinja
    - makedirs: True
    - defaults:
        HYDRAMERGED: {{ HYDRAMERGED }}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
