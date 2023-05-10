# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}

include:
  - strelka.config
  - strelka.manager.sostatus

manager_config:
  file.managed:
    - name: /opt/so/conf/strelka/manager/manager.yaml
    - source: salt://strelka/manager/files/manager.yaml.jinja
    - template: jinja
    - user: 939
    - group: 939
    - makedirs: True
    - defaults:
        MANAGERCONFIG: {{ STRELKAMERGED.manager.config }}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
