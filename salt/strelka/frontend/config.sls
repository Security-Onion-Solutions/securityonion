# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}

include:
  - strelka.config
  - strelka.frontend.sostatus

# Check to see if Strelka frontend port is available
strelkaportavailable:
    cmd.run:
      - name: netstat -utanp | grep ":57314" | grep -qvE 'docker|TIME_WAIT' && PROCESS=$(netstat -utanp | grep ":57314" | uniq) && echo "Another process ($PROCESS) appears to be using port 57314.  Please terminate this process, or reboot to ensure a clean state so that Strelka can start properly." && exit 1 || exit 0

frontend_config:
  file.managed:
    - name: /opt/so/conf/strelka/frontend/frontend.yaml
    - source: salt://strelka/frontend/files/frontend.yaml.jinja
    - template: jinja
    - user: 939
    - group: 939
    - makedirs: True
    - defaults:
        FRONTENDCONFIG: {{ STRELKAMERGED.frontend.config }}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
