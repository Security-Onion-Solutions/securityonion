# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if sls.split('.')[0] in allowed_states %}

# Add EA Group
elasticagentgroup:
  group.present:
    - name: elastic-agent
    - gid: 949

# Add EA user
elastic-agent:
  user.present:
    - uid: 949
    - gid: 949
    - home: /opt/so/conf/elastic-agent
    - createhome: False

elasticagentconfdir:
  file.directory:
    - name: /opt/so/conf/elastic-agent
    - user: 949
    - group: 939
    - makedirs: True

# Create config
create-elastic-agent-config:
  file.managed:
    - name: /opt/so/conf/elastic-agent/elastic-agent.yml
    - source: salt://elasticagent/files/elastic-agent.yml.jinja
    - user: 949
    - group: 939
    - template: jinja


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
