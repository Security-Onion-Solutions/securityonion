# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

# Add EA Group
elasticsagentgroup:
  group.present:
    - name: elastic-agent
    - gid: 947

# Add EA user
elastic-agent:
  user.present:
    - uid: 947
    - gid: 947
    - home: /opt/so/conf/elastic-fleet
    - createhome: False

elasticfleet_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin
    - user: 947
    - group: 939
    - file_mode: 755

elasticfleet_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://elasticfleet/tools/sbin_jinja
    - user: 947
    - group: 939 
    - file_mode: 755
    - template: jinja

eaconfdir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet
    - user: 947
    - group: 939
    - makedirs: True

eastatedir:
  file.directory:
    - name: /opt/so/conf/elastic-fleet/state
    - user: 947
    - group: 939
    - makedirs: True

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
