# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from "curator/map.jinja" import CURATORMERGED %}

# Create the group
curatorgroup:
  group.present:
    - name: curator
    - gid: 934

# Add user
curator:
  user.present:
    - uid: 934
    - gid: 934
    - home: /opt/so/conf/curator
    - createhome: False

# Create the log directory
curlogdir:
  file.directory:
    - name: /opt/so/log/curator
    - user: 934
    - group: 939

curactiondir:
  file.directory:
    - name: /opt/so/conf/curator/action
    - user: 934
    - group: 939
    - makedirs: True

actionconfs:
  file.recurse:
    - name: /opt/so/conf/curator/action
    - source: salt://curator/files/action
    - user: 934
    - group: 939
    - template: jinja
    - defaults:
        CURATORMERGED: {{ CURATORMERGED.elasticsearch.index_settings }}
        
curconf:
  file.managed:
    - name: /opt/so/conf/curator/curator.yml
    - source: salt://curator/files/curator.yml
    - user: 934
    - group: 939
    - mode: 660
    - template: jinja
    - show_changes: False

curator_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://curator/tools/sbin
    - user: 934
    - group: 939
    - file_mode: 755

curator_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://curator/tools/sbin_jinja
    - user: 934
    - group: 939 
    - file_mode: 755
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
