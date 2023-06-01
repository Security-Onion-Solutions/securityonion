# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - nginx.config

soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus/sigma-import
    - user: 939
    - group: 939
    - makedirs: True

soctopus-sync:
  file.recurse:
    - name: /opt/so/conf/soctopus/templates
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

soctopusconf:
  file.managed:
    - name: /opt/so/conf/soctopus/SOCtopus.conf
    - source: salt://soctopus/files/SOCtopus.conf
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False
    - defaults:
        GLOBALS: {{ GLOBALS }}

soctopuslogdir:
  file.directory:
    - name: /opt/so/log/soctopus
    - user: 939
    - group: 939

playbookrulesdir:
  file.directory:
    - name: /opt/so/rules/elastalert/playbook
    - user: 939
    - group: 939
    - makedirs: True

playbookrulessync:
  file.recurse:
    - name: /opt/so/rules/elastalert/playbook
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

soctopus_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://soctopus/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#soctopus_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://soctopus/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
