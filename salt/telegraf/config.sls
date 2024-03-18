# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'telegraf/map.jinja' import TELEGRAFMERGED %}

include:
  - ssl

# add Telegraf to monitor all the things
tgraflogdir:
  file.directory:
    - name: /opt/so/log/telegraf
    - makedirs: True
    - user: 939
    - group: 939
    - recurse:
      - user
      - group
      
tgrafetcdir:
  file.directory:
    - name: /opt/so/conf/telegraf/etc
    - makedirs: True

tgrafetsdir:
  file.directory:
    - name: /opt/so/conf/telegraf/scripts
    - makedirs: True

{% for script in TELEGRAFMERGED.scripts[GLOBALS.role.split('-')[1]] %}
tgraf_sync_script_{{script}}:
  file.managed:
    - name: /opt/so/conf/telegraf/scripts/{{script}}
    - user: root
    - group: 939
    - mode: 770
    - template: jinja
    - source: salt://telegraf/scripts/{{script}}
    - defaults:
        GLOBALS: {{ GLOBALS }}
{% endfor %}

telegraf_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://telegraf/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#telegraf_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://telegraf/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - mode: 660
    - template: jinja
    - source: salt://telegraf/etc/telegraf.conf
    - show_changes: False
    - defaults:
        GLOBALS: {{ GLOBALS }}
        TELEGRAFMERGED: {{ TELEGRAFMERGED }}

# this file will be read by telegraf to send node details (management interface, monitor interface, etc)
# into influx
node_config:
  file.managed:
    - name: /opt/so/conf/telegraf/node_config.json
    - source: salt://telegraf/node_config.json.jinja
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
