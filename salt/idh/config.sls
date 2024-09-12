# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'idh/opencanary_config.map.jinja' import RESTRICTIDHSERVICES %}
{%   from 'idh/opencanary_config.map.jinja' import OPENCANARYCONFIG %}

include:
  - idh.openssh.config
  - firewall

# If True, block IDH Services from accepting connections on Managment IP
{% if RESTRICTIDHSERVICES %}
  {% from 'idh/opencanary_config.map.jinja' import IDH_SERVICES %}

  {% for service in IDH_SERVICES %}
  {% if service in ["smnp","ntp", "tftp"] %}
    {% set proto = 'udp' %}
  {% else %}
    {% set proto = 'tcp' %}
  {% endif %}
block_mgt_ip_idh_services_{{ proto }}_{{ OPENCANARYCONFIG[service~'_x_port'] }} :
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: DROP
    - position: 1
    - proto:  {{ proto }}
    - dport: {{ OPENCANARYCONFIG[service~'_x_port'] }}
    - destination: {{ GLOBALS.node_ip }}
  {% endfor %}
{% endif %}

# Create a config directory
idhconfdir:
  file.directory:
    - name: /opt/so/conf/idh
    - user: 939
    - group: 939
    - makedirs: True

idhhttpskinsdir:
  file.directory:
    - name: /opt/so/conf/idh/http-skins
    - user: 939
    - group: 939
    - makedirs: True

# Copy over default http skins
idhhttpskins:
  file.recurse:
    - name: /opt/so/conf/idh/http-skins
    - user: 939
    - group: 939
    - source: salt://idh/skins/http/opencanary

# Copy over custom http skins
idhcustomhttpskins:
  file.recurse:
    - name: /opt/so/conf/idh/http-skins
    - user: 939
    - group: 939
    - source: salt://idh/skins/http/custom

# Create a log directory
idhlogdir:
  file.directory:
    - name: /nsm/idh
    - user: 939
    - group: 939
    - makedirs: True

opencanary_config:
  file.managed:
    - name: /opt/so/conf/idh/opencanary.conf
    - source: salt://idh/idh.conf.jinja
    - template: jinja
    - defaults:
        OPENCANARYCONFIG: {{ OPENCANARYCONFIG }}

idh_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://idh/tools/sbin
    - user: 934
    - group: 939
    - file_mode: 755

#idh_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://idh/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
