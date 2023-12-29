# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'telegraf/map.jinja' import TELEGRAFMERGED %}


include:
  - telegraf.config
  - telegraf.sostatus

so-telegraf:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-telegraf:{{ GLOBALS.so_version }}
    - user: 939
    - group_add: 939,920
    - environment:
      - HOST_PROC=/host/proc
      - HOST_ETC=/host/etc
      - HOST_SYS=/host/sys
      - HOST_MOUNT_PREFIX=/host
      - GODEBUG=x509ignoreCN=0
      {% if DOCKER.containers['so-telegraf'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-telegraf'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - network_mode: host
    - init: True
    - binds:
      - /opt/so/log/telegraf:/var/log/telegraf:rw
      - /opt/so/conf/telegraf/etc/telegraf.conf:/etc/telegraf/telegraf.conf:ro
      - /opt/so/conf/telegraf/node_config.json:/etc/telegraf/node_config.json:ro
      - /var/run/utmp:/var/run/utmp:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /:/host/root:ro
      - /sys:/host/sys:ro
      - /proc:/host/proc:ro
      - /nsm:/host/nsm:ro
      - /etc:/host/etc:ro
      {% if GLOBALS.role in ['so-manager', 'so-eval', 'so-managersearch' ] %}
      - /etc/pki/ca.crt:/etc/telegraf/ca.crt:ro
      {% else %}
      - /etc/pki/tls/certs/intca.crt:/etc/telegraf/ca.crt:ro
      {% endif %}
      - /etc/pki/influxdb.crt:/etc/telegraf/telegraf.crt:ro
      - /etc/pki/influxdb.key:/etc/telegraf/telegraf.key:ro
      - /opt/so/conf/telegraf/scripts:/scripts:ro
      - /opt/so/log/stenographer:/var/log/stenographer:ro
      - /opt/so/log/suricata:/var/log/suricata:ro
      - /opt/so/log/raid:/var/log/raid:ro
      - /opt/so/log/sostatus:/var/log/sostatus:ro
      - /opt/so/log/salt:/var/log/salt:ro
      {% if DOCKER.containers['so-telegraf'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-telegraf'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-telegraf'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-telegraf'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: tgrafconf
      - file: node_config
    {% for script in TELEGRAFMERGED.scripts[GLOBALS.role.split('-')[1]] %}
      - file: tgraf_sync_script_{{script}}
    {% endfor %}
    - require: 
      - file: tgrafconf
      - file: node_config
      {% if GLOBALS.role in ['so-manager', 'so-eval', 'so-managersearch' ] %}
      - x509: pki_public_ca_crt
      {% else %}
      - x509: trusttheca
      {% endif %}
      - x509: influxdb_crt
      - x509: influxdb_key

delete_so-telegraf_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-telegraf$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
