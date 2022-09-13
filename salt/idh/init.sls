# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MAININT = salt['pillar.get']('host:mainint') %}
{% set MAINIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% set RESTRICTIDHSERVICES = salt['pillar.get']('idh:restrict_management_ip', False) %}

include:
  - idh.openssh.config
  - firewall


# If True, block IDH Services from accepting connections on Managment IP
{% if RESTRICTIDHSERVICES %}
  {% from 'idh/opencanary_config.map.jinja' import OPENCANARYCONFIG %}
  {% set idh_services = salt['pillar.get']('idh:services', []) %}

  {% for service in idh_services %}
  {% if service in ["smnp","ntp", "tftp"] %}
    {% set proto = 'udp' %}
  {% else %}
    {% set proto = 'tcp' %}
  {% endif %}
block_mgt_ip_idh_services_{{ proto }}_{{ OPENCANARYCONFIG[service~'.port'] }} :
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: DROP
    - position: 1
    - proto:  {{ proto }}
    - dport: {{ OPENCANARYCONFIG[service~'.port'] }}
    - destination: {{ MAINIP }}
  {% endfor %}
{% endif %}

# Create a config directory
temp:
  file.directory:
    - name: /opt/so/conf/idh
    - user: 939
    - group: 939
    - makedirs: True

# Create a log directory
configdir:
  file.directory:
    - name: /nsm/idh
    - user: 939
    - group: 939
    - makedirs: True

{% from 'idh/opencanary_config.map.jinja' import OPENCANARYCONFIG with context %}
opencanary_config:
  file.managed:
    - name: /opt/so/conf/idh/opencanary.conf
    - source: salt://idh/idh.conf.jinja
    - template: jinja
    - defaults:
        OPENCANARYCONFIG: {{ OPENCANARYCONFIG }}

so-idh:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-idh:{{ VERSION }}
    - name: so-idh
    - detach: True
    - network_mode: host
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro
    - watch:
      - file: opencanary_config
    - require:
      - file: opencanary_config

append_so-idh_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-idh

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
