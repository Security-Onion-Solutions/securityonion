# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set proxy = salt['pillar.get']('manager:proxy') %}

include:
  - idstools.config
  - idstools.sostatus

so-idstools:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-idstools:{{ GLOBALS.so_version }}
    - hostname: so-idstools
    - user: socore
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-idstools'].ip }}
    {% if proxy %}
    - environment:
      - http_proxy={{ proxy }}
      - https_proxy={{ proxy }}
      - no_proxy={{ salt['pillar.get']('manager:no_proxy') }}
      {% if DOCKER.containers['so-idstools'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-idstools'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    {% elif DOCKER.containers['so-idstools'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-idstools'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - binds:
      - /opt/so/conf/idstools/etc:/opt/so/idstools/etc:ro
      - /opt/so/rules/nids/suri:/opt/so/rules/nids/suri:rw
      - /nsm/rules/:/nsm/rules/:rw
    {% if DOCKER.containers['so-idstools'].custom_bind_mounts %}
      {% for BIND in DOCKER.containers['so-idstools'].custom_bind_mounts %}
      - {{ BIND }}
      {% endfor %}
    {% endif %}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% if DOCKER.containers['so-idstools'].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers['so-idstools'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: idstoolsetcsync

delete_so-idstools_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-idstools$

so-rule-update:
  cron.present:
    - name: /usr/sbin/so-rule-update > /opt/so/log/idstools/download_cron.log 2>&1
    - identifier: so-rule-update
    - user: root
    - minute: '1'
    - hour: '7'

# order this last to give so-idstools container time to be ready
run_so-rule-update:
  cmd.run:
    - name: '/usr/sbin/so-rule-update > /opt/so/log/idstools/download_idstools_state.log 2>&1'
    - require:
      - docker_container: so-idstools
    - onchanges:
      - file: idstoolsetcsync
      - file: synclocalnidsrules
    - order: last

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
