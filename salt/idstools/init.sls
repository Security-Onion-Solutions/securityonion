# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% set proxy = salt['pillar.get']('manager:proxy') %}

include:
  - idstools.sync_files

# IDSTools Setup

idstoolslogdir:
  file.directory:
    - name: /opt/so/log/idstools
    - user: 939
    - group: 939
    - makedirs: True

so-ruleupdatecron:
  cron.present:
    - name: /usr/sbin/so-rule-update > /opt/so/log/idstools/download.log 2>&1
    - user: root
    - minute: '1'
    - hour: '7'

so-idstools:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-idstools:{{ GLOBALS.so_version }}
    - hostname: so-idstools
    - user: socore
    - networks:
      - sosnet:
        - ipv4_address: {{ DOCKER.containers['so-idstools'].ip }}
    {% if proxy %}
    - environment:
      - http_proxy={{ proxy }}
      - https_proxy={{ proxy }}
      - no_proxy={{ salt['pillar.get']('manager:no_proxy') }}
    {% endif %}
    - binds:
      - /opt/so/conf/idstools/etc:/opt/so/idstools/etc:ro
      - /opt/so/rules/nids:/opt/so/rules/nids:rw
    - watch:
      - file: idstoolsetcsync

append_so-idstools_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-idstools

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif%}
