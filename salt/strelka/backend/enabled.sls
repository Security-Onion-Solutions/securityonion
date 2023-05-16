# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - strelka.backend.config
  - strelka.backend.sostatus

strelka_backend:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-backend:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/backend/:/etc/strelka/:ro
      - /opt/so/conf/strelka/rules/:/etc/yara/:ro
    - name: so-strelka-backend
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-strelka-backend'].ip }}
    - command: strelka-backend
    - extra_hosts:
      - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
    - restart_policy: on-failure

delete_so-strelka-backend_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-strelka-backend$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
