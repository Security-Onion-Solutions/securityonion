# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - strelka.manager.config
  - strelka.manager.sostatus

strelka_manager:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-manager:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/manager/:/etc/strelka/:ro
      {% if DOCKER.containers['so-strelka-manager'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-strelka-manager'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - name: so-strelka-manager
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-strelka-manager'].ip }}
    - command: strelka-manager
    - extra_hosts:
      - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
      {% if DOCKER.containers['so-strelka-manager'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-strelka-manager'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
   {% if DOCKER.containers['so-strelka-manager'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-strelka-manager'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: manager_config

delete_so-strelka-manager_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-strelka-manager$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
