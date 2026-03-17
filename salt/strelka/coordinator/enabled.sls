# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - strelka.coordinator.config
  - strelka.coordinator.sostatus

strelka_coordinator:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-redis:{{ GLOBALS.so_version }}
    - name: so-strelka-coordinator
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKERMERGED.containers['so-strelka-coordinator'].ip }}
    - entrypoint: redis-server --save "" --appendonly no
    - extra_hosts:
      - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
      {% if DOCKERMERGED.containers['so-strelka-coordinator'].extra_hosts %}
        {% for XTRAHOST in DOCKERMERGED.containers['so-strelka-coordinator'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKERMERGED.containers['so-strelka-coordinator'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
  {% if DOCKERMERGED.containers['so-strelka-coordinator'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKERMERGED.containers['so-strelka-coordinator'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - binds:
      - /nsm/strelka/coord-redis-data:/data:rw
      {% if DOCKERMERGED.containers['so-strelka-coordinator'].custom_bind_mounts %}
        {% for BIND in DOCKERMERGED.containers['so-strelka-coordinator'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKERMERGED.containers['so-strelka-coordinator'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKERMERGED.containers['so-strelka-coordinator'].ulimits %}
      - {{ ULIMIT }}
    {%   endfor %}
    {% endif %}
delete_so-strelka-coordinator_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-strelka-coordinator$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
