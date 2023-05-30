# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - kratos.config
  - kratos.sostatus

so-kratos:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-kratos:{{ GLOBALS.so_version }}
    - hostname: kratos
    - name: so-kratos
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-kratos'].ip }}
    - binds:
      - /opt/so/conf/kratos/schema.json:/kratos-conf/schema.json:ro    
      - /opt/so/conf/kratos/kratos.yaml:/kratos-conf/kratos.yaml:ro
      - /opt/so/log/kratos/:/kratos-log:rw
      - /nsm/kratos/db:/kratos-data:rw
      {% if DOCKER.containers['so-kratos'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-kratos'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-kratos'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    {% if DOCKER.containers['so-kratos'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-kratos'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers['so-kratos'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-kratos'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - restart_policy: unless-stopped
    - watch:
      - file: kratosschema
      - file: kratosconfig
    - require:
      - file: kratosschema
      - file: kratosconfig
      - file: kratoslogdir
      - file: kratosdir

delete_so-kratos_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-kratos$

wait_for_kratos:
  http.wait_for_successful_query:
    - name: 'http://{{ GLOBALS.manager }}:4434/'
    - ssl: True
    - verify_ssl: False
    - status:
      - 200
      - 301
      - 302
      - 404
    - status_type: list
    - wait_for: 300
    - request_interval: 10
    - require:
      -  docker_container: so-kratos

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
