# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - idh.config
  - idh.sostatus

so-idh:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-idh:{{ GLOBALS.so_version }}
    - name: so-idh
    - detach: True
    - network_mode: host
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/http-skins:/usr/local/lib/python3.12/site-packages/opencanary/modules/data/http/skin:ro
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro
      {% if DOCKER.containers['so-idh'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-idh'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-idh'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-idh'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers['so-idh'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-idh'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - watch:
      - file: opencanary_config
    - require:
      - file: opencanary_config

delete_so-idh_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-idh$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
