# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - elastalert.config
  - elastalert.sostatus

wait_for_elasticsearch:
  cmd.run:
    - name: so-elasticsearch-wait

so-elastalert:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastalert:{{ GLOBALS.so_version }}
    - hostname: elastalert
    - name: so-elastalert
    - user: so-elastalert
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elastalert'].ip }}
    - detach: True
    - binds:
      - /opt/so/rules/elastalert:/opt/elastalert/rules/:ro
      - /opt/so/log/elastalert:/var/log/elastalert:rw
      - /opt/so/conf/elastalert/modules/:/opt/elastalert/modules/:ro
      - /opt/so/conf/elastalert/predefined/:/opt/elastalert/predefined/:ro
      - /opt/so/conf/elastalert/custom/:/opt/elastalert/custom/:ro
      - /opt/so/conf/elastalert/elastalert_config.yaml:/opt/elastalert/config.yaml:ro
      {% if DOCKER.containers['so-elastalert'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-elastalert'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
      {% if DOCKER.containers['so-elastalert'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-elastalert'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
      {% if DOCKER.containers['so-elastalert'].extra_env %}
    - environment:
        {% for XTRAENV in DOCKER.containers['so-elastalert'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - require:
      - cmd: wait_for_elasticsearch
      - file: elastarules
      - file: elastalogdir
      - file: elastacustmodulesdir
      - file: elastaconf
    - watch:
      - file: elastaconf
    - onlyif:
      - "so-elasticsearch-query / | jq -r '.version.number[0:1]' | grep -q 8" {# only run this state if elasticsearch is version 8 #}

delete_so-elastalert_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elastalert$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
