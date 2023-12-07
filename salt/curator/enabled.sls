# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - curator.config
  - curator.sostatus

so-curator:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-curator:{{ GLOBALS.so_version }}
    - start: True
    - hostname: curator
    - name: so-curator
    - user: curator
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-curator'].ip }}
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/conf/curator/curator.yml:/etc/curator/config/curator.yml:ro
      - /opt/so/conf/curator/action/:/etc/curator/action:ro
      - /opt/so/log/curator:/var/log/curator:rw
      {% if DOCKER.containers['so-curator'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-curator'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
      {% if DOCKER.containers['so-curator'].extra_hosts %}
    - extra_hosts:
        {% for XTRAHOST in DOCKER.containers['so-curator'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
      {% if DOCKER.containers['so-curator'].extra_env %}
    - environment:
        {% for XTRAENV in DOCKER.containers['so-curator'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - require:
      - file: actionconfs
      - file: curconf
      - file: curlogdir
    - watch:
      - file: curconf

delete_so-curator_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-curator$

so-curator-cluster-close:
  cron.absent:
    - identifier: so-curator-cluster-close

so-curator-cluster-delete:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-delete > /opt/so/log/curator/cron-cluster-delete.log 2>&1
    - identifier: so-curator-cluster-delete
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
