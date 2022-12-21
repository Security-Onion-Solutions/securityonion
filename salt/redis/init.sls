# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - ssl

# Redis Setup
redisconfdir:
  file.directory:
    - name: /opt/so/conf/redis/etc
    - user: 939
    - group: 939
    - makedirs: True

redisworkdir:
  file.directory:
    - name: /opt/so/conf/redis/working
    - user: 939
    - group: 939
    - makedirs: True

redislogdir:
  file.directory:
    - name: /opt/so/log/redis
    - user: 939
    - group: 939
    - makedirs: True

redisconf:
  file.managed:
    - name: /opt/so/conf/redis/etc/redis.conf
    - source: salt://redis/etc/redis.conf.jinja
    - user: 939
    - group: 939
    - template: jinja

so-redis:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-redis:{{ GLOBALS.so_version }}
    - hostname: so-redis
    - user: socore
    - networks:
      - sosnet:
        - ipv4_address: {{ DOCKER.containers['so-redis'].ip }}
    - port_bindings:
      - 0.0.0.0:6379:6379
      - 0.0.0.0:9696:9696
    - binds:
      - /opt/so/log/redis:/var/log/redis:rw
      - /opt/so/conf/redis/etc/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - /opt/so/conf/redis/working:/redis:rw
      - /etc/pki/redis.crt:/certs/redis.crt:ro
      - /etc/pki/redis.key:/certs/redis.key:ro
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - /etc/pki/ca.crt:/certs/ca.crt:ro
  {% else %}
      - /etc/ssl/certs/intca.crt:/certs/ca.crt:ro
  {% endif %}
    - entrypoint: "redis-server /usr/local/etc/redis/redis.conf"
    - watch:
      - file: /opt/so/conf/redis/etc
    - require:
      - file: redisconf
      - x509: redis_crt
      - x509: redis_key
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - x509: pki_public_ca_crt
  {% else %}
      - x509: trusttheca
  {% endif %}

append_so-redis_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-redis

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
