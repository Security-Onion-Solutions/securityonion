# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   set PASSWORD = salt['pillar.get']('secrets:postgres_pass') %}
{%   set SO_POSTGRES_USER = salt['pillar.get']('postgres:auth:users:so_postgres_user:user', 'so_postgres') %}
{%   set SO_POSTGRES_PASS = salt['pillar.get']('postgres:auth:users:so_postgres_user:pass', '') %}

include:
  - postgres.auth
  - postgres.ssl
  - postgres.config
  - postgres.sostatus
  - postgres.telegraf_users

so-postgres:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-postgres:{{ GLOBALS.so_version }}
    - hostname: so-postgres
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKERMERGED.containers['so-postgres'].ip }}
    - port_bindings:
      {% for BINDING in DOCKERMERGED.containers['so-postgres'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - environment:
      - POSTGRES_DB=securityonion
      - POSTGRES_PASSWORD={{ PASSWORD }}
      - SO_POSTGRES_USER={{ SO_POSTGRES_USER }}
      - SO_POSTGRES_PASS={{ SO_POSTGRES_PASS }}
      {% if DOCKERMERGED.containers['so-postgres'].extra_env %}
        {% for XTRAENV in DOCKERMERGED.containers['so-postgres'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - binds:
      - /opt/so/log/postgres/:/log:rw
      - /nsm/postgres:/var/lib/postgresql/data:rw
      - /opt/so/conf/postgres/postgresql.conf:/conf/postgresql.conf:ro
      - /opt/so/conf/postgres/init/init-users.sh:/docker-entrypoint-initdb.d/init-users.sh:ro
      - /etc/pki/postgres.crt:/conf/postgres.crt:ro
      - /etc/pki/postgres.key:/conf/postgres.key:ro
      - /etc/pki/tls/certs/intca.crt:/conf/ca.crt:ro
      {% if DOCKERMERGED.containers['so-postgres'].custom_bind_mounts %}
        {% for BIND in DOCKERMERGED.containers['so-postgres'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKERMERGED.containers['so-postgres'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKERMERGED.containers['so-postgres'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKERMERGED.containers['so-postgres'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKERMERGED.containers['so-postgres'].ulimits %}
      - {{ ULIMIT.name }}={{ ULIMIT.soft }}:{{ ULIMIT.hard }}
    {%   endfor %}
    {% endif %}
    - watch:
      - file: postgresconf
      - file: postgresinitusers
      - x509: postgres_crt
      - x509: postgres_key
    - require:
      - file: postgresconf
      - file: postgresinitusers
      - x509: postgres_crt
      - x509: postgres_key

delete_so-postgres_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-postgres$

# Retention is now handled by pg_partman (hourly maintenance via pg_cron
# scheduled from postgres/telegraf_users.sls). The so-telegraf-trim script
# stays on disk for manual/emergency use but is no longer scheduled.
so_telegraf_trim:
  cron.absent:
    - name: /usr/sbin/so-telegraf-trim >> /opt/so/log/postgres/telegraf-trim.log 2>&1
    - identifier: so_telegraf_trim
    - user: root

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
