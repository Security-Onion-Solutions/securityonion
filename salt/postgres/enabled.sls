# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   set SO_POSTGRES_USER = salt['pillar.get']('postgres:auth:users:so_postgres_user:user', 'so_postgres') %}

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
      # Passwords are delivered via mounted 0600 secret files, not plaintext env vars.
      # The upstream postgres image resolves POSTGRES_PASSWORD_FILE; entrypoint.sh and
      # init-users.sh resolve SO_POSTGRES_PASS_FILE the same way.
      - POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
      - SO_POSTGRES_USER={{ SO_POSTGRES_USER }}
      - SO_POSTGRES_PASS_FILE=/run/secrets/so_postgres_pass
      {% if DOCKERMERGED.containers['so-postgres'].extra_env %}
        {% for XTRAENV in DOCKERMERGED.containers['so-postgres'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - binds:
      - /opt/so/log/postgres/:/log:rw
      - /nsm/postgres:/var/lib/postgresql/data:rw
      - /opt/so/conf/postgres/postgresql.conf:/conf/postgresql.conf:ro
      - /opt/so/conf/postgres/pg_hba.conf:/conf/pg_hba.conf:ro
      - /opt/so/conf/postgres/secrets:/run/secrets:ro
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
      - file: postgreshba
      - file: postgresinitusers
      - file: postgres_super_secret
      - file: postgres_app_secret
      - x509: postgres_crt
      - x509: postgres_key
    - require:
      - file: postgresconf
      - file: postgreshba
      - file: postgresinitusers
      - file: postgres_super_secret
      - file: postgres_app_secret
      - x509: postgres_crt
      - x509: postgres_key

delete_so-postgres_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-postgres$

so_postgres_backup:
  cron.present:
    - name: /usr/sbin/so-postgres-backup > /dev/null 2>&1
    - identifier: so_postgres_backup
    - user: root
    - minute: '5'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
