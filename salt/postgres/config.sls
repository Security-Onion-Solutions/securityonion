# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'postgres/map.jinja' import PGMERGED %}

# Postgres Setup
postgresconfdir:
  file.directory:
    - name: /opt/so/conf/postgres
    - user: 939
    - group: 939
    - makedirs: True

postgressecretsdir:
  file.directory:
    - name: /opt/so/conf/postgres/secrets
    - user: 939
    - group: 939
    - mode: 700
    - require:
      - file: postgresconfdir

postgresdatadir:
  file.directory:
    - name: /nsm/postgres
    - user: 939
    - group: 939
    - makedirs: True

postgreslogdir:
  file.directory:
    - name: /opt/so/log/postgres
    - user: 939
    - group: 939
    - makedirs: True

postgresinitdir:
  file.directory:
    - name: /opt/so/conf/postgres/init
    - user: 939
    - group: 939
    - require:
      - file: postgresconfdir

postgresinitusers:
  file.managed:
    - name: /opt/so/conf/postgres/init/init-users.sh
    - source: salt://postgres/files/init-users.sh
    - user: 939
    - group: 939
    - mode: 755

postgresconf:
  file.managed:
    - name: /opt/so/conf/postgres/postgresql.conf
    - source: salt://postgres/files/postgresql.conf.jinja
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        PGMERGED: {{ PGMERGED }}

postgreshba:
  file.managed:
    - name: /opt/so/conf/postgres/pg_hba.conf
    - source: salt://postgres/files/pg_hba.conf
    - user: 939
    - group: 939
    - mode: 640

postgres_super_secret:
  file.managed:
    - name: /opt/so/conf/postgres/secrets/postgres_password
    - user: 939
    - group: 939
    - mode: 600
    - contents_pillar: 'secrets:postgres_pass'
    - show_changes: False
    - require:
      - file: postgressecretsdir

postgres_app_secret:
  file.managed:
    - name: /opt/so/conf/postgres/secrets/so_postgres_pass
    - user: 939
    - group: 939
    - mode: 600
    - contents_pillar: 'postgres:auth:users:so_postgres_user:pass'
    - show_changes: False
    - require:
      - file: postgressecretsdir

postgres_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://postgres/tools/sbin
    - user: root
    - group: root
    - file_mode: 755

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
