# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

{% set TG_OUT = (GLOBALS.telegraf_output | default('INFLUXDB')) | upper %}
{% if TG_OUT in ['POSTGRES', 'BOTH'] %}

# Ensure the shared Telegraf database exists. init-users.sh only runs on a
# fresh data dir, so hosts upgraded onto an existing /nsm/postgres volume
# would otherwise never get so_telegraf.
postgres_create_telegraf_db:
  cmd.run:
    - name: |
        docker exec -i so-postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres <<'EOSQL'
        SELECT 'CREATE DATABASE so_telegraf'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'so_telegraf')\gexec
        EOSQL
    - require:
      - docker_container: so-postgres

# Provision the shared group role and schema once. Every per-minion role is a
# member of so_telegraf, and each Telegraf connection does SET ROLE so_telegraf
# (via options='-c role=so_telegraf' in the connection string) so tables created
# on first write are owned by the group role and every member can INSERT/SELECT.
postgres_telegraf_group_role:
  cmd.run:
    - name: |
        docker exec -i so-postgres psql -v ON_ERROR_STOP=1 -U postgres -d so_telegraf <<'EOSQL'
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'so_telegraf') THEN
                CREATE ROLE so_telegraf NOLOGIN;
            END IF;
        END
        $$;
        GRANT CONNECT ON DATABASE so_telegraf TO so_telegraf;
        CREATE SCHEMA IF NOT EXISTS telegraf AUTHORIZATION so_telegraf;
        GRANT USAGE, CREATE ON SCHEMA telegraf TO so_telegraf;
        CREATE SCHEMA IF NOT EXISTS partman;
        CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        -- Hourly partman maintenance. cron.schedule is idempotent by jobname.
        SELECT cron.schedule(
          'telegraf-partman-maintenance',
          '17 * * * *',
          'CALL partman.run_maintenance_proc()'
        );
        EOSQL
    - require:
      - cmd: postgres_create_telegraf_db

{%   set users = salt['pillar.get']('postgres:auth:users', {}) %}
{%   for key, entry in users.items() %}
{%     if key.startswith('telegraf_') and entry.get('user') and entry.get('pass') %}
{%       set u = entry.user %}
{%       set p = entry.pass | replace("'", "''") %}

postgres_telegraf_role_{{ u }}:
  cmd.run:
    - name: |
        docker exec -i so-postgres psql -v ON_ERROR_STOP=1 -U postgres -d so_telegraf <<'EOSQL'
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{{ u }}') THEN
                EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', '{{ u }}', '{{ p }}');
            ELSE
                EXECUTE format('ALTER ROLE %I WITH PASSWORD %L', '{{ u }}', '{{ p }}');
            END IF;
        END
        $$;
        GRANT CONNECT ON DATABASE so_telegraf TO "{{ u }}";
        GRANT so_telegraf TO "{{ u }}";
        EOSQL
    - require:
      - cmd: postgres_telegraf_group_role

{%     endif %}
{%   endfor %}

# Reconcile partman retention from pillar. Runs after role/schema setup so
# any partitioned parents Telegraf has already created get their retention
# refreshed whenever postgres.telegraf.retention_days changes.
{%   set retention = salt['pillar.get']('postgres:telegraf:retention_days', 14) %}
postgres_telegraf_retention_reconcile:
  cmd.run:
    - name: |
        docker exec -i so-postgres psql -v ON_ERROR_STOP=1 -U postgres -d so_telegraf <<'EOSQL'
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pg_partman') THEN
                UPDATE partman.part_config
                SET retention = '{{ retention }} days',
                    retention_keep_table = false
                WHERE parent_table LIKE 'telegraf.%';
            END IF;
        END
        $$;
        EOSQL
    - require:
      - cmd: postgres_telegraf_group_role

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
