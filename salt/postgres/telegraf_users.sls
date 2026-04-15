# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

{% set TG_OUT = (GLOBALS.telegraf_output | default('INFLUXDB')) | upper %}
{% if TG_OUT in ['POSTGRES', 'BOTH'] %}

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
        CREATE SCHEMA IF NOT EXISTS "{{ u }}" AUTHORIZATION "{{ u }}";
        EOSQL
    - require:
      - docker_container: so-postgres

{%     endif %}
{%   endfor %}

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
