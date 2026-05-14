# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'telegraf/map.jinja' import TELEGRAFMERGED %}

{# postgres_wait_ready below requires `docker_container: so-postgres`, which is
   declared in postgres.enabled. Include it here so state.apply postgres.telegraf_users
   on its own (e.g. from orch.deploy_newnode) still has that ID in scope. Salt
   de-duplicates the circular include. #}
include:
  - postgres.enabled

{% set TG_OUT = TELEGRAFMERGED.output | upper %}
{% if TG_OUT in ['POSTGRES', 'BOTH'] %}

# docker_container.running returns as soon as the container starts, but on
# first-init docker-entrypoint.sh starts a temporary postgres with
# `listen_addresses=''` to run /docker-entrypoint-initdb.d scripts, then
# shuts it down before exec'ing the real CMD. A default pg_isready check
# (Unix socket) passes during that ephemeral phase and races the shutdown
# with "the database system is shutting down". Checking TCP readiness on
# 127.0.0.1 only succeeds after the final postgres binds the port.
postgres_wait_ready:
  cmd.run:
    - name: |
        for i in $(seq 1 60); do
          if docker exec so-postgres pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null; then
            exit 0
          fi
          sleep 2
        done
        echo "so-postgres did not accept TCP connections within 120s" >&2
        exit 1
    - require:
      - docker_container: so-postgres

# Ensure the shared Telegraf database exists. init-db.sh only runs on a
# fresh data dir, so hosts upgraded onto an existing /nsm/postgres volume
# would otherwise never get so_telegraf.
postgres_create_telegraf_db:
  cmd.run:
    - name: /usr/sbin/so-telegraf-postgres create_db
    - require:
      - cmd: postgres_wait_ready
      - file: postgres_sbin

# Provision the shared group role and schema once. Every per-minion role is a
# member of so_telegraf, and each Telegraf connection does SET ROLE so_telegraf
# (via options='-c role=so_telegraf' in the connection string) so tables created
# on first write are owned by the group role and every member can INSERT/SELECT.
postgres_telegraf_group_role:
  cmd.run:
    - name: /usr/sbin/so-telegraf-postgres group_role
    - require:
      - cmd: postgres_create_telegraf_db
      - file: postgres_sbin

{%   set creds = salt['pillar.get']('telegraf:postgres_creds', {}) %}
{%   for mid, entry in creds.items() %}
{%     if entry.get('user') and entry.get('pass') %}
{%       set u = entry.user %}
{%       set p = entry.pass %}

postgres_telegraf_role_{{ u }}:
  cmd.run:
    - name: /usr/sbin/so-telegraf-postgres user
    - env:
      - ROLE_USER: {{ u | tojson }}
      - ROLE_PASS: {{ p | tojson }}
    - hide_output: True
    - require:
      - file: postgres_sbin
      - cmd: postgres_telegraf_group_role

{%     endif %}
{%   endfor %}

# Reconcile partman retention from pillar. Runs after role/schema setup so
# any partitioned parents Telegraf has already created get their retention
# refreshed whenever postgres.telegraf.retention_days changes.
{%   set retention = salt['pillar.get']('postgres:telegraf:retention_days', 14) | int %}
postgres_telegraf_retention_reconcile:
  cmd.run:
    - name: /usr/sbin/so-telegraf-postgres retention
    - env:
      - RETENTION_DAYS: {{ retention }}
    - require:
      - cmd: postgres_telegraf_group_role
      - file: postgres_sbin

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
