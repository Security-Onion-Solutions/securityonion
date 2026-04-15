# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set MINION = salt['pillar.get']('minion_id') %}
{% set MANAGER = salt['pillar.get']('setup:manager') or salt['grains.get']('master') %}

manager_sync_telegraf_pg_users:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - postgres.auth
      - postgres.telegraf_users
    - queue: True

{% if MINION and MINION != MANAGER %}
{{ MINION }}_apply_telegraf:
  salt.state:
    - tgt: {{ MINION }}
    - sls:
      - telegraf
    - queue: True
    - require:
      - salt: manager_sync_telegraf_pg_users
{% endif %}
