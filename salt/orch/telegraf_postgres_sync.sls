# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set MANAGER = salt['pillar.get']('setup:manager') or salt['grains.get']('master') %}

# Fired by salt/reactor/telegraf_user_sync.sls when salt-key accepts a new
# minion. Only provisions the per-minion pillar entry and DB role on the
# manager; the minion itself will pick up its telegraf config on its first
# highstate during onboarding, so there's no need to push the telegraf state
# from here.
manager_sync_telegraf_pg_users:
  salt.state:
    - tgt: {{ MANAGER }}
    - sls:
      - postgres.auth
      - postgres.telegraf_users
    - queue: True
