# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Fired by salt/reactor/telegraf_user_sync.sls when salt-key accepts a new
# minion. Only provisions the per-minion pillar entry and DB role on the
# manager; the minion itself will pick up its telegraf config on its first
# highstate during onboarding, so there's no need to push the telegraf state
# from here.
#
# Target the manager via role grains — same pattern as orch/delete_hypervisor.sls.
# The reactor doesn't know the manager's minion id, and grains.master on the
# runner is a hostname, not a targetable id.
manager_sync_telegraf_pg_users:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managerhype or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - postgres.auth
      - postgres.telegraf_users
    - queue: True
