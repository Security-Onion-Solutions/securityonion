# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set hypervisor = pillar.minion_id %}

ensure_hypervisor_mine_deleted:
  salt.function:
    - name: file.remove
    - tgt: 'G@role:so-manager or G@role:so-managerhype or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - arg:
      - /var/cache/salt/master/minions/{{hypervisor}}

update_salt_cloud_profile:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managerhype or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - salt.cloud.config
    - concurrent: True
