# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This state should only be run on managers and should never be run manually

{% set MINION_ID = grains.id %}

# Run mine.update on all minions
salt.master.mine_update_highstate.update_mine_all_minions:
  salt.function:
    - name: mine.update
    - tgt: '*'
    - batch: 50
    - retry:
        attempts: 3
        interval: 1

# Run highstate on the original minion
# we can use concurrent on this highstate because no other highstate would be running when this is called
salt.master.mine_update_highstate.run_highstate_on_{{ MINION_ID }}:
  salt.state:
    - tgt: {{ MINION_ID }}
    - highstate: True
    - concurrent: True
