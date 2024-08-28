# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

set_role_grain:
  grains.present:
    - name: role
    - value: so-{{ grains.id.split("_") | last }}

# disable the initial schedule
remove_init_node_schedule:
  schedule.absent:
    - name: init_node

set_highstate:
  file.append:
    - name: /etc/salt/minion
    - text: 'startup_states: highstate'
