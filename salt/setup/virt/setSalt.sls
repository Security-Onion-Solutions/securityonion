# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

set_role_grain:
  grains.present:
    - name: role
    - value: so-{{ grains.id.split("_") | last }}

# salt-cloud guests never run so-setup, so nothing else marks them setup-complete.
# Replaces the 'startup_states: highstate' line this state used to append. No
# GLOBALS import -- this runs before the guest's pillars exist.
mark_setup_complete_vm_guest:
  file.managed:
    - name: /opt/so/state/setup-complete
    - replace: false
    - makedirs: True

enable_salt_minion:
  service.enabled:
    - name: salt-minion
