# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - salt.master

unset_minimum_auth_version_0:
  file.absent:
    - name: /etc/salt/master.d/minimum_auth_version.conf

remove_minimum_auth_version_engine_config:
  file.absent:
    - name: /etc/salt/master.d/minimum_auth_version_engine.conf

remove_minimum_auth_version_engine:
  file.absent:
    - name: /etc/salt/engines/minimum_auth_version.py
    - watch_in:
      - service: salt_master_service
