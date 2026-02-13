# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This state is to be used during soup preupgrade_changes, and run when the salt-master has been stopped. Soup will later start the salt-master.

add_minimum_auth_version_engine_config:
  file.managed:
    - name: /etc/salt/master.d/minimum_auth_version_engine.conf
    - source: salt://salt/master/files/minimum_auth_version_engine.conf

add_minimum_auth_version_engine:
  file.managed:
    - name: /etc/salt/engines/minimum_auth_version.py
    - source: salt://salt/engines/master/minimum_auth_version.py
