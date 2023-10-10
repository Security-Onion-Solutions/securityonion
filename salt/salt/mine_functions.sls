# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# this state was seperated from salt.minion state since it is called during setup
# GLOBALS are imported in the salt.minion state and that is not available at that point in setup
# this state is included in the salt.minion state
mine_functions:
  file.managed:
    - name: /etc/salt/minion.d/mine_functions.conf
    - source: salt://salt/etc/minion.d/mine_functions.conf.jinja
    - template: jinja
