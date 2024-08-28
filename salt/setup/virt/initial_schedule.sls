# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# initially tried to use schedule.present here, but that state trys to return data to the master even if run with --local
# that causes it to fail since th firewall may not yet be open on the manager
init_node_cron:
  cron.present:
    - name: salt-call state.apply setup.virt.init
    - identifier: init_node_cron
    - user: root
    - minute: '*/1'
