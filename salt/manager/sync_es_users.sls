# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - elasticsearch.auth
  - kratos

so-user.lock:
  file.missing:
    - name: /var/tmp/so-user.lock

so-client.lock:
  file.missing:
    - name: /var/tmp/so-client.lock

# Must run before elasticsearch docker container is started!
sync_es_users:
  cmd.run:
    - name: so-user sync
    - env:
      - SKIP_STATE_APPLY: 'true'
    - creates:
      - /opt/so/saltstack/local/salt/elasticsearch/files/users
      - /opt/so/saltstack/local/salt/elasticsearch/files/users_roles
      - /opt/so/conf/soc/soc_users_roles
    - show_changes: False
    - require:
      - docker_container: so-kratos
      - http: wait_for_kratos
      - file: so-user.lock # require so-user.lock file to be missing

# we dont want this added too early in setup, so the onlyif gates on the
# /opt/so/state/setup-complete marker. The marker is written by
# mark_setup_complete in setup/so-functions just before the final setup
# highstate (and by an upgrade-path state for systems set up under the old gate).
so-user_sync:
  cron.present:
    - user: root
    - name: 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin /usr/sbin/so-user sync &>> /opt/so/log/soc/sync.log'
    - identifier: so-user_sync
    - onlyif: "test -e /opt/so/state/setup-complete"
