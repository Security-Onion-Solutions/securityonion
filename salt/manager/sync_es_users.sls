include:
  - elasticsearch.auth
  - kratos

so-user.lock:
  file.missing:
    - name: /var/tmp/so-user.lock

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

# we dont want this added too early in setup, so we add the onlyif to verify 'startup_states: highstate'
# is in the minion config. That line is added before the final highstate during setup
sosyncusers:
  cron.present:
    - user: root
    - name: 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin /usr/sbin/so-user sync &>> /opt/so/log/soc/sync.log'
    - onlyif: "grep 'startup_states: highstate' /etc/salt/minion"
