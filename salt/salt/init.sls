# distribute to minions for salt upgrades
salt_bootstrap:
  file.managed:
    - name: /usr/sbin/bootstrap-salt.sh
    - source: salt://salt/scripts/bootstrap-salt.sh
    - user: root
    - group: root
    - mode: 755
    - show_changes: False

salt_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://salt/tools/sbin
    - user: root
    - group: root
    - file_mode: 755
