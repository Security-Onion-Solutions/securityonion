surilocaldir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/suricata
    - user: socore
    - group: socore
    - makedirs: True

ruleslink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/suricata/rules
    - user: socore
    - group: socore
    - target: /opt/so/rules/nids

refresh_salt_master_fileserver_suricata_ruleslink:
  salt.runner:
    - name: fileserver.update
    - onchanges:
      - file: ruleslink