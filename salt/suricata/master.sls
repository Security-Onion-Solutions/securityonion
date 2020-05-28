include:
  - salt.master.refresh_fileserver

surilocaldir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/suricata
    - user: 940
    - group: 940
    - makedirs: True

ruleslink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/suricata/rules
    - target: /opt/so/rules/nids
    - watch_in: 
      - saltmod: refresh_salt_master_fileserver
    