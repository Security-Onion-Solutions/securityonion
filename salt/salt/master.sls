include:
  - salt.minion

salt_master_package:
  pkg.installed:
    - pkgs:
      - salt
      - salt-master
    - hold: True

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True

engines:
  file.directory:
    - name: /etc/salt/engines

checkmine_engine:
  file.managed:
    - name: /etc/salt/engines/checkmine.py
    - source: salt://salt/engines/checkmine.py
    - watch_in:
        - service: salt_minion_service

engines_config:
  file.managed:
    - name: /etc/salt/minion.d/engines.conf
    - source: salt://salt/files/engines.conf
    - watch_in:
        - service: salt_minion_service