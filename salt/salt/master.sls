salt_master_package:
  pkg.installed:
    - pkgs:
      - salt
      - salt-master
    - hold: True

salt_minion_service:
  service.running:
    - name: salt-master
    - enable: True