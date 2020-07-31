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