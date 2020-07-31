include:
  - salt

{% from 'salt/map.jinja' import SALTPACKAGES with context %}
{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}


install_salt_minion:
  cmd.run:
    - name: {{ UPGRADECOMMAND }} 

#versionlock_salt_minion:
#  module.run:
#    - pkg.hold:
#      - name: "salt-*"

salt_minion_package:
  pkg.installed:
    - pkgs:
      - {{ SALTPACKAGES.common }}
      - salt-minion
    - hold: True

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
