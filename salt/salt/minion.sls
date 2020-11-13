{% from 'salt/map.jinja' import COMMON with context %}
{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}

include:
  - salt

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
      - {{ COMMON }}
      - salt-minion
    - hold: True

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True