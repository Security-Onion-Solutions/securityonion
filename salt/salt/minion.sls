include:
  - salt

{% import_yaml 'salt/minion.defaults.yaml' as salt %}
{% set SALTVERSION = salt.salt.minion.version %}

{% if grains.saltversion|string != SALTVERSION|string %}
  {% if grains.os|lower == 'centos' %}
    {% set UPGRADECOMMAND = 'yum versionlock delete "salt-*" && sh bootstrap-salt.sh -F -x python3 stable {{ SALTVERSION }}' %}
  {% elif grains.os|lower == 'ubuntu' %}
    {% set UPGRADECOMMAND = 'apt-mark unhold salt && apt-mark unhold salt-minion && sh bootstrap-salt.sh -F -x python3 stable {{ SALTVERSION }}' %}
  {% endif %}
{% else %}
  {% set UPGRADECOMMAND = 'echo "Already running Salt Minon version {{ SALTVERSION }}"' %}
{% endif %}

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
      - salt
      - salt-minion
    - hold: True

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
