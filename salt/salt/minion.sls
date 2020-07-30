include:
  - salt

{% import_yaml 'salt/minion.defaults.yaml' as salt %}
{% set saltversion = salt.salt.minion.version %}

{% if grains.os|lower == 'centos' %}
install_salt_minion:
  cmd.run:
    {% if grains.saltversion|string != saltversion|string %}
    - name: yum versionlock delete "salt-*" && sh bootstrap-salt.sh -F -x python3 stable {{ saltversion }}
    {% else %}
    - name: echo 'Already running Salt Minon version {{ saltversion }}'
    {% endif %}

versionlock_salt_minion:
  module.run:
    - pkg.hold:
      - name: "salt-*"
{% endif %}

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
