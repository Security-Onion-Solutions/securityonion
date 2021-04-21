{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}
{% from 'salt/map.jinja' import SALTNOTHELD %}
{% import_yaml 'salt/minion.defaults.yaml' as SALTMINION %}
{% set service_start_delay = SALTMINION.salt.minion.service_start_delay %}

include:
  - salt
  - salt.helper-packages
  - systemd.reload

{% if INSTALLEDSALTVERSION|string != SALTVERSION|string %}

{% if SALTNOTHELD == 0 %}
unhold_salt_packages:
  module.run:
    - pkg.unhold:
      - name: 'salt-*'
{% endif %}

install_salt_minion:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c '{{ UPGRADECOMMAND }}' &
{% endif %}

{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}

{% if SALTNOTHELD == 1 %}
hold_salt_packages:
  module.run:
    - pkg.hold:
      - name: 'salt-*'
{% endif %}

set_log_levels:
  file.append:
    - name: /etc/salt/minion
    - text:
      - "log_level: info"
      - "log_level_logfile: info"
    - listen_in:
      - service: salt_minion_service

salt_minion_service_unit_file:
  file.managed:
    - name: /etc/systemd/system/multi-user.target.wants/salt-minion.service
    - source: salt://salt/service/salt-minion.service.jinja
    - template: jinja
    - defaults:
        service_start_delay: {{ service_start_delay }}
    - onchanges_in:
      - module: systemd_reload
    - listen_in:
      - service: salt_minion_service
{% endif %}

# this has to be outside the if statement above since there are <requisite>_in calls to this state
salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
    - onlyif: test "{{INSTALLEDSALTVERSION}}" == "{{SALTVERSION}}"

patch_pkg:
  pkg.installed:
    - name: patch