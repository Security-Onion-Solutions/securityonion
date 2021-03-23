{% from 'salt/map.jinja' import COMMON with context %}
{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}

include:
  - salt

install_salt_minion:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c '{{ UPGRADECOMMAND }}' &
    - onlyif: test "{{INSTALLEDSALTVERSION}}" != "{{SALTVERSION}}"

salt_minion_package:
  pkg.installed:
    - pkgs:
      - {{ COMMON }}
      - salt-minion
    - hold: True
    - onlyif: test "{{INSTALLEDSALTVERSION}}" == "{{SALTVERSION}}"

set_log_levels:
  file.append:
    - name: /etc/salt/minion
    - text:
      - "log_level: info"
      - "log_level_logfile: info"
    - listen_in:
      - service: salt_minion_service

salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
    - onlyif: test "{{INSTALLEDSALTVERSION}}" == "{{SALTVERSION}}"

patch_pkg:
  pkg.installed:
    - name: patch


#https://github.com/saltstack/salt/issues/59766
influxdb_continuous_query.present_patch:
  file.patch:
    - name: /usr/lib/python3.6/site-packages/salt/states/influxdb_continuous_query.py
    - source: salt://salt/files/influxdb_continuous_query.py.patch

#https://github.com/saltstack/salt/issues/59761
influxdb_retention_policy.present_patch:
  file.patch:
    - name: /usr/lib/python3.6/site-packages/salt/states/influxdb_retention_policy.py
    - source: salt://salt/files/influxdb_retention_policy.py.patch