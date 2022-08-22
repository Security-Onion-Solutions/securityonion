{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}
{% from 'salt/map.jinja' import SALTNOTHELD %}
{% from 'salt/map.jinja' import SALTPACKAGES %}
{% from 'salt/map.jinja' import SYSTEMD_UNIT_FILE %}
{% import_yaml 'salt/minion.defaults.yaml' as SALTMINION %}
{% set service_start_delay = SALTMINION.salt.minion.service_start_delay %}

include:
  - salt
  - salt.helper-packages
  - systemd.reload
  - repo.client

{% if INSTALLEDSALTVERSION|string != SALTVERSION|string %}

{% if SALTNOTHELD | int == 0 %}
unhold_salt_packages:
  module.run:
    - pkg.unhold:
      - pkgs:
{% for package in SALTPACKAGES %}
        - {{ package }}
{% endfor %}
{% endif %}

install_salt_minion:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c '{{ UPGRADECOMMAND }}' &

  {# if we are the salt master #}
  {% if grains.id.split('_')|first == grains.master %}
remove_influxdb_continuous_query_state_file:
  file.absent:
    - name: /opt/so/state/influxdb_continuous_query.py.patched

remove_influxdbmod_state_file:
  file.absent:
    - name: /opt/so/state/influxdbmod.py.patched

remove_influxdb_retention_policy_state_file:
  file.absent:
    - name: /opt/so/state/influxdb_retention_policy.py.patched
  {% endif %}

{% endif %}

{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}

{% if SALTNOTHELD | int == 1 %}
hold_salt_packages:
  module.run:
    - pkg.hold:
      - pkgs:
{% for package in SALTPACKAGES %}
        - {{ package }}
{% endfor %}
{% endif %}

remove_info_log_level_logfile:
  file.line:
    - name: /etc/salt/minion
    - match: "log_level_logfile: info"
    - mode: delete

remove_info_log_level:
  file.line:
    - name: /etc/salt/minion
    - match: "log_level: info"
    - mode: delete

set_log_levels:
  file.append:
    - name: /etc/salt/minion
    - text:
      - "log_level: error"
      - "log_level_logfile: error"

delete_pre_150_start_delay:
  file.line:
    - name: {{ SYSTEMD_UNIT_FILE }}
    - match: ^ExecStartPre=*
    - mode: delete
    - onchanges_in:
      - module: systemd_reload

salt_minion_service_start_delay:
  file.managed:
    - name: /etc/systemd/system/salt-minion.service.d/start-delay.conf
    - source: salt://salt/service/start-delay.conf.jinja
    - template: jinja
    - makedirs: True
    - defaults:
        service_start_delay: {{ service_start_delay }}
    - onchanges_in:
      - module: systemd_reload

{% endif %}

mine_functions:
  file.managed:
    - name: /etc/salt/minion.d/mine_functions.conf
    - source: salt://salt/etc/minion.d/mine_functions.conf
    - template: jinja

# this has to be outside the if statement above since there are <requisite>_in calls to this state
salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
    - onlyif: test "{{INSTALLEDSALTVERSION}}" == "{{SALTVERSION}}"
    - listen:
      - file: mine_functions
{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}
      - file: set_log_levels
      - file: salt_minion_service_start_delay
{% endif %}
    - order: last


patch_pkg:
  pkg.installed:
    - name: patch
