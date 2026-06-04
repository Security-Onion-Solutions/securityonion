# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/map.jinja' import UPGRADECOMMAND with context %}
{% from 'salt/map.jinja' import SALTVERSION %}
{% from 'salt/map.jinja' import INSTALLEDSALTVERSION %}
{% from 'salt/map.jinja' import SALTPACKAGES %}
{% import_yaml 'salt/minion.defaults.yaml' as SALTMINION %}

include:
  - salt.python_modules
  - salt.patch.x509_v2
  - salt
  - repo.client
  - salt.mine_functions
  - salt.minion.service_file
  - salt.minion.boot_highstate
{% if GLOBALS.is_manager %}
  - ca.signing_policy
{% endif %}

{% if INSTALLEDSALTVERSION|string != SALTVERSION|string %}
unhold_salt_packages:
  pkg.unheld:
    - pkgs:
{% for package in SALTPACKAGES %}
      - {{ package }}
{% endfor %}

install_salt_minion:
  cmd.run:
    - name: /bin/sh -c '{{ UPGRADECOMMAND }}'

# minion service is in failed state after upgrade. this command will start it after the state run for the upgrade completes
start_minion_post_upgrade:
  cmd.run:
    - name: |
        exec 0>&- # close stdin
        exec 1>&- # close stdout
        exec 2>&- # close stderr
        nohup /bin/sh -c 'sleep 30; systemctl start salt-minion' &
    - require:
      - cmd: install_salt_minion
    - watch:
      - cmd: install_salt_minion
    - order: last

{% endif %}

{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}

{% for package in SALTPACKAGES %}
# only hold the package if it is already installed
{%   if salt['pkg.version'](package) %}
hold_{{ package }}_package:
  pkg.held:
    - name: {{ package }}
    - version: {{SALTVERSION}}-0.*
{%   endif %}
{% endfor %}

remove_error_log_level_logfile:
  file.line:
    - name: /etc/salt/minion
    - match: "log_level_logfile: error"
    - mode: delete

remove_error_log_level:
  file.line:
    - name: /etc/salt/minion
    - match: "log_level: error"
    - mode: delete

set_log_levels:
  file.append:
    - name: /etc/salt/minion
    - text:
      - "log_level: info"
      - "log_level_logfile: info"

# startup_states: highstate caused a full highstate to run on every
# salt-minion service start, including the restart triggered when a highstate
# itself modified the minion config (beacons, mine, unit file). Replaced by
# so-boot-highstate.service (managed in salt.minion.boot_highstate), which
# runs once per system boot only. Strip the line from /etc/salt/minion on
# upgrade; both the commented and uncommented forms historically existed.
remove_startup_states:
  file.line:
    - name: /etc/salt/minion
    - match: 'startup_states: highstate'
    - mode: delete

# Upgrade-path bridge: systems that already passed setup under the old gate
# (`grep -x 'startup_states: highstate' /etc/salt/minion`) get a /opt/so/state/setup-complete
# marker so so-boot-highstate.service can be enabled and the so-user_sync cron
# in sync_es_users.sls keeps installing. Setup-in-progress systems instead get
# the marker from `mark_setup_complete` in setup/so-functions at the right
# moment. `replace: false` means we never overwrite a marker once written.
mark_setup_complete_for_upgrades:
  file.managed:
    - name: /opt/so/state/setup-complete
    - replace: false
    - makedirs: True
    - onlyif: "grep -qx 'startup_states: highstate' /etc/salt/minion"
    - require_in:
      - file: remove_startup_states
      - service: so_boot_highstate_service

{% endif %}

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
{% endif %}
{% if GLOBALS.is_manager %}
      - file: signing_policy
{% endif %}
    - order: last
