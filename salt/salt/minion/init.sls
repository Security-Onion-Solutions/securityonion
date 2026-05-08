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

enable_startup_states:
  file.uncomment:
    - name: /etc/salt/minion
    - regex: '^startup_states: highstate$'
    - unless: pgrep so-setup

{% endif %}

# this has to be outside the if statement above since there are <requisite>_in calls to this state.
# uses watch (not listen) so the restart fires in-state and its result lands on this state's
# running entry; that is what lets wait_for_salt_minion_ready below detect any restart
# uniformly via onchanges, regardless of whether the trigger came from these files or from
# external watch_in's (e.g. beacons, master/pyinotify).
salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
    - onlyif: test "{{INSTALLEDSALTVERSION}}" == "{{SALTVERSION}}"
    - watch:
      - file: mine_functions
{% if INSTALLEDSALTVERSION|string == SALTVERSION|string %}
      - file: set_log_levels
{% endif %}
{% if GLOBALS.is_manager %}
      - file: signing_policy
{% endif %}
    - order: last

# block until the just-restarted salt-minion is back and can execute modules locally, so
# follow-on jobs and the next highstate iteration do not race the restart. onchanges +
# require on salt_minion_service catches every restart trigger uniformly because watch
# mod_watch results replace the service state's running entry. wait logic lives in
# /usr/sbin/so-salt-minion-wait (deployed by common_sbin from common/tools/sbin/).
wait_for_salt_minion_ready:
  cmd.run:
    - name: /usr/sbin/so-salt-minion-wait
    - onchanges:
      - service: salt_minion_service
    - require:
      - service: salt_minion_service
    - order: last
