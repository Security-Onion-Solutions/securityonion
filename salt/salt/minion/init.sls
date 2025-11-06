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
{% if GLOBALS.role in GLOBALS.manager_roles %}
  - ca
{% endif %}

{% if INSTALLEDSALTVERSION|string != SALTVERSION|string %}

{# this is added in 2.4.120 to remove salt repo files pointing to saltproject.io to accomodate the move to broadcom and new bootstrap-salt script #}
{%   if salt['pkg.version_cmp'](GLOBALS.so_version, '2.4.120') == -1 %}
{%     set saltrepofile = '/etc/yum.repos.d/salt.repo' %}
{%     if grains.os_family == 'Debian' %}
{%       set saltrepofile = '/etc/apt/sources.list.d/salt.list' %}
{%     endif %}
remove_saltproject_io_repo_minion:
  file.absent:
    - name: {{ saltrepofile }}
{%   endif %}

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
{% if GLOBALS.role in GLOBALS.manager_roles %}
      - file: /etc/salt/minion.d/signing_policies.conf
{% endif %}
    - order: last
