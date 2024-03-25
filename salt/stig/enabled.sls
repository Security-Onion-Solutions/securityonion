# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states and GLOBALS.os == 'OEL' %}
{%   if 'stg' in salt['pillar.get']('features', []) %}
  {% set OSCAP_PROFILE_NAME = 'xccdf_org.ssgproject.content_profile_stig' %}
  {% set OSCAP_PROFILE_LOCATION = '/opt/so/conf/stig/sos-oscap.xml' %}
  {% set OSCAP_OUTPUT_DIR = '/opt/so/log/stig' %}
oscap_packages:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - openscap
      - openscap-scanner
      - scap-security-guide

make_some_dirs:
  file.directory:
    - name: /opt/so/log/stig
    - user: socore
    - group: socore
    - makedirs: True

make_more_dir:
  file.directory:
    - name: /opt/so/conf/stig
    - user: socore
    - group: socore
    - makedirs: True

update_stig_profile:
  file.managed:
    - name: /opt/so/conf/stig/sos-oscap.xml
    - source: salt://stig/files/sos-oscap.xml
    - user: socore
    - group: socore
    - mode: 0644

{% if not salt['file.file_exists'](OSCAP_OUTPUT_DIR ~ '/pre-oscap-report.html') %}
run_initial_scan:
  cmd.run:
    - name: 'oscap xccdf eval --profile {{ OSCAP_PROFILE_NAME }} --results {{ OSCAP_OUTPUT_DIR }}/pre-oscap-results.xml --report {{ OSCAP_OUTPUT_DIR }}/pre-oscap-report.html {{ OSCAP_PROFILE_LOCATION }}'
    - success_retcodes:
      - 2
{% endif %}

run_remediate:
  cmd.run:
    - name: 'oscap xccdf eval --remediate --profile {{ OSCAP_PROFILE_NAME }} {{ OSCAP_PROFILE_LOCATION }}'
    - success_retcodes:
      - 2

{# OSCAP rule id: xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction #}
disable_ctrl_alt_del_action:
  file.replace:
    - name: /etc/systemd/system.conf
    - pattern: '^#CtrlAltDelBurstAction=none'
    - repl: 'CtrlAltDelBurstAction=none'
    - backup: '.bak'

{# OSCAP rule id: xccdf_org.ssgproject.content_rule_no_empty_passwords #}
remove_nullok_from_password_auth:
  file.replace:
    - name: /etc/pam.d/password-auth
    - pattern: ' nullok'
    - repl: ''
    - backup: '.bak'

remove_nullok_from_system_auth_auth:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: ' nullok'
    - repl: ''
    - backup: '.bak'

run_post_scan:
  cmd.run:
    - name: 'oscap xccdf eval --profile {{ OSCAP_PROFILE_NAME }} --results {{ OSCAP_OUTPUT_DIR }}/post-oscap-results.xml --report {{ OSCAP_OUTPUT_DIR }}/post-oscap-report.html /usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml'
    - success_retcodes:
      - 2

{%   else %}
{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "The application of STIGs is a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
{%   endif %}

{% else %}
{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}