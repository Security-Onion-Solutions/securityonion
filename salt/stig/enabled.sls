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
{%   if 'stig' in salt['pillar.get']('features', []) %}
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

update_remediation_script:
  file.managed:
    - name: /usr/sbin/so-stig
    - source: salt://stig/files/so-stig
    - user: socore
    - group: socore
    - mode: 0755
    - template: jinja

remove_old_stig_log:
  file.absent:
    - name: /opt/so/log/stig/stig-remediate.log

run_remediation_script:
  cmd.run:
    - name: so-stig > /opt/so/log/stig/stig-remediate.log
    - hide_output: True
    - success_retcodes:
      - 0
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