# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if sls in allowed_states and GLOBALS.os == 'OEL' %}

{%   set LICFEAT = salt['pillar.get']('features', []) %}
{%   set oscap_profile = '/usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml' %}

{%   if 'stig' in LICFEAT %}
ensure-fips:
  cmd.run:
    - name: /usr/bin/fips-mode-setup --enable
    - unless: /usr/bin/fips-mode-setup --is-enabled

python3-pkg-fips-error:
  cmd.run:
    - name: rpm -U --nofiledigest /nsm/repo/python3-watchdog-1.0-securityonion.rpm || true

#Move to deployed SO instance and run this state. Then add schedule to run state every 24h.
oscap_pkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - scap-security-guide
      - usbguard-selinux
      - aide
      - gnutls-utils
      - libreswan
      - opensc
      - openscap
      - openscap-scanner
      - pcsc-lite
      - rng-tools
      - tmux
      - usbguard

oscap_report_logdir:
  file.directory:
    - name: /opt/so/log/oscap
    - user: 939
    - group: 939
    - makedirs: True
    - mode: 755

#Create custom tailoring file to explicity disable problematic STIGs
oscap_initial_remediate:
  cmd.run:
    - name: /usr/bin/oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --remediate {{ oscap_profile }} || true

oscap_report:
  cmd.run:
    - name: /usr/bin/oscap xccdf eval --profile stig --report /opt/so/log/oscap/latest-oscap-report.html {{ oscap_profile }} || true

oscap_schedule:
  schedule.present:
    - name: oscap_schedule
    - function: state.sls
    - job_args:
      - oscap
    - hours: 24

{%   else %}
{{sls}}_license_not_found:
  test.fail_without_changes:
    - name: STIG license feature not found activated.

{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}