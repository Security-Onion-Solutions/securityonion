# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'stig/map.jinja' import STIGMERGED %}
{%   if 'stg' in salt['pillar.get']('features', []) %}
stig_remediate_schedule:
  schedule.present:
    - function: state.apply
    - job_args:
      - stig.enabled
    - hours: {{ STIGMERGED.run_interval }}
    - maxrunning: 1
    - enabled: true
{%   else %}
{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "The application of STIGs is a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
{%   endif %}