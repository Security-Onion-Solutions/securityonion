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

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}

hypervisor_log_dir:
  file.directory:
    - name: /opt/so/log/hypervisor

hypervisor_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://hypervisor/tools/sbin
    - file_mode: 744

hypervisor_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://hypervisor/tools/sbin_jinja
    - template: jinja
    - file_mode: 744

{%   else %}
{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
