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

{% if 'vrt' in salt['pillar.get']('features', []) %}

{%   from 'vm/map.jinja' import VMMERGED %}

{%   if VMMERGED.user.soqemussh.enabled %}

vm_user_soqemussh:
  user.present:
    - name: soqemussh
    - shell: /bin/bash
    - home: /home/soqemussh
    - password: '{{ VMMERGED.user.soqemussh.passwordHash }}'

vm_user_soqemussh_home_directory:
  file.directory:
    - name: /home/soqemussh
    - user: soqemussh
    - group: soqemussh
    - mode: 700
    - recurse:
      - user
      - group

{%   else %}

vm_user_soqemussh:
  user.absent:
    - name: soqemussh
    - force: True

{%   endif %}

{% else %}

{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."

{% endif %}
