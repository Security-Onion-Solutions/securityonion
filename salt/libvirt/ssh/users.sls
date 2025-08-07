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
{% if sls.split('.')[0] in allowed_states or sls in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}
{%     from 'vars/globals.map.jinja' import GLOBALS %}

{%     if GLOBALS.is_manager %}

root_ssh_config:
  file.touch:
    - name: /root/.ssh/config

qemu_ssh_client_config:
  file.blockreplace:
    - name: /root/.ssh/config
    - marker_start: "# START of block managed by Salt - soqemussh config"
    - marker_end: "# END of block managed by Salt - soqemussh config"
    - source: salt://libvirt/ssh/files/config
    - prepend_if_not_found: True

{%     endif %}

{%     if GLOBALS.role in ['so-hypervisor', 'so-managerhype'] %}

# used for qemu+ssh connection between manager and hypervisors
create_soqemussh_user:
  user.present:
    - name: soqemussh
    - shell: /bin/bash
    - home: /home/soqemussh
    - groups:
      - wheel
      - qemu
      - libvirt

soqemussh_pub_key:
  ssh_auth.present:
    - user: soqemussh
    - source: salt://libvirt/ssh/keys/id_ecdsa.pub

{%     endif %}

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
