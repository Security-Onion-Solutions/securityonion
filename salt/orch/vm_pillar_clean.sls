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

{%   do salt.log.debug('vm_pillar_clean_orch: Running') %}
{%   set vm_name = pillar.get('vm_name') %}

delete_adv_{{ vm_name }}_pillar:
  module.run:
    - file.remove:
      - path: /opt/so/saltstack/local/pillar/minions/adv_{{ vm_name }}.sls

delete_{{ vm_name }}_pillar:
  module.run:
    - file.remove:
      - path: /opt/so/saltstack/local/pillar/minions/{{ vm_name }}.sls

{% else %}

{%   do salt.log.error(
    'Hypervisor nodes are a feature supported only for customers with a valid license.'
    'Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com'
    'for more information about purchasing a license to enable this feature.'
) %}

{% endif %}
