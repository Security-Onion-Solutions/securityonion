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

# Send highstate trigger event for VM deployment status tracking
# so-salt-emit-vm-deployment-status sets event_tag = f'soc/dyanno/hypervisor/{status.lower()}'
vm_highstate_trigger:
  event.send:
    - name: soc/dyanno/hypervisor/highstate initiated
    - data:
        status: Highstate Initiated
        vm_name: {{ grains.id }}
        hypervisor: {{ salt['grains.get']('salt-cloud:profile', '').split('_')[1] }}
    - unless: test -f /opt/so/state/highstate_trigger.txt
    - order: 1 # Ensure this runs early in the highstate process

# Check if the trigger has already run
vm_highstate_trigger_file:
  file.managed:
    - name: /opt/so/state/highstate_trigger.txt
    - contents: |
        VM Highstate Trigger executed at: {{ salt['cmd.run']('date') }}
    - onchanges:
      - event: vm_highstate_trigger

{% else %}

{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."

{% endif %}
