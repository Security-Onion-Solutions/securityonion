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
{% if sls.split('.')[:2]|join('.') in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}
reactor_config_hypervisor:
  file.managed:
    - name: /etc/salt/master.d/reactor_hypervisor.conf
    - contents: |
        reactor:
          - 'salt/key':
            - salt://reactor/check_hypervisor.sls
          - 'salt/cloud/*/creating':
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
          - 'salt/cloud/*/deploying':
            - /opt/so/saltstack/default/salt/reactor/createEmptyPillar.sls
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
          - 'setup/so-minion':
            - /opt/so/saltstack/default/salt/reactor/sominion_setup.sls
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
          - 'salt/cloud/*/created':
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
          - 'soc/dyanno/hypervisor/*':
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
          - 'salt/cloud/*/destroyed':
            - /opt/so/saltstack/default/salt/reactor/deleteKey.sls
            - /opt/so/saltstack/default/salt/reactor/vm_status.sls
    - user: root
    - group: root
    - mode: 644
    - makedirs: True
    - watch_in:
      - service: salt_master_service
    - order: last

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
