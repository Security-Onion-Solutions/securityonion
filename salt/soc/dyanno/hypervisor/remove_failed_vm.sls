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

{% do salt.log.info('soc/dyanno/hypervisor/remove_failed_vm: Running') %}
{% set vm_name = pillar.get('vm_name') %}
{% set hypervisor = pillar.get('hypervisor') %}

{% if vm_name and hypervisor %}
{%   set vm_parts = vm_name.split('_') %}
{%   if vm_parts | length >= 2 %}
{%     set vm_role = vm_parts[-1] %}
{%     set vm_hostname = '_'.join(vm_parts[:-1]) %}
{%     set vms_file = '/opt/so/saltstack/local/salt/hypervisor/hosts/' ~ hypervisor ~ 'VMs' %}

{%     do salt.log.info('soc/dyanno/hypervisor/remove_failed_vm: Removing VM ' ~ vm_name ~ ' from ' ~ vms_file) %}

remove_vm_{{ vm_name }}_from_vms_file:
  module.run:
    - name: hypervisor.remove_vm_from_vms_file
    - vms_file_path: {{ vms_file }}
    - vm_hostname: {{ vm_hostname }}
    - vm_role: {{ vm_role }}

{%   else %}
{%     do salt.log.error('soc/dyanno/hypervisor/remove_failed_vm: Invalid vm_name format: ' ~ vm_name) %}
{%   endif %}
{% else %}
{%   do salt.log.error('soc/dyanno/hypervisor/remove_failed_vm: Missing required pillar data (vm_name or hypervisor)') %}
{% endif %}

{% do salt.log.info('soc/dyanno/hypervisor/remove_failed_vm: Completed') %}

{% else %}

{% do salt.log.error(
  'Hypervisor nodes are a feature supported only for customers with a valid license. '
  'Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com '
  'for more information about purchasing a license to enable this feature.'
) %}

{% endif %}
