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

{% if 'hvn' in salt['pillar.get']('features', []) %}

{% do salt.log.info('dyanno_hypervisor_orch: Running') %}
{% set data = pillar.get('data', {}) %}
{% set tag = pillar.get('tag', '') %}
{% set timestamp = data.get('_stamp') %}
{% do salt.log.debug('dyanno_hypervisor_orch: tag: ' ~ tag) %}
{% do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ data|json|string) %}

{# Our custom tag #}
{% if tag.startswith('soc/dyanno/hypervisor') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = status_data.get('vm_name') %}
{%   set hypervisor = status_data.get('hypervisor') %}
{%   set status = status_data.get('status') %}
{% endif %}

{# setup/so-minion tag #}
{% if tag == ('setup/so-minion') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = data.get('id') %}
{%   set grains = salt.saltutil.runner('cache.grains', tgt=vm_name).get(vm_name) %}
{%   if grains %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Got cache.grains ' ~ grains|string) %}
{%     if grains.get('salt-cloud').get('profile') %}
{%       do salt.log.debug('dyanno_hypervisor_orch: Found salt-cloud:profile grain: ' ~ grains.get('salt-cloud').get('profile')|string) %}
{%       set hypervisor = grains.get('salt-cloud').get('profile').split('-')[1] %}
{%       do salt.log.debug('dyanno_hypervisor_orch: Got hypervisor: ' ~ hypervisor) %}
{%     endif %}
{%   else %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Did not get cache.grains.') %}
{%   endif %}
{%   set hypervisor = hypervisor %}
{%   set status = 'Initialize Minion Pillars' %}
{% endif %}

{# salt-cloud tag #}
{% if tag.startswith('salt/cloud/') and (tag.endswith('/creating') or tag.endswith('/deploying') or tag.endswith('/created') or tag.endswith('/destroyed')) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = tag.split('/')[2] %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Got vm_name from tag: ' ~ vm_name) %}
{%   if tag.endswith('/deploying') %}
{%     set hypervisor = data.get('kwargs').get('cloud_grains').get('profile').split('-')[1] %}
{%   endif %}
{%   if data.get('profile', False) %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Did not get cache.grains.') %}
{%     set hypervisor = data.profile.split('-')[1] %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Got hypervisor from data: ' ~ hypervisor) %}
{%   else %}
{%     set grains = salt.saltutil.runner('cache.grains', tgt=vm_name).get(vm_name) %}
{%     if grains %}
{%       do salt.log.debug('dyanno_hypervisor_orch: Got cache.grains: ' ~ grains|string) %}
{%       if grains.get('salt-cloud').get('profile') %}
{%         do salt.log.debug('dyanno_hypervisor_orch: Found salt-cloud:profile grain: ' ~ grains.get('salt-cloud').get('profile')|string) %}
{%         set hypervisor = grains.get('salt-cloud').get('profile').split('-')[1] %}
{%         do salt.log.debug('dyanno_hypervisor_orch: Got hypervisor: ' ~ hypervisor) %}
{%       endif %}
{%     endif %}
{%   endif %}
{%   set status = data.get('event').title() %}
{% endif %}

{% do salt.log.info('dyanno_hypervisor_orch: vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}


{# We will need to populate hypervisor:hosts in this orch and pass to state to run as runner
update_hypervisor_status:
  salt.runner:
    - name: state.orchestrate
    - mods: soc.dyanno.hypervisor
{% if event_tag.startswith('soc/dyanno/hypervisor') %}
    - require:
      - salt: write_vm_status
{% endif %}
#}

write_vm_status:
  salt.runner:
    - name: state.orchestrate
    - mods: soc.dyanno.hypervisor.write_status
    - pillar:
        vm_name: {{ vm_name }}
        hypervisor: {{ hypervisor }}
        status_data:
          timestamp: {{ timestamp }}
          status: {{ status }}
        event_tag: {{ tag }}

# Update hypervisor status
update_hypervisor_annotation:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - soc.dyanno.hypervisor
    - concurrent: True
    - require:
      - salt: write_vm_status

{% do salt.log.info('dyanno_hypervisor_orch: Completed') %}

{% else %}

{% do salt.log.error(
  'Hypervisor nodes are a feature supported only for customers with a valid license.'
  'Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com'
  'for more information about purchasing a license to enable this feature.'
) %}

{% endif %}
