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

{% do salt.log.info('dyanno_hypervisor_orch: Running') %}
{% set vm_name = None %}
{% set hypervisor = None %}
{% set status = None %}
{% set data = pillar.get('data', {}) %}
{% set tag = pillar.get('tag', '') %}
{% set timestamp = data.get('_stamp') %}
{% do salt.log.debug('dyanno_hypervisor_orch: tag: ' ~ tag) %}
{% do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ data|json|string) %}

{# Macro to find hypervisor name from VM status file #}
{% macro find_hypervisor_from_status(vm_name) -%}
  {%- set path = salt['file.find']('/opt/so/saltstack/local/salt/hypervisor/hosts/',type='f', name=vm_name ~ '.status') -%}
  {%- if path | length == 1 -%}
    {%- set parts = path[0].split('/') -%}
    {%- set hypervisor = parts[-2] -%}
    {%- do salt.log.debug('dyanno_hypervisor_orch: Found hypervisor from file.find: ' ~ hypervisor) -%}
    {{- hypervisor -}}
  {%- elif path | length == 0 -%}
    {%- do salt.log.error('dyanno_hypervisor_orch: ' ~ vm_name ~ ' not found in any hypervisor directories') -%}
    {{- '' -}}
  {%- else -%}
    {%- do salt.log.error('dyanno_hypervisor_orch: Found ' ~ vm_name ~ ' in multiple hypervisor directories: ' ~ path | string) -%}
    {{- '' -}}
  {%- endif -%}
{%- endmacro %}

{# Our custom tag #}
{% if tag.startswith('soc/dyanno/hypervisor') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   if not tag.endswith('/baseDomain') %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%     set vm_name = status_data.get('vm_name') %}
{%     set hypervisor = status_data.get('hypervisor') %}
{%   else %}
{%     set hypervisor = data.get('id') %}
{%   endif %}
{%   set status = status_data.get('status') %}
{% endif %}

{# setup/so-minion tag #}
{% if tag == ('setup/so-minion') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = data.get('id') %}
{%   set hypervisor = find_hypervisor_from_status(vm_name) %}
{%   set status = 'Initialize Minion Pillars' %}
{% endif %}


{# salt-cloud tag #}
{% if tag.startswith('salt/cloud/') and (tag.endswith('/creating') or tag.endswith('/deploying') or tag.endswith('/created') or tag.endswith('/destroyed')) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = tag.split('/')[2] %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Got vm_name from tag: ' ~ vm_name) %}
{%   if tag.endswith('/deploying') %}
{%     set hypervisor = data.get('kwargs').get('cloud_grains').get('profile').split('_')[1] %}
{%   endif %}
{#   Set the hypervisor #}
{#   First try to get it from the event #}
{%   if data.get('profile', False) %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Did not get cache.grains.') %}
{%     set hypervisor = data.profile.split('_')[1] %}
{%     do salt.log.debug('dyanno_hypervisor_orch: Got hypervisor from data: ' ~ hypervisor) %}
{%   else %}
{%     set hypervisor = find_hypervisor_from_status(vm_name) %}
{%   endif %}
{%   set status = data.get('event').title() %}
{% endif %}

{% do salt.log.info('dyanno_hypervisor_orch: vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}

{% if vm_name and hypervisor and timestamp and status and tag %}
write_vm_status:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managerhype or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - soc.dyanno.hypervisor.write_status
    - concurrent: True
    - pillar:
        vm_name: {{ vm_name }}
        hypervisor: {{ hypervisor }}
        status_data:
          timestamp: {{ timestamp }}
          status: {{ status }}
        event_tag: {{ tag }}
{% endif %}

# Update hypervisor status
update_hypervisor_annotation:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managerhype or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - soc.dyanno.hypervisor
    - concurrent: True
{% if tag == ('soc/dyanno/hypervisor/baseDomain') %}
    - pillar:
        baseDomain:
          status: {{ status }}
{% endif %}

{% do salt.log.info('dyanno_hypervisor_orch: Completed') %}

{% else %}

{% do salt.log.error(
  'Hypervisor nodes are a feature supported only for customers with a valid license.'
  'Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com'
  'for more information about purchasing a license to enable this feature.'
) %}

{% endif %}
