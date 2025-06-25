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

{# Import the process steps from map.jinja #}
{% from 'soc/dyanno/hypervisor/map.jinja' import PROCESS_STEPS %}

{% do salt.log.info('soc/dyanno/hypervisor/write_status: Running') %}
{% set vm_name = pillar.get('vm_name') %}
{% set hypervisor = pillar.get('hypervisor') %}
{% set status_data = pillar.get('status_data', {}) %}
{% set event_tag = pillar.get('event_tag') %}
{% do salt.log.debug('soc/dyanno/hypervisor/write_status: tag: ' ~ event_tag) %}
{% set base_path = '/opt/so/saltstack/local/salt/hypervisor/hosts' %}
{% set status_dir = base_path ~ '/' ~ hypervisor %}
{% set status_file = status_dir ~ '/' ~ vm_name ~ '.status' %}

{% set new_index = PROCESS_STEPS.index(status_data.get('status')) %}
{% do salt.log.debug('soc/dyanno/hypervisor/write_status: new_index: ' ~ new_index|string) %}

# Function to read and parse current JSON status file
{% macro get_current_status(status_file) %}
{% do salt.log.debug('soc/dyanno/hypervisor/write_status: getting current status from file: ' ~ status_file) %}

{% set rel_path_status_file = 'hypervisor/hosts' ~ '/' ~ hypervisor ~ '/' ~ vm_name ~ '.status' %}
{# If the status file doesn't exist, then we are just now Processing, so return -1 #}
{% if salt['file.file_exists'](status_file)%}
{%   import_json rel_path_status_file as current_status %}
{%   do salt.log.debug('soc/dyanno/hypervisor/write_status: current status: ' ~ current_status) %}
{%   do salt.log.debug('soc/dyanno/hypervisor/write_status: current status: ' ~ current_status.get('status')) %}
{%   if current_status.get('status') in PROCESS_STEPS %}
{%     set current_index = PROCESS_STEPS.index(current_status.get('status')) %}
{%     do salt.log.debug('soc/dyanno/hypervisor/write_status: current_index: ' ~ current_index|string) %}
{%-    set return_value = current_index -%}
{%   else %}
{%-    set return_value = -1 -%}
{%   endif %}
{% else %}
{%   set return_value = -1 %}
{% endif %}
{{- return_value -}}
{% endmacro %}

{% set current_index = get_current_status(status_file)|int %}
{% do salt.log.debug('soc/dyanno/hypervisor/write_status: ' ~ status_file ~ ' current status index: ' ~ current_index|string) %}

ensure_status_dir:
  file.directory:
    - name: {{ status_dir }}
    - user: 939
    - group: 939
    - mode: 755
    - makedirs: True


{# Some of the status updates trigger within a second of each other can can cause, for example, IP Configuration orchestration to process before the Processing #}
{# This check has been put in place to ensure a status sooner in the process can't overwrite this file if a status later in the process wrote to it first. #}
{# The final step is Destroyed, so we allow Processing to overwrite that incase someone creates a new VM with same name that was previously destroyed. #}
{% if new_index > current_index or (current_index == PROCESS_STEPS | length - 1 and new_index == 0) %}
write_status_file:
  file.serialize:
    - name: {{ status_file }}
    - dataset: {{ status_data|json }}
    - formatter: json
    - user: 939
    - group: 939
    - mode: 600
    - indent: 2
    - require:
      - file: ensure_status_dir
{% else %}

{%   do salt.log.debug('soc/dyanno/hypervisor/write_status: File not written. ' ~ PROCESS_STEPS[new_index] ~ ' cannot overwrite ' ~ PROCESS_STEPS[current_index] ~ '.' ) %}

{% endif %}

{% do salt.log.info('soc/dyanno/hypervisor/write_status: Completed') %}

{% else %}

{% do salt.log.error(
  'Hypervisor nodes are a feature supported only for customers with a valid license.'
  'Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com'
  'for more information about purchasing a license to enable this feature.'
) %}

{% endif %}
