{% do salt.log.info('dyanno_hypervisor_orch: Running') %}
{% set event_data = pillar.get('event_data', {}) %}
{% set event_tag = pillar.get('event_tag', '') %}
{% set timestamp = event_data.get('_stamp') %}
{% do salt.log.debug('dyanno_hypervisor_orch: tag: ' ~ event_tag) %}


{# Our custom tag #}
{% if event_tag.startswith('soc/dyanno/hypervisor') %}
{%   set status_data = event_data.get('data')%}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   set vm_name = status_data.get('vm_name') %}
{%   set hypervisor = status_data.get('hypervisor') %}
{%   set status = status_data.get('status') %}
{%   set details = status_data.get('details', '') %}
{%   do salt.log.info('dyanno_hypervisor_orch: vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}
{% endif %}

{# salt-cloud tag #}
{% if 'salt/cloud/' in event_tag and event_tag.endswith('/destroyed') %}
{%   set status_data = event_data %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Setting vm_name, hypervisor and status') %}
{%   do salt.log.debug('dyanno_hypervisor_orch: Received data: ' ~ status_data|json|string) %}
{%   set vm_name = status_data.get('name') %}
{%   set hypervisor = None %}
{%   set status = status_data.get('event') %}
{%   do salt.log.info('dyanno_hypervisor_orch: vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}
{% endif %}

{#
{% if event_tag.startswith('soc/dyanno/hypervisor') %}
{%   if vm_name and status and hypervisor %}
{%     do salt.log.info('dyanno_hypervisor_orch: soc.dyanno.hypervisor.write_status state running - vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}
# Write status file

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
          details: {{ details }}
        event_tag: {{ event_tag }}

write_vm_status:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
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
          details: {{ details }}
        event_tag: {{ event_tag }}


{%   else %}
{%     do salt.log.error('dyanno_hypervisor_orch: Missing required fields - vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}
{%   endif %}
{% endif %}
#}

{#
update_hypervisor_status:
  salt.runner:
    - name: state.orchestrate
    - mods: soc.dyanno.hypervisor
{% if event_tag.startswith('soc/dyanno/hypervisor') %}
    - require:
      - salt: write_vm_status
{% endif %}
#}

# Update hypervisor status
update_hypervisor_annotation:
  salt.state:
    - tgt: 'G@role:so-manager or G@role:so-managersearch or G@role:so-standalone or G@role:so-eval'
    - tgt_type: compound
    - sls:
      - soc.dyanno.hypervisor
    - concurrent: True
{#% if event_tag.startswith('soc/dyanno/hypervisor') %}
    - require:
      - salt: write_vm_status
{% endif %#}

{% do salt.log.info('dyanno_hypervisor_orch: Completed') %}