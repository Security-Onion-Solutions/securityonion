{% do salt.log.debug('vm_status_reactor: Running') %}
{% do salt.log.debug('vm_status_reactor: tag: ' ~ tag | string) %}

{# Remove all the nasty characters that exist in this data #}
{% if tag.startswith('salt/cloud/') and tag.endswith('/deploying') %}
{%   set data = {
      "_stamp": data._stamp,
      "event": data.event,
      "kwargs": {
          "cloud_grains": data.kwargs.cloud_grains
      }
} %}
{% endif %}

{% do salt.log.debug('vm_status_reactor: Received data: ' ~ data|json|string) %}

{#
update_hypervisor:
  runner.state.orchestrate:
    - args:
      - mods: orch.dyanno_hypervisor
      - pillar:
          event_tag: {{ tag }}
          event_data: {{ data }}
#}

{# Our custom tag #}
{% if tag.startswith('soc/dyanno/hypervisor') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('vm_status_reactor: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('vm_status_reactor: Setting vm_name, hypervisor and status') %}
{%   set vm_name = status_data.get('vm_name') %}
{%   set hypervisor = status_data.get('hypervisor') %}
{%   set status = status_data.get('status') %}
{%   set details = status_data.get('details', '') %}
{% endif %}

{# setup/so-minion tag #}
{% if tag == ('setup/so-minion') %}
{%   set status_data = data.get('data')%}
{%   do salt.log.debug('vm_status_reactor: Received data: ' ~ status_data|json|string) %}
{%   do salt.log.debug('vm_status_reactor: Setting vm_name, hypervisor and status') %}
{%   set vm_name = data.get('id') %}

{%   set grains = salt.saltutil.runner('cache.grains', tgt=vm_name).get(vm_name) %}
{%   if grains %}
{%     do salt.log.debug('vm_status_reactor: Got cache.grains ' ~ grains|string) %}
{%     if grains.get('salt-cloud').get('profile') %}
{%       do salt.log.debug('vm_status_reactor: Found salt-cloud:profile grain: ' ~ grains.get('salt-cloud').get('profile')|string) %}
{%       set hypervisor = grains.get('salt-cloud').get('profile').split('-')[1] %}
{%       do salt.log.debug('vm_status_reactor: Got hypervisor: ' ~ hypervisor) %}
{%     endif %}
{%   else %}
{%     do salt.log.debug('vm_status_reactor: Did not get cache.grains.') %}
{%   endif %}

{%   set hypervisor = hypervisor %}
{%   set status = 'Initialize Minion Pillars' %}
{%   set details = status_data.get('details', '') %}
{% endif %}

{# salt-cloud tag #}
{% if tag.startswith('salt/cloud/') and (tag.endswith('/creating') or tag.endswith('/deploying') or tag.endswith('/created') or tag.endswith('/destroyed')) %}
{%   do salt.log.debug('vm_status_reactor: Received data: ' ~ data|json|string) %}
{%   do salt.log.debug('vm_status_reactor: Setting vm_name, hypervisor and status') %}
{%   set vm_name = tag.split('/')[2] %}
{%   do salt.log.debug('vm_status_reactor: Got vm_name from tag: ' ~ vm_name) %}

{%   if tag.endswith('/deploying') %}
{%     set hypervisor = data.get('kwargs').get('cloud_grains').get('profile').split('-')[1] %}
{%   endif %}

{%   if data.get('profile', False) %}
{%     do salt.log.debug('vm_status_reactor: Did not get cache.grains.') %}
{%     set hypervisor = data.profile.split('-')[1] %}
{%     do salt.log.debug('vm_status_reactor: Got hypervisor from data: ' ~ hypervisor) %}
{%   else %}
{%     set grains = salt.saltutil.runner('cache.grains', tgt=vm_name).get(vm_name) %}
{%     if grains %}
{%       do salt.log.debug('vm_status_reactor: Got cache.grains: ' ~ grains|string) %}
{%       if grains.get('salt-cloud').get('profile') %}
{%         do salt.log.debug('vm_status_reactor: Found salt-cloud:profile grain: ' ~ grains.get('salt-cloud').get('profile')|string) %}
{%         set hypervisor = grains.get('salt-cloud').get('profile').split('-')[1] %}
{%         do salt.log.debug('vm_status_reactor: Got hypervisor: ' ~ hypervisor) %}
{%       endif %}
{%     endif %}
{%   endif %}

{%   set status = data.get('event').title() %}
{%   set details = data.get('details', '') %}
{% endif %}

{%   do salt.log.info('vm_status_reactor: vm_name: ' ~ vm_name ~ ' hypervisor: ' ~ hypervisor ~ ' status: ' ~ status) %}

{% set timestamp = data.get('_stamp') %}
write_vm_status:
  runner.state.orchestrate:
    - args:
      - mods: soc.dyanno.hypervisor.write_status
      - pillar:
          vm_name: {{ vm_name }}
          hypervisor: {{ hypervisor }}
          status_data:
            timestamp: {{ timestamp }}
            status: {{ status }}
          details: {{ details }}
          event_tag: {{ tag }}

update_hypervisor:
  runner.state.orchestrate:
    - args:
      - mods: orch.dyanno_hypervisor
      - pillar:
          event_tag: {{ tag }}
          event_data: {{ data }}

{% do salt.log.debug('vm_status_reactor: Completed') %}