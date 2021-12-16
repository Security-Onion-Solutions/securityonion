{% set node_types = {} %}
{% set manage_alived = salt.saltutil.runner('manage.alived', show_ip=True) %}
{% set manager = grains.master %}
{% set manager_type = manager.split('_')|last %}
{% for minionid, ip in salt.saltutil.runner('mine.get', tgt='*', fun='network.ip_addrs', tgt_type='glob') | dictsort() %}
{%   set hostname = minionid.split('_')[0] %}
{%   set node_type = minionid.split('_')[1] %}
{%   set is_alive = False %}
{%   if minionid in manage_alived.keys() %}
{%     if ip[0] == manage_alived[minionid] %}
{%       set is_alive = True %}
{%     endif %}
{%   endif %}
{%   if node_type not in node_types.keys() %}
{%     do node_types.update({node_type: {hostname: {'ip':ip[0], 'alive':is_alive }}}) %}
{%   else %}
{%     if hostname not in node_types[node_type] %}
{%       do node_types[node_type].update({hostname: {'ip':ip[0], 'alive':is_alive}}) %}
{%     else %}
{%       do node_types[node_type][hostname].update({'ip':ip[0], 'alive':is_alive}) %}
{%     endif %}
{%   endif %}
{% endfor %}

node_data:
{% for node_type, host_values in node_types.items() %}
  {{node_type}}:
{%   for hostname, details in host_values.items() %}
    {{hostname}}:
      ip: {{details.ip}}
      alive: {{ details.alive }}
{%   endfor %}
{% endfor %}
