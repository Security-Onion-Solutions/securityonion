{% set node_types = {} %}
{% for minionid, ip in salt.saltutil.runner(
    'mine.get',
    tgt='redis:enabled:true',
    fun='network.ip_addrs',
    tgt_type='pillar') | dictsort()
%}

# only add a node to the pillar if it returned an ip from the mine
{%   if ip | length > 0%}
{%     set hostname = minionid.split('_') | first %}
{%     set node_type = minionid.split('_') | last %}
{%     if node_type not in node_types.keys() %}
{%       do node_types.update({node_type: {hostname: ip[0]}}) %}
{%     else %}
{%       if hostname not in node_types[node_type] %}
{%         do node_types[node_type].update({hostname: ip[0]}) %}
{%       else %}
{%         do node_types[node_type][hostname].update(ip[0]) %}
{%       endif %}
{%     endif %}
{%   endif %}
{% endfor %}


redis:
  nodes:
{% for node_type, values in node_types.items() %}
    {{node_type}}:
{%   for hostname, ip in values.items() %}
      {{hostname}}:
        ip: {{ip}}
{%   endfor %}
{% endfor %}
