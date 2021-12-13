{% set node_types = {} %}
{% for minionid, ip in salt.saltutil.runner('mine.get', tgt='*', fun='network.ip_addrs', tgt_type='glob') | dictsort() %}
{%   set hostname = minionid.split('_')[0] %}
{%   set node_type = minionid.split('_')[1] %}
{%   if node_type not in node_types.keys() %}
{%     do node_types.update({node_type: {hostname: ip[0]}}) %}
{%   else %}
{%     if hostname not in node_types[node_type] %}
{%       do node_types[node_type].update({hostname: ip[0]}) %}
{%     else %}
{%       do node_types[node_type][hostname].update(ip[0]) %}
{%     endif %}
{%   endif %}
{% endfor %}

node_data:
{% for node_type, values in node_types.items() %}
  {{node_type}}:
{%   for hostname, ip in values.items() %}
    {{hostname}}:
      ip: {{ip}}
{%   endfor %}
{% endfor %}
