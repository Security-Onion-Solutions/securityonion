{% set node_types = {} %}
{% for minionid, ip in salt.saltutil.runner(
    'mine.get',
    tgt='G@role:so-manager or G@role:so-managersearch or G@role:so-standalone or G@role:so-node or G@role:so-heavynode or G@role:so-receiver or G@role:so-helix ',
    fun='network.ip_addrs',
    tgt_type='compound') | dictsort() 
%}
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

logstash:
  nodes:
{% for node_type, values in node_types.items() %}
    {{node_type}}:
{%   for hostname, ip in values.items() %}
      {{hostname}}:
        ip: {{ip}}
{%   endfor %}
{% endfor %}
