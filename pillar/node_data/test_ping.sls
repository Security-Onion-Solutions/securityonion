{% set node_types = {} %}
{% for minionid, test_ping in salt.saltutil.runner('mine.get', tgt='*', fun='test.ping', tgt_type='glob') | dictsort() %}
{%   set node_type = minionid.split('_')[1] %}
{%   set hostname = minionid.split('_')[0] %}
{%   if node_type not in node_types.keys() %}
{%     do node_types.update({node_type: {hostname: test_ping}}) %}
{%   else %}
{%     if hostname not in node_types[node_type] %}
{%       do node_types[node_type].update({hostname: test_ping}) %}
{%     else %}
{%       do node_types[node_type][hostname].update(test_ping) %}
{%     endif %}
{%   endif %}
{% endfor %}

node_data:
{% for node_type, values in node_types.items() %}
  {{node_type}}:
{%   for hostname, test_ping in values.items() %}
    {{hostname}}:
      test_ping: {{test_ping}}
{%   endfor %}
{% endfor %}
