{% set current_kafkanodes = salt.saltutil.runner('mine.get', tgt='G@role:so-kafkanode', fun='network.ip_addrs', tgt_type='compound') %}
{% set pillar_kafkanodes = salt['pillar.get']('kafka:nodes', default={}, merge=True) %}

{% set existing_ids = [] %}
{% for node in pillar_kafkanodes.values() %}
  {% if node.get('id') %}
    {% do existing_ids.append(node['nodeid']) %}
  {% endif %}
{% endfor %}
{% set all_possible_ids = range(1, 256)|list %}

{% set available_ids = [] %}
{% for id in all_possible_ids %}
  {% if id not in existing_ids %}
    {% do available_ids.append(id) %}
  {% endif %}
{% endfor %}

{% set final_nodes = pillar_kafkanodes.copy() %}

{% for minionid, ip in current_kafkanodes.items() %}
    {% set hostname = minionid.split('_')[0] %}
    {% if hostname not in final_nodes %}
        {% set new_id = available_ids.pop(0) %}
        {% do final_nodes.update({hostname: {'nodeid': new_id, 'ip': ip[0]}}) %}
    {% endif %}
{% endfor %}

kafka:
  nodes: {{ final_nodes|tojson }}