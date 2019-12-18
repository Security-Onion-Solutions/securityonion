{%- set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') -%}
{%- set OSQUERY = salt['pillar.get']('master:osquery', '0') -%}
{%- set WAZUH = salt['pillar.get']('master:wazuh', '0') -%}
{%- set GRAFANA = salt['pillar.get']('master:grafana', '0') -%}
{%- set THEHIVE = salt['pillar.get']('master:thehive', '0') -%}
{%- set PLAYBOOK = salt['pillar.get']('master:playbook', '0') -%}
base:
  '*':
    - patch.os.schedule
    - motd

  'G@role:so-helix':
    - ca
    - ssl
    - common
    - firewall
    - idstools
    - pcap
    - suricata
    - bro
    - redis
    - logstash
    - filebeat
    - schedule

  'G@role:so-sensor':
    - ca
    - ssl
    - common
    - firewall
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - bro
    {%- endif %}
    - wazuh
    - filebeat
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  'G@role:so-eval':
    - ca
    - ssl
    - common
    - sensoroni
    - firewall
    - master
    - idstools
    {%- if OSQUERY != 0 %}
    - mysql
    {%- endif %}
    - elasticsearch
    - logstash
    - kibana
    - pcap
    - suricata
    - bro
    - curator
    - cyberchef
    - elastalert
    {%- if OSQUERY != 0 %}
    - fleet
    - redis
    - launcher
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - filebeat
    - utility
    - schedule
    - soctopus
    {%- if THEHIVE != 0 %}
    - hive
    {%- endif %}
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}



  'G@role:so-master':
    - ca
    - ssl
    - common
    - cyberchef
    - sensoroni
    - firewall
    - master
    - idstools
    - redis
    {%- if OSQUERY != 0 %}
    - mysql
    {%- endif %}
    - elasticsearch
    - logstash
    - kibana
    - elastalert
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - filebeat
    - utility
    - schedule
    {%- if OSQUERY != 0 %}
    - fleet
    - launcher
    {%- endif %}
    - soctopus
    {%- if THEHIVE != 0 %}
    - hive
    {%- endif %}
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}


  # Search node logic

  'G@role:so-node and I@node:node_type:parser':
    - match: pillar
    - common
    - firewall
    - logstash
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  'G@role:so-node and I@node:node_type:hot':
    - match: pillar
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  'G@role:so-node and I@node:node_type:warm':
    - match: pillar
    - common
    - firewall
    - elasticsearch
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  'G@role:so-node and I@node:node_type:search':
    - match: compound
    - ca
    - ssl
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - filebeat
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  'G@role:mastersensor':
    - common
    - firewall
    - sensor
    - master
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule
