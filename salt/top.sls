{%- set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') -%}
{%- set OSQUERY = salt['pillar.get']('master:osquery', '0') -%}
{%- set WAZUH = salt['pillar.get']('master:wazuh', '0') -%}
{%- set THEHIVE = salt['pillar.get']('master:thehive', '0') -%}
{%- set PLAYBOOK = salt['pillar.get']('master:playbook', '0') -%}
{%- set FREQSERVER = salt['pillar.get']('master:freq', '0') -%}
{%- set DOMAINSTATS = salt['pillar.get']('master:domainstats', '0') -%}

base:
  '*':
    - patch.os.schedule
    - motd

  '*_helix':
    - ca
    - ssl
    - registry
    - common
    - firewall
    - idstools
    - pcap
    - suricata
    - zeek
    - redis
    - logstash
    - filebeat
    - schedule

  '*_sensor':
    - ca
    - ssl
    - common
    - firewall
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - wazuh
    - filebeat
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_eval':
    - ca
    - ssl
    - registry
    - master
    - common
    - soc
    - firewall
    - idstools
    - auth
    {%- if OSQUERY != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - filebeat
    - kibana
    - pcap
    - suricata
    - zeek
    - curator
    - elastalert
    {%- if OSQUERY != 0 %}
    - fleet
    - redis
    - launcher
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if THEHIVE != 0 %}
    - hive
    {%- endif %}
    {%- if PLAYBOOK != 0 %}
    - playbook
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}


  '*_master':
    - ca
    - ssl
    - registry
    - common
    - soc
    - firewall
    - master
    - idstools
    - redis
    - auth
    {%- if OSQUERY != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - kibana
    - elastalert
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
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}

  # Search node logic

  '*_node and I@node:node_type:parser':
    - match: compound
    - common
    - firewall
    - logstash
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:hot':
    - match: compound
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:warm':
    - match: compound
    - common
    - firewall
    - elasticsearch
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:search':
    - match: compound
    - ca
    - ssl
    - common
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - logstash
    - elasticsearch
    - curator
    - filebeat
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_mastersensor':
    - common
    - firewall
    - sensor
    - master
    - auth
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - schedule

  '*_mastersearch':
    - ca
    - ssl
    - registry
    - common
    - soc
    - auth
    - firewall
    - master
    - idstools
    - redis
    - auth
    {%- if OSQUERY != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - logstash
    - elasticsearch
    - curator
    - kibana
    - elastalert
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
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}

  '*_heavynode':
    - ca
    - ssl
    - common
    - firewall
    - redis
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - logstash
    - elasticsearch
    - curator
    - filebeat
    {%- if OSQUERY != 0 %}
    - launcher
    {%- endif %}
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - filebeat
    - schedule
