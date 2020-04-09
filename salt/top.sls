{%- set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') -%}
{%- set WAZUH = salt['pillar.get']('static:wazuh', '0') -%}
{%- set THEHIVE = salt['pillar.get']('master:thehive', '0') -%}
{%- set PLAYBOOK = salt['pillar.get']('master:playbook', '0') -%}
{%- set FREQSERVER = salt['pillar.get']('master:freq', '0') -%}
{%- set DOMAINSTATS = salt['pillar.get']('master:domainstats', '0') -%}
{%- set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}
{%- set STRELKA = salt['pillar.get']('static:strelka', '0') -%}


base:
  '*':
    - patch.os.schedule
    - motd
    - salt

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
    - healthcheck
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - wazuh
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - filebeat
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
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
    - healthcheck
    {%- if FLEETMASTER or FLEETNODE %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - kibana
    - pcap
    - suricata
    - zeek
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - filebeat
    - curator
    - elastalert
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet
    - redis
    - fleet.install_package
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
    {%- if FLEETMASTER or FLEETNODE %}
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
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet
    - fleet.install_package
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
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:hot':
    - match: compound
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:warm':
    - match: compound
    - common
    - firewall
    - elasticsearch
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_searchnode':
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
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_mastersensor':
    - common
    - firewall
    - sensor
    - master
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_mastersearch':
    - ca
    - ssl
    - registry
    - common
    - soc
    - firewall
    - master
    - idstools
    - redis
    {%- if FLEETMASTER or FLEETNODE %}
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
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet
    - fleet.install_package
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
    {%- if FLEETMASTER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - filebeat
    - schedule
  
  '*_fleet':
    - ca
    - ssl
    - common
    - firewall
    - mysql
    - redis
    - fleet
    - fleet.install_package
    - filebeat
