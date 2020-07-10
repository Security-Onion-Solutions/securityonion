{%- set BROVER = salt['pillar.get']('static:broversion', '') -%}
{%- set WAZUH = salt['pillar.get']('static:wazuh', '0') -%}
{%- set THEHIVE = salt['pillar.get']('manager:thehive', '0') -%}
{%- set PLAYBOOK = salt['pillar.get']('manager:playbook', '0') -%}
{%- set FREQSERVER = salt['pillar.get']('manager:freq', '0') -%}
{%- set DOMAINSTATS = salt['pillar.get']('manager:domainstats', '0') -%}
{%- set FLEETMANAGER = salt['pillar.get']('static:fleet_manager', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}
{%- set STRELKA = salt['pillar.get']('strelka:enabled', '0') -%}


base:

  'os:CentOS':
    - match: grain
    - yum
    - yum.packages

  '*':
    - salt
    - docker
    - patch.os.schedule
    - motd

  '*_helix':
    - ca
    - ssl
    - registry
    - common
    - telegraf
    - firewall
    - idstools
    - suricata.manager
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
    - telegraf
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
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_eval':
    - ca
    - ssl
    - registry
    - manager
    - common
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - idstools
    - suricata.manager
    - healthcheck
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - kibana
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - filebeat
    - curator
    - elastalert
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - redis
    - fleet.install_package
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if THEHIVE != 0 %}
    - thehive
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


  '*_manager':
    - ca
    - ssl
    - registry
    - common
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - manager
    - idstools
    - suricata.manager
    - redis
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
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
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - fleet.install_package
    {%- endif %}
    - soctopus
    {%- if THEHIVE != 0 %}
    - thehive
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

  '*_standalone':
    - ca
    - ssl
    - registry
    - manager
    - common
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - idstools
    - suricata.manager    
    - healthcheck
    - redis
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - kibana
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - filebeat
    - curator
    - elastalert
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - redis
    - fleet.install_package
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if THEHIVE != 0 %}
    - thehive
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
    {%- if FLEETMANAGER or FLEETNODE %}
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
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_node and I@node:node_type:warm':
    - match: compound
    - common
    - firewall
    - elasticsearch
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_searchnode':
    - ca
    - ssl
    - common
    - nginx
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - logstash
    - elasticsearch
    - curator
    - filebeat
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_managersensor':
    - common
    - nginx
    - telegraf
    - influxdb
    - grafana
    - firewall
    - sensor
    - manager
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule

  '*_managersearch':
    - ca
    - ssl
    - registry
    - common
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - manager
    - idstools
    - suricata.manager
    - redis
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
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
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet
    - fleet.install_package
    {%- endif %}
    - soctopus
    {%- if THEHIVE != 0 %}
    - thehive
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
    - telegraf
    - firewall
    - redis
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - logstash
    - elasticsearch
    - curator
    - filebeat
    {%- if FLEETMANAGER or FLEETNODE %}
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
    - nginx
    - telegraf
    - firewall
    - mysql
    - redis
    - fleet
    - fleet.install_package
    - filebeat
