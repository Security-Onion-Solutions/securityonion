{% set ZEEKVER = salt['pillar.get']('global:mdengine', '') %}
{% set WAZUH = salt['pillar.get']('global:wazuh', '0') %}
{% set THEHIVE = salt['pillar.get']('manager:thehive', '0') %}
{% set PLAYBOOK = salt['pillar.get']('manager:playbook', '0') %}
{% set FREQSERVER = salt['pillar.get']('manager:freq', '0') %}
{% set DOMAINSTATS = salt['pillar.get']('manager:domainstats', '0') %}
{% set FLEETMANAGER = salt['pillar.get']('global:fleet_manager', False) %}
{% set FLEETNODE = salt['pillar.get']('global:fleet_node', False) %}
{% set STRELKA = salt['pillar.get']('strelka:enabled', '0') %}
{% set ISAIRGAP = salt['pillar.get']('global:airgap', 'False') %}
{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}

base:

  'not G@saltversion:{{saltversion}}':
    - match: compound
    {% if ISAIRGAP is sameas true %}
    - airgap
    {% endif %}
    - salt.minion

  'G@os:CentOS and G@saltversion:{{saltversion}}':
    - match: compound
    {% if ISAIRGAP is sameas true %}
    - airgap
    {% else %}
    - yum
    {% endif %}
    - yum.packages

  '* and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion
    - common
    - patch.os.schedule
    - motd
  
  '*_helix and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
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

  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - ca
    - ssl
    - common
    - telegraf
    - firewall
    - nginx
    - pcap
    - suricata
    - healthcheck
    {%- if ZEEKVER != 'SURICATA' %}
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
    - docker_clean

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
    - manager
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
    {%- if ZEEKVER != 'SURICATA' %}
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
    - redis
    {%- endif %}
    {%- if FREQSERVER != 0 %}
    - freqserver
    {%- endif %}
    {%- if DOMAINSTATS != 0 %}
    - domainstats
    {%- endif %}
    - docker_clean

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - manager
    - idstools
    - suricata.manager
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - redis
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
    - docker_clean

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
    - manager
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
    - logstash
    - redis
    - kibana
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
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
    - docker_clean

  # Search node logic

  '*_node and I@node:node_type:parser and G@saltversion:{{saltversion}}':
    - match: compound
    - common
    - firewall
    - logstash
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_node and I@node:node_type:hot and G@saltversion:{{saltversion}}':
    - match: compound
    - common
    - firewall
    - logstash
    - curator
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_node and I@node:node_type:warm and G@saltversion:{{saltversion}}':
    - match: compound
    - common
    - firewall
    - elasticsearch
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - ca
    - ssl
    - common
    - nginx
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - curator
    - filebeat
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - schedule
    - docker_clean

  '*_managersensor and G@saltversion:{{saltversion}}':
    - match: compound
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
    - docker_clean

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
    - nginx
    - telegraf
    - influxdb
    - grafana
    - soc
    - firewall
    - manager
    - idstools
    - suricata.manager
    {%- if FLEETMANAGER or FLEETNODE or PLAYBOOK != 0 %}
    - mysql
    {%- endif %}
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - redis
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
    - docker_clean

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - ca
    - ssl
    - common
    - nginx
    - telegraf
    - firewall
    {%- if WAZUH != 0 %}
    - wazuh
    {%- endif %}
    - elasticsearch
    - logstash
    - redis
    - curator
    - filebeat
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    {%- if FLEETMANAGER or FLEETNODE %}
    - fleet.install_package
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - filebeat
    - schedule
    - docker_clean
  
  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
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
    - docker_clean

  '*_import and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - common
    - registry
    - manager
    - nginx
    - soc
    - firewall
    - idstools
    - suricata.manager
    - pcap
    - elasticsearch
    - kibana
    - filebeat
    - utility
    - suricata
    - zeek
    - schedule
    - docker_clean
