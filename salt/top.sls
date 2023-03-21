# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


{% set ZEEKVER = salt['pillar.get']('global:mdengine', '') %}
{% set PLAYBOOK = salt['pillar.get']('manager:playbook', '0') %}
{% set ELASTALERT = salt['pillar.get']('elastalert:enabled', True) %}
{% set ELASTICSEARCH = salt['pillar.get']('elasticsearch:enabled', True) %}
{% set KIBANA = salt['pillar.get']('kibana:enabled', True) %}
{% set LOGSTASH = salt['pillar.get']('logstash:enabled', True) %}
{% set REDIS = salt['pillar.get']('redis:enabled', True) %}
{% set STRELKA = salt['pillar.get']('strelka:enabled', '0') %}
{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}
{% set INSTALLEDSALTVERSION = grains.saltversion %}

base:

  '*':
    - cron.running
    - repo.client
    - ntp

  'not G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion-state-apply-test
    - salt.minion

  '* and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion
    - patch.os.schedule
    - motd
    - salt.minion-check
    - salt.lasthighstate
    - docker

  'not *_workstation and G@saltversion:{{saltversion}}':
    - match: compound
    - common
  
  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - nginx
    - pcap
    - suricata
    - healthcheck
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - schedule
    - docker_clean
    - elasticfleet.install_agent_grid

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - backup.config_backup
    - nginx
    - telegraf
    - influxdb
    - soc
    - firewall.soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - healthcheck
    - mysql
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    - utility
    - schedule
    - soctopus
    {%- if PLAYBOOK != 0 %}
    - playbook
    - redis
    {%- endif %}
    - docker_clean

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - soc
    - firewall.soc
    - kratos
    - firewall
    - manager
    - backup.config_backup
    - idstools
    - suricata.manager
    - mysql
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    - utility
    - schedule
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - backup.config_backup
    - nginx
    - telegraf
    - influxdb
    - soc
    - firewall.soc
    - kratos
    - firewall
    - idstools
    - suricata.manager    
    - healthcheck
    - mysql
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %} 
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - curator
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    - utility
    - schedule
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    - schedule
    - elasticfleet.install_agent_grid
    - docker_clean

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - soc
    - firewall.soc
    - kratos
    - firewall
    - manager
    - backup.config_backup
    - idstools
    - suricata.manager
    - mysql
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    - curator
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    {%- if ELASTALERT %}
    - elastalert
    {%- endif %}
    - utility
    - schedule
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    - curator
    {%- if STRELKA %}
    - strelka
    {%- endif %}
    - pcap
    - suricata
    {%- if ZEEKVER != 'SURICATA' %}
    - zeek
    {%- endif %}
    - schedule
    - elasticfleet.install_agent_grid
    - docker_clean
  
  '*_import and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - nginx
    - telegraf
    - influxdb
    - soc
    - firewall.soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - pcap
    {%- if ELASTICSEARCH %}
    - elasticsearch
    {%- endif %}
    {%- if KIBANA %}
    - kibana.so_savedobjects_defaults
    {%- endif %}
    - utility
    - suricata
    - zeek
    - schedule
    - elasticfleet
    - docker_clean

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    {%- if LOGSTASH %}
    - logstash
    {%- endif %}
    {%- if REDIS %}
    - redis
    {%- endif %}
    - schedule
    - elasticfleet.install_agent_grid
    - docker_clean

  '*_idh and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - schedule
    - elasticfleet.install_agent_grid
    - docker_clean
    - idh

  'J@workstation:gui:enabled:^[Tt][Rr][Uu][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:Rocky )':
    - match: compound
    - workstation

  'J@workstation:gui:enabled:^[Ff][Aa][Ll][Ss][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:Rocky )':
    - match: compound
    - workstation.remove_gui
