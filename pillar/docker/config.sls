{%- set FLEETMANAGER = salt['pillar.get']('global:fleet_manager', False) -%}
{%- set FLEETNODE = salt['pillar.get']('global:fleet_node', False) -%}
{% set WAZUH = salt['pillar.get']('manager:wazuh', '0') %}
{% set THEHIVE = salt['pillar.get']('manager:thehive', '0') %}
{% set PLAYBOOK = salt['pillar.get']('manager:playbook', '0') %}
{% set FREQSERVER = salt['pillar.get']('manager:freq', '0') %}
{% set DOMAINSTATS = salt['pillar.get']('manager:domainstats', '0') %}
{% set ZEEKVER = salt['pillar.get']('global:mdengine', 'COMMUNITY') %}
{% set GRAFANA = salt['pillar.get']('manager:grafana', '0') %}

eval:
  containers:
    - so-nginx
    - so-telegraf
    {% if  GRAFANA == '1' %}
    - so-influxdb
    - so-grafana
    {% endif %}
    - so-dockerregistry
    - so-soc
    - so-kratos
    - so-idstools
    {% if FLEETMANAGER %}
    - so-mysql
    - so-fleet
    - so-redis
    {% endif %}
    - so-elasticsearch
    - so-logstash
    - so-kibana
    - so-steno
    - so-suricata
    - so-zeek
    - so-curator
    - so-elastalert
    {% if WAZUH != '0' %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK != '0' %}
    - so-playbook
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
heavy_node:
  containers:
    - so-nginx
    - so-telegraf
    - so-redis
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-steno
    - so-suricata
    - so-wazuh
    - so-filebeat
    {% if ZEEKVER != 'SURICATA' %}
    - so-zeek
    {% endif %}
helix:
  containers:
    - so-nginx
    - so-telegraf
    - so-idstools
    - so-steno
    - so-zeek
    - so-redis
    - so-logstash
    - so-filebeat
hot_node:
  containers:
    - so-nginx
    - so-telegraf
    - so-logstash
    - so-elasticsearch
    - so-curator
manager_search:
  containers:
    - so-nginx
    - so-telegraf
    - so-soc
    - so-kratos
    - so-acng
    - so-idstools
    - so-redis
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-kibana
    - so-elastalert
    - so-filebeat
    - so-soctopus
    {% if FLEETMANAGER %}
    - so-mysql
    - so-fleet
    - so-redis
    {% endif %}
    {% if WAZUH != '0' %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK != '0' %}
    - so-playbook
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
manager:
  containers:
    - so-dockerregistry
    - so-nginx
    - so-telegraf
    {% if  GRAFANA == '1' %}
    - so-influxdb
    - so-grafana
    {% endif %}
    - so-soc
    - so-kratos
    - so-acng
    - so-idstools
    - so-redis
    - so-elasticsearch
    - so-logstash
    - so-kibana
    - so-elastalert
    - so-filebeat
    {% if FLEETMANAGER %}
    - so-mysql
    - so-fleet
    - so-redis
    {% endif %}
    {% if WAZUH != '0' %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK != '0' %}
    - so-playbook
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
parser_node:
  containers:
    - so-nginx
    - so-telegraf
    - so-logstash
search_node:
  containers:
    - so-nginx
    - so-telegraf
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-filebeat
    {% if WAZUH != '0' %}
    - so-wazuh
    {% endif %}
sensor:
  containers:
    - so-nginx
    - so-telegraf
    - so-steno
    - so-suricata
    {% if ZEEKVER != 'SURICATA' %}
    - so-zeek
    {% endif %}
    - so-wazuh
    - so-filebeat
warm_node:
  containers:
    - so-nginx
    - so-telegraf
    - so-elasticsearch
fleet:
  containers:
    {% if FLEETNODE %}
    - so-mysql
    - so-fleet
    - so-redis
    - so-filebeat
    - so-nginx
    - so-telegraf
    {% endif %}