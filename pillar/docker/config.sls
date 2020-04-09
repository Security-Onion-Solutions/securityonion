{%- set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}
{% set WAZUH = salt['pillar.get']('master:wazuh', '0') %}
{% set THEHIVE = salt['pillar.get']('master:thehive', '0') %}
{% set PLAYBOOK = salt['pillar.get']('master:playbook', '0') %}
{% set FREQSERVER = salt['pillar.get']('master:freq', '0') %}
{% set DOMAINSTATS = salt['pillar.get']('master:domainstats', '0') %}
{% set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') %}
{% set GRAFANA = salt['pillar.get']('master:grafana', '0') %}

eval:
  containers:
    - so-core
    - so-telegraf
    {% if  GRAFANA == '1' %}
    - so-influxdb
    - so-grafana
    {% endif %}
    - so-dockerregistry
    - so-soc
    - so-kratos
    - so-idstools
    {% if FLEETMASTER %}
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
    - so-navigator
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
heavy_node:
  containers:
    - so-core
    - so-telegraf
    - so-redis
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-steno
    - so-suricata
    - so-wazuh
    - so-filebeat
    {% if BROVER != 'SURICATA' %}
    - so-zeek
    {% endif %}
helix:
  containers:
    - so-core
    - so-telegraf
    - so-idstools
    - so-steno
    - so-zeek
    - so-redis
    - so-logstash
    - so-filebeat
hot_node:
  containers:
    - so-core
    - so-telegraf
    - so-logstash
    - so-elasticsearch
    - so-curator
master_search:
  containers:
    - so-core
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
    {% if FLEETMASTER %}
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
    - so-navigator
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
master:
  containers:
    - so-dockerregistry
    - so-core
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
    {% if FLEETMASTER %}
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
    - so-navigator
    {% endif %}
    {% if FREQSERVER != '0' %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS != '0' %}
    - so-domainstats
    {% endif %}
parser_node:
  containers:
    - so-core
    - so-telegraf
    - so-logstash
search_node:
  containers:
    - so-core
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
    - so-core
    - so-telegraf
    - so-steno
    - so-suricata
    {% if BROVER != 'SURICATA' %}
    - so-zeek
    {% endif %}
    - so-wazuh
    - so-filebeat
warm_node:
  containers:
    - so-core
    - so-telegraf
    - so-elasticsearch
fleet:
  containers:
    {% if FLEETNODE %}
    - so-mysql
    - so-fleet
    - so-redis
    - so-filebeat
    - so-core
    - so-telegraf
    {% endif %}