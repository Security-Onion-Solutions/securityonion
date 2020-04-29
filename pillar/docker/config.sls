{% set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) %}
{% set FLEETNODE = salt['pillar.get']('static:fleet_node', False) %}
{% set WAZUH = salt['pillar.get']('master:wazuh', False) %}
{% set THEHIVE = salt['pillar.get']('master:thehive', False) %}
{% set PLAYBOOK = salt['pillar.get']('master:playbook', False) %}
{% set FREQSERVER = salt['pillar.get']('master:freq', False) %}
{% set DOMAINSTATS = salt['pillar.get']('master:domainstats', False) %}
{% set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') %}
{% set GRAFANA = salt['pillar.get']('master:grafana', False) %}

eval:
  containers:
    - so-core
    - so-telegraf
    {% if  GRAFANA %}
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
    - so-kibana
    - so-steno
    - so-suricata
    - so-zeek
    - so-curator
    - so-elastalert
    {% if WAZUH %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK %}
    - so-playbook
    - so-navigator
    {% endif %}
    {% if FREQSERVER %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS %}
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
    {% if WAZUH %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK %}
    - so-playbook
    - so-navigator
    {% endif %}
    {% if FREQSERVER %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS %}
    - so-domainstats
    {% endif %}
master:
  containers:
    - so-dockerregistry
    - so-core
    - so-telegraf
    {% if  GRAFANA %}
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
    {% if WAZUH %}
    - so-wazuh
    {% endif %}
    - so-soctopus
    {% if THEHIVE %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {% endif %}
    {% if PLAYBOOK %}
    - so-playbook
    - so-navigator
    {% endif %}
    {% if FREQSERVER %}
    - so-freqserver
    {% endif %}
    {% if DOMAINSTATS %}
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
    {% if WAZUH %}
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