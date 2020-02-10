{%- set OSQUERY = salt['pillar.get']('master:osquery', '0') -%}
{%- set WAZUH = salt['pillar.get']('master:wazuh', '0') -%}
{%- set THEHIVE = salt['pillar.get']('master:thehive', '0') -%}
{%- set PLAYBOOK = salt['pillar.get']('master:playbook', '0') -%}
{%- set FREQSERVER = salt['pillar.get']('master:freq', '0') -%}
{%- set DOMAINSTATS = salt['pillar.get']('master:domainstats', '0') -%}
{%- set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') -%}

eval:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-dockerregistry
    - so-sensoroni
    - so-idstools
    - so-auth-api
    - so-auth-ui
    {%- if OSQUERY != '0' %}
    - so-mysql
    - so-fleet
    - so-redis
    {%- endif %}
    - so-elasticsearch
    - so-logstash
    - so-kibana
    - so-steno
    - so-suricata
    - so-zeek
    - so-curator
    - so-elastalert
    {%- if WAZUH != '0' %}
    - so-wazuh
    {%- endif %}
    - so-soctopus
    {%- if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {%- endif %}
    {%- if PLAYBOOK != '0' %}
    - so-playbook
    - so-navigator
    {%- endif %}
    {%- if FREQSERVER != '0' %}
    - so-freqserver
    {%- endif %}
    {%- if DOMAINSTATS != '0' %}
    - so-domainstats
    {%- endif %}
heavy_node:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-redis
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-steno
    - so-suricata
    - so-wazuh
    - so-filebeat
    {%- if BROVER != 'SURICATA' %}
    - so-zeek
    {%- endif %}
helix:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-idstools
    - so-steno
    - so-zeek
    - so-zeek
    - so-redis
    - so-logstash
    - so-filebeat
hot_node:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-logstash
    - so-elasticsearch
    - so-curator
master_search:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-sensoroni
    - so-acng
    - so-idstools
    - so-redis
    - so-auth-api
    - so-auth-ui
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-kibana
    - so-elastalert
    - so-filebeat
    - so-soctopus
    {%- if OSQUERY != '0' %}
    - so-mysql
    - so-fleet
    - so-redis
    {%- endif %}
    {%- if WAZUH != '0' %}
    - so-wazuh
    {%- endif %}
    - so-soctopus
    {%- if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {%- endif %}
    {%- if PLAYBOOK != '0' %}
    - so-playbook
    - so-navigator
    {%- endif %}
    {%- if FREQSERVER != '0' %}
    - so-freqserver
    {%- endif %}
    {%- if DOMAINSTATS != '0' %}
    - so-domainstats
    {%- endif %}
master:
  containers:
    - so-dockerregistry
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-sensoroni
    - so-acng
    - so-idstools
    - so-redis
    - so-auth-api
    - so-auth-ui
    - so-elasticsearch
    - so-logstash
    - so-kibana
    - so-elastalert
    - so-filebeat
    {%- if OSQUERY != '0' %}
    - so-mysql
    - so-fleet
    - so-redis
    {%- endif %}
    {%- if WAZUH != '0' %}
    - so-wazuh
    {%- endif %}
    - so-soctopus
    {%- if THEHIVE != '0' %}
    - so-thehive
    - so-thehive-es
    - so-cortex
    {%- endif %}
    {%- if PLAYBOOK != '0' %}
    - so-playbook
    - so-navigator
    {%- endif %}
    {%- if FREQSERVER != '0' %}
    - so-freqserver
    {%- endif %}
    {%- if DOMAINSTATS != '0' %}
    - so-domainstats
    {%- endif %}
parser_node:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-logstash
search_node:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-logstash
    - so-elasticsearch
    - so-curator
    - so-filebeat
    {%- if WAZUH != '0' %}
    - so-wazuh
    {%- endif %}
sensor:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-steno
    - so-suricata
    {%- if BROVER != 'SURICATA' %}
    - so-zeek
    {%- endif %}
    - so-wazuh
    - so-filebeat
warm_node:
  containers:
    - so-core
    - so-telegraf
    - so-influxdb
    - so-grafana
    - so-elasticsearch
    