# Firewall Magic for the grid
{%- if grains['role'] == 'so-master' or grains['role'] == 'so-eval' %}
{%- set ip = salt['pillar.get']('static:masterip', '') %}
{%- elif grains['role'] == 'so-node' %}
{%- set ip = salt['pillar.get']('node:mainip', '') %}
{%- elif grains['role'] == 'so-sensor' %}
{%- set ip = salt['pillar.get']('sensor:mainip', '') %}
{%- endif %}
# Quick Fix for Docker being difficult
iptables_fix_docker:
  iptables.chain_present:
    - name: DOCKER-USER
    - table: filter

# Add the Forward Rule since Docker ripped it out
iptables_fix_fwd:
  iptables.insert:
    - table: filter
    - chain: FORWARD
    - jump: ACCEPT
    - position: 1
    - target: DOCKER-USER
    
# Keep localhost in the game
iptables_allow_localhost:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 127.0.0.1
    - save: True

# Allow related/established sessions
iptables_allow_established:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - match: conntrack
    - ctstate: 'RELATED,ESTABLISHED'
    - save: True

# Always allow SSH so we can like log in
iptables_allow_ssh:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - dport: 22
    - proto: tcp
    - save: True

# I like pings
iptables_allow_pings:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: icmp
    - save: True

# Create the chain for logging
iptables_LOGGING_chain:
  iptables.chain_present:
    - name: LOGGING
    - table: filter
    - family: ipv4

iptables_LOGGING_limit:
  iptables.append:
    - table: filter
    - chain: LOGGING
    - match: limit
    - jump: LOG
    - limit: 2/min
    - log-level: 4
    - log-prefix: "IPTables-dropped: "

# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_log_input_drops:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: LOGGING
    - save: True

# Enable global DOCKER-USER block rule
enable_docker_user_fw_policy:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: LOGGING
    - in-interface: '!docker0'
    - out-interface: docker0
    - position: 1
    - save: True

enable_docker_user_established:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - in-interface: '!docker0'
    - out-interface: docker0
    - position: 1
    - save: True
    - match: conntrack
    - ctstate: 'RELATED,ESTABLISHED'

# Add rule(s) for Wazuh manager
enable_wazuh_manager_1514_tcp_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 1514
    - position: 1
    - save: True

enable_wazuh_manager_1514_udp_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: udp
    - source: {{ ip }}
    - dport: 1514
    - position: 1
    - save: True

# Rules if you are a Master
{% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' %}
#This should be more granular
iptables_allow_master_docker:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 172.17.0.0/24
    - position: 1
    - save: True

{% for ip in pillar.get('masterfw')  %}
# Allow Redis
enable_maternode_redis_6379_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 6379
    - position: 1
    - save: True

enable_masternode_kibana_5601_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 5601
    - position: 1
    - save: True

enable_masternode_ES_9200_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9200
    - position: 1
    - save: True

enable_masternode_ES_9300_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9300
    - position: 1
    - save: True

enable_masternode_ES_9400_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9400
    - position: 1
    - save: True

enable_masternode_ES_9500_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9500
    - position: 1
    - save: True

enable_masternode_influxdb_8086_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8086
    - position: 1
    - save: True

enable_masternode_mysql_3306_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 3306
    - position: 1
    - save: True

enable_master_osquery_8080_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8080
    - position: 1
    - save: True

enable_master_playbook_3200_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 3200
    - position: 1
    - save: True

enable_master_navigator_4200_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 4200
    - position: 1
    - save: True
 
enable_master_cortex_9001_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9001
    - position: 1
    - save: True 

{% endfor %}

# Make it so all the minions can talk to salt and update etc.
{% for ip in pillar.get('minions')  %}

enable_salt_minions_4505_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 4505
    - position: 1
    - save: True

enable_salt_minions_4506_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 4506
    - position: 1
    - save: True

enable_salt_minions_5000_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 5000
    - position: 1
    - save: True

enable_salt_minions_3142_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 3142
    - position: 1
    - save: True

enable_minions_influxdb_8086_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8086
    - position: 1
    - save: True

enable_minion_osquery_8080_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8080
    - position: 1
    - save: True

{% endfor %}

# Allow Forward Nodes to send their beats traffic
{% for ip in pillar.get('forward_nodes')  %}

enable_forwardnode_beats_5044_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 5044
    - position: 1
    - save: True

enable_forwardnode_beats_5644_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 5644
    - position: 1
    - save: True

enable_forwardnode_sensoroni_443_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 443
    - position: 1
    - save: True

enable_forwardnode_sensoroni_9822_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9822
    - position: 1
    - save: True

{% endfor %}

{% for ip in pillar.get('storage_nodes')  %}

enable_storagenode_redis_6379_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 6379
    - position: 1
    - save: True

enable_storagenode_ES_9300_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9300
    - position: 1
    - save: True

{% endfor %}

# Allow Beats Endpoints to send their beats traffic
{% for ip in pillar.get('beats_endpoint')  %}

enable_standard_beats_5044_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 5044
    - position: 1
    - save: True

{% endfor %}

# Allow OSQuery Endpoints to send their traffic
{% for ip in pillar.get('osquery_endpoint')  %}

enable_standard_osquery_8080_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8080
    - position: 1
    - save: True

{% endfor %}

# Allow Wazuh Endpoints to send their traffic
{% for ip in pillar.get('wazuh_endpoint')  %}

enable_wazuh_endpoint_tcp_1514_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 1514
    - position: 1
    - save: True

enable_wazuh_endpoint_udp_1514_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: udp
    - source: {{ ip }}
    - dport: 1514
    - position: 1
    - save: True

{% endfor %}

# Allow Analysts
{% for ip in pillar.get('analyst')  %}

enable_standard_analyst_80_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 80
    - position: 1
    - save: True

enable_standard_analyst_443_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 443
    - position: 1
    - save: True

#enable_standard_analyst_3000_{{ip}}:
#  iptables.insert:
#    - table: filter
#    - chain: DOCKER-USER
#    - jump: ACCEPT
#    - proto: tcp
#    - source: {{ ip }}
#    - dport: 3000
#    - position: 1
#    - save: True

#enable_standard_analyst_7000_{{ip}}:
#  iptables.insert:
#    - table: filter
#    - chain: DOCKER-USER
#    - jump: ACCEPT
#    - proto: tcp
#    - source: {{ ip }}
#    - dport: 7000
#    - position: 1
#    - save: True

#enable_standard_analyst_9000_{{ip}}:
#  iptables.insert:
#    - table: filter
#    - chain: DOCKER-USER
#    - jump: ACCEPT
#    - proto: tcp
#    - source: {{ ip }}
#    - dport: 9000
#    - position: 1
#    - save: True

#enable_standard_analyst_9001_{{ip}}:
#  iptables.insert:
#    - table: filter
#    - chain: DOCKER-USER
#    - jump: ACCEPT
#    - proto: tcp
#    - source: {{ ip }}
#    - dport: 9001
#    - position: 1
#    - save: True

# This is temporary for sensoroni testing
#enable_standard_analyst_9822_{{ip}}:
#  iptables.insert:
#    - table: filter
#    - chain: DOCKER-USER
#    - jump: ACCEPT
#    - proto: tcp
#    - source: {{ ip }}
#    - dport: 9822
#    - position: 1
#    - save: True

{% endfor %}

# Rules for storage nodes connecting to master


{% endif %}

# Rules if you are a Storage Node
{% if grains['role'] == 'so-node' %}

#This should be more granular
iptables_allow_docker:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 172.17.0.0/24
    - position: 1
    - save: True

enable_docker_ES_9200:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: 172.17.0.0/24
    - dport: 9200
    - position: 1
    - save: True


enable_docker_ES_9300:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: 172.17.0.0/24
    - dport: 9300
    - position: 1
    - save: True


{% for ip in pillar.get('masterfw')  %}

enable_cluster_ES_9300_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 9300
    - position: 1
    - save: True


{% endfor %}
{% endif %}

# Rules if you are a Sensor
{% if grains['role'] == 'so-sensor' %}

{% endif %}

# Rules if you are a Hot Node

# Rules if you are a Warm Node

# Some Fixer upper type rules
# Drop it like it's hot
# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_drop_all_the_things:
  iptables.append:
    - table: filter
    - chain: LOGGING
    - jump: DROP
    - save: True
