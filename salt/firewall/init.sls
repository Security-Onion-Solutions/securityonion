# Firewall Magic for the grid
{% if grains['role'] in ['so-eval','so-master','so-helix','so-mastersearch', 'so-standalone'] %}
  {% set ip = salt['pillar.get']('static:masterip', '') %}
{% elif grains['role'] == 'so-node' or grains['role'] == 'so-heavynode' %}
  {% set ip = salt['pillar.get']('node:mainip', '') %}
{% elif grains['role'] == 'so-sensor' %}
  {% set ip = salt['pillar.get']('sensor:mainip', '') %}
{% elif grains['role'] == 'so-fleet' %}
  {% set ip = salt['pillar.get']('node:mainip', '') %}
{% endif %}

{% set FLEET_NODE = salt['pillar.get']('static:fleet_node') %}
{% set FLEET_NODE_IP = salt['pillar.get']('static:fleet_ip') %}

{% import_yaml 'firewall/ports.yml' as firewall_ports %}
{% set firewall_aliases = salt['pillar.get']('firewall:aliases', firewall_ports.firewall.aliases, merge=True) %}

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

# Rules if you are a Master
{% if grains['role'] in ['so-master', 'so-eval', 'so-helix', 'so-mastersearch', 'so-standalone'] %}
#This should be more granular
iptables_allow_master_docker:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 172.17.0.0/24
    - position: 1
    - save: True

{% for alias in ['master', 'minions', 'forward_nodes', 'search_nodes', 'beats_endpoint', 'osquery_endpoint', 'wazuh_endpoint', 'analyst'] %}
  {% for ip in firewall_aliases[alias].ips %}
    {% for servicename, services in firewall_aliases[alias].ports.items() %}
      {% for proto, ports in services.items() %}
        {% for port in ports %}
{{alias}}_{{ip}}_{{servicename}}_{{port}}_{{proto}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: {{ proto }}
    - source: {{ ip }}
    - dport: {{ port }}
    - position: 1
    - save: True
        {% endfor %}
      {% endfor %}
    {% endfor %}
  {% endfor %}
{% endfor %}

# Allow Fleet Node to send its beats traffic
{% if FLEET_NODE %}
enable_fleetnode_beats_5644_{{FLEET_NODE_IP}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ FLEET_NODE_IP }}
    - dport: 5644
    - position: 1
    - save: True
{% endif %}

{% endif %}

# All Nodes get the below rules:
{% if 'node' in grains['role'] %}

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


{% for ip in pillar.get('firewall:masterfw')  %}

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

# All Sensors get the below rules:
{% if grains['role'] == 'so-sensor' %}
iptables_allow_sensor_docker:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 172.17.0.0/24
    - position: 1
    - save: True
{% endif %}

# Rules if you are a Hot Node

# Rules if you are a Warm Node

# All heavy nodes get the below rules:
{% if grains['role'] == 'so-heavynode' %}
# Allow Redis
enable_heavynode_redis_6379_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 6379
    - position: 1
    - save: True

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
{% endif %}


# Rules if you are a Standalone Fleet node
{% if grains['role'] == 'so-fleet' %}
#This should be more granular
iptables_allow_fleetnode_docker:
  iptables.insert:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - source: 172.17.0.0/24
    - position: 1
    - save: True

# Allow Redis
enable_fleetnode_redis_6379_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 6379
    - position: 1
    - save: True

enable_fleetnode_mysql_3306_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 3306
    - position: 1
    - save: True

enable_fleet_osquery_8080_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8080
    - position: 1
    - save: True

    
enable_fleetnodetemp_mysql_3306_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: 127.0.0.1
    - dport: 3306
    - position: 1
    - save: True

enable_fleettemp_osquery_8080_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: 127.0.0.1
    - dport: 8080
    - position: 1
    - save: True


# Allow Analysts to access Fleet WebUI
{% for ip in pillar.get('firewall:analyst')  %}

enable_fleetnode_fleet_443_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 443
    - position: 1
    - save: True

{% endfor %}

# Needed for osquery endpoints to checkin to Fleet API for mgt
{% for ip in pillar.get('firewall:osquery_endpoint')  %}

enable_fleetnode_8090_{{ip}}:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 8090
    - position: 1
    - save: True

{% endfor %}

{% endif %}
# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_drop_all_the_things:
  iptables.append:
    - table: filter
    - chain: LOGGING
    - jump: DROP
    - save: True
