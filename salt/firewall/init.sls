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

{% from 'firewall/map.jinja' import hostgroups with context %}
{% from 'firewall/map.jinja' import assigned_hostgroups with context %}
{% set role = grains.id.split('_') | last %}

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

{% for hostgroup, portgroups in assigned_hostgroups.role[role].hostgroups.items() %}
  {% for action in ['insert', 'delete' ] %}
    {% if hostgroups[hostgroup].ips[action] %}
      {% for ip in hostgroups[hostgroup].ips[action] %}
        {% for portgroup in portgroups.portgroups %}
          {% for proto, ports in portgroup.items() %}
            {% for port in ports %}

{{action}}_{{hostgroup}}_{{ip}}_{{port}}_{{proto}}:
  iptables.{{action}}:
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
    {% endif %}
  {% endfor %}
{% endfor %}

# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_drop_all_the_things:
  iptables.append:
    - table: filter
    - chain: LOGGING
    - jump: DROP
    - save: True
