{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

# Firewall Magic for the grid
{% from 'firewall/map.jinja' import hostgroups with context %}
{% from 'firewall/map.jinja' import assigned_hostgroups with context %}

create_sysconfig_iptables:
  file.touch:
    - name: /etc/sysconfig/iptables
    - makedirs: True
    - unless: 'ls /etc/sysconfig/iptables'

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

# Allow related/established sessions
iptables_allow_established:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - match: conntrack
    - ctstate: 'RELATED,ESTABLISHED'

# I like pings
iptables_allow_pings:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: icmp

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

# Enable global DOCKER-USER block rule
enable_docker_user_fw_policy:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: LOGGING
    - in-interface: '!docker0'
    - out-interface: docker0
    - position: 1

enable_docker_user_established:
  iptables.insert:
    - table: filter
    - chain: DOCKER-USER
    - jump: ACCEPT
    - in-interface: '!docker0'
    - out-interface: docker0
    - position: 1
    - match: conntrack
    - ctstate: 'RELATED,ESTABLISHED'

{% set count = namespace(value=0) %}
{% for chain, hg in assigned_hostgroups.chain.items() %}
  {% for hostgroup, portgroups in assigned_hostgroups.chain[chain].hostgroups.items() %}
    {% for action in ['insert', 'delete' ] %}
      {% if hostgroups[hostgroup].ips[action] %}
        {% for ip in hostgroups[hostgroup].ips[action] %}
          {% for portgroup in portgroups.portgroups %}
            {% for proto, ports in portgroup.items() %}
              {% for port in ports %}
                {% set count.value = count.value + 1 %}

{{action}}_{{chain}}_{{hostgroup}}_{{ip}}_{{port}}_{{proto}}_{{count.value}}:
  iptables.{{action}}:
    - table: filter
    - chain: {{ chain }}
    - jump: ACCEPT
    - proto: {{ proto }}
    - source: {{ ip }}
    - dport: {{ port }}
              {% if action == 'insert' %}
    - position: 1
              {% endif %}

              {% endfor %}
            {% endfor %}
          {% endfor %}
        {% endfor %}
      {% endif %}
    {% endfor %}
  {% endfor %}
{% endfor %}

# Block icmp timestamp response
block_icmp_timestamp_reply:
  iptables.append:
    - table: filter
    - chain: OUTPUT
    - jump: DROP
    - proto: icmp
    - icmp-type: 'timestamp-reply'

# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_drop_all_the_things:
  iptables.append:
    - table: filter
    - chain: LOGGING
    - jump: DROP
    - save: True

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}