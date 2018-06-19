# Default Rules for everyone

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

# Set the policy to deny everything unless defined
enable_reject_policy:
  iptables.set_policy:
    - table: filter
    - chain: INPUT
    - policy: DROP
    - require:
      - iptables: iptables_allow_localhost
      - iptables: iptables_allow_established
      - iptables: iptables_allow_ssh
      - iptables: iptables_allow_pings

# Rules if you are a Master
{% if grains['role'] == 'so-master' %}

{% for ip in pillar.get('minions')  %}

enable_salt_minions_4505_{{ip}}:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 4505
    - save: True

enable_salt_minions_4506_{{ip}}:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - proto: tcp
    - source: {{ ip }}
    - dport: 4506
    - save: True

{% endfor %}

{% endif %}

# Rules if you are a Storage Node

# Rules if you are a Sensor
{% if grains['role'] == 'so-sensor' %}

{% endif %}

# Rules if you are a Hot Node

# Rules if you are a Warm Node
