{%- set BROVER = salt['pillar.get']('static:broversion', 'COMMUNITY') %}
base:
  'G@role:so-sensor':
    - ca
    - ssl
    - common
    - firewall
    - pcap
    - suricata
    {%- if BROVER != 'SURICATA' %}
    - bro
    {%- endif %}
    - filebeat
    - schedule

  'G@role:so-eval':
    - ca
    - ssl
    - common
    - firewall
    - master
    - idstools
<<<<<<< HEAD
    - redis
    - mysql
=======
>>>>>>> 7816c6e18e21870b0249cc05a161ef1644a94066
    - elasticsearch
    - logstash
    - kibana
    - pcap
    - suricata
    - bro
    - curator
    - elastalert
    - filebeat
    - utility
    - schedule
    - fleet 


  'G@role:so-master':
    - ca
    - ssl
    - common
    - firewall
    - master
    - idstools
    - redis
    - mysql
    - elasticsearch
    - logstash
    - kibana
    - elastalert
    - utility
    - schedule
    - fleet

  # Storage node logic

  'G@role:so-node and I@node:node_type:parser':
    - match: pillar
    - common
    - firewall
    - logstash
    - schedule

  'G@role:so-node and I@node:node_type:hot':
    - match: pillar
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    - schedule

  'G@role:so-node and I@node:node_type:warm':
    - match: pillar
    - common
    - firewall
    - elasticsearch
    - schedule

  'G@role:so-node and I@node:node_type:storage':
    - match: compound
    - ca
    - ssl
    - common
    - firewall
    - logstash
    - elasticsearch
    - curator
    - schedule

  'G@role:mastersensor':
    - common
    - firewall
    - sensor
    - master
    - schedule
