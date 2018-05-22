base:
  'G@role:so-sensor':
    - common
    - pcap
    - suricata
    - bro
    - filebeat

  'G@role:eval':
    - common
    - sensor
    - master
    - eval

  'G@role:so-master':
    - common
    - master
    - idstools
    - redis
    - elasticsearch
    - logstash

  # Storage node logic

  'node_type:parser':
    - match: pillar
    - common
    - logstash

  'node_type:hot':
    - match: pillar
    - common
    - logstash
    - elasticsearch

  'node_type:warm':
    - match: pillar
    - common
    - elasticsearch

  'node_type:storage':
    - match: pillar
    - common
    - logstash
    - elasticsearch

  'G@role:mastersensor':
    - common
    - sensor
    - master
