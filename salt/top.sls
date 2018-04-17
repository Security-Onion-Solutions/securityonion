base:
  'G@role:so-sensor':
    - common
    - pcap
    - suricata
    - bro

  'G@role:eval':
    - common
    - sensor
    - master
    - eval

  'G@role:so-master':
    - common
    - master
    - idstools
    - elasticsearch
    - logstash

  'G@role:mastersensor':
    - common
    - sensor
    - master
