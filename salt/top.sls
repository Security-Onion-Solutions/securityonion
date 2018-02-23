base:
  'G@role:so-sensor':
    - common
    - pcap
    - suricata

  'G@role:eval':
    - common
    - sensor
    - master
    - eval

  'G@role:so-master':
    - common
    - master
    - pulledpork
    - elasticsearch
    - logstash

  'G@role:mastersensor':
    - common
    - sensor
    - master
