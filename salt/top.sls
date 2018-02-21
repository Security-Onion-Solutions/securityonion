base:
  'G@role:sensor':
    - common
    - pcap
    
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
