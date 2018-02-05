base:
  'G@so-role:sensor'
    - common
    - pcap
    - logstash
    - nids
    - syslog-ng
    - bro

  'G@so-role:eval'
    - common
    - sensor
    - master
    - eval

  'G@so-role:master'
    - common
    - master

  'G@so-role:mastersensor'
    - common
    - sensor
    - master
