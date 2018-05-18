{% set nodetype = salt['pillar_get']('node:node_type', 'storage') %}

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

  'G@role:so-node':
    {%- if nodetype == 'parser' %}
    - common
    - logstash
    {% elsif nodetype == 'hot' %}
    - common
    - logstash
    - elasticsearch
    {% elseif nodetype == 'warm' %}
    - common
    - elasticsearch
    {% elseif nodetype == 'storage' %}
    - common
    - logstash
    - elasticsearch
    {% endif %}

  'G@role:mastersensor':
    - common
    - sensor
    - master
