base:
  '*':
    - patch.needs_restarting
    - docker.config

  '*_mastersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.master
    - logstash.search

  '*_sensor':
    - static
    - firewall.*
    - brologs
    - minions.{{ grains.id }}

  '*_master or *_mastersearch':
    - match: compound
    - static
    - firewall.*
    - data.*
    - minions.{{ grains.id }}

  '*_master':
    - logstash
    - logstash.master

  '*_eval':
    - static
    - firewall.*
    - data.*
    - brologs
    - logstash
    - logstash.eval
    - minions.{{ grains.id }}

  '*_node':
    - static
    - firewall.*
    - minions.{{ grains.id }}

  '*_heavynode':
    - static
    - firewall.*
    - brologs
    - minions.{{ grains.id }}

  '*_helix':
    - static
    - firewall.*
    - fireeye
    - brologs
    - logstash
    - logstash.helix
    - minions.{{ grains.id }}

  '*_fleet':
    - static
    - firewall.*
    - data.*
    - minions.{{ grains.id }}
