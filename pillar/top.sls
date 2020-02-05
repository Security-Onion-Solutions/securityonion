base:
  '*':
    - patch.needs_restarting

  'G@role:so-mastersearch or G@role:so-heavynode':
    - match: compound
    - logstash.master
    - logstash.search

  'G@role:so-sensor':
    - static
    - firewall.*
    - brologs
    - minions.{{ grains.id }}

  'G@role:so-master or G@role:so-mastersearch':
    - match: compound
    - static
    - firewall.*
    - data.*
    - auth
    - minions.{{ grains.id }}

  'G@role:so-master':
    - logstash.master

  'G@role:so-eval':
    - static
    - firewall.*
    - data.*
    - brologs
    - auth
    - logstash.eval
    - minions.{{ grains.id }}

  'G@role:so-node':
    - static
    - firewall.*
    - minions.{{ grains.id }}

  'G@role:so-heavynode':
    - static
    - firewall.*
    - brologs
    - minions.{{ grains.id }}

  'G@role:so-helix':
    - static
    - firewall.*
    - fireeye
    - brologs
    - logstash.helix
    - static
    - minions.{{ grains.id }}
