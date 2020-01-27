base:
  '*':
    - patch.needs_restarting

  'G@role:so-mastersearch':
    - logstash.mastersearch

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

  'G@role:so-eval':
    - static
    - firewall.*
    - data.*
    - brologs
    - auth
    - minions.{{ grains.id }}

  'G@role:so-node':
    - static
    - firewall.*
    - minions.{{ grains.id }}

  'G@role:so-helix':
    - static
    - firewall.*
    - fireeye
    - static
    - brologs
    - minions.{{ grains.id }}
