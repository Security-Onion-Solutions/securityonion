base:
  '*':
    - patch.needs_restarting

  'G@role:so-sensor':
    - minions.{{ grains.id }}
    - static
    - firewall.*
    - brologs

  'G@role:so-master':
    - minions.{{ grains.id }}
    - static
    - firewall.*
    - data.*
    - auth

  'G@role:so-eval':
    - minions.{{ grains.id }}
    - static
    - firewall.*
    - data.*
    - brologs
    - auth

  'G@role:so-node':
    - minions.{{ grains.id }}
    - static
    - firewall.*

  'G@role:so-helix':
    - minions.{{ grains.id }}
    - static
    - firewall.*
    - fireeye
    - static
    - brologs
