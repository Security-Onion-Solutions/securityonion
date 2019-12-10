base:
  '*':
    - patch.needs_restarting

  'G@role:so-sensor':
    - sensors.{{ grains.id }}
    - static
    - firewall.*
    - brologs

  'G@role:so-master':
    - masters.{{ grains.id }}
    - static
    - firewall.*
    - data.*
    - auth

  'G@role:so-eval':
    - masters.{{ grains.id }}
    - static
    - firewall.*
    - data.*
    - brologs
    - auth

  'G@role:so-node':
    - nodes.{{ grains.id }}
    - static
    - firewall.*

  'G@role:so-helix':
    - masters.{{ grains.id }}
    - static
    - firewall.*
    - fireeye
    - static
    - brologs
