base:
  'G@role:so-sensor':
    - sensors.{{ grains.host }}
    - static
    - firewall.*
    - brologs

  'G@role:so-master':
    - masters.{{ grains.host }}
    - static
    - firewall.*
    - data.*
    - auth

  'G@role:so-eval':
    - masters.{{ grains.host }}
    - static
    - firewall.*
    - data.*
    - brologs
    - auth

  'G@role:so-node':
    - nodes.{{ grains.host }}
    - static
    - firewall.*
