base:
  'G@role:so-sensor':
    - sensors.schedule
    - sensors.{{ grains.host }}
    - static
    - firewall.*
    - brologs

  'G@role:so-master':
    - masters.schedule
    - masters.{{ grains.host }}
    - static
    - firewall.*
    - data.*

  'G@role:so-eval':
    - masters.schedule
    - masters.{{ grains.host }}
    - static
    - firewall.*
    - data.*

  'G@role:so-node':
    - nodes.schedule
    - nodes.{{ grains.host }}
    - static
    - firewall.*
