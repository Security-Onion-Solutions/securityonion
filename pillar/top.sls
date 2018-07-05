base:
  'G@role:so-sensor':
    - sensors.schedule
    - sensors.{{ grains.host }}
    - static

  'G@role:so-master':
    - masters.schedule
    - masters.{{ grains.host }}
    - static
    - firewall.*
