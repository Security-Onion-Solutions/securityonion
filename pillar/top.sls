base:
  'G@role:so-sensor':
    - sensors.schedule
    - sensors.{{ grains.host }}

  'G@role:so-master':
    - masters.schedule
    - masters.{{ grains.host }}
