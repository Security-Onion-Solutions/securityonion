base:
  'G@role:so-sensor':
    - sensor.schedule
    - sensors.{{ grains.host }}

  'G@role:so-master':
    - masters.schedule
    - masters.{{ grains.host }}
