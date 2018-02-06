base:
  'G@role:so-sensor'
    - sensor.schedule
    - sensors.{{ grains.host }}
  'G@role:so-master'
    - master.schedule
    - masters.{{ grains.host }}
