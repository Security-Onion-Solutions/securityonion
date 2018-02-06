base:
  'G@role:so-sensor'
    - sensor.schedule
    - sensors.{{ hostname }}
  'G@role:so-master'
    - master.schedule
    - masters.{{ hostname }}
