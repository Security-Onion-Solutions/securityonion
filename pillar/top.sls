base:
  'G@role:so-sensor'
    - sensor.schedule
    - sensors.{{ hostname }}
