{% set CHECKS = salt['pillar.get']('healthcheck:checks', {}) %}
{% set ENABLED = salt['pillar.get']('healthcheck:enabled', False) %}
{% set SCHEDULE = salt['pillar.get']('healthcheck:schedule', 30) %}

include:
  - salt

{% if CHECKS and ENABLED %}
salt_beacons:
  file.managed:
    - name: /etc/salt/minion.d/beacons.conf
    - source: salt://salt/files/beacons.conf.jinja
    - template: jinja
    - defaults:
        CHECKS: {{ CHECKS }}
        SCHEDULE: {{ SCHEDULE }}
    - watch_in: 
      - service: salt_minion_service
{% else %}
salt_beacons:
  file.absent:
    - name: /etc/salt/minion.d/beacons.conf
    - watch_in: 
      - service: salt_minion_service
{% endif %}
