{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/auto_apply.map.jinja' import AUTOAPPLY %}

include:
  - salt.minion

{% if GLOBALS.is_manager and AUTOAPPLY.enabled %}
salt_beacons_pushstate:
  file.managed:
    - name: /etc/salt/minion.d/beacons_pushstate.conf
    - source: salt://manager/files/beacons_pushstate.conf.jinja
    - template: jinja
    - watch_in:
      - service: salt_minion_service
{% else %}
salt_beacons_pushstate:
  file.absent:
    - name: /etc/salt/minion.d/beacons_pushstate.conf
    - watch_in:
      - service: salt_minion_service
{% endif %}
