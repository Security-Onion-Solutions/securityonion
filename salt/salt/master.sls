{% from 'salt/map.jinja' import SALTNOTHELD %}
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

include:
  - salt.minion

{% if SALTNOTHELD == 1 %}
hold_salt_master_package:
  module.run:
    - pkg.hold:
      - name: salt-master
{% endif %}

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True

checkmine_engine:
  file.managed:
    - name: /etc/salt/engines/checkmine.py
    - source: salt://salt/engines/checkmine.py
    - makedirs: True
    - watch_in:
        - service: salt_minion_service

engines_config:
  file.managed:
    - name: /etc/salt/minion.d/engines.conf
    - source: salt://salt/files/engines.conf
    - watch_in:
        - service: salt_minion_service

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}