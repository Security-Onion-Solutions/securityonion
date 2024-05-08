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

# prior to 2.4.30 this engine ran on the manager with salt-minion
# this has changed to running with the salt-master in 2.4.30
remove_engines_config:
  file.absent:
    - name: /etc/salt/minion.d/engines.conf
    - source: salt://salt/files/engines.conf
    - watch_in:
      - service: salt_minion_service

checkmine_engine:
  file.managed:
    - name: /etc/salt/engines/checkmine.py
    - source: salt://salt/engines/master/checkmine.py
    - makedirs: True

pillarWatch_engine:
  file.managed:
    - name: /etc/salt/engines/pillarWatch.py
    - source: salt://salt/engines/master/pillarWatch.py

engines_config:
  file.managed:
    - name: /etc/salt/master.d/engines.conf
    - source: salt://salt/files/engines.conf

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True
    - watch:
      - file: checkmine_engine
      - file: pillarWatch_engine
      - file: engines_config
    - order: last

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
