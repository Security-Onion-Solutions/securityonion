{% from 'salt/map.jinja' import COMMON with context %}

{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'salt.master' in top_states %}

include:
  - salt.minion

salt_master_package:
  pkg.installed:
    - pkgs:
      - {{ COMMON }}
      - salt-master
    - hold: True

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

salt_master_state_not_allowed:
  test.fail_without_changes:
    - name: salt_master_state_not_allowed

{% endif %}