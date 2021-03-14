{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set CHECKS = salt['pillar.get']('healthcheck:checks', {}) %}
{% set ENABLED = salt['pillar.get']('healthcheck:enabled', False) %}
{% set SCHEDULE = salt['pillar.get']('healthcheck:schedule', 300) %}

{% if CHECKS and ENABLED %}
  {% set STATUS = ['present','enabled'] %}
{% else %}
  {% set STATUS = ['absent','disabled'] %}
nohealthchecks:
  test.configurable_test_state:
    - name: nohealthchecks
    - changes: True
    - result: True
    - comment: 'No checks are enabled for the healthcheck schedule'
{% endif %}

healthcheck_schedule_{{ STATUS[0] }}:
  schedule.{{ STATUS[0] }}:
    - name: healthcheck
    - function: healthcheck.run
    - seconds: {{ SCHEDULE }}

healthcheck_schedule_{{ STATUS[1] }}:
  schedule.{{ STATUS[1] }}:
    - name: healthcheck

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}