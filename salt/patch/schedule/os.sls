{% if salt['pillar.get']('patch:os:schedule') != 'manual' and salt['pillar.get']('patch:os:schedule') != 'auto' %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - when:
  {% for day in pillar['patch']['os']['schedule'] %}
    {% for day, time in day.iteritems() %}
      {% for each_time in time %}
        - {{day}} {{each_time}}
      {% endfor %}
    {% endfor %}
  {% endfor %}
    - splay:
        start: 5
        end: 10

{% elif salt['pillar.get']('patch:os:schedule') == 'auto' %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - minutes: 20
    - splay:
        start: 150
        end: 300

{% endif %}
