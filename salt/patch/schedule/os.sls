{% if salt['pillar.get']('patch:os:schedule') != 'manual' and salt['pillar.get']('patch:os:schedule') != 'auto' %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - when:
  {% for days in pillar['patch']['os']['schedule'] %}
    {% for day, times in days.iteritems() %}
      {% for time in times %}
        - {{day}} {{time}}
      {% endfor %}
    {% endfor %}
  {% endfor %}
    - splay:
        start: 30
        end: 120

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
