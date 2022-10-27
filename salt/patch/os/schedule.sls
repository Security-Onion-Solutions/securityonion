{% from 'patch/os/schedules/map.jinja' import PATCHMERGED %}

{% if PATCHMERGED.os.enabled %}
  {% set SCHEDULE_TO_RUN = PATCHMERGED.os.schedule_to_run %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - splay: {{PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].splay}}
    - return_job: True
  {# check if *day is in the schedule #}
  {% if PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].schedule.keys() | select("match", ".*day") | list | length  > 0 %}

    - when:
        {% for day, times in PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].schedule.items() %}
          {% for time in times %}
        - {{day}} {{time}}
            {% endfor %}
        {% endfor %}
  {# check if days, hours, minutes is in the schedule #}
  {% elif PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].schedule.keys() | select("match", "days|hours|minutes") | list | length > 0 %}
    {% set DHM = PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].schedule.keys() | first %}

    - {{DHM}}: {{ PATCHMERGED.os.schedules[SCHEDULE_TO_RUN].schedule[DHM] }}

  {% endif %}

{% else %}

remove_patch_os_schedule:
  schedule.absent:
    - name: patch_os_schedule

{% endif %}
