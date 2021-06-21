{% if salt['pillar.get']('patch:os:schedule_name') %}
    {% set patch_os_pillar = salt['pillar.get']('patch:os') %}
    {% set schedule_name = patch_os_pillar.schedule_name %}
    {% set splay = patch_os_pillar.get('splay', 300) %}

    {% if schedule_name != 'manual' and schedule_name != 'auto' %}
      {% import_yaml "patch/os/schedules/"~schedule_name~".yml" as os_schedule %}

      {% if patch_os_pillar.enabled %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - when:
        {% for days in os_schedule.patch.os.schedule %}
          {% for day, times in days.items() %}
            {% for time in times %}
        - {{day}} {{time}}
            {% endfor %}
          {% endfor %}
        {% endfor %}
    - splay: {{splay}}
    - return_job: True

      {% else %}

disable_patch_os_schedule:
  schedule.disabled:
    - name: patch_os_schedule

      {% endif %}


    {% elif schedule_name == 'auto' %}

      {% if patch_os_pillar.enabled %}

patch_os_schedule:
  schedule.present:
    - function: state.sls
    - job_args:
      - patch.os
    - hours: 8 
    - splay: {{splay}}
    - return_job: True

      {% else %}

disable_patch_os_schedule:
  schedule.disabled:
    - name: patch_os_schedule

      {% endif %}

    {% elif schedule_name == 'manual' %}

remove_patch_os_schedule:
  schedule.absent:
    - name: patch_os_schedule

    {% endif %}

{% else %}

no_patch_os_schedule_name_set:
  test.fail_without_changes:
    - name: "Set a pillar value for patch:os:schedule_name in this minion's .sls file. If an OS patch schedule is not listed as enabled in show_schedule output below, then OS patches will need to be applied manually until this is corrected."

show_patch_os_schedule:
  module.run:
    - schedule.is_enabled:
      - name: patch_os_schedule

{% endif %}
