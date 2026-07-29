{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/auto_apply.map.jinja' import AUTOAPPLY %}

{% if GLOBALS.is_manager and AUTOAPPLY.enabled %}
push_drain_schedule:
  schedule.present:
    - function: cmd.run
    - job_args:
      - /usr/sbin/so-push-drainer
    - seconds: {{ AUTOAPPLY.drain_interval }}
    - maxrunning: 1
    - return_job: False
{% elif GLOBALS.is_manager %}
push_drain_schedule:
  schedule.absent:
    - name: push_drain_schedule
{% endif %}
