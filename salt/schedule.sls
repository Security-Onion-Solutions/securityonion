{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/auto_apply.map.jinja' import AUTOAPPLY %}

highstate_schedule:
  schedule.present:
    - function: state.highstate
    - hours: {{ AUTOAPPLY.highstate_interval_hours }}
    - maxrunning: 1
{% if not GLOBALS.is_manager %}
    - splay: 1800
{% endif %}

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
