{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/schedule.map.jinja' import SCHEDULEMERGED %}

highstate_schedule:
  schedule.present:
    - function: state.highstate
    - hours: {{ SCHEDULEMERGED.highstate_interval_hours }}
    - maxrunning: 1
{% if not GLOBALS.is_manager %}
    - splay: 1800
{% endif %}
