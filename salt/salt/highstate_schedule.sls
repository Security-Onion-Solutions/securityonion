{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'salt/schedule.map.jinja' import SCHEDULEMERGED %}

{# splay a quarter of the interval, clamped to [5 min, 30 min], so short intervals
   don't get jitter larger than the interval itself #}
{% set SPLAY = [[(SCHEDULEMERGED.highstate_interval_minutes * 60 // 4) | int, 300] | max, 1800] | min %}

highstate_schedule:
  schedule.present:
    - function: state.highstate
    - minutes: {{ SCHEDULEMERGED.highstate_interval_minutes }}
    - maxrunning: 1
{% if not GLOBALS.is_manager %}
    - splay: {{ SPLAY }}
{% endif %}
