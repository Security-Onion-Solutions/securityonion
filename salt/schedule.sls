{%   from 'vars/globals.map.jinja' import GLOBALS %}

highstate_schedule:
  schedule.present:
    - function: state.highstate
    - minutes: 15
    - maxrunning: 1
{% if not GLOBALS.is_manager %}
    - splay: 120
{% endif %}
