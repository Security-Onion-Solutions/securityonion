{% if salt['service.status']('salt-minion', True) %}
schedule:
  schedule.present:
    - function: state.highstate
    - minutes: 15
    - maxrunning: 1
{% endif %}
