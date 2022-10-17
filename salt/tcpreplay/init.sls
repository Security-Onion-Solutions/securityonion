{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}

so-tcpreplay:
  docker_container.running:
    - network_mode: "host"
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-tcpreplay:{{ GLOBALS.so_version }}
    - name: so-tcpreplay
    - user: root
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/samples:/opt/so/samples:ro


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
