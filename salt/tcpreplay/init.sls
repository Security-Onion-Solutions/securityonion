{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

so-tcpreplay:
  docker_container.running:
    - network_mode: "host"
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-tcpreplay:{{ VERSION }}
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
