{% if grains['role'] == 'so-sensor' or grains['role'] == 'so-eval' %}
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

{% endif %}
