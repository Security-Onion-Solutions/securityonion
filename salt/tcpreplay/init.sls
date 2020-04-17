{% if grains['role'] == 'so-sensor' or grains['role'] == 'so-eval' %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}

so-tcpreplay:
  docker_container.running:
    - network_mode: "host"
    - image: {{ MASTER }}:5000/soshybridhunter/so-tcpreplay:{{ VERSION }}
    - name: so-tcpreplay
    - user: root
    - interactive: True
    - tty: True

{% endif %}
