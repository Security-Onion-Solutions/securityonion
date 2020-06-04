{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}
{% set MASTER = salt['grains.get']('master') %}

navigatorconfig:
  file.managed:
    - name: /opt/so/conf/navigator/navigator_config.json
    - source: salt://navigator/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

so-navigator:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-navigator:{{ VERSION }}
    - hostname: navigator
    - name: so-navigator
    - binds:
      - /opt/so/conf/navigator/navigator_config.json:/nav-app/src/assets/config.json:ro
      - /opt/so/conf/navigator/nav_layer_playbook.json:/nav-app/src/assets/playbook.json:ro
    - port_bindings:
      - 0.0.0.0:4200:4200
