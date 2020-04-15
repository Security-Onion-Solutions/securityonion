{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}

soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus
    - user: 939
    - group: 939
    - makedirs: True

soctopussync:
  file.recurse:
    - name: /opt/so/conf/soctopus/templates
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja

soctopusconf:
  file.managed:
    - name: /opt/so/conf/soctopus/SOCtopus.conf
    - source: salt://soctopus/files/SOCtopus.conf
    - user: 939
    - group: 939
    - replace: False
    - mode: 600
    - template: jinja

soctopuslogdir:
  file.directory:
    - name: /opt/so/log/soctopus
    - user: 939
    - group: 939

playbookrulesdir:
  file.directory:
    - name: /opt/so/rules/elastalert/playbook
    - user: 939
    - group: 939
    - makedirs: True

playbookrulessync:
  file.recurse:
    - name: /opt/so/rules/elastalert/playbook
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja

navigatordefaultlayer:
  file.managed:
    - name: /opt/so/conf/playbook/nav_layer_playbook.json
    - source: salt://playbook/files/nav_layer_playbook.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False
    - template: jinja

so-soctopus:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-soctopus:{{ VERSION }}
    - hostname: soctopus
    - name: so-soctopus
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
      - /opt/so/log/soctopus/:/var/log/SOCtopus/:rw
      - /opt/so/rules/elastalert/playbook:/etc/playbook-rules:rw
      - /opt/so/conf/playbook/nav_layer_playbook.json:/etc/playbook/nav_layer_playbook.json:rw
    - port_bindings:
      - 0.0.0.0:7000:7000
