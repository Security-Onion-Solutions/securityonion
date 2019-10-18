soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus
    - user: 939
    - group: 939
    - makedirs: True

soctopussync:
  file.recurse:
    - name: /opt/so/conf/soctopus
    - source: salt://soctopus/files
    - user: 939
    - group: 939
    - template: jinja

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

so-soctopusimage:
  cmd.run:
    - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-soctopus:HH1.1.1

so-soctopus:
  docker_container.running:
    - require:
      - so-soctopusimage
    - image: docker.io/soshybridhunter/so-soctopus:HH1.1.1
    - hostname: soctopus
    - name: so-soctopus
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
      - /opt/so/rules/elastalert/playbook:/etc/playbook-rules:rw
      - /opt/so/conf/playbook/nav_layer_playbook.json:/etc/playbook/nav_layer_playbook.json:rw
    - port_bindings:
      - 0.0.0.0:7000:7000
