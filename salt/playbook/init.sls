navigatordefaultlayer:
  file.manage:
    - name: /opt/so/conf/playbook/nav_layer_playbook.json
    - source: salt://playbook/files/nav_layer_playbook.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False
    - template: jinja

navigatorconfig:
  file.manage:
    - name: /opt/so/conf/playbook/navigator_config.json
    - source: salt://playbook/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

so-playbookimage:
  cmd.run:
    - name: docker pull --disable-content-trust=false soshybridhunter/so-playbook:HH1.1.1

so-playbook:
  docker_container.running:
    - require:
      - so-playbookimage
    - image: soshybridhunter/so-playbook:HH1.1.1
    - hostname: playbook
    - name: so-playbook
    - port_bindings:
      - 0.0.0.0:3200:3000

so-navigatorimage:
  cmd.run:
    - name: docker pull --disable-content-trust=false soshybridhunter/so-navigator:HH1.1.1

so-navigator:
  docker_container.running:
    - require:
      - so-navigatorimage
    - image: soshybridhunter/so-navigator:HH1.1.1
    - hostname: navigator
    - name: so-navigator
    - binds:
      - /opt/so/conf/playbook/navigator_config.json:/nav-app/src/assets/config.json:ro
      - /opt/so/conf/playbook/nav_layer_playbook.json:/nav-app/src/assets/playbook.json:ro
    - port_bindings:
      - 0.0.0.0:4200:4200
