{% set MASTERIP = salt['pillar.get']('master:mainip', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}

playbookdb:
  file.managed:
    - name: /opt/so/conf/playbook/redmine.db
    - source: salt://playbook/files/redmine.db
    - user: 999
    - group: 999
    - makedirs: True
    - replace: False

playbookwebhook:
  module.run:
    - sqlite3.modify:
      - db: /opt/so/conf/playbook/redmine.db
      - sql: "update webhooks set url = 'http://{{MASTERIP}}:7000/playbook/webhook' where project_id = 1"

playbookapiendpoints:
  module.run:
    - sqlite3.modify:
      - db: /opt/so/conf/playbook/redmine.db
      - sql: |- 
          update settings set value = 
          "--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess
          project: '1'
          import_trackers:
          - '6'
          convert_url: http://{{MASTERIP}}:7000/playbook/sigmac
          create_url: http://{{MASTERIP}}:7000/playbook/play"
          where id  = 46;
      
navigatorconfig:
  file.managed:
    - name: /opt/so/conf/playbook/navigator_config.json
    - source: salt://playbook/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

so-playbook:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-playbook:{{ VERSION }}
    - hostname: playbook
    - name: so-playbook
    - binds:
      - /opt/so/conf/playbook/redmine.db:/usr/src/redmine/sqlite/redmine.db:rw
    - port_bindings:
      - 0.0.0.0:3200:3000

so-navigator:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-navigator:{{ VERSION }}
    - hostname: navigator
    - name: so-navigator
    - binds:
      - /opt/so/conf/playbook/navigator_config.json:/nav-app/src/assets/config.json:ro
      - /opt/so/conf/playbook/nav_layer_playbook.json:/nav-app/src/assets/playbook.json:ro
    - port_bindings:
      - 0.0.0.0:4200:4200

so-playbooksynccron:
  cron.present:
    - name: /usr/sbin/so-playbook-sync
    - user: root
    - minute: '*/5'

so-playbookruleupdatecron:
  cron.present:
    - name: /usr/sbin/so-playbook-ruleupdate
    - user: root
    - minute: '1'
    - hour: '6'
