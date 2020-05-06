{% set MASTERIP = salt['pillar.get']('master:mainip', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}
{% set MASTER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('node:mainip') %}
{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
{%- set PLAYBOOKPASS = salt['pillar.get']('secrets:playbook', None) -%}

playbookdb-dep:
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
      
playbookdb:
  mysql_database.present:
    - name: playbook
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

playbookdbuser:
  mysql_user.present:
    - host: 172.17.0.0/255.255.0.0
    - password: {{ PLAYBOOKPASS }}
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

playbookdbdbpriv:
  mysql_grants.present:
    - grant: all privileges
    - database: playbook.*
    - user: playbookdbuser
    - host: 172.17.0.0/255.255.0.0
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

{% if PLAYBOOKPASS == None %}

playbook_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "Playbook MySQL Password Error - Not Starting Playbook"

{% else %}

so-playbook:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-playbook:{{ VERSION }}
    - hostname: playbook
    - name: so-playbook
    - environment:
      - REDMINE_DB_MYSQL={{ MASTERIP }}
      - REDMINE_DB_DATABASE=playbook
      - REDMINE_DB_USERNAME=playbookdbuser
      - REDMINE_DB_PASSWORD={{ PLAYBOOKPASS }}
    - binds:
      - /opt/so/conf/playbook/redmine.db:/usr/src/redmine/sqlite/redmine.db:rw
    - port_bindings:
      - 0.0.0.0:3200:3000

{% endif %}

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
