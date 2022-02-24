{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set MANAGERIP = salt['pillar.get']('manager:mainip', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MAINIP = salt['grains.get']('ip_interfaces').get(salt['pillar.get']('sensor:mainint', salt['pillar.get']('manager:mainint', salt['pillar.get']('elasticsearch:mainint', salt['pillar.get']('host:mainint')))))[0] %}
{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
{%- set PLAYBOOKPASS = salt['pillar.get']('secrets:playbook_db', None) -%}
{%- set DNET = salt['pillar.get']('global:dockernet', '172.17.0.0') %}


include:
  - mysql
  
create_playbookdbuser:
  mysql_user.present:
    - name: playbookdbuser
    - password: {{ PLAYBOOKPASS }}
    - host: {{ DNET }}/255.255.255.0
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_playbookdbuser_grants:
  mysql_query.run:
    - database: playbook
    - query:    "GRANT ALL ON playbook.* TO 'playbookdbuser'@'{{ DNET }}/255.255.255.0';"
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_updatwebhooks:
  mysql_query.run:
    - database: playbook
    - query:    "update webhooks set url = 'http://{{MANAGERIP}}:7000/playbook/webhook' where project_id = 1"
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_updatepluginurls:
  mysql_query.run:
    - database: playbook
    - query: |- 
        update settings set value = 
        "--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess
        project: '1'
        convert_url: http://{{MANAGERIP}}:7000/playbook/sigmac
        create_url: http://{{MANAGERIP}}:7000/playbook/play"
        where id  = 43
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

playbooklogdir:
  file.directory:
    - name: /opt/so/log/playbook
    - dir_mode: 775
    - user: 939
    - group: 939
    - makedirs: True

{% if PLAYBOOKPASS == None %}

playbook_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "Playbook MySQL Password Error - Not Starting Playbook"

{% else %}

so-playbook:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-playbook:{{ VERSION }}
    - hostname: playbook
    - name: so-playbook
    - binds:
      - /opt/so/log/playbook:/playbook/log:rw
    - environment:
      - REDMINE_DB_MYSQL={{ MANAGERIP }}
      - REDMINE_DB_DATABASE=playbook
      - REDMINE_DB_USERNAME=playbookdbuser
      - REDMINE_DB_PASSWORD={{ PLAYBOOKPASS }}
    - port_bindings:
      - 0.0.0.0:3200:3000

append_so-playbook_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-playbook

{% endif %}

so-playbooksynccron:
  cron.present:
    - name: /usr/sbin/so-playbook-sync > /opt/so/log/playbook/sync.log 2>&1
    - user: root
    - minute: '*/5'

so-playbookruleupdatecron:
  cron.present:
    - name: /usr/sbin/so-playbook-ruleupdate > /opt/so/log/playbook/update.log 2>&1
    - user: root
    - minute: '1'
    - hour: '6'
    
{% if 'idh' in salt['cmd.shell']("ls /opt/so/saltstack/local/pillar/minions/|awk -F'_' {'print $2'}|awk -F'.' {'print $1'}").split() %}
idh-plays:
  file.recurse:
    - name: /opt/so/conf/soctopus/sigma-import
    - source: salt://idh/plays
    - makedirs: True
  cmd.run:
    - name: so-playbook-import True
    - onchanges:
      - file: /opt/so/conf/soctopus/sigma-import
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
