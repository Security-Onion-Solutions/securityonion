# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql') -%}
{%- set PLAYBOOKPASS = salt['pillar.get']('secrets:playbook_db') -%}


include:
  - mysql
  
create_playbookdbuser:
  mysql_user.present:
    - name: playbookdbuser
    - password: {{ PLAYBOOKPASS }}
    - host: "{{ DOCKER.sorange.split('/')[0] }}/255.255.255.0"
    - connection_host: {{ GLOBALS.manager }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_playbookdbuser_grants:
  mysql_query.run:
    - database: playbook
    - query:    "GRANT ALL ON playbook.* TO 'playbookdbuser'@'{{ DOCKER.sorange.split('/')[0] }}/255.255.255.0';"
    - connection_host: {{ GLOBALS.manager }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_updatwebhooks:
  mysql_query.run:
    - database: playbook
    - query:    "update webhooks set url = 'http://{{ GLOBALS.manager_ip}}:7000/playbook/webhook' where project_id = 1"
    - connection_host: {{ GLOBALS.manager }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

query_updatename:
  mysql_query.run:
    - database: playbook
    - query:    "update custom_fields set name = 'Custom Filter' where id = 21;"
    - connection_host: {{ GLOBALS.manager }}
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
        convert_url: http://{{ GLOBALS.manager }}:7000/playbook/sigmac
        create_url: http://{{ GLOBALS.manager }}:7000/playbook/play"
        where id  = 43
    - connection_host: {{ GLOBALS.manager }}
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
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-playbook:{{ GLOBALS.so_version }}
    - hostname: playbook
    - name: so-playbook
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-playbook'].ip }}
    - binds:
      - /opt/so/log/playbook:/playbook/log:rw
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    - environment:
      - REDMINE_DB_MYSQL={{ GLOBALS.manager }}
      - REDMINE_DB_DATABASE=playbook
      - REDMINE_DB_USERNAME=playbookdbuser
      - REDMINE_DB_PASSWORD={{ PLAYBOOKPASS }}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-playbook'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}

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
