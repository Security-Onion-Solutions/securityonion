# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set MYSQLPASS = salt['pillar.get']('secrets:mysql') %}
{%   set PLAYBOOKPASS = salt['pillar.get']('secrets:playbook_db') %}


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

playbook_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://playbook/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#playbook_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://playbook/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

playbooklogdir:
  file.directory:
    - name: /opt/so/log/playbook
    - dir_mode: 775
    - user: 939
    - group: 939
    - makedirs: True

{%   if 'idh' in salt['cmd.shell']("ls /opt/so/saltstack/local/pillar/minions/|awk -F'_' {'print $2'}|awk -F'.' {'print $1'}").split() %}
idh-plays:
  file.recurse:
    - name: /opt/so/conf/soctopus/sigma-import
    - source: salt://idh/plays
    - makedirs: True
  cmd.run:
    - name: so-playbook-import True
    - onchanges:
      - file: /opt/so/conf/soctopus/sigma-import
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
