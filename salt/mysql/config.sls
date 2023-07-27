# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   set MYSQLPASS = salt['pillar.get']('secrets:mysql') %}

# MySQL Setup
mysqlpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      {% if grains['os_family'] != 'RedHat' %}
      - python3-mysqldb
      {% else %}
      - python3-mysqlclient
      {% endif %}

mysqletcdir:
  file.directory:
    - name: /opt/so/conf/mysql/etc
    - user: 939
    - group: 939
    - makedirs: True

mysqlpiddir:
  file.directory:
    - name: /opt/so/conf/mysql/pid
    - user: 939
    - group: 939
    - makedirs: True

mysqlcnf:
  file.managed:
    - name: /opt/so/conf/mysql/etc/my.cnf
    - source: salt://mysql/etc/my.cnf
    - user: 939
    - group: 939

mysqlpass:
  file.managed:
    - name: /opt/so/conf/mysql/etc/mypass
    - source: salt://mysql/etc/mypass
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        MYSQLPASS: {{ MYSQLPASS }}

mysqllogdir:
  file.directory:
    - name: /opt/so/log/mysql
    - user: 939
    - group: 939
    - makedirs: True

mysqldatadir:
  file.directory:
    - name: /nsm/mysql
    - user: 939
    - group: 939
    - makedirs: True

mysql_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://mysql/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#mysql_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://mysql/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
