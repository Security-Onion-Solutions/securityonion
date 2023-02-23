# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql') %}

# MySQL Setup
mysqlpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      {% if grains['os'] != 'Rocky' %}
        {% if grains['oscodename'] == 'bionic' %}
      - python3-mysqldb
        {% elif grains['oscodename'] == 'focal' %}
      - python3-mysqldb
        {% endif %}
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

{% if MYSQLPASS == None %}

mysql_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "MySQL Password Error - Not Starting MySQL"

{% else %}

so-mysql:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-mysql:{{ GLOBALS.so_version }}
    - hostname: so-mysql
    - user: socore
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-mysql'].ip }}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-mysql'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - environment:
      - MYSQL_ROOT_HOST={{ GLOBALS.manager }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc
    - require:
      - file: mysqlcnf
      - file: mysqlpass
  cmd.run:
    - name: until nc -z {{ GLOBALS.manager }} 3306; do sleep 1; done
    - timeout: 600
    - onchanges:
      - docker_container: so-mysql
  module.run:
    - so.mysql_conn:
      - retry: 300
    - onchanges:
      - cmd: so-mysql

append_so-mysql_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-mysql

{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
