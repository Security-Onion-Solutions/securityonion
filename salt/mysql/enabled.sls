# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set MYSQLPASS = salt['pillar.get']('secrets:mysql') %}

include:
  - mysql.config
  - mysql.sostatus

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
      {% if DOCKER.containers['so-mysql'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-mysql'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-mysql'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - environment:
      - MYSQL_ROOT_HOST={{ GLOBALS.so_docker_bip }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
      {% if DOCKER.containers['so-mysql'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-mysql'].extra_env %}
        - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - binds:
      - /opt/so/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
      {% if DOCKER.containers['so-mysql'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-mysql'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - watch:
      - file: mysqlcnf
      - file: mysqlpass
    - require:
      - file: mysqlcnf
      - file: mysqlpass
{% endif %}

delete_so-mysql_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-mysql$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
