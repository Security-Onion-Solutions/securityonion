{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) %}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('node:mainip') %}
{% set FLEETARCH = salt['grains.get']('role') %}

{% if FLEETARCH == "so-fleet" %}
  {% set MAINIP = salt['pillar.get']('node:mainip') %}
{% else %}
  {% set MAINIP = salt['pillar.get']('static:masterip') %}
{% endif %}

# MySQL Setup
mysqlpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      {% if grains['os'] != 'CentOS' %}
      - python-mysqldb
      {% else %}
      - MySQL-python
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

mysqletcsync:
  file.recurse:
    - name: /opt/so/conf/mysql/etc
    - source: salt://mysql/etc
    - user: 939
    - group: 939
    - template: jinja

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
    - image: {{ MASTER }}:5000/soshybridhunter/so-mysql:{{ VERSION }}
    - hostname: so-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
      - MYSQL_ROOT_HOST={{ MAINIP }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc
  cmd.run:
    - name: until nc -z localhost 3306; do sleep 1; done
    - timeout: 10
    - onchanges:
      - docker_container: so-mysql
{% endif %}