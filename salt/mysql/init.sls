{%- set MYSQLPASS = salt['pillar.get']('auth:mysql', 'iwonttellyou') %}
{%- set FLEETPASS = salt['pillar.get']('auth:fleet', 'bazinga') %}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('node:mainip') %}
{% set FLEETARCH = salt['grains.get']('role') %}

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

so-mysql:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-mysql:{{ VERSION }}
    - hostname: so-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
{% if FLEETARCH == "so-fleet" %}
      - MYSQL_ROOT_HOST={{ MAINIP }}
{% else %}
      - MYSQL_ROOT_HOST={{ MASTERIP }}
{% endif %}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc
