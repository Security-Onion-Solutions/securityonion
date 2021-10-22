{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) %}
{%- set MANAGERIP = salt['pillar.get']('global:managerip', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('elasticsearch:mainip') %}
{% set FLEETARCH = salt['grains.get']('role') %}

{% if FLEETARCH == "so-fleet" %}
  {% set MAININT = salt['pillar.get']('host:mainint') %}
  {% set MAINIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% else %}
  {% set MAINIP = salt['pillar.get']('global:managerip') %}
{% endif %}

# MySQL Setup
mysqlpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      {% if grains['os'] != 'CentOS' %}
        {% if grains['oscodename'] == 'bionic' %}
      - python3-mysqldb
        {% elif grains['oscodename'] == 'focal' %}
      - python3-mysqldb
        {% endif %}
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

mysqletc:
  file.recurse:
    - name: /opt/so/conf/mysql/etc
    - source: salt://mysql/etc
    - user: 939
    - group: 939
    - template: jinja
    - file_mode: 640

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
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-mysql:{{ VERSION }}
    - hostname: so-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
      - MYSQL_ROOT_HOST={{ MAINIP }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/mysql/etc/:/etc/:ro
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc
    - require:
      - file: mysqletc
  cmd.run:
    - name: until nc -z {{ MAINIP }} 3306; do sleep 1; done
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
