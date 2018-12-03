{%- set MYSQLPASS = salt['pillar.get']('master:mysqlpass', 'iwonttellyou') %}
{%- set FLEETPASS = salt['pillar.get']('master:fleetpass', 'bazinga') %}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}
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

lsetcsync:
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
    - image: soshybridhunter/so-redis:HH1.0.3
    - hostname: so-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
      - MYSQL_ROOT_HOST={{ MASTERIP }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc

fleetdb:
  mysql_database.present:
    - name: fleet

fleetdbuser:
  mysql_user.present:
    - host: {{ MASTERIP }}
    - password: {{ FLEETPASS }}
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

fleetdbpriv:
  mysql_grants.present:
    - grant: all privileges
    - database: fleet.*
    - user: fleet
