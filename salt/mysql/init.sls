{%- set MYSQLPASS = salt['pillar.get']('auth:mysql', 'iwonttellyou') %}
{%- set FLEETPASS = salt['pillar.get']('auth:fleet', 'bazinga') %}
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

so-mysqlimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-mysql:HH1.1.0

so-mysql:
  docker_container.running:
    - require:
      - so-mysqlimage
    - image: docker.io/soshybridhunter/so-mysql:HH1.1.0
    - hostname: so-mysql
    - user: socore
    - port_bindings:
      - 0.0.0.0:3306:3306
    - environment:
      - MYSQL_ROOT_HOST={{ MASTERIP }}
      - MYSQL_ROOT_PASSWORD=/etc/mypass
    - binds:
      - /opt/so/conf/mysql/etc/my.cnf:/etc/my.cnf:ro
      - /opt/so/conf/mysql/etc/mypass:/etc/mypass
      - /nsm/mysql:/var/lib/mysql:rw
      - /opt/so/log/mysql:/var/log/mysql:rw
    - watch:
      - /opt/so/conf/mysql/etc
