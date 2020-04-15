{%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
{%- set FLEETPASS = salt['pillar.get']('secrets:fleet', None) -%}
{%- set FLEETJWT = salt['pillar.get']('secrets:fleet_jwt', None) -%}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set MAINIP = salt['pillar.get']('node:mainip') %}
{% set FLEETARCH = salt['grains.get']('role') %}


{% if FLEETARCH == "so-fleet" %}
  {% set MAINIP = salt['pillar.get']('node:mainip') %}
{% else %}
  {% set MAINIP = salt['pillar.get']('static:masterip') %}
{% endif %}

#{% if grains.id.split('_')|last in ['master', 'eval', 'fleet'] %}
#so/fleet:
#  event.send:
#    - data:
#        action: 'enablefleet'
#        hostname: {{ grains.host }}
#{% endif %}

# Fleet Setup
fleetcdir:
  file.directory:
    - name: /opt/so/conf/fleet/etc
    - user: 939
    - group: 939
    - makedirs: True

fleetpackcdir:
  file.directory:
    - name: /opt/so/conf/fleet/packs
    - user: 939
    - group: 939
    - makedirs: True
    
fleetnsmdir:
  file.directory:
    - name: /nsm/osquery/fleet
    - user: 939
    - group: 939
    - makedirs: True

fleetpacksync:
  file.recurse:
    - name: /opt/so/conf/fleet/packs
    - source: salt://fleet/files/packs
    - user: 939
    - group: 939

fleetpackagessync:
  file.recurse:
    - name: /opt/so/conf/fleet/packages
    - source: salt://fleet/packages/
    - user: 939
    - group: 939

fleetlogdir:
  file.directory:
    - name: /opt/so/log/fleet
    - user: 939
    - group: 939
    - makedirs: True

fleetsetupscripts:
  file.recurse:
    - name: /usr/sbin
    - user: 0
    - group: 0
    - file_mode: 755
    - template: jinja
    - source: salt://fleet/files/scripts

osquerypackageswebpage:
  file.managed:
    - name: /opt/so/conf/fleet/packages/index.html
    - source: salt://fleet/files/dedicated-index.html
    - template: jinja

fleetdb:
  mysql_database.present:
    - name: fleet
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

fleetdbuser:
  mysql_user.present:
    - host: 172.17.0.0/255.255.0.0
    - password: {{ FLEETPASS }}
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

fleetdbpriv:
  mysql_grants.present:
    - grant: all privileges
    - database: fleet.*
    - user: fleetdbuser
    - host: 172.17.0.0/255.255.0.0
    - connection_host: {{ MAINIP }}
    - connection_port: 3306
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}


{% if FLEETPASS == None or FLEETJWT == None %}

fleet_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "Fleet MySQL Password or JWT Key Error - Not Starting Fleet"

{% else %}

so-fleet:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-fleet:{{ VERSION }}
    - hostname: so-fleet
    - port_bindings:
      - 0.0.0.0:8080:8080
    - environment:
      - KOLIDE_MYSQL_ADDRESS={{ MAINIP }}:3306
      - KOLIDE_REDIS_ADDRESS={{ MAINIP }}:6379
      - KOLIDE_MYSQL_DATABASE=fleet
      - KOLIDE_MYSQL_USERNAME=fleetdbuser
      - KOLIDE_MYSQL_PASSWORD={{ FLEETPASS }}
      - KOLIDE_SERVER_CERT=/ssl/server.cert
      - KOLIDE_SERVER_KEY=/ssl/server.key
      - KOLIDE_LOGGING_JSON=true
      - KOLIDE_AUTH_JWT_KEY= {{ FLEETJWT }}
      - KOLIDE_OSQUERY_STATUS_LOG_FILE=/var/log/fleet/status.log
      - KOLIDE_OSQUERY_RESULT_LOG_FILE=/var/log/osquery/result.log
      - KOLIDE_SERVER_URL_PREFIX=/fleet
    - binds:
      - /etc/pki/fleet.key:/ssl/server.key:ro
      - /etc/pki/fleet.crt:/ssl/server.cert:ro
      - /opt/so/log/fleet:/var/log/fleet
      - /nsm/osquery/fleet:/var/log/osquery
      - /opt/so/conf/fleet/packs:/packs
    - watch:
      - /opt/so/conf/fleet/etc

{% endif %}
