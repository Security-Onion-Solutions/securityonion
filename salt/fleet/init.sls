{%- set MYSQLPASS = salt['pillar.get']('auth:mysql', 'iwonttellyou') %}
{%- set FLEETPASS = salt['pillar.get']('auth:fleet', 'bazinga') -%}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') -%}

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

fleetpacksync:
  file.recurse:
    - name: /opt/so/conf/fleet/packs
    - source: salt://fleet/packs
    - user: 939
    - group: 939

fleetlogdir:
  file.directory:
    - name: /opt/so/log/fleet
    - user: 939
    - group: 939
    - makedirs: True

fleetsetupscript:
  file.managed:
    - name: /opt/so/conf/fleet/so-fleet-setup.sh
    - source: salt://fleet/so-fleet-setup.sh

osquerypackageswebpage:
  file.managed:
    - name: /opt/so/conf/fleet/packages/index.html
    - source: salt://fleet/osquery-packages.html

fleetdb:
  mysql_database.present:
    - name: fleet

fleetdbuser:
  mysql_user.present:
    - host: 172.17.0.0/255.255.0.0
    - password: {{ FLEETPASS }}
    - connection_user: root
    - connection_pass: {{ MYSQLPASS }}

fleetdbpriv:
  mysql_grants.present:
    - grant: all privileges
    - database: fleet.*
    - user: fleetdbuser
    - host: 172.17.0.0/255.255.0.0

so-fleetimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-fleet:HH1.1.0

so-fleet:
  docker_container.running:
    - require:
      - so-fleetimage
    - image: docker.io/soshybridhunter/so-fleet:HH1.1.0
    - hostname: so-fleet
    - port_bindings:
      - 0.0.0.0:8080:8080
    - environment:
      - KOLIDE_MYSQL_ADDRESS={{ MASTERIP }}:3306
      - KOLIDE_MYSQL_DATABASE=fleet
      - KOLIDE_MYSQL_USERNAME=fleetdbuser
      - KOLIDE_MYSQL_PASSWORD={{ FLEETPASS }}
      - KOLIDE_REDIS_ADDRESS={{ MASTERIP }}:6379
      - KOLIDE_SERVER_CERT=/ssl/server.cert
      - KOLIDE_SERVER_KEY=/ssl/server.key
      - KOLIDE_LOGGING_JSON=true
      - KOLIDE_AUTH_JWT_KEY=thisisatest
      - KOLIDE_OSQUERY_STATUS_LOG_FILE=/var/log/osquery/status.log
      - KOLIDE_OSQUERY_RESULT_LOG_FILE=/var/log/osquery/result.log
      - KOLIDE_SERVER_URL_PREFIX=/fleet
    - binds:
      - /etc/pki/fleet.key:/ssl/server.key:ro
      - /etc/pki/fleet.crt:/ssl/server.cert:ro
      - /opt/so/log/fleet:/var/log/osquery
      - /opt/so/conf/fleet/packs:/packs
    - watch:
      - /opt/so/conf/fleet/etc
