{%- set FLEETPASS = salt['pillar.get']('master:fleetpass', 'bazinga') -%}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') -%}

# Fleet Setup
fleetcdir:
  file.directory:
    - name: /opt/so/conf/fleet/etc
    - user: 939
    - group: 939
    - makedirs: True

so-fleet:
  docker_container.running:
    - image: kolide/fleet
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
    - binds:
      - /etc/pki/fleet.key:/ssl/server.key:ro
      - /etc/pki/fleet.crt:/ssl/server.cert
    - watch:
      - /opt/so/conf/fleet/etc
