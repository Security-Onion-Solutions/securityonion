# Add socore Group
socoregroup:
  group.present:
    - name: socore
    - gid: 939

# Add socore user
socore:
  user.present:
    - uid: 939
    - gid: 939
    - home: /opt/so
    - createhome: True
    - shell: /bin/bash

# Create a state directory

statedir:
  file.directory:
    - name: /opt/so/state
    - user: 939
    - group: 939
    - makedirs: True

salttmp:
  file.directory:
    - name: /opt/so/tmp
    - user: 939
    - group: 939
    - makedirs: True

# Install packages needed for the sensor

sensorpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - docker-ce
      {% if grains['os'] != 'CentOS' %}
      - python-docker
      - python-m2crypto
      {% endif %}

# Always keep these packages up to date

alwaysupdated:
  pkg.latest:
    - pkgs:
      - openssl
      - openssh-server
      - bash
    - skip_suggestions: True

# Set time to UTC

Etc/UTC:
  timezone.system

# Make sure Docker is running!
docker:
  service.running:
    - enable: True

# Drop the correct nginx config based on role

nginxconfdir:
  file.directory:
    - name: /opt/so/conf/nginx
    - user: 939
    - group: 939
    - makedirs: True

nginxconf:
  file.managed:
    - name: /opt/so/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://common/nginx/nginx.conf.{{ grains.role }}

nginxlogdir:
  file.directory:
    - name: /opt/so/log/nginx/
    - user: 939
    - group: 939
    - makedirs: True

nginxtmp:
  file.directory:
    - name: /opt/so/tmp/nginx/tmp
    - user: 939
    - group: 939
    - makedirs: True

# Start the core docker
so-core:
  docker_container.running:
    - image: soshybridhunter/so-core:HH1.0.3
    - hostname: so-core
    - user: socore
    - binds:
      - /opt/so:/opt/so:rw
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
      - /etc/pki/masterssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/masterssl.key:/etc/pki/nginx/server.key:ro
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      - 80:80
      - 443:443
    - watch:
      - file: /opt/so/conf/nginx/nginx.conf

# Add Telegraf to monitor all the things.
tgraflogdir:
  file.directory:
    - name: /opt/so/log/telegraf
    - makedirs: True

tgrafetcdir:
  file.directory:
    - name: /opt/so/conf/telegraf/etc
    - makedirs: True

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://common/telegraf/etc/telegraf.conf

so-telegraf:
  docker_container.running:
    - image: soshybridhunter/so-telegraf:HH1.0.4
    - hostname: telegraf
    - binds:
      - /opt/so/log/telegraf:/var/log/telegraf:rw
      - /opt/so/conf/telegraf/etc/telegraf.conf:/etc/telegraf/telegraf.conf:ro
      - /var/run/utmp:/var/run/utmp:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /:/host:ro
      - /sys:/host/sys:ro
      - /proc:/host/proc:ro
      - /nsm:/host/nsm:ro
      - /etc:/host/etc:ro

# If its a master or eval lets install the back end for now
{% if grains['role'] == 'so-master' or grains['role'] == 'so-eval' %}

# Influx DB
influxconfdir:
  file.directory:
    - name: /opt/so/conf/influxdb/etc
    - makedirs: True

influxdbdir:
  file.directory:
    - name: /nsm/influxdb
    - makedirs: True

influxdbconf:
  file.managed:
    - name: /opt/so/conf/influxdb/etc/influxdb.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://common/influxdb/etc/influxdb.conf

so-influxdb:
  docker_container.running:
    - image: soshybridhunter/so-influxdb:HH1.0.4
    - hostname: influxdb
    - binds:
      - /opt/so/conf/influxdb/etc/influxdb.conf:/etc/influxdb/influxdb.conf:ro
      - /nsm/influxdb:/var/lib/influxdb:rw
      - /etc/pki/influxdb.crt:/etc/ssl/influxdb.crt:ro
      - /etc/pki/influxdb.key:/etc/ssl/influxdb.key:ro
    - port_bindings:
      - 0.0.0.0:8086:8086

# Grafana all the things
grafanadir:
  file.directory:
    - name: /nsm/grafana
    - user: 939
    - group: 939
    - makedirs: True

# Install the docker. This needs to be behind nginx at some point
so-grafana:
  docker_container.running:
    - image: soshybridhunter/so-grafana:HH1.0.4
    - hostname: grafana
    - user: socore
    - binds:
      - /nsm/grafana:/var/lib/grafana:rw
    - environment:
      - GF_SECURITY_ADMIN_PASSWORD=augusta
    - port_bindings:
      - 0.0.0.0:3000:3000

{% endif %}
