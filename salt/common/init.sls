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

# Set up docker network
# This is broken right now.
#dockernet:
#  docker_network.present:
#    - name: so-elastic-net
#    - driver: bridge

# dockernet work around
#dockernet:
#  cmd.script:
#    - source: salt://common/scripts/dockernet.sh


# Snag the so-core docker
toosmooth/so-core:test2:
  docker_image.present

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
    - image: toosmooth/so-core:test2
    - hostname: so-core
    - user: socore
    - binds:
      - /opt/so:/opt/so:rw
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      - 80:80
      - 443:443
