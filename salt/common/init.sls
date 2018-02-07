# Create a state directory

statedir:
  file.directory:
    - name: /opt/so/state

salttmp:
  file.directory:
    - name: /opt/so/tmp

# Install packages needed for the sensor

sensorpkgs:
  pkg.installed:
    - skip_suggestions: True
    - pkgs:
      - docker-ce
      - python-docker

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

# Set up docker network
dockernet:
  docker_network.present:
    - name: so-elastic-net
    - driver: bridge

# Snag the so-core docker
toosmooth/so-core:test2:
  docker_image.present

# Drop the correct nginx config based on role

nginxconf:
  file.managed:
    - name: /opt/so/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://conf/nginx/nginx.conf.{{ grains.role }}

# Start the core docker
so-core:
  docker_container.running:
    - image: toosmooth/so-core:test2
    - hostname: so-core
    - user: socore
    - binds:
      - /opt/so:/opt/so:rw
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    - network_mode: so-elastic-net
    - cap_add: NET_BIND_SERVICE
    - ports:
      - 80
      - 443
