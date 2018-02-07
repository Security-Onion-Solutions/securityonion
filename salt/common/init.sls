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

toosmooth/so-core:test2:
  docker_image.present

so-core:
  docker_container.running:
    - image: toosmooth/so-core:test2
    - hostname: so-core
    - user: socore
    - binds:
      - /opt/so:/opt/so:rw
    - network_mode: so-elastic-net
