# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'docker/docker.map.jinja' import DOCKER %}

dockergroup:
  group.present:
    - name: docker
    - gid: 920

dockerheldpackages:
  pkg.installed:
    - pkgs:
      - containerd.io: 1.4.4-3.1.el7
      - docker-ce: 3:20.10.5-3.el7
      - docker-ce-cli: 1:20.10.5-3.el7
      - docker-ce-rootless-extras: 20.10.5-3.el7
    - hold: True
    - update_holds: True

#disable docker from managing iptables
iptables_disabled:
  file.managed:
    - name: /etc/systemd/system/docker.service.d/iptables-disabled.conf
    - source: salt://docker/files/iptables-disabled.conf
    - makedirs: True
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: iptables_disabled

# Make sure etc/docker exists
dockeretc:
  file.directory:
    - name: /etc/docker

# Manager daemon.json
docker_daemon:
  file.managed:
    - source: salt://common/files/daemon.json
    - name: /etc/docker/daemon.json
    - template: jinja 

# Make sure Docker is always running
docker_running:
  service.running:
    - name: docker
    - enable: True
    - watch:
      - file: docker_daemon

# Reserve OS ports for Docker proxy in case boot settings are not already applied/present
# 57314 = Strelka, 47760-47860 = Zeek
dockerapplyports:
    cmd.run:
      - name: if [ ! -s /etc/sysctl.d/99-reserved-ports.conf ]; then sysctl -w net.ipv4.ip_local_reserved_ports="57314,47760-47860"; fi

# Reserve OS ports for Docker proxy
dockerreserveports:
  file.managed:
    - source: salt://common/files/99-reserved-ports.conf
    - name: /etc/sysctl.d/99-reserved-ports.conf

sos_docker_net:
  docker_network.present:
    - name: sosbridge
    - subnet: {{ DOCKER.sosrange }}
    - gateway: {{ DOCKER.sosbip }}
    - options:
        com.docker.network.bridge.name: 'sosbridge'
        com.docker.network.driver.mtu: '1500'
        com.docker.network.bridge.enable_ip_masquerade: 'true'
        com.docker.network.bridge.enable_icc: 'true'
        com.docker.network.bridge.host_binding_ipv4: '0.0.0.0'
    - unless: 'docker network ls | grep sosbridge'
