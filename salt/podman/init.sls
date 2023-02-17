{% from 'docker/docker.map.jinja' import DOCKER %}

Podman pkg:
  pkg.installed:
    - name: podman

{#
Podman service:
  file.managed:
    - name: /usr/lib/systemd/system/podman.service
    - source: salt://podman/podman.service
#}

Podman_socket_service:
  service.running:
    - name: podman.socket
    - enable: true

Podman_service:
  service.running:
    - name: podman.service
    - enable: true

Docker socket:
  file.symlink:
    - name: /var/run/docker.sock
    - target: /var/run/podman/podman.sock

podman_docker_symlink:
  file.symlink:
    - name: /usr/bin/docker
    - target: /usr/local/bin/podman

sos_docker_net:
  docker_network.present:
    - name: sobridge
    - subnet: {{ DOCKER.sorange }}
    - gateway: {{ DOCKER.sobip }}
    - options:
        com.docker.network.bridge.name: 'sobridge'
        com.docker.network.driver.mtu: '1500'
        com.docker.network.bridge.enable_ip_masquerade: 'true'
        com.docker.network.bridge.enable_icc: 'true'
        com.docker.network.bridge.host_binding_ipv4: '0.0.0.0'
    - unless: 'docker network ls | grep sobridge'
