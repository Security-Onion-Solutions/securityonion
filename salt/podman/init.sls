Podman pkg:
  pkg.installed:
    - name: podman

{#
Podman service:
  file.managed:
    - name: /usr/lib/systemd/system/podman.service
    - source: salt://podman/podman.service

Podman socket:
  file.managed:
    - name: /usr/lib/systemd/system/podman.socket
    - source: salt://podman/podman.socket
  service.running:
    - name: podman.socket
    - enable: true
#}

Docker socket:
  file.symlink:
    - name: /var/run/docker.sock
    - target: /var/run/podman/podman.sock

podman_docker_symlink:
  file.symlink:
    - name: /usr/bin/docker
    - target: /usr/local/bin/podman
