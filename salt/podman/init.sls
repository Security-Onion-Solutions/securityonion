Pip pkg:
  pkg.installed:
    - name: python3-pip

Podman pkg:
  pkg.installed:
    - name: podman

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

Docker socket:
  file.symlink:
    - name: /var/run/docker.sock
    - target: /var/run/podman/podman.sock

Docker python:
  pip.installed:
    - bin_env: /usr/bin/pip3
    - reload_modules: true
    - pkgs:
        - certifi==2019.11.28
        - chardet==3.0.4
        - docker==4.2.1
        - idna==2.9
        # - requests==2.23.0
        - six==1.14.0
        - urllib3==1.25.8
        - websocket-client==0.57.0

podman_docker_symlink:
  file.symlink:
    - name: /bin/docker
    - target: /usr/bin/podman

restart_salt_minion:
  cmd.run:
    - name: 'salt-call service.restart salt-minion'
    - bg: true
    - onchanges:
      - pip: Docker python
