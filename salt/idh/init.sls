# IDH State

# Create a config directory
temp:
  file.directory:
    - name: /opt/so/conf/idh
    - user: 939
    - group: 939
    - makedirs: True

# Create a config directory
configdir:
  file.directory:
    - name: /nsm/idh
    - user: 939
    - group: 939
    - makedirs: True

# Sync IDH files
idhfiles:
  file.recurse:
    - name: /opt/so/conf/idh
    - user: 0
    - group: 0
    - file_mode: 755
    - source: salt://idh/config
    - replace: False
    - template: jinja

# Build IDH Docker
so-idh:
  docker_image.present:
    - build: /opt/so/saltstack/local/salt/idh
    - tag: latest

# Set IDH Docker to run
so-idh-run:
  docker_container.running:
    - image: so-idh
    - name: so-idh
    - detach: True
    - network_mode: host
    - restart_policy: always
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro
