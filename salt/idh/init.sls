{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

# IDH State

# Create a config directory
temp:
  file.directory:
    - name: /opt/so/conf/idh
    - user: 939
    - group: 939
    - makedirs: True

# Create a log directory
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

so-idh:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-idh:{{ VERSION }}
    - hostname: so-idh
    - name: so-idh
    - detach: True
    - network_mode: host
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro