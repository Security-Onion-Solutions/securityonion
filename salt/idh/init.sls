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

{% from 'idh/opencanary_config.map.jinja' import OPENCANARYCONFIG with context %}
opencanary_config:
  file.managed:
    - name: /opt/so/conf/idh/opencanary.conf
    - source: salt://idh/idh.conf.jinja
    - template: jinja
    - defaults:
        OPENCANARYCONFIG: {{ OPENCANARYCONFIG }}

so-idh:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-idh:{{ VERSION }}
    - name: so-idh
    - detach: True
    - network_mode: host
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro