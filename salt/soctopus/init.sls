{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('static:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{%- set MANAGER_URL = salt['pillar.get']('manager:url_base', '') %}
{%- set MANAGER_IP = salt['pillar.get']('static:managerip', '') %}

soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus
    - user: 939
    - group: 939
    - makedirs: True

soctopus-sync:
  file.recurse:
    - name: /opt/so/conf/soctopus/templates
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja

soctopusconf:
  file.managed:
    - name: /opt/so/conf/soctopus/SOCtopus.conf
    - source: salt://soctopus/files/SOCtopus.conf
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soctopuslogdir:
  file.directory:
    - name: /opt/so/log/soctopus
    - user: 939
    - group: 939

playbookrulesdir:
  file.directory:
    - name: /opt/so/rules/elastalert/playbook
    - user: 939
    - group: 939
    - makedirs: True

playbookrulessync:
  file.recurse:
    - name: /opt/so/rules/elastalert/playbook
    - source: salt://soctopus/files/templates
    - user: 939
    - group: 939
    - template: jinja

so-soctopus:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soctopus:{{ VERSION }}
    - hostname: soctopus
    - name: so-soctopus
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
      - /opt/so/log/soctopus/:/var/log/SOCtopus/:rw
      - /opt/so/rules/elastalert/playbook:/etc/playbook-rules:rw
      - /opt/so/conf/navigator/nav_layer_playbook.json:/etc/playbook/nav_layer_playbook.json:rw
    - port_bindings:
      - 0.0.0.0:7000:7000
    - extra_hosts:
      - {{MANAGER_URL}}:{{MANAGER_IP}}
