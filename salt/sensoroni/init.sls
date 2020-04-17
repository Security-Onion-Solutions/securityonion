{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}

sensoronidir:
  file.directory:
    - name: /opt/so/conf/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

sensoronidatadir:
  file.directory:
    - name: /nsm/sensoroni/jobs
    - user: 939
    - group: 939
    - makedirs: True

sensoronilogdir:
  file.directory:
    - name: /opt/so/log/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

sensoronisync:
  file.recurse:
    - name: /opt/so/conf/sensoroni
    - source: salt://sensoroni/files
    - user: 939
    - group: 939
    - template: jinja

so-sensoroni:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-sensoroni:{{ VERSION }}
    - hostname: sensoroni
    - name: so-sensoroni
    - binds:
      - /nsm/sensoroni/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/conf/sensoroni/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/sensoroni/:/opt/sensoroni/logs/:rw
    - port_bindings:
      - 0.0.0.0:9822:9822
    - watch:
      - file: /opt/so/conf/sensoroni
