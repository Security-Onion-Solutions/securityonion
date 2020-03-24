{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}

socdir:
  file.directory:
    - name: /opt/so/conf/soc
    - user: 939
    - group: 939
    - makedirs: True

socdatadir:
  file.directory:
    - name: /nsm/soc/jobs
    - user: 939
    - group: 939
    - makedirs: True

soclogdir:
  file.directory:
    - name: /opt/so/log/soc
    - user: 939
    - group: 939
    - makedirs: True

socsync:
  file.recurse:
    - name: /opt/so/conf/soc
    - source: salt://soc/files
    - user: 939
    - group: 939
    - template: jinja

so-soc:
  docker_container.running:
    - image: docker.io/soshybridhunter/so-soc:{{ VERSION }}
    - hostname: soc
    - name: so-soc
    - binds:
      - /nsm/soc/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/conf/soc/soc.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/soc/:/opt/sensoroni/logs/:rw
    - port_bindings:
      - 0.0.0.0:9822:9822
    - watch:
      - file: /opt/so/conf/soc

so-kratos:
  docker_container.running:
    - image: docker.io/soshybridhunter/so-soc:{{ VERSION }}
    - hostname: soc
    - name: so-soc
    - binds:
      - /nsm/soc/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/conf/soc/soc.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/soc/:/opt/sensoroni/logs/:rw
    - port_bindings:
      - 0.0.0.0:9822:9822
    - watch:
      - file: /opt/so/conf/soc
