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

so-sensoroniimage:
  cmd.run:
    - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-sensoroni:HH1.1.3

so-sensoroni:
  docker_container.running:
    - require:
      - so-sensoroniimage
    - image: docker.io/soshybridhunter/so-sensoroni:HH1.1.3
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
