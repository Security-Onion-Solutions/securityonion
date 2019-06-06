sensoronidir:
  file.directory:
    - name: /opt/so/conf/sensoroni
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
    - name: docker pull --disable-content-trust=false soshybridhunter/so-sensoroni:HH1.1.0

so-sensoroni:
  docker_container.running:
    - require:
      - so-sensoroniimage
    - image: soshybridhunter/so-sensoroni:HH1.0.8
    - hostname: sensoroni
    - name: so-sensoroni
    - binds:
      - /opt/so/conf/sensoroni:/sensoroni:rw
    - port_bindings:
      - 0.0.0.0:9822:9822
