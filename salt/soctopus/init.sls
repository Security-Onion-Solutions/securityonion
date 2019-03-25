soctopusdir:
  file.directory:
    - name: /opt/so/conf/soctopus
    - user: 939
    - group: 939
    - makedirs: True

soctopussync:
  file.recurse:
    - name: /opt/so/conf/soctopus
    - source: salt://soctopus/files
    - user: 939
    - group: 939
    - template: jinja

so-soctopus:
  docker_container.running:
    - image: soshybridhunter/so-soctopus:HH1.0.7
    - hostname: soctopus
    - name: so-soctopus
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
    - port_bindings:
      - 0.0.0.0:7000:7000
