# Create a state directory

ppdir:
  file.directory:
    - name: /opt/so/pulledpork
    - user: 939
    - group: 939

rulesdir:
  file.directory:
    - name: /opt/so/rules/nids
    - user: 939
    - group: 939
    - makedirs: True

toosmooth/so-pulledpork:test2:
  docker_image.present

so-pulledpork:
  docker_container.running:
    - image: toosmooth/so-pulledpork:test2
    - hostname: so-pulledpork
    - user: socore
    - binds:
      - /opt/so/pulledpork/etc:/opt/pulledpork/etc:ro
      - /opt/so/rules/nids:/opt/so/rules/nids:rw
    - network_mode: so-elastic-net
