# Create the config directory for the docker registry
dockerregistryconfdir:
  file.directory:
    - name: /opt/so/conf/docker-registry/etc
    - user: 939
    - group: 939
    - makedirs: True

dockerregistrydir:
  file.directory:
    - name: /nsm/docker-registry/docker
    - user: 939
    - group: 939
    - makedirs: True

dockerregistrylogdir:
  file.directory:
    - name: /opt/so/log/docker-registry
    - user: 939
    - group: 939
    - makedirs: true

# Copy the config
dockerregistryconf:
  file.managed:
    - name: /opt/so/conf/docker-registry/etc/config.yml
    - source: salt://registry/etc/config.yml

# Copy the registry script
#dockerregistrybuild:
#  file.managed:
#    - name: /opt/so/conf/docker-registry/so-buildregistry
#    - source: salt://registry/bin/so-buildregistry
#    - mode: 755

#dockerexpandregistry:
# cmd.run:
#   - name: /opt/so/conf/docker-registry/so-buildregistry

# Install the registry container
so-dockerregistry:
  docker_container.running:
    - image: registry:2
    - hostname: so-registry
    - port_bindings:
      - 0.0.0.0:5000:5000
    - binds:
      - /opt/so/conf/docker-registry/etc/config.yml:/etc/docker/registry/config.yml:ro
      - /opt/so/conf/docker-registry:/var/lib/registry:rw
      - /nsm/docker-registry/docker:/var/lib/registry/docker:rw
      - /etc/pki/registry.crt:/etc/pki/registry.crt:ro
      - /etc/pki/registry.key:/etc/pki/registry.key:ro
