{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'registry' in top_states %}

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
    - image: registry:latest
    - hostname: so-registry
    - restart_policy: always
    - port_bindings:
      - 0.0.0.0:5000:5000
    - binds:
      - /opt/so/conf/docker-registry/etc/config.yml:/etc/docker/registry/config.yml:ro
      - /opt/so/conf/docker-registry:/var/lib/registry:rw
      - /nsm/docker-registry/docker:/var/lib/registry/docker:rw
      - /etc/pki/registry.crt:/etc/pki/registry.crt:ro
      - /etc/pki/registry.key:/etc/pki/registry.key:ro

append_so-registry_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-registry

{% else %}

registry_state_not_allowed:
  test.fail_without_changes:
    - name: registry_state_not_allowed

{% endif %}