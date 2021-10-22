{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

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

# Install the registry container
so-dockerregistry:
  docker_container.running:
    - image: ghcr.io/security-onion-solutions/registry:latest
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
    - client_timeout: 180
    - retry:
        attempts: 5
        interval: 30
    - require:
      - file: dockerregistryconf
      - x509: registry_crt
      - x509: registry_key

append_so-dockerregistry_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-dockerregistry

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
