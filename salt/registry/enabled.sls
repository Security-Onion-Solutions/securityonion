# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - registry.config
  - registry.sostatus

# Install the registry container
so-dockerregistry:
  docker_container.running:
    - image: ghcr.io/security-onion-solutions/registry:2.8.3
    - hostname: so-registry
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-dockerregistry'].ip }}
    - restart_policy: always
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-dockerregistry'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/so/conf/docker-registry/etc/config.yml:/etc/docker/registry/config.yml:ro
      - /opt/so/conf/docker-registry:/var/lib/registry:rw
      - /nsm/docker-registry/docker:/var/lib/registry/docker:rw
      - /etc/pki/registry.crt:/etc/pki/registry.crt:ro
      - /etc/pki/registry.key:/etc/pki/registry.key:ro
      {% if DOCKER.containers['so-dockerregistry'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-dockerregistry'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-dockerregistry'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-dockerregistry'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - client_timeout: 180
    - environment:
      - HOME=/root
      {% if DOCKER.containers['so-dockerregistry'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-dockerregistry'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - retry:
        attempts: 5
        interval: 30
    - require:
      - file: dockerregistryconf
      - x509: registry_crt
      - x509: registry_key

delete_so-dockerregistry_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-dockerregistry$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
