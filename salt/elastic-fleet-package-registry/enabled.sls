# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - elastic-fleet-package-registry.config
  - elastic-fleet-package-registry.sostatus

so-elastic-fleet-package-registry:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastic-fleet-package-registry:{{ GLOBALS.so_version }}
    - name: so-elastic-fleet-package-registry
    - hostname: Fleet-package-reg-{{ GLOBALS.hostname }}
    - detach: True
    - user: 948
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elastic-fleet-package-registry'].ip }}
    - extra_hosts:
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-elastic-fleet-package-registry'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}

delete_so-elastic-fleet-package-registry_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elastic-fleet-package-registry$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
