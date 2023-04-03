# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'docker/docker.map.jinja' import DOCKER %}

# Add Group
elasticsagentprgroup:
  group.present:
    - name: elastic-agent-pr
    - gid: 948


# Add user
elastic-agent-pr:
  user.present:
    - uid: 948
    - gid: 948
    - home: /opt/so/conf/elastic-fleet-pr
    - createhome: False

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

append_so-elastic-fleet-package-registry_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-elastic-fleet-package-registry

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
