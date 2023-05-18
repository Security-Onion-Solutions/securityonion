# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - soctopus.config
  - soctopus.sostatus

so-soctopus:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-soctopus:{{ GLOBALS.so_version }}
    - hostname: soctopus
    - name: so-soctopus
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-soctopus'].ip }}
    - binds:
      - /opt/so/conf/soctopus/SOCtopus.conf:/SOCtopus/SOCtopus.conf:ro
      - /opt/so/log/soctopus/:/var/log/SOCtopus/:rw
      - /opt/so/rules/elastalert/playbook:/etc/playbook-rules:rw
      - /opt/so/conf/navigator/nav_layer_playbook.json:/etc/playbook/nav_layer_playbook.json:rw
      - /opt/so/conf/soctopus/sigma-import/:/SOCtopus/sigma-import/:rw    
      {% if GLOBALS.airgap %}
      - /nsm/repo/rules/sigma:/soctopus/sigma
      {% endif %}
      {% if DOCKER.containers['so-soctopus'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-soctopus'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}     
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-soctopus'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - extra_hosts:
      - {{GLOBALS.url_base}}:{{GLOBALS.manager_ip}}
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
      {% if DOCKER.containers['so-soctopus'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-soctopus'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-soctopus'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-soctopus'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - require:
      - file: soctopusconf
      - file: navigatordefaultlayer

delete_so-soctopus_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-soctopus$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
