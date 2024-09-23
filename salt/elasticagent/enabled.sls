# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - elasticagent.config
  - elasticagent.sostatus

so-elastic-agent:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-elastic-agent:{{ GLOBALS.so_version }}
    - name: so-elastic-agent
    - hostname: {{ GLOBALS.hostname }}
    - detach: True
    - user: 949
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-elastic-agent'].ip }}
    - extra_hosts:
        - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
        - {{ GLOBALS.hostname }}:{{ GLOBALS.node_ip }}
        {% if DOCKER.containers['so-elastic-agent'].extra_hosts %}
          {% for XTRAHOST in DOCKER.containers['so-elastic-agent'].extra_hosts %}
        - {{ XTRAHOST }}
          {% endfor %}
        {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-elastic-agent'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /opt/so/conf/elastic-agent/elastic-agent.yml:/usr/share/elastic-agent/elastic-agent.yml:ro
      - /opt/so/log/elasticagent:/usr/share/elastic-agent/logs
      - /etc/pki/tls/certs/intca.crt:/etc/pki/tls/certs/intca.crt:ro 
      - /nsm:/nsm:ro
      - /opt/so/log:/opt/so/log:ro
     {% if DOCKER.containers['so-elastic-agent'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-elastic-agent'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - environment:
      - FLEET_CA=/etc/pki/tls/certs/intca.crt
      - LOGS_PATH=logs
      {% if DOCKER.containers['so-elastic-agent'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-elastic-agent'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - require:
      - file: create-elastic-agent-config
    - watch:
      - file: create-elastic-agent-config

delete_so-elastic-agent_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-elastic-agent$


{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
