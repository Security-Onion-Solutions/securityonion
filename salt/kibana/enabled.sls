# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKERMERGED %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - kibana.config
  - kibana.sostatus

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-kibana:{{ GLOBALS.so_version }}
    - restart_policy: unless-stopped
    - hostname: kibana
    - user: kibana
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKERMERGED.containers['so-kibana'].ip }}
    - environment:
      - ELASTICSEARCH_HOST={{ GLOBALS.manager }}
      - ELASTICSEARCH_PORT=9200
      - MANAGER={{ GLOBALS.manager }}
      {% if DOCKERMERGED.containers['so-kibana'].extra_env %}
        {% for XTRAENV in DOCKERMERGED.containers['so-kibana'].extra_env %}
      - {{ XTRAENV }}
        {% endfor %}
      {% endif %}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% if DOCKERMERGED.containers['so-kibana'].extra_hosts %}
      {% for XTRAHOST in DOCKERMERGED.containers['so-kibana'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - binds:
      - /opt/so/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      {% if DOCKERMERGED.containers['so-kibana'].custom_bind_mounts %}
        {% for BIND in DOCKERMERGED.containers['so-kibana'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKERMERGED.containers['so-kibana'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    {% if DOCKERMERGED.containers['so-kibana'].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKERMERGED.containers['so-kibana'].ulimits %}
      - {{ ULIMIT.name }}={{ ULIMIT.soft }}:{{ ULIMIT.hard }}
    {%   endfor %}
    {% endif %}
    - watch:
      - file: kibanaconfig

delete_so-kibana_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-kibana$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
