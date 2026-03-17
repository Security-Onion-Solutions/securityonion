# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'nginx/map.jinja' import NGINXMERGED %}

include:
  - nginx.ssl
  - nginx.config
  - nginx.sostatus

{%   if GLOBALS.role != 'so-fleet' %}
{%     set container_config = 'so-nginx' %}
make-rule-dir-nginx:
  file.directory:
    - name: /nsm/rules
    - user: socore
    - group: socore
    - recurse:
      - user
      - group
    - show_changes: False

{%   else %}
{#     if this is an so-fleet node then we want to use the port bindings, custom bind mounts defined for fleet #}
{%     set container_config = 'so-nginx-fleet-node' %}
{%   endif %}

so-nginx:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-nginx:{{ GLOBALS.so_version }}
    - hostname: so-nginx
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers[container_config].ip }}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% if DOCKER.containers[container_config].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers[container_config].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    - binds:
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
      - /nsm/elastic-fleet/so_agent-installers/:/opt/socore/html/packages
      - /nsm/elastic-fleet/artifacts/:/opt/socore/html/artifacts 
      {% if GLOBALS.is_manager %}
      - /etc/pki/managerssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/managerssl.key:/etc/pki/nginx/server.key:ro
      # ATT&CK Navigator binds
      - /opt/so/conf/navigator/layers/:/opt/socore/html/navigator/assets/so:ro
      - /opt/so/conf/navigator/config.json:/opt/socore/html/navigator/assets/config.json:ro
      - /nsm/repo:/opt/socore/html/repo:ro
      - /nsm/rules:/nsm/rules:ro
      {%   if NGINXMERGED.external_suricata %}
      - /opt/so/rules/nids/suri:/surirules:ro
      {%   endif %}
      {% endif %}
      {% if DOCKER.containers[container_config].custom_bind_mounts %}
        {% for BIND in DOCKER.containers[container_config].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers[container_config].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers[container_config].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers[container_config].ulimits %}
    - ulimits:
    {%   for ULIMIT in DOCKER.containers[container_config].ulimits %}
      - {{ ULIMIT }}
    {%   endfor %}
    {% endif %}
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      {% for BINDING in DOCKER.containers[container_config].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: nginxconf
      - file: nginxconfdir
      {% if GLOBALS.is_manager %}
      {%   if NGINXMERGED.ssl.replace_cert %}
      - file: managerssl_key
      - file: managerssl_crt
      {%   else %}
      - x509: managerssl_key
      - x509: managerssl_crt
      {%   endif%}
      {% endif %}
    - require:
      - file: nginxconf
      {% if GLOBALS.is_manager %}
      {%   if NGINXMERGED.ssl.replace_cert %}
      - file: managerssl_key
      - file: managerssl_crt
      {%   else %}
      - x509: managerssl_key
      - x509: managerssl_crt
      {%   endif%}
      - file: navigatorconfig
      {% endif %}

delete_so-nginx_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-nginx$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
