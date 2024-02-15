# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'nginx/map.jinja' import NGINXMERGED %}
{%   set ca_server = GLOBALS.minion_id %}

include:
  - nginx.config
  - nginx.sostatus


{%   if grains.role not in ['so-fleet'] %}

{#   if the user has selected to replace the crt and key in the ui #}
{%   if NGINXMERGED.ssl.replace_cert %}

managerssl_key:
  file.managed:
    - name: /etc/pki/managerssl.key
    - source: salt://nginx/ssl/ssl.key
    - mode: 640
    - group: 939
    - watch_in:
      - docker_container: so-nginx

managerssl_crt:
  file.managed:
    - name: /etc/pki/managerssl.crt
    - source: salt://nginx/ssl/ssl.crt
    - mode: 644
    - watch_in:
      - docker_container: so-nginx

{%   else %}

managerssl_key:
  x509.private_key_managed:
    - name: /etc/pki/managerssl.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/managerssl.key') -%}
    - prereq:
      - x509: /etc/pki/managerssl.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30
    - watch_in:
      - docker_container: so-nginx

# Create a cert for the reverse proxy
managerssl_crt:
  x509.certificate_managed:
    - name: /etc/pki/managerssl.crt
    - ca_server: {{ ca_server }}
    - signing_policy: managerssl
    - private_key: /etc/pki/managerssl.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
    - watch_in:
      - docker_container: so-nginx

{%   endif %}

msslkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/managerssl.key
    - mode: 640
    - group: 939

make-rule-dir-nginx:
  file.directory:
    - name: /nsm/rules
    - user: socore
    - group: socore
    - recurse:
      - user
      - group
      
{%   endif %}

{# if this is an so-fleet node then we want to use the port bindings, custom bind mounts defined for fleet #}
{% if GLOBALS.role == 'so-fleet' %}
{%   set container_config = 'so-nginx-fleet-node' %}
{% else %}
{%   set container_config = 'so-nginx' %}
{% endif %}

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
      - /opt/so/saltstack/local/salt/elasticfleet/files/so_agent-installers/:/opt/socore/html/packages
      - /nsm/elastic-fleet/artifacts/:/opt/socore/html/artifacts 
      {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import'] %}
      - /etc/pki/managerssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/managerssl.key:/etc/pki/nginx/server.key:ro
      # ATT&CK Navigator binds
      - /opt/so/conf/navigator/layers/:/opt/socore/html/navigator/assets/so:ro
      - /opt/so/conf/navigator/config.json:/opt/socore/html/navigator/assets/config.json:ro
      - /nsm/repo:/opt/socore/html/repo:ro
      - /nsm/rules:/nsm/rules:ro
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
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      {% for BINDING in DOCKER.containers[container_config].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: nginxconf
      - file: nginxconfdir
    - require:
      - file: nginxconf
{%   if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import'] %}
{%     if NGINXMERGED.ssl.replace_cert %}
      - file: managerssl_key
      - file: managerssl_crt
{%     else %}
      - x509: managerssl_key
      - x509: managerssl_crt
{%     endif%}
      - file: navigatorconfig
      - file: navigatordefaultlayer
{%   endif %}

delete_so-nginx_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-nginx$

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
