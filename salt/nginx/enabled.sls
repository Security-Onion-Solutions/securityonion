# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}

include:
  - nginx.config
  - nginx.sostatus

make-rule-dir-nginx:
  file.directory:
    - name: /nsm/rules
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

so-nginx:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-nginx:{{ GLOBALS.so_version }}
    - hostname: so-nginx
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-nginx'].ip }}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    {% if DOCKER.containers['so-nginx'].extra_hosts %}
      {% for XTRAHOST in DOCKER.containers['so-nginx'].extra_hosts %}
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
      - /opt/so/conf/navigator/navigator_config.json:/opt/socore/html/navigator/assets/config.json:ro
      - /opt/so/conf/navigator/nav_layer_playbook.json:/opt/socore/html/navigator/assets/playbook.json:ro
      - /opt/so/conf/navigator/enterprise-attack.json:/opt/socore/html/navigator/assets/enterprise-attack.json:ro
      - /opt/so/conf/navigator/pre-attack.json:/opt/socore/html/navigator/assets/pre-attack.json:ro
      - /nsm/repo:/opt/socore/html/repo:ro
      - /nsm/rules:/nsm/rules:ro
      {% endif %}
      {% if DOCKER.containers['so-nginx'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-nginx'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    {% if DOCKER.containers['so-nginx'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-nginx'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-nginx'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: nginxconf
      - file: nginxconfdir
    - require:
      - file: nginxconf
      {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import'] %}
      - x509: managerssl_key
      - x509: managerssl_crt
      - file: navigatorconfig
      - file: navigatordefaultlayer
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
