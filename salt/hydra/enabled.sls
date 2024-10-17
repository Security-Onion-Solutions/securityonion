# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   if 'api' in salt['pillar.get']('features', []) %}

include:
  - hydra.config
  - hydra.sostatus

so-hydra:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-hydra:{{ GLOBALS.so_version }}
    - hostname: hydra
    - name: so-hydra
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-hydra'].ip }}
    - binds:
      - /opt/so/conf/hydra/:/hydra-conf:ro
      - /opt/so/log/hydra/:/hydra-log:rw
      - /nsm/hydra/db:/hydra-data:rw
      {% if DOCKER.containers['so-hydra'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-hydra'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-hydra'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    {% if DOCKER.containers['so-hydra'].extra_hosts %}
    - extra_hosts:
      {% for XTRAHOST in DOCKER.containers['so-hydra'].extra_hosts %}
      - {{ XTRAHOST }}
      {% endfor %}
    {% endif %}
    {% if DOCKER.containers['so-hydra'].extra_env %}
    - environment:
      {% for XTRAENV in DOCKER.containers['so-hydra'].extra_env %}
      - {{ XTRAENV }}
      {% endfor %}
    {% endif %}
    - restart_policy: unless-stopped
    - watch:
      - file: hydraconfig
    - require:
      - file: hydraconfig
      - file: hydralogdir
      - file: hydradir

delete_so-hydra_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-hydra$

wait_for_hydra:
  http.wait_for_successful_query:
    - name: 'http://{{ GLOBALS.manager }}:4444/'
    - ssl: True
    - verify_ssl: False
    - status:
      - 200
      - 301
      - 302
      - 404
    - status_type: list
    - wait_for: 300
    - request_interval: 10
    - require:
      -  docker_container: so-hydra

{%   else %}

{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "This is a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
include:
  - hydra.disabled
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
