# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'nginx/map.jinja' import NGINXMERGED %}
{%   from 'ca/map.jinja' import CA %}

{%   if GLOBALS.role != 'so-fleet' %}
{#     if the user has selected to replace the crt and key in the ui #}
{%     if NGINXMERGED.ssl.replace_cert %}

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
{% set san_list = [GLOBALS.hostname, GLOBALS.node_ip, GLOBALS.url_base] + NGINXMERGED.ssl.alt_names %}
{% set unique_san_list = san_list | unique %}
{% set managerssl_san_list = [] %}
{% for item in unique_san_list %}
{%   if item | ipaddr %}
{%     do managerssl_san_list.append("IP:" + item) %}
{%   else %}
{%     do managerssl_san_list.append("DNS:" + item) %}
{%   endif %}
{% endfor %}
{% set managerssl_san = managerssl_san_list | join(', ') %}
managerssl_crt:
  x509.certificate_managed:
    - name: /etc/pki/managerssl.crt
    - ca_server: {{ CA.server }}
    - signing_policy: managerssl
    - private_key: /etc/pki/managerssl.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: {{ managerssl_san }}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
    - watch_in:
      - docker_container: so-nginx

{%     endif %}

msslkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/managerssl.key
    - mode: 640
    - group: 939

{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
