# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'nginx/map.jinja' import NGINXMERGED %}

{#   if the user has selected to replace the crt and key in the ui #}
{%   if NGINXMERGED.ssl.replace_cert %}

managerssl_key:
  file.managed:
    - name: /etc/pki/managerssl.key
    - source: salt://nginx/ssl/ssl.key
    - mode: 640
    - group: 939

managerssl_crt:
  file.managed:
    - name: /etc/pki/managerssl.crt
    - source: salt://nginx/ssl/ssl.crt
    - mode: 644

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
    - unless:
      # https://github.com/saltstack/salt/issues/52167
      # Will trigger 5 days (432000 sec) from cert expiration
      - 'enddate=$(date -d "$(openssl x509 -in /etc/pki/managerssl.crt -enddate -noout | cut -d= -f2)" +%s) ; now=$(date +%s) ; expire_date=$(( now + 432000)); [ $enddate -gt $expire_date ]'
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

{%   endif %}

msslkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/managerssl.key
    - mode: 640
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
