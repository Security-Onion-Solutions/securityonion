# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'ca/map.jinja' import CA %}

registry_key:
  x509.private_key_managed:
    - name: /etc/pki/registry.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/registry.key') -%}
    - prereq:
      - x509: /etc/pki/registry.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the docker registry
registry_crt:
  x509.certificate_managed:
    - name: /etc/pki/registry.crt
    - ca_server: {{ CA.server }}
    - subjectAltName: DNS:{{ GLOBALS.manager }}, IP:{{ GLOBALS.manager_ip }} 
    - signing_policy: general
    - private_key: /etc/pki/registry.key
    - CN: {{ GLOBALS.manager }}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

regkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/registry.key
    - mode: 640
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
