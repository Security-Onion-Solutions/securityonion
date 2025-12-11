# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'ca/map.jinja' import CA %}

# Create a cert for elasticsearch
elasticsearch_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticsearch.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticsearch.key') -%}
    - prereq:
      - x509: /etc/pki/elasticsearch.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

elasticsearch_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticsearch.crt
    - ca_server: {{ CA.server }}
    - signing_policy: general
    - private_key: /etc/pki/elasticsearch.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs12 -inkey /etc/pki/elasticsearch.key -in /etc/pki/elasticsearch.crt -export -out /etc/pki/elasticsearch.p12 -nodes -passout pass:"
    - onchanges:
      - x509: /etc/pki/elasticsearch.key

elastickeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.key
    - mode: 640
    - group: 930
    
elasticp12perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.p12
    - mode: 640
    - group: 930

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
