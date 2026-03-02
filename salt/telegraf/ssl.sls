# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'ca/map.jinja' import CA %}

telegraf_key:
  x509.private_key_managed:
    - name: /etc/pki/telegraf.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/telegraf.key') -%}
    - prereq:
      - x509: /etc/pki/telegraf.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the talking to telegraf
telegraf_crt:
  x509.certificate_managed:
    - name: /etc/pki/telegraf.crt
    - ca_server: {{ CA.server }}
    - signing_policy: influxdb
    - private_key: /etc/pki/telegraf.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }} 
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

telegraf_key_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/telegraf.key
    - mode: 640
    - group: 939

{%   if not GLOBALS.is_manager %}
{# Prior to 2.4.220, minions used influxdb.crt and key for telegraf #}
remove_influxdb.crt:
  file.absent:
    - name: /etc/pki/influxdb.crt

remove_influxdb.key:
  file.absent:
    - name: /etc/pki/influxdb.key
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
