# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states or sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set kafka_password = salt['pillar.get']('kafka:config:password') %}

include:
  - ca.dirs
    {% set global_ca_server = [] %}
    {% set x509dict = salt['mine.get'](GLOBALS.manager | lower~'*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if 'manager' in host.split('_')|last or host.split('_')|last == 'standalone' %}
        {% do global_ca_server.append(host) %}
      {% endif %}
    {% endfor %}
    {% set ca_server = global_ca_server[0] %}

{% if GLOBALS.pipeline == "KAFKA" %}

{%   if GLOBALS.role in ['so-manager', 'so-managersearch', 'so-standalone'] %}
kafka_client_key:
  x509.private_key_managed:
    - name: /etc/pki/kafka-client.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/kafka-client.key') -%}
    - prereq:
      - x509: /etc/pki/kafka-client.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

kafka_client_crt:
  x509.certificate_managed:
    - name: /etc/pki/kafka-client.crt
    - ca_server: {{ ca_server }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - signing_policy: kafka
    - private_key: /etc/pki/kafka-client.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

kafka_client_key_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka-client.key
    - mode: 640
    - user: 960
    - group: 939

kafka_client_crt_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka-client.crt
    - mode: 640
    - user: 960
    - group: 939
{%   endif %}

{%   if GLOBALS.role in ['so-manager', 'so-managersearch','so-receiver', 'so-standalone'] %}
kafka_key:
  x509.private_key_managed:
    - name: /etc/pki/kafka.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/kafka.key') -%}
    - prereq:
      - x509: /etc/pki/kafka.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

kafka_crt:
  x509.certificate_managed:
    - name: /etc/pki/kafka.crt
    - ca_server: {{ ca_server }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - signing_policy: kafka
    - private_key: /etc/pki/kafka.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs12 -inkey /etc/pki/kafka.key -in /etc/pki/kafka.crt -export -out /etc/pki/kafka.p12 -nodes -passout pass:{{ kafka_password }}"
    - onchanges:
      - x509: /etc/pki/kafka.key
kafka_key_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka.key
    - mode: 640
    - user: 960
    - group: 939

kafka_crt_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka.crt
    - mode: 640
    - user: 960
    - group: 939

kafka_pkcs12_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka.p12
    - mode: 640
    - user: 960
    - group: 939
{%   endif %}

# Standalone needs kafka-logstash for automated testing. Searchnode/manager search need it for logstash to consume from Kafka.
# Manager will have cert, but be unused until a pipeline is created and logstash enabled.
{%   if GLOBALS.role in ['so-standalone', 'so-managersearch', 'so-searchnode', 'so-manager'] %}
kafka_logstash_key:
  x509.private_key_managed:
    - name: /etc/pki/kafka-logstash.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/kafka-logstash.key') -%}
    - prereq:
      - x509: /etc/pki/kafka-logstash.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

kafka_logstash_crt:
  x509.certificate_managed:
    - name: /etc/pki/kafka-logstash.crt
    - ca_server: {{ ca_server }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - signing_policy: kafka
    - private_key: /etc/pki/kafka-logstash.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs12 -inkey /etc/pki/kafka-logstash.key -in /etc/pki/kafka-logstash.crt -export -out /etc/pki/kafka-logstash.p12 -nodes -passout pass:{{ kafka_password }}"
    - onchanges:
      - x509: /etc/pki/kafka-logstash.key

kafka_logstash_key_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka-logstash.key
    - mode: 640
    - user: 931
    - group: 939

kafka_logstash_crt_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka-logstash.crt
    - mode: 640
    - user: 931
    - group: 939

kafka_logstash_pkcs12_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/kafka-logstash.p12
    - mode: 640
    - user: 931
    - group: 939

{%   endif %}
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}