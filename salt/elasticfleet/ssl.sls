# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}
{%   from 'ca/map.jinja' import CA %}

{% if GLOBALS.is_manager or GLOBALS.role in ['so-heavynode', 'so-fleet', 'so-receiver'] %}

{% if grains['role'] not in [ 'so-heavynode', 'so-receiver'] %}
# Start -- Elastic Fleet Host Cert
etc_elasticfleet_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticfleet-server.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticfleet-server.key') -%}
    - prereq:
      - x509: etc_elasticfleet_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

etc_elasticfleet_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticfleet-server.crt
    - ca_server: {{ CA.server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-server.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }},DNS:{{ GLOBALS.url_base }},IP:{{ GLOBALS.node_ip }}{% if ELASTICFLEETMERGED.config.server.custom_fqdn | length > 0 %},DNS:{{ ELASTICFLEETMERGED.config.server.custom_fqdn | join(',DNS:') }}{% endif %}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

efperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-server.key
    - mode: 640
    - group: 939

chownelasticfleetcrt:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-server.crt
    - mode: 640
    - user: 947
    - group: 939

chownelasticfleetkey:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-server.key
    - mode: 640
    - user: 947
    - group: 939
# End -- Elastic Fleet Host Cert
{% endif %} # endif is for not including HeavyNodes & Receivers 


# Start -- Elastic Fleet Client Cert for Agent (Mutual Auth with Logstash Output)
etc_elasticfleet_agent_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticfleet-agent.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticfleet-agent.key') -%}
    - prereq:
      - x509: etc_elasticfleet_agent_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

etc_elasticfleet_agent_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticfleet-agent.crt
    - ca_server: {{ CA.server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-agent.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/elasticfleet-agent.key -topk8 -out /etc/pki/elasticfleet-agent.p8 -nocrypt"
    - onchanges:
      - x509: etc_elasticfleet_agent_key

efagentperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-agent.key
    - mode: 640
    - group: 939

chownelasticfleetagentcrt:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-agent.crt
    - mode: 640
    - user: 947
    - group: 939

chownelasticfleetagentkey:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-agent.key
    - mode: 640
    - user: 947
    - group: 939
# End -- Elastic Fleet Client Cert for Agent (Mutual Auth with Logstash Output)

{% endif %}

{% if GLOBALS.role in ['so-manager', 'so-managerhype', 'so-managersearch', 'so-standalone'] %}
elasticfleet_kafka_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticfleet-kafka.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticfleet-kafka.key') -%}
    - prereq:
      - x509: elasticfleet_kafka_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

elasticfleet_kafka_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticfleet-kafka.crt
    - ca_server: {{ CA.server }}
    - signing_policy: kafka
    - private_key: /etc/pki/elasticfleet-kafka.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 7
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

elasticfleet_kafka_cert_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-kafka.crt
    - mode: 640
    - user: 947
    - group: 939

elasticfleet_kafka_key_perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-kafka.key
    - mode: 640
    - user: 947
    - group: 939
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
