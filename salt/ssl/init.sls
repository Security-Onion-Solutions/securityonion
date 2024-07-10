# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}

{% set global_ca_text = [] %}
{% set global_ca_server = [] %}
{% if grains.role in ['so-heavynode'] %}
  {% set COMMONNAME = GLOBALS.hostname %}
{% else %}
  {% set COMMONNAME = GLOBALS.manager %}
{% endif %}

{% if grains.id.split('_')|last in ['manager', 'managersearch', 'eval', 'standalone', 'import'] %}
include:
  - ca
    {% set trusttheca_text = salt['cp.get_file_str']('/etc/pki/ca.crt')|replace('\n', '') %}
    {% set ca_server = grains.id %}
{% else %}
include:
  - ca.dirs
    {% set x509dict = salt['mine.get'](GLOBALS.manager | lower~'*', 'x509.get_pem_entries') %}
    {% for host in x509dict %}
      {% if 'manager' in host.split('_')|last or host.split('_')|last == 'standalone' %}
        {% do global_ca_text.append(x509dict[host].get('/etc/pki/ca.crt')|replace('\n', '')) %}
        {% do global_ca_server.append(host) %}
      {% endif %}
    {% endfor %}
    {% set trusttheca_text = global_ca_text[0] %}
    {% set ca_server = global_ca_server[0] %}
{% endif %}

cacertdir:
  file.directory:
    - name: /etc/pki/tls/certs
    - makedirs: True

# Trust the CA
trusttheca:
  x509.pem_managed:
    - name: /etc/pki/tls/certs/intca.crt
    - text:  {{ trusttheca_text }}

{% if GLOBALS.os_family == 'Debian' %}
symlinkca:
  file.symlink:
    - target: /etc/pki/tls/certs/intca.crt
    - name: /etc/ssl/certs/intca.crt
{% endif %}

# Install packages needed for the sensor
m2cryptopkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - python3-m2crypto

influxdb_key:
  x509.private_key_managed:
    - name: /etc/pki/influxdb.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/influxdb.key') -%}
    - prereq:
      - x509: /etc/pki/influxdb.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

# Create a cert for the talking to influxdb
influxdb_crt:
  x509.certificate_managed:
    - name: /etc/pki/influxdb.crt
    - ca_server: {{ ca_server }}
    - signing_policy: influxdb
    - private_key: /etc/pki/influxdb.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }} 
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

influxkeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/influxdb.key
    - mode: 640
    - group: 939

{% if grains['role'] in ['so-manager', 'so-eval', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-fleet', 'so-receiver'] %}
# Create a cert for Redis encryption
redis_key:
  x509.private_key_managed:
    - name: /etc/pki/redis.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/redis.key') -%}
    - prereq:
      - x509: /etc/pki/redis.crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

redis_crt:
  x509.certificate_managed:
    - name: /etc/pki/redis.crt
    - ca_server: {{ ca_server }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - signing_policy: registry
    - private_key: /etc/pki/redis.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

rediskeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/redis.key
    - mode: 640
    - group: 939
{% endif %}

{% if grains['role'] in ['so-manager', 'so-eval', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-fleet', 'so-receiver'] %}

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
    - ca_server: {{ ca_server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-server.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }},DNS:{{ GLOBALS.url_base }},IP:{{ GLOBALS.node_ip }}{% if ELASTICFLEETMERGED.config.server.custom_fqdn | length > 0 %},DNS:{{ ELASTICFLEETMERGED.config.server.custom_fqdn | join(',DNS:') }}{% endif %}
    - days_remaining: 0
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

{% if grains['role'] not in [ 'so-heavynode'] %}
# Start -- Elastic Fleet Logstash Input Cert
etc_elasticfleet_logstash_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticfleet-logstash.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticfleet-logstash.key') -%}
    - prereq:
      - x509: etc_elasticfleet_logstash_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

etc_elasticfleet_logstash_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticfleet-logstash.crt
    - ca_server: {{ ca_server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-logstash.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }},DNS:{{ GLOBALS.url_base }},IP:{{ GLOBALS.node_ip }}{% if ELASTICFLEETMERGED.config.server.custom_fqdn | length > 0 %},DNS:{{ ELASTICFLEETMERGED.config.server.custom_fqdn | join(',DNS:') }}{% endif %}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/elasticfleet-logstash.key -topk8 -out /etc/pki/elasticfleet-logstash.p8 -nocrypt"
    - onchanges:
      - x509: etc_elasticfleet_logstash_key

eflogstashperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-logstash.key
    - mode: 640
    - group: 939

chownelasticfleetlogstashcrt:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-logstash.crt
    - mode: 640
    - user: 931
    - group: 939

chownelasticfleetlogstashkey:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-logstash.key
    - mode: 640
    - user: 931
    - group: 939
# End -- Elastic Fleet Logstash Input Cert
{% endif %} # endif is for not including HeavyNodes 

# Start -- Elastic Fleet Node - Logstash Lumberjack Input / Output
# Cert needed on: Managers, Receivers
etc_elasticfleetlumberjack_key:
  x509.private_key_managed:
    - name: /etc/pki/elasticfleet-lumberjack.key
    - bits: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/elasticfleet-lumberjack.key') -%}
    - prereq:
      - x509: etc_elasticfleetlumberjack_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

etc_elasticfleetlumberjack_crt:
  x509.certificate_managed:
    - name: /etc/pki/elasticfleet-lumberjack.crt
    - ca_server: {{ ca_server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-lumberjack.key
    - CN: {{ GLOBALS.node_ip }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/elasticfleet-lumberjack.key -topk8 -out /etc/pki/elasticfleet-lumberjack.p8 -nocrypt"
    - onchanges:
      - x509: etc_elasticfleetlumberjack_key

eflogstashlumberjackperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-lumberjack.key
    - mode: 640
    - group: 939

chownilogstashelasticfleetlumberjackp8:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-lumberjack.p8
    - mode: 640
    - user: 931
    - group: 939

chownilogstashelasticfleetlogstashlumberjackcrt:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-lumberjack.crt
    - mode: 640
    - user: 931
    - group: 939

chownilogstashelasticfleetlogstashlumberjackkey:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticfleet-lumberjack.key
    - mode: 640
    - user: 931
    - group: 939

# End -- Elastic Fleet Node - Logstash Lumberjack Input / Output

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
    - ca_server: {{ ca_server }}
    - signing_policy: elasticfleet
    - private_key: /etc/pki/elasticfleet-agent.key
    - CN: {{ GLOBALS.hostname }}
    - days_remaining: 0
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

{% if grains['role'] in ['so-manager', 'so-eval', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
etc_filebeat_key:
  x509.private_key_managed:
    - name: /etc/pki/filebeat.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/etc/pki/filebeat.key') -%}
    - prereq:
      - x509: etc_filebeat_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

# Request a cert and drop it where it needs to go to be distributed
etc_filebeat_crt:
  x509.certificate_managed:
    - name: /etc/pki/filebeat.crt
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - private_key: /etc/pki/filebeat.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/filebeat.key -topk8 -out /etc/pki/filebeat.p8 -nocrypt"
    - onchanges:
      - x509: etc_filebeat_key

fbperms:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.key
    - mode: 640
    - group: 939

chownilogstashfilebeatp8:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.p8
    - mode: 640
    - user: 931
    - group: 939

  {% if grains.role not in ['so-heavynode', 'so-receiver'] %}
# Create Symlinks to the keys so I can distribute it to all the things
filebeatdir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/filebeat/files
    - makedirs: True

fbkeylink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/filebeat/files/filebeat.p8
    - target: /etc/pki/filebeat.p8
    - user: socore
    - group: socore

fbcrtlink:
  file.symlink:
    - name: /opt/so/saltstack/local/salt/filebeat/files/filebeat.crt
    - target: /etc/pki/filebeat.crt
    - user: socore
    - group: socore

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
    - ca_server: {{ ca_server }}
    - subjectAltName: DNS:{{ GLOBALS.manager }}, IP:{{ GLOBALS.manager_ip }} 
    - signing_policy: registry
    - private_key: /etc/pki/registry.key
    - CN: {{ GLOBALS.manager }}
    - days_remaining: 0
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

  {% endif %}
  {% if grains.role not in ['so-receiver'] %}
# Create a cert for elasticsearch
/etc/pki/elasticsearch.key:
  x509.private_key_managed:
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

/etc/pki/elasticsearch.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - private_key: /etc/pki/elasticsearch.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
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

  {% endif %}


{% endif %}

{% if grains['role'] in ['so-sensor', 'so-manager', 'so-searchnode', 'so-eval', 'so-managersearch', 'so-heavynode', 'so-fleet', 'so-standalone', 'so-idh', 'so-import', 'so-receiver'] %}
   
fbcertdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - makedirs: True

conf_filebeat_key:
  x509.private_key_managed:
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - keysize: 4096
    - backup: True
    - new: True
    {% if salt['file.file_exists']('/opt/so/conf/filebeat/etc/pki/filebeat.key') -%}
    - prereq:
      - x509: conf_filebeat_crt
    {%- endif %}
    - retry:
        attempts: 5
        interval: 30

# Request a cert and drop it where it needs to go to be distributed
conf_filebeat_crt:
  x509.certificate_managed:
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.crt
    - ca_server: {{ ca_server }}
    - signing_policy: filebeat
    - private_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
    - days_valid: 820
    - backup: True
    - timeout: 30
    - retry:
        attempts: 5
        interval: 30

# Convert the key to pkcs#8 so logstash will work correctly.
filebeatpkcs:
  cmd.run:
    - name: "/usr/bin/openssl pkcs8 -in /opt/so/conf/filebeat/etc/pki/filebeat.key -topk8 -out /opt/so/conf/filebeat/etc/pki/filebeat.p8 -passout pass:"
    - onchanges:
      - x509: conf_filebeat_key

filebeatkeyperms:
  file.managed:
    - replace: False
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - mode: 640
    - group: 939

chownfilebeatp8:
  file.managed:
    - replace: False
    - name: /opt/so/conf/filebeat/etc/pki/filebeat.p8
    - mode: 640
    - user: 931
    - group: 939
    
{% endif %}

{% if grains['role'] == 'so-searchnode' %}
# Create a cert for elasticsearch
/etc/pki/elasticsearch.key:
  x509.private_key_managed:
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

/etc/pki/elasticsearch.crt:
  x509.certificate_managed:
    - ca_server: {{ ca_server }}
    - signing_policy: registry
    - private_key: /etc/pki/elasticsearch.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
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

elasticp12perms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.p12
    - mode: 640
    - group: 930
    
elastickeyperms:
  file.managed:
    - replace: False
    - name: /etc/pki/elasticsearch.key
    - mode: 640
    - group: 930
{%- endif %}

{% if grains['role'] in ['so-manager', 'so-managersearch', 'so-standalone'] %}
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
    - ca_server: {{ ca_server }}
    - signing_policy: kafka
    - private_key: /etc/pki/elasticfleet-kafka.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 0
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
