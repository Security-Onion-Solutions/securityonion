# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'elasticfleet/map.jinja' import ELASTICFLEETMERGED %}
{%   from 'ca/map.jinja' import CA %}

{%   if GLOBALS.is_manager or GLOBALS.role in ['so-heavynode', 'so-fleet', 'so-receiver'] %}

{%     if grains['role'] not in [ 'so-heavynode'] %}
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
    - ca_server: {{ CA.server }}
    - signing_policy: general
    - private_key: /etc/pki/elasticfleet-logstash.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }},DNS:{{ GLOBALS.url_base }},IP:{{ GLOBALS.node_ip }}{% if ELASTICFLEETMERGED.config.server.custom_fqdn | length > 0 %},DNS:{{ ELASTICFLEETMERGED.config.server.custom_fqdn | join(',DNS:') }}{% endif %}
    - days_remaining: 7
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
{%     endif %} # endif is for not including HeavyNodes 

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
    - ca_server: {{ CA.server }}
    - signing_policy: general
    - private_key: /etc/pki/elasticfleet-lumberjack.key
    - CN: {{ GLOBALS.node_ip }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}
    - days_remaining: 7
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
{%   endif %}

{%   if GLOBALS.is_manager or GLOBALS.role in ['so-heavynode', 'so-receiver'] %}
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
    - ca_server: {{ CA.server }}
    - signing_policy: general
    - private_key: /etc/pki/filebeat.key
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
    - name: "/usr/bin/openssl pkcs8 -in /etc/pki/filebeat.key -topk8 -out /etc/pki/filebeat.p8 -nocrypt"
    - onchanges:
      - x509: etc_filebeat_key

fbperms:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.key
    - mode: 640
    - group: 939

logstash_filebeat_p8:
  file.managed:
    - replace: False
    - name: /etc/pki/filebeat.p8
    - mode: 640
    - user: 931
    - group: 939

{%     if grains.role not in ['so-heavynode', 'so-receiver'] %}
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

{%     endif %}
{%   endif %}

{%   if GLOBALS.is_manager or GLOBALS.role in ['so-sensor', 'so-searchnode', 'so-heavynode', 'so-fleet', 'so-idh', 'so-receiver'] %}
   
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
    - ca_server: {{ CA.server }}
    - signing_policy: general
    - private_key: /opt/so/conf/filebeat/etc/pki/filebeat.key
    - CN: {{ GLOBALS.hostname }}
    - subjectAltName: DNS:{{ GLOBALS.hostname }}, IP:{{ GLOBALS.node_ip }}
    - days_remaining: 7
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
    
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
