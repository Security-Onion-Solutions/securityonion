# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states or sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set KAFKATRUST = salt['pillar.get']('kafka:truststore') %}

kafkaconfdir:
  file.directory:
    - name: /opt/so/conf/kafka
    - user: 960
    - group: 960
    - makedirs: True

{% if GLOBALS.is_manager %}
# Manager runs so-kafka-trust to create truststore for Kafka ssl communication
kafka_truststore:
  cmd.script:
    - source: salt://kafka/tools/sbin_jinja/so-kafka-trust
    - template: jinja
    - cwd: /opt/so
    - defaults:
        GLOBALS: {{ GLOBALS }}
        KAFKATRUST: {{ KAFKATRUST }}
{% endif %}

kafkacertz:
  file.managed:
    - name: /opt/so/conf/kafka/kafka-truststore.jks
    - source: salt://kafka/files/kafka-truststore
    - user: 960
    - group: 931

{% endif %}