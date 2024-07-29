# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   set KAFKANODES = salt['pillar.get']('kafka:nodes') %}
{%   if 'gmd' in salt['pillar.get']('features', []) %}

include:
  - kafka.ca
  - kafka.config
  - kafka.ssl
  - kafka.storage
  - kafka.sostatus

so-kafka:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-kafka:{{ GLOBALS.so_version }}
    - hostname: so-kafka
    - name: so-kafka
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-kafka'].ip }}
    - user: kafka
    - environment:
        KAFKA_HEAP_OPTS: -Xmx2G -Xms1G
        KAFKA_OPTS: -javaagent:/opt/jolokia/agents/jolokia-agent-jvm-javaagent.jar=port=8778,host={{ DOCKER.containers['so-kafka'].ip }},policyLocation=file:/opt/jolokia/jolokia.xml
    - extra_hosts:
      {% for node in KAFKANODES %}
      - {{ node }}:{{ KAFKANODES[node].ip }}
      {% endfor %}
      {% if DOCKER.containers['so-kafka'].extra_hosts %}
      {%   for XTRAHOST in DOCKER.containers['so-kafka'].extra_hosts %}
      - {{ XTRAHOST }}
      {%   endfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-kafka'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - binds:
      - /etc/pki/kafka.p12:/etc/pki/kafka.p12:ro
      - /opt/so/conf/kafka/kafka-truststore.jks:/etc/pki/kafka-truststore.jks:ro
      - /nsm/kafka/data/:/nsm/kafka/data/:rw
      - /opt/so/log/kafka:/opt/kafka/logs/:rw
      - /opt/so/conf/kafka/server.properties:/opt/kafka/config/kraft/server.properties:ro
      - /opt/so/conf/kafka/client.properties:/opt/kafka/config/kraft/client.properties
    - watch:
      {% for sc in ['server', 'client'] %}
      - file: kafka_kraft_{{sc}}_properties
      {% endfor %}
      - file: kafkacertz
    - require:
      - file: kafkacertz

delete_so-kafka_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-kafka$

{%   else %}

{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Kafka for Guaranteed Message Delivery is a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
include:
  - kafka.disabled
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
