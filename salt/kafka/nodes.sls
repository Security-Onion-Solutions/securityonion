# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if GLOBALS.pipeline == "KAFKA" %}
{%   from 'kafka/nodes.map.jinja' import COMBINED_KAFKANODES %}

{# Store kafka pillar in a file rather than memory where values could be lost. Kafka does not support nodeid's changing #}
write_kafka_pillar_yaml:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/kafka/nodes.sls
    - mode: 644
    - user: socore
    - source: salt://kafka/files/managed_node_pillar.jinja
    - template: jinja
    - context:
        COMBINED_KAFKANODES: {{ COMBINED_KAFKANODES }}
{% endif %}