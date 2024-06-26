# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'kafka/nodes.map.jinja' import COMBINED_KAFKANODES %}
{% set kafka_cluster_id = salt['pillar.get']('kafka:cluster_id', default=None) %}

{# Write Kafka pillar, so all grid members have access to nodeid of other kafka nodes and their roles #}
write_kafka_pillar_yaml:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/kafka/nodes.sls
    - mode: 644
    - user: socore
    - source: salt://kafka/files/managed_node_pillar.jinja
    - template: jinja
    - context:
        COMBINED_KAFKANODES: {{ COMBINED_KAFKANODES }}