# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{%   from 'vars/globals.map.jinja' import GLOBALS %}

{# Create Kafka output policy if it doesn't exist #}
update_kafka_output_policy_script:
  file.managed:
    - name: /usr/sbin/so-kafka-fleet-output-policy
    - source: salt://kafka/tools/sbin_jinja/so-kafka-fleet-output-policy
    - user: root
    - mode: 755
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}

create_kafka_output_policy:
  cmd.run:
    - name: 'so-kafka-fleet-output-policy > /dev/null 2>&1'
    - show_changes: false