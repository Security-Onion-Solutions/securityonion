# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'kafka/map.jinja' import KAFKAMERGED %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

so-kafka:
  docker_container.absent:
    - force: True

so-kafka_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-kafka$
    - onlyif: grep -q '^so-kafka$' /opt/so/conf/so-status/so-status.conf

{% if GLOBALS.is_manager and KAFKAMERGED.enabled or GLOBALS.pipeline == "KAFKA" %}
ensure_default_pipeline:
  cmd.run:
    - name: |
        /usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/kafka/soc_kafka.sls kafka.enabled False;
        /usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/global/soc_global.sls global.pipeline REDIS
{% endif %}