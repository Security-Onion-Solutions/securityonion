# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

so-kafka:
  docker_container.absent:
    - force: True

so-kafka_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-kafka$
    - onlyif: grep -q '^so-kafka$' /opt/so/conf/so-status/so-status.conf

{% if grains.role in ['so-manager','so-managersearch','so-standalone'] %}
{%   import_yaml '/opt/so/saltstack/local/pillar/kafka/soc_kafka.sls' as SOC_KAFKA %}
{%   import_yaml '/opt/so/saltstack/local/pillar/global/soc_global.sls' as SOC_GLOBAL %}
{%   if SOC_KAFKA.kafka.enabled or SOC_GLOBAL.global.pipeline == "KAFKA" %}
ensure_default_pipeline:
  cmd.run:
    - name: |
        /usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/kafka/soc_kafka.sls kafka.enabled False;
        /usr/sbin/so-yaml.py replace /opt/so/saltstack/local/pillar/global/soc_global.sls global.pipeline REDIS
{%   endif %}
{% endif %}