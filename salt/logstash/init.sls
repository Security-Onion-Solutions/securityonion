# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'logstash/map.jinja' import LOGSTASH_MERGED %}
{% from 'kafka/map.jinja' import KAFKAMERGED %}

include:
{# Disable logstash when Kafka is enabled except when the role is standalone #}
{% if LOGSTASH_MERGED.enabled and grains.role == 'so-standalone' %}
  - logstash.enabled
{% elif LOGSTASH_MERGED.enabled and not KAFKAMERGED.enabled %}
  - logstash.enabled
{% else %}
  - logstash.disabled
{% endif %}
