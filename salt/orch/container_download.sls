# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set NEWNODE = salt['pillar.get']('setup:newnode') %}

{% if NEWNODE.split('_')|last in ['searchnode', 'heavynode'] %}
{{NEWNODE}}_download_logstash_elasticsearch:
  salt.state:
    - tgt: {{ NEWNODE }}
    - sls:
      - repo.client
      - docker
      - logstash.download
      - elasticsearch.download
{% endif %}
