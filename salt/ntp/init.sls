# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
{% from 'ntp/config.map.jinja' import NTPCONFIG %}

chronyconf:
  file.managed:
    - name: /etc/chrony.conf
    - source: salt://ntp/chrony.conf
    - template: jinja
    - defaults:
        NTPCONFIG: {{ NTPCONFIG }}

chronyd:
  service.running:
    - enable: True
    - watch: 
      - file: chronyconf