# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  - docker

cacertdir:
  file.directory:
    - name: /etc/pki/tls/certs
    - makedirs: True

# Trust the CA
trusttheca:
  file.managed:
    - name: /etc/pki/tls/certs/intca.crt
    - source: salt://ca/files/ca.crt
    - listen_in:
      - service: docker_running

{% if GLOBALS.os_family == 'Debian' %}
symlinkca:
  file.symlink:
    - target: /etc/pki/tls/certs/intca.crt
    - name: /etc/ssl/certs/intca.crt
{% endif %}
