# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - docker

# Trust the CA
trusttheca:
  file.managed:
    - name: /etc/pki/tls/certs/intca.crt
    - source: salt://ca/files/ca.crt
    - watch_in:
      - service: docker_running
    - show_changes: False
    - makedirs: True

