# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - sensoroni.sostatus
  
so-sensoroni:
  docker_container.absent:
    - force: True

so-sensoroni_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-sensoroni$
