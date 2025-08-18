# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

setHostname_{{grains.id.split("_") | first}}:
  cmd.run:
    - name: hostnamectl set-hostname --static {{grains.id.split("_") | first}}
  network.system:
    - name: {{grains.id.split("_") | first}}
    - enabled: True
    - hostname: {{grains.id.split("_") | first}}
    - apply_hostname: True
