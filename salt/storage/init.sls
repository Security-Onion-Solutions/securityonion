# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


{% set nvme_devices = salt['cmd.shell']("find /dev -name 'nvme*n1' 2>/dev/null") %}
{% if nvme_devices %}

include:
  - storage.nsm_mount

{% endif %}
