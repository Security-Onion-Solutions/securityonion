# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

kibana_curl_config_distributed:
  file.managed:
    - name: /opt/so/conf/kibana/curl.config
    - source: salt://kibana/files/curl.config.template
    - template: jinja
    - mode: 600
    - show_changes: False
    - makedirs: True
