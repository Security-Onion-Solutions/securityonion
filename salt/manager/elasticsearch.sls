# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

elastic_curl_config_distributed:
  file.managed:
    - name: /opt/so/saltstack/local/salt/elasticsearch/curl.config
    - source: salt://elasticsearch/files/curl.config.template
    - template: jinja
    - mode: 640
    - show_changes: False
