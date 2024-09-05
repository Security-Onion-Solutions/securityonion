# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - kibana.enabled

config_saved_objects:
  file.managed:
    - name: /opt/so/conf/kibana/config_saved_objects.ndjson.template
    - source: salt://kibana/files/config_saved_objects.ndjson.jinja
    - template: jinja
    - user: 932
    - group: 939

config_saved_objects_changes:
  file.absent:
    - names:
      - /opt/so/state/kibana_config_saved_objects.txt
    - onchanges:
      - file: config_saved_objects

so-kibana-config-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/so/conf/kibana/config_saved_objects.ndjson.template
    - cwd: /opt/so
    - require:
      - sls: kibana.enabled
      - file: config_saved_objects
