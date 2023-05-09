# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

include:
  - kibana.enabled

securitySolution_saved_objects:
  file.managed:
    - name: /opt/so/conf/kibana/securitySolution_saved_objects.ndjson.template
    - source: salt://kibana/files/securitySolution_saved_objects.ndjson
    - user: 932
    - group: 939

securitySolution_saved_objects_changes:
  file.absent:
    - names:
      - /opt/so/state/kibana_config_saved_objects.txt
    - onchanges:
      - file: securitySolution_saved_objects

so-kibana-securitySolution_saved_objects-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -u /opt/so/conf/kibana/securitySolution_saved_objects.ndjson.template
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: securitySolution_saved_objects
