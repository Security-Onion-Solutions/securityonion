# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

sensoroniconfdir:
  file.directory:
    - name: /opt/so/conf/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

sensoroniagentconf:
  file.managed:
    - name: /opt/so/conf/sensoroni/sensoroni.json
    - source: salt://sensoroni/files/sensoroni.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False

analyzersdir:
  file.directory:
    - name: /opt/so/conf/sensoroni/analyzers
    - user: 939
    - group: 939
    - makedirs: True

sensoronilog:
  file.directory:
    - name: /opt/so/log/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

analyzerscripts:
  file.recurse:
    - name: /opt/so/conf/sensoroni/analyzers
    - user: 939
    - group: 939
    - file_mode: 755
    - template: jinja
    - source: salt://sensoroni/files/analyzers
    - show_changes: False

templatesdir:
  file.directory:
    - name: /opt/so/conf/sensoroni/templates
    - user: 939
    - group: 939
    - makedirs: True

sensoronitemplates:
  file.recurse:
    - name: /opt/so/conf/sensoroni/templates
    - source: salt://sensoroni/files/templates
    - user: 939
    - group: 939
    - file_mode: 664
    - show_changes: False

sensoroni_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://sensoroni/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#sensoroni_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://sensoroni/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja
