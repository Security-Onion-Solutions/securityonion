# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - idstools.sync_files

idstoolslogdir:
  file.directory:
    - name: /opt/so/log/idstools
    - user: 939
    - group: 939
    - makedirs: True

idstools_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://idstools/tools/sbin
    - user: 934
    - group: 939
    - file_mode: 755

idstools_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://idstools/tools/sbin_jinja
    - user: 934
    - group: 939 
    - file_mode: 755
    - template: jinja

suricatacustomdirsfile:
  file.directory:
    - name: /nsm/rules/detect-suricata/custom_file
    - user: 939
    - group: 939
    - makedirs: True

suricatacustomdirsurl:
  file.directory:
    - name: /nsm/rules/detect-suricata/custom_temp
    - user: 939
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
