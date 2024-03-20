# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}

include:
  - strelka.config
  - strelka.backend.sostatus

backend_backend_config:
  file.managed:
    - name: /opt/so/conf/strelka/backend/backend.yaml
    - source: salt://strelka/backend/files/backend.yaml.jinja
    - template: jinja
    - user: 939
    - group: 939
    - makedirs: True
    - defaults:
        BACKENDCONFIG: {{ STRELKAMERGED.backend.config.backend }}

backend_logging_config:
  file.managed:
    - name: /opt/so/conf/strelka/backend/logging.yaml
    - source: salt://strelka/backend/files/logging.yaml.jinja
    - template: jinja
    - user: 939
    - group: 939
    - defaults:
        LOGGINGCONFIG: {{ STRELKAMERGED.backend.config.logging }}

backend_passwords:
  file.managed:
    - name: /opt/so/conf/strelka/backend/passwords.dat
    - source: salt://strelka/backend/files/passwords.dat.jinja
    - template: jinja
    - user: 939
    - group: 939
    - defaults:
        PASSWORDS: {{ STRELKAMERGED.backend.config.passwords }}

backend_taste:
  file.managed:
    - name: /opt/so/conf/strelka/backend/taste/taste.yara
    - source: salt://strelka/backend/files/taste/taste.yara
    - makedirs: True
    - user: 939
    - group: 939

{% if STRELKAMERGED.rules.enabled %}
strelkarules:
   file.recurse:
     - name: /opt/so/conf/strelka/rules
     - source: salt://strelka/rules
     - user: 939
     - group: 939
     - clean: True
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
