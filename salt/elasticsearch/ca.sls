# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states or sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

# Move our new CA over so Elastic and Logstash can use SSL with the internal CA
catrustdir:
  file.directory:
    - name: /opt/so/conf/ca
    - user: 939
    - group: 939
    - makedirs: True

{%   if GLOBALS.is_manager %}
# We have to add the Manager CA to the CA list
catrustscript:
  cmd.script:
    - source: salt://elasticsearch/tools/sbin_jinja/so-catrust
    - template: jinja
    - cwd: /opt/so
    - defaults:
        GLOBALS: {{ GLOBALS }}
{%   endif %}

cacertz:
  file.managed:
    - name: /opt/so/conf/ca/cacerts
    - source: salt://elasticsearch/cacerts
    - user: 939
    - group: 939

capemz:
  file.managed:
    - name: /opt/so/conf/ca/tls-ca-bundle.pem
    - source: salt://elasticsearch/tls-ca-bundle.pem
    - user: 939
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
