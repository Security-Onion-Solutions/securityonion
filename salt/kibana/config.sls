# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   import_yaml 'kibana/defaults.yaml' as default_settings %}
{%   from 'kibana/map.jinja' import KIBANAMERGED %}

# Add ES Group
kibanasearchgroup:
  group.present:
    - name: kibana
    - gid: 932

# Add ES user
kibana:
  user.present:
    - uid: 932
    - gid: 932
    - home: /opt/so/conf/kibana
    - createhome: False

# Drop the correct nginx config based on role

kibanaconfdir:
  file.directory:
    - name: /opt/so/conf/kibana/etc
    - user: 932
    - group: 939
    - makedirs: True

kibana_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://kibana/tools/sbin
    - user: 932
    - group: 939
    - file_mode: 755

kibana_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://kibana/tools/sbin_jinja
    - user: 932
    - group: 939 
    - file_mode: 755
    - template: jinja
    - defaults:
      GLOBALS: {{ GLOBALS }}

kibanaconfig:
  file.managed:
    - name: /opt/so/conf/kibana/etc/kibana.yml
    - source: salt://kibana/etc/kibana.yml.jinja
    - user: 932
    - group: 939
    - mode: 660
    - template: jinja
    - defaults:
        KIBANACONFIG: {{ KIBANAMERGED.config }}
    - show_changes: False

kibanalogdir:
  file.directory:
    - name: /opt/so/log/kibana
    - user: 932
    - group: 939
    - makedirs: True

kibanacustdashdir:
  file.directory:
    - name: /opt/so/conf/kibana/customdashboards
    - user: 932
    - group: 939
    - makedirs: True

synckibanacustom:
  file.recurse:
    - name: /opt/so/conf/kibana/customdashboards
    - source: salt://kibana/custom
    - user: 932
    - group: 939

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
