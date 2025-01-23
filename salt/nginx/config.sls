# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - ssl

# Drop the correct nginx config based on role
nginxconfdir:
  file.directory:
    - name: /opt/so/conf/nginx
    - user: 939
    - group: 939
    - makedirs: True

nginxconf:
  file.managed:
    - name: /opt/so/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://nginx/etc/nginx.conf
    - show_changes: False

nginxlogdir:
  file.directory:
    - name: /opt/so/log/nginx/
    - user: 939
    - group: 939
    - makedirs: True

nginxtmp:
  file.directory:
    - name: /opt/so/tmp/nginx/tmp
    - user: 939
    - group: 939
    - makedirs: True

navigatorconfig:
  file.managed:
    - name: /opt/so/conf/navigator/config.json
    - source: salt://nginx/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

navigatorlayersdir:
  file.directory:
    - name: /opt/so/conf/navigator/layers/
    - user: 939
    - group: 939
    - makedirs: True

nginx_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://nginx/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#nginx_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://nginx/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
