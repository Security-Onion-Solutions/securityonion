# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'redis/map.jinja' import REDISMERGED %}

include:
  - ssl

# Redis Setup
redisconfdir:
  file.directory:
    - name: /opt/so/conf/redis/etc
    - user: 939
    - group: 939
    - makedirs: True

redisworkdir:
  file.directory:
    - name: /opt/so/conf/redis/working
    - user: 939
    - group: 939
    - makedirs: True

redislogdir:
  file.directory:
    - name: /opt/so/log/redis
    - user: 939
    - group: 939
    - makedirs: True

redisconf:
  file.managed:
    - name: /opt/so/conf/redis/etc/redis.conf
    - source: salt://redis/etc/redis.conf.jinja
    - user: 939
    - group: 939
    - template: jinja
    - defaults:
        REDISMERGED: {{ REDISMERGED }}

redis_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://redis/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

redis_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://redis/tools/sbin_jinja
    - user: 939
    - group: 939 
    - file_mode: 755
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
