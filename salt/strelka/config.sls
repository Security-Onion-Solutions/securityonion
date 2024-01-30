# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

# Strelka config
strelkaconfdir:
  file.directory:
    - name: /opt/so/conf/strelka
    - user: 939
    - group: 939
    - makedirs: True

strelkarulesdir:
  file.directory:
    - name: /opt/so/conf/strelka/rules
    - user: 939
    - group: 939
    - makedirs: True

strelkareposdir:
  file.directory:
    - name: /opt/so/conf/strelka/repos
    - user: 939
    - group: 939
    - makedirs: True

strelkadatadir:
   file.directory:
    - name: /nsm/strelka
    - user: 939
    - group: 939
    - makedirs: True

strelkalogdir:
  file.directory:
    - name: /nsm/strelka/log
    - user: 939
    - group: 939
    - makedirs: True

strelka_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://strelka/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

strelkagkredisdatadir:
  file.directory:
    - name: /nsm/strelka/gk-redis-data
    - user: 939
    - group: 939
    - makedirs: True

strelkacoordredisdatadir:
  file.directory:
    - name: /nsm/strelka/coord-redis-data
    - user: 939
    - group: 939
    - makedirs: True

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
