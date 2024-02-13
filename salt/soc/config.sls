# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - manager.sync_es_users

socdirtest:
  file.directory:
    - name: /opt/so/rules/elastalert/rules
    - user: 939
    - group: 939
    - makedirs: True

socdir:
  file.directory:
    - name: /opt/so/conf/soc/fingerprints
    - user: 939
    - group: 939
    - makedirs: True

socdatadir:
  file.directory:
    - name: /nsm/soc/jobs
    - user: 939
    - group: 939
    - makedirs: True

soclogdir:
  file.directory:
    - name: /opt/so/log/soc
    - user: 939
    - group: 939
    - makedirs: True

socsaltdir:
  file.directory:
    - name: /opt/so/conf/soc/queue
    - user: 939
    - group: 939
    - mode: 770
    - makedirs: True

socconfig:
  file.managed:
    - name: /opt/so/conf/soc/soc.json
    - source: salt://soc/files/soc/soc.json.jinja
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False

socmotd:
  file.managed:
    - name: /opt/so/conf/soc/motd.md
    - source: salt://soc/files/soc/motd.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socsigmafinalpipeline:
  file.managed:
    - name: /opt/so/conf/soc/sigma_final_pipeline.yaml
    - source: salt://soc/files/soc/sigma_final_pipeline.yaml
    - user: 939
    - group: 939
    - mode: 600

socsigmasopipeline:
  file.managed:
    - name: /opt/so/conf/soc/sigma_so_pipeline.yaml
    - source: salt://soc/files/soc/sigma_so_pipeline.yaml
    - user: 939
    - group: 939
    - mode: 600

socbanner:
  file.managed:
    - name: /opt/so/conf/soc/banner.md
    - source: salt://soc/files/soc/banner.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soc_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://soc/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#soc_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://soc/tools/sbin_jinja
#    - user: 939
#    - group: 939
#    - file_mode: 755
#    - template: jinja

soccustom:
  file.managed:
    - name: /opt/so/conf/soc/custom.js
    - source: salt://soc/files/soc/custom.js
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soccustomroles:
  file.managed:
    - name: /opt/so/conf/soc/custom_roles
    - source: salt://soc/files/soc/custom_roles
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socusersroles:
  file.exists:
    - name: /opt/so/conf/soc/soc_users_roles
    - require:
      - sls: manager.sync_es_users

socuploaddir:
  file.directory:
    - name: /nsm/soc/uploads
    - user: 939
    - group: 939
    - makedirs: True

socsigmarepo:
  file.directory:
    - name: /opt/so/rules
    - user: 939
    - group: 939
    - mode: 775

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
