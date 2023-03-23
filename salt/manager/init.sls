# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'strelka/map.jinja' import STRELKAMERGED %}
{% import_yaml 'manager/defaults.yaml' as MANAGERDEFAULTS %}
{% set MANAGERMERGED = salt['pillar.get']('manager', MANAGERDEFAULTS.manager, merge=true) %}

include:
  - salt.minion
  - kibana.secrets
  - manager.sync_es_users
  - manager.elasticsearch

repo_log_dir:
  file.directory:
    - name: /opt/so/log/reposync
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

repo_dir:
  file.directory:
    - name: /nsm/repo
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

reposync_cron:
  {% if MANAGERMERGED.reposync.enabled %}
  cron.present:
  {% else %}
  cron.absent:
  {% endif %}
    - user: socore
    - name: '/usr/sbin/so-repo-sync >> /opt/so/log/reposync/reposync.log 2>&1'
    - hour: '{{ MANAGERMERGED.reposync.hour }}'
    - minute: '{{ MANAGERMERGED.reposync.minute }}'

socore_own_saltstack:
  file.directory:
    - name: /opt/so/saltstack
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

yara_update_script:
  file.managed:
    - name: /usr/sbin/so-yara-update
    - source: salt://manager/files/so-yara-update.jinja
    - user: root
    - group: root
    - mode: 755
    - template: jinja
    - defaults:
        ISAIRGAP: {{ GLOBALS.airgap }}
        EXCLUDEDRULES: {{ STRELKAMERGED.rules.excluded }}

strelka_yara_update:
  cron.present:
    - user: root
    - name: '/usr/sbin/so-yara-update >> /nsm/strelka/log/yara-update.log 2>&1'
    - hour: '7'
    - minute: '1'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
