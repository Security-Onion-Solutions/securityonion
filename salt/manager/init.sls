# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}
{%   import_yaml 'manager/defaults.yaml' as MANAGERDEFAULTS %}
{%   set MANAGERMERGED = salt['pillar.get']('manager', MANAGERDEFAULTS.manager, merge=true) %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}

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

repo_conf_dir:
  file.directory:
    - name: /opt/so/conf/reposync
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

manager_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://manager/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#manager_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://manager/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

so-repo-sync:
  {% if MANAGERMERGED.reposync.enabled %}
  cron.present:
  {% else %}
  cron.absent:
  {% endif %}
    - user: socore
    - name: '/usr/sbin/so-repo-sync >> /opt/so/log/reposync/reposync.log 2>&1'
    - identifier: so-repo-sync
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

{%   if STRELKAMERGED.rules.enabled %}
strelkarepos:
  file.managed:
    - name: /opt/so/conf/strelka/repos.txt
    - source: salt://strelka/rules/repos.txt.jinja
    - template: jinja
    - defaults:
        STRELKAREPOS: {{ STRELKAMERGED.rules.repos }}
    - makedirs: True
{%   endif %}

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

strelka-yara-update:
  cron.present:
    - user: root
    - name: '/usr/sbin/so-yara-update >> /nsm/strelka/log/yara-update.log 2>&1'
    - identifier: strelka-yara-update
    - hour: '7'
    - minute: '1'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
