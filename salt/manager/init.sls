# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'manager/map.jinja' import MANAGERMERGED %}

include:
  - salt.minion
  - kibana.secrets
  - manager.sync_es_users
  - manager.elasticsearch
  - manager.kibana
  - manager.managed_soc_annotations

repo_log_dir:
  file.directory:
    - name: /opt/so/log/reposync
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

agents_log_dir:
  file.directory:
    - name: /opt/so/log/agents
    - user: root
    - group: root
    - recurse:
      - user
      - group

yara_log_dir:
  file.directory:
    - name: /opt/so/log/yarasync
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

{% if GLOBALS.os_family == 'RedHat' %}
install_createrepo:
  pkg.installed:
    - name: createrepo_c
{% endif %}

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
    - show_changes: False

manager_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://manager/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755
    - exclude_pat:
      - "*_test.py"
    - show_changes: False

manager_sbin_jinja:
  file.recurse:
    - name: /usr/sbin/
    - source: salt://manager/tools/sbin_jinja/
    - user: socore
    - group: socore
    - file_mode: 755
    - template: jinja
    - show_changes: False

so-repo-file:
  file.managed:
    - name: /opt/so/conf/reposync/repodownload.conf
    - source: salt://manager/files/repodownload.conf
    - user: socore
    - group: socore
    - show_changes: False

so-repo-mirrorlist:
  file.managed:
    - name: /opt/so/conf/reposync/mirror.txt
    - source: salt://manager/files/mirror.txt
    - user: socore
    - group: socore

so-repo-sync:
  {%     if MANAGERMERGED.reposync.enabled %}
  cron.present:
  {%     else %}
  cron.absent:
  {%     endif %}
    - user: socore
    - name: '/usr/sbin/so-repo-sync >> /opt/so/log/reposync/reposync.log 2>&1'
    - identifier: so-repo-sync
    - hour: '{{ MANAGERMERGED.reposync.hour }}'
    - minute: '{{ MANAGERMERGED.reposync.minute }}'

so_fleetagent_status:
  cron.present:
    - name: /usr/sbin/so-elasticagent-status > /opt/so/log/agents/agentstatus.log 2>&1
    - identifier: so_fleetagent_status
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

socore_own_saltstack:
  file.directory:
    - name: /opt/so/saltstack
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

rules_dir:
  file.directory:
    - name: /nsm/rules/yara
    - user: socore
    - group: socore
    - makedirs: True

git_config_set_safe_dirs:
  git.config_set:
    - name: safe.directory
    - global: True
    - user: socore
    - multivar:
      - /nsm/rules/custom-local-repos/local-sigma
      - /nsm/rules/custom-local-repos/local-yara
      - /nsm/securityonion-resources
      - /opt/so/conf/soc/ai_summary_repos/securityonion-resources
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
