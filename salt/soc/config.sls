# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

include:
  - manager.sync_es_users

sigmarepodir:
  file.directory:
    - name: /opt/so/conf/sigma/repos
    - user: 939
    - group: 939
    - makedirs: True

socdirelastaertrules:
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

socanalytics:
  file.managed:
    - name: /opt/so/conf/soc/analytics.js
    - source: salt://soc/files/soc/analytics.js
    - user: 939
    - group: 939
    - mode: 600
    - show_changes: False

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

filedetectionsbackup:
  file.managed:
    - name: /opt/so/conf/soc/so-detections-backup.py
    - source: salt://soc/files/soc/so-detections-backup.py
    - user: 939
    - group: 939
    - mode: 600

crondetectionsruntime:
  cron.present:
    - name: /usr/sbin/so-detections-runtime-status cron
    - identifier: detections-runtime-status
    - user: root
    - minute: '*/10'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

crondetectionsbackup:
  cron.present:
    - name: python3 /opt/so/conf/soc/so-detections-backup.py &>> /opt/so/log/soc/detections-backup.log
    - identifier: detections-backup
    - user: root
    - minute: '0'
    - hour: '0'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

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

socclientsroles:
  file.managed:
    - name: /opt/so/conf/soc/soc_clients_roles
    - user: 939
    - group: 939
    - mode: 600
    - allow_empty: true
    - create: true

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

socsensoronirepos:
  file.directory:
    - name: /opt/so/conf/soc/ai_summary_repos
    - user: 939
    - group: 939
    - mode: 775
    - makedirs: True


create_custom_local_yara_repo_template:
  git.present:
    - name: /nsm/rules/custom-local-repos/local-yara
    - bare: False
    - force: True

add_readme_custom_local_yara_repo_template:
  file.managed:
    - name: /nsm/rules/custom-local-repos/local-yara/README
    - source: salt://soc/files/soc/detections_custom_repo_template_readme.jinja
    - user: 939
    - group: 939
    - template: jinja
    - context:
        repo_type: "yara"


create_custom_local_sigma_repo_template:
  git.present:
    - name: /nsm/rules/custom-local-repos/local-sigma
    - bare: False
    - force: True

add_readme_custom_local_sigma_repo_template:
  file.managed:
    - name: /nsm/rules/custom-local-repos/local-sigma/README
    - source: salt://soc/files/soc/detections_custom_repo_template_readme.jinja
    - user: 939
    - group: 939
    - template: jinja
    - context:
        repo_type: "sigma"

socore_own_custom_repos:
  file.directory:
    - name: /nsm/rules/custom-local-repos/
    - user: socore
    - group: socore
    - recurse:
      - user
      - group
  
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
