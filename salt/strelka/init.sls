# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% set STRELKA_RULES = salt['pillar.get']('strelka:rules', '1') %}
{% import_yaml 'strelka/defaults.yaml' as strelka_config with context %}
{% set IGNORELIST = salt['pillar.get']('strelka:ignore', strelka_config.strelka.ignore, merge=True, merge_nested_lists=True) %}
{% set ENGINE = salt['pillar.get']('global:mdengine', '') %}

{% if ENGINE == "SURICATA" %}
  {% set filecheck_runas = 'suricata' %}
{% else %}
  {% set filecheck_runas = 'socore' %}
{% endif %}

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

# Sync dynamic config to conf dir
strelkasync:
  file.recurse:
    - name: /opt/so/conf/strelka/
    - source: salt://strelka/files
    - user: 939
    - group: 939
    - template: jinja

{% if STRELKA_RULES == 1 %}

strelkarules:
  file.recurse:
    - name: /opt/so/conf/strelka/rules
    - source: salt://strelka/rules
    - user: 939
    - group: 939
    - clean: True
    - exclude_pat:
      {% for IGNOREDRULE in IGNORELIST %}
      - {{ IGNOREDRULE }}
      {% endfor %}

      {% for IGNOREDRULE in IGNORELIST %}
remove_rule_{{ IGNOREDRULE }}:
  file.absent:
    - name: /opt/so/conf/strelka/rules/signature-base/{{ IGNOREDRULE }}
      {% endfor %}

{% if grains['role'] in GLOBALS.manager_roles %}
strelkarepos:
  file.managed:
    - name: /opt/so/saltstack/default/salt/strelka/rules/repos.txt
    - source: salt://strelka/rules/repos.txt.jinja
    - template: jinja

{% endif %}
{% endif %}

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

strelkaprocessed:
   file.directory:
    - name: /nsm/strelka/processed
    - user: 939
    - group: 939
    - makedirs: True

strelkastaging:
   file.directory:
    - name: /nsm/strelka/staging
    - user: 939
    - group: 939
    - makedirs: True

strelkaunprocessed:
   file.directory:
    - name: /nsm/strelka/unprocessed
    - user: 939
    - group: 939
    - mode: 775
    - makedirs: True

# Check to see if Strelka frontend port is available
strelkaportavailable:
    cmd.run:
      - name: netstat -utanp | grep ":57314" | grep -qvE 'docker|TIME_WAIT' && PROCESS=$(netstat -utanp | grep ":57314" | uniq) && echo "Another process ($PROCESS) appears to be using port 57314.  Please terminate this process, or reboot to ensure a clean state so that Strelka can start properly." && exit 1 || exit 0

# Filecheck Section
filecheck_logdir:
  file.directory:
    - name: /opt/so/log/strelka
    - user: 939
    - group: 939
    - mode: 775
    - makedirs: True

filecheck_history:
  file.directory:
    - name: /nsm/strelka/history
    - user: 939
    - group: 939
    - mode: 775
    - makedirs: True

filecheck_conf:
  file.managed:
    - name: /opt/so/conf/strelka/filecheck.yaml
    - source: salt://strelka/filecheck/filecheck.yaml
    - template: jinja

filecheck_script:
  file.managed:
    - name: /opt/so/conf/strelka/filecheck
    - source: salt://strelka/filecheck/filecheck
    - user: 939
    - group: 939
    - mode: 755

filecheck_restart:
  cmd.run:
    - name: pkill -f "python3 /opt/so/conf/strelka/filecheck"
    - hide_output: True
    - success_retcodes: [0,1]
    - onchanges:
      - file: filecheck_script

filecheck_run:
  cron.present:
    - name: 'ps -ef | grep filecheck | grep -v grep &> /dev/null >> /opt/so/log/strelka/filecheck_stdout.log 2>&1 &'
    - user: {{ filecheck_runas }}

filcheck_history_clean:
  cron.present:
    - name: '/usr/bin/find /nsm/strelka/history/ -type f -mtime +2 -exec rm {} + > /dev/null 2>&1'
    - minute: '33'
# End Filecheck Section


strelka_coordinator:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-redis:{{ GLOBALS.so_version }}
    - name: so-strelka-coordinator
    - entrypoint: redis-server --save "" --appendonly no
    - port_bindings:
      - 0.0.0.0:6380:6379

append_so-strelka-coordinator_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-coordinator

strelka_gatekeeper:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-redis:{{ GLOBALS.so_version }}
    - name: so-strelka-gatekeeper
    - entrypoint: redis-server --save "" --appendonly no --maxmemory-policy allkeys-lru
    - port_bindings:
      - 0.0.0.0:6381:6379

append_so-strelka-gatekeeper_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-gatekeeper

strelka_frontend:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-frontend:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/frontend/:/etc/strelka/:ro
      - /nsm/strelka/log/:/var/log/strelka/:rw
    - privileged: True
    - name: so-strelka-frontend
    - command: strelka-frontend
    - port_bindings:
      - 0.0.0.0:57314:57314

append_so-strelka-frontend_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-frontend

strelka_backend:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-backend:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/backend/:/etc/strelka/:ro
      - /opt/so/conf/strelka/rules/:/etc/yara/:ro
    - name: so-strelka-backend
    - command: strelka-backend
    - restart_policy: on-failure

append_so-strelka-backend_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-backend

strelka_manager:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-manager:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/manager/:/etc/strelka/:ro
    - name: so-strelka-manager
    - command: strelka-manager

append_so-strelka-manager_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-manager

strelka_filestream:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-strelka-filestream:{{ GLOBALS.so_version }}
    - binds:
      - /opt/so/conf/strelka/filestream/:/etc/strelka/:ro
      - /nsm/strelka:/nsm/strelka
    - name: so-strelka-filestream
    - command: strelka-filestream

append_so-strelka-filestream_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-filestream

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
