# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'strelka/map.jinja' import STRELKAMERGED %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'strelka/map.jinja' import filecheck_runas %}

include:
  - strelka.config
  - strelka.filestream.sostatus

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

filestream_config:
  file.managed:
    - name: /opt/so/conf/strelka/filestream/filestream.yaml
    - source: salt://strelka/filestream/files/filestream.yaml.jinja
    - template: jinja
    - user: 939
    - group: 939
    - makedirs: True
    - defaults:
        FILESTREAMCONFIG: {{ STRELKAMERGED.filestream.config }}

# Filecheck Section
{% if GLOBALS.os_family == 'Debian' %}
install_watchdog:
  pkg.installed:
    - name: python3-watchdog

{% elif GLOBALS.os_family == 'RedHat' %}
remove_old_watchdog:
  pkg.removed:
    - name: python3-watchdog

install_watchdog:
  pkg.installed:
    - name: securityonion-python39-watchdog
{% endif %}

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
    - source: salt://strelka/filecheck/filecheck.yaml.jinja
    - template: jinja
    - defaults:
        FILECHECKCONFIG: {{ STRELKAMERGED.filecheck }}

filecheck_script:
  file.managed:
    - name: /opt/so/conf/strelka/filecheck
    - source: salt://strelka/filecheck/filecheck
    - user: 939
    - group: 939
    - mode: 755

filecheck.log:
  file.managed:
    - name: /opt/so/log/strelka/filecheck.log
    - user: {{ filecheck_runas }}
    - group: {{ filecheck_runas }}
    - replace: False

filecheck_stdout.log:
  file.managed:
    - name: /opt/so/log/strelka/filecheck_stdout.log
    - user: {{ filecheck_runas }}
    - group: {{ filecheck_runas }}
    - replace: False

{% if GLOBALS.md_engine == 'ZEEK' %}

remove_filecheck_run:
  cron.absent:
    - identifier: filecheck_run
    - user: socore

filecheck_run_socore:
  cron.present:
    - name: 'ps -ef | grep filecheck | grep -v grep > /dev/null 2>&1 || python3 /opt/so/conf/strelka/filecheck >> /opt/so/log/strelka/filecheck_stdout.log 2>&1 &'
    - identifier: filecheck_run_socore
    - user: socore

remove_filecheck_run_suricata:
  cron.absent:
    - identifier: filecheck_run_suricata
    - user: suricata

{% elif GLOBALS.md_engine == 'SURICATA'%}

remove_filecheck_run:
  cron.absent:
    - identifier: filecheck_run
    - user: suricata

filecheck_run_suricata:
  cron.present:
    - name: 'ps -ef | grep filecheck | grep -v grep > /dev/null 2>&1 || python3 /opt/so/conf/strelka/filecheck >> /opt/so/log/strelka/filecheck_stdout.log 2>&1 &'
    - identifier: filecheck_run_suricata
    - user: suricata

remove_filecheck_run_socore:
  cron.absent:
    - identifier: filecheck_run_socore
    - user: socore

{% endif %}

filecheck_restart:
  cmd.run:
    - name: pkill -f "python3 /opt/so/conf/strelka/filecheck"
    - hide_output: True
    - success_retcodes: [0,1]
    - onchanges:
      - file: filecheck_script
      - file: filecheck_conf
      - pkg: install_watchdog

filcheck_history_clean:
  cron.present:
    - name: '/usr/bin/find /nsm/strelka/history/ -type f -mtime +2 -exec rm {} + > /dev/null 2>&1'
    - identifier: filecheck_history_clean
    - minute: '33'
# End Filecheck Section

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
