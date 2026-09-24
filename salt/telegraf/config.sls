# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'telegraf/map.jinja' import TELEGRAFMERGED %}
{%   from 'logstash/map.jinja' import LOGSTASH_MERGED %}

# add Telegraf to monitor all the things
tgraflogdir:
  file.directory:
    - name: /opt/so/log/telegraf
    - makedirs: True
    - user: 939
    - group: 939
    - recurse:
      - user
      - group
      
tgrafetcdir:
  file.directory:
    - name: /opt/so/conf/telegraf/etc
    - makedirs: True

tgrafetsdir:
  file.directory:
    - name: /opt/so/conf/telegraf/scripts
    - makedirs: True

{% for script in TELEGRAFMERGED.scripts[GLOBALS.role.split('-')[1]] %}
tgraf_sync_script_{{script}}:
  file.managed:
    - name: /opt/so/conf/telegraf/scripts/{{script}}
    - user: root
    - group: 939
    - mode: 750
    - template: jinja
    - source: salt://telegraf/scripts/{{script}}
    - defaults:
        GLOBALS: {{ GLOBALS }}
{% endfor %}

{% if GLOBALS.is_manager or GLOBALS.role == 'so-heavynode' %}
tgraf_sync_script_esindexsize.sh:
  file.managed:
    - name: /opt/so/conf/telegraf/scripts/esindexsize.sh
    - user: root
    - group: 939
    - mode: 750
    - source: salt://telegraf/scripts/esindexsize.sh
{# Copy conf/elasticsearch/curl.config for telegraf to use with esindexsize.sh #}
tgraf_sync_escurl_conf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/escurl.config
    - user: 939
    - group: 939
    - mode: 400
    - source: salt://elasticsearch/curl.config
{% endif %}

# so-container-stats runs on the host as somon, a docker group member, so the container does
# not need the docker socket
somongroup:
  group.present:
    - name: somon
    - gid: 961

# cron chdirs to $HOME before running a job, so home must exist
somon:
  user.present:
    - uid: 961
    - gid: 961
    - home: /opt/so/log/somon
    - createhome: False
    - shell: /sbin/nologin
    - groups:
      - docker
    # renumbering an existing somon is a no-op on a fresh host and lets a host created
    # before the id changed converge instead of failing the whole telegraf state
    - allow_uid_change: True
    - allow_gid_change: True
    - require:
      - group: somongroup

somonlogdir:
  file.directory:
    - name: /opt/so/log/somon
    - user: 961
    - group: 961
    - mode: 755
    # the lock file is not otherwise managed; recurse so a renumber rechowns it too
    - recurse:
      - user
      - group
    - require:
      - user: somon

containers_log:
  file.managed:
    - name: /opt/so/log/somon/containers.log
    - user: 961
    - group: 961
    - mode: 644
    - replace: False
    - require:
      - file: somonlogdir

# telegraf reads on the same minute boundary the collector runs, and docker stats takes
# seconds, so write aside and rename rather than truncating the file telegraf is reading.
# ; not && so a failed run replaces the file instead of leaving stale metrics behind.
# flock -n keeps a run that outlives its minute from racing the next one over the same tmp
# file; the skipped run leaves a stale containers.log, which containers.sh discards by age
so-container-stats_cron:
  cron.present:
    - name: "flock -n /opt/so/log/somon/containers.lock -c '/usr/sbin/so-container-stats > /opt/so/log/somon/containers.log.tmp 2>&1; mv -f /opt/so/log/somon/containers.log.tmp /opt/so/log/somon/containers.log'"
    - identifier: so-container-stats_cron
    - user: somon
    - minute: '*/1'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
    - require:
      - user: somon

# salt.lasthighstate touches this at order 9001, after the container starts; pre-create it so
# docker does not create a directory at the bind mount source
lasthighstate_placeholder:
  file.managed:
    - name: /opt/so/log/salt/lasthighstate
    - mode: 644
    - replace: False
    - makedirs: True

telegraf_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://telegraf/tools/sbin
    - user: root
    - group: root
    - file_mode: 755

# so-container-stats needs the per-stat toggles, so it renders instead of copying
tgraf_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://telegraf/tools/sbin_jinja
    - user: root
    - group: root
    - file_mode: 755
    # the unit test lives beside the script; it must not ship or be rendered as jinja
    - exclude_pat:
      - "*_test.py"
    - template: jinja
    - defaults:
        CONTAINER_STATS: {{ TELEGRAFMERGED.container_stats }}

tgrafconf:
  file.managed:
    - name: /opt/so/conf/telegraf/etc/telegraf.conf
    - user: 939
    - group: 939
    - mode: 660
    - template: jinja
    - source: salt://telegraf/etc/telegraf.conf
    - show_changes: False
    - defaults:
        GLOBALS: {{ GLOBALS }}
        TELEGRAFMERGED: {{ TELEGRAFMERGED }}
        LOGSTASH_MERGED: {{ LOGSTASH_MERGED }}

# this file will be read by telegraf to send node details (management interface, monitor interface, etc)
# into influx
node_config:
  file.managed:
    - name: /opt/so/conf/telegraf/node_config.json
    - source: salt://telegraf/node_config.json.jinja
    - template: jinja

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
